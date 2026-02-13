//! Stake tokens instruction

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    clock::Clock,
    entrypoint::ProgramResult,
    msg,
    program::{invoke, invoke_signed},
    pubkey::Pubkey,
    rent::Rent,
    system_instruction,
    sysvar::Sysvar,
};
use spl_token_2022::extension::StateWithExtensions;

use crate::{
    error::StakingError,
    math::{calculate_user_weighted_stake, exp_time_ratio, wad_div, wad_mul, MAX_EXP_INPUT, U256, WAD},
    state::{PoolMetadata, StakingPool, UserStake, STAKE_SEED},
};

/// Stake tokens into the pool
///
/// Accounts:
/// 0. `[writable]` Pool account
/// 1. `[writable]` User stake account (PDA: ["stake", pool, owner])
/// 2. `[writable]` Token vault
/// 3. `[writable]` User token account
/// 4. `[]` Token mint
/// 5. `[writable, signer]` User/owner
/// 6. `[]` System program
/// 7. `[]` Token 2022 program
pub fn process_stake(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    amount: u64,
) -> ProgramResult {
    if amount == 0 {
        return Err(StakingError::ZeroAmount.into());
    }

    let account_info_iter = &mut accounts.iter();

    let pool_info = next_account_info(account_info_iter)?;
    let user_stake_info = next_account_info(account_info_iter)?;
    let token_vault_info = next_account_info(account_info_iter)?;
    let user_token_info = next_account_info(account_info_iter)?;
    let mint_info = next_account_info(account_info_iter)?;
    let user_info = next_account_info(account_info_iter)?;
    let system_program_info = next_account_info(account_info_iter)?;
    let token_program_info = next_account_info(account_info_iter)?;

    // Validate Token 2022 program
    if *token_program_info.key != spl_token_2022::id() {
        return Err(StakingError::InvalidTokenProgram.into());
    }

    // Validate user is signer
    if !user_info.is_signer {
        return Err(StakingError::MissingRequiredSigner.into());
    }

    // Load and validate pool
    if pool_info.owner != program_id {
        return Err(StakingError::InvalidAccountOwner.into());
    }
    let mut pool = StakingPool::try_from_slice(&pool_info.try_borrow_data()?)?;
    if !pool.is_initialized() {
        return Err(StakingError::NotInitialized.into());
    }

    // Verify pool PDA
    let (expected_pool, _) = StakingPool::derive_pda(&pool.mint, program_id);
    if *pool_info.key != expected_pool {
        return Err(StakingError::InvalidPDA.into());
    }

    // Verify mint matches pool
    if pool.mint != *mint_info.key {
        return Err(StakingError::InvalidPoolMint.into());
    }

    // Verify token vault
    if pool.token_vault != *token_vault_info.key {
        return Err(StakingError::InvalidTokenVault.into());
    }

    // Verify user stake PDA
    let (expected_stake, stake_bump) =
        UserStake::derive_pda(pool_info.key, user_info.key, program_id);
    if *user_stake_info.key != expected_stake {
        return Err(StakingError::InvalidPDA.into());
    }

    let clock = Clock::get()?;
    let current_time = clock.unix_timestamp;

    // Check if pool needs rebasing (sum_stake_exp near overflow)
    if pool.get_sum_stake_exp().needs_rebase() {
        return Err(StakingError::PoolRequiresSync.into());
    }

    // Calculate exp_start_factor for this stake
    let time_since_base = current_time.saturating_sub(pool.base_time);

    // Check if time_since_base / tau would overflow exp_wad.
    // Require SyncPool first if the ratio exceeds MAX_EXP_INPUT.
    let ratio_wad = (time_since_base as u128)
        .checked_mul(WAD)
        .ok_or(StakingError::MathOverflow)?
        / (pool.tau_seconds as u128);
    if ratio_wad > MAX_EXP_INPUT {
        return Err(StakingError::PoolRequiresSync.into());
    }

    let exp_start_factor = exp_time_ratio(time_since_base, pool.tau_seconds)?;

    // Create or update user stake account
    let is_new_stake = user_stake_info.data_is_empty();

    // Deferred auto-claim amount (set in else branch, transferred after token CPI)
    let mut auto_claim_transfer: u64 = 0;

    if is_new_stake {
        // Check minimum stake amount
        if pool.min_stake_amount > 0 && amount < pool.min_stake_amount {
            return Err(StakingError::BelowMinimumStake.into());
        }

        // Create new user stake account
        let rent = Rent::get()?;
        let stake_rent = rent.minimum_balance(UserStake::LEN);
        let stake_seeds = &[
            STAKE_SEED,
            pool_info.key.as_ref(),
            user_info.key.as_ref(),
            &[stake_bump],
        ];

        invoke_signed(
            &system_instruction::create_account(
                user_info.key,
                user_stake_info.key,
                stake_rent,
                UserStake::LEN as u64,
                program_id,
            ),
            &[
                user_info.clone(),
                user_stake_info.clone(),
                system_program_info.clone(),
            ],
            &[stake_seeds],
        )?;

        // Initialize user stake
        let mut user_stake = UserStake::new(
            *user_info.key,
            *pool_info.key,
            amount,
            current_time,
            exp_start_factor,
            stake_bump,
            pool.base_time,
        );

        // Set reward_debt using max weight (amount * WAD) to prevent accessing prior rewards
        user_stake.reward_debt = wad_mul(
            (amount as u128).checked_mul(WAD).ok_or(StakingError::MathOverflow)?,
            pool.acc_reward_per_weighted_share,
        )?;

        // Track in pool-level aggregate
        pool.total_reward_debt = pool
            .total_reward_debt
            .checked_add(user_stake.reward_debt)
            .ok_or(StakingError::MathOverflow)?;

        let mut stake_data = user_stake_info.try_borrow_mut_data()?;
        user_stake.serialize(&mut &mut stake_data[..])?;

        // Update pool sum_stake_exp
        // sum_stake_exp += amount * exp_start_factor
        let stake_contribution = wad_mul(
            (amount as u128).checked_mul(WAD).ok_or(StakingError::MathOverflow)?,
            exp_start_factor,
        )?;
        let new_sum = pool
            .get_sum_stake_exp()
            .checked_add(U256::from_u128(stake_contribution))
            .ok_or(StakingError::MathOverflow)?;
        pool.set_sum_stake_exp(new_sum);
    } else {
        // Load existing stake
        if user_stake_info.owner != program_id {
            return Err(StakingError::InvalidAccountOwner.into());
        }
        let mut user_stake = UserStake::try_from_slice(&user_stake_info.try_borrow_data()?)?;
        if !user_stake.is_initialized() {
            return Err(StakingError::NotInitialized.into());
        }

        // Verify ownership
        if user_stake.owner != *user_info.key {
            return Err(StakingError::InvalidOwner.into());
        }
        if user_stake.pool != *pool_info.key {
            return Err(StakingError::InvalidPool.into());
        }

        // Block staking while unstake request is pending
        if user_stake.has_pending_unstake_request() {
            return Err(StakingError::PendingUnstakeRequestExists.into());
        }

        // Check minimum stake amount on new total
        let new_total = user_stake
            .amount
            .checked_add(amount)
            .ok_or(StakingError::MathOverflow)?;
        if pool.min_stake_amount > 0 && new_total < pool.min_stake_amount {
            return Err(StakingError::BelowMinimumStake.into());
        }

        // Lazily adjust exp_start_factor if pool has been rebased
        user_stake.sync_to_pool(&pool)?;

        // Capture old reward_debt for total_reward_debt bookkeeping
        let old_reward_debt = user_stake.reward_debt;

        // Auto-claim pending rewards before resetting reward_debt.
        // Track any unpaid portion so it remains claimable after the stake update.
        // NOTE: Actual SOL transfer is deferred until after the token CPI to avoid
        // Solana's CPI balance check failure (same pattern as execute_unstake).
        let mut unpaid_rewards_wad: u128 = 0;
        let user_weighted_before = calculate_user_weighted_stake(
            user_stake.amount,
            user_stake.exp_start_factor,
            current_time,
            pool.base_time,
            pool.tau_seconds,
        )?;
        if user_weighted_before > 0 && pool.acc_reward_per_weighted_share > 0 {
            // Snapshot-delta: pending = user_weighted * (acc_rps - snapshot)
            let old_amount_wad = (user_stake.amount as u128)
                .checked_mul(WAD)
                .ok_or(StakingError::MathOverflow)?;
            let snapshot = wad_div(user_stake.reward_debt, old_amount_wad)?;
            let delta_rps = pool.acc_reward_per_weighted_share.saturating_sub(snapshot);
            let pending = wad_mul(user_weighted_before, delta_rps)?;
            if pending > 0 {
                let pending_lamports = pending / WAD;
                if pending_lamports > 0 {
                    let rent = Rent::get()?;
                    let rent_exempt_minimum = rent.minimum_balance(pool_info.data_len());
                    let available = pool_info.lamports().saturating_sub(rent_exempt_minimum);
                    auto_claim_transfer = pending_lamports.min(available as u128) as u64;
                    if auto_claim_transfer > 0 {
                        pool.last_synced_lamports =
                            pool.last_synced_lamports.saturating_sub(auto_claim_transfer);
                    }
                    // Track unpaid portion so it remains claimable
                    let paid_wad = (auto_claim_transfer as u128)
                        .checked_mul(WAD)
                        .ok_or(StakingError::MathOverflow)?;
                    unpaid_rewards_wad = pending.saturating_sub(paid_wad);
                }
            }
        }

        // For additional stakes, we need to track a weighted average exp_start_factor
        // New exp_factor = (old_amount * old_exp + new_amount * new_exp) / total_amount
        let old_contribution = wad_mul(
            (user_stake.amount as u128).checked_mul(WAD).ok_or(StakingError::MathOverflow)?,
            user_stake.exp_start_factor,
        )?;
        let new_contribution = wad_mul(
            (amount as u128).checked_mul(WAD).ok_or(StakingError::MathOverflow)?,
            exp_start_factor,
        )?;

        let total_amount = new_total;

        // Update pool sum_stake_exp with new contribution
        let new_sum = pool
            .get_sum_stake_exp()
            .checked_add(U256::from_u128(new_contribution))
            .ok_or(StakingError::MathOverflow)?;
        pool.set_sum_stake_exp(new_sum);

        // Calculate new weighted average exp_start_factor
        // total_contribution is WAD-scaled (sum of amount_i * exp_factor_i),
        // total_amount is raw, so division yields a WAD-scaled result directly.
        let total_contribution = old_contribution
            .checked_add(new_contribution)
            .ok_or(StakingError::MathOverflow)?;
        let new_exp_factor = total_contribution
            .checked_div(total_amount as u128)
            .ok_or(StakingError::MathOverflow)?;

        // Update user stake
        user_stake.amount = total_amount;
        user_stake.exp_start_factor = new_exp_factor;
        // Note: stake_time stays as original for weight calculation purposes
        user_stake.last_stake_time = current_time;

        // Recalculate reward_debt using max weight (total_amount * WAD) to prevent reward theft.
        // Subtract any unpaid rewards so they remain claimable.
        let total_amount_wad = (total_amount as u128)
            .checked_mul(WAD)
            .ok_or(StakingError::MathOverflow)?;
        let base_debt = wad_mul(total_amount_wad, pool.acc_reward_per_weighted_share)?;
        user_stake.reward_debt = base_debt.saturating_sub(unpaid_rewards_wad);

        // Update pool-level aggregate: subtract old, add new (saturating for bootstrapping)
        pool.total_reward_debt = pool
            .total_reward_debt
            .saturating_sub(old_reward_debt)
            .checked_add(user_stake.reward_debt)
            .ok_or(StakingError::MathOverflow)?;

        let mut stake_data = user_stake_info.try_borrow_mut_data()?;
        user_stake.serialize(&mut &mut stake_data[..])?;
    }

    // Update pool total staked
    pool.total_staked = pool
        .total_staked
        .checked_add(amount as u128)
        .ok_or(StakingError::MathOverflow)?;

    // Save pool state
    let mut pool_data = pool_info.try_borrow_mut_data()?;
    pool.serialize(&mut &mut pool_data[..])?;

    // Transfer tokens from user to vault
    // Get decimals from mint for transfer_checked
    let mint_data = mint_info.try_borrow_data()?;
    let mint = StateWithExtensions::<spl_token_2022::state::Mint>::unpack(&mint_data)?;
    let decimals = mint.base.decimals;
    drop(mint_data);

    invoke(
        &spl_token_2022::instruction::transfer_checked(
            &spl_token_2022::id(),
            user_token_info.key,
            mint_info.key,
            token_vault_info.key,
            user_info.key,
            &[],
            amount,
            decimals,
        )?,
        &[
            user_token_info.clone(),
            mint_info.clone(),
            token_vault_info.clone(),
            user_info.clone(),
        ],
    )?;

    // Transfer auto-claimed SOL rewards AFTER token CPI to avoid balance check failure
    if auto_claim_transfer > 0 {
        **pool_info.try_borrow_mut_lamports()? -= auto_claim_transfer;
        **user_info.try_borrow_mut_lamports()? += auto_claim_transfer;
        msg!("Auto-claimed {} lamports in pending rewards", auto_claim_transfer);
    }

    // Optional metadata account: increment member_count on new stake
    if is_new_stake {
        if let Some(metadata_info) = account_info_iter.next() {
            if metadata_info.owner == program_id && !metadata_info.data_is_empty() {
                let (expected_metadata, _) =
                    PoolMetadata::derive_pda(pool_info.key, program_id);
                if *metadata_info.key == expected_metadata {
                    let mut metadata =
                        PoolMetadata::try_from_slice(&metadata_info.try_borrow_data()?)?;
                    if metadata.is_initialized() && metadata.pool == *pool_info.key {
                        metadata.member_count = metadata.member_count.saturating_add(1);
                        let mut metadata_data = metadata_info.try_borrow_mut_data()?;
                        metadata.serialize(&mut &mut metadata_data[..])?;
                    }
                }
            }
        }
    }

    msg!("Staked {} tokens", amount);

    Ok(())
}
