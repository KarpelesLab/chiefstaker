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
    math::{calculate_user_weighted_stake, exp_time_ratio, wad_mul, U256, WAD},
    state::{StakingPool, UserStake, STAKE_SEED},
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
    let _token_program_info = next_account_info(account_info_iter)?;

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

    // Check if pool needs rebasing
    if pool.get_sum_stake_exp().needs_rebase() {
        return Err(StakingError::PoolRequiresSync.into());
    }

    // Calculate exp_start_factor for this stake
    let time_since_base = current_time.saturating_sub(pool.base_time);
    let exp_start_factor = exp_time_ratio(time_since_base, pool.tau_seconds)?;

    // Create or update user stake account
    let is_new_stake = user_stake_info.data_is_empty();

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
        let user_stake = UserStake::new(
            *user_info.key,
            *pool_info.key,
            amount,
            current_time,
            exp_start_factor,
            stake_bump,
        );

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

        // Recalculate reward_debt for new weighted stake to prevent reward theft
        let new_user_weighted = calculate_user_weighted_stake(
            total_amount,
            new_exp_factor,
            current_time,
            pool.base_time,
            pool.tau_seconds,
        )?;
        user_stake.reward_debt = wad_mul(new_user_weighted, pool.acc_reward_per_weighted_share)?;

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

    msg!("Staked {} tokens", amount);

    Ok(())
}
