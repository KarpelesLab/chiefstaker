//! Unstake tokens instruction

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    clock::Clock,
    entrypoint::ProgramResult,
    msg,
    program::invoke_signed,
    pubkey::Pubkey,
    sysvar::Sysvar,
};
use spl_token_2022::extension::StateWithExtensions;

use crate::{
    error::StakingError,
    math::{
        calculate_total_weighted_stake, calculate_user_weighted_stake, wad_mul, U256, WAD,
    },
    state::{StakingPool, UserStake, POOL_SEED},
};

/// Shared unstake logic used by both process_unstake and process_complete_unstake.
/// Handles: reward claiming, pool math updates (sum_stake_exp, total_staked),
/// reward_debt recalculation, and token transfer.
///
/// Assumes all account validation has been done by the caller.
pub fn execute_unstake<'a>(
    program_id: &Pubkey,
    pool: &mut StakingPool,
    user_stake: &mut UserStake,
    pool_info: &AccountInfo<'a>,
    user_stake_info: &AccountInfo<'a>,
    token_vault_info: &AccountInfo<'a>,
    user_token_info: &AccountInfo<'a>,
    mint_info: &AccountInfo<'a>,
    user_info: &AccountInfo<'a>,
    amount: u64,
) -> ProgramResult {
    let clock = Clock::get()?;
    let current_time = clock.unix_timestamp;

    // Calculate and claim pending rewards first
    let total_weighted = calculate_total_weighted_stake(
        pool.total_staked,
        &pool.get_sum_stake_exp(),
        current_time,
        pool.base_time,
        pool.tau_seconds,
    )?;

    let user_weighted = calculate_user_weighted_stake(
        user_stake.amount,
        user_stake.exp_start_factor,
        current_time,
        pool.base_time,
        pool.tau_seconds,
    )?;

    if total_weighted > 0 && user_weighted > 0 {
        // Calculate pending rewards
        let pending = wad_mul(user_weighted, pool.acc_reward_per_weighted_share)?
            .saturating_sub(user_stake.reward_debt);

        if pending > 0 {
            // Convert from WAD-scaled to lamports
            let pending_lamports = pending / WAD;

            if pending_lamports > 0 {
                // Check pool has sufficient balance
                let pool_lamports = pool_info.lamports();
                let rent_exempt_minimum = solana_program::rent::Rent::get()?
                    .minimum_balance(pool_info.data_len());

                let available_rewards = pool_lamports.saturating_sub(rent_exempt_minimum);
                let transfer_amount = pending_lamports.min(available_rewards as u128) as u64;

                if transfer_amount > 0 {
                    // Transfer SOL rewards from pool to user
                    **pool_info.try_borrow_mut_lamports()? -= transfer_amount;
                    **user_info.try_borrow_mut_lamports()? += transfer_amount;
                    // Update last_synced_lamports so sync_rewards doesn't miss new deposits
                    pool.last_synced_lamports = pool.last_synced_lamports.saturating_sub(transfer_amount);
                    msg!("Claimed {} lamports in rewards", transfer_amount);
                }
            }
        }
    }

    // Calculate the unstaked portion's contribution to sum_stake_exp
    // contribution = amount * exp_start_factor
    let unstake_contribution = wad_mul(
        (amount as u128).checked_mul(WAD).ok_or(StakingError::MathOverflow)?,
        user_stake.exp_start_factor,
    )?;

    // Update pool sum_stake_exp
    let new_sum = pool
        .get_sum_stake_exp()
        .checked_sub(U256::from_u128(unstake_contribution))
        .ok_or(StakingError::MathUnderflow)?;
    pool.set_sum_stake_exp(new_sum);

    // Update pool total staked
    pool.total_staked = pool
        .total_staked
        .checked_sub(amount as u128)
        .ok_or(StakingError::MathUnderflow)?;

    // Update user stake
    user_stake.amount = user_stake
        .amount
        .checked_sub(amount)
        .ok_or(StakingError::MathUnderflow)?;

    // Recalculate reward debt for remaining stake
    if user_stake.amount > 0 {
        let new_user_weighted = calculate_user_weighted_stake(
            user_stake.amount,
            user_stake.exp_start_factor,
            current_time,
            pool.base_time,
            pool.tau_seconds,
        )?;
        user_stake.reward_debt = wad_mul(new_user_weighted, pool.acc_reward_per_weighted_share)?;
    } else {
        user_stake.reward_debt = 0;
    }

    // Save states
    {
        let mut pool_data = pool_info.try_borrow_mut_data()?;
        pool.serialize(&mut &mut pool_data[..])?;
    }
    {
        let mut stake_data = user_stake_info.try_borrow_mut_data()?;
        user_stake.serialize(&mut &mut stake_data[..])?;
    }

    // Transfer tokens from vault to user
    let mint_data = mint_info.try_borrow_data()?;
    let mint = StateWithExtensions::<spl_token_2022::state::Mint>::unpack(&mint_data)?;
    let decimals = mint.base.decimals;
    drop(mint_data);

    // Pool PDA owns the vault, so we need pool seeds for signing
    let (_, pool_bump) =
        Pubkey::find_program_address(&[POOL_SEED, pool.mint.as_ref()], program_id);
    let pool_seeds = &[POOL_SEED, pool.mint.as_ref(), &[pool_bump]];

    invoke_signed(
        &spl_token_2022::instruction::transfer_checked(
            &spl_token_2022::id(),
            token_vault_info.key,
            mint_info.key,
            user_token_info.key,
            pool_info.key, // Pool is the owner/authority of the vault
            &[],
            amount,
            decimals,
        )?,
        &[
            token_vault_info.clone(),
            mint_info.clone(),
            user_token_info.clone(),
            pool_info.clone(),
        ],
        &[pool_seeds],
    )?;

    msg!("Unstaked {} tokens", amount);

    Ok(())
}

/// Unstake tokens from the pool (direct unstake when cooldown is 0)
///
/// Accounts:
/// 0. `[writable]` Pool account
/// 1. `[writable]` User stake account
/// 2. `[writable]` Token vault
/// 3. `[writable]` User token account
/// 4. `[]` Token mint
/// 5. `[writable, signer]` User/owner
/// 6. `[]` Token 2022 program
pub fn process_unstake(
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

    // If pool has a cooldown, reject direct unstake
    if pool.unstake_cooldown_seconds > 0 {
        return Err(StakingError::CooldownRequired.into());
    }

    // Verify token vault
    if pool.token_vault != *token_vault_info.key {
        return Err(StakingError::InvalidTokenVault.into());
    }

    // Load and validate user stake
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

    // Check sufficient balance
    if user_stake.amount < amount {
        return Err(StakingError::InsufficientStakeBalance.into());
    }

    // Block if pending unstake request
    if user_stake.has_pending_unstake_request() {
        return Err(StakingError::PendingUnstakeRequestExists.into());
    }

    // Check lock duration
    if pool.lock_duration_seconds > 0 {
        let clock = Clock::get()?;
        let current_time = clock.unix_timestamp;
        let last_stake = user_stake.effective_last_stake_time();
        let elapsed = current_time.saturating_sub(last_stake);
        if (elapsed as u64) < pool.lock_duration_seconds {
            return Err(StakingError::StakeLocked.into());
        }
    }

    // Execute the shared unstake logic
    execute_unstake(
        program_id,
        &mut pool,
        &mut user_stake,
        pool_info,
        user_stake_info,
        token_vault_info,
        user_token_info,
        mint_info,
        user_info,
        amount,
    )
}
