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
    _program_id: &Pubkey,
    pool: &mut StakingPool,
    user_stake: &mut UserStake,
    pool_info: &AccountInfo<'a>,
    user_stake_info: &AccountInfo<'a>,
    token_vault_info: &AccountInfo<'a>,
    user_token_info: &AccountInfo<'a>,
    mint_info: &AccountInfo<'a>,
    user_info: &AccountInfo<'a>,
    amount: u64,
    current_time: i64,
) -> ProgramResult {

    // Calculate pending rewards (but defer SOL transfer until after token CPI,
    // because the Solana runtime verifies CPI account balances and user_info
    // is not a CPI account)
    let mut reward_transfer_amount: u64 = 0;

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

    // Track unpaid rewards (WAD-scaled) to carry forward in reward_debt
    let mut unpaid_rewards_wad: u128 = 0;

    if total_weighted > 0 && user_weighted > 0 {
        let pending = wad_mul(user_weighted, pool.acc_reward_per_weighted_share)?
            .saturating_sub(user_stake.reward_debt);

        if pending > 0 {
            let pending_lamports = pending / WAD;

            if pending_lamports > 0 {
                let pool_lamports = pool_info.lamports();
                let rent_exempt_minimum = solana_program::rent::Rent::get()?
                    .minimum_balance(pool_info.data_len());

                let available_rewards = pool_lamports.saturating_sub(rent_exempt_minimum);
                reward_transfer_amount = pending_lamports.min(available_rewards as u128) as u64;

                // Track unpaid portion so it remains claimable later
                let paid_wad = (reward_transfer_amount as u128)
                    .checked_mul(WAD)
                    .ok_or(StakingError::MathOverflow)?;
                unpaid_rewards_wad = pending.saturating_sub(paid_wad);

                // Pre-update last_synced_lamports (actual SOL transfer deferred to after CPI)
                if reward_transfer_amount > 0 {
                    pool.last_synced_lamports = pool.last_synced_lamports.saturating_sub(reward_transfer_amount);
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

    // Update pool sum_stake_exp (saturating to handle rounding drift)
    let new_sum = pool
        .get_sum_stake_exp()
        .saturating_sub(U256::from_u128(unstake_contribution));
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

    // Recalculate reward debt for remaining stake using max weight, preserving any unpaid rewards
    if user_stake.amount > 0 {
        let remaining_amount_wad = (user_stake.amount as u128)
            .checked_mul(WAD)
            .ok_or(StakingError::MathOverflow)?;
        let base_debt = wad_mul(remaining_amount_wad, pool.acc_reward_per_weighted_share)?;
        // Subtract unpaid rewards so they remain claimable
        user_stake.reward_debt = base_debt.saturating_sub(unpaid_rewards_wad);
    } else {
        user_stake.reward_debt = 0;
    }

    // Save states (before CPI — pool data includes pre-updated last_synced_lamports)
    {
        let mut pool_data = pool_info.try_borrow_mut_data()?;
        pool.serialize(&mut &mut pool_data[..])?;
    }
    {
        let mut stake_data = user_stake_info.try_borrow_mut_data()?;
        user_stake.serialize(&mut &mut stake_data[..])?;
    }

    // Transfer tokens from vault to user (CPI)
    let mint_data = mint_info.try_borrow_data()?;
    let mint = StateWithExtensions::<spl_token_2022::state::Mint>::unpack(&mint_data)?;
    let decimals = mint.base.decimals;
    drop(mint_data);

    let pool_seeds = &[POOL_SEED, pool.mint.as_ref(), &[pool.bump]];

    invoke_signed(
        &spl_token_2022::instruction::transfer_checked(
            &spl_token_2022::id(),
            token_vault_info.key,
            mint_info.key,
            user_token_info.key,
            pool_info.key,
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

    // Transfer SOL rewards AFTER token CPI to avoid CPI balance check failure
    // (pool_info is a CPI account but user_info is not)
    if reward_transfer_amount > 0 {
        **pool_info.try_borrow_mut_lamports()? -= reward_transfer_amount;
        **user_info.try_borrow_mut_lamports()? += reward_transfer_amount;
        msg!("Claimed {} lamports in rewards", reward_transfer_amount);
    }

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

    // Verify pool PDA
    let (expected_pool, _) = StakingPool::derive_pda(&pool.mint, program_id);
    if *pool_info.key != expected_pool {
        return Err(StakingError::InvalidPDA.into());
    }

    // Check if pool needs rebasing
    if pool.get_sum_stake_exp().needs_rebase() {
        return Err(StakingError::PoolRequiresSync.into());
    }

    // If pool has a cooldown, reject direct unstake
    if pool.unstake_cooldown_seconds > 0 {
        return Err(StakingError::CooldownRequired.into());
    }

    // Verify mint matches pool
    if pool.mint != *mint_info.key {
        return Err(StakingError::InvalidPoolMint.into());
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

    // Verify user stake PDA
    let (expected_stake, _) =
        UserStake::derive_pda(pool_info.key, user_info.key, program_id);
    if *user_stake_info.key != expected_stake {
        return Err(StakingError::InvalidPDA.into());
    }

    // Check sufficient balance
    if user_stake.amount < amount {
        return Err(StakingError::InsufficientStakeBalance.into());
    }

    // Block if pending unstake request
    if user_stake.has_pending_unstake_request() {
        return Err(StakingError::PendingUnstakeRequestExists.into());
    }

    // Lazily adjust exp_start_factor if pool has been rebased
    user_stake.sync_to_pool(&pool)?;

    let clock = Clock::get()?;
    let current_time = clock.unix_timestamp;

    // Check lock duration
    if pool.lock_duration_seconds > 0 {
        let last_stake = user_stake.effective_last_stake_time();
        let elapsed = current_time.saturating_sub(last_stake).max(0) as u64;
        if elapsed < pool.lock_duration_seconds {
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
        current_time,
    )
}
