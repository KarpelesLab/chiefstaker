//! Claim rewards instruction

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    clock::Clock,
    entrypoint::ProgramResult,
    msg,
    pubkey::Pubkey,
    rent::Rent,
    sysvar::Sysvar,
};

use crate::{
    error::StakingError,
    math::{calculate_user_weighted_stake, wad_mul, WAD},
    state::{StakingPool, UserStake},
};

/// Claim accumulated SOL rewards
///
/// Accounts:
/// 0. `[writable]` Pool account (holds SOL rewards)
/// 1. `[writable]` User stake account
/// 2. `[writable, signer]` User/owner
pub fn process_claim_rewards(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();

    let pool_info = next_account_info(account_info_iter)?;
    let user_stake_info = next_account_info(account_info_iter)?;
    let user_info = next_account_info(account_info_iter)?;

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

    // Check user has a stake
    if user_stake.amount == 0 {
        return Err(StakingError::ZeroAmount.into());
    }

    let clock = Clock::get()?;
    let current_time = clock.unix_timestamp;

    // Calculate user's current weighted stake
    let user_weighted = calculate_user_weighted_stake(
        user_stake.amount,
        user_stake.exp_start_factor,
        current_time,
        pool.base_time,
        pool.tau_seconds,
    )?;

    if user_weighted == 0 {
        msg!("No rewards to claim (stake too new)");
        return Ok(());
    }

    // Calculate pending rewards
    // pending = user_weighted * acc_reward_per_weighted_share - reward_debt
    let accumulated = wad_mul(user_weighted, pool.acc_reward_per_weighted_share)?;
    let pending = accumulated.saturating_sub(user_stake.reward_debt);

    if pending == 0 {
        msg!("No pending rewards to claim");
        return Ok(());
    }

    // Convert from WAD-scaled to lamports
    let pending_lamports = pending / WAD;

    if pending_lamports == 0 {
        msg!("Pending rewards too small to claim");
        return Ok(());
    }

    // Check pool has sufficient balance (keep rent-exempt minimum)
    let rent = Rent::get()?;
    let rent_exempt_minimum = rent.minimum_balance(pool_info.data_len());
    let pool_lamports = pool_info.lamports();

    let available_rewards = pool_lamports.saturating_sub(rent_exempt_minimum);

    if available_rewards == 0 {
        return Err(StakingError::InsufficientRewardBalance.into());
    }

    let transfer_amount = pending_lamports.min(available_rewards as u128) as u64;

    // Transfer SOL from pool to user
    **pool_info.try_borrow_mut_lamports()? -= transfer_amount;
    **user_info.try_borrow_mut_lamports()? += transfer_amount;

    // Update reward debt to prevent double claiming
    user_stake.reward_debt = accumulated;

    // Update last_synced_lamports so sync_rewards doesn't miss new deposits
    pool.last_synced_lamports = pool.last_synced_lamports.saturating_sub(transfer_amount);

    // Save user stake
    {
        let mut stake_data = user_stake_info.try_borrow_mut_data()?;
        user_stake.serialize(&mut &mut stake_data[..])?;
    }

    // Save pool state
    {
        let mut pool_data = pool_info.try_borrow_mut_data()?;
        pool.serialize(&mut &mut pool_data[..])?;
    }

    msg!("Claimed {} lamports in rewards", transfer_amount);

    Ok(())
}
