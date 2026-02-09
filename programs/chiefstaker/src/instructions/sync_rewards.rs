//! Sync rewards instruction - distributes SOL sent directly to pool
//!
//! This allows external sources (like pump.fun) to send SOL directly
//! to the pool PDA, and anyone can call this to distribute it.

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
    math::{wad_div, WAD},
    state::StakingPool,
};

/// Sync rewards that were sent directly to the pool account
/// This is a permissionless crank that anyone can call
///
/// Accounts:
/// 0. `[writable]` Pool account
pub fn process_sync_rewards(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let pool_info = next_account_info(account_info_iter)?;

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

    let rent = Rent::get()?;
    let clock = Clock::get()?;
    let current_time = clock.unix_timestamp;

    // Calculate how much SOL is available for rewards
    let pool_lamports = pool_info.lamports();
    let rent_exempt_minimum = rent.minimum_balance(pool_info.data_len());

    let last_known = pool.last_synced_lamports;
    let current_available = pool_lamports.saturating_sub(rent_exempt_minimum);

    // New rewards = current balance - what we knew about
    let new_rewards = current_available.saturating_sub(last_known);

    if new_rewards == 0 {
        msg!("No new rewards to sync");
        return Ok(());
    }

    // Denominator: total_staked * WAD (max weight, not time-varying)
    let total_staked_wad = (pool.total_staked as u128)
        .checked_mul(WAD)
        .ok_or(StakingError::MathOverflow)?;

    if total_staked_wad == 0 {
        // No stakers to distribute to. Leave rewards pending.
        msg!(
            "Rewards deferred: {} new lamports, no stakers",
            new_rewards,
        );
        return Ok(());
    }

    // Calculate reward per share using max weight denominator
    let amount_wad = (new_rewards as u128)
        .checked_mul(WAD)
        .ok_or(StakingError::MathOverflow)?;
    let reward_per_share = wad_div(amount_wad, total_staked_wad)?;

    // Update accumulator
    pool.acc_reward_per_weighted_share = pool
        .acc_reward_per_weighted_share
        .checked_add(reward_per_share)
        .ok_or(StakingError::MathOverflow)?;

    pool.last_update_time = current_time;
    pool.last_synced_lamports = current_available;

    // Save pool state
    let mut pool_data = pool_info.try_borrow_mut_data()?;
    pool.serialize(&mut &mut pool_data[..])?;

    msg!(
        "Synced {} lamports of new rewards, reward_per_share: {}",
        new_rewards,
        reward_per_share
    );

    Ok(())
}
