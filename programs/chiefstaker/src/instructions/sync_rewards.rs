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
    math::{calculate_total_weighted_stake, wad_div, WAD},
    state::StakingPool,
};

/// Minimum weighted stake required to distribute rewards
/// If total_weighted is below this, rewards are held until more weight accumulates
/// Set to 1 WAD (equivalent to 1 token with full weight)
const MIN_WEIGHTED_STAKE_FOR_DISTRIBUTION: u128 = WAD;

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

    let rent = Rent::get()?;
    let clock = Clock::get()?;
    let current_time = clock.unix_timestamp;

    // Calculate how much SOL is available for rewards
    let pool_lamports = pool_info.lamports();
    let rent_exempt_minimum = rent.minimum_balance(pool_info.data_len());

    // Track distributed rewards in the pool state
    // New field: last_known_lamports tracks what we've already accounted for
    let last_known = pool.last_synced_lamports;
    let current_available = pool_lamports.saturating_sub(rent_exempt_minimum);

    // New rewards = current balance - what we knew about
    let new_rewards = current_available.saturating_sub(last_known);

    if new_rewards == 0 {
        msg!("No new rewards to sync");
        return Ok(());
    }

    // Calculate current total weighted stake
    let total_weighted = calculate_total_weighted_stake(
        pool.total_staked,
        &pool.get_sum_stake_exp(),
        current_time,
        pool.base_time,
        pool.tau_seconds,
    )?;

    if total_weighted < MIN_WEIGHTED_STAKE_FOR_DISTRIBUTION {
        // Not enough weighted stake to distribute rewards safely.
        // Do NOT update last_synced_lamports so the rewards remain pending
        // and will be distributed once sufficient weight accumulates.
        msg!(
            "Rewards deferred: {} new lamports, weighted stake {} below threshold {}",
            new_rewards,
            total_weighted,
            MIN_WEIGHTED_STAKE_FOR_DISTRIBUTION
        );
        return Ok(());
    }

    // Calculate reward per weighted share
    let amount_wad = (new_rewards as u128)
        .checked_mul(WAD)
        .ok_or(StakingError::MathOverflow)?;
    let reward_per_share = wad_div(amount_wad, total_weighted)?;

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
