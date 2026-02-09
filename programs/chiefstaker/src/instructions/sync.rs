//! Sync/rebase pool instruction

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    clock::Clock,
    entrypoint::ProgramResult,
    msg,
    pubkey::Pubkey,
    sysvar::Sysvar,
};

use crate::{
    error::StakingError,
    math::{exp_neg_time_ratio, wad_mul_u256, U256},
    state::StakingPool,
};

/// Sync/rebase the pool to prevent overflow
/// This shifts base_time forward and scales down sum_stake_exp
///
/// Anyone can call this (permissionless crank)
///
/// Accounts:
/// 0. `[writable]` Pool account
pub fn process_sync_pool(
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

    let clock = Clock::get()?;
    let current_time = clock.unix_timestamp;

    // Calculate time delta since base_time
    let time_delta = current_time.saturating_sub(pool.base_time);

    if time_delta <= 0 {
        msg!("No time has passed since base_time");
        return Ok(());
    }

    // Record the original base_time before first rebase so legacy UserStake
    // accounts can be lazily adjusted (their exp_start_factor is relative
    // to the initial base_time).
    if pool.initial_base_time == 0 {
        pool.initial_base_time = pool.base_time;
    }

    // Calculate the decay factor: e^(-time_delta / tau)
    // For very large time_delta (> 87*tau), exp_neg_time_ratio returns 0,
    // meaning all stakes are fully matured and sum_stake_exp zeroes out.
    let decay_factor = exp_neg_time_ratio(time_delta, pool.tau_seconds)?;

    // Scale down sum_stake_exp by decay factor
    // new_sum_stake_exp = old_sum_stake_exp * decay_factor / WAD
    let sum_stake_exp = pool.get_sum_stake_exp();
    let decay_u256 = U256::from_u128(decay_factor);
    let new_sum_stake_exp = wad_mul_u256(sum_stake_exp, decay_u256)?;

    // Update pool state
    pool.set_sum_stake_exp(new_sum_stake_exp);
    pool.base_time = current_time;

    // Save pool state
    let mut pool_data = pool_info.try_borrow_mut_data()?;
    pool.serialize(&mut &mut pool_data[..])?;

    msg!(
        "Synced pool: base_time updated to {}, sum_stake_exp reduced by factor {}",
        current_time,
        decay_factor
    );

    Ok(())
}
