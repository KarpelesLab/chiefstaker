//! Recover stranded rewards instruction
//!
//! When users did additional stakes (before the round-7 fix), immature rewards
//! became permanently stranded — tracked in `last_synced_lamports` but not owed
//! to any staker.  This permissionless instruction computes the exact stranded
//! amount on-chain using only pool state (`total_reward_debt`), then marks the
//! excess as undistributed so the next `sync_rewards` redistributes it.

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    msg,
    pubkey::Pubkey,
};

use crate::{
    error::StakingError,
    math::{wad_mul, WAD},
    state::StakingPool,
};

/// Recover stranded rewards using only pool state.
///
/// Computes:
///   total_max_pending = wad_mul(total_staked * WAD, acc_rps) − total_reward_debt
///   total_owed_lamports = total_max_pending / WAD
///   stranded = last_synced_lamports − total_owed_lamports
///
/// Reduces `last_synced_lamports` so the next `sync_rewards` redistributes
/// the stranded amount to all stakers.
///
/// Permissionless — anyone can call this.
///
/// Accounts:
/// 0. `[writable]` Pool account
pub fn process_recover_stranded_rewards(
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

    // Must have stakers
    if pool.total_staked == 0 {
        msg!("No stakers in pool");
        return Ok(());
    }

    // Compute total max pending rewards (what would be owed if every stake was at max weight)
    // total_max_pending = wad_mul(total_staked * WAD, acc_rps) - total_reward_debt
    let total_staked_wad = (pool.total_staked)
        .checked_mul(WAD)
        .ok_or(StakingError::MathOverflow)?;
    let total_max_accumulated = wad_mul(total_staked_wad, pool.acc_reward_per_weighted_share)?;
    let total_max_pending = total_max_accumulated.saturating_sub(pool.total_reward_debt);

    // Convert to lamports (truncate WAD fraction)
    let total_owed_lamports = (total_max_pending / WAD) as u64;

    // Stranded = what the pool has synced minus what is actually owed at max weight
    let stranded = pool.last_synced_lamports.saturating_sub(total_owed_lamports);

    if stranded == 0 {
        msg!("No stranded rewards to recover");
        return Ok(());
    }

    pool.last_synced_lamports = pool.last_synced_lamports.saturating_sub(stranded);

    // Save pool state
    let mut pool_data = pool_info.try_borrow_mut_data()?;
    pool.serialize(&mut &mut pool_data[..])?;

    msg!(
        "Recovered {} stranded lamports for redistribution (last_synced now {})",
        stranded,
        pool.last_synced_lamports
    );

    Ok(())
}
