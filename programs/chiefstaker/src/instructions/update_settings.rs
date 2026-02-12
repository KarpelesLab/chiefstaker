//! Update pool settings instruction

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    msg,
    pubkey::Pubkey,
};

use crate::{
    error::StakingError,
    state::StakingPool,
};

/// Maximum lock duration: 365 days. Prevents authority from trapping stakers indefinitely.
const MAX_LOCK_DURATION_SECONDS: u64 = 365 * 24 * 60 * 60;

/// Maximum unstake cooldown: 30 days.
const MAX_UNSTAKE_COOLDOWN_SECONDS: u64 = 30 * 24 * 60 * 60;

/// Maximum min_stake_amount: 10^15 base units.
/// Prevents authority from setting it so high that new staking is effectively blocked.
/// (10^15 = 1M tokens at 9 decimals, generous for any realistic mint.)
const MAX_MIN_STAKE_AMOUNT: u64 = 1_000_000_000_000_000;

/// Update pool settings (authority only)
///
/// Accounts:
/// 0. `[writable]` Pool account
/// 1. `[signer]` Authority
pub fn process_update_pool_settings(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    min_stake_amount: Option<u64>,
    lock_duration_seconds: Option<u64>,
    unstake_cooldown_seconds: Option<u64>,
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();

    let pool_info = next_account_info(account_info_iter)?;
    let authority_info = next_account_info(account_info_iter)?;

    // Validate authority is signer
    if !authority_info.is_signer {
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

    // Check authority is not renounced
    if pool.is_authority_renounced() {
        return Err(StakingError::AuthorityRenounced.into());
    }

    // Verify authority
    if pool.authority != *authority_info.key {
        return Err(StakingError::InvalidAuthority.into());
    }

    // Apply settings (with caps to prevent authority abuse)
    if let Some(val) = min_stake_amount {
        if val > MAX_MIN_STAKE_AMOUNT {
            return Err(StakingError::SettingExceedsMaximum.into());
        }
        pool.min_stake_amount = val;
        msg!("Updated min_stake_amount to {}", val);
    }
    if let Some(val) = lock_duration_seconds {
        if val > MAX_LOCK_DURATION_SECONDS {
            return Err(StakingError::SettingExceedsMaximum.into());
        }
        pool.lock_duration_seconds = val;
        msg!("Updated lock_duration_seconds to {}", val);
    }
    if let Some(val) = unstake_cooldown_seconds {
        if val > MAX_UNSTAKE_COOLDOWN_SECONDS {
            return Err(StakingError::SettingExceedsMaximum.into());
        }
        pool.unstake_cooldown_seconds = val;
        msg!("Updated unstake_cooldown_seconds to {}", val);
    }

    // Save pool state
    let mut pool_data = pool_info.try_borrow_mut_data()?;
    pool.serialize(&mut &mut pool_data[..])?;

    msg!("Pool settings updated");
    Ok(())
}
