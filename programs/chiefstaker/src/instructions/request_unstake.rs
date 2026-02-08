//! Request unstake instruction (starts cooldown period)

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
    state::{StakingPool, UserStake},
};

/// Request unstake - starts cooldown period. Tokens remain staked and earn rewards.
///
/// Accounts:
/// 0. `[writable]` Pool account
/// 1. `[writable]` User stake account
/// 2. `[signer]` User/owner
pub fn process_request_unstake(
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
    let user_info = next_account_info(account_info_iter)?;

    // Validate user is signer
    if !user_info.is_signer {
        return Err(StakingError::MissingRequiredSigner.into());
    }

    // Load and validate pool
    if pool_info.owner != program_id {
        return Err(StakingError::InvalidAccountOwner.into());
    }
    let pool = StakingPool::try_from_slice(&pool_info.try_borrow_data()?)?;
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

    // Check no existing pending request
    if user_stake.has_pending_unstake_request() {
        return Err(StakingError::PendingUnstakeRequestExists.into());
    }

    // Check sufficient balance
    if user_stake.amount < amount {
        return Err(StakingError::InsufficientStakeBalance.into());
    }

    // Check lock duration has elapsed
    if pool.lock_duration_seconds > 0 {
        let clock = Clock::get()?;
        let current_time = clock.unix_timestamp;
        let last_stake = user_stake.effective_last_stake_time();
        let elapsed = current_time.saturating_sub(last_stake);
        if (elapsed as u64) < pool.lock_duration_seconds {
            return Err(StakingError::StakeLocked.into());
        }
    }

    let clock = Clock::get()?;
    let current_time = clock.unix_timestamp;

    // Set unstake request fields
    user_stake.unstake_request_amount = amount;
    user_stake.unstake_request_time = current_time;

    // Save user stake
    let mut stake_data = user_stake_info.try_borrow_mut_data()?;
    user_stake.serialize(&mut &mut stake_data[..])?;

    msg!(
        "Unstake request created for {} tokens, cooldown {} seconds",
        amount,
        pool.unstake_cooldown_seconds
    );

    Ok(())
}
