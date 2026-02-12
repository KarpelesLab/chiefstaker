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

    // Verify pool PDA
    let (expected_pool, _) = StakingPool::derive_pda(&pool.mint, program_id);
    if *pool_info.key != expected_pool {
        return Err(StakingError::InvalidPDA.into());
    }

    // Check if pool needs rebasing
    if pool.get_sum_stake_exp().needs_rebase() {
        return Err(StakingError::PoolRequiresSync.into());
    }

    // Require cooldown to be configured; otherwise use direct Unstake
    if pool.unstake_cooldown_seconds == 0 {
        return Err(StakingError::CooldownNotConfigured.into());
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

    // Check no existing pending request
    if user_stake.has_pending_unstake_request() {
        return Err(StakingError::PendingUnstakeRequestExists.into());
    }

    // Lazily adjust exp_start_factor if pool has been rebased
    user_stake.sync_to_pool(&pool)?;

    // Check sufficient balance
    if user_stake.amount < amount {
        return Err(StakingError::InsufficientStakeBalance.into());
    }

    let clock = Clock::get()?;
    let current_time = clock.unix_timestamp;

    // Check lock duration has elapsed
    if pool.lock_duration_seconds > 0 {
        let last_stake = user_stake.effective_last_stake_time();
        let elapsed = current_time.saturating_sub(last_stake).max(0) as u64;
        if elapsed < pool.lock_duration_seconds {
            return Err(StakingError::StakeLocked.into());
        }
    }

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
