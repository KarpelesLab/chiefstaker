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
    events::{emit_reward_payout, RewardPayoutType},
    state::{StakingPool, UserStake},
};

use super::unstake::settle_unstake_accounting;

/// Request unstake - starts the cooldown period.
///
/// The requested coins stop earning rewards immediately: their stake and weight
/// are removed from the pool (so they no longer share in new rewards), and the
/// rewards they have already earned are settled and paid out now. Only the token
/// transfer is deferred to CompleteUnstake — the tokens stay in the vault until
/// the cooldown elapses. A pending request can be reversed with CancelUnstake,
/// which restores the frozen coins to the active position.
///
/// Accounts:
/// 0. `[writable]` Pool account
/// 1. `[writable]` User stake account
/// 2. `[writable, signer]` User/owner (receives settled reward SOL)
/// 3. `[]` System program (optional, for legacy account reallocation)
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

    // Require cooldown to be configured; otherwise use direct Unstake
    if pool.unstake_cooldown_seconds == 0 {
        return Err(StakingError::CooldownNotConfigured.into());
    }

    // Realloc legacy accounts to current size (payer = user)
    // System program is optional trailing account, only needed for legacy accounts
    let system_program_info = account_info_iter.next();
    UserStake::maybe_realloc(user_stake_info, user_info, system_program_info)?;

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

    // Settle and remove the requested coins from the pool's reward accounting so
    // they stop earning during the cooldown. This pays out their already-earned
    // rewards and reduces user_stake.amount to the still-active remainder; the
    // requested tokens remain in the vault until CompleteUnstake.
    let reward_transfer_amount = settle_unstake_accounting(
        &mut pool,
        &mut user_stake,
        pool_info,
        user_stake_info,
        user_info,
        amount,
        current_time,
        system_program_info,
    )?;

    // Record the pending request (the frozen amount awaiting withdrawal).
    // Mark it as settled-at-request so Cancel/Complete know the coins were already
    // removed from the pool here (distinguishes new requests from legacy in-flight
    // requests created before this upgrade).
    user_stake.unstake_request_amount = amount;
    user_stake.unstake_request_time = current_time;
    user_stake.unstake_request_settled = 1;

    // Save pool and user stake
    {
        let mut pool_data = pool_info.try_borrow_mut_data()?;
        pool.serialize(&mut &mut pool_data[..])?;
    }
    {
        let mut stake_data = user_stake_info.try_borrow_mut_data()?;
        user_stake.serialize(&mut &mut stake_data[..])?;
    }

    // Pay out settled rewards (no token CPI here, so SOL can move directly)
    if reward_transfer_amount > 0 {
        **pool_info.try_borrow_mut_lamports()? -= reward_transfer_amount;
        **user_info.try_borrow_mut_lamports()? += reward_transfer_amount;
        msg!("Claimed {} lamports in rewards", reward_transfer_amount);
        emit_reward_payout(pool_info.key, user_info.key, reward_transfer_amount, RewardPayoutType::Unstake);
    }

    msg!(
        "Unstake request created for {} tokens, cooldown {} seconds",
        amount,
        pool.unstake_cooldown_seconds
    );

    Ok(())
}
