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
    events::{emit_reward_payout, RewardPayoutType},
    math::{calculate_user_weighted_stake, wad_div, wad_mul, WAD},
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

    // Verify pool PDA
    let (expected_pool, _) = StakingPool::derive_pda(&pool.mint, program_id);
    if *pool_info.key != expected_pool {
        return Err(StakingError::InvalidPDA.into());
    }

    // Check if pool needs rebasing
    if pool.get_sum_stake_exp().needs_rebase() {
        return Err(StakingError::PoolRequiresSync.into());
    }

    // Realloc legacy accounts to current size (payer = user)
    UserStake::maybe_realloc(user_stake_info, user_info)?;

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

    // Handle two claim paths:
    // 1. amount > 0: normal claim using snapshot-delta formula
    // 2. amount == 0 with reward_debt > 0: residual rewards from full unstake
    //    (when pool lacked SOL at unstake time, unpaid rewards are stored in reward_debt)
    let (pending, is_residual_claim) = if user_stake.amount == 0 {
        // Post-full-unstake: reward_debt stores unclaimed WAD-scaled rewards
        if user_stake.reward_debt == 0 {
            msg!("No rewards to claim");
            return Ok(());
        }
        (user_stake.reward_debt, true)
    } else {
        // Normal claim path: compute pending from time-weighted stake

        // Lazily adjust exp_start_factor if pool has been rebased
        user_stake.sync_to_pool(&pool)?;

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

        // Full entitlement: user_weighted * (acc_rps - snapshot)
        // where snapshot = reward_debt / (amount * WAD)
        let amount_wad = (user_stake.amount as u128)
            .checked_mul(WAD)
            .ok_or(StakingError::MathOverflow)?;
        let snapshot = wad_div(user_stake.reward_debt, amount_wad)?;
        let delta_rps = pool.acc_reward_per_weighted_share.saturating_sub(snapshot);
        let full_entitlement = wad_mul(user_weighted, delta_rps)?;

        // Subtract already-claimed amount to get pending (frequency-independent)
        let p = full_entitlement.saturating_sub(user_stake.claimed_rewards_wad);

        if p == 0 {
            msg!("No pending rewards to claim");
            return Ok(());
        }
        (p, false)
    };

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

    let paid_wad = (transfer_amount as u128)
        .checked_mul(WAD)
        .ok_or(StakingError::MathOverflow)?;

    if is_residual_claim {
        // Residual claim (amount==0): reward_debt IS the unclaimed amount, so subtract
        user_stake.reward_debt = user_stake.reward_debt.saturating_sub(paid_wad);
        // Residual debts are tracked in total_residual_unpaid (not total_reward_debt)
        pool.total_residual_unpaid = pool.total_residual_unpaid.saturating_sub(transfer_amount);
    } else {
        // Track cumulative claimed amount (no snapshot reset).
        // Snapshot stays fixed so weight maturation isn't forfeited on claim.
        // Same-block double-claim yields 0: full_entitlement - claimed_rewards_wad = 0.
        user_stake.claimed_rewards_wad = user_stake.claimed_rewards_wad
            .checked_add(paid_wad)
            .ok_or(StakingError::MathOverflow)?;
    }

    // Update last_synced_lamports so sync_rewards doesn't miss new deposits
    pool.last_synced_lamports = pool.last_synced_lamports.saturating_sub(transfer_amount);

    // Increment cumulative rewards counter
    user_stake.total_rewards_claimed = user_stake.total_rewards_claimed.saturating_add(transfer_amount);

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

    if is_residual_claim {
        msg!("Claimed {} lamports in residual rewards", transfer_amount);
    } else {
        msg!("Claimed {} lamports in rewards", transfer_amount);
    }

    emit_reward_payout(pool_info.key, user_info.key, transfer_amount, RewardPayoutType::Claim);

    Ok(())
}
