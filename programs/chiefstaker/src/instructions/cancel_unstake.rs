//! Cancel unstake request instruction

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    msg,
    pubkey::Pubkey,
};

use crate::{
    error::StakingError,
    math::{wad_mul, U256, WAD},
    state::{StakingPool, UserStake},
};

/// Cancel a pending unstake request, restoring the frozen coins to the active
/// staking position so they earn rewards again.
///
/// RequestUnstake removed the frozen coins from the pool's reward accounting. This
/// adds them back: total_staked and sum_stake_exp are restored (re-granting the
/// weight at the original maturity, since exp_start_factor is unchanged), and the
/// re-added tokens receive a fresh reward snapshot so they do not retroactively
/// claim rewards distributed during the cooldown (mirrors add-stake).
///
/// Accounts:
/// 0. `[writable]` Pool account
/// 1. `[writable]` User stake account
/// 2. `[signer]` User/owner
/// 3. `[]` System program (optional, for legacy account reallocation)
pub fn process_cancel_unstake_request(
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

    // Check if pool needs rebasing (we are about to grow sum_stake_exp)
    if pool.get_sum_stake_exp().needs_rebase() {
        return Err(StakingError::PoolRequiresSync.into());
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

    // Check there is a pending request
    if !user_stake.has_pending_unstake_request() {
        return Err(StakingError::NoPendingUnstakeRequest.into());
    }

    // Lazily adjust exp_start_factor if pool has been rebased
    user_stake.sync_to_pool(&pool)?;

    let frozen = user_stake.unstake_request_amount;

    if user_stake.unstake_request_settled == 1 {
        // New-style request: RequestUnstake removed the frozen coins from the pool
        // and settled their rewards. Restore them to the active position.

        // Edge case: a full unstake request (amount == 0) that still has unpaid
        // residual rewards stores those in reward_debt. Reactivating the position
        // would overwrite that storage with a snapshot, losing the residual.
        // Require the user to claim it first (ClaimRewards works on amount==0).
        if user_stake.amount == 0 && user_stake.reward_debt / WAD > 0 {
            return Err(StakingError::ResidualRewardsPending.into());
        }

        let frozen_wad = (frozen as u128)
            .checked_mul(WAD)
            .ok_or(StakingError::MathOverflow)?;

        // sum_stake_exp += frozen * exp_start_factor (restores weight / maturity)
        let contribution = wad_mul(frozen_wad, user_stake.exp_start_factor)?;
        let new_sum = pool
            .get_sum_stake_exp()
            .checked_add(U256::from_u128(contribution))
            .ok_or(StakingError::MathOverflow)?;
        pool.set_sum_stake_exp(new_sum);

        // total_staked += frozen
        pool.total_staked = pool
            .total_staked
            .checked_add(frozen as u128)
            .ok_or(StakingError::MathOverflow)?;

        // Fresh reward snapshot for the re-added tokens (no retroactive rewards)
        let new_token_debt = wad_mul(frozen_wad, pool.acc_reward_per_weighted_share)?;

        if user_stake.amount == 0 {
            // Was a full request (no residual remains): start clean.
            user_stake.reward_debt = new_token_debt;
            user_stake.claimed_rewards_wad = 0;
        } else {
            // Partial request: keep the active remainder's pending intact and add a
            // fresh debt snapshot for the re-added tokens (mirrors add-stake).
            user_stake.reward_debt = user_stake
                .reward_debt
                .checked_add(new_token_debt)
                .ok_or(StakingError::MathOverflow)?;
        }

        user_stake.amount = user_stake
            .amount
            .checked_add(frozen)
            .ok_or(StakingError::MathOverflow)?;

        pool.total_reward_debt = pool
            .total_reward_debt
            .checked_add(new_token_debt)
            .ok_or(StakingError::MathOverflow)?;
    } else {
        // Legacy in-flight request (created before this upgrade): the coins were
        // never removed from the pool's accounting, so there is nothing to restore
        // — adding them back here would credit the user stake they never lost.
        // Just clear the request, matching the pre-upgrade cancel behavior.
    }

    // Clear the request fields
    user_stake.unstake_request_amount = 0;
    user_stake.unstake_request_time = 0;
    user_stake.unstake_request_settled = 0;

    // Save pool and user stake
    {
        let mut pool_data = pool_info.try_borrow_mut_data()?;
        pool.serialize(&mut &mut pool_data[..])?;
    }
    {
        let mut stake_data = user_stake_info.try_borrow_mut_data()?;
        user_stake.serialize(&mut &mut stake_data[..])?;
    }

    msg!("Cancelled unstake request for {} tokens", frozen);

    Ok(())
}
