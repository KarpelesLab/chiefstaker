//! Deposit rewards instruction

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    clock::Clock,
    entrypoint::ProgramResult,
    msg,
    program::invoke,
    pubkey::Pubkey,
    rent::Rent,
    system_instruction,
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

/// Deposit SOL rewards into the pool
/// Anyone can call this (permissionless)
///
/// Accounts:
/// 0. `[writable]` Pool account (receives SOL)
/// 1. `[writable, signer]` Depositor
/// 2. `[]` System program
pub fn process_deposit_rewards(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    amount: u64,
) -> ProgramResult {
    if amount == 0 {
        return Err(StakingError::ZeroAmount.into());
    }

    let account_info_iter = &mut accounts.iter();

    let pool_info = next_account_info(account_info_iter)?;
    let depositor_info = next_account_info(account_info_iter)?;
    let system_program_info = next_account_info(account_info_iter)?;

    // Validate depositor is signer
    if !depositor_info.is_signer {
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

    let clock = Clock::get()?;
    let current_time = clock.unix_timestamp;

    // Calculate current total weighted stake
    let total_weighted = calculate_total_weighted_stake(
        pool.total_staked,
        &pool.get_sum_stake_exp(),
        current_time,
        pool.base_time,
        pool.tau_seconds,
    )?;

    let rent = Rent::get()?;
    let rent_exempt_minimum = rent.minimum_balance(pool_info.data_len());

    if total_weighted < MIN_WEIGHTED_STAKE_FOR_DISTRIBUTION {
        // Not enough weighted stake to distribute rewards safely.
        // Accept the deposit but do NOT update last_synced_lamports so the
        // rewards remain pending and will be distributed once sufficient
        // weight accumulates (via sync_rewards or a future deposit).
        invoke(
            &system_instruction::transfer(depositor_info.key, pool_info.key, amount),
            &[
                depositor_info.clone(),
                pool_info.clone(),
                system_program_info.clone(),
            ],
        )?;

        msg!(
            "Deposited {} lamports (deferred - weighted stake {} below threshold {})",
            amount,
            total_weighted,
            MIN_WEIGHTED_STAKE_FOR_DISTRIBUTION
        );
        return Ok(());
    }

    // Include any previously undistributed rewards (e.g., from deposits made
    // while total_weighted was below threshold) alongside this deposit.
    let current_available = pool_info.lamports().saturating_sub(rent_exempt_minimum);
    let undistributed = current_available.saturating_sub(pool.last_synced_lamports);
    let total_new_rewards = (amount as u64).saturating_add(undistributed);

    // Calculate reward per weighted share
    // reward_per_share = total_new_rewards * WAD / total_weighted
    let amount_wad = (total_new_rewards as u128)
        .checked_mul(WAD)
        .ok_or(StakingError::MathOverflow)?;
    let reward_per_share = wad_div(amount_wad, total_weighted)?;

    // Update accumulator
    pool.acc_reward_per_weighted_share = pool
        .acc_reward_per_weighted_share
        .checked_add(reward_per_share)
        .ok_or(StakingError::MathOverflow)?;

    pool.last_update_time = current_time;

    // Transfer SOL from depositor to pool (before serialization so lamports() is updated)
    invoke(
        &system_instruction::transfer(depositor_info.key, pool_info.key, amount),
        &[
            depositor_info.clone(),
            pool_info.clone(),
            system_program_info.clone(),
        ],
    )?;

    // Update last_synced_lamports so sync_rewards doesn't double-count
    pool.last_synced_lamports = pool_info.lamports().saturating_sub(rent_exempt_minimum);

    // Save pool state
    {
        let mut pool_data = pool_info.try_borrow_mut_data()?;
        pool.serialize(&mut &mut pool_data[..])?;
    }

    msg!(
        "Deposited {} lamports (distributed {} total), total_weighted: {}, reward_per_share: {}",
        amount,
        total_new_rewards,
        total_weighted,
        reward_per_share
    );

    Ok(())
}
