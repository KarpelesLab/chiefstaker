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
    math::{wad_div, WAD},
    state::StakingPool,
};

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

    // Verify pool PDA
    let (expected_pool, _) = StakingPool::derive_pda(&pool.mint, program_id);
    if *pool_info.key != expected_pool {
        return Err(StakingError::InvalidPDA.into());
    }

    let clock = Clock::get()?;
    let current_time = clock.unix_timestamp;

    let rent = Rent::get()?;
    let rent_exempt_minimum = rent.minimum_balance(pool_info.data_len());

    // Denominator: total_staked * WAD (max weight, not time-varying)
    let total_staked_wad = (pool.total_staked as u128)
        .checked_mul(WAD)
        .ok_or(StakingError::MathOverflow)?;

    if total_staked_wad == 0 {
        // No stakers to distribute to.
        // Accept the deposit but do NOT update last_synced_lamports so the
        // rewards remain pending and will be distributed once someone stakes.
        invoke(
            &system_instruction::transfer(depositor_info.key, pool_info.key, amount),
            &[
                depositor_info.clone(),
                pool_info.clone(),
                system_program_info.clone(),
            ],
        )?;

        msg!(
            "Deposited {} lamports (deferred - no stakers)",
            amount,
        );
        return Ok(());
    }

    // Include any previously undistributed rewards alongside this deposit.
    let current_available = pool_info.lamports().saturating_sub(rent_exempt_minimum);
    let undistributed = current_available.saturating_sub(pool.last_synced_lamports);
    let total_new_rewards = amount.saturating_add(undistributed);

    // Calculate reward per share using max weight denominator
    // reward_per_share = total_new_rewards * WAD / (total_staked * WAD)
    let amount_wad = (total_new_rewards as u128)
        .checked_mul(WAD)
        .ok_or(StakingError::MathOverflow)?;
    let reward_per_share = wad_div(amount_wad, total_staked_wad)?;

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
        "Deposited {} lamports (distributed {} total), total_staked: {}, reward_per_share: {}",
        amount,
        total_new_rewards,
        pool.total_staked,
        reward_per_share
    );

    Ok(())
}
