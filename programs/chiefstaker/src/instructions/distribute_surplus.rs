//! Fix user stake account instruction (program upgrade authority only)
//!
//! Corrects a user's exp_start_factor and reward_debt that were corrupted by
//! the old add-stake bug (which blended exp_start_factor and reset reward_debt
//! on every add-stake). The authority computes the correct values off-chain
//! and passes them here.
//!
//! After the fix, the user can claim their corrected rewards via normal
//! ClaimRewards.

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    bpf_loader_upgradeable,
    entrypoint::ProgramResult,
    msg,
    pubkey::Pubkey,
};

use crate::{
    error::StakingError,
    math::{wad_mul, U256, WAD},
    state::{StakingPool, UserStake},
};

/// Fix a user's stake account corrupted by the add-stake blending bug.
///
/// Sets exp_start_factor and reward_debt to their correct values, and
/// updates pool-level aggregates (sum_stake_exp, total_reward_debt).
///
/// Accounts:
/// 0. `[writable]` Pool account
/// 1. `[writable]` User stake account (PDA: ["stake", pool, owner])
/// 2. `[signer]`   Program upgrade authority
/// 3. `[]`         ProgramData account (derived from program_id)
pub fn process_fix_stake_account(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    new_exp_start_factor: u128,
    new_reward_debt: u128,
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();

    let pool_info = next_account_info(account_info_iter)?;
    let user_stake_info = next_account_info(account_info_iter)?;
    let authority_info = next_account_info(account_info_iter)?;
    let programdata_info = next_account_info(account_info_iter)?;

    // ── Verify program upgrade authority ──────────────────────────────

    if !authority_info.is_signer {
        return Err(StakingError::MissingRequiredSigner.into());
    }

    let (expected_programdata, _) = Pubkey::find_program_address(
        &[program_id.as_ref()],
        &bpf_loader_upgradeable::id(),
    );
    if *programdata_info.key != expected_programdata {
        return Err(StakingError::InvalidPDA.into());
    }
    if programdata_info.owner != &bpf_loader_upgradeable::id() {
        return Err(StakingError::InvalidAccountOwner.into());
    }

    let programdata_data = programdata_info.try_borrow_data()?;
    if programdata_data.len() < 45 {
        return Err(StakingError::InvalidInstruction.into());
    }
    if programdata_data[12] != 1 {
        msg!("Program is immutable (no upgrade authority)");
        return Err(StakingError::AuthorityRenounced.into());
    }
    let upgrade_authority = Pubkey::try_from(&programdata_data[13..45])
        .map_err(|_| StakingError::InvalidInstruction)?;
    if *authority_info.key != upgrade_authority {
        return Err(StakingError::InvalidAuthority.into());
    }

    // ── Load and validate pool ───────────────────────────────────────

    if pool_info.owner != program_id {
        return Err(StakingError::InvalidAccountOwner.into());
    }
    let mut pool = StakingPool::try_from_slice(&pool_info.try_borrow_data()?)?;
    if !pool.is_initialized() {
        return Err(StakingError::NotInitialized.into());
    }

    let (expected_pool, _) = StakingPool::derive_pda(&pool.mint, program_id);
    if *pool_info.key != expected_pool {
        return Err(StakingError::InvalidPDA.into());
    }

    // ── Load and validate user stake ─────────────────────────────────

    if user_stake_info.owner != program_id {
        return Err(StakingError::InvalidAccountOwner.into());
    }
    let mut user_stake = UserStake::try_from_slice(&user_stake_info.try_borrow_data()?)?;
    if !user_stake.is_initialized() {
        return Err(StakingError::NotInitialized.into());
    }
    if user_stake.pool != *pool_info.key {
        return Err(StakingError::InvalidPool.into());
    }
    if user_stake.amount == 0 {
        msg!("User has no active stake");
        return Err(StakingError::InsufficientStakeBalance.into());
    }

    let amount_wad = (user_stake.amount as u128)
        .checked_mul(WAD)
        .ok_or(StakingError::MathOverflow)?;

    // ── Update sum_stake_exp ─────────────────────────────────────────

    let old_exp = user_stake.exp_start_factor;
    if new_exp_start_factor != old_exp {
        let old_contribution = wad_mul(amount_wad, old_exp)?;
        let new_contribution = wad_mul(amount_wad, new_exp_start_factor)?;

        let mut sum = pool.get_sum_stake_exp();
        if new_contribution >= old_contribution {
            let delta = U256::from_u128(new_contribution - old_contribution);
            sum = sum.checked_add(delta).ok_or(StakingError::MathOverflow)?;
        } else {
            let delta = U256::from_u128(old_contribution - new_contribution);
            sum = sum.saturating_sub(delta);
        }
        pool.set_sum_stake_exp(sum);

        user_stake.exp_start_factor = new_exp_start_factor;
        msg!(
            "Fixed exp_start_factor: {} -> {}",
            old_exp,
            new_exp_start_factor
        );
    }

    // ── Update reward_debt ───────────────────────────────────────────

    let old_debt = user_stake.reward_debt;
    if new_reward_debt != old_debt {
        if new_reward_debt >= old_debt {
            pool.total_reward_debt = pool
                .total_reward_debt
                .checked_add(new_reward_debt - old_debt)
                .ok_or(StakingError::MathOverflow)?;
        } else {
            pool.total_reward_debt = pool
                .total_reward_debt
                .saturating_sub(old_debt - new_reward_debt);
        }

        user_stake.reward_debt = new_reward_debt;
        msg!("Fixed reward_debt: {} -> {}", old_debt, new_reward_debt);
    }

    // ── Save ─────────────────────────────────────────────────────────

    {
        let mut stake_data = user_stake_info.try_borrow_mut_data()?;
        user_stake.serialize(&mut &mut stake_data[..])?;
    }
    {
        let mut pool_data = pool_info.try_borrow_mut_data()?;
        pool.serialize(&mut &mut pool_data[..])?;
    }

    msg!(
        "Fixed stake account for user {}",
        user_stake.owner
    );

    Ok(())
}
