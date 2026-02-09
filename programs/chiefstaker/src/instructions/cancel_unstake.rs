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
    state::{StakingPool, UserStake},
};

/// Cancel a pending unstake request
///
/// Accounts:
/// 0. `[]` Pool account
/// 1. `[writable]` User stake account
/// 2. `[signer]` User/owner
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

    // Verify user stake PDA
    let (expected_stake, _) =
        UserStake::derive_pda(pool_info.key, user_info.key, program_id);
    if *user_stake_info.key != expected_stake {
        return Err(StakingError::InvalidPDA.into());
    }

    // Lazily adjust exp_start_factor if pool has been rebased
    user_stake.sync_to_pool(&pool)?;

    // Check there is a pending request
    if !user_stake.has_pending_unstake_request() {
        return Err(StakingError::NoPendingUnstakeRequest.into());
    }

    let cancelled_amount = user_stake.unstake_request_amount;

    // Clear the request fields
    user_stake.unstake_request_amount = 0;
    user_stake.unstake_request_time = 0;

    // Save user stake
    let mut stake_data = user_stake_info.try_borrow_mut_data()?;
    user_stake.serialize(&mut &mut stake_data[..])?;

    msg!("Cancelled unstake request for {} tokens", cancelled_amount);

    Ok(())
}
