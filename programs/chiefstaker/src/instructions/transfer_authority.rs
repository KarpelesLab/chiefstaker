//! Transfer authority instruction

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

/// Transfer pool authority to a new address
/// Setting new_authority to Pubkey::default() renounces authority (irreversible)
///
/// Accounts:
/// 0. `[writable]` Pool account
/// 1. `[signer]` Current authority
pub fn process_transfer_authority(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    new_authority: Pubkey,
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

    // Check authority is not already renounced
    if pool.is_authority_renounced() {
        return Err(StakingError::AuthorityRenounced.into());
    }

    // Verify current authority
    if pool.authority != *authority_info.key {
        return Err(StakingError::InvalidAuthority.into());
    }

    // Transfer authority
    pool.authority = new_authority;

    // Save pool state
    let mut pool_data = pool_info.try_borrow_mut_data()?;
    pool.serialize(&mut &mut pool_data[..])?;

    if new_authority == Pubkey::default() {
        msg!("Authority renounced (irreversible)");
    } else {
        msg!("Authority transferred to {}", new_authority);
    }

    Ok(())
}
