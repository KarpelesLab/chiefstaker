//! Complete unstake instruction (after cooldown period has elapsed)

use borsh::BorshDeserialize;
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    clock::Clock,
    entrypoint::ProgramResult,
    pubkey::Pubkey,
    sysvar::Sysvar,
};

use crate::{
    error::StakingError,
    state::{StakingPool, UserStake},
};

use super::unstake::execute_unstake;

/// Complete unstake after cooldown has elapsed
///
/// Accounts (same as Unstake):
/// 0. `[writable]` Pool account
/// 1. `[writable]` User stake account
/// 2. `[writable]` Token vault
/// 3. `[writable]` User token account
/// 4. `[]` Token mint
/// 5. `[writable, signer]` User/owner
/// 6. `[]` Token 2022 program
pub fn process_complete_unstake(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();

    let pool_info = next_account_info(account_info_iter)?;
    let user_stake_info = next_account_info(account_info_iter)?;
    let token_vault_info = next_account_info(account_info_iter)?;
    let user_token_info = next_account_info(account_info_iter)?;
    let mint_info = next_account_info(account_info_iter)?;
    let user_info = next_account_info(account_info_iter)?;
    let _token_program_info = next_account_info(account_info_iter)?;

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

    // Verify mint matches pool
    if pool.mint != *mint_info.key {
        return Err(StakingError::InvalidPoolMint.into());
    }

    // Verify token vault
    if pool.token_vault != *token_vault_info.key {
        return Err(StakingError::InvalidTokenVault.into());
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

    // Check there is a pending request
    if !user_stake.has_pending_unstake_request() {
        return Err(StakingError::NoPendingUnstakeRequest.into());
    }

    // Check cooldown has elapsed
    let clock = Clock::get()?;
    let current_time = clock.unix_timestamp;
    let elapsed = current_time.saturating_sub(user_stake.unstake_request_time);
    if (elapsed as u64) < pool.unstake_cooldown_seconds {
        return Err(StakingError::CooldownNotElapsed.into());
    }

    let amount = user_stake.unstake_request_amount;

    // Clear the request fields before execute_unstake (which serializes)
    user_stake.unstake_request_amount = 0;
    user_stake.unstake_request_time = 0;

    // Execute the shared unstake logic
    execute_unstake(
        program_id,
        &mut pool,
        &mut user_stake,
        pool_info,
        user_stake_info,
        token_vault_info,
        user_token_info,
        mint_info,
        user_info,
        amount,
    )
}
