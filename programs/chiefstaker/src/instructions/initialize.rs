//! Initialize a staking pool for a Token 2022 mint

use borsh::BorshSerialize;
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    clock::Clock,
    entrypoint::ProgramResult,
    msg,
    program::invoke_signed,
    pubkey::Pubkey,
    rent::Rent,
    system_instruction,
    sysvar::Sysvar,
};
use spl_token_2022::{
    extension::{
        permanent_delegate::PermanentDelegate,
        transfer_fee::TransferFeeConfig,
        transfer_hook::TransferHook,
        BaseStateWithExtensions, StateWithExtensions,
    },
    state::Mint,
};

use crate::{
    error::StakingError,
    state::{StakingPool, POOL_SEED, TOKEN_VAULT_SEED},
};

/// Initialize a new staking pool
///
/// Accounts:
/// 0. `[writable]` Pool account (PDA: ["pool", mint])
/// 1. `[]` Token mint (Token 2022)
/// 2. `[writable]` Token vault (PDA: ["token_vault", pool])
/// 3. `[writable, signer]` Authority/payer
/// 4. `[]` System program
/// 5. `[]` Token 2022 program
/// 6. `[]` Rent sysvar
pub fn process_initialize_pool(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    tau_seconds: u64,
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();

    let pool_info = next_account_info(account_info_iter)?;
    let mint_info = next_account_info(account_info_iter)?;
    let token_vault_info = next_account_info(account_info_iter)?;
    let authority_info = next_account_info(account_info_iter)?;
    let system_program_info = next_account_info(account_info_iter)?;
    let token_program_info = next_account_info(account_info_iter)?;
    let rent_sysvar_info = next_account_info(account_info_iter)?;

    // Validate Token 2022 program
    if *token_program_info.key != spl_token_2022::id() {
        return Err(StakingError::InvalidTokenProgram.into());
    }

    // Validate authority is signer
    if !authority_info.is_signer {
        return Err(StakingError::MissingRequiredSigner.into());
    }

    // Validate tau_seconds (min 60s to prevent near-instant maturation,
    // max ~10 years to ensure weights eventually mature)
    const MIN_TAU_SECONDS: u64 = 60;
    const MAX_TAU_SECONDS: u64 = 10 * 365 * 24 * 60 * 60; // ~10 years
    if tau_seconds < MIN_TAU_SECONDS || tau_seconds > MAX_TAU_SECONDS {
        return Err(StakingError::InvalidTau.into());
    }

    // Verify mint is a Token 2022 mint
    if *mint_info.owner != spl_token_2022::id() {
        return Err(StakingError::InvalidMintProgram.into());
    }

    // Verify mint is valid by trying to unpack it
    let mint_data = mint_info.try_borrow_data()?;
    let mint_state = StateWithExtensions::<Mint>::unpack(&mint_data)?;

    // Reject mints with transfer fee extension — fee-on-transfer tokens
    // would cause total_staked to diverge from actual vault balance,
    // eventually bricking unstakes for later users.
    if mint_state.get_extension::<TransferFeeConfig>().is_ok() {
        msg!("Token 2022 mints with TransferFee extension are not supported");
        return Err(StakingError::InvalidPoolMint.into());
    }

    // Reject mints with PermanentDelegate — the delegate can transfer tokens
    // out of the vault at any time, breaking the total_staked invariant and
    // enabling theft of all staked tokens.
    if mint_state.get_extension::<PermanentDelegate>().is_ok() {
        msg!("Token 2022 mints with PermanentDelegate extension are not supported");
        return Err(StakingError::UnsupportedMintExtension.into());
    }

    // Reject mints with TransferHook — allows arbitrary program execution
    // during every transfer CPI (stake/unstake), which could manipulate
    // state or extract MEV.
    if mint_state.get_extension::<TransferHook>().is_ok() {
        msg!("Token 2022 mints with TransferHook extension are not supported");
        return Err(StakingError::UnsupportedMintExtension.into());
    }

    // Derive and verify pool PDA
    let (expected_pool, pool_bump) =
        Pubkey::find_program_address(&[POOL_SEED, mint_info.key.as_ref()], program_id);
    if *pool_info.key != expected_pool {
        return Err(StakingError::InvalidPDA.into());
    }

    // Derive and verify token vault PDA
    let (expected_vault, vault_bump) =
        Pubkey::find_program_address(&[TOKEN_VAULT_SEED, pool_info.key.as_ref()], program_id);
    if *token_vault_info.key != expected_vault {
        return Err(StakingError::InvalidPDA.into());
    }

    let rent = Rent::from_account_info(rent_sysvar_info)?;
    let clock = Clock::get()?;

    // Create pool account
    let pool_seeds = &[POOL_SEED, mint_info.key.as_ref(), &[pool_bump]];
    let pool_rent = rent.minimum_balance(StakingPool::LEN);

    invoke_signed(
        &system_instruction::create_account(
            authority_info.key,
            pool_info.key,
            pool_rent,
            StakingPool::LEN as u64,
            program_id,
        ),
        &[
            authority_info.clone(),
            pool_info.clone(),
            system_program_info.clone(),
        ],
        &[pool_seeds],
    )?;

    // Create token vault account (Token 2022 account)
    let vault_seeds = &[TOKEN_VAULT_SEED, pool_info.key.as_ref(), &[vault_bump]];

    // Get the size needed for a token account (with potential extensions)
    let vault_size = spl_token_2022::extension::ExtensionType::try_calculate_account_len::<
        spl_token_2022::state::Account,
    >(&[])?;
    let vault_rent = rent.minimum_balance(vault_size);

    invoke_signed(
        &system_instruction::create_account(
            authority_info.key,
            token_vault_info.key,
            vault_rent,
            vault_size as u64,
            &spl_token_2022::id(),
        ),
        &[
            authority_info.clone(),
            token_vault_info.clone(),
            system_program_info.clone(),
        ],
        &[vault_seeds],
    )?;

    // Initialize token vault as token account
    invoke_signed(
        &spl_token_2022::instruction::initialize_account3(
            &spl_token_2022::id(),
            token_vault_info.key,
            mint_info.key,
            pool_info.key, // Pool PDA is the owner of the vault
        )?,
        &[token_vault_info.clone(), mint_info.clone()],
        &[vault_seeds],
    )?;

    // Initialize pool state
    let pool = StakingPool::new(
        *mint_info.key,
        *token_vault_info.key,
        *pool_info.key, // Reward vault is the pool itself (stores SOL as lamports)
        *authority_info.key,
        tau_seconds,
        clock.unix_timestamp,
        pool_bump,
    );

    // Serialize pool state
    let mut pool_data = pool_info.try_borrow_mut_data()?;
    pool.serialize(&mut &mut pool_data[..])?;

    msg!("Initialized staking pool for mint {}", mint_info.key);
    msg!("Tau: {} seconds", tau_seconds);

    Ok(())
}
