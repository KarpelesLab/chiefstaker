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
use solana_program::program_option::COption;
use solana_program::program_pack::Pack;
use spl_token_2022::{
    extension::{
        permanent_delegate::PermanentDelegate,
        transfer_fee::TransferFeeConfig,
        transfer_hook::TransferHook,
        BaseStateWithExtensions, PodStateWithExtensions, StateWithExtensions,
    },
    pod::PodMint,
    state::Mint,
};
use spl_token_metadata_interface::state::TokenMetadata;

use crate::{
    error::StakingError,
    state::{
        is_valid_token_program, StakingPool, METAPLEX_PROGRAM_ID, PFEE_PROGRAM_ID,
        PFEE_SHARING_CONFIG_DISC, POOL_SEED, PUMP_PROGRAM_ID, TOKEN_VAULT_SEED,
    },
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

    // Validate token program (SPL Token or Token 2022)
    if !is_valid_token_program(token_program_info.key) {
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

    // Verify mint is owned by the provided token program
    if *mint_info.owner != *token_program_info.key {
        return Err(StakingError::InvalidMintProgram.into());
    }

    // Verify mint is valid by trying to unpack it
    let mint_data = mint_info.try_borrow_data()?;
    let mint_state = StateWithExtensions::<Mint>::unpack(&mint_data)?;

    // Reject Token 2022 mints with dangerous extensions
    // (SPL Token mints have no extensions, so these checks are skipped naturally)
    if *token_program_info.key == spl_token_2022::id() {
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
    }

    // === Authority check: signer must match a known authority for this mint ===
    let mut authority_verified = false;

    // 1. Token 2022: check metadata update_authority
    if *token_program_info.key == spl_token_2022::id() {
        let pod_mint = PodStateWithExtensions::<PodMint>::unpack(&mint_data)?;
        if let Ok(token_metadata) = pod_mint.get_variable_len_extension::<TokenMetadata>() {
            let update_auth_option: Option<Pubkey> = token_metadata.update_authority.into();
            let update_auth = update_auth_option.unwrap_or_default();
            if update_auth != Pubkey::default() && update_auth == *authority_info.key {
                authority_verified = true;
            }
        }
    }

    // 2. Check mint_authority (works for both SPL Token and Token 2022)
    if !authority_verified {
        if let COption::Some(mint_auth) = mint_state.base.mint_authority {
            if mint_auth == *authority_info.key {
                authority_verified = true;
            }
        }
    }

    // 3–5. Check remaining accounts (Metaplex metadata, pfee SharingConfig, PumpFun bonding curve)
    if !authority_verified {
        while let Ok(proof_info) = next_account_info(account_info_iter) {
            // 3. Metaplex metadata: owner=metaqbxx, PDA=["metadata", program, mint]
            if *proof_info.owner == METAPLEX_PROGRAM_ID {
                let (expected_pda, _) = Pubkey::find_program_address(
                    &[
                        b"metadata",
                        METAPLEX_PROGRAM_ID.as_ref(),
                        mint_info.key.as_ref(),
                    ],
                    &METAPLEX_PROGRAM_ID,
                );
                if *proof_info.key == expected_pda {
                    let data = proof_info.try_borrow_data()?;
                    // Metaplex metadata: byte 0 = key, bytes 1-32 = update_authority
                    if data.len() >= 33 {
                        let update_auth = Pubkey::try_from(&data[1..33]).unwrap();
                        if update_auth != Pubkey::default() && update_auth == *authority_info.key {
                            authority_verified = true;
                            break;
                        }
                    }
                }
            }

            // 4. pfee SharingConfig: owner=pfee, PDA=["sharing-config", mint]
            if *proof_info.owner == PFEE_PROGRAM_ID {
                let (expected_pda, _) = Pubkey::find_program_address(
                    &[b"sharing-config", mint_info.key.as_ref()],
                    &PFEE_PROGRAM_ID,
                );
                if *proof_info.key == expected_pda {
                    let data = proof_info.try_borrow_data()?;
                    // Anchor: 8-byte discriminator + bump(1) + version(1) + status(1) + mint(32) + admin(32)
                    if data.len() >= 75 && data[..8] == PFEE_SHARING_CONFIG_DISC {
                        let admin = Pubkey::try_from(&data[43..75]).unwrap();
                        if admin == *authority_info.key {
                            authority_verified = true;
                            break;
                        }
                    }
                }
            }

            // 5. PumpFun bonding curve: owner=pump, PDA=["bonding-curve", mint]
            if *proof_info.owner == PUMP_PROGRAM_ID {
                let (expected_pda, _) = Pubkey::find_program_address(
                    &[b"bonding-curve", mint_info.key.as_ref()],
                    &PUMP_PROGRAM_ID,
                );
                if *proof_info.key == expected_pda {
                    let data = proof_info.try_borrow_data()?;
                    // PumpFun bonding curve layout: creator pubkey at bytes 49–81
                    if data.len() >= 81 {
                        let creator = Pubkey::try_from(&data[49..81]).unwrap();
                        if creator == *authority_info.key {
                            authority_verified = true;
                            break;
                        }
                    }
                }
            }
        }
    }

    if !authority_verified {
        msg!(
            "Signer does not match any known authority for mint {}",
            mint_info.key
        );
        return Err(StakingError::InvalidAuthority.into());
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

    // Create token vault account
    let vault_seeds = &[TOKEN_VAULT_SEED, pool_info.key.as_ref(), &[vault_bump]];

    // Get the size needed for a token account
    let vault_size = if *token_program_info.key == spl_token_2022::id() {
        spl_token_2022::extension::ExtensionType::try_calculate_account_len::<
            spl_token_2022::state::Account,
        >(&[])?
    } else {
        spl_token_2022::state::Account::LEN
    };
    let vault_rent = rent.minimum_balance(vault_size);

    invoke_signed(
        &system_instruction::create_account(
            authority_info.key,
            token_vault_info.key,
            vault_rent,
            vault_size as u64,
            token_program_info.key,
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
            token_program_info.key,
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
