//! Regression test for the pool/vault init griefing vector.
//!
//! The pool (`["pool", mint]`) and vault (`["token_vault", pool]`) PDAs are
//! deterministic, so anyone could pre-fund them with lamports before the real
//! authority initializes. `system_instruction::create_account` fails on a
//! non-zero balance, which would permanently brick pool creation for that mint.
//! `process_initialize_pool` now tolerates a pre-funded PDA (fund-to-rent +
//! allocate + assign under the PDA seeds). This test pre-funds BOTH PDAs and
//! asserts initialization still succeeds.

use borsh::BorshDeserialize;
use chiefstaker::{
    state::{StakingPool, POOL_SEED, TOKEN_VAULT_SEED},
    StakingInstruction,
};
use solana_program::{
    instruction::{AccountMeta, Instruction},
    program_option::COption,
    program_pack::Pack,
    pubkey::Pubkey,
    system_program,
    sysvar,
};
use solana_program_test::*;
use solana_sdk::{
    account::Account,
    signature::{Keypair, Signer},
    transaction::Transaction,
};

fn pack_mint(mint_authority: Pubkey, decimals: u8) -> Vec<u8> {
    let mut data = vec![0u8; spl_token_2022::state::Mint::LEN];
    spl_token_2022::state::Mint {
        mint_authority: COption::Some(mint_authority),
        supply: 0,
        decimals,
        is_initialized: true,
        freeze_authority: COption::None,
    }
    .pack_into_slice(&mut data);
    data
}

#[tokio::test]
async fn initialize_succeeds_when_pdas_are_pre_funded() {
    let program_id = chiefstaker::id();

    // The signer must prove authority over the mint; the simplest valid proof is
    // being the mint_authority, so craft a basic Token-2022 mint with this signer
    // as the mint authority.
    let authority = Keypair::new();
    let mint = Pubkey::new_unique();
    let (pool_pda, _) = Pubkey::find_program_address(&[POOL_SEED, mint.as_ref()], &program_id);
    let (vault_pda, _) = Pubkey::find_program_address(&[TOKEN_VAULT_SEED, pool_pda.as_ref()], &program_id);

    let mut pt = ProgramTest::new("chiefstaker", program_id, processor!(chiefstaker::process_instruction));
    pt.add_program(
        "spl_token_2022",
        spl_token_2022::id(),
        processor!(spl_token_2022::processor::Processor::process),
    );

    pt.add_account(
        mint,
        Account {
            lamports: 10_000_000,
            data: pack_mint(authority.pubkey(), 9),
            owner: spl_token_2022::id(),
            executable: false,
            rent_epoch: 0,
        },
    );
    // Authority funds the rent top-ups + fees.
    pt.add_account(
        authority.pubkey(),
        Account { lamports: 1_000_000_000, data: vec![], owner: system_program::id(), executable: false, rent_epoch: 0 },
    );
    // GRIEF: pre-fund both PDAs with stray lamports, system-owned, empty data.
    pt.add_account(
        pool_pda,
        Account { lamports: 1, data: vec![], owner: system_program::id(), executable: false, rent_epoch: 0 },
    );
    pt.add_account(
        vault_pda,
        Account { lamports: 1, data: vec![], owner: system_program::id(), executable: false, rent_epoch: 0 },
    );

    let (mut banks, payer, blockhash) = pt.start().await;

    let ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(pool_pda, false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new(vault_pda, false),
            AccountMeta::new(authority.pubkey(), true),
            AccountMeta::new_readonly(system_program::id(), false),
            AccountMeta::new_readonly(spl_token_2022::id(), false),
            AccountMeta::new_readonly(sysvar::rent::id(), false),
        ],
        data: borsh::to_vec(&StakingInstruction::InitializePool { tau_seconds: 60 }).unwrap(),
    };
    let tx = Transaction::new_signed_with_payer(&[ix], Some(&payer.pubkey()), &[&payer, &authority], blockhash);
    banks
        .process_transaction(tx)
        .await
        .expect("InitializePool must succeed even when the PDAs were pre-funded");

    // Pool created, owned by the program, with correct state.
    let pool_acc = banks.get_account(pool_pda).await.unwrap().unwrap();
    assert_eq!(pool_acc.owner, program_id, "pool must be owned by the program");
    let pool = StakingPool::try_from_slice(&pool_acc.data).unwrap();
    assert!(pool.is_initialized());
    assert_eq!(pool.mint, mint);
    assert_eq!(pool.total_staked, 0);
    assert_eq!(pool.token_vault, vault_pda);

    // Vault created as a token account owned (token-authority) by the pool PDA.
    let vault_acc = banks.get_account(vault_pda).await.unwrap().unwrap();
    assert_eq!(vault_acc.owner, spl_token_2022::id(), "vault must be a token account");
    let vault = spl_token_2022::state::Account::unpack(&vault_acc.data).unwrap();
    assert_eq!(vault.owner, pool_pda, "vault authority must be the pool PDA");
    assert_eq!(vault.mint, mint);
}
