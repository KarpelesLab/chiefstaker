//! Integration tests for legacy in-flight unstake requests created BEFORE the
//! "settle at request" upgrade.
//!
//! Under the old code, `RequestUnstake` only set the request fields — it did NOT
//! remove the coins from the pool's accounting (`total_staked` / `sum_stake_exp`)
//! and the account had no `unstake_request_settled` byte (177 bytes). These tests
//! craft exactly that on-chain state and verify the upgraded program handles it:
//!   * Cancel must NOT credit the user any stake (the coins never left the pool).
//!   * Complete must run the full unstake (remove from pool + transfer + close).

use borsh::BorshDeserialize;
use chiefstaker::{
    math::{wad_mul, U256, WAD},
    state::{StakingPool, UserStake, METADATA_SEED, POOL_SEED, STAKE_SEED, TOKEN_VAULT_SEED},
    StakingInstruction,
};
use solana_program::{
    instruction::{AccountMeta, Instruction},
    program_option::COption,
    program_pack::Pack,
    pubkey::Pubkey,
    system_program,
};
use solana_program_test::*;
use solana_sdk::{
    account::Account,
    rent::Rent,
    signature::{Keypair, Signer},
    transaction::Transaction,
};

fn rent_for(len: usize) -> u64 {
    Rent::default().minimum_balance(len)
}

/// Build a pool whose accounting still counts `staked` tokens (as the old code
/// left it during a pending request), staked at base_time so each token has full
/// exp_start_factor (= WAD).
fn make_pool(mint: Pubkey, vault: Pubkey, bump: u8, staked: u64, cooldown: u64) -> Vec<u8> {
    let mut pool = StakingPool::new(mint, vault, Pubkey::default(), Pubkey::new_unique(), 60, 0, bump);
    pool.total_staked = staked as u128;
    // exp_start_factor = WAD for every token (staked at base_time), so
    // sum_stake_exp = staked * WAD.
    let contribution = wad_mul((staked as u128) * WAD, WAD).unwrap();
    pool.set_sum_stake_exp(U256::from_u128(contribution));
    pool.unstake_cooldown_seconds = cooldown;
    borsh::to_vec(&pool).unwrap()
}

/// Build a LEGACY (177-byte, pre-marker) UserStake with a pending request.
/// The serialized form is truncated to drop the `unstake_request_settled` byte,
/// exactly as an account written by the old program would appear.
fn make_legacy_stake(owner: Pubkey, pool: Pubkey, bump: u8, amount: u64, request: u64) -> Vec<u8> {
    let mut us = UserStake::new(owner, pool, amount, 0, WAD, bump, 0);
    us.unstake_request_amount = request;
    us.unstake_request_time = 0;
    let mut data = borsh::to_vec(&us).unwrap(); // 178 bytes (current layout)
    data.truncate(UserStake::LEN - 1); // 177 bytes: legacy, no settled byte
    data
}

fn pack_mint(decimals: u8) -> Vec<u8> {
    let mut data = vec![0u8; spl_token_2022::state::Mint::LEN];
    spl_token_2022::state::Mint {
        mint_authority: COption::Some(Pubkey::new_unique()),
        supply: 1_000_000,
        decimals,
        is_initialized: true,
        freeze_authority: COption::None,
    }
    .pack_into_slice(&mut data);
    data
}

fn pack_token_account(mint: Pubkey, owner: Pubkey, amount: u64) -> Vec<u8> {
    let mut data = vec![0u8; spl_token_2022::state::Account::LEN];
    spl_token_2022::state::Account {
        mint,
        owner,
        amount,
        delegate: COption::None,
        state: spl_token_2022::state::AccountState::Initialized,
        is_native: COption::None,
        delegated_amount: 0,
        close_authority: COption::None,
    }
    .pack_into_slice(&mut data);
    data
}

/// CancelUnstakeRequest on a legacy in-flight request must restore NOTHING to the
/// pool — the coins were never removed — so total_staked and the user's amount are
/// unchanged. (Regression guard: the new restore path must not run for legacy.)
#[tokio::test]
async fn legacy_cancel_does_not_credit_stake() {
    let program_id = chiefstaker::id();
    let mint = Pubkey::new_unique();
    let (pool_pda, pool_bump) = Pubkey::find_program_address(&[POOL_SEED, mint.as_ref()], &program_id);
    let (vault_pda, _) = Pubkey::find_program_address(&[TOKEN_VAULT_SEED, pool_pda.as_ref()], &program_id);
    let user = Keypair::new();
    let (stake_pda, stake_bump) =
        Pubkey::find_program_address(&[STAKE_SEED, pool_pda.as_ref(), user.pubkey().as_ref()], &program_id);

    let staked: u64 = 1_000_000_000;
    let request: u64 = 400_000_000;

    let mut pt = ProgramTest::new("chiefstaker", program_id, processor!(chiefstaker::process_instruction));
    pt.add_account(
        pool_pda,
        Account {
            lamports: rent_for(StakingPool::LEN),
            data: make_pool(mint, vault_pda, pool_bump, staked, 60),
            owner: program_id,
            executable: false,
            rent_epoch: 0,
        },
    );
    pt.add_account(
        stake_pda,
        Account {
            lamports: rent_for(UserStake::LEN), // enough to cover realloc to 178
            data: make_legacy_stake(user.pubkey(), pool_pda, stake_bump, staked, request),
            owner: program_id,
            executable: false,
            rent_epoch: 0,
        },
    );
    pt.add_account(
        user.pubkey(),
        Account {
            lamports: 10_000_000_000,
            data: vec![],
            owner: system_program::id(),
            executable: false,
            rent_epoch: 0,
        },
    );

    let (mut banks, payer, blockhash) = pt.start().await;

    let ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(pool_pda, false),
            AccountMeta::new(stake_pda, false),
            AccountMeta::new(user.pubkey(), true),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data: borsh::to_vec(&StakingInstruction::CancelUnstakeRequest).unwrap(),
    };
    let tx = Transaction::new_signed_with_payer(&[ix], Some(&payer.pubkey()), &[&payer, &user], blockhash);
    banks.process_transaction(tx).await.expect("legacy cancel should succeed");

    // Pool accounting unchanged: total_staked must NOT have grown.
    let pool_acc = banks.get_account(pool_pda).await.unwrap().unwrap();
    let pool = StakingPool::try_from_slice(&pool_acc.data).unwrap();
    assert_eq!(pool.total_staked, staked as u128, "legacy cancel must not credit stake to the pool");

    // User stake: request cleared, amount unchanged, still marked legacy (0).
    let stake_acc = banks.get_account(stake_pda).await.unwrap().unwrap();
    let us = UserStake::try_from_slice(&stake_acc.data).unwrap();
    assert_eq!(us.unstake_request_amount, 0, "request must be cleared");
    assert_eq!(us.amount, staked, "active amount must be unchanged");
    assert_eq!(us.unstake_request_settled, 0);
}

/// CompleteUnstake on a legacy in-flight FULL request must run the full unstake:
/// remove the coins from the pool, transfer them out of the vault, and close the
/// account.
#[tokio::test]
async fn legacy_complete_full_removes_and_closes() {
    let program_id = chiefstaker::id();
    let mint = Pubkey::new_unique();
    let (pool_pda, pool_bump) = Pubkey::find_program_address(&[POOL_SEED, mint.as_ref()], &program_id);
    let (vault_pda, _) = Pubkey::find_program_address(&[TOKEN_VAULT_SEED, pool_pda.as_ref()], &program_id);
    let user = Keypair::new();
    let user_token = Keypair::new();
    let (stake_pda, stake_bump) =
        Pubkey::find_program_address(&[STAKE_SEED, pool_pda.as_ref(), user.pubkey().as_ref()], &program_id);
    let (metadata_pda, _) = Pubkey::find_program_address(&[METADATA_SEED, pool_pda.as_ref()], &program_id);

    let staked: u64 = 1_000_000_000;

    let mut pt = ProgramTest::new("chiefstaker", program_id, processor!(chiefstaker::process_instruction));
    pt.add_program(
        "spl_token_2022",
        spl_token_2022::id(),
        processor!(spl_token_2022::processor::Processor::process),
    );

    // cooldown 0 so the elapsed check passes regardless of the genesis clock.
    pt.add_account(
        pool_pda,
        Account {
            lamports: rent_for(StakingPool::LEN),
            data: make_pool(mint, vault_pda, pool_bump, staked, 0),
            owner: program_id,
            executable: false,
            rent_epoch: 0,
        },
    );
    pt.add_account(
        stake_pda,
        Account {
            lamports: rent_for(UserStake::LEN),
            data: make_legacy_stake(user.pubkey(), pool_pda, stake_bump, staked, staked),
            owner: program_id,
            executable: false,
            rent_epoch: 0,
        },
    );
    pt.add_account(
        mint,
        Account {
            lamports: rent_for(spl_token_2022::state::Mint::LEN),
            data: pack_mint(9),
            owner: spl_token_2022::id(),
            executable: false,
            rent_epoch: 0,
        },
    );
    pt.add_account(
        vault_pda,
        Account {
            lamports: rent_for(spl_token_2022::state::Account::LEN),
            data: pack_token_account(mint, pool_pda, staked),
            owner: spl_token_2022::id(),
            executable: false,
            rent_epoch: 0,
        },
    );
    pt.add_account(
        user_token.pubkey(),
        Account {
            lamports: rent_for(spl_token_2022::state::Account::LEN),
            data: pack_token_account(mint, user.pubkey(), 0),
            owner: spl_token_2022::id(),
            executable: false,
            rent_epoch: 0,
        },
    );
    pt.add_account(
        user.pubkey(),
        Account {
            lamports: 10_000_000_000,
            data: vec![],
            owner: system_program::id(),
            executable: false,
            rent_epoch: 0,
        },
    );

    let (mut banks, payer, blockhash) = pt.start().await;

    let ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(pool_pda, false),
            AccountMeta::new(stake_pda, false),
            AccountMeta::new(vault_pda, false),
            AccountMeta::new(user_token.pubkey(), false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new(user.pubkey(), true),
            AccountMeta::new_readonly(spl_token_2022::id(), false),
            AccountMeta::new_readonly(system_program::id(), false),
            // Metadata PDA (required; uninitialized here — this pool has no metadata)
            AccountMeta::new(metadata_pda, false),
        ],
        data: borsh::to_vec(&StakingInstruction::CompleteUnstake).unwrap(),
    };
    let tx = Transaction::new_signed_with_payer(&[ix], Some(&payer.pubkey()), &[&payer, &user], blockhash);
    banks.process_transaction(tx).await.expect("legacy complete should succeed");

    // Tokens delivered to the user, vault drained.
    let user_tok = banks.get_account(user_token.pubkey()).await.unwrap().unwrap();
    let user_tok = spl_token_2022::state::Account::unpack(&user_tok.data).unwrap();
    assert_eq!(user_tok.amount, staked, "user must receive the full unstaked amount");

    let vault = banks.get_account(vault_pda).await.unwrap().unwrap();
    let vault = spl_token_2022::state::Account::unpack(&vault.data).unwrap();
    assert_eq!(vault.amount, 0, "vault must be drained");

    // Pool accounting reduced; stake account closed.
    let pool_acc = banks.get_account(pool_pda).await.unwrap().unwrap();
    let pool = StakingPool::try_from_slice(&pool_acc.data).unwrap();
    assert_eq!(pool.total_staked, 0, "pool total_staked must drop by the unstaked amount");

    let stake_acc = banks.get_account(stake_pda).await.unwrap();
    let closed = stake_acc.map(|a| a.lamports == 0 || a.data.iter().all(|b| *b == 0)).unwrap_or(true);
    assert!(closed, "stake account must be closed after a full unstake");
}
