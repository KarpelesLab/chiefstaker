//! Integration tests for `MigrateStake`: a clean 1:1 transfer of a staking
//! position to an empty destination address, preserving every time/maturity/
//! reward field. Source is closed; pool aggregates and `member_count` are
//! unchanged. These tests cover the happy path, all rejection conditions, the
//! legacy-size source case, and lock-window preservation.

use borsh::BorshDeserialize;
use chiefstaker::{
    error::StakingError,
    math::{wad_mul, U256, WAD},
    state::{StakingPool, UserStake, POOL_SEED, STAKE_SEED, TOKEN_VAULT_SEED},
    StakingInstruction,
};
use solana_program::{
    instruction::{AccountMeta, Instruction, InstructionError},
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

fn make_pool(mint: Pubkey, vault: Pubkey, bump: u8, staked: u64) -> Vec<u8> {
    let mut pool = StakingPool::new(mint, vault, Pubkey::default(), Pubkey::new_unique(), 60, 0, bump);
    pool.total_staked = staked as u128;
    // Each token has full maturity (exp_start_factor = WAD), so the pool's
    // sum_stake_exp = staked * WAD — keeps the rebase check happy.
    let contribution = wad_mul((staked as u128) * WAD, WAD).unwrap();
    pool.set_sum_stake_exp(U256::from_u128(contribution));
    borsh::to_vec(&pool).unwrap()
}

fn make_stake_data(
    owner: Pubkey,
    pool: Pubkey,
    bump: u8,
    amount: u64,
    pending_request: u64,
    last_stake_time: i64,
) -> Vec<u8> {
    let mut us = UserStake::new(owner, pool, amount, 0, WAD, bump, 0);
    us.last_stake_time = last_stake_time;
    us.unstake_request_amount = pending_request;
    borsh::to_vec(&us).unwrap()
}

fn migrate_ix(
    program_id: Pubkey,
    pool: Pubkey,
    source_stake: Pubkey,
    source_owner: Pubkey,
    dest_stake: Pubkey,
    new_owner: Pubkey,
) -> Instruction {
    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new_readonly(pool, false),
            AccountMeta::new(source_stake, false),
            AccountMeta::new(source_owner, true),
            AccountMeta::new(dest_stake, false),
            AccountMeta::new_readonly(new_owner, false),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data: borsh::to_vec(&StakingInstruction::MigrateStake).unwrap(),
    }
}

/// Build a ProgramTest fixture with a pool and a source stake of the given
/// amount, last_stake_time, and (optional) pending unstake request. Returns
/// every handle the tests need.
struct Fixture {
    program_id: Pubkey,
    pool_pda: Pubkey,
    source: Keypair,
    source_stake_pda: Pubkey,
}

fn setup(
    source_amount: u64,
    pending_request: u64,
    last_stake_time: i64,
) -> (ProgramTest, Fixture) {
    let program_id = chiefstaker::id();
    let mint = Pubkey::new_unique();
    let (pool_pda, pool_bump) = Pubkey::find_program_address(&[POOL_SEED, mint.as_ref()], &program_id);
    let (vault_pda, _) = Pubkey::find_program_address(&[TOKEN_VAULT_SEED, pool_pda.as_ref()], &program_id);
    let source = Keypair::new();
    let (source_stake_pda, source_bump) = Pubkey::find_program_address(
        &[STAKE_SEED, pool_pda.as_ref(), source.pubkey().as_ref()],
        &program_id,
    );

    let mut pt = ProgramTest::new("chiefstaker", program_id, processor!(chiefstaker::process_instruction));
    pt.add_account(pool_pda, Account {
        lamports: rent_for(StakingPool::LEN),
        // pool.total_staked = source_amount so the pool/stake numbers line up;
        // migrate does not read total_staked but it keeps invariants clean.
        data: make_pool(mint, vault_pda, pool_bump, source_amount),
        owner: program_id, executable: false, rent_epoch: 0,
    });
    pt.add_account(source_stake_pda, Account {
        lamports: rent_for(UserStake::LEN),
        data: make_stake_data(source.pubkey(), pool_pda, source_bump, source_amount, pending_request, last_stake_time),
        owner: program_id, executable: false, rent_epoch: 0,
    });
    pt.add_account(source.pubkey(), Account {
        lamports: 10_000_000_000,
        data: vec![],
        owner: system_program::id(), executable: false, rent_epoch: 0,
    });

    (pt, Fixture { program_id, pool_pda, source, source_stake_pda })
}

fn assert_custom_error(err: BanksClientError, expected: StakingError) {
    let BanksClientError::TransactionError(te) = err else {
        panic!("expected TransactionError, got {:?}", err)
    };
    let solana_sdk::transaction::TransactionError::InstructionError(_, ie) = te else {
        panic!("expected InstructionError, got {:?}", te)
    };
    let InstructionError::Custom(code) = ie else {
        panic!("expected Custom error, got {:?}", ie)
    };
    assert_eq!(code, expected as u32, "expected {:?} (code {}), got code {}", expected, expected as u32, code);
}

/// Happy path: migrate a full position to a fresh new owner. Source is closed,
/// dest carries the same state with owner+bump rewritten, pool aggregates are
/// unchanged.
#[tokio::test]
async fn migrate_happy_path() {
    let staked: u64 = 1_000_000_000;
    let (pt, fx) = setup(staked, 0, 12345);

    let new_owner = Pubkey::new_unique();
    let (dest_pda, dest_bump) = Pubkey::find_program_address(
        &[STAKE_SEED, fx.pool_pda.as_ref(), new_owner.as_ref()],
        &fx.program_id,
    );

    let (mut banks, payer, blockhash) = pt.start().await;
    let pool_before = banks.get_account(fx.pool_pda).await.unwrap().unwrap();
    let pool_before = StakingPool::try_from_slice(&pool_before.data).unwrap();

    let ix = migrate_ix(fx.program_id, fx.pool_pda, fx.source_stake_pda, fx.source.pubkey(), dest_pda, new_owner);
    let tx = Transaction::new_signed_with_payer(&[ix], Some(&payer.pubkey()), &[&payer, &fx.source], blockhash);
    banks.process_transaction(tx).await.expect("migrate should succeed");

    // Source closed: zero lamports OR all-zero data.
    let src = banks.get_account(fx.source_stake_pda).await.unwrap();
    let closed = src.map(|a| a.lamports == 0 || a.data.iter().all(|b| *b == 0)).unwrap_or(true);
    assert!(closed, "source stake must be closed");

    // Dest exists at full LEN with the copied state and rewritten owner/bump.
    let dest = banks.get_account(dest_pda).await.unwrap().expect("dest must exist");
    assert_eq!(dest.owner, fx.program_id);
    assert_eq!(dest.data.len(), UserStake::LEN);
    let dest_us = UserStake::try_from_slice(&dest.data).unwrap();
    assert_eq!(dest_us.owner, new_owner, "owner must be the new owner");
    assert_eq!(dest_us.bump, dest_bump, "bump must be dest_bump");
    assert_eq!(dest_us.pool, fx.pool_pda);
    assert_eq!(dest_us.amount, staked, "amount preserved");
    assert_eq!(dest_us.last_stake_time, 12345, "last_stake_time preserved");
    assert_eq!(dest_us.exp_start_factor, WAD, "exp_start_factor preserved");
    assert_eq!(dest_us.unstake_request_amount, 0);
    assert!(dest_us.is_initialized());

    // Pool aggregates untouched.
    let pool_after = banks.get_account(fx.pool_pda).await.unwrap().unwrap();
    let pool_after = StakingPool::try_from_slice(&pool_after.data).unwrap();
    assert_eq!(pool_after.total_staked, pool_before.total_staked);
    assert_eq!(pool_after.get_sum_stake_exp(), pool_before.get_sum_stake_exp());
    assert_eq!(pool_after.total_reward_debt, pool_before.total_reward_debt);
}

#[tokio::test]
async fn migrate_rejects_zero_amount_source() {
    let (pt, fx) = setup(0, 0, 0);
    let new_owner = Pubkey::new_unique();
    let (dest_pda, _) = Pubkey::find_program_address(
        &[STAKE_SEED, fx.pool_pda.as_ref(), new_owner.as_ref()],
        &fx.program_id,
    );
    let (mut banks, payer, blockhash) = pt.start().await;
    let ix = migrate_ix(fx.program_id, fx.pool_pda, fx.source_stake_pda, fx.source.pubkey(), dest_pda, new_owner);
    let tx = Transaction::new_signed_with_payer(&[ix], Some(&payer.pubkey()), &[&payer, &fx.source], blockhash);
    let err = banks.process_transaction(tx).await.expect_err("zero-amount migrate must fail");
    assert_custom_error(err, StakingError::InsufficientStakeBalance);
}

#[tokio::test]
async fn migrate_rejects_pending_unstake_request() {
    let (pt, fx) = setup(1_000_000_000, 400_000_000, 0);
    let new_owner = Pubkey::new_unique();
    let (dest_pda, _) = Pubkey::find_program_address(
        &[STAKE_SEED, fx.pool_pda.as_ref(), new_owner.as_ref()],
        &fx.program_id,
    );
    let (mut banks, payer, blockhash) = pt.start().await;
    let ix = migrate_ix(fx.program_id, fx.pool_pda, fx.source_stake_pda, fx.source.pubkey(), dest_pda, new_owner);
    let tx = Transaction::new_signed_with_payer(&[ix], Some(&payer.pubkey()), &[&payer, &fx.source], blockhash);
    let err = banks.process_transaction(tx).await.expect_err("migrate with pending request must fail");
    assert_custom_error(err, StakingError::PendingUnstakeRequestExists);
}

#[tokio::test]
async fn migrate_rejects_self_migrate() {
    let (pt, fx) = setup(1_000_000_000, 0, 0);
    // new_owner == source_owner: dest PDA is the same as source PDA.
    let new_owner = fx.source.pubkey();
    let dest_pda = fx.source_stake_pda;
    let (mut banks, payer, blockhash) = pt.start().await;
    let ix = migrate_ix(fx.program_id, fx.pool_pda, fx.source_stake_pda, fx.source.pubkey(), dest_pda, new_owner);
    let tx = Transaction::new_signed_with_payer(&[ix], Some(&payer.pubkey()), &[&payer, &fx.source], blockhash);
    let err = banks.process_transaction(tx).await.expect_err("self-migrate must fail");
    assert_custom_error(err, StakingError::SelfMigrateNotAllowed);
}

#[tokio::test]
async fn migrate_rejects_dest_already_initialized() {
    let (mut pt, fx) = setup(1_000_000_000, 0, 0);
    let new_owner_kp = Keypair::new();
    let new_owner = new_owner_kp.pubkey();
    let (dest_pda, dest_bump) = Pubkey::find_program_address(
        &[STAKE_SEED, fx.pool_pda.as_ref(), new_owner.as_ref()],
        &fx.program_id,
    );
    // Pre-create the dest as an already-initialized stake.
    pt.add_account(dest_pda, Account {
        lamports: rent_for(UserStake::LEN),
        data: make_stake_data(new_owner, fx.pool_pda, dest_bump, 1, 0, 0),
        owner: fx.program_id, executable: false, rent_epoch: 0,
    });
    let (mut banks, payer, blockhash) = pt.start().await;
    let ix = migrate_ix(fx.program_id, fx.pool_pda, fx.source_stake_pda, fx.source.pubkey(), dest_pda, new_owner);
    let tx = Transaction::new_signed_with_payer(&[ix], Some(&payer.pubkey()), &[&payer, &fx.source], blockhash);
    let err = banks.process_transaction(tx).await.expect_err("dest-not-empty must fail");
    assert_custom_error(err, StakingError::AlreadyInitialized);
}

#[tokio::test]
async fn migrate_rejects_wrong_dest_pda() {
    let (pt, fx) = setup(1_000_000_000, 0, 0);
    let new_owner = Pubkey::new_unique();
    // Pass a dest pubkey that is NOT derive_pda(pool, new_owner).
    let wrong_dest = Pubkey::new_unique();
    let (mut banks, payer, blockhash) = pt.start().await;
    let ix = migrate_ix(fx.program_id, fx.pool_pda, fx.source_stake_pda, fx.source.pubkey(), wrong_dest, new_owner);
    let tx = Transaction::new_signed_with_payer(&[ix], Some(&payer.pubkey()), &[&payer, &fx.source], blockhash);
    let err = banks.process_transaction(tx).await.expect_err("wrong dest PDA must fail");
    assert_custom_error(err, StakingError::InvalidPDA);
}

/// A legacy 161-byte source (no `claimed_rewards_wad` / `unstake_request_settled`
/// bytes) migrates cleanly to a full-LEN destination, with the missing fields
/// defaulted to 0.
#[tokio::test]
async fn migrate_legacy_source() {
    let program_id = chiefstaker::id();
    let mint = Pubkey::new_unique();
    let (pool_pda, pool_bump) = Pubkey::find_program_address(&[POOL_SEED, mint.as_ref()], &program_id);
    let (vault_pda, _) = Pubkey::find_program_address(&[TOKEN_VAULT_SEED, pool_pda.as_ref()], &program_id);
    let source = Keypair::new();
    let (source_stake_pda, source_bump) = Pubkey::find_program_address(
        &[STAKE_SEED, pool_pda.as_ref(), source.pubkey().as_ref()],
        &program_id,
    );

    let staked: u64 = 1_000_000_000;
    // Legacy: serialize full struct, truncate to LEGACY_LEN (161 bytes).
    let mut legacy_data = make_stake_data(source.pubkey(), pool_pda, source_bump, staked, 0, 999);
    legacy_data.truncate(UserStake::LEGACY_LEN);
    assert_eq!(legacy_data.len(), UserStake::LEGACY_LEN);

    let mut pt = ProgramTest::new("chiefstaker", program_id, processor!(chiefstaker::process_instruction));
    pt.add_account(pool_pda, Account {
        lamports: rent_for(StakingPool::LEN),
        data: make_pool(mint, vault_pda, pool_bump, staked),
        owner: program_id, executable: false, rent_epoch: 0,
    });
    pt.add_account(source_stake_pda, Account {
        lamports: rent_for(UserStake::LEGACY_LEN),
        data: legacy_data,
        owner: program_id, executable: false, rent_epoch: 0,
    });
    pt.add_account(source.pubkey(), Account {
        lamports: 10_000_000_000,
        data: vec![],
        owner: system_program::id(), executable: false, rent_epoch: 0,
    });

    let new_owner = Pubkey::new_unique();
    let (dest_pda, dest_bump) = Pubkey::find_program_address(
        &[STAKE_SEED, pool_pda.as_ref(), new_owner.as_ref()],
        &program_id,
    );

    let (mut banks, payer, blockhash) = pt.start().await;
    let ix = migrate_ix(program_id, pool_pda, source_stake_pda, source.pubkey(), dest_pda, new_owner);
    let tx = Transaction::new_signed_with_payer(&[ix], Some(&payer.pubkey()), &[&payer, &source], blockhash);
    banks.process_transaction(tx).await.expect("legacy migrate should succeed");

    let dest = banks.get_account(dest_pda).await.unwrap().expect("dest must exist");
    assert_eq!(dest.data.len(), UserStake::LEN, "dest must be at full LEN, not legacy size");
    let dest_us = UserStake::try_from_slice(&dest.data).unwrap();
    assert_eq!(dest_us.owner, new_owner);
    assert_eq!(dest_us.bump, dest_bump);
    assert_eq!(dest_us.amount, staked);
    assert_eq!(dest_us.last_stake_time, 999, "last_stake_time preserved from legacy source");
    // The legacy-only-missing fields default to 0.
    assert_eq!(dest_us.claimed_rewards_wad, 0);
    assert_eq!(dest_us.unstake_request_settled, 0);
}

/// `last_stake_time` is preserved verbatim, so the new owner inherits the
/// source's remaining lock window. This is the property that prevents lock
/// evasion via migration.
#[tokio::test]
async fn migrate_preserves_last_stake_time() {
    let recent_stake_time: i64 = 1_700_000_000;
    let (pt, fx) = setup(1_000_000_000, 0, recent_stake_time);
    let new_owner = Pubkey::new_unique();
    let (dest_pda, _) = Pubkey::find_program_address(
        &[STAKE_SEED, fx.pool_pda.as_ref(), new_owner.as_ref()],
        &fx.program_id,
    );
    let (mut banks, payer, blockhash) = pt.start().await;
    let ix = migrate_ix(fx.program_id, fx.pool_pda, fx.source_stake_pda, fx.source.pubkey(), dest_pda, new_owner);
    let tx = Transaction::new_signed_with_payer(&[ix], Some(&payer.pubkey()), &[&payer, &fx.source], blockhash);
    banks.process_transaction(tx).await.expect("migrate should succeed");

    let dest = banks.get_account(dest_pda).await.unwrap().unwrap();
    let dest_us = UserStake::try_from_slice(&dest.data).unwrap();
    assert_eq!(
        dest_us.last_stake_time, recent_stake_time,
        "last_stake_time must be preserved verbatim so the lock window carries over to the new owner",
    );
    assert_eq!(dest_us.stake_time, 0, "stake_time also preserved");
}
