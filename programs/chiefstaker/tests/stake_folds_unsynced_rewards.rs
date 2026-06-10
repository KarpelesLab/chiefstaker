//! Regression test for the stale-accumulator snapshot fix.
//!
//! SOL donated directly to the pool PDA is normally credited by the
//! permissionless SyncRewards crank. Before the fix, Stake / StakeOnBehalf /
//! CancelUnstake snapshotted the new tokens' reward_debt against the CURRENT
//! (stale) acc_reward_per_weighted_share and grew total_staked WITHOUT first
//! folding pending unsynced lamports. An attacker could see D unsynced lamports
//! on the pool, atomically add a huge stake (snapshot at the pre-D accumulator),
//! call SyncRewards (D now divided by the inflated total_staked), and claim
//! ~all of D — collapsing the pre-existing stakers' share.
//!
//! After the fix, these instructions call `StakingPool::sync_pending_rewards`
//! first, so D is folded into the accumulator over the OLD total_staked before
//! any snapshot is taken: the new tokens' snapshot already includes D and they
//! are entitled to none of it, while the pre-existing staker keeps it all.

use borsh::BorshDeserialize;
use chiefstaker::{
    math::WAD,
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

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// A stake performed while unsynced donation lamports sit on the pool PDA does
/// not entitle the new tokens to those lamports — they are folded into the
/// accumulator over the pre-stake total_staked first, so the pre-existing
/// staker keeps the full donation.
#[tokio::test]
async fn stake_folds_unsynced_rewards_before_snapshot() {
    let program_id = chiefstaker::id();
    let mint = Pubkey::new_unique();
    let (pool_pda, pool_bump) =
        Pubkey::find_program_address(&[POOL_SEED, mint.as_ref()], &program_id);
    let (vault_pda, _) =
        Pubkey::find_program_address(&[TOKEN_VAULT_SEED, pool_pda.as_ref()], &program_id);
    let (metadata_pda, _) =
        Pubkey::find_program_address(&[METADATA_SEED, pool_pda.as_ref()], &program_id);

    // Pre-existing staker A (constructed directly) and just-in-time staker B.
    let staker_a = Keypair::new();
    let staker_b = Keypair::new();
    let b_token = Keypair::new();
    let (a_stake_pda, a_stake_bump) = Pubkey::find_program_address(
        &[STAKE_SEED, pool_pda.as_ref(), staker_a.pubkey().as_ref()],
        &program_id,
    );
    let (b_stake_pda, _) = Pubkey::find_program_address(
        &[STAKE_SEED, pool_pda.as_ref(), staker_b.pubkey().as_ref()],
        &program_id,
    );

    let amount_a: u64 = 1_000; // pre-existing stake
    let amount_b: u64 = 9_000; // just-in-time stake (9x larger)
    let donation: u64 = 1_000_000; // unsynced lamports sitting on the pool PDA

    // base_time slightly in the past so the test clock (real time) gives a small,
    // valid time_since_base for B's Stake (ratio check needs it <= 42 * tau).
    let base_time = now_unix() - 60;

    let mut pool = StakingPool::new(
        mint,
        vault_pda,
        Pubkey::default(),
        Pubkey::new_unique(), // authority
        100_000,              // tau_seconds
        base_time,
        pool_bump,
    );
    pool.total_staked = amount_a as u128;
    pool.set_sum_stake_exp(chiefstaker::math::U256::from_u128(amount_a as u128 * WAD));
    pool.acc_reward_per_weighted_share = 0;
    pool.last_synced_lamports = 0; // donation not synced yet

    // A staked at base_time (exp_start_factor = 1 WAD), nothing claimed yet.
    let a_stake = UserStake::new(
        staker_a.pubkey(),
        pool_pda,
        amount_a,
        base_time,
        WAD,
        a_stake_bump,
        base_time,
    );

    let mut pt = ProgramTest::new(
        "chiefstaker",
        program_id,
        processor!(chiefstaker::process_instruction),
    );
    pt.add_program(
        "spl_token_2022",
        spl_token_2022::id(),
        processor!(spl_token_2022::processor::Processor::process),
    );
    // Pool PDA carries the unsynced donation on top of its rent minimum.
    pt.add_account(
        pool_pda,
        Account {
            lamports: rent_for(StakingPool::LEN) + donation,
            data: borsh::to_vec(&pool).unwrap(),
            owner: program_id,
            executable: false,
            rent_epoch: 0,
        },
    );
    pt.add_account(
        a_stake_pda,
        Account {
            lamports: rent_for(UserStake::LEN),
            data: borsh::to_vec(&a_stake).unwrap(),
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
            data: pack_token_account(mint, pool_pda, amount_a),
            owner: spl_token_2022::id(),
            executable: false,
            rent_epoch: 0,
        },
    );
    pt.add_account(
        b_token.pubkey(),
        Account {
            lamports: rent_for(spl_token_2022::state::Account::LEN),
            data: pack_token_account(mint, staker_b.pubkey(), amount_b),
            owner: spl_token_2022::id(),
            executable: false,
            rent_epoch: 0,
        },
    );
    pt.add_account(
        staker_b.pubkey(),
        Account {
            lamports: 10_000_000_000,
            data: vec![],
            owner: system_program::id(),
            executable: false,
            rent_epoch: 0,
        },
    );

    let (mut banks, payer, blockhash) = pt.start().await;

    // B performs the just-in-time stake while the donation is unsynced.
    let stake_ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(pool_pda, false),
            AccountMeta::new(b_stake_pda, false),
            AccountMeta::new(vault_pda, false),
            AccountMeta::new(b_token.pubkey(), false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new(staker_b.pubkey(), true),
            AccountMeta::new_readonly(system_program::id(), false),
            AccountMeta::new_readonly(spl_token_2022::id(), false),
            AccountMeta::new(metadata_pda, false),
        ],
        data: borsh::to_vec(&StakingInstruction::Stake { amount: amount_b }).unwrap(),
    };
    let tx = Transaction::new_signed_with_payer(
        &[stake_ix],
        Some(&payer.pubkey()),
        &[&payer, &staker_b],
        blockhash,
    );
    banks.process_transaction(tx).await.expect("stake should succeed");

    // The donation must have been folded over the OLD total_staked (A's 1000
    // tokens) before B's snapshot: acc = donation * WAD / amount_a.
    let expected_acc = (donation as u128) * WAD / (amount_a as u128);

    let pool_acc = banks.get_account(pool_pda).await.unwrap().unwrap();
    let post_pool = StakingPool::try_from_slice(&pool_acc.data).unwrap();
    assert_eq!(
        post_pool.acc_reward_per_weighted_share, expected_acc,
        "donation must be distributed over the pre-stake total_staked",
    );
    assert_eq!(
        post_pool.last_synced_lamports, donation,
        "folded donation must be marked as synced",
    );
    assert_eq!(post_pool.total_staked, (amount_a + amount_b) as u128);

    // B's snapshot must be taken AT the post-fold accumulator, so B's pending
    // share of the donation is exactly zero.
    let b_stake_acc = banks.get_account(b_stake_pda).await.unwrap().unwrap();
    let post_b = UserStake::try_from_slice(&b_stake_acc.data).unwrap();
    let expected_b_debt = (amount_b as u128) * expected_acc; // wad_mul(amount_b * WAD, acc)
    assert_eq!(
        post_b.reward_debt, expected_b_debt,
        "new tokens must snapshot at the post-fold accumulator (pre-fix: snapshot at 0)",
    );

    // Running the permissionless SyncRewards crank afterwards is a no-op: the
    // donation can no longer be re-divided over the inflated total_staked.
    let sync_ix = Instruction {
        program_id,
        accounts: vec![AccountMeta::new(pool_pda, false)],
        data: borsh::to_vec(&StakingInstruction::SyncRewards).unwrap(),
    };
    let blockhash = banks.get_latest_blockhash().await.unwrap();
    let tx = Transaction::new_signed_with_payer(&[sync_ix], Some(&payer.pubkey()), &[&payer], blockhash);
    banks.process_transaction(tx).await.expect("sync should succeed");

    let pool_acc = banks.get_account(pool_pda).await.unwrap().unwrap();
    let post_sync = StakingPool::try_from_slice(&pool_acc.data).unwrap();
    assert_eq!(
        post_sync.acc_reward_per_weighted_share, expected_acc,
        "SyncRewards after the stake must not redistribute the donation",
    );
    assert_eq!(post_sync.last_synced_lamports, donation);

    // A's entitlement to the donation is intact: A's per-token snapshot is 0,
    // so A's max-weight allocation of the accumulator delta is the full donation.
    let a_stake_acc = banks.get_account(a_stake_pda).await.unwrap().unwrap();
    let post_a = UserStake::try_from_slice(&a_stake_acc.data).unwrap();
    assert_eq!(post_a.reward_debt, 0, "A's snapshot must be untouched");
    let a_allocation_lamports =
        (amount_a as u128) * (post_sync.acc_reward_per_weighted_share - 0) / WAD;
    assert_eq!(
        a_allocation_lamports, donation as u128,
        "the pre-existing staker must still be allocated the entire donation",
    );
}
