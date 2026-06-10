//! Regression test for the StakeOnBehalf lock-clock reset griefing fix.
//!
//! Only the staker signs StakeOnBehalf — the beneficiary does not. Before the
//! fix, the add-to-existing-position branch unconditionally refreshed
//! `last_stake_time`, so anyone could add 1 token to a victim's position to
//! reset their lock clock forever, permanently preventing unstake in pools with
//! `lock_duration_seconds > 0`.
//!
//! After the fix, `last_stake_time` is only refreshed when the signing staker
//! IS the position owner; a non-owner add leaves the owner's lock untouched.

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

struct Setup {
    program_id: Pubkey,
    pool_pda: Pubkey,
    vault_pda: Pubkey,
    metadata_pda: Pubkey,
    mint: Pubkey,
    owner: Keypair,
    owner_stake_pda: Pubkey,
    base_time: i64,
    victim_last_stake_time: i64,
}

/// Build a ProgramTest with a locked pool, an existing position for `owner`
/// (with a distinctive old `last_stake_time`), and a funded token account for
/// `staker` to add from.
fn build(staker: &Keypair) -> (ProgramTest, Setup, Pubkey) {
    let program_id = chiefstaker::id();
    let mint = Pubkey::new_unique();
    let (pool_pda, pool_bump) =
        Pubkey::find_program_address(&[POOL_SEED, mint.as_ref()], &program_id);
    let (vault_pda, _) =
        Pubkey::find_program_address(&[TOKEN_VAULT_SEED, pool_pda.as_ref()], &program_id);
    let (metadata_pda, _) =
        Pubkey::find_program_address(&[METADATA_SEED, pool_pda.as_ref()], &program_id);

    let owner = Keypair::new();
    let (owner_stake_pda, owner_stake_bump) = Pubkey::find_program_address(
        &[STAKE_SEED, pool_pda.as_ref(), owner.pubkey().as_ref()],
        &program_id,
    );

    let amount_owner: u64 = 1_000;
    let base_time = now_unix() - 60;
    // Distinctively old lock clock for the existing position.
    let victim_last_stake_time = base_time - 12_345;

    let mut pool = StakingPool::new(
        mint,
        vault_pda,
        Pubkey::default(),
        Pubkey::new_unique(), // authority
        100_000,              // tau_seconds
        base_time,
        pool_bump,
    );
    pool.total_staked = amount_owner as u128;
    pool.set_sum_stake_exp(chiefstaker::math::U256::from_u128(amount_owner as u128 * WAD));
    // Locked pool: this is what makes the lock-clock reset griefing matter.
    pool.lock_duration_seconds = 86_400;

    let mut owner_stake = UserStake::new(
        owner.pubkey(),
        pool_pda,
        amount_owner,
        base_time,
        WAD,
        owner_stake_bump,
        base_time,
    );
    owner_stake.last_stake_time = victim_last_stake_time;

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
    pt.add_account(
        pool_pda,
        Account {
            lamports: rent_for(StakingPool::LEN),
            data: borsh::to_vec(&pool).unwrap(),
            owner: program_id,
            executable: false,
            rent_epoch: 0,
        },
    );
    pt.add_account(
        owner_stake_pda,
        Account {
            lamports: rent_for(UserStake::LEN),
            data: borsh::to_vec(&owner_stake).unwrap(),
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
            data: pack_token_account(mint, pool_pda, amount_owner),
            owner: spl_token_2022::id(),
            executable: false,
            rent_epoch: 0,
        },
    );

    // Token account holding the tokens the staker will add.
    let staker_token = Pubkey::new_unique();
    pt.add_account(
        staker_token,
        Account {
            lamports: rent_for(spl_token_2022::state::Account::LEN),
            data: pack_token_account(mint, staker.pubkey(), 1_000),
            owner: spl_token_2022::id(),
            executable: false,
            rent_epoch: 0,
        },
    );
    pt.add_account(
        staker.pubkey(),
        Account {
            lamports: 10_000_000_000,
            data: vec![],
            owner: system_program::id(),
            executable: false,
            rent_epoch: 0,
        },
    );

    let setup = Setup {
        program_id,
        pool_pda,
        vault_pda,
        metadata_pda,
        mint,
        owner,
        owner_stake_pda,
        base_time,
        victim_last_stake_time,
    };
    (pt, setup, staker_token)
}

fn stake_on_behalf_ix(
    s: &Setup,
    staker: Pubkey,
    staker_token: Pubkey,
    beneficiary: Pubkey,
    beneficiary_stake: Pubkey,
    amount: u64,
) -> Instruction {
    Instruction {
        program_id: s.program_id,
        accounts: vec![
            AccountMeta::new(s.pool_pda, false),
            AccountMeta::new(beneficiary_stake, false),
            AccountMeta::new(s.vault_pda, false),
            AccountMeta::new(staker_token, false),
            AccountMeta::new_readonly(s.mint, false),
            AccountMeta::new(staker, true),
            AccountMeta::new(beneficiary, false),
            AccountMeta::new_readonly(system_program::id(), false),
            AccountMeta::new_readonly(spl_token_2022::id(), false),
            AccountMeta::new(s.metadata_pda, false),
        ],
        data: borsh::to_vec(&StakingInstruction::StakeOnBehalf { amount }).unwrap(),
    }
}

/// A non-owner StakeOnBehalf add must NOT refresh the owner's last_stake_time
/// (otherwise anyone could extend the owner's lock forever with 1-token adds).
#[tokio::test]
async fn non_owner_stake_on_behalf_does_not_reset_lock_clock() {
    let attacker = Keypair::new();
    let (pt, s, attacker_token) = build(&attacker);
    let (mut banks, payer, blockhash) = pt.start().await;

    let ix = stake_on_behalf_ix(
        &s,
        attacker.pubkey(),
        attacker_token,
        s.owner.pubkey(),
        s.owner_stake_pda,
        1, // griefing-sized add
    );
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer.pubkey()),
        &[&payer, &attacker],
        blockhash,
    );
    banks
        .process_transaction(tx)
        .await
        .expect("non-owner StakeOnBehalf add should succeed");

    let stake_acc = banks.get_account(s.owner_stake_pda).await.unwrap().unwrap();
    let post = UserStake::try_from_slice(&stake_acc.data).unwrap();

    // Tokens were added...
    assert_eq!(post.amount, 1_001);
    // ...but the owner's lock clock is untouched.
    assert_eq!(
        post.last_stake_time, s.victim_last_stake_time,
        "a non-owner add must not extend the owner's lock",
    );
}

/// When the signing staker IS the position owner (self StakeOnBehalf), the lock
/// clock refreshes exactly as a regular add-stake would.
#[tokio::test]
async fn owner_stake_on_behalf_still_refreshes_lock_clock() {
    // `build` creates its own (unrelated) owner position; add a second position
    // owned by the staker so that staker == beneficiary == owner for this case.
    let staker = Keypair::new();
    let (mut pt, mut s, staker_token) = build(&staker);

    // Re-point the existing position at the staker (so staker == owner).
    let (stake_pda, stake_bump) = Pubkey::find_program_address(
        &[STAKE_SEED, s.pool_pda.as_ref(), staker.pubkey().as_ref()],
        &s.program_id,
    );
    let mut owner_stake = UserStake::new(
        staker.pubkey(),
        s.pool_pda,
        1_000,
        s.base_time,
        WAD,
        stake_bump,
        s.base_time,
    );
    owner_stake.last_stake_time = s.victim_last_stake_time;
    pt.add_account(
        stake_pda,
        Account {
            lamports: rent_for(UserStake::LEN),
            data: borsh::to_vec(&owner_stake).unwrap(),
            owner: s.program_id,
            executable: false,
            rent_epoch: 0,
        },
    );
    s.owner_stake_pda = stake_pda;

    let (mut banks, payer, blockhash) = pt.start().await;

    let ix = stake_on_behalf_ix(
        &s,
        staker.pubkey(),
        staker_token,
        staker.pubkey(), // beneficiary == staker == owner
        stake_pda,
        10,
    );
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer.pubkey()),
        &[&payer, &staker],
        blockhash,
    );
    banks
        .process_transaction(tx)
        .await
        .expect("self StakeOnBehalf add should succeed");

    let stake_acc = banks.get_account(stake_pda).await.unwrap().unwrap();
    let post = UserStake::try_from_slice(&stake_acc.data).unwrap();

    assert_eq!(post.amount, 1_010);
    assert!(
        post.last_stake_time > s.victim_last_stake_time,
        "an owner add must refresh the lock clock (got {}, expected > {})",
        post.last_stake_time,
        s.victim_last_stake_time,
    );
}
