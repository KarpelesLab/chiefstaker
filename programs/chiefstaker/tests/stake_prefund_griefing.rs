//! Regression test for the first-time stake PDA pre-fund griefing vector.
//!
//! The user stake PDA (`["stake", pool, owner]`) is deterministic, so anyone
//! could send it 1 lamport before the user's first Stake. The previous plain
//! `system_instruction::create_account` fails on a non-zero destination
//! balance, permanently bricking first-time staking for that user. Stake and
//! StakeOnBehalf now use the pre-fund-tolerant creation pattern (fund-to-rent +
//! allocate + assign under the PDA seeds), mirroring the InitializePool fix
//! covered by tests/init_griefing.rs.

use borsh::BorshDeserialize;
use chiefstaker::{
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

#[tokio::test]
async fn first_stake_succeeds_when_stake_pda_is_pre_funded() {
    let program_id = chiefstaker::id();
    let mint = Pubkey::new_unique();
    let (pool_pda, pool_bump) =
        Pubkey::find_program_address(&[POOL_SEED, mint.as_ref()], &program_id);
    let (vault_pda, _) =
        Pubkey::find_program_address(&[TOKEN_VAULT_SEED, pool_pda.as_ref()], &program_id);
    let (metadata_pda, _) =
        Pubkey::find_program_address(&[METADATA_SEED, pool_pda.as_ref()], &program_id);

    let user = Keypair::new();
    let user_token = Keypair::new();
    let (stake_pda, _) = Pubkey::find_program_address(
        &[STAKE_SEED, pool_pda.as_ref(), user.pubkey().as_ref()],
        &program_id,
    );

    let base_time = now_unix() - 60;
    let pool = StakingPool::new(
        mint,
        vault_pda,
        Pubkey::default(),
        Pubkey::new_unique(), // authority
        100_000,              // tau_seconds
        base_time,
        pool_bump,
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
            data: pack_token_account(mint, pool_pda, 0),
            owner: spl_token_2022::id(),
            executable: false,
            rent_epoch: 0,
        },
    );
    pt.add_account(
        user_token.pubkey(),
        Account {
            lamports: rent_for(spl_token_2022::state::Account::LEN),
            data: pack_token_account(mint, user.pubkey(), 1_000),
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
    // GRIEF: pre-fund the deterministic stake PDA with a stray lamport,
    // system-owned, empty data.
    pt.add_account(
        stake_pda,
        Account {
            lamports: 1,
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
            AccountMeta::new_readonly(system_program::id(), false),
            AccountMeta::new_readonly(spl_token_2022::id(), false),
            AccountMeta::new(metadata_pda, false),
        ],
        data: borsh::to_vec(&StakingInstruction::Stake { amount: 1_000 }).unwrap(),
    };
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer.pubkey()),
        &[&payer, &user],
        blockhash,
    );
    banks
        .process_transaction(tx)
        .await
        .expect("first Stake must succeed even when the stake PDA was pre-funded");

    // Stake account created, owned by the program, with correct state.
    let stake_acc = banks.get_account(stake_pda).await.unwrap().unwrap();
    assert_eq!(stake_acc.owner, program_id, "stake PDA must be owned by the program");
    assert!(stake_acc.lamports >= rent_for(UserStake::LEN));
    let stake = UserStake::try_from_slice(&stake_acc.data).unwrap();
    assert!(stake.is_initialized());
    assert_eq!(stake.owner, user.pubkey());
    assert_eq!(stake.pool, pool_pda);
    assert_eq!(stake.amount, 1_000);

    // Pool accounting reflects the stake.
    let pool_acc = banks.get_account(pool_pda).await.unwrap().unwrap();
    let post_pool = StakingPool::try_from_slice(&pool_acc.data).unwrap();
    assert_eq!(post_pool.total_staked, 1_000);
}
