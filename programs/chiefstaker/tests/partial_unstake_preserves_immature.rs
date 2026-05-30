//! Regression test for the partial-unstake snapshot-preservation fix.
//!
//! Before the fix, the partial-unstake branch of `settle_unstake_accounting`
//! reset `reward_debt` to `remaining × acc_rps` and `claimed_rewards_wad` to 0,
//! which collapsed `delta_rps` to 0 for the remaining position. The
//! user-facing "immature balance" calculation
//!     forfeit_full = (amount * WAD − user_weighted) × delta_rps / WAD
//! therefore went from the pre-unstake gap to zero on any partial unstake,
//! instead of dropping by the unstaked fraction the proportional-forfeiture
//! comment in c17dc55 promised.
//!
//! After the fix both fields scale by (A-X)/A, preserving per-token snapshot
//! and per-token claimed tracker (matching the claim path's behavior).

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

/// Partial unstake of X out of A scales reward_debt and claimed_rewards_wad
/// by (A-X)/A instead of resetting them — so the per-token snapshot is
/// preserved and the remaining position retains its claim on the immature gap
/// of the pre-unstake delta period.
#[tokio::test]
async fn partial_unstake_scales_snapshot_and_claimed_tracker() {
    let program_id = chiefstaker::id();
    let mint = Pubkey::new_unique();
    let (pool_pda, pool_bump) =
        Pubkey::find_program_address(&[POOL_SEED, mint.as_ref()], &program_id);
    let (vault_pda, _) =
        Pubkey::find_program_address(&[TOKEN_VAULT_SEED, pool_pda.as_ref()], &program_id);
    let user = Keypair::new();
    let user_token = Keypair::new();
    let (stake_pda, stake_bump) = Pubkey::find_program_address(
        &[STAKE_SEED, pool_pda.as_ref(), user.pubkey().as_ref()],
        &program_id,
    );
    let (metadata_pda, _) =
        Pubkey::find_program_address(&[METADATA_SEED, pool_pda.as_ref()], &program_id);

    // Pre-unstake values chosen so that:
    //   weighted = A × WAD       (fully mature: base_time=0, tau short, test clock far ahead)
    //   delta_rps = R − D/A = 5e17
    //   full_entitlement = weighted × delta_rps / WAD = A × 5e17 = 5e20
    //   claimed_rewards_wad = full_entitlement  →  pending = 0
    // Then the unstake's only on-chain effect is the token transfer + the
    // accounting updates we're asserting on.
    let amount_a: u64 = 1_000;
    let unstake_x: u64 = 200;
    let pre_reward_debt: u128 = 100u128 * WAD;            // 1e20
    let pre_acc_rps: u128 = 600_000_000_000_000_000;       // 6e17 = 0.6 WAD; D/A = 1e17 → δ = 5e17
    let pre_claimed: u128 = 500u128 * WAD;                 // 5e20  (= full_entitlement)

    // Build the pool with these specific values. We construct StakingPool
    // directly (rather than via the make_pool helpers in other test files) so
    // we can set acc_reward_per_weighted_share / total_reward_debt precisely.
    let mut pool = StakingPool::new(
        mint,
        vault_pda,
        Pubkey::default(),
        Pubkey::new_unique(), // authority
        100,                  // tau_seconds — small so age >> tau gives full maturity
        0,                    // base_time
        pool_bump,
    );
    pool.total_staked = amount_a as u128;
    // sum_stake_exp = amount * exp_start_factor; we'll use exp_start_factor = WAD on the stake.
    pool.set_sum_stake_exp(chiefstaker::math::U256::from_u128(amount_a as u128 * WAD));
    pool.acc_reward_per_weighted_share = pre_acc_rps;
    pool.total_reward_debt = pre_reward_debt;
    pool.last_synced_lamports = 0;
    // No cooldown — direct Unstake path.
    pool.unstake_cooldown_seconds = 0;

    // Build the user_stake with the pre-unstake values.
    let mut us = UserStake::new(
        user.pubkey(),
        pool_pda,
        amount_a,
        0,    // stake_time
        WAD,  // exp_start_factor (= 1 in WAD)
        stake_bump,
        0,    // base_time_snapshot
    );
    us.reward_debt = pre_reward_debt;
    us.claimed_rewards_wad = pre_claimed;

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
        stake_pda,
        Account {
            lamports: rent_for(UserStake::LEN),
            data: borsh::to_vec(&us).unwrap(),
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
            AccountMeta::new(metadata_pda, false),
        ],
        data: borsh::to_vec(&StakingInstruction::Unstake { amount: unstake_x }).unwrap(),
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
        .expect("partial unstake should succeed");

    // Decode post-state.
    let stake_acc = banks.get_account(stake_pda).await.unwrap().unwrap();
    let post = UserStake::try_from_slice(&stake_acc.data).unwrap();

    // amount: A - X
    assert_eq!(post.amount, amount_a - unstake_x);

    // reward_debt: D × (A-X)/A. With D = 100 WAD and (A-X)/A = 0.8 → 80 WAD.
    let expected_reward_debt = pre_reward_debt * (amount_a - unstake_x) as u128 / amount_a as u128;
    assert_eq!(
        post.reward_debt, expected_reward_debt,
        "reward_debt must scale by (A-X)/A — old behavior reset to remaining * acc_rps",
    );

    // claimed_rewards_wad: full_entitlement × (A-X)/A. With full_entitlement = 5e20
    // and (A-X)/A = 0.8 → 4e20.
    let expected_claimed = pre_claimed * (amount_a - unstake_x) as u128 / amount_a as u128;
    assert_eq!(
        post.claimed_rewards_wad, expected_claimed,
        "claimed_rewards_wad must scale by (A-X)/A — old behavior reset to 0",
    );

    // Per-token snapshot is preserved: reward_debt / amount stays at the pre-unstake value.
    assert_eq!(
        post.reward_debt / post.amount as u128,
        pre_reward_debt / amount_a as u128,
        "per-token snapshot must be preserved across partial unstake",
    );

    // exp_start_factor untouched — maturity is a property of stake_time, not amount.
    assert_eq!(post.exp_start_factor, WAD);

    // Pool aggregate reflects the scaled debt.
    let pool_acc = banks.get_account(pool_pda).await.unwrap().unwrap();
    let post_pool = StakingPool::try_from_slice(&pool_acc.data).unwrap();
    assert_eq!(
        post_pool.total_reward_debt, expected_reward_debt,
        "pool.total_reward_debt must reflect the scaled user debt (was the only contributor)",
    );

    // Tokens delivered to the user.
    let user_tok_acc = banks.get_account(user_token.pubkey()).await.unwrap().unwrap();
    let user_tok = spl_token_2022::state::Account::unpack(&user_tok_acc.data).unwrap();
    assert_eq!(user_tok.amount, unstake_x);
}
