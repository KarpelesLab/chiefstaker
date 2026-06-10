//! Regression test for capped (underfunded) partial-unstake reward settlement.
//!
//! On a partial unstake the reward payout is capped to the pool's available
//! lamports (pool_lamports - rent_exempt). Before the fix, the surviving
//! position's `claimed_rewards_wad` was set from the FULL pending entitlement
//! (`full_entitlement * (A-X)/A`) even when the actual payout was capped, so
//! the unpaid portion was silently destroyed for that position — unlike the
//! full-unstake branch, which redistributes the unpaid remainder via
//! `last_synced_lamports`.
//!
//! After the fix, `claimed_rewards_wad` is derived from the SETTLED
//! entitlement (old claimed + actually paid), scaled by (A-X)/A like the rest
//! of the position, so the surviving position keeps its (A-X)/A share of the
//! unpaid rewards pending; the unstaked X/A share is redistributed via
//! `last_synced_lamports` exactly like the full-unstake branch. The healthy
//! (fully funded) path is bit-for-bit unchanged — see
//! tests/partial_unstake_preserves_immature.rs.

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

/// Partial unstake of X out of A when the pool cannot pay the pending rewards
/// (pool holds only its rent): the payout is capped to 0, and the surviving
/// position must NOT mark the unpaid entitlement as claimed.
#[tokio::test]
async fn capped_partial_unstake_does_not_destroy_unpaid_rewards() {
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

    // Mirrors the fully-funded test in partial_unstake_preserves_immature.rs,
    // but with claimed_rewards_wad = 0 so there IS a pending entitlement, and a
    // pool that holds only its rent so the payout is capped to 0:
    //   weighted = A × WAD            (fully mature: base_time=0, tau short)
    //   delta_rps = R − D/A = 5e17
    //   full_entitlement = A × 5e17 = 5e20  → pending = 5e20 (500 lamports)
    //   available = 0                 → paid = 0, unpaid = 5e20
    let amount_a: u64 = 1_000;
    let unstake_x: u64 = 200;
    let pre_reward_debt: u128 = 100u128 * WAD;            // 1e20; D/A = 1e17
    let pre_acc_rps: u128 = 600_000_000_000_000_000;      // 6e17 → δ = 5e17

    // Pool "knows" about 1_000 lamports of rewards it no longer actually holds
    // (the underfunded edge case this fix is about).
    let pre_last_synced: u64 = 1_000;

    let mut pool = StakingPool::new(
        mint,
        vault_pda,
        Pubkey::default(),
        Pubkey::new_unique(),
        100, // tau_seconds — small so age >> tau gives full maturity
        0,   // base_time
        pool_bump,
    );
    pool.total_staked = amount_a as u128;
    pool.set_sum_stake_exp(chiefstaker::math::U256::from_u128(amount_a as u128 * WAD));
    pool.acc_reward_per_weighted_share = pre_acc_rps;
    pool.total_reward_debt = pre_reward_debt;
    pool.last_synced_lamports = pre_last_synced;
    pool.unstake_cooldown_seconds = 0;

    let mut us = UserStake::new(user.pubkey(), pool_pda, amount_a, 0, WAD, stake_bump, 0);
    us.reward_debt = pre_reward_debt;
    us.claimed_rewards_wad = 0; // nothing claimed yet → pending = full_entitlement

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
            // Rent only: zero lamports available for the reward payout.
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

    let user_before = banks.get_account(user.pubkey()).await.unwrap().unwrap().lamports;

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
        .expect("capped partial unstake should succeed");

    // No SOL was available, so no reward payout happened.
    let user_after = banks.get_account(user.pubkey()).await.unwrap().unwrap().lamports;
    assert_eq!(user_after, user_before, "no reward lamports were available to pay");

    let stake_acc = banks.get_account(stake_pda).await.unwrap().unwrap();
    let post = UserStake::try_from_slice(&stake_acc.data).unwrap();

    assert_eq!(post.amount, amount_a - unstake_x);

    // reward_debt scales by (A-X)/A as in the funded case (snapshot preserved).
    let expected_reward_debt = pre_reward_debt * (amount_a - unstake_x) as u128 / amount_a as u128;
    assert_eq!(post.reward_debt, expected_reward_debt);

    // Nothing was actually paid, so the settled entitlement is the old claimed
    // amount (0) and claimed_rewards_wad must stay 0. The buggy behavior set it
    // to full_entitlement × (A-X)/A = 4e20, marking 400 never-paid lamports as
    // claimed and destroying them for this position.
    assert_eq!(
        post.claimed_rewards_wad, 0,
        "capped partial unstake must not mark unpaid rewards as claimed",
    );
    assert_eq!(post.total_rewards_claimed, 0, "no payout happened");

    // The surviving position's pending entitlement is recomputable as
    // full_entitlement × (A-X)/A − claimed = 5e20 × 0.8 − 0 = 4e20 (400
    // lamports), i.e. the (A-X)/A share of the unpaid remainder stays owed.
    // The unstaked X/A share (100 lamports) is redistributed via
    // last_synced_lamports, exactly like the full-unstake branch.
    let unpaid_total_lamports: u64 = 500;
    let unstaked_share: u64 = unpaid_total_lamports * unstake_x / amount_a; // 100
    let pool_acc = banks.get_account(pool_pda).await.unwrap().unwrap();
    let post_pool = StakingPool::try_from_slice(&pool_acc.data).unwrap();
    assert_eq!(
        post_pool.last_synced_lamports,
        pre_last_synced - unstaked_share,
        "unstaked fraction of the unpaid remainder must be redistributed",
    );

    // Standard partial-unstake accounting still holds.
    assert_eq!(post_pool.total_staked, (amount_a - unstake_x) as u128);
    assert_eq!(post_pool.total_reward_debt, expected_reward_debt);

    // Tokens still delivered in full.
    let user_tok_acc = banks.get_account(user_token.pubkey()).await.unwrap().unwrap();
    let user_tok = spl_token_2022::state::Account::unpack(&user_tok_acc.data).unwrap();
    assert_eq!(user_tok.amount, unstake_x);
}
