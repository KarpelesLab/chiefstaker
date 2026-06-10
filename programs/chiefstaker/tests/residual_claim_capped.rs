//! Regression tests for the residual-claim reservation cap.
//!
//! When a UserStake has amount == 0, `reward_debt` is reinterpreted as residual
//! unclaimed WAD-scaled rewards (legacy accounts only — current code never
//! creates new residual obligations). Before the fix, the residual payout in
//! ClaimRewards was capped only by the pool's available lamports, NOT by
//! `pool.total_residual_unpaid`: a legacy account whose stored reward_debt
//! exceeded the remaining reservation could over-draw SOL that backs active
//! stakers' pending rewards.
//!
//! After the fix the payout is min(reward_debt/WAD, total_residual_unpaid,
//! available lamports), the reservation is decremented by what was actually
//! paid, and any debt above the remaining reservation (unfundable forever,
//! since the field is never incremented) is forgotten so the account can still
//! be closed.

use borsh::BorshDeserialize;
use chiefstaker::{
    math::WAD,
    state::{StakingPool, UserStake, POOL_SEED, STAKE_SEED, TOKEN_VAULT_SEED},
    StakingInstruction,
};
use solana_program::{
    instruction::{AccountMeta, Instruction},
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

struct ResidualSetup {
    program_id: Pubkey,
    pool_pda: Pubkey,
    stake_pda: Pubkey,
    user: Keypair,
}

/// Build a pool with `total_residual_unpaid = reservation` and
/// `available_lamports` of SOL above rent, plus a residual-style UserStake
/// (amount == 0) owing `debt_lamports` (stored WAD-scaled in reward_debt).
fn make_residual_program_test(
    reservation: u64,
    available_lamports: u64,
    debt_lamports: u64,
) -> (ProgramTest, ResidualSetup) {
    let program_id = chiefstaker::id();
    let mint = Pubkey::new_unique();
    let (pool_pda, pool_bump) =
        Pubkey::find_program_address(&[POOL_SEED, mint.as_ref()], &program_id);
    let (vault_pda, _) =
        Pubkey::find_program_address(&[TOKEN_VAULT_SEED, pool_pda.as_ref()], &program_id);
    let user = Keypair::new();
    let (stake_pda, stake_bump) = Pubkey::find_program_address(
        &[STAKE_SEED, pool_pda.as_ref(), user.pubkey().as_ref()],
        &program_id,
    );

    let mut pool = StakingPool::new(
        mint,
        vault_pda,
        Pubkey::default(),
        Pubkey::new_unique(),
        2_592_000, // tau
        0,         // base_time
        pool_bump,
    );
    pool.total_residual_unpaid = reservation;
    // The pool already knows about its full balance — the available SOL is the
    // (already-synced) backing for pending rewards / residual obligations.
    pool.last_synced_lamports = available_lamports;

    // Residual-style legacy position: amount == 0, reward_debt reinterpreted as
    // unclaimed WAD-scaled rewards.
    let mut us = UserStake::new(user.pubkey(), pool_pda, 0, 0, WAD, stake_bump, 0);
    us.reward_debt = (debt_lamports as u128) * WAD;

    let mut pt = ProgramTest::new(
        "chiefstaker",
        program_id,
        processor!(chiefstaker::process_instruction),
    );
    pt.add_account(
        pool_pda,
        Account {
            lamports: rent_for(StakingPool::LEN) + available_lamports,
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
        user.pubkey(),
        Account {
            lamports: 10_000_000_000,
            data: vec![],
            owner: system_program::id(),
            executable: false,
            rent_epoch: 0,
        },
    );

    (
        pt,
        ResidualSetup {
            program_id,
            pool_pda,
            stake_pda,
            user,
        },
    )
}

fn claim_ix(s: &ResidualSetup) -> Instruction {
    Instruction {
        program_id: s.program_id,
        accounts: vec![
            AccountMeta::new(s.pool_pda, false),
            AccountMeta::new(s.stake_pda, false),
            AccountMeta::new(s.user.pubkey(), true),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data: borsh::to_vec(&StakingInstruction::ClaimRewards).unwrap(),
    }
}

/// A residual claim whose stored reward_debt exceeds total_residual_unpaid must
/// pay out no more than the reservation, even when the pool holds plenty of
/// SOL (that SOL backs active stakers' rewards).
#[tokio::test]
async fn residual_claim_capped_by_total_residual_unpaid() {
    let reservation: u64 = 1_000_000;
    let available: u64 = 10_000_000; // pool has plenty — but it isn't this user's
    let debt: u64 = 5_000_000; // > reservation

    let (pt, s) = make_residual_program_test(reservation, available, debt);
    let (mut banks, payer, blockhash) = pt.start().await;

    let user_before = banks.get_account(s.user.pubkey()).await.unwrap().unwrap().lamports;
    let pool_before = banks.get_account(s.pool_pda).await.unwrap().unwrap().lamports;

    let tx = Transaction::new_signed_with_payer(
        &[claim_ix(&s)],
        Some(&payer.pubkey()),
        &[&payer, &s.user],
        blockhash,
    );
    banks
        .process_transaction(tx)
        .await
        .expect("residual claim should succeed");

    // Payout is capped at the reservation, not the (larger) available balance.
    let user_after = banks.get_account(s.user.pubkey()).await.unwrap().unwrap().lamports;
    assert_eq!(
        user_after - user_before,
        reservation,
        "residual payout must be capped at total_residual_unpaid",
    );
    let pool_after = banks.get_account(s.pool_pda).await.unwrap().unwrap().lamports;
    assert_eq!(pool_before - pool_after, reservation);

    let pool_acc = banks.get_account(s.pool_pda).await.unwrap().unwrap();
    let pool = StakingPool::try_from_slice(&pool_acc.data).unwrap();
    assert_eq!(pool.total_residual_unpaid, 0, "reservation fully consumed");
    assert_eq!(
        pool.last_synced_lamports,
        available - reservation,
        "last_synced_lamports tracks the actual transfer",
    );

    // The excess debt is unfundable forever (the reservation is never
    // incremented again) and must be forgotten so the account can be closed.
    let stake_acc = banks.get_account(s.stake_pda).await.unwrap().unwrap();
    let us = UserStake::try_from_slice(&stake_acc.data).unwrap();
    assert_eq!(
        us.reward_debt, 0,
        "debt beyond the drained reservation must be cleared",
    );
    assert_eq!(us.total_rewards_claimed, reservation);
}

/// A residual claim within the reservation behaves exactly as before the fix:
/// paid in full, reservation and debt both decremented by the paid amount.
#[tokio::test]
async fn residual_claim_within_reservation_unchanged() {
    let reservation: u64 = 5_000_000;
    let available: u64 = 10_000_000;
    let debt: u64 = 1_000_000; // <= reservation

    let (pt, s) = make_residual_program_test(reservation, available, debt);
    let (mut banks, payer, blockhash) = pt.start().await;

    let user_before = banks.get_account(s.user.pubkey()).await.unwrap().unwrap().lamports;

    let tx = Transaction::new_signed_with_payer(
        &[claim_ix(&s)],
        Some(&payer.pubkey()),
        &[&payer, &s.user],
        blockhash,
    );
    banks
        .process_transaction(tx)
        .await
        .expect("residual claim should succeed");

    let user_after = banks.get_account(s.user.pubkey()).await.unwrap().unwrap().lamports;
    assert_eq!(user_after - user_before, debt, "in-reservation claim pays in full");

    let pool_acc = banks.get_account(s.pool_pda).await.unwrap().unwrap();
    let pool = StakingPool::try_from_slice(&pool_acc.data).unwrap();
    assert_eq!(pool.total_residual_unpaid, reservation - debt);

    let stake_acc = banks.get_account(s.stake_pda).await.unwrap().unwrap();
    let us = UserStake::try_from_slice(&stake_acc.data).unwrap();
    assert_eq!(us.reward_debt, 0, "fully paid debt is cleared");
    assert_eq!(us.total_rewards_claimed, debt);
}

/// When the reservation is already exhausted (e.g. pre-reservation legacy
/// account, or the reservation was drained by earlier claimants), a residual
/// claim pays nothing — and clears the unfundable debt so the account is not
/// locked open forever by CloseStakeAccount's AccountNotEmpty check.
#[tokio::test]
async fn residual_claim_with_exhausted_reservation_pays_nothing() {
    let reservation: u64 = 0;
    let available: u64 = 10_000_000;
    let debt: u64 = 2_000_000;

    let (pt, s) = make_residual_program_test(reservation, available, debt);
    let (mut banks, payer, blockhash) = pt.start().await;

    let user_before = banks.get_account(s.user.pubkey()).await.unwrap().unwrap().lamports;
    let pool_before = banks.get_account(s.pool_pda).await.unwrap().unwrap().lamports;

    let tx = Transaction::new_signed_with_payer(
        &[claim_ix(&s)],
        Some(&payer.pubkey()),
        &[&payer, &s.user],
        blockhash,
    );
    banks
        .process_transaction(tx)
        .await
        .expect("claim should succeed (as a no-payout)");

    let user_after = banks.get_account(s.user.pubkey()).await.unwrap().unwrap().lamports;
    assert_eq!(user_after, user_before, "no SOL may leave the pool");
    let pool_after = banks.get_account(s.pool_pda).await.unwrap().unwrap().lamports;
    assert_eq!(pool_after, pool_before);

    let stake_acc = banks.get_account(s.stake_pda).await.unwrap().unwrap();
    let us = UserStake::try_from_slice(&stake_acc.data).unwrap();
    assert_eq!(us.reward_debt, 0, "unfundable debt is forgotten so the account can close");
    assert_eq!(us.total_rewards_claimed, 0);
}
