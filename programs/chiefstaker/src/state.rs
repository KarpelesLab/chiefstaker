//! Account state structures for the staking program

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::AccountInfo,
    program::{invoke, invoke_signed},
    pubkey::Pubkey,
    rent::Rent,
    system_instruction,
    sysvar::Sysvar,
};

use crate::error::StakingError;
use crate::math::{exp_neg_time_ratio, wad_div, wad_mul, U256, WAD};

/// Seed prefixes for PDAs
pub const POOL_SEED: &[u8] = b"pool";
pub const STAKE_SEED: &[u8] = b"stake";
pub const TOKEN_VAULT_SEED: &[u8] = b"token_vault";
pub const METADATA_SEED: &[u8] = b"metadata";

/// The original SPL Token program ID (TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA)
pub const SPL_TOKEN_PROGRAM_ID: Pubkey = Pubkey::new_from_array([
    0x06, 0xdd, 0xf6, 0xe1, 0xd7, 0x65, 0xa1, 0x93,
    0xd9, 0xcb, 0xe1, 0x46, 0xce, 0xeb, 0x79, 0xac,
    0x1c, 0xb4, 0x85, 0xed, 0x5f, 0x5b, 0x37, 0x91,
    0x3a, 0x8c, 0xf5, 0x85, 0x7e, 0xff, 0x00, 0xa9,
]);

/// Check if a program ID is a valid token program (SPL Token or Token 2022)
pub fn is_valid_token_program(key: &Pubkey) -> bool {
    *key == spl_token_2022::id() || *key == SPL_TOKEN_PROGRAM_ID
}

/// Metaplex Token Metadata program ID (metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s)
pub const METAPLEX_PROGRAM_ID: Pubkey = Pubkey::new_from_array([
    0x0b, 0x70, 0x65, 0xb1, 0xe3, 0xd1, 0x7c, 0x45,
    0x38, 0x9d, 0x52, 0x7f, 0x6b, 0x04, 0xc3, 0xcd,
    0x58, 0xb8, 0x6c, 0x73, 0x1a, 0xa0, 0xfd, 0xb5,
    0x49, 0xb6, 0xd1, 0xbc, 0x03, 0xf8, 0x29, 0x46,
]);

/// pfee program ID (pfeeUxB6jkeY1Hxd7CsFCAjcbHA9rWtchMGdZ6VojVZ)
pub const PFEE_PROGRAM_ID: Pubkey = Pubkey::new_from_array([
    0x0c, 0x35, 0xff, 0xa9, 0x05, 0x5a, 0x8e, 0x56,
    0x8d, 0xa8, 0xf7, 0xbc, 0x07, 0x56, 0x15, 0x27,
    0x4c, 0xf1, 0xc9, 0x2c, 0xa4, 0x1f, 0x40, 0x00,
    0x9c, 0x51, 0x6a, 0xa4, 0x14, 0xc2, 0x7c, 0x70,
]);

/// Anchor discriminator for pfee SharingConfig account
pub const PFEE_SHARING_CONFIG_DISC: [u8; 8] = [216, 74, 9, 0, 56, 140, 93, 75];

/// PumpFun program ID (6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P)
pub const PUMP_PROGRAM_ID: Pubkey = Pubkey::new_from_array([
    0x01, 0x56, 0xe0, 0xf6, 0x93, 0x66, 0x5a, 0xcf,
    0x44, 0xdb, 0x15, 0x68, 0xbf, 0x17, 0x5b, 0xaa,
    0x51, 0x89, 0xcb, 0x97, 0xf5, 0xd2, 0xff, 0x3b,
    0x65, 0x5d, 0x2b, 0xb6, 0xfd, 0x6d, 0x18, 0xb0,
]);

/// PumpSwap AMM program ID (pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA)
pub const PUMP_AMM_PROGRAM_ID: Pubkey = Pubkey::new_from_array([
    0x0c, 0x14, 0xde, 0xfc, 0x82, 0x5e, 0xc6, 0x76,
    0x94, 0x25, 0x08, 0x18, 0xbb, 0x65, 0x40, 0x65,
    0xf4, 0x29, 0x8d, 0x31, 0x56, 0xd5, 0x71, 0xb4,
    0xd4, 0xf8, 0x09, 0x0c, 0x18, 0xe9, 0xa8, 0x63,
]);

/// Anchor discriminator for PumpSwap Pool account
pub const PUMP_AMM_POOL_DISC: [u8; 8] = [241, 154, 109, 4, 17, 177, 109, 188];

/// Meteora DBC token creator registry (GL6kwZxTaXUXMGAvmmNZSXxANnwtPmKCHprHBM82zYXp)
pub const METEORA_DBC_CREATOR_PROGRAM_ID: Pubkey = Pubkey::new_from_array([
    0xe3, 0xc3, 0xd9, 0x72, 0xc3, 0x54, 0x14, 0xdc,
    0xd9, 0xf5, 0xc3, 0x2d, 0x30, 0x2d, 0x45, 0x8b,
    0x1e, 0x4b, 0xe9, 0xcd, 0x78, 0x50, 0xd4, 0xb6,
    0x9f, 0x16, 0x7f, 0xfc, 0x02, 0x73, 0x11, 0xaf,
]);

/// Discriminator for Meteora DBC creator account
pub const METEORA_DBC_CREATOR_DISC: [u8; 8] = [36, 36, 123, 35, 158, 89, 75, 41];

/// Whitelisted pool creators.
///
/// Signers in this list may initialize a staking pool for any mint without
/// proving they are one of the mint's recognized authorities (mint authority,
/// metadata update authority, PumpFun/PumpSwap/Meteora/pfee creator, etc.).
/// This is an operational allowlist for trusted operators.
///
/// HjDTtYiKNVnRcfQExf5YufEuCghmKN8mXnD8iixep9RL ("Van")
/// 3k9z7k83NfzG8AAKy2DTqKkSCYGYj3b8opKgvQRFEWah ("Mark")
pub const POOL_CREATOR_WHITELIST: [Pubkey; 2] = [
    // "Van" — HjDTtYiKNVnRcfQExf5YufEuCghmKN8mXnD8iixep9RL
    Pubkey::new_from_array([
        0xf8, 0x8b, 0x7a, 0x39, 0x71, 0x7f, 0x46, 0x22,
        0x58, 0x95, 0x18, 0x16, 0x78, 0x4e, 0x63, 0xd5,
        0x9a, 0x76, 0x54, 0x62, 0x56, 0xd8, 0xd9, 0x93,
        0x5f, 0xdf, 0xb4, 0x66, 0xbd, 0xee, 0x56, 0x6b,
    ]),
    // "Mark" — 3k9z7k83NfzG8AAKy2DTqKkSCYGYj3b8opKgvQRFEWah
    Pubkey::new_from_array([
        0x28, 0xc5, 0x81, 0xfb, 0xb6, 0xa3, 0xaa, 0x26,
        0x92, 0x91, 0xcf, 0x11, 0x80, 0x1a, 0x00, 0x44,
        0xbf, 0x62, 0x01, 0x1a, 0xdc, 0xa9, 0x69, 0x14,
        0xa4, 0xf0, 0xbc, 0x4b, 0x0b, 0x36, 0x09, 0xde,
    ]),
];

/// Returns true if `key` is a whitelisted pool creator (see [`POOL_CREATOR_WHITELIST`]).
pub fn is_whitelisted_pool_creator(key: &Pubkey) -> bool {
    POOL_CREATOR_WHITELIST.contains(key)
}

/// Account discriminators
pub const POOL_DISCRIMINATOR: [u8; 8] = [0xc7, 0x5f, 0x7e, 0x2d, 0x3b, 0x1a, 0x9c, 0x4e];
pub const USER_STAKE_DISCRIMINATOR: [u8; 8] = [0xa3, 0x8b, 0x5d, 0x2f, 0x7c, 0x4a, 0x1e, 0x9d];
pub const METADATA_DISCRIMINATOR: [u8; 8] = [0xd4, 0x2a, 0x8f, 0x6b, 0x51, 0x3c, 0xe7, 0x90];

/// Staking pool state account
/// PDA: ["pool", mint]
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct StakingPool {
    /// Discriminator for account type identification
    pub discriminator: [u8; 8],

    /// Token 2022 mint address
    pub mint: Pubkey,

    /// PDA holding staked tokens
    pub token_vault: Pubkey,

    /// DEPRECATED: No longer used (pool PDA holds SOL directly via lamports).
    /// Retained for Borsh serialization layout compatibility.
    pub reward_vault: Pubkey,

    /// Admin authority who initialized the pool
    pub authority: Pubkey,

    /// Total tokens staked (raw amount, not WAD-scaled)
    pub total_staked: u128,

    /// Sum of stake_i * e^(start_time_i / tau) stored as U256 bytes
    /// This is WAD-scaled
    pub sum_stake_exp: [u8; 32],

    /// Time constant in seconds (e.g., 2592000 for 30 days)
    pub tau_seconds: u64,

    /// Base time for rebasing (Unix timestamp)
    /// All exp_start_factors are relative to this time
    pub base_time: i64,

    /// Accumulated reward per weighted share (scaled by 10^18)
    pub acc_reward_per_weighted_share: u128,

    /// Last time rewards were updated
    pub last_update_time: i64,

    /// PDA bump seed
    pub bump: u8,

    /// Last known lamport balance (for sync_rewards to detect new deposits)
    pub last_synced_lamports: u64,

    /// Minimum stake amount (0 = no minimum)
    pub min_stake_amount: u64,

    /// Lock duration in seconds after staking before unstake is allowed (0 = no lock)
    pub lock_duration_seconds: u64,

    /// Unstake cooldown period in seconds (0 = direct unstake, >0 = requires RequestUnstake flow)
    pub unstake_cooldown_seconds: u64,

    /// Original base_time before first rebase (0 = no rebase has occurred).
    /// Used to lazily adjust legacy UserStake.exp_start_factor after rebase.
    pub initial_base_time: i64,

    /// Sum of all active users' reward_debt values.
    /// Maintained incrementally by stake/unstake/claim instructions.
    /// Used by FixTotalRewardDebt to compute stranded rewards from pool state alone.
    /// Starts at 0 for existing pools (bootstraps conservatively — under-recovery is safe).
    pub total_reward_debt: u128,

    /// Total lamports owed to residual claimants (users who fully unstaked
    /// but couldn't be fully paid because the pool lacked SOL).
    /// Tracked separately from `total_reward_debt` because residual users have
    /// amount=0 (no allocation in `total_staked * acc_rps`), so including their
    /// debt in `total_reward_debt` would break the FixTotalRewardDebt formula.
    /// Starts at 0 for existing pools (binary-compatible with old `_reserved3`).
    ///
    /// LEGACY-ONLY as of the "always close on full unstake" change: full unstakes
    /// now pay out in full and redistribute any unpayable remainder, so the
    /// current code never *increments* this field. It is only ever decremented,
    /// servicing residual balances created by pre-upgrade accounts via the
    /// `amount == 0` claim path. The field is retained for binary layout
    /// compatibility and to drain those legacy balances; off-chain tooling should
    /// not treat it as a live obligation counter for new pools.
    pub total_residual_unpaid: u64,
}

impl StakingPool {
    /// Size of the account in bytes
    pub const LEN: usize = 8 + // discriminator
        32 + // mint
        32 + // token_vault
        32 + // reward_vault
        32 + // authority
        16 + // total_staked
        32 + // sum_stake_exp
        8 +  // tau_seconds
        8 +  // base_time
        16 + // acc_reward_per_weighted_share
        8 +  // last_update_time
        1 +  // bump
        8 +  // last_synced_lamports
        8 +  // min_stake_amount
        8 +  // lock_duration_seconds
        8 +  // unstake_cooldown_seconds
        8 +  // initial_base_time
        16 + // total_reward_debt
        8;   // total_residual_unpaid

    /// Create a new staking pool
    pub fn new(
        mint: Pubkey,
        token_vault: Pubkey,
        reward_vault: Pubkey,
        authority: Pubkey,
        tau_seconds: u64,
        base_time: i64,
        bump: u8,
    ) -> Self {
        Self {
            discriminator: POOL_DISCRIMINATOR,
            mint,
            token_vault,
            reward_vault,
            authority,
            total_staked: 0,
            sum_stake_exp: [0u8; 32],
            tau_seconds,
            base_time,
            acc_reward_per_weighted_share: 0,
            last_update_time: base_time,
            bump,
            last_synced_lamports: 0,
            min_stake_amount: 0,
            lock_duration_seconds: 0,
            unstake_cooldown_seconds: 0,
            initial_base_time: 0,
            total_reward_debt: 0,
            total_residual_unpaid: 0,
        }
    }

    /// Get sum_stake_exp as U256
    pub fn get_sum_stake_exp(&self) -> U256 {
        U256::from_le_bytes(&self.sum_stake_exp)
    }

    /// Set sum_stake_exp from U256
    pub fn set_sum_stake_exp(&mut self, value: U256) {
        self.sum_stake_exp = value.to_le_bytes();
    }

    /// Check if pool is initialized
    pub fn is_initialized(&self) -> bool {
        self.discriminator == POOL_DISCRIMINATOR
    }

    /// Check if authority has been renounced (set to default/zero pubkey)
    pub fn is_authority_renounced(&self) -> bool {
        self.authority == Pubkey::default()
    }

    /// Derive pool PDA
    pub fn derive_pda(mint: &Pubkey, program_id: &Pubkey) -> (Pubkey, u8) {
        Pubkey::find_program_address(&[POOL_SEED, mint.as_ref()], program_id)
    }

    /// Derive token vault PDA
    pub fn derive_token_vault_pda(pool: &Pubkey, program_id: &Pubkey) -> (Pubkey, u8) {
        Pubkey::find_program_address(&[TOKEN_VAULT_SEED, pool.as_ref()], program_id)
    }

    /// Fold any not-yet-distributed lamports sitting on the pool account into
    /// `acc_reward_per_weighted_share`, replicating `process_sync_rewards` exactly.
    ///
    /// SOL can land on the pool PDA via direct transfers (e.g. pump.fun fees) and
    /// is normally credited by the permissionless SyncRewards crank. Any
    /// instruction that snapshots `reward_debt` against the accumulator or grows
    /// `total_staked` (Stake / StakeOnBehalf / CancelUnstake) MUST call this
    /// first: otherwise a just-in-time staker could inflate `total_staked`
    /// against a stale accumulator, run SyncRewards, and siphon rewards that
    /// were donated while only the pre-existing stakers were active.
    ///
    /// Semantics match sync_rewards.rs:
    /// - available = pool_lamports - rent_exempt_minimum (saturating)
    /// - undistributed = available - last_synced_lamports (saturating)
    /// - if `total_staked == 0`, distribution is deferred (last_synced_lamports
    ///   is NOT advanced) so the rewards fold in once stakers exist — same as
    ///   the no-stakers deferral in sync_rewards / deposit.
    pub fn sync_pending_rewards(
        &mut self,
        pool_lamports: u64,
        rent_exempt_minimum: u64,
        current_time: i64,
    ) -> Result<(), solana_program::program_error::ProgramError> {
        let current_available = pool_lamports.saturating_sub(rent_exempt_minimum);

        // New rewards = current balance - what we knew about
        let new_rewards = current_available.saturating_sub(self.last_synced_lamports);
        if new_rewards == 0 {
            return Ok(());
        }

        // Denominator: total_staked * WAD (max weight, not time-varying)
        let total_staked_wad = self
            .total_staked
            .checked_mul(WAD)
            .ok_or(StakingError::MathOverflow)?;
        if total_staked_wad == 0 {
            // No stakers to distribute to. Leave rewards pending.
            return Ok(());
        }

        // Calculate reward per share using max weight denominator
        let amount_wad = (new_rewards as u128)
            .checked_mul(WAD)
            .ok_or(StakingError::MathOverflow)?;
        let reward_per_share = wad_div(amount_wad, total_staked_wad)?;

        // Update accumulator
        self.acc_reward_per_weighted_share = self
            .acc_reward_per_weighted_share
            .checked_add(reward_per_share)
            .ok_or(StakingError::MathOverflow)?;

        self.last_update_time = current_time;
        self.last_synced_lamports = current_available;

        Ok(())
    }
}

/// Create a program-derived account at `target`, tolerating the case where the
/// target PDA has already been funded with lamports by a third party.
///
/// `system_instruction::create_account` requires the destination to hold zero
/// lamports, so anyone can permanently block creation of a deterministic PDA by
/// sending it 1 lamport first. To avoid that DoS we, when the account is already
/// funded, top it up to rent-exemption and then `allocate` + `assign` it under
/// its own seeds — operations that require the PDA's signature and therefore
/// cannot be performed by a griefer who only transferred lamports.
///
/// (Mirrors the private helper in initialize.rs; shared here so the user-stake
/// PDA creation paths in stake.rs / stake_on_behalf.rs get the same hardening.)
pub fn create_pda_account<'a>(
    payer: &AccountInfo<'a>,
    target: &AccountInfo<'a>,
    system_program: &AccountInfo<'a>,
    owner: &Pubkey,
    space: usize,
    rent: &Rent,
    seeds: &[&[u8]],
) -> Result<(), solana_program::program_error::ProgramError> {
    let required = rent.minimum_balance(space);

    if target.lamports() == 0 {
        // Fast path: empty + unfunded, a single create_account does it all.
        return invoke_signed(
            &system_instruction::create_account(
                payer.key,
                target.key,
                required,
                space as u64,
                owner,
            ),
            &[payer.clone(), target.clone(), system_program.clone()],
            &[seeds],
        );
    }

    // Pre-funded path: fund to rent-exemption, then allocate + assign under seeds.
    let current = target.lamports();
    if current < required {
        invoke(
            &system_instruction::transfer(payer.key, target.key, required - current),
            &[payer.clone(), target.clone(), system_program.clone()],
        )?;
    }
    invoke_signed(
        &system_instruction::allocate(target.key, space as u64),
        &[target.clone(), system_program.clone()],
        &[seeds],
    )?;
    invoke_signed(
        &system_instruction::assign(target.key, owner),
        &[target.clone(), system_program.clone()],
        &[seeds],
    )
}

/// User stake account
/// PDA: ["stake", pool, owner]
#[derive(BorshSerialize, Debug, Clone)]
pub struct UserStake {
    /// Discriminator for account type identification
    pub discriminator: [u8; 8],

    /// Owner of this stake
    pub owner: Pubkey,

    /// Pool this stake belongs to
    pub pool: Pubkey,

    /// Amount of tokens staked
    pub amount: u64,

    /// Unix timestamp when stake began
    pub stake_time: i64,

    /// e^((stake_time - base_time) / tau) at time of staking, WAD-scaled
    /// Used to track contribution to sum_stake_exp
    pub exp_start_factor: u128,

    /// Reward debt encoding an acc_rps snapshot for pending reward calculation.
    /// Encodes: reward_debt = wad_mul(amount * WAD, snapshot_acc_rps).
    /// Pending = user_weighted * (current_acc_rps - snapshot_acc_rps).
    /// When amount == 0 (post-full-unstake), reinterpreted as unclaimed WAD-scaled rewards.
    pub reward_debt: u128,

    /// PDA bump seed
    pub bump: u8,

    /// Pending unstake request amount (0 = no pending request)
    pub unstake_request_amount: u64,

    /// Timestamp when unstake was requested
    pub unstake_request_time: i64,

    /// Timestamp of most recent stake deposit (for lock duration checks)
    /// Falls back to stake_time when 0 (for existing accounts)
    pub last_stake_time: i64,

    /// Pool base_time when exp_start_factor was last calibrated.
    /// 0 = legacy account (pre-rebase-aware); treated as matching the pool's
    /// initial_base_time or current base_time if no rebase has occurred.
    pub base_time_snapshot: i64,

    /// Cumulative SOL rewards claimed by this user (lamports).
    /// Defaults to 0 for legacy 153-byte accounts (populated on first realloc).
    pub total_rewards_claimed: u64,

    /// Cumulative WAD-scaled rewards already paid out for the current position.
    /// Used to make claims frequency-independent: pending = full_entitlement - claimed_rewards_wad.
    /// Preserved on add-stake (pending rewards unchanged). Reset to 0 on unstake
    /// (partial/full) when the position is restructured and pending is settled.
    /// Defaults to 0 for existing accounts (correct: first claim gets full pending).
    pub claimed_rewards_wad: u128,

    /// 1 when the current pending unstake request was created under the
    /// "settle at request" flow, meaning the requested coins were already removed
    /// from the pool's reward accounting (total_staked / sum_stake_exp) at request
    /// time. 0 means no pending request, OR a legacy in-flight request created
    /// before this upgrade (whose coins are still counted in the pool).
    /// CancelUnstake / CompleteUnstake use this to avoid double-restoring or
    /// double-removing a legacy request. Defaults to 0 for existing accounts.
    pub unstake_request_settled: u8,
}

impl UserStake {
    /// Size of the account in bytes
    pub const LEN: usize = 8 +  // discriminator
        32 + // owner
        32 + // pool
        8 +  // amount
        8 +  // stake_time
        16 + // exp_start_factor
        16 + // reward_debt
        1 +  // bump
        8 +  // unstake_request_amount
        8 +  // unstake_request_time
        8 +  // last_stake_time
        8 +  // base_time_snapshot
        8 +  // total_rewards_claimed
        16 + // claimed_rewards_wad
        1;   // unstake_request_settled

    /// Legacy account size (before claimed_rewards_wad and unstake_request_settled
    /// were added). Equals 161 bytes.
    pub const LEGACY_LEN: usize = Self::LEN - 17;

    /// Create a new user stake
    pub fn new(
        owner: Pubkey,
        pool: Pubkey,
        amount: u64,
        stake_time: i64,
        exp_start_factor: u128,
        bump: u8,
        base_time_snapshot: i64,
    ) -> Self {
        Self {
            discriminator: USER_STAKE_DISCRIMINATOR,
            owner,
            pool,
            amount,
            stake_time,
            exp_start_factor,
            reward_debt: 0,
            bump,
            unstake_request_amount: 0,
            unstake_request_time: 0,
            last_stake_time: stake_time,
            base_time_snapshot,
            total_rewards_claimed: 0,
            claimed_rewards_wad: 0,
            unstake_request_settled: 0,
        }
    }

    /// Check if stake is initialized
    pub fn is_initialized(&self) -> bool {
        self.discriminator == USER_STAKE_DISCRIMINATOR
    }

    /// Derive user stake PDA
    pub fn derive_pda(pool: &Pubkey, owner: &Pubkey, program_id: &Pubkey) -> (Pubkey, u8) {
        Pubkey::find_program_address(&[STAKE_SEED, pool.as_ref(), owner.as_ref()], program_id)
    }

    /// Get the effective last stake time (falls back to stake_time for existing accounts)
    pub fn effective_last_stake_time(&self) -> i64 {
        if self.last_stake_time != 0 {
            self.last_stake_time
        } else {
            self.stake_time
        }
    }

    /// Check if there is a pending unstake request
    pub fn has_pending_unstake_request(&self) -> bool {
        self.unstake_request_amount > 0
    }

    /// Lazily adjust exp_start_factor when pool has been rebased.
    /// Must be called before any calculation that uses exp_start_factor.
    /// Returns true if an adjustment was made.
    pub fn sync_to_pool(&mut self, pool: &StakingPool) -> Result<bool, StakingError> {
        if self.base_time_snapshot == pool.base_time {
            return Ok(false);
        }

        if self.base_time_snapshot == 0 {
            // Legacy account (created before rebase-aware upgrade)
            if pool.initial_base_time == 0 {
                // No rebase has occurred since upgrade — exp_start_factor is still
                // relative to the current pool.base_time, so no adjustment needed.
                self.base_time_snapshot = pool.base_time;
                return Ok(true);
            }
            // A rebase has occurred — adjust from the original base_time
            let delta = pool.base_time.saturating_sub(pool.initial_base_time);
            if delta > 0 {
                let adjustment = exp_neg_time_ratio(delta, pool.tau_seconds)?;
                self.exp_start_factor = wad_mul(self.exp_start_factor, adjustment)?;
            }
            self.base_time_snapshot = pool.base_time;
            return Ok(true);
        }

        // Standard case: adjust from the snapshot's base_time to the current one
        let delta = pool.base_time.saturating_sub(self.base_time_snapshot);
        if delta > 0 {
            let adjustment = exp_neg_time_ratio(delta, pool.tau_seconds)?;
            self.exp_start_factor = wad_mul(self.exp_start_factor, adjustment)?;
        }
        self.base_time_snapshot = pool.base_time;
        Ok(true)
    }
}

impl BorshDeserialize for UserStake {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let discriminator = <[u8; 8]>::deserialize_reader(reader)?;
        let owner = Pubkey::deserialize_reader(reader)?;
        let pool = Pubkey::deserialize_reader(reader)?;
        let amount = u64::deserialize_reader(reader)?;
        let stake_time = i64::deserialize_reader(reader)?;
        let exp_start_factor = u128::deserialize_reader(reader)?;
        let reward_debt = u128::deserialize_reader(reader)?;
        let bump = u8::deserialize_reader(reader)?;
        let unstake_request_amount = u64::deserialize_reader(reader)?;
        let unstake_request_time = i64::deserialize_reader(reader)?;
        let last_stake_time = i64::deserialize_reader(reader)?;
        let base_time_snapshot = i64::deserialize_reader(reader)?;

        // New fields — may not be present in legacy accounts
        let total_rewards_claimed = u64::deserialize_reader(reader).unwrap_or(0);
        let claimed_rewards_wad = u128::deserialize_reader(reader).unwrap_or(0);
        let unstake_request_settled = u8::deserialize_reader(reader).unwrap_or(0);

        Ok(Self {
            discriminator,
            owner,
            pool,
            amount,
            stake_time,
            exp_start_factor,
            reward_debt,
            bump,
            unstake_request_amount,
            unstake_request_time,
            last_stake_time,
            base_time_snapshot,
            total_rewards_claimed,
            claimed_rewards_wad,
            unstake_request_settled,
        })
    }
}

impl UserStake {
    /// Realloc account to current LEN if it's a legacy (smaller) account.
    /// Transfers additional rent from payer to the account via system program CPI.
    /// No-op if account is already at or above current LEN.
    pub fn maybe_realloc<'a>(
        account: &AccountInfo<'a>,
        payer: &AccountInfo<'a>,
        system_program: Option<&AccountInfo<'a>>,
    ) -> Result<(), solana_program::program_error::ProgramError> {
        if account.data_len() >= Self::LEN {
            return Ok(());
        }

        let rent = solana_program::rent::Rent::get()?;
        let new_rent = rent.minimum_balance(Self::LEN);
        let old_rent = rent.minimum_balance(account.data_len());
        let rent_delta = new_rent.saturating_sub(old_rent);

        if rent_delta > 0 {
            let sys_prog = system_program
                .ok_or(StakingError::MissingSystemProgram)?;
            solana_program::program::invoke(
                &solana_program::system_instruction::transfer(
                    payer.key,
                    account.key,
                    rent_delta,
                ),
                &[payer.clone(), account.clone(), sys_prog.clone()],
            )?;
        }

        account.realloc(Self::LEN, false)?;

        Ok(())
    }
}

/// Pool metadata account for explorer display
/// PDA: ["metadata", pool]
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct PoolMetadata {
    /// Discriminator for account type identification
    pub discriminator: [u8; 8],

    /// Back-reference to staking pool
    pub pool: Pubkey,

    /// Actual byte length of name
    pub name_len: u8,

    /// UTF-8 name, zero-padded
    pub name: [u8; 64],

    /// Number of active tags (max 8)
    pub num_tags: u8,

    /// Byte length of each tag
    pub tag_lengths: [u8; 8],

    /// UTF-8 tags, zero-padded
    pub tags: [[u8; 32]; 8],

    /// Actual byte length of url
    pub url_len: u8,

    /// UTF-8 URL, zero-padded
    pub url: [u8; 128],

    /// Active staker count. The metadata PDA is a REQUIRED account on every
    /// member-count-changing instruction (Stake, StakeOnBehalf, Unstake,
    /// CompleteUnstake, CloseStakeAccount), so this stays exact: +1 on a new
    /// stake, -1 on close. Maintained via `update_pool_member_count`, which
    /// tolerates an uninitialized metadata account for pools that never created
    /// metadata. Display-only; never affects funds.
    pub member_count: u64,

    /// PDA bump seed
    pub bump: u8,
}

impl PoolMetadata {
    /// Size of the account in bytes
    pub const LEN: usize = 8 +  // discriminator
        32 + // pool
        1 +  // name_len
        64 + // name
        1 +  // num_tags
        8 +  // tag_lengths
        256 + // tags (8 * 32)
        1 +  // url_len
        128 + // url
        8 +  // member_count
        1;   // bump

    /// Derive metadata PDA
    pub fn derive_pda(pool: &Pubkey, program_id: &Pubkey) -> (Pubkey, u8) {
        Pubkey::find_program_address(&[METADATA_SEED, pool.as_ref()], program_id)
    }

    /// Check if metadata is initialized
    pub fn is_initialized(&self) -> bool {
        self.discriminator == METADATA_DISCRIMINATOR
    }
}

/// Apply `delta` (+1 / -1) to a pool's `member_count`.
///
/// `metadata_info` must be the canonical metadata PDA for `pool_info`; a
/// non-canonical account is rejected with `InvalidPDA`. This lets callers
/// require the metadata account unconditionally on every member-count-changing
/// instruction (stake / unstake / close) so the counter stays exact. A pool that
/// never created metadata is supported transparently: the canonical PDA is then
/// an uninitialized (system-owned, empty) account, which is detected and the
/// update is skipped.
pub fn update_pool_member_count<'a>(
    program_id: &Pubkey,
    pool_info: &AccountInfo<'a>,
    metadata_info: &AccountInfo<'a>,
    delta: i64,
) -> Result<(), solana_program::program_error::ProgramError> {
    // The supplied account must be the canonical metadata PDA for this pool.
    let (expected_metadata, _) = PoolMetadata::derive_pda(pool_info.key, program_id);
    if *metadata_info.key != expected_metadata {
        return Err(StakingError::InvalidPDA.into());
    }

    // Metadata-less pool: the canonical PDA is uninitialized — nothing to update.
    if metadata_info.owner != program_id || metadata_info.data_is_empty() {
        return Ok(());
    }

    let mut metadata = PoolMetadata::try_from_slice(&metadata_info.try_borrow_data()?)?;
    if !metadata.is_initialized() || metadata.pool != *pool_info.key {
        return Ok(());
    }

    metadata.member_count = if delta >= 0 {
        metadata.member_count.saturating_add(delta as u64)
    } else {
        metadata.member_count.saturating_sub(delta.unsigned_abs())
    };

    let mut data = metadata_info.try_borrow_mut_data()?;
    metadata.serialize(&mut &mut data[..])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_size() {
        // Verify the calculated size matches actual serialized size
        let pool = StakingPool::new(
            Pubkey::default(),
            Pubkey::default(),
            Pubkey::default(),
            Pubkey::default(),
            2592000,
            0,
            255,
        );
        let serialized = borsh::to_vec(&pool).unwrap();
        assert_eq!(serialized.len(), StakingPool::LEN);
    }

    #[test]
    fn test_pool_metadata_size() {
        let metadata = PoolMetadata {
            discriminator: METADATA_DISCRIMINATOR,
            pool: Pubkey::default(),
            name_len: 0,
            name: [0u8; 64],
            num_tags: 0,
            tag_lengths: [0u8; 8],
            tags: [[0u8; 32]; 8],
            url_len: 0,
            url: [0u8; 128],
            member_count: 0,
            bump: 255,
        };
        let serialized = borsh::to_vec(&metadata).unwrap();
        assert_eq!(serialized.len(), PoolMetadata::LEN);
        assert_eq!(PoolMetadata::LEN, 508);
    }

    #[test]
    fn test_user_stake_size() {
        let stake = UserStake::new(
            Pubkey::default(),
            Pubkey::default(),
            1000,
            12345,
            1_000_000_000_000_000_000,
            255,
            12345,
        );
        let serialized = borsh::to_vec(&stake).unwrap();
        assert_eq!(serialized.len(), UserStake::LEN);
        assert_eq!(UserStake::LEN, 178);
        assert_eq!(UserStake::LEGACY_LEN, 161);
    }

    #[test]
    fn test_user_stake_legacy_deserialize() {
        // Create a new stake and serialize it
        let stake = UserStake::new(
            Pubkey::default(),
            Pubkey::default(),
            1000,
            12345,
            1_000_000_000_000_000_000,
            255,
            12345,
        );
        let full = borsh::to_vec(&stake).unwrap();

        // Truncate to legacy 161 bytes (no claimed_rewards_wad)
        let legacy = &full[..UserStake::LEGACY_LEN];

        // Deserialize should succeed with new fields defaulting to 0.
        // Critically, a legacy in-flight unstake request must classify as
        // unstake_request_settled == 0 so cancel/complete use the legacy path.
        let deserialized = UserStake::try_from_slice(legacy).unwrap();
        assert_eq!(deserialized.amount, 1000);
        assert_eq!(deserialized.total_rewards_claimed, 0);
        assert_eq!(deserialized.claimed_rewards_wad, 0);
        assert_eq!(deserialized.unstake_request_settled, 0);
        assert_eq!(deserialized.bump, 255);

        // Very old 153-byte accounts (no total_rewards_claimed or claimed_rewards_wad)
        let very_old = &full[..153];
        let deserialized_old = UserStake::try_from_slice(very_old).unwrap();
        assert_eq!(deserialized_old.amount, 1000);
        assert_eq!(deserialized_old.total_rewards_claimed, 0);
        assert_eq!(deserialized_old.claimed_rewards_wad, 0);
        assert_eq!(deserialized_old.unstake_request_settled, 0);

        // 177-byte accounts (pre-marker, with claimed_rewards_wad) classify as legacy
        let pre_marker = &full[..177];
        let deserialized_pre = UserStake::try_from_slice(pre_marker).unwrap();
        assert_eq!(deserialized_pre.unstake_request_settled, 0);

        // Full 178-byte deserialization should also work
        let deserialized_full = UserStake::try_from_slice(&full).unwrap();
        assert_eq!(deserialized_full.total_rewards_claimed, 0);
        assert_eq!(deserialized_full.claimed_rewards_wad, 0);
        assert_eq!(deserialized_full.unstake_request_settled, 0);
    }

    #[test]
    fn test_user_stake_total_rewards_roundtrip() {
        let mut stake = UserStake::new(
            Pubkey::default(),
            Pubkey::default(),
            1000,
            12345,
            1_000_000_000_000_000_000,
            255,
            12345,
        );
        stake.total_rewards_claimed = 999_999;
        stake.claimed_rewards_wad = 42_000_000_000_000_000_000;
        stake.unstake_request_settled = 1;
        let serialized = borsh::to_vec(&stake).unwrap();
        let deserialized = UserStake::try_from_slice(&serialized).unwrap();
        assert_eq!(deserialized.total_rewards_claimed, 999_999);
        assert_eq!(deserialized.claimed_rewards_wad, 42_000_000_000_000_000_000);
        assert_eq!(deserialized.unstake_request_settled, 1);
    }

    #[test]
    fn test_sync_pending_rewards_folds_undistributed() {
        let mut pool = StakingPool::new(
            Pubkey::default(),
            Pubkey::default(),
            Pubkey::default(),
            Pubkey::default(),
            2592000,
            0,
            255,
        );
        pool.total_staked = 1_000;

        // 600 lamports on the account, 100 rent minimum, nothing synced yet
        // → 500 undistributed lamports folded over 1000 staked tokens.
        pool.sync_pending_rewards(600, 100, 42).unwrap();
        assert_eq!(pool.acc_reward_per_weighted_share, 500 * WAD / 1_000);
        assert_eq!(pool.last_synced_lamports, 500);
        assert_eq!(pool.last_update_time, 42);

        // Idempotent: nothing new to sync, accumulator and timestamps untouched.
        pool.sync_pending_rewards(600, 100, 43).unwrap();
        assert_eq!(pool.acc_reward_per_weighted_share, 500 * WAD / 1_000);
        assert_eq!(pool.last_synced_lamports, 500);
        assert_eq!(pool.last_update_time, 42);
    }

    #[test]
    fn test_sync_pending_rewards_defers_when_no_stakers() {
        let mut pool = StakingPool::new(
            Pubkey::default(),
            Pubkey::default(),
            Pubkey::default(),
            Pubkey::default(),
            2592000,
            0,
            255,
        );
        // No stakers: rewards stay pending — last_synced_lamports must NOT
        // advance (matches the sync_rewards / deposit deferral semantics).
        pool.sync_pending_rewards(600, 100, 42).unwrap();
        assert_eq!(pool.acc_reward_per_weighted_share, 0);
        assert_eq!(pool.last_synced_lamports, 0);
        assert_eq!(pool.last_update_time, 0);
    }

    #[test]
    fn test_spl_token_program_id() {
        // Verify our constant matches the canonical SPL Token program ID
        let expected: Pubkey = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
            .parse()
            .unwrap();
        assert_eq!(SPL_TOKEN_PROGRAM_ID, expected);
    }

    #[test]
    fn test_is_valid_token_program() {
        assert!(is_valid_token_program(&spl_token_2022::id()));
        assert!(is_valid_token_program(&SPL_TOKEN_PROGRAM_ID));
        assert!(!is_valid_token_program(&Pubkey::default()));
    }

    #[test]
    fn test_metaplex_program_id() {
        let expected: Pubkey = "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s"
            .parse()
            .unwrap();
        assert_eq!(METAPLEX_PROGRAM_ID, expected);
    }

    #[test]
    fn test_pfee_program_id() {
        let expected: Pubkey = "pfeeUxB6jkeY1Hxd7CsFCAjcbHA9rWtchMGdZ6VojVZ"
            .parse()
            .unwrap();
        assert_eq!(PFEE_PROGRAM_ID, expected);
    }

    #[test]
    fn test_pump_program_id() {
        let expected: Pubkey = "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P"
            .parse()
            .unwrap();
        assert_eq!(PUMP_PROGRAM_ID, expected);
    }

    #[test]
    fn test_pump_amm_program_id() {
        let expected: Pubkey = "pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA"
            .parse()
            .unwrap();
        assert_eq!(PUMP_AMM_PROGRAM_ID, expected);
    }

    #[test]
    fn test_meteora_dbc_creator_program_id() {
        let expected: Pubkey = "GL6kwZxTaXUXMGAvmmNZSXxANnwtPmKCHprHBM82zYXp"
            .parse()
            .unwrap();
        assert_eq!(METEORA_DBC_CREATOR_PROGRAM_ID, expected);
    }

    #[test]
    fn test_pool_creator_whitelist() {
        let van: Pubkey = "HjDTtYiKNVnRcfQExf5YufEuCghmKN8mXnD8iixep9RL"
            .parse()
            .unwrap();
        let mark: Pubkey = "3k9z7k83NfzG8AAKy2DTqKkSCYGYj3b8opKgvQRFEWah"
            .parse()
            .unwrap();
        assert_eq!(POOL_CREATOR_WHITELIST[0], van);
        assert_eq!(POOL_CREATOR_WHITELIST[1], mark);

        assert!(is_whitelisted_pool_creator(&van));
        assert!(is_whitelisted_pool_creator(&mark));
        assert!(!is_whitelisted_pool_creator(&Pubkey::default()));
    }
}
