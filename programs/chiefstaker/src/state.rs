//! Account state structures for the staking program

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::pubkey::Pubkey;

use crate::math::U256;

/// Seed prefixes for PDAs
pub const POOL_SEED: &[u8] = b"pool";
pub const STAKE_SEED: &[u8] = b"stake";
pub const TOKEN_VAULT_SEED: &[u8] = b"token_vault";
pub const REWARD_VAULT_SEED: &[u8] = b"reward_vault";

/// Account discriminators
pub const POOL_DISCRIMINATOR: [u8; 8] = [0xc7, 0x5f, 0x7e, 0x2d, 0x3b, 0x1a, 0x9c, 0x4e];
pub const USER_STAKE_DISCRIMINATOR: [u8; 8] = [0xa3, 0x8b, 0x5d, 0x2f, 0x7c, 0x4a, 0x1e, 0x9d];

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

    /// PDA holding SOL rewards (this is the pool PDA itself, uses lamports)
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

    /// Reserved space for future upgrades
    pub _reserved2: [u8; 32],
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
        32;  // _reserved2

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
            _reserved2: [0u8; 32],
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

    /// Derive reward vault PDA (not used since we store SOL in pool account)
    pub fn derive_reward_vault_pda(pool: &Pubkey, program_id: &Pubkey) -> (Pubkey, u8) {
        Pubkey::find_program_address(&[REWARD_VAULT_SEED, pool.as_ref()], program_id)
    }
}

/// User stake account
/// PDA: ["stake", pool, owner]
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
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

    /// Reward debt for pending reward calculation
    /// reward_debt = user_weight * acc_reward_per_weighted_share at last update
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

    /// Reserved space for future upgrades
    pub _reserved2: [u8; 8],
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
        8;   // _reserved2

    /// Create a new user stake
    pub fn new(
        owner: Pubkey,
        pool: Pubkey,
        amount: u64,
        stake_time: i64,
        exp_start_factor: u128,
        bump: u8,
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
            _reserved2: [0u8; 8],
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
    fn test_user_stake_size() {
        let stake = UserStake::new(
            Pubkey::default(),
            Pubkey::default(),
            1000,
            12345,
            1_000_000_000_000_000_000,
            255,
        );
        let serialized = borsh::to_vec(&stake).unwrap();
        assert_eq!(serialized.len(), UserStake::LEN);
    }
}
