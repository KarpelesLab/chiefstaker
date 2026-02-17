//! Instruction handlers for the staking program

pub mod initialize;
pub mod stake;
pub mod unstake;
pub mod claim;
pub mod deposit;
pub mod sync;
pub mod sync_rewards;
pub mod update_settings;
pub mod transfer_authority;
pub mod request_unstake;
pub mod complete_unstake;
pub mod cancel_unstake;
pub mod close_stake;
pub mod fix_total_reward_debt;
pub mod set_metadata;
pub mod take_fee_ownership;

pub use initialize::*;
pub use stake::*;
pub use unstake::*;
pub use claim::*;
pub use deposit::*;
pub use sync::*;
pub use sync_rewards::*;
pub use update_settings::*;
pub use transfer_authority::*;
pub use request_unstake::*;
pub use complete_unstake::*;
pub use cancel_unstake::*;
pub use close_stake::*;
pub use fix_total_reward_debt::*;
pub use set_metadata::*;
pub use take_fee_ownership::*;
