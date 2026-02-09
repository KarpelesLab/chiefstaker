use solana_program::program_error::ProgramError;
use thiserror::Error;

#[derive(Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum StakingError {
    #[error("Invalid instruction data")]
    InvalidInstruction,

    #[error("Account already initialized")]
    AlreadyInitialized,

    #[error("Account not initialized")]
    NotInitialized,

    #[error("Invalid pool mint")]
    InvalidPoolMint,

    #[error("Invalid token vault")]
    InvalidTokenVault,

    /// UNUSED: Retained for ABI stability (error code numbering).
    #[error("Invalid reward vault")]
    InvalidRewardVault,

    #[error("Invalid authority")]
    InvalidAuthority,

    #[error("Invalid owner")]
    InvalidOwner,

    #[error("Invalid pool")]
    InvalidPool,

    #[error("Invalid PDA")]
    InvalidPDA,

    #[error("Insufficient stake balance")]
    InsufficientStakeBalance,

    #[error("Insufficient reward balance")]
    InsufficientRewardBalance,

    #[error("Math overflow")]
    MathOverflow,

    #[error("Math underflow")]
    MathUnderflow,

    #[error("Zero amount not allowed")]
    ZeroAmount,

    #[error("Invalid tau value")]
    InvalidTau,

    #[error("Pool requires sync before operation")]
    PoolRequiresSync,

    #[error("Invalid mint - must be Token 2022")]
    InvalidMintProgram,

    #[error("Missing required signer")]
    MissingRequiredSigner,

    #[error("Account data too small")]
    AccountDataTooSmall,

    #[error("Invalid account owner")]
    InvalidAccountOwner,

    #[error("Stake amount below pool minimum")]
    BelowMinimumStake,

    #[error("Stake is locked - lock duration has not elapsed")]
    StakeLocked,

    #[error("Unstake cooldown period has not elapsed")]
    CooldownNotElapsed,

    #[error("Pool requires RequestUnstake flow, not direct Unstake")]
    CooldownRequired,

    #[error("No pending unstake request")]
    NoPendingUnstakeRequest,

    #[error("Must cancel existing unstake request first")]
    PendingUnstakeRequestExists,

    #[error("Authority has been renounced")]
    AuthorityRenounced,

    #[error("Pool has no cooldown configured - use direct Unstake instead")]
    CooldownNotConfigured,
}

impl From<StakingError> for ProgramError {
    fn from(e: StakingError) -> Self {
        ProgramError::Custom(e as u32)
    }
}
