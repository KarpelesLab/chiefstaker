//! Fixed-point math for exponential calculations
//!
//! Scale factor: 10^18 (WAD precision)
//! Uses range reduction and polynomial approximation for exp()

use crate::error::StakingError;
use uint::construct_uint;

construct_uint! {
    /// 256-bit unsigned integer for large intermediate values
    pub struct U256(4);
}

/// Scale factor: 10^18 (WAD)
pub const WAD: u128 = 1_000_000_000_000_000_000;
pub const WAD_U256: U256 = U256([WAD as u64, (WAD >> 64) as u64, 0, 0]);

/// ln(2) scaled by WAD: 0.693147180559945309...
pub const LN2_WAD: u128 = 693_147_180_559_945_309;

/// 1/ln(2) scaled by WAD: 1.442695040888963407...
pub const INV_LN2_WAD: u128 = 1_442_695_040_888_963_407;

/// e scaled by WAD: 2.718281828459045235...
pub const E_WAD: u128 = 2_718_281_828_459_045_235;

/// Maximum safe exponent input (scaled by WAD) to avoid overflow
/// e^87 < 2^128, so we cap at ~87 WAD
pub const MAX_EXP_INPUT: u128 = 87_000_000_000_000_000_000;

/// Threshold for sum_stake_exp to trigger rebase (near U256 max / 2)
pub const REBASE_THRESHOLD: U256 = U256([u64::MAX / 2, u64::MAX, u64::MAX, u64::MAX / 2]);

impl U256 {
    /// Create U256 from u128
    pub const fn from_u128(val: u128) -> Self {
        U256([val as u64, (val >> 64) as u64, 0, 0])
    }

    /// Convert to u128, returning None if overflow
    pub fn to_u128(&self) -> Option<u128> {
        if self.0[2] != 0 || self.0[3] != 0 {
            return None;
        }
        Some((self.0[1] as u128) << 64 | self.0[0] as u128)
    }

    /// Convert to [u8; 32] for storage
    pub fn to_le_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[0..8].copy_from_slice(&self.0[0].to_le_bytes());
        bytes[8..16].copy_from_slice(&self.0[1].to_le_bytes());
        bytes[16..24].copy_from_slice(&self.0[2].to_le_bytes());
        bytes[24..32].copy_from_slice(&self.0[3].to_le_bytes());
        bytes
    }

    /// Create from [u8; 32] storage
    pub fn from_le_bytes(bytes: &[u8; 32]) -> Self {
        let w0 = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let w1 = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        let w2 = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
        let w3 = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
        U256([w0, w1, w2, w3])
    }

    /// Check if value exceeds rebase threshold
    pub fn needs_rebase(&self) -> bool {
        *self > REBASE_THRESHOLD
    }
}

/// Multiply two WAD-scaled values, returning WAD-scaled result
pub fn wad_mul(a: u128, b: u128) -> Result<u128, StakingError> {
    let result = U256::from_u128(a)
        .checked_mul(U256::from_u128(b))
        .ok_or(StakingError::MathOverflow)?
        / WAD_U256;
    result.to_u128().ok_or(StakingError::MathOverflow)
}

/// Divide two WAD-scaled values, returning WAD-scaled result
pub fn wad_div(a: u128, b: u128) -> Result<u128, StakingError> {
    if b == 0 {
        return Err(StakingError::MathOverflow);
    }
    let result = U256::from_u128(a)
        .checked_mul(WAD_U256)
        .ok_or(StakingError::MathOverflow)?
        / U256::from_u128(b);
    result.to_u128().ok_or(StakingError::MathOverflow)
}

/// U256 version of wad_mul
pub fn wad_mul_u256(a: U256, b: U256) -> Result<U256, StakingError> {
    a.checked_mul(b)
        .ok_or(StakingError::MathOverflow)?
        .checked_div(WAD_U256)
        .ok_or(StakingError::MathOverflow)
}

/// Calculate e^x where x is WAD-scaled (x = actual_value * WAD)
/// Uses range reduction: e^x = 2^(x/ln(2)) = 2^n * 2^f
/// where n is integer part and f is fractional part
///
/// Returns WAD-scaled result
pub fn exp_wad(x: u128) -> Result<u128, StakingError> {
    if x == 0 {
        return Ok(WAD);
    }

    if x > MAX_EXP_INPUT {
        return Err(StakingError::MathOverflow);
    }

    // Convert x to base-2 exponent: x / ln(2)
    // x_div_ln2 = x * (1/ln2) / WAD
    let x_div_ln2 = wad_mul(x, INV_LN2_WAD)?;

    // Split into integer and fractional parts
    let int_part = x_div_ln2 / WAD;
    let frac_part = x_div_ln2 % WAD; // Already WAD-scaled fractional part

    // Calculate 2^frac using Taylor series for 2^x = e^(x*ln2)
    // 2^f = 1 + f*ln2 + (f*ln2)^2/2! + (f*ln2)^3/3! + ...
    let f_ln2 = wad_mul(frac_part, LN2_WAD)?;
    let two_pow_frac = exp_taylor(f_ln2)?;

    // Calculate 2^int by shifting (careful with overflow)
    if int_part > 127 {
        return Err(StakingError::MathOverflow);
    }

    // 2^int_part * two_pow_frac / WAD
    let two_pow_int = 1u128 << int_part;
    wad_mul(two_pow_int.checked_mul(WAD).ok_or(StakingError::MathOverflow)?, two_pow_frac)
}

/// Taylor series approximation for e^x where x is small (|x| < ln(2))
/// e^x = 1 + x + x^2/2! + x^3/3! + x^4/4! + x^5/5! + x^6/6!
/// x is WAD-scaled, returns WAD-scaled result
fn exp_taylor(x: u128) -> Result<u128, StakingError> {
    // Precomputed 1/n! values scaled by WAD
    const INV_FACTORIAL: [u128; 7] = [
        WAD,                           // 1/0! = 1
        WAD,                           // 1/1! = 1
        500_000_000_000_000_000,       // 1/2! = 0.5
        166_666_666_666_666_667,       // 1/3! ≈ 0.1667
        41_666_666_666_666_667,        // 1/4! ≈ 0.0417
        8_333_333_333_333_333,         // 1/5! ≈ 0.00833
        1_388_888_888_888_889,         // 1/6! ≈ 0.00139
    ];

    let mut result = WAD; // Start with 1
    let mut x_pow = x;    // x^1

    for i in 1..=6 {
        let term = wad_mul(x_pow, INV_FACTORIAL[i])?;
        result = result.checked_add(term).ok_or(StakingError::MathOverflow)?;
        if i < 6 {
            x_pow = wad_mul(x_pow, x)?;
        }
    }

    Ok(result)
}

/// Calculate e^(-x) where x is WAD-scaled
/// Uses e^(-x) = 1/e^x
pub fn exp_neg_wad(x: u128) -> Result<u128, StakingError> {
    if x == 0 {
        return Ok(WAD);
    }

    let exp_x = exp_wad(x)?;
    wad_div(WAD, exp_x)
}

/// Calculate e^(t/tau) where t is time in seconds, tau is time constant in seconds
/// Returns WAD-scaled result
pub fn exp_time_ratio(t: i64, tau: u64) -> Result<u128, StakingError> {
    if t <= 0 {
        return Ok(WAD);
    }
    if tau == 0 {
        return Err(StakingError::InvalidTau);
    }

    // Calculate t/tau scaled by WAD
    // t_ratio = (t * WAD) / tau
    let t_wad = (t as u128).checked_mul(WAD).ok_or(StakingError::MathOverflow)?;
    let ratio = t_wad / (tau as u128);

    exp_wad(ratio)
}

/// Calculate e^(-t/tau) where t is time in seconds, tau is time constant in seconds
/// Returns WAD-scaled result
pub fn exp_neg_time_ratio(t: i64, tau: u64) -> Result<u128, StakingError> {
    if t <= 0 {
        return Ok(WAD);
    }
    if tau == 0 {
        return Err(StakingError::InvalidTau);
    }

    let t_wad = (t as u128).checked_mul(WAD).ok_or(StakingError::MathOverflow)?;
    let ratio = t_wad / (tau as u128);

    exp_neg_wad(ratio)
}

/// Calculate weight = amount * (1 - e^(-age/tau))
/// Returns WAD-scaled weight
pub fn calculate_weight(amount: u64, age_seconds: i64, tau: u64) -> Result<u128, StakingError> {
    if age_seconds <= 0 || amount == 0 {
        return Ok(0);
    }

    let exp_neg = exp_neg_time_ratio(age_seconds, tau)?;
    let one_minus_exp = WAD.checked_sub(exp_neg).ok_or(StakingError::MathUnderflow)?;

    // weight = amount * (1 - exp_neg)
    wad_mul((amount as u128).checked_mul(WAD).ok_or(StakingError::MathOverflow)?, one_minus_exp)
}

/// Calculate total weighted stake at time t
/// total_weighted = total_staked - exp(-t/tau) * sum_stake_exp
/// Both inputs should be in their native units (not WAD scaled for amounts)
pub fn calculate_total_weighted_stake(
    total_staked: u128,
    sum_stake_exp: &U256,
    current_time: i64,
    base_time: i64,
    tau: u64,
) -> Result<u128, StakingError> {
    if total_staked == 0 {
        return Ok(0);
    }

    // Calculate exp(-(current_time - base_time) / tau)
    let age = current_time.saturating_sub(base_time);
    let exp_neg = exp_neg_time_ratio(age, tau)?;

    // exp_neg * sum_stake_exp / WAD
    let exp_neg_u256 = U256::from_u128(exp_neg);
    let decay_term = wad_mul_u256(*sum_stake_exp, exp_neg_u256)?;

    // total_staked * WAD - decay_term
    let total_staked_wad = U256::from_u128(total_staked)
        .checked_mul(WAD_U256)
        .ok_or(StakingError::MathOverflow)?;

    let weighted = total_staked_wad
        .checked_sub(decay_term)
        .ok_or(StakingError::MathUnderflow)?;

    // Convert back from U256 to u128
    weighted.to_u128().ok_or(StakingError::MathOverflow)
}

/// Calculate user's weighted stake
pub fn calculate_user_weighted_stake(
    amount: u64,
    exp_start_factor: u128,
    current_time: i64,
    base_time: i64,
    tau: u64,
) -> Result<u128, StakingError> {
    if amount == 0 {
        return Ok(0);
    }

    // User weight = amount - exp(-t/tau) * amount * exp(start_time/tau)
    //             = amount - exp(-(t - start_time)/tau) * amount
    //             = amount * (1 - exp(-age/tau))
    // But we track exp_start_factor = exp((start_time - base_time)/tau)
    // So: weight = amount * WAD - exp(-current_t/tau) * amount * exp_start_factor
    //            = amount * (WAD - exp(-(current_time - base_time)/tau) * exp_start_factor / WAD)

    let age = current_time.saturating_sub(base_time);
    let exp_neg_current = exp_neg_time_ratio(age, tau)?;

    // decay = exp_neg_current * exp_start_factor / WAD
    let decay = wad_mul(exp_neg_current, exp_start_factor)?;

    // weight = amount * (WAD - decay)
    let weight_factor = WAD.checked_sub(decay).ok_or(StakingError::MathUnderflow)?;
    wad_mul((amount as u128).checked_mul(WAD).ok_or(StakingError::MathOverflow)?, weight_factor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exp_zero() {
        assert_eq!(exp_wad(0).unwrap(), WAD);
    }

    #[test]
    fn test_exp_one() {
        let result = exp_wad(WAD).unwrap();
        // e^1 ≈ 2.718281828...
        let expected = E_WAD;
        let diff = if result > expected {
            result - expected
        } else {
            expected - result
        };
        // Allow 0.01% error
        assert!(diff < expected / 10000, "exp(1) = {} vs expected {}", result, expected);
    }

    #[test]
    fn test_exp_neg() {
        let result = exp_neg_wad(WAD).unwrap();
        // e^(-1) ≈ 0.367879441...
        let expected = 367_879_441_171_442_322u128;
        let diff = if result > expected {
            result - expected
        } else {
            expected - result
        };
        assert!(diff < expected / 10000, "exp(-1) = {} vs expected {}", result, expected);
    }

    #[test]
    fn test_weight_at_tau() {
        // At age = tau, weight should be about 63.2% of max
        let tau = 2_592_000u64; // 30 days
        let amount = 1_000_000u64;
        let weight = calculate_weight(amount, tau as i64, tau).unwrap();
        let max_weight = (amount as u128) * WAD;
        let ratio = weight * 100 / max_weight;
        // Should be ~63%
        assert!(ratio >= 62 && ratio <= 64, "Weight at tau = {}%", ratio);
    }

    #[test]
    fn test_u128_min_before_truncation() {
        // Verify that taking min() in u128 space before truncating to u64 is correct.
        // Bug scenario: pending_lamports overflows u64, truncation discards high bits.
        let pending_lamports: u128 = (u64::MAX as u128) + 1_000_000; // > u64::MAX
        let available_rewards: u64 = 500_000_000; // 0.5 SOL

        // CORRECT: min in u128 space, then truncate
        let correct = pending_lamports.min(available_rewards as u128) as u64;
        assert_eq!(correct, available_rewards);

        // INCORRECT (old bug): truncate first, then min
        let buggy = (pending_lamports as u64).min(available_rewards);
        // pending_lamports as u64 wraps around, giving a small number
        // which is less than available_rewards, so user gets less than they should
        assert_ne!(buggy, available_rewards, "truncation before min gives wrong result");

        // Also verify when pending_lamports fits in u64
        let small_pending: u128 = 100_000;
        let large_available: u64 = 500_000_000;
        let result = small_pending.min(large_available as u128) as u64;
        assert_eq!(result, 100_000);
    }

    #[test]
    fn test_u256_roundtrip() {
        let val = U256::from_u128(123456789012345678901234567890u128);
        let bytes = val.to_le_bytes();
        let restored = U256::from_le_bytes(&bytes);
        assert_eq!(val, restored);
    }
}
