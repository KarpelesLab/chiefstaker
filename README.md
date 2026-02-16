# ChiefStaker

A Solana program for staking Token 2022 tokens with time-weighted SOL reward distribution. Permissionless pool creation with creator-configurable settings.

## How It Works

Staking weight grows over time using an exponential curve:

```
weight = stake_amount * (1 - e^(-age / tau))
```

- New stakers start near **0% weight**
- Weight asymptotically approaches **100%** over time
- At 1 tau: ~63% weight
- At 3 tau: ~95% weight
- At 5 tau: ~99% weight

This prevents flash-stake attacks -- you can't just deposit right before a reward distribution and steal rewards from long-term stakers.

SOL rewards are distributed using a **snapshot-delta** formula. When rewards arrive, they are divided by `total_staked * WAD` (max weight) to produce an accumulator increment. Each staker's pending rewards are computed as:

```
pending = user_weighted * (acc_reward_per_weighted_share - snapshot) - claimed_rewards_wad
```

where `snapshot` is encoded in `reward_debt` and `claimed_rewards_wad` tracks cumulative payouts for frequency-independent claiming (claiming once or ten times yields the same total).

**Immature rewards** are the gap between max-weight entitlement and time-weighted entitlement — SOL the staker has earned "on paper" but can't claim until their weight matures further. These stay in the pool and can be redistributed via `RecoverStrandedRewards`.

### Additional Stakes (Restaking)

When a staker adds more tokens to an existing position:

1. **Auto-claim**: mature pending rewards are paid out immediately
2. **Immature preservation**: unvested rewards are preserved as a credit in the new `reward_debt` (set below the baseline so `delta_rps > 0` from the start)
3. **Weight blending**: `exp_start_factor` is recomputed as a weighted average of old and new contributions
4. **Snapshot reset**: `claimed_rewards_wad` resets to 0 for the restructured position

The immature credit gradually becomes claimable as the combined position's weight matures. At full maturity, 100% of the preserved credit is recoverable.

Rewards can be deposited directly via instruction or sent to the pool PDA (e.g., from pump.fun fee revenue) and synced.

## Features

- **Permissionless pool creation** -- anyone can create a staking pool for any Token 2022 mint
- **Time-weighted rewards** -- configurable tau (time constant) per pool
- **Creator-configurable settings** -- minimum stake amounts, lock durations, unstake cooldown periods
- **Authority management** -- transfer or renounce pool authority
- **Cooldown unstake flow** -- optional request/wait/complete unstake for pools that want it
- **O(1) operations** -- all instructions run in constant time regardless of staker count
- **Sybil resistant** -- splitting stake across accounts gives no advantage
- **Direct SOL rewards** -- SOL sent directly to the pool PDA is auto-detected via `SyncRewards`

## Program ID

```
3Ecf8gyRURyrBtGHS1XAVXyQik5PqgDch4VkxrH4ECcr
```

## Instructions

| # | Instruction | Description |
|---|-------------|-------------|
| 0 | `InitializePool` | Create a new staking pool for a Token 2022 mint |
| 1 | `Stake` | Stake tokens into the pool |
| 2 | `Unstake` | Unstake tokens (direct, when no cooldown) |
| 3 | `ClaimRewards` | Claim accumulated SOL rewards |
| 4 | `DepositRewards` | Deposit SOL rewards into the pool |
| 5 | `SyncPool` | Rebase pool math to prevent overflow |
| 6 | `SyncRewards` | Sync SOL sent directly to the pool PDA |
| 7 | `UpdatePoolSettings` | Set min stake, lock duration, cooldown (authority only) |
| 8 | `TransferAuthority` | Transfer or renounce pool authority |
| 9 | `RequestUnstake` | Start unstake cooldown (tokens keep earning) |
| 10 | `CompleteUnstake` | Finish unstake after cooldown elapsed |
| 11 | `CancelUnstakeRequest` | Cancel a pending unstake request |
| 12 | `CloseStakeAccount` | Close zero-balance stake account to reclaim rent |
| 13 | `RecoverStrandedRewards` | Redistribute stranded rewards (permissionless) |
| 14 | `SetPoolMetadata` | Set pool name, tags, and URL (permissionless) |

## Pool Settings

Pool creators can configure these settings at any time (until authority is renounced):

| Setting | Default | Max | Description |
|---------|---------|-----|-------------|
| `min_stake_amount` | 0 (none) | -- | Minimum tokens required to stake |
| `lock_duration_seconds` | 0 (none) | 365 days | Time staker must wait after last deposit before unstaking |
| `unstake_cooldown_seconds` | 0 (none) | 30 days | Required cooldown period via request/complete flow |

The tau value (`tau_seconds`) is set at pool creation and is **immutable**.

## Building

```bash
# Build for Solana
./scripts/build-sbf.sh

# Run unit tests
cargo test
```

## Testing

```bash
# Start a local test validator
./scripts/start-validator.sh --reset

# Deploy the program
./scripts/deploy-program.sh target/deploy/chiefstaker.so

# Run E2E tests
./scripts/run-e2e-tests.sh
```

CI runs the full E2E suite against a local test validator on every push.

## Verification

The deployed program is verified on the OtterSec registry. To verify locally:

```bash
./scripts/verify-deploy.sh
```

This runs `solana-verify verify-from-repo --remote` against the deployed program ID.

## Changelog

### v3 (current)

- **Immature rewards preservation**: staking additional tokens no longer loses unvested SOL rewards. The auto-claim pays mature rewards and the immature portion is preserved as a credit in the new `reward_debt`, gradually unlocking as the combined position matures.
- **Legacy account realloc fix**: `maybe_realloc` uses system program CPI (`system_instruction::transfer`) instead of direct lamport manipulation, fixing "instruction spent from the balance of an account it does not own" for legacy accounts.
- **System program as trailing account**: instructions that call `maybe_realloc` (claim, unstake, request unstake, complete unstake, cancel unstake) accept an optional trailing system program account for legacy account resizing.
- **Frequency-independent claims**: `claimed_rewards_wad` field tracks cumulative payouts so claiming once or many times yields the same total. Prevents repeated-claim exploits.
- **`total_rewards_claimed` accounting**: per-user cumulative lamport counter for reward tracking.

## Project Structure

```
programs/chiefstaker/src/
  lib.rs                          # Entrypoint, instruction enum, dispatch
  state.rs                        # Account state (StakingPool, UserStake)
  error.rs                        # Error types
  math.rs                         # Fixed-point exponential math (WAD-scaled)
  instructions/
    initialize.rs                 # InitializePool
    stake.rs                      # Stake (with min stake + lock guards)
    unstake.rs                    # Unstake + shared execute_unstake helper
    claim.rs                      # ClaimRewards
    deposit.rs                    # DepositRewards
    sync.rs                       # SyncPool (rebase)
    sync_rewards.rs               # SyncRewards (detect direct SOL transfers)
    update_settings.rs            # UpdatePoolSettings
    transfer_authority.rs         # TransferAuthority
    request_unstake.rs            # RequestUnstake
    complete_unstake.rs           # CompleteUnstake
    cancel_unstake.rs             # CancelUnstakeRequest
    close_stake.rs                # CloseStakeAccount
    recover_stranded.rs           # RecoverStrandedRewards
    set_metadata.rs               # SetPoolMetadata
tests/typescript/
  test_staking.ts                 # E2E tests
```

## License

[MIT](LICENSE)
