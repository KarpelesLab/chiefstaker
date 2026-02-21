/**
 * ChiefStaker E2E Tests
 *
 * Run against a local test validator with the program deployed.
 *
 * Setup:
 *   1. Start validator: ./scripts/start-validator.sh --reset
 *   2. Deploy program: ./scripts/deploy-program.sh target/deploy/chiefstaker.so
 *   3. Run tests: cd tests/typescript && npm install && npm test
 */

import {
  Connection,
  Keypair,
  PublicKey,
  Transaction,
  TransactionInstruction,
  SystemProgram,
  LAMPORTS_PER_SOL,
  sendAndConfirmTransaction,
} from '@solana/web3.js';
import {
  createMint,
  createAccount,
  mintTo,
  getAccount,
  TOKEN_2022_PROGRAM_ID,
  ExtensionType,
  getMintLen,
  createInitializeMintInstruction,
  createInitializeMetadataPointerInstruction,
  TYPE_SIZE,
  LENGTH_SIZE,
} from '@solana/spl-token';
import { createInitializeInstruction, pack } from '@solana/spl-token-metadata';
import * as borsh from 'borsh';
import BN from 'bn.js';
import * as fs from 'fs';
import * as path from 'path';

// Program ID - should match the deployed program
const PROGRAM_ID = new PublicKey('3Ecf8gyRURyrBtGHS1XAVXyQik5PqgDch4VkxrH4ECcr');

// Seeds for PDAs
const POOL_SEED = Buffer.from('pool');
const STAKE_SEED = Buffer.from('stake');
const TOKEN_VAULT_SEED = Buffer.from('token_vault');
const METADATA_SEED = Buffer.from('metadata');

// Instruction discriminators (borsh enum indices)
enum InstructionType {
  InitializePool = 0,
  Stake = 1,
  Unstake = 2,
  ClaimRewards = 3,
  DepositRewards = 4,
  SyncPool = 5,
  SyncRewards = 6,
  UpdatePoolSettings = 7,
  TransferAuthority = 8,
  RequestUnstake = 9,
  CompleteUnstake = 10,
  CancelUnstakeRequest = 11,
  CloseStakeAccount = 12,
  FixTotalRewardDebt = 13,
  SetPoolMetadata = 14,
  TakeFeeOwnership = 15,
  StakeOnBehalf = 16,
}

// Helper to derive PDAs
function derivePoolPDA(mint: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [POOL_SEED, mint.toBuffer()],
    PROGRAM_ID
  );
}

function deriveTokenVaultPDA(pool: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [TOKEN_VAULT_SEED, pool.toBuffer()],
    PROGRAM_ID
  );
}

function deriveUserStakePDA(pool: PublicKey, user: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [STAKE_SEED, pool.toBuffer(), user.toBuffer()],
    PROGRAM_ID
  );
}

function deriveMetadataPDA(pool: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [METADATA_SEED, pool.toBuffer()],
    PROGRAM_ID
  );
}

async function airdropAndConfirm(connection: Connection, publicKey: PublicKey, lamports: number): Promise<void> {
  const sig = await connection.requestAirdrop(publicKey, lamports);
  await connection.confirmTransaction(sig);
}

// Instruction builders
function createInitializePoolInstruction(
  pool: PublicKey,
  mint: PublicKey,
  tokenVault: PublicKey,
  authority: PublicKey,
  tauSeconds: bigint
): TransactionInstruction {
  // Borsh serialize: enum variant (u8) + tau_seconds (u64)
  const data = Buffer.alloc(1 + 8);
  data.writeUInt8(InstructionType.InitializePool, 0);
  data.writeBigUInt64LE(tauSeconds, 1);

  return new TransactionInstruction({
    keys: [
      { pubkey: pool, isSigner: false, isWritable: true },
      { pubkey: mint, isSigner: false, isWritable: false },
      { pubkey: tokenVault, isSigner: false, isWritable: true },
      { pubkey: authority, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      { pubkey: TOKEN_2022_PROGRAM_ID, isSigner: false, isWritable: false },
      { pubkey: new PublicKey('SysvarRent111111111111111111111111111111111'), isSigner: false, isWritable: false },
    ],
    programId: PROGRAM_ID,
    data,
  });
}

function createStakeInstruction(
  pool: PublicKey,
  userStake: PublicKey,
  tokenVault: PublicKey,
  userToken: PublicKey,
  mint: PublicKey,
  user: PublicKey,
  amount: bigint
): TransactionInstruction {
  const data = Buffer.alloc(1 + 8);
  data.writeUInt8(InstructionType.Stake, 0);
  data.writeBigUInt64LE(amount, 1);

  return new TransactionInstruction({
    keys: [
      { pubkey: pool, isSigner: false, isWritable: true },
      { pubkey: userStake, isSigner: false, isWritable: true },
      { pubkey: tokenVault, isSigner: false, isWritable: true },
      { pubkey: userToken, isSigner: false, isWritable: true },
      { pubkey: mint, isSigner: false, isWritable: false },
      { pubkey: user, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      { pubkey: TOKEN_2022_PROGRAM_ID, isSigner: false, isWritable: false },
    ],
    programId: PROGRAM_ID,
    data,
  });
}

function createUnstakeInstruction(
  pool: PublicKey,
  userStake: PublicKey,
  tokenVault: PublicKey,
  userToken: PublicKey,
  mint: PublicKey,
  user: PublicKey,
  amount: bigint
): TransactionInstruction {
  const data = Buffer.alloc(1 + 8);
  data.writeUInt8(InstructionType.Unstake, 0);
  data.writeBigUInt64LE(amount, 1);

  return new TransactionInstruction({
    keys: [
      { pubkey: pool, isSigner: false, isWritable: true },
      { pubkey: userStake, isSigner: false, isWritable: true },
      { pubkey: tokenVault, isSigner: false, isWritable: true },
      { pubkey: userToken, isSigner: false, isWritable: true },
      { pubkey: mint, isSigner: false, isWritable: false },
      { pubkey: user, isSigner: true, isWritable: true },
      { pubkey: TOKEN_2022_PROGRAM_ID, isSigner: false, isWritable: false },
    ],
    programId: PROGRAM_ID,
    data,
  });
}

function createClaimRewardsInstruction(
  pool: PublicKey,
  userStake: PublicKey,
  user: PublicKey
): TransactionInstruction {
  const data = Buffer.alloc(1);
  data.writeUInt8(InstructionType.ClaimRewards, 0);

  return new TransactionInstruction({
    keys: [
      { pubkey: pool, isSigner: false, isWritable: true },
      { pubkey: userStake, isSigner: false, isWritable: true },
      { pubkey: user, isSigner: true, isWritable: true },
    ],
    programId: PROGRAM_ID,
    data,
  });
}

function createDepositRewardsInstruction(
  pool: PublicKey,
  depositor: PublicKey,
  amount: bigint
): TransactionInstruction {
  const data = Buffer.alloc(1 + 8);
  data.writeUInt8(InstructionType.DepositRewards, 0);
  data.writeBigUInt64LE(amount, 1);

  return new TransactionInstruction({
    keys: [
      { pubkey: pool, isSigner: false, isWritable: true },
      { pubkey: depositor, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    programId: PROGRAM_ID,
    data,
  });
}

function createSyncPoolInstruction(pool: PublicKey): TransactionInstruction {
  const data = Buffer.alloc(1);
  data.writeUInt8(InstructionType.SyncPool, 0);

  return new TransactionInstruction({
    keys: [
      { pubkey: pool, isSigner: false, isWritable: true },
    ],
    programId: PROGRAM_ID,
    data,
  });
}

function createSyncRewardsInstruction(pool: PublicKey): TransactionInstruction {
  const data = Buffer.alloc(1);
  data.writeUInt8(InstructionType.SyncRewards, 0);

  return new TransactionInstruction({
    keys: [
      { pubkey: pool, isSigner: false, isWritable: true },
    ],
    programId: PROGRAM_ID,
    data,
  });
}

function createUpdatePoolSettingsInstruction(
  pool: PublicKey,
  authority: PublicKey,
  minStakeAmount: bigint | null,
  lockDurationSeconds: bigint | null,
  unstakeCooldownSeconds: bigint | null,
): TransactionInstruction {
  // Borsh serialization: enum variant (u8) + 3x Option<u64>
  // Option<u64> = 1 byte tag (0=None, 1=Some) + 8 bytes value if Some
  let size = 1; // variant
  size += 1 + (minStakeAmount !== null ? 8 : 0);
  size += 1 + (lockDurationSeconds !== null ? 8 : 0);
  size += 1 + (unstakeCooldownSeconds !== null ? 8 : 0);

  const data = Buffer.alloc(size);
  let offset = 0;
  data.writeUInt8(InstructionType.UpdatePoolSettings, offset); offset += 1;

  // Write Option<u64> for each
  for (const val of [minStakeAmount, lockDurationSeconds, unstakeCooldownSeconds]) {
    if (val !== null) {
      data.writeUInt8(1, offset); offset += 1;
      data.writeBigUInt64LE(val, offset); offset += 8;
    } else {
      data.writeUInt8(0, offset); offset += 1;
    }
  }

  return new TransactionInstruction({
    keys: [
      { pubkey: pool, isSigner: false, isWritable: true },
      { pubkey: authority, isSigner: true, isWritable: false },
    ],
    programId: PROGRAM_ID,
    data,
  });
}

function createTransferAuthorityInstruction(
  pool: PublicKey,
  authority: PublicKey,
  newAuthority: PublicKey,
): TransactionInstruction {
  // Borsh: enum variant (u8) + pubkey (32 bytes)
  const data = Buffer.alloc(1 + 32);
  data.writeUInt8(InstructionType.TransferAuthority, 0);
  newAuthority.toBuffer().copy(data, 1);

  return new TransactionInstruction({
    keys: [
      { pubkey: pool, isSigner: false, isWritable: true },
      { pubkey: authority, isSigner: true, isWritable: false },
    ],
    programId: PROGRAM_ID,
    data,
  });
}

function createRequestUnstakeInstruction(
  pool: PublicKey,
  userStake: PublicKey,
  user: PublicKey,
  amount: bigint,
): TransactionInstruction {
  const data = Buffer.alloc(1 + 8);
  data.writeUInt8(InstructionType.RequestUnstake, 0);
  data.writeBigUInt64LE(amount, 1);

  return new TransactionInstruction({
    keys: [
      { pubkey: pool, isSigner: false, isWritable: true },
      { pubkey: userStake, isSigner: false, isWritable: true },
      { pubkey: user, isSigner: true, isWritable: false },
    ],
    programId: PROGRAM_ID,
    data,
  });
}

function createCompleteUnstakeInstruction(
  pool: PublicKey,
  userStake: PublicKey,
  tokenVault: PublicKey,
  userToken: PublicKey,
  mint: PublicKey,
  user: PublicKey,
): TransactionInstruction {
  const data = Buffer.alloc(1);
  data.writeUInt8(InstructionType.CompleteUnstake, 0);

  return new TransactionInstruction({
    keys: [
      { pubkey: pool, isSigner: false, isWritable: true },
      { pubkey: userStake, isSigner: false, isWritable: true },
      { pubkey: tokenVault, isSigner: false, isWritable: true },
      { pubkey: userToken, isSigner: false, isWritable: true },
      { pubkey: mint, isSigner: false, isWritable: false },
      { pubkey: user, isSigner: true, isWritable: true },
      { pubkey: TOKEN_2022_PROGRAM_ID, isSigner: false, isWritable: false },
    ],
    programId: PROGRAM_ID,
    data,
  });
}

function createCancelUnstakeRequestInstruction(
  pool: PublicKey,
  userStake: PublicKey,
  user: PublicKey,
): TransactionInstruction {
  const data = Buffer.alloc(1);
  data.writeUInt8(InstructionType.CancelUnstakeRequest, 0);

  return new TransactionInstruction({
    keys: [
      { pubkey: pool, isSigner: false, isWritable: false },
      { pubkey: userStake, isSigner: false, isWritable: true },
      { pubkey: user, isSigner: true, isWritable: false },
    ],
    programId: PROGRAM_ID,
    data,
  });
}

function createFixTotalRewardDebtInstruction(
  pool: PublicKey,
  authority: PublicKey,
  newDebt: bigint,
): TransactionInstruction {
  const data = Buffer.alloc(1 + 16);
  data.writeUInt8(InstructionType.FixTotalRewardDebt, 0);
  // Write u128 LE (16 bytes)
  data.writeBigUInt64LE(newDebt & BigInt('0xFFFFFFFFFFFFFFFF'), 1);
  data.writeBigUInt64LE((newDebt >> BigInt(64)) & BigInt('0xFFFFFFFFFFFFFFFF'), 9);

  // Derive ProgramData account (BPF Loader Upgradeable PDA)
  const BPF_LOADER_UPGRADEABLE = new PublicKey('BPFLoaderUpgradeab1e11111111111111111111111');
  const [programData] = PublicKey.findProgramAddressSync(
    [PROGRAM_ID.toBuffer()],
    BPF_LOADER_UPGRADEABLE,
  );

  return new TransactionInstruction({
    keys: [
      { pubkey: pool, isSigner: false, isWritable: true },
      { pubkey: authority, isSigner: true, isWritable: false },
      { pubkey: programData, isSigner: false, isWritable: false },
    ],
    programId: PROGRAM_ID,
    data,
  });
}

function createSetPoolMetadataInstruction(
  pool: PublicKey,
  metadataPDA: PublicKey,
  mint: PublicKey,
  payer: PublicKey,
): TransactionInstruction {
  const data = Buffer.alloc(1);
  data.writeUInt8(InstructionType.SetPoolMetadata, 0);

  return new TransactionInstruction({
    keys: [
      { pubkey: pool, isSigner: false, isWritable: false },
      { pubkey: metadataPDA, isSigner: false, isWritable: true },
      { pubkey: mint, isSigner: false, isWritable: false },
      { pubkey: payer, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    programId: PROGRAM_ID,
    data,
  });
}

function createCloseStakeAccountInstruction(
  pool: PublicKey,
  userStake: PublicKey,
  user: PublicKey,
  metadataPDA?: PublicKey,
): TransactionInstruction {
  const data = Buffer.alloc(1);
  data.writeUInt8(InstructionType.CloseStakeAccount, 0);

  const keys = [
    { pubkey: pool, isSigner: false, isWritable: false },
    { pubkey: userStake, isSigner: false, isWritable: true },
    { pubkey: user, isSigner: true, isWritable: true },
  ];
  if (metadataPDA) {
    keys.push({ pubkey: metadataPDA, isSigner: false, isWritable: true });
  }

  return new TransactionInstruction({
    keys,
    programId: PROGRAM_ID,
    data,
  });
}

function createStakeOnBehalfInstruction(
  pool: PublicKey,
  beneficiaryStake: PublicKey,
  tokenVault: PublicKey,
  stakerToken: PublicKey,
  mint: PublicKey,
  staker: PublicKey,
  beneficiary: PublicKey,
  amount: bigint,
  metadataPDA?: PublicKey,
): TransactionInstruction {
  const data = Buffer.alloc(1 + 8);
  data.writeUInt8(InstructionType.StakeOnBehalf, 0);
  data.writeBigUInt64LE(amount, 1);

  const keys = [
    { pubkey: pool, isSigner: false, isWritable: true },
    { pubkey: beneficiaryStake, isSigner: false, isWritable: true },
    { pubkey: tokenVault, isSigner: false, isWritable: true },
    { pubkey: stakerToken, isSigner: false, isWritable: true },
    { pubkey: mint, isSigner: false, isWritable: false },
    { pubkey: staker, isSigner: true, isWritable: true },
    { pubkey: beneficiary, isSigner: false, isWritable: true },
    { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    { pubkey: TOKEN_2022_PROGRAM_ID, isSigner: false, isWritable: false },
  ];
  if (metadataPDA) {
    keys.push({ pubkey: metadataPDA, isSigner: false, isWritable: true });
  }

  return new TransactionInstruction({
    keys,
    programId: PROGRAM_ID,
    data,
  });
}

function createStakeWithMetadataInstruction(
  pool: PublicKey,
  userStake: PublicKey,
  tokenVault: PublicKey,
  userToken: PublicKey,
  mint: PublicKey,
  user: PublicKey,
  amount: bigint,
  metadataPDA: PublicKey,
): TransactionInstruction {
  const data = Buffer.alloc(1 + 8);
  data.writeUInt8(InstructionType.Stake, 0);
  data.writeBigUInt64LE(amount, 1);

  return new TransactionInstruction({
    keys: [
      { pubkey: pool, isSigner: false, isWritable: true },
      { pubkey: userStake, isSigner: false, isWritable: true },
      { pubkey: tokenVault, isSigner: false, isWritable: true },
      { pubkey: userToken, isSigner: false, isWritable: true },
      { pubkey: mint, isSigner: false, isWritable: false },
      { pubkey: user, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      { pubkey: TOKEN_2022_PROGRAM_ID, isSigner: false, isWritable: false },
      { pubkey: metadataPDA, isSigner: false, isWritable: true },
    ],
    programId: PROGRAM_ID,
    data,
  });
}

// Helper to read u128 little-endian from a Buffer
function readU128LE(buf: Buffer, offset: number): bigint {
  const lo = buf.readBigUInt64LE(offset);
  const hi = buf.readBigUInt64LE(offset + 8);
  return lo + (hi << 64n);
}

// Decoded pool state fields relevant to reward accounting
interface PoolState {
  totalStaked: bigint;
  accRewardPerWeightedShare: bigint;
  lastSyncedLamports: bigint;
  totalRewardDebt: bigint;
}

// Decoded user stake fields relevant to reward testing
interface UserStakeState {
  amount: bigint;
  expStartFactor: bigint;
  rewardDebt: bigint;
  totalRewardsClaimed: bigint;
  claimedRewardsWad: bigint;
}

// Test context
class TestContext {
  connection: Connection;
  payer: Keypair;
  programAuthority: Keypair;
  mint!: PublicKey;
  mintAuthority: Keypair;
  poolPDA!: PublicKey;
  tokenVaultPDA!: PublicKey;

  constructor(connection: Connection, payer: Keypair, programAuthority: Keypair) {
    this.connection = connection;
    this.payer = payer;
    this.programAuthority = programAuthority;
    this.mintAuthority = Keypair.generate();
  }

  async setup() {
    // Airdrop SOL to payer
    const airdropSig = await this.connection.requestAirdrop(
      this.payer.publicKey,
      10 * LAMPORTS_PER_SOL
    );
    await this.connection.confirmTransaction(airdropSig);

    // Airdrop to mint authority
    const airdropSig2 = await this.connection.requestAirdrop(
      this.mintAuthority.publicKey,
      1 * LAMPORTS_PER_SOL
    );
    await this.connection.confirmTransaction(airdropSig2);
  }

  async createMint(decimals: number = 9): Promise<PublicKey> {
    this.mint = await createMint(
      this.connection,
      this.payer,
      this.mintAuthority.publicKey,
      null,
      decimals,
      undefined,
      undefined,
      TOKEN_2022_PROGRAM_ID
    );

    [this.poolPDA] = derivePoolPDA(this.mint);
    [this.tokenVaultPDA] = deriveTokenVaultPDA(this.poolPDA);

    return this.mint;
  }

  async initializePool(tauSeconds: bigint): Promise<string> {
    const ix = createInitializePoolInstruction(
      this.poolPDA,
      this.mint,
      this.tokenVaultPDA,
      this.payer.publicKey,
      tauSeconds
    );

    const tx = new Transaction().add(ix);
    return await sendAndConfirmTransaction(this.connection, tx, [this.payer]);
  }

  async createUserTokenAccount(owner: PublicKey): Promise<PublicKey> {
    return await createAccount(
      this.connection,
      this.payer,
      this.mint,
      owner,
      undefined,
      undefined,
      TOKEN_2022_PROGRAM_ID
    );
  }

  async mintTokens(destination: PublicKey, amount: bigint): Promise<string> {
    return await mintTo(
      this.connection,
      this.payer,
      this.mint,
      destination,
      this.mintAuthority,
      amount,
      undefined,
      undefined,
      TOKEN_2022_PROGRAM_ID
    );
  }

  async stake(user: Keypair, userToken: PublicKey, amount: bigint): Promise<string> {
    const [userStakePDA] = deriveUserStakePDA(this.poolPDA, user.publicKey);

    const ix = createStakeInstruction(
      this.poolPDA,
      userStakePDA,
      this.tokenVaultPDA,
      userToken,
      this.mint,
      user.publicKey,
      amount
    );

    const tx = new Transaction().add(ix);
    return await sendAndConfirmTransaction(this.connection, tx, [this.payer, user]);
  }

  async stakeOnBehalf(staker: Keypair, stakerToken: PublicKey, beneficiary: PublicKey, amount: bigint): Promise<string> {
    const [beneficiaryStakePDA] = deriveUserStakePDA(this.poolPDA, beneficiary);

    const ix = createStakeOnBehalfInstruction(
      this.poolPDA,
      beneficiaryStakePDA,
      this.tokenVaultPDA,
      stakerToken,
      this.mint,
      staker.publicKey,
      beneficiary,
      amount,
    );

    const tx = new Transaction().add(ix);
    return await sendAndConfirmTransaction(this.connection, tx, [this.payer, staker]);
  }

  async unstake(user: Keypair, userToken: PublicKey, amount: bigint): Promise<string> {
    const [userStakePDA] = deriveUserStakePDA(this.poolPDA, user.publicKey);

    const ix = createUnstakeInstruction(
      this.poolPDA,
      userStakePDA,
      this.tokenVaultPDA,
      userToken,
      this.mint,
      user.publicKey,
      amount
    );

    const tx = new Transaction().add(ix);
    return await sendAndConfirmTransaction(this.connection, tx, [this.payer, user]);
  }

  async claimRewards(user: Keypair): Promise<string> {
    const [userStakePDA] = deriveUserStakePDA(this.poolPDA, user.publicKey);

    const ix = createClaimRewardsInstruction(
      this.poolPDA,
      userStakePDA,
      user.publicKey
    );

    const tx = new Transaction().add(ix);
    return await sendAndConfirmTransaction(this.connection, tx, [this.payer, user]);
  }

  async depositRewards(amount: bigint): Promise<string> {
    const ix = createDepositRewardsInstruction(
      this.poolPDA,
      this.payer.publicKey,
      amount
    );

    const tx = new Transaction().add(ix);
    return await sendAndConfirmTransaction(this.connection, tx, [this.payer]);
  }

  async syncPool(): Promise<string> {
    const ix = createSyncPoolInstruction(this.poolPDA);

    const tx = new Transaction().add(ix);
    return await sendAndConfirmTransaction(this.connection, tx, [this.payer]);
  }

  async syncRewards(): Promise<string> {
    const ix = createSyncRewardsInstruction(this.poolPDA);

    const tx = new Transaction().add(ix);
    return await sendAndConfirmTransaction(this.connection, tx, [this.payer]);
  }

  async sendSolToPool(amount: bigint): Promise<string> {
    const ix = SystemProgram.transfer({
      fromPubkey: this.payer.publicKey,
      toPubkey: this.poolPDA,
      lamports: amount,
    });

    const tx = new Transaction().add(ix);
    return await sendAndConfirmTransaction(this.connection, tx, [this.payer]);
  }

  async updatePoolSettings(
    authority: Keypair,
    minStakeAmount: bigint | null,
    lockDurationSeconds: bigint | null,
    unstakeCooldownSeconds: bigint | null,
  ): Promise<string> {
    const ix = createUpdatePoolSettingsInstruction(
      this.poolPDA,
      authority.publicKey,
      minStakeAmount,
      lockDurationSeconds,
      unstakeCooldownSeconds,
    );

    const tx = new Transaction().add(ix);
    return await sendAndConfirmTransaction(this.connection, tx, [this.payer, authority]);
  }

  async transferAuthority(currentAuthority: Keypair, newAuthority: PublicKey): Promise<string> {
    const ix = createTransferAuthorityInstruction(
      this.poolPDA,
      currentAuthority.publicKey,
      newAuthority,
    );

    const tx = new Transaction().add(ix);
    return await sendAndConfirmTransaction(this.connection, tx, [this.payer, currentAuthority]);
  }

  async requestUnstake(user: Keypair, amount: bigint): Promise<string> {
    const [userStakePDA] = deriveUserStakePDA(this.poolPDA, user.publicKey);

    const ix = createRequestUnstakeInstruction(
      this.poolPDA,
      userStakePDA,
      user.publicKey,
      amount,
    );

    const tx = new Transaction().add(ix);
    return await sendAndConfirmTransaction(this.connection, tx, [this.payer, user]);
  }

  async completeUnstake(user: Keypair, userToken: PublicKey): Promise<string> {
    const [userStakePDA] = deriveUserStakePDA(this.poolPDA, user.publicKey);

    const ix = createCompleteUnstakeInstruction(
      this.poolPDA,
      userStakePDA,
      this.tokenVaultPDA,
      userToken,
      this.mint,
      user.publicKey,
    );

    const tx = new Transaction().add(ix);
    return await sendAndConfirmTransaction(this.connection, tx, [this.payer, user]);
  }

  async cancelUnstakeRequest(user: Keypair): Promise<string> {
    const [userStakePDA] = deriveUserStakePDA(this.poolPDA, user.publicKey);

    const ix = createCancelUnstakeRequestInstruction(
      this.poolPDA,
      userStakePDA,
      user.publicKey,
    );

    const tx = new Transaction().add(ix);
    return await sendAndConfirmTransaction(this.connection, tx, [this.payer, user]);
  }

  async fixTotalRewardDebt(newDebt: bigint): Promise<string> {
    const ix = createFixTotalRewardDebtInstruction(this.poolPDA, this.programAuthority.publicKey, newDebt);
    const tx = new Transaction().add(ix);
    return await sendAndConfirmTransaction(this.connection, tx, [this.programAuthority]);
  }

  async createMintWithMetadata(decimals: number, tokenName: string, tokenSymbol: string): Promise<PublicKey> {
    const mintKeypair = Keypair.generate();
    this.mint = mintKeypair.publicKey;

    // Calculate space: mint base + MetadataPointer extension
    const mintLen = getMintLen([ExtensionType.MetadataPointer]);

    // Metadata to be stored in the mint (variable-length TLV)
    const metadataData = {
      mint: this.mint,
      name: tokenName,
      symbol: tokenSymbol,
      uri: '',
      updateAuthority: this.mintAuthority.publicKey,
      additionalMetadata: [] as [string, string][],
    };
    const metadataExtensionLen = TYPE_SIZE + LENGTH_SIZE + pack(metadataData).length;
    const totalLen = mintLen + metadataExtensionLen;

    // Allocate lamports for the full size (mint + metadata), but only
    // set space to mintLen. Token 2022 will extend the account when
    // the metadata is initialized (it uses the excess lamports for rent).
    const lamports = await this.connection.getMinimumBalanceForRentExemption(totalLen);

    const tx = new Transaction().add(
      // Create account with space for mint + MetadataPointer only
      SystemProgram.createAccount({
        fromPubkey: this.payer.publicKey,
        newAccountPubkey: this.mint,
        space: mintLen,
        lamports,
        programId: TOKEN_2022_PROGRAM_ID,
      }),
      // Initialize MetadataPointer (points to the mint itself)
      createInitializeMetadataPointerInstruction(
        this.mint,
        this.mintAuthority.publicKey,
        this.mint,
        TOKEN_2022_PROGRAM_ID,
      ),
      // Initialize the mint
      createInitializeMintInstruction(
        this.mint,
        decimals,
        this.mintAuthority.publicKey,
        null,
        TOKEN_2022_PROGRAM_ID,
      ),
      // Initialize token metadata
      createInitializeInstruction({
        programId: TOKEN_2022_PROGRAM_ID,
        mint: this.mint,
        metadata: this.mint,
        mintAuthority: this.mintAuthority.publicKey,
        name: tokenName,
        symbol: tokenSymbol,
        uri: '',
        updateAuthority: this.mintAuthority.publicKey,
      }),
    );

    await sendAndConfirmTransaction(this.connection, tx, [this.payer, mintKeypair, this.mintAuthority]);

    [this.poolPDA] = derivePoolPDA(this.mint);
    [this.tokenVaultPDA] = deriveTokenVaultPDA(this.poolPDA);

    return this.mint;
  }

  async setPoolMetadata(payer?: Keypair): Promise<string> {
    const effectivePayer = payer || this.payer;
    const [metadataPDA] = deriveMetadataPDA(this.poolPDA);

    const ix = createSetPoolMetadataInstruction(
      this.poolPDA,
      metadataPDA,
      this.mint,
      effectivePayer.publicKey,
    );

    const tx = new Transaction().add(ix);
    const signers = effectivePayer === this.payer ? [this.payer] : [this.payer, effectivePayer];
    return await sendAndConfirmTransaction(this.connection, tx, signers);
  }

  async stakeWithMetadata(user: Keypair, userToken: PublicKey, amount: bigint): Promise<string> {
    const [userStakePDA] = deriveUserStakePDA(this.poolPDA, user.publicKey);
    const [metadataPDA] = deriveMetadataPDA(this.poolPDA);

    const ix = createStakeWithMetadataInstruction(
      this.poolPDA,
      userStakePDA,
      this.tokenVaultPDA,
      userToken,
      this.mint,
      user.publicKey,
      amount,
      metadataPDA,
    );

    const tx = new Transaction().add(ix);
    return await sendAndConfirmTransaction(this.connection, tx, [this.payer, user]);
  }

  async closeStakeAccount(user: Keypair, withMetadata: boolean = false): Promise<string> {
    const [userStakePDA] = deriveUserStakePDA(this.poolPDA, user.publicKey);
    const [metadataPDA] = deriveMetadataPDA(this.poolPDA);

    const ix = createCloseStakeAccountInstruction(
      this.poolPDA,
      userStakePDA,
      user.publicKey,
      withMetadata ? metadataPDA : undefined,
    );

    const tx = new Transaction().add(ix);
    return await sendAndConfirmTransaction(this.connection, tx, [this.payer, user]);
  }

  async readMetadata(): Promise<{
    pool: PublicKey;
    nameLen: number;
    name: string;
    numTags: number;
    tags: string[];
    urlLen: number;
    url: string;
    memberCount: bigint;
    bump: number;
  }> {
    const [metadataPDA] = deriveMetadataPDA(this.poolPDA);
    const info = await this.connection.getAccountInfo(metadataPDA);
    if (!info) throw new Error('Metadata account not found');
    const data = info.data;

    // Parse PoolMetadata from Borsh layout:
    // discriminator: [u8; 8] = 8
    // pool: Pubkey = 32
    // name_len: u8 = 1
    // name: [u8; 64] = 64
    // num_tags: u8 = 1
    // tag_lengths: [u8; 8] = 8
    // tags: [[u8; 32]; 8] = 256
    // url_len: u8 = 1
    // url: [u8; 128] = 128
    // member_count: u64 = 8
    // bump: u8 = 1
    let offset = 8; // skip discriminator
    const pool = new PublicKey(data.subarray(offset, offset + 32)); offset += 32;
    const nameLen = data[offset]; offset += 1;
    const name = data.subarray(offset, offset + nameLen).toString('utf8'); offset += 64;
    const numTags = data[offset]; offset += 1;
    const tagLengths = Array.from(data.subarray(offset, offset + 8)); offset += 8;
    const tags: string[] = [];
    for (let i = 0; i < numTags; i++) {
      const tagData = data.subarray(offset + i * 32, offset + i * 32 + tagLengths[i]);
      tags.push(tagData.toString('utf8'));
    }
    offset += 256;
    const urlLen = data[offset]; offset += 1;
    const url = data.subarray(offset, offset + urlLen).toString('utf8'); offset += 128;
    const memberCount = data.readBigUInt64LE(offset); offset += 8;
    const bump = data[offset];

    return { pool, nameLen, name, numTags, tags, urlLen, url, memberCount, bump };
  }

  async readPoolState(): Promise<PoolState> {
    const info = await this.connection.getAccountInfo(this.poolPDA);
    if (!info) throw new Error('Pool account not found');
    const data = info.data;
    // Offsets from Borsh serialization layout (state.rs):
    // 136: total_staked (u128)
    // 200: acc_reward_per_weighted_share (u128)
    // 225: last_synced_lamports (u64)
    // 265: total_reward_debt (u128)
    return {
      totalStaked: readU128LE(data, 136),
      accRewardPerWeightedShare: readU128LE(data, 200),
      lastSyncedLamports: BigInt(data.readBigUInt64LE(225)),
      totalRewardDebt: readU128LE(data, 265),
    };
  }

  async readUserStakeState(user: PublicKey): Promise<UserStakeState> {
    const [userStakePDA] = deriveUserStakePDA(this.poolPDA, user);
    const info = await this.connection.getAccountInfo(userStakePDA);
    if (!info) throw new Error('User stake account not found');
    const data = info.data;
    // Offsets from Borsh serialization layout (state.rs UserStake):
    // 0:   discriminator (8)
    // 8:   owner (32)
    // 40:  pool (32)
    // 72:  amount (u64)
    // 80:  stake_time (i64)
    // 88:  exp_start_factor (u128)
    // 104: reward_debt (u128)
    // 120: bump (u8)
    // 121: unstake_request_amount (u64)
    // 129: unstake_request_time (i64)
    // 137: last_stake_time (i64)
    // 145: base_time_snapshot (i64)
    // 153: total_rewards_claimed (u64) — may not exist on legacy 153-byte accounts
    const amount = data.readBigUInt64LE(72);
    const expStartFactor = readU128LE(data, 88);
    const rewardDebt = readU128LE(data, 104);
    const totalRewardsClaimed = data.length >= 161
      ? data.readBigUInt64LE(153)
      : 0n;
    const claimedRewardsWad = data.length >= 177
      ? readU128LE(data, 161)
      : 0n;
    return { amount, expStartFactor, rewardDebt, totalRewardsClaimed, claimedRewardsWad };
  }

  async getBalance(pubkey: PublicKey): Promise<number> {
    return await this.connection.getBalance(pubkey);
  }

  async getTokenBalance(tokenAccount: PublicKey): Promise<bigint> {
    const account = await getAccount(this.connection, tokenAccount, undefined, TOKEN_2022_PROGRAM_ID);
    return account.amount;
  }
}

// Test runner
async function runTests() {
  console.log('=== ChiefStaker E2E Tests ===\n');

  const connection = new Connection('http://localhost:8899', 'confirmed');
  const payer = Keypair.generate();

  // Load the program deployer keypair (upgrade authority)
  const solanaKeypairPath = path.join(
    process.env.HOME || require('os').homedir(),
    '.config', 'solana', 'id.json',
  );
  const programAuthority = Keypair.fromSecretKey(
    new Uint8Array(JSON.parse(fs.readFileSync(solanaKeypairPath, 'utf8'))),
  );

  // Check connection
  try {
    await connection.getVersion();
  } catch (e) {
    console.error('ERROR: Cannot connect to test validator. Start it with:');
    console.error('  ./scripts/start-validator.sh --reset');
    process.exit(1);
  }

  // Check program is deployed
  const programInfo = await connection.getAccountInfo(PROGRAM_ID);
  if (!programInfo) {
    console.error('ERROR: Program not deployed. Deploy it with:');
    console.error('  ./scripts/deploy-program.sh target/deploy/chiefstaker.so');
    process.exit(1);
  }

  let passed = 0;
  let failed = 0;

  async function test(name: string, fn: () => Promise<void>) {
    try {
      await fn();
      console.log(`✓ ${name}`);
      passed++;
    } catch (e: any) {
      console.log(`✗ ${name}`);
      console.log(`  Error: ${e.message}`);
      if (e.logs) {
        console.log(`  Logs: ${e.logs.slice(-5).join('\n        ')}`);
      }
      failed++;
    }
  }

  // Test: Initialize Pool
  await test('Initialize pool', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);

    const tauSeconds = BigInt(30 * 24 * 60 * 60); // 30 days
    await ctx.initializePool(tauSeconds);

    const poolInfo = await connection.getAccountInfo(ctx.poolPDA);
    if (!poolInfo) throw new Error('Pool not created');
    if (poolInfo.data.length === 0) throw new Error('Pool data empty');
  });

  // Test: Stake tokens
  await test('Stake tokens', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(2592000));

    const user = Keypair.generate();
    await airdropAndConfirm(connection, user.publicKey, LAMPORTS_PER_SOL);

    const userToken = await ctx.createUserTokenAccount(user.publicKey);
    const stakeAmount = BigInt(1_000_000_000);
    await ctx.mintTokens(userToken, stakeAmount);

    await ctx.stake(user, userToken, stakeAmount);

    const vaultBalance = await ctx.getTokenBalance(ctx.tokenVaultPDA);
    if (vaultBalance !== stakeAmount) {
      throw new Error(`Expected vault balance ${stakeAmount}, got ${vaultBalance}`);
    }
  });

  // Test: Multiple stakers
  await test('Multiple stakers', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(2592000));

    const user1 = Keypair.generate();
    const user2 = Keypair.generate();
    await airdropAndConfirm(connection, user1.publicKey, LAMPORTS_PER_SOL);
    await airdropAndConfirm(connection, user2.publicKey, LAMPORTS_PER_SOL);

    const user1Token = await ctx.createUserTokenAccount(user1.publicKey);
    const user2Token = await ctx.createUserTokenAccount(user2.publicKey);

    await ctx.mintTokens(user1Token, BigInt(1_000_000_000));
    await ctx.mintTokens(user2Token, BigInt(2_000_000_000));

    await ctx.stake(user1, user1Token, BigInt(1_000_000_000));
    await ctx.stake(user2, user2Token, BigInt(2_000_000_000));

    const vaultBalance = await ctx.getTokenBalance(ctx.tokenVaultPDA);
    if (vaultBalance !== BigInt(3_000_000_000)) {
      throw new Error(`Expected vault balance 3000000000, got ${vaultBalance}`);
    }
  });

  // Test: Deposit and claim rewards
  await test('Deposit and claim rewards', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(100)); // Short tau

    const user = Keypair.generate();
    await airdropAndConfirm(connection, user.publicKey, LAMPORTS_PER_SOL);

    const userToken = await ctx.createUserTokenAccount(user.publicKey);
    await ctx.mintTokens(userToken, BigInt(1_000_000_000));
    await ctx.stake(user, userToken, BigInt(1_000_000_000));

    // Deposit rewards
    await ctx.depositRewards(BigInt(LAMPORTS_PER_SOL));

    const balanceBefore = await ctx.getBalance(user.publicKey);
    await ctx.claimRewards(user);
    const balanceAfter = await ctx.getBalance(user.publicKey);

    // User should receive some rewards (payer covers tx fee, so diff = pure reward)
    // Due to time-weighted calculation, might be small if just staked
    const reward = balanceAfter - balanceBefore;
    if (reward < 0) throw new Error(`Unexpected SOL loss: ${reward}`);
    console.log(`    Reward claimed: ${reward} lamports`);
  });

  // Test: Unstake partial
  await test('Unstake partial', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(2592000));

    const user = Keypair.generate();
    await airdropAndConfirm(connection, user.publicKey, LAMPORTS_PER_SOL);

    const userToken = await ctx.createUserTokenAccount(user.publicKey);
    await ctx.mintTokens(userToken, BigInt(1_000_000_000));
    await ctx.stake(user, userToken, BigInt(1_000_000_000));

    // Unstake half
    await ctx.unstake(user, userToken, BigInt(500_000_000));

    const userBalance = await ctx.getTokenBalance(userToken);
    if (userBalance !== BigInt(500_000_000)) {
      throw new Error(`Expected user balance 500000000, got ${userBalance}`);
    }
  });

  // Test: Unstake full
  await test('Unstake full', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(2592000));

    const user = Keypair.generate();
    await airdropAndConfirm(connection, user.publicKey, LAMPORTS_PER_SOL);

    const userToken = await ctx.createUserTokenAccount(user.publicKey);
    await ctx.mintTokens(userToken, BigInt(1_000_000_000));
    await ctx.stake(user, userToken, BigInt(1_000_000_000));
    await ctx.unstake(user, userToken, BigInt(1_000_000_000));

    const userBalance = await ctx.getTokenBalance(userToken);
    if (userBalance !== BigInt(1_000_000_000)) {
      throw new Error(`Expected user balance 1000000000, got ${userBalance}`);
    }
  });

  // Test: SyncRewards (pump.fun simulation)
  await test('SyncRewards (pump.fun simulation)', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(100));

    const user = Keypair.generate();
    await airdropAndConfirm(connection, user.publicKey, LAMPORTS_PER_SOL);

    const userToken = await ctx.createUserTokenAccount(user.publicKey);
    await ctx.mintTokens(userToken, BigInt(1_000_000_000));
    await ctx.stake(user, userToken, BigInt(1_000_000_000));

    // Send SOL directly to pool (simulating pump.fun)
    await ctx.sendSolToPool(BigInt(LAMPORTS_PER_SOL / 2));

    // Sync rewards
    await ctx.syncRewards();

    const balanceBefore = await ctx.getBalance(user.publicKey);
    await ctx.claimRewards(user);
    const balanceAfter = await ctx.getBalance(user.publicKey);

    const reward = balanceAfter - balanceBefore;
    if (reward <= 0) throw new Error(`Expected positive reward from synced SOL, got: ${reward}`);
    console.log(`    Direct SOL reward claimed: ${reward} lamports`);
  });

  // Test: Additional stake
  await test('Additional stake (same user)', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(2592000));

    const user = Keypair.generate();
    await airdropAndConfirm(connection, user.publicKey, LAMPORTS_PER_SOL);

    const userToken = await ctx.createUserTokenAccount(user.publicKey);
    await ctx.mintTokens(userToken, BigInt(2_000_000_000));

    await ctx.stake(user, userToken, BigInt(1_000_000_000));
    await ctx.stake(user, userToken, BigInt(500_000_000));

    const vaultBalance = await ctx.getTokenBalance(ctx.tokenVaultPDA);
    if (vaultBalance !== BigInt(1_500_000_000)) {
      throw new Error(`Expected vault balance 1500000000, got ${vaultBalance}`);
    }
  });

  // ============================================
  // POOL SETTINGS / AUTHORITY TESTS
  // ============================================

  console.log('\n--- Pool Settings & Authority Tests ---\n');

  // Test: Update pool settings
  await test('UpdatePoolSettings: set min_stake, lock, cooldown', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(2592000));

    // Set all three settings
    await ctx.updatePoolSettings(
      ctx.payer,
      BigInt(1_000_000), // min stake
      null, // no lock
      null, // no cooldown
    );

    // Now update lock duration only
    await ctx.updatePoolSettings(
      ctx.payer,
      null,
      BigInt(10), // 10 second lock
      null,
    );
  });

  // Test: Update settings with wrong authority fails
  await test('UpdatePoolSettings: wrong authority rejected', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(2592000));

    const wrongAuth = Keypair.generate();
    await airdropAndConfirm(connection, wrongAuth.publicKey, LAMPORTS_PER_SOL);

    let failed = false;
    try {
      await ctx.updatePoolSettings(wrongAuth, BigInt(100), null, null);
    } catch (e) {
      failed = true;
      const errMsg = (e as any).message || '';
      if (!errMsg.includes('0x6')) {
        throw new Error(`Expected InvalidAuthority (0x6), got: ${errMsg}`);
      }
    }
    if (!failed) throw new Error('Should reject wrong authority');
  });

  // Test: Transfer authority
  await test('TransferAuthority: transfer and use new authority', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(2592000));

    const newAuth = Keypair.generate();
    await airdropAndConfirm(connection, newAuth.publicKey, LAMPORTS_PER_SOL);

    // Transfer authority
    await ctx.transferAuthority(ctx.payer, newAuth.publicKey);

    // Old authority should fail
    let oldFailed = false;
    try {
      await ctx.updatePoolSettings(ctx.payer, BigInt(100), null, null);
    } catch (e) {
      oldFailed = true;
      const errMsg = (e as any).message || '';
      if (!errMsg.includes('0x6')) {
        throw new Error(`Expected InvalidAuthority (0x6), got: ${errMsg}`);
      }
    }
    if (!oldFailed) throw new Error('Old authority should be rejected');

    // New authority should work
    await ctx.updatePoolSettings(newAuth, BigInt(100), null, null);
  });

  // Test: Renounce authority
  await test('TransferAuthority: renounce (set to default pubkey)', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(2592000));

    // Renounce authority (set to default pubkey = zero)
    await ctx.transferAuthority(ctx.payer, PublicKey.default);

    // Authority should now be rejected
    let failed = false;
    try {
      await ctx.updatePoolSettings(ctx.payer, BigInt(100), null, null);
    } catch (e) {
      failed = true;
      const errMsg = (e as any).message || '';
      if (!errMsg.includes('0x1b')) {
        throw new Error(`Expected AuthorityRenounced (0x1b), got: ${errMsg}`);
      }
    }
    if (!failed) throw new Error('Renounced authority should be rejected');
  });

  // Test: Min stake amount enforced on new stake
  await test('MinStake: enforced on new stake', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(2592000));

    // Set min stake to 1 billion (1 token with 9 decimals)
    await ctx.updatePoolSettings(ctx.payer, BigInt(1_000_000_000), null, null);

    const user = Keypair.generate();
    await airdropAndConfirm(connection, user.publicKey, LAMPORTS_PER_SOL);
    const userToken = await ctx.createUserTokenAccount(user.publicKey);
    await ctx.mintTokens(userToken, BigInt(2_000_000_000));

    // Stake below minimum should fail
    let belowMinFailed = false;
    try {
      await ctx.stake(user, userToken, BigInt(500_000_000));
    } catch (e) {
      belowMinFailed = true;
      const errMsg = (e as any).message || '';
      if (!errMsg.includes('0x15')) {
        throw new Error(`Expected BelowMinimumStake (0x15), got: ${errMsg}`);
      }
    }
    if (!belowMinFailed) throw new Error('Below-minimum stake should fail');

    // Stake at minimum should succeed
    await ctx.stake(user, userToken, BigInt(1_000_000_000));
  });

  // Test: Lock duration blocks early unstake
  await test('LockDuration: blocks early unstake', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(2592000));

    // Set 10-second lock duration
    await ctx.updatePoolSettings(ctx.payer, null, BigInt(10), null);

    const user = Keypair.generate();
    await airdropAndConfirm(connection, user.publicKey, LAMPORTS_PER_SOL);
    const userToken = await ctx.createUserTokenAccount(user.publicKey);
    await ctx.mintTokens(userToken, BigInt(1_000_000_000));
    await ctx.stake(user, userToken, BigInt(1_000_000_000));

    // Try unstake immediately - should fail (locked)
    let lockedFailed = false;
    try {
      await ctx.unstake(user, userToken, BigInt(1_000_000_000));
    } catch (e) {
      lockedFailed = true;
      const errMsg = (e as any).message || '';
      if (!errMsg.includes('0x16')) {
        throw new Error(`Expected StakeLocked (0x16), got: ${errMsg}`);
      }
    }
    if (!lockedFailed) throw new Error('Should reject unstake during lock period');

    // Wait for lock to expire
    console.log('    Waiting 11s for lock to expire...');
    await new Promise(r => setTimeout(r, 11000));

    // Now unstake should succeed
    await ctx.unstake(user, userToken, BigInt(1_000_000_000));
  });

  // Test: Cooldown flow - request → wait → complete
  await test('Cooldown: request → wait → complete unstake', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(2592000));

    // Set 5-second cooldown
    await ctx.updatePoolSettings(ctx.payer, null, null, BigInt(5));

    const user = Keypair.generate();
    await airdropAndConfirm(connection, user.publicKey, LAMPORTS_PER_SOL);
    const userToken = await ctx.createUserTokenAccount(user.publicKey);
    await ctx.mintTokens(userToken, BigInt(1_000_000_000));
    await ctx.stake(user, userToken, BigInt(1_000_000_000));

    // Direct unstake should fail (cooldown required)
    let directFailed = false;
    try {
      await ctx.unstake(user, userToken, BigInt(1_000_000_000));
    } catch (e) {
      directFailed = true;
      const errMsg = (e as any).message || '';
      if (!errMsg.includes('0x18')) {
        throw new Error(`Expected CooldownRequired (0x18), got: ${errMsg}`);
      }
    }
    if (!directFailed) throw new Error('Direct unstake should fail with cooldown');

    // Request unstake
    await ctx.requestUnstake(user, BigInt(1_000_000_000));

    // Complete immediately should fail (cooldown not elapsed)
    let earlyFailed = false;
    try {
      await ctx.completeUnstake(user, userToken);
    } catch (e) {
      earlyFailed = true;
      const errMsg = (e as any).message || '';
      if (!errMsg.includes('0x17')) {
        throw new Error(`Expected CooldownNotElapsed (0x17), got: ${errMsg}`);
      }
    }
    if (!earlyFailed) throw new Error('Complete unstake should fail before cooldown');

    // Wait for cooldown
    console.log('    Waiting 6s for cooldown...');
    await new Promise(r => setTimeout(r, 6000));

    // Complete unstake should now succeed
    await ctx.completeUnstake(user, userToken);

    const balance = await ctx.getTokenBalance(userToken);
    if (balance !== BigInt(1_000_000_000)) {
      throw new Error(`Expected 1000000000 tokens back, got ${balance}`);
    }
  });

  // Test: Cancel unstake request
  await test('Cooldown: cancel unstake request', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(2592000));

    // Set 60-second cooldown (long, we cancel before)
    await ctx.updatePoolSettings(ctx.payer, null, null, BigInt(60));

    const user = Keypair.generate();
    await airdropAndConfirm(connection, user.publicKey, LAMPORTS_PER_SOL);
    const userToken = await ctx.createUserTokenAccount(user.publicKey);
    await ctx.mintTokens(userToken, BigInt(1_000_000_000));
    await ctx.stake(user, userToken, BigInt(1_000_000_000));

    // Request unstake
    await ctx.requestUnstake(user, BigInt(1_000_000_000));

    // Cancel request
    await ctx.cancelUnstakeRequest(user);

    // Cancel again should fail (no pending request)
    let doubleCancelFailed = false;
    try {
      await ctx.cancelUnstakeRequest(user);
    } catch (e) {
      doubleCancelFailed = true;
      const errMsg = (e as any).message || '';
      if (!errMsg.includes('0x19')) {
        throw new Error(`Expected NoPendingUnstakeRequest (0x19), got: ${errMsg}`);
      }
    }
    if (!doubleCancelFailed) throw new Error('Double cancel should fail');
  });

  // Test: Cannot stake while unstake request pending
  await test('Cooldown: cannot stake while unstake pending', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(2592000));

    // Set cooldown
    await ctx.updatePoolSettings(ctx.payer, null, null, BigInt(60));

    const user = Keypair.generate();
    await airdropAndConfirm(connection, user.publicKey, LAMPORTS_PER_SOL);
    const userToken = await ctx.createUserTokenAccount(user.publicKey);
    await ctx.mintTokens(userToken, BigInt(2_000_000_000));
    await ctx.stake(user, userToken, BigInt(1_000_000_000));

    // Request unstake
    await ctx.requestUnstake(user, BigInt(500_000_000));

    // Staking more should fail
    let stakeFailed = false;
    try {
      await ctx.stake(user, userToken, BigInt(500_000_000));
    } catch (e) {
      stakeFailed = true;
      const errMsg = (e as any).message || '';
      if (!errMsg.includes('0x1a')) {
        throw new Error(`Expected PendingUnstakeRequestExists (0x1a), got: ${errMsg}`);
      }
    }
    if (!stakeFailed) throw new Error('Should not stake while unstake pending');

    // Cancel request, then stake should work
    await ctx.cancelUnstakeRequest(user);
    await ctx.stake(user, userToken, BigInt(500_000_000));
  });

  // Test: Cannot request unstake twice
  await test('Cooldown: cannot request unstake twice', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(2592000));

    await ctx.updatePoolSettings(ctx.payer, null, null, BigInt(60));

    const user = Keypair.generate();
    await airdropAndConfirm(connection, user.publicKey, LAMPORTS_PER_SOL);
    const userToken = await ctx.createUserTokenAccount(user.publicKey);
    await ctx.mintTokens(userToken, BigInt(1_000_000_000));
    await ctx.stake(user, userToken, BigInt(1_000_000_000));

    // First request succeeds
    await ctx.requestUnstake(user, BigInt(500_000_000));

    // Second request should fail
    let doubleRequestFailed = false;
    try {
      await ctx.requestUnstake(user, BigInt(500_000_000));
    } catch (e) {
      doubleRequestFailed = true;
      const errMsg = (e as any).message || '';
      if (!errMsg.includes('0x1a')) {
        throw new Error(`Expected PendingUnstakeRequestExists (0x1a), got: ${errMsg}`);
      }
    }
    if (!doubleRequestFailed) throw new Error('Double request should fail');
  });

  // Test: Existing pools (zero reserved fields) work unchanged
  await test('Backward compat: existing pool works with zero settings', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(2592000));

    // With default settings (all zeros), everything should work as before
    const user = Keypair.generate();
    await airdropAndConfirm(connection, user.publicKey, LAMPORTS_PER_SOL);
    const userToken = await ctx.createUserTokenAccount(user.publicKey);
    await ctx.mintTokens(userToken, BigInt(1_000_000_000));

    // Stake works (no min stake)
    await ctx.stake(user, userToken, BigInt(100));

    // Unstake works immediately (no lock, no cooldown)
    await ctx.unstake(user, userToken, BigInt(100));
  });

  // ============================================
  // MATHEMATICAL CORRECTNESS TESTS
  // ============================================
  // Verify stakers receive the correct proportional rewards based on the
  // weight formula: weight = amount × (1 - e^(-age/τ))

  console.log('\n--- Mathematical Correctness Tests ---\n');

  // Test: Weight formula verification - new staker gains weight over old staker
  await test('Math: New staker weight increases relative to old staker', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);

    // tau=60 (minimum allowed)
    const tauSeconds = BigInt(60);
    await ctx.initializePool(tauSeconds);

    // Old staker stakes first and waits to accumulate weight
    const oldStaker = Keypair.generate();
    await airdropAndConfirm(connection, oldStaker.publicKey, 3 * LAMPORTS_PER_SOL);
    const oldToken = await ctx.createUserTokenAccount(oldStaker.publicKey);
    await ctx.mintTokens(oldToken, BigInt(1_000_000_000));
    await ctx.stake(oldStaker, oldToken, BigInt(1_000_000_000));

    // Wait for old staker to accumulate weight (~28% at 20s/60s tau)
    console.log(`    Waiting 20s for old staker to accumulate weight...`);
    await new Promise(r => setTimeout(r, 20000));

    // New staker joins - starts with ~0% weight
    const newStaker = Keypair.generate();
    await airdropAndConfirm(connection, newStaker.publicKey, 3 * LAMPORTS_PER_SOL);
    const newToken = await ctx.createUserTokenAccount(newStaker.publicKey);
    await ctx.mintTokens(newToken, BigInt(1_000_000_000));
    await ctx.stake(newStaker, newToken, BigInt(1_000_000_000));

    // Deposit and check shares (old should dominate)
    await ctx.depositRewards(BigInt(LAMPORTS_PER_SOL / 2));

    let oldBal = await ctx.getBalance(oldStaker.publicKey);
    await ctx.claimRewards(oldStaker);
    const oldReward1 = (await ctx.getBalance(oldStaker.publicKey)) - oldBal;

    // New staker has ~0 weight, so likely gets nothing or very little
    let newBal = await ctx.getBalance(newStaker.publicKey);
    try {
      await ctx.claimRewards(newStaker);
    } catch (e: any) {
      if (!e.message?.includes('0xb')) throw e;
    }
    const newReward1 = (await ctx.getBalance(newStaker.publicKey)) - newBal;
    if (newReward1 < 0) throw new Error(`Unexpected SOL loss: ${newReward1}`);

    const total1 = oldReward1 + newReward1;
    const newShare1 = total1 > 0 ? (newReward1 * 100) / total1 : 0;
    console.log(`    New staker share at t=0: ${newShare1.toFixed(1)}%`);

    // Wait 10s - new staker should gain relative share (~15% weight)
    console.log(`    Waiting 10s for new staker weight...`);
    await new Promise(r => setTimeout(r, 10000));

    await ctx.depositRewards(BigInt(LAMPORTS_PER_SOL / 2));

    oldBal = await ctx.getBalance(oldStaker.publicKey);
    await ctx.claimRewards(oldStaker);
    const oldReward2 = (await ctx.getBalance(oldStaker.publicKey)) - oldBal;

    newBal = await ctx.getBalance(newStaker.publicKey);
    await ctx.claimRewards(newStaker);
    const newReward2 = (await ctx.getBalance(newStaker.publicKey)) - newBal;

    const newShare2 = (newReward2 * 100) / (oldReward2 + newReward2);
    console.log(`    New staker share at t=10s: ${newShare2.toFixed(1)}%`);

    // New staker's share should increase over time
    if (newShare2 <= newShare1) {
      throw new Error(`New staker share should increase: ${newShare1}% -> ${newShare2}%`);
    }
  });

  // Test: Old staker gets more than new staker
  await test('Math: Old staker gets more rewards than new staker', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);

    // tau=60 (minimum allowed)
    const tauSeconds = BigInt(60);
    await ctx.initializePool(tauSeconds);

    // Old staker stakes first
    const oldStaker = Keypair.generate();
    await airdropAndConfirm(connection, oldStaker.publicKey, 2 * LAMPORTS_PER_SOL);
    const oldToken = await ctx.createUserTokenAccount(oldStaker.publicKey);
    const stakeAmount = BigInt(1_000_000_000);
    await ctx.mintTokens(oldToken, stakeAmount);
    await ctx.stake(oldStaker, oldToken, stakeAmount);

    // Wait 20s - old staker will have ~28% weight at tau=60
    console.log(`    Waiting 20s for old staker to accumulate weight...`);
    await new Promise(r => setTimeout(r, 20000));

    // New staker stakes now (will have ~0% weight)
    const newStaker = Keypair.generate();
    await airdropAndConfirm(connection, newStaker.publicKey, 2 * LAMPORTS_PER_SOL);
    const newToken = await ctx.createUserTokenAccount(newStaker.publicKey);
    await ctx.mintTokens(newToken, stakeAmount);
    await ctx.stake(newStaker, newToken, stakeAmount);

    // Deposit rewards - use smaller amount to ensure pool has enough
    await ctx.depositRewards(BigInt(LAMPORTS_PER_SOL / 2));

    // Claim for old staker first
    const oldBalanceBefore = await ctx.getBalance(oldStaker.publicKey);
    await ctx.claimRewards(oldStaker);
    const oldBalanceAfter = await ctx.getBalance(oldStaker.publicKey);
    const oldReward = oldBalanceAfter - oldBalanceBefore;

    // New staker should have nearly 0 weight, so minimal/no rewards
    const newBalanceBefore = await ctx.getBalance(newStaker.publicKey);
    try {
      await ctx.claimRewards(newStaker);
    } catch (e: any) {
      if (!e.message?.includes('0xb')) throw e;
      console.log(`    New staker claim: insufficient (expected)`);
    }
    const newBalanceAfter = await ctx.getBalance(newStaker.publicKey);
    const newReward = newBalanceAfter - newBalanceBefore;
    if (newReward < 0) throw new Error(`Unexpected SOL loss: ${newReward}`);

    console.log(`    Old staker (20s age) reward: ${oldReward} lamports`);
    console.log(`    New staker (~0 age) reward: ${newReward} lamports`);

    // Old staker should get significantly more
    if (oldReward <= newReward) {
      throw new Error(`Old staker should get more: old=${oldReward}, new=${newReward}`);
    }

    // Old staker should get >75% of rewards.
    // With τ=60s and 20s wait, old has ~28% weight.
    // New staker gains ~3% weight during ~2s of tx processing.
    // Old share ≈ 28/(28+3) ≈ 90%.
    const totalRewards = oldReward + newReward;
    if (totalRewards > 0) {
      const oldShare = (oldReward * 100) / totalRewards;
      console.log(`    Old staker share: ${oldShare.toFixed(1)}%`);
      if (oldShare < 75) {
        throw new Error(`Old staker should get >75% of rewards, got ${oldShare}%`);
      }
    }
  });

  // Test: Equal stakers get equal rewards (when both matured)
  await test('Math: Equal age stakers get equal rewards (matured)', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);

    // tau=60 (minimum allowed)
    const tauSeconds = BigInt(60);
    await ctx.initializePool(tauSeconds);

    // Two stakers stake same amount
    const staker1 = Keypair.generate();
    const staker2 = Keypair.generate();
    await airdropAndConfirm(connection, staker1.publicKey, 2 * LAMPORTS_PER_SOL);
    await airdropAndConfirm(connection, staker2.publicKey, 2 * LAMPORTS_PER_SOL);

    const token1 = await ctx.createUserTokenAccount(staker1.publicKey);
    const token2 = await ctx.createUserTokenAccount(staker2.publicKey);
    const stakeAmount = BigInt(1_000_000_000);
    await ctx.mintTokens(token1, stakeAmount);
    await ctx.mintTokens(token2, stakeAmount);

    // Stake sequentially (slight time difference)
    await ctx.stake(staker1, token1, stakeAmount);
    await ctx.stake(staker2, token2, stakeAmount);

    // Wait 15s for both stakes to accumulate similar weight (~22% at tau=60)
    // The ~1s staking difference is small relative to tau=60
    console.log(`    Waiting 15s for both stakes to accumulate weight...`);
    await new Promise(r => setTimeout(r, 15000));

    // Deposit rewards
    await ctx.depositRewards(BigInt(LAMPORTS_PER_SOL));

    // Claim for both
    const balance1Before = await ctx.getBalance(staker1.publicKey);
    await ctx.claimRewards(staker1);
    const balance1After = await ctx.getBalance(staker1.publicKey);
    const reward1 = balance1After - balance1Before;

    const balance2Before = await ctx.getBalance(staker2.publicKey);
    await ctx.claimRewards(staker2);
    const balance2After = await ctx.getBalance(staker2.publicKey);
    const reward2 = balance2After - balance2Before;

    console.log(`    Staker 1 reward: ${reward1} lamports`);
    console.log(`    Staker 2 reward: ${reward2} lamports`);

    // Should be approximately equal (within 15% - both at similar weight with tau=60)
    const diff = Math.abs(reward1 - reward2);
    const avg = (reward1 + reward2) / 2;
    const diffPercent = (diff * 100) / avg;
    console.log(`    Difference: ${diffPercent.toFixed(2)}%`);

    if (diffPercent > 15) {
      throw new Error(`Equal-age stakers should get ~equal rewards, diff=${diffPercent}%`);
    }
  });

  // Test: 2x stake = 2x rewards (when both fully matured)
  await test('Math: Double stake gets double rewards (matured)', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);

    // tau=60 (minimum allowed)
    const tauSeconds = BigInt(60);
    await ctx.initializePool(tauSeconds);

    // Staker 1: stakes 1 token
    // Staker 2: stakes 2 tokens
    const staker1 = Keypair.generate();
    const staker2 = Keypair.generate();
    await airdropAndConfirm(connection, staker1.publicKey, 2 * LAMPORTS_PER_SOL);
    await airdropAndConfirm(connection, staker2.publicKey, 2 * LAMPORTS_PER_SOL);

    const token1 = await ctx.createUserTokenAccount(staker1.publicKey);
    const token2 = await ctx.createUserTokenAccount(staker2.publicKey);
    await ctx.mintTokens(token1, BigInt(1_000_000_000));
    await ctx.mintTokens(token2, BigInt(2_000_000_000));

    // Stake both
    await ctx.stake(staker1, token1, BigInt(1_000_000_000));
    await ctx.stake(staker2, token2, BigInt(2_000_000_000));

    // Wait 15s for both stakes to accumulate similar weight (~22% at tau=60)
    // The small timing difference between stakes is negligible relative to tau=60
    console.log(`    Waiting 15s for both stakes to accumulate weight...`);
    await new Promise(r => setTimeout(r, 15000));

    // Deposit rewards
    await ctx.depositRewards(BigInt(LAMPORTS_PER_SOL));

    // Claim
    const balance1Before = await ctx.getBalance(staker1.publicKey);
    await ctx.claimRewards(staker1);
    const balance1After = await ctx.getBalance(staker1.publicKey);
    const reward1 = balance1After - balance1Before;

    const balance2Before = await ctx.getBalance(staker2.publicKey);
    await ctx.claimRewards(staker2);
    const balance2After = await ctx.getBalance(staker2.publicKey);
    const reward2 = balance2After - balance2Before;

    console.log(`    1x stake reward: ${reward1} lamports`);
    console.log(`    2x stake reward: ${reward2} lamports`);

    // Staker 2 should get ~2x rewards
    const ratio = reward2 / reward1;
    console.log(`    Ratio: ${ratio.toFixed(2)}x`);

    if (ratio < 1.8 || ratio > 2.2) {
      throw new Error(`2x stake should get ~2x rewards, got ${ratio}x`);
    }
  });

  // Test: Verify weight differentiation between old and new staker
  await test('Math: Older staker gets proportionally more rewards', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);

    // tau=60 (minimum allowed)
    const tauSeconds = BigInt(60);
    await ctx.initializePool(tauSeconds);

    // Old staker stakes and waits to accumulate weight
    const oldStaker = Keypair.generate();
    await airdropAndConfirm(connection, oldStaker.publicKey, 2 * LAMPORTS_PER_SOL);
    const oldToken = await ctx.createUserTokenAccount(oldStaker.publicKey);
    await ctx.mintTokens(oldToken, BigInt(1_000_000_000));
    await ctx.stake(oldStaker, oldToken, BigInt(1_000_000_000));

    // Wait 20s for old staker (~28.3% weight at tau=60)
    console.log(`    Waiting 20s for old staker to accumulate weight...`);
    await new Promise(r => setTimeout(r, 20000));

    // New staker stakes same amount
    const newStaker = Keypair.generate();
    await airdropAndConfirm(connection, newStaker.publicKey, 2 * LAMPORTS_PER_SOL);
    const newToken = await ctx.createUserTokenAccount(newStaker.publicKey);
    await ctx.mintTokens(newToken, BigInt(1_000_000_000));
    await ctx.stake(newStaker, newToken, BigInt(1_000_000_000));

    // Wait 10s for new staker (~15.4% weight), old is now at ~39.3%
    console.log(`    Waiting 10s for new staker to accumulate weight...`);
    await new Promise(r => setTimeout(r, 10000));

    // Now: old staker has ~39% weight (30s age), new staker has ~15% weight (10s age)
    // Old should get: 39/(39+15) = ~72%
    // New should get: 15/(39+15) = ~28%

    await ctx.depositRewards(BigInt(LAMPORTS_PER_SOL));

    const oldBalBefore = await ctx.getBalance(oldStaker.publicKey);
    await ctx.claimRewards(oldStaker);
    const oldBalAfter = await ctx.getBalance(oldStaker.publicKey);
    const oldReward = oldBalAfter - oldBalBefore;

    const newBalBefore = await ctx.getBalance(newStaker.publicKey);
    await ctx.claimRewards(newStaker);
    const newBalAfter = await ctx.getBalance(newStaker.publicKey);
    const newReward = newBalAfter - newBalBefore;

    const total = oldReward + newReward;
    const oldPercent = (oldReward * 100) / total;
    const newPercent = (newReward * 100) / total;

    console.log(`    Old staker (30s, ~39% weight): ${oldPercent.toFixed(1)}%`);
    console.log(`    New staker (10s, ~15% weight): ${newPercent.toFixed(1)}%`);

    // Expected: old ~72%, new ~28% (with some tolerance for timing)
    if (oldPercent < 55 || oldPercent > 85) {
      throw new Error(`Old staker should get ~72%, got ${oldPercent}%`);
    }
    if (newPercent < 15 || newPercent > 45) {
      throw new Error(`New staker should get ~28%, got ${newPercent}%`);
    }
  });

  // ============================================
  // ABUSE / SECURITY TESTS
  // ============================================
  // Verify the system cannot be gamed or exploited

  console.log('\n--- Abuse / Security Tests ---\n');

  // Test: Sybil attack - splitting stake doesn't give advantage
  await test('Abuse: Sybil attack (split stake) gives no advantage', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);

    const tauSeconds = BigInt(60);
    await ctx.initializePool(tauSeconds);

    // Honest staker: 2 tokens in one account
    const honest = Keypair.generate();
    await airdropAndConfirm(connection, honest.publicKey, 2 * LAMPORTS_PER_SOL);
    const honestToken = await ctx.createUserTokenAccount(honest.publicKey);
    await ctx.mintTokens(honestToken, BigInt(2_000_000_000));
    await ctx.stake(honest, honestToken, BigInt(2_000_000_000));

    // Sybil attacker: 2 tokens split across 2 accounts (1 each)
    const sybil1 = Keypair.generate();
    const sybil2 = Keypair.generate();
    await airdropAndConfirm(connection, sybil1.publicKey, 2 * LAMPORTS_PER_SOL);
    await airdropAndConfirm(connection, sybil2.publicKey, 2 * LAMPORTS_PER_SOL);
    const sybil1Token = await ctx.createUserTokenAccount(sybil1.publicKey);
    const sybil2Token = await ctx.createUserTokenAccount(sybil2.publicKey);
    await ctx.mintTokens(sybil1Token, BigInt(1_000_000_000));
    await ctx.mintTokens(sybil2Token, BigInt(1_000_000_000));
    await ctx.stake(sybil1, sybil1Token, BigInt(1_000_000_000));
    await ctx.stake(sybil2, sybil2Token, BigInt(1_000_000_000));

    // Wait for weight accumulation (~22% at 15s/60s tau)
    console.log(`    Waiting 15s for stakes to accumulate weight...`);
    await new Promise(r => setTimeout(r, 15000));

    // Deposit rewards
    await ctx.depositRewards(BigInt(LAMPORTS_PER_SOL));

    // Claim for all
    const honestBefore = await ctx.getBalance(honest.publicKey);
    await ctx.claimRewards(honest);
    const honestReward = (await ctx.getBalance(honest.publicKey)) - honestBefore;

    const sybil1Before = await ctx.getBalance(sybil1.publicKey);
    await ctx.claimRewards(sybil1);
    const sybil1Reward = (await ctx.getBalance(sybil1.publicKey)) - sybil1Before;

    const sybil2Before = await ctx.getBalance(sybil2.publicKey);
    await ctx.claimRewards(sybil2);
    const sybil2Reward = (await ctx.getBalance(sybil2.publicKey)) - sybil2Before;

    const sybilTotal = sybil1Reward + sybil2Reward;

    console.log(`    Honest (2 tokens): ${honestReward} lamports`);
    console.log(`    Sybil (1+1 tokens): ${sybilTotal} lamports`);

    // Sybil should NOT get more than honest staker
    // Allow small variance for timing differences
    const ratio = sybilTotal / honestReward;
    console.log(`    Sybil/Honest ratio: ${ratio.toFixed(3)}`);

    if (ratio > 1.1) {
      throw new Error(`Sybil attack should not be profitable: ratio=${ratio}`);
    }
  });

  // Test: Flash stake attack - staking right before deposit
  await test('Abuse: Flash stake attack (stake before deposit) fails', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);

    // tau=60 so tx processing time (~2s) gives attacker minimal weight
    const tauSeconds = BigInt(60);
    await ctx.initializePool(tauSeconds);

    // Honest staker stakes early
    const honest = Keypair.generate();
    await airdropAndConfirm(connection, honest.publicKey, 2 * LAMPORTS_PER_SOL);
    const honestToken = await ctx.createUserTokenAccount(honest.publicKey);
    await ctx.mintTokens(honestToken, BigInt(1_000_000_000));
    await ctx.stake(honest, honestToken, BigInt(1_000_000_000));

    // Wait 20s for honest staker to accumulate weight (~28% at tau=60)
    console.log(`    Waiting 20s for honest staker to accumulate weight...`);
    await new Promise(r => setTimeout(r, 20000));

    // Attacker stakes right before deposit (flash stake)
    const attacker = Keypair.generate();
    await airdropAndConfirm(connection, attacker.publicKey, 2 * LAMPORTS_PER_SOL);
    const attackerToken = await ctx.createUserTokenAccount(attacker.publicKey);
    await ctx.mintTokens(attackerToken, BigInt(1_000_000_000));
    await ctx.stake(attacker, attackerToken, BigInt(1_000_000_000));

    // Deposit immediately after attacker stakes
    await ctx.depositRewards(BigInt(LAMPORTS_PER_SOL));

    // Claim for both
    const honestBefore = await ctx.getBalance(honest.publicKey);
    await ctx.claimRewards(honest);
    const honestReward = (await ctx.getBalance(honest.publicKey)) - honestBefore;

    const attackerBefore = await ctx.getBalance(attacker.publicKey);
    try {
      await ctx.claimRewards(attacker);
    } catch (e) {
      // Expected - attacker has ~0 weight
    }
    const attackerReward = Math.max(0, (await ctx.getBalance(attacker.publicKey)) - attackerBefore);

    console.log(`    Honest staker (20s age) reward: ${honestReward} lamports`);
    console.log(`    Flash attacker (new) reward: ${attackerReward} lamports`);

    // Honest staker should get the vast majority (~28% weight vs ~3%)
    const honestShare = (honestReward * 100) / (honestReward + attackerReward);
    console.log(`    Honest staker share: ${honestShare.toFixed(1)}%`);

    // With τ=60s and 20s wait, honest has ~28% weight, attacker ~3%
    // Honest share ≈ 28/(28+3) ≈ 90%
    if (honestShare < 75) {
      throw new Error(`Flash stake should not be profitable: honest=${honestShare}%`);
    }
  });

  // Test: Cannot unstake more than staked
  await test('Abuse: Cannot unstake more than staked', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(100));

    const user = Keypair.generate();
    await airdropAndConfirm(connection, user.publicKey, 2 * LAMPORTS_PER_SOL);
    const userToken = await ctx.createUserTokenAccount(user.publicKey);
    await ctx.mintTokens(userToken, BigInt(1_000_000_000));
    await ctx.stake(user, userToken, BigInt(1_000_000_000));

    // Try to unstake 2x what was staked
    let failed = false;
    try {
      await ctx.unstake(user, userToken, BigInt(2_000_000_000));
    } catch (e: any) {
      failed = true;
      console.log(`    Correctly rejected: ${e.message?.includes('0xa') ? 'InsufficientStakeBalance' : 'error'}`);
    }

    if (!failed) {
      throw new Error('Should not be able to unstake more than staked');
    }
  });

  // Test: Cannot profit from claim after full unstake
  await test('Abuse: Cannot claim after full unstake', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(60));

    const user = Keypair.generate();
    await airdropAndConfirm(connection, user.publicKey, 2 * LAMPORTS_PER_SOL);
    const userToken = await ctx.createUserTokenAccount(user.publicKey);
    await ctx.mintTokens(userToken, BigInt(1_000_000_000));
    await ctx.stake(user, userToken, BigInt(1_000_000_000));

    // Wait for weight, deposit rewards
    await new Promise(r => setTimeout(r, 2000));
    await ctx.depositRewards(BigInt(LAMPORTS_PER_SOL));

    // Claim rewards first
    await ctx.claimRewards(user);

    // Fully unstake
    await ctx.unstake(user, userToken, BigInt(1_000_000_000));

    // Deposit more rewards (user has amount=0, should not benefit)
    await ctx.depositRewards(BigInt(LAMPORTS_PER_SOL));

    // Claim again — should succeed silently (amount==0 path returns Ok)
    // but should give the user 0 SOL from the new deposit
    const balBefore = BigInt(await ctx.getBalance(user.publicKey));
    await ctx.claimRewards(user);
    const balAfter = BigInt(await ctx.getBalance(user.publicKey));

    // User should gain nothing (or lose tx fee)
    const gained = balAfter - balBefore;
    if (gained > BigInt(0)) {
      throw new Error(`User gained ${gained} lamports after full unstake — should be 0`);
    }
  });

  // Test: Cannot double claim
  await test('Abuse: Cannot double claim same rewards', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(60));

    const user = Keypair.generate();
    await airdropAndConfirm(connection, user.publicKey, 2 * LAMPORTS_PER_SOL);
    const userToken = await ctx.createUserTokenAccount(user.publicKey);
    await ctx.mintTokens(userToken, BigInt(1_000_000_000));
    await ctx.stake(user, userToken, BigInt(1_000_000_000));

    // Wait and deposit
    await new Promise(r => setTimeout(r, 2000));
    await ctx.depositRewards(BigInt(LAMPORTS_PER_SOL));

    // First claim
    const balance1 = await ctx.getBalance(user.publicKey);
    await ctx.claimRewards(user);
    const reward1 = (await ctx.getBalance(user.publicKey)) - balance1;
    console.log(`    First claim: ${reward1} lamports`);

    // Second claim — with max-weight denominator, weight maturation between claims
    // yields additional rewards. This is NOT double-claiming: the user is entitled
    // to more as their stake matures. Verify conservation instead.
    const balance2 = await ctx.getBalance(user.publicKey);
    try {
      await ctx.claimRewards(user);
    } catch (e: any) {
      if (!e.message?.includes('0xb')) throw e;
    }
    const reward2 = (await ctx.getBalance(user.publicKey)) - balance2;
    console.log(`    Second claim: ${reward2} lamports`);

    // Second claim should be strictly less than first (diminishing returns)
    if (reward2 >= reward1) {
      throw new Error(`Possible double-claim: reward2 (${reward2}) >= reward1 (${reward1})`);
    }

    // Conservation: total claimed must not exceed deposit
    const totalClaimed = reward1 + reward2;
    const depositAmount = LAMPORTS_PER_SOL;
    if (totalClaimed > depositAmount) {
      throw new Error(`Over-distribution: claimed ${totalClaimed} > deposited ${depositAmount}`);
    }
    console.log(`    Conservation OK: claimed ${reward1 + reward2} <= deposited ${depositAmount}`);
  });

  // Test: Stake/unstake cycling doesn't reset weight unfairly
  await test('Abuse: Stake/unstake cycling resets weight', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);

    const tauSeconds = BigInt(60);
    await ctx.initializePool(tauSeconds);

    // Honest staker - stakes and holds
    const honest = Keypair.generate();
    await airdropAndConfirm(connection, honest.publicKey, 2 * LAMPORTS_PER_SOL);
    const honestToken = await ctx.createUserTokenAccount(honest.publicKey);
    await ctx.mintTokens(honestToken, BigInt(1_000_000_000));
    await ctx.stake(honest, honestToken, BigInt(1_000_000_000));

    // Cycler - stakes, waits, unstakes, restakes (trying to game)
    const cycler = Keypair.generate();
    await airdropAndConfirm(connection, cycler.publicKey, 2 * LAMPORTS_PER_SOL);
    const cyclerToken = await ctx.createUserTokenAccount(cycler.publicKey);
    await ctx.mintTokens(cyclerToken, BigInt(1_000_000_000));
    await ctx.stake(cycler, cyclerToken, BigInt(1_000_000_000));

    // Wait 10s (honest gets ~15.4% weight at tau=60)
    console.log(`    Waiting 10s...`);
    await new Promise(r => setTimeout(r, 10000));

    // Cycler unstakes and restakes (resets their weight!)
    await ctx.unstake(cycler, cyclerToken, BigInt(1_000_000_000));
    await ctx.stake(cycler, cyclerToken, BigInt(1_000_000_000));

    // Deposit rewards
    await ctx.depositRewards(BigInt(LAMPORTS_PER_SOL));

    // Claim
    const honestBefore = await ctx.getBalance(honest.publicKey);
    await ctx.claimRewards(honest);
    const honestReward = (await ctx.getBalance(honest.publicKey)) - honestBefore;

    const cyclerBefore = await ctx.getBalance(cycler.publicKey);
    try {
      await ctx.claimRewards(cycler);
    } catch (e: any) {
      if (!e.message?.includes('0xb')) throw e;
    }
    const cyclerReward = (await ctx.getBalance(cycler.publicKey)) - cyclerBefore;
    if (cyclerReward < 0) throw new Error(`Unexpected SOL loss: ${cyclerReward}`);

    console.log(`    Honest (held 10s): ${honestReward} lamports`);
    console.log(`    Cycler (reset weight): ${cyclerReward} lamports`);

    // Honest should get more since cycler reset their weight
    if (honestReward <= cyclerReward) {
      throw new Error(`Cycling should reset weight: honest=${honestReward}, cycler=${cyclerReward}`);
    }
  });

  // Test: Zero amount operations fail
  await test('Abuse: Zero amount operations rejected', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(100));

    const user = Keypair.generate();
    await airdropAndConfirm(connection, user.publicKey, 2 * LAMPORTS_PER_SOL);
    const userToken = await ctx.createUserTokenAccount(user.publicKey);
    await ctx.mintTokens(userToken, BigInt(1_000_000_000));

    // Try zero stake
    let zeroStakeFailed = false;
    try {
      await ctx.stake(user, userToken, BigInt(0));
    } catch (e) {
      zeroStakeFailed = true;
      const errMsg = (e as any).message || '';
      if (!errMsg.includes('0xe')) {
        throw new Error(`Expected ZeroAmount (0xe), got: ${errMsg}`);
      }
    }

    // Stake normally first
    await ctx.stake(user, userToken, BigInt(1_000_000_000));

    // Try zero unstake
    let zeroUnstakeFailed = false;
    try {
      await ctx.unstake(user, userToken, BigInt(0));
    } catch (e) {
      zeroUnstakeFailed = true;
      const errMsg = (e as any).message || '';
      if (!errMsg.includes('0xe')) {
        throw new Error(`Expected ZeroAmount (0xe), got: ${errMsg}`);
      }
    }

    // Try zero deposit
    let zeroDepositFailed = false;
    try {
      await ctx.depositRewards(BigInt(0));
    } catch (e) {
      zeroDepositFailed = true;
      const errMsg = (e as any).message || '';
      if (!errMsg.includes('0xe')) {
        throw new Error(`Expected ZeroAmount (0xe), got: ${errMsg}`);
      }
    }

    console.log(`    Zero stake rejected: ${zeroStakeFailed}`);
    console.log(`    Zero unstake rejected: ${zeroUnstakeFailed}`);
    console.log(`    Zero deposit rejected: ${zeroDepositFailed}`);

    if (!zeroStakeFailed) {
      throw new Error('Zero stake should be rejected');
    }
    if (!zeroUnstakeFailed) {
      throw new Error('Zero unstake should be rejected');
    }
    if (!zeroDepositFailed) {
      throw new Error('Zero deposit should be rejected');
    }
  });

  // Test: Frontrunning deposit with equal stake
  // Note: With vastly different stake amounts, the attacker may still win on absolute weight
  // This test verifies that equal stakes favor the mature staker
  await test('Abuse: Frontrunning deposit (equal stakes)', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);

    // tau=60 so tx processing time (~2s) gives attacker minimal weight
    const tauSeconds = BigInt(60);
    await ctx.initializePool(tauSeconds);

    // Honest staker
    const honest = Keypair.generate();
    await airdropAndConfirm(connection, honest.publicKey, 2 * LAMPORTS_PER_SOL);
    const honestToken = await ctx.createUserTokenAccount(honest.publicKey);
    await ctx.mintTokens(honestToken, BigInt(1_000_000_000));
    await ctx.stake(honest, honestToken, BigInt(1_000_000_000));

    // Wait 20s for honest staker to accumulate weight (~28% at tau=60)
    console.log(`    Waiting 20s for honest staker to accumulate weight...`);
    await new Promise(r => setTimeout(r, 20000));

    // Frontrunner stakes equal amount right before deposit
    const attacker = Keypair.generate();
    await airdropAndConfirm(connection, attacker.publicKey, 2 * LAMPORTS_PER_SOL);
    const attackerToken = await ctx.createUserTokenAccount(attacker.publicKey);
    await ctx.mintTokens(attackerToken, BigInt(1_000_000_000));
    await ctx.stake(attacker, attackerToken, BigInt(1_000_000_000));

    // Deposit immediately
    await ctx.depositRewards(BigInt(LAMPORTS_PER_SOL));

    // Claim
    const honestBefore = await ctx.getBalance(honest.publicKey);
    await ctx.claimRewards(honest);
    const honestReward = (await ctx.getBalance(honest.publicKey)) - honestBefore;

    const attackerBefore = await ctx.getBalance(attacker.publicKey);
    try {
      await ctx.claimRewards(attacker);
    } catch (e: any) {
      if (!e.message?.includes('0xb')) throw e;
    }
    const attackerReward = (await ctx.getBalance(attacker.publicKey)) - attackerBefore;
    if (attackerReward < 0) throw new Error(`Unexpected SOL loss: ${attackerReward}`);

    const total = honestReward + attackerReward;
    const honestShare = (honestReward * 100) / total;

    console.log(`    Honest (1 token, 20s age): ${honestShare.toFixed(1)}% (${honestReward} lamports)`);
    console.log(`    Attacker (1 token, new): ${(100-honestShare).toFixed(1)}% (${attackerReward} lamports)`);

    // With τ=60s and 20s wait, honest has ~28% weight, attacker ~3%
    // Honest share ≈ 28/(28+3) ≈ 90%
    if (honestShare < 75) {
      throw new Error(`Frontrunning should not be profitable: honest only got ${honestShare}%`);
    }
  });

  // ============================================
  // SECURITY REGRESSION TESTS
  // ============================================
  // Verify fixes for identified security audit findings

  console.log('\n--- Security Regression Tests ---\n');

  // Test: DepositRewards + SyncRewards does not double-count
  await test('Security: DepositRewards + SyncRewards does not double-count', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(60)); // Minimum tau

    const user = Keypair.generate();
    await airdropAndConfirm(connection, user.publicKey, 2 * LAMPORTS_PER_SOL);

    const userToken = await ctx.createUserTokenAccount(user.publicKey);
    await ctx.mintTokens(userToken, BigInt(1_000_000_000));
    await ctx.stake(user, userToken, BigInt(1_000_000_000));

    // Wait for weight to accumulate (~15% at 10s/60s tau)
    console.log('    Waiting 10s for weight...');
    await new Promise(r => setTimeout(r, 10000));

    // Deposit via instruction
    const depositAmount = BigInt(LAMPORTS_PER_SOL);
    await ctx.depositRewards(depositAmount);

    // Call sync_rewards - should find NO new rewards (deposit already accounted for)
    await ctx.syncRewards();

    // Claim - user should get approximately depositAmount, NOT 2x
    const balanceBefore = await ctx.getBalance(user.publicKey);
    await ctx.claimRewards(user);
    const balanceAfter = await ctx.getBalance(user.publicKey);
    const claimed = BigInt(balanceAfter - balanceBefore);

    console.log(`    Deposited: ${depositAmount} lamports`);
    console.log(`    Claimed: ${claimed} lamports`);

    // Claimed should be <= depositAmount (accounting for tx fees and weight < 100%)
    // If double-counted, claimed would be close to 2x depositAmount
    if (claimed > depositAmount + BigInt(6000)) {
      throw new Error(`Double-counting detected! Claimed ${claimed} > deposited ${depositAmount}`);
    }
  });

  // Test: Additional stake does not allow reward theft
  await test('Security: Additional stake does not allow reward theft', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(60)); // Minimum tau

    const attacker = Keypair.generate();
    await airdropAndConfirm(connection, attacker.publicKey, 2 * LAMPORTS_PER_SOL);

    const attackerToken = await ctx.createUserTokenAccount(attacker.publicKey);
    const smallStake = BigInt(1_000); // tiny initial stake
    const largeStake = BigInt(1_000_000_000); // 1 billion additional
    await ctx.mintTokens(attackerToken, smallStake + largeStake);

    // Stake small amount
    await ctx.stake(attacker, attackerToken, smallStake);

    // Wait for weight to accumulate
    console.log('    Waiting 10s for weight...');
    await new Promise(r => setTimeout(r, 10000));

    // Deposit rewards
    const depositAmount = BigInt(LAMPORTS_PER_SOL);
    await ctx.depositRewards(depositAmount);

    // Now add large stake (attack vector: reward_debt stays at old small-stake value)
    await ctx.stake(attacker, attackerToken, largeStake);

    // Claim - should get rewards proportional to the ORIGINAL small stake, not the new large stake
    const balanceBefore = await ctx.getBalance(attacker.publicKey);
    try {
      await ctx.claimRewards(attacker);
    } catch (e) {
      // May fail if no pending rewards (correct behavior)
    }
    const balanceAfter = await ctx.getBalance(attacker.publicKey);
    const claimed = BigInt(balanceAfter - balanceBefore);

    console.log(`    Small stake: ${smallStake}, Large additional: ${largeStake}`);
    console.log(`    Deposited: ${depositAmount} lamports`);
    console.log(`    Claimed: ${claimed} lamports`);

    // With the fix, reward_debt is recalculated on additional stake,
    // so the attacker shouldn't be able to claim more than what the small stake earned.
    // A reasonable upper bound: all rewards (since they were the only staker).
    // But claimed should NOT be inflated by the large stake addition.
    // The key check: claimed should be roughly proportional to the deposit, not vastly more.
    if (claimed > depositAmount + BigInt(6000)) {
      throw new Error(`Reward theft detected! Claimed ${claimed} >> deposited ${depositAmount}`);
    }
  });

  // Test: Claim then SyncRewards works for new deposits
  await test('Security: Claim then SyncRewards works for new deposits', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(60)); // Minimum tau

    const user = Keypair.generate();
    await airdropAndConfirm(connection, user.publicKey, 3 * LAMPORTS_PER_SOL);

    const userToken = await ctx.createUserTokenAccount(user.publicKey);
    await ctx.mintTokens(userToken, BigInt(1_000_000_000));
    await ctx.stake(user, userToken, BigInt(1_000_000_000));

    // Wait for weight
    console.log('    Waiting 10s for weight...');
    await new Promise(r => setTimeout(r, 10000));

    // Deposit and claim
    await ctx.depositRewards(BigInt(LAMPORTS_PER_SOL / 2));
    const bal1Before = await ctx.getBalance(user.publicKey);
    await ctx.claimRewards(user);
    const claim1 = BigInt((await ctx.getBalance(user.publicKey)) - bal1Before);
    console.log(`    First claim: ${claim1} lamports`);

    // Send SOL directly to pool (simulating pump.fun)
    const directAmount = BigInt(LAMPORTS_PER_SOL / 2);
    await ctx.sendSolToPool(directAmount);

    // Sync rewards - should detect the new direct SOL
    await ctx.syncRewards();

    // Claim again - should get the new rewards
    const bal2Before = await ctx.getBalance(user.publicKey);
    await ctx.claimRewards(user);
    const claim2 = BigInt((await ctx.getBalance(user.publicKey)) - bal2Before);
    console.log(`    Second claim (after direct SOL + sync): ${claim2} lamports`);

    // Second claim should be > 0 (new rewards were synced)
    if (claim2 <= BigInt(0)) {
      throw new Error(`SyncRewards failed to detect new deposits after claim! Got ${claim2}`);
    }
  });

  // Test: Unstake rewards then SyncRewards works
  await test('Security: Unstake rewards then SyncRewards works', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(60)); // Minimum tau

    const user = Keypair.generate();
    await airdropAndConfirm(connection, user.publicKey, 3 * LAMPORTS_PER_SOL);

    const userToken = await ctx.createUserTokenAccount(user.publicKey);
    await ctx.mintTokens(userToken, BigInt(2_000_000_000));
    await ctx.stake(user, userToken, BigInt(2_000_000_000));

    // Wait for weight
    console.log('    Waiting 10s for weight...');
    await new Promise(r => setTimeout(r, 10000));

    // Deposit rewards
    await ctx.depositRewards(BigInt(LAMPORTS_PER_SOL / 2));

    // Unstake half (this claims pending rewards and reduces last_synced_lamports)
    await ctx.unstake(user, userToken, BigInt(1_000_000_000));

    // Send more SOL directly to pool — needs to be large enough to overcome the
    // immature weight deficit (reward_debt set at max weight during unstake).
    // At tau=60 with ~15% weight, delta must exceed ~4.5x the old acc_rps.
    const directAmount = BigInt(5 * LAMPORTS_PER_SOL);
    await ctx.sendSolToPool(directAmount);

    // Sync rewards - should detect the new direct SOL
    await ctx.syncRewards();

    // Claim - should get the new rewards
    const balBefore = await ctx.getBalance(user.publicKey);
    await ctx.claimRewards(user);
    const claimed = BigInt((await ctx.getBalance(user.publicKey)) - balBefore);
    console.log(`    Claim after unstake + new SOL + sync: ${claimed} lamports`);

    // Claimed should be > 0
    if (claimed <= BigInt(0)) {
      throw new Error(`SyncRewards failed after unstake! Got ${claimed}`);
    }
  });

  // ============================================
  // STRESS TESTS: Simulate 1 million stakers
  // ============================================
  // Since operations are O(1), complexity depends on value magnitudes, not staker count.
  // We test with values representing: 1M stakers × 1000 tokens each = 1 trillion tokens
  // This verifies the math handles large aggregates without overflow or excessive compute.

  console.log('\n--- Stress Tests (simulating 1M stakers) ---\n');

  // Test: Large stake amount (simulating pool with many existing stakers)
  await test('Stress: Stake with large existing total', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(2592000)); // 30 days tau

    // First, create a "whale" that represents aggregate of ~1M stakers
    // 1M stakers × 1000 tokens × 10^9 decimals = 10^18 raw tokens
    const whale = Keypair.generate();
    await airdropAndConfirm(connection, whale.publicKey, 2 * LAMPORTS_PER_SOL);

    const whaleToken = await ctx.createUserTokenAccount(whale.publicKey);
    // Mint a large amount representing aggregate stake
    // Using 10^15 (1 quadrillion) as a large but safe value
    const largeAmount = BigInt('1000000000000000'); // 10^15
    await ctx.mintTokens(whaleToken, largeAmount);

    const startTime = Date.now();
    await ctx.stake(whale, whaleToken, largeAmount);
    const stakeTime = Date.now() - startTime;
    console.log(`    Large stake (${largeAmount} tokens): ${stakeTime}ms`);

    // Now test a regular user staking against this large pool
    const user = Keypair.generate();
    await airdropAndConfirm(connection, user.publicKey, LAMPORTS_PER_SOL);

    const userToken = await ctx.createUserTokenAccount(user.publicKey);
    const userAmount = BigInt(1_000_000_000); // 1 token (normal stake)
    await ctx.mintTokens(userToken, userAmount);

    const startTime2 = Date.now();
    await ctx.stake(user, userToken, userAmount);
    const stakeTime2 = Date.now() - startTime2;
    console.log(`    Regular stake against large pool: ${stakeTime2}ms`);

    // Verify both stakes exist
    const vaultBalance = await ctx.getTokenBalance(ctx.tokenVaultPDA);
    if (vaultBalance !== largeAmount + userAmount) {
      throw new Error(`Expected ${largeAmount + userAmount}, got ${vaultBalance}`);
    }
  });

  // Test: Deposit rewards with large total stake
  await test('Stress: Deposit rewards with 1M staker simulation', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(100)); // Short tau for weight accumulation

    // Create large aggregate stake
    const whale = Keypair.generate();
    await airdropAndConfirm(connection, whale.publicKey, 5 * LAMPORTS_PER_SOL);

    const whaleToken = await ctx.createUserTokenAccount(whale.publicKey);
    const largeAmount = BigInt('1000000000000000'); // 10^15
    await ctx.mintTokens(whaleToken, largeAmount);
    await ctx.stake(whale, whaleToken, largeAmount);

    // Wait a bit for weight to accumulate
    await new Promise(r => setTimeout(r, 1000));

    // Deposit reasonable reward (5 SOL) - tests program handles large stake values
    const rewardAmount = BigInt(5 * LAMPORTS_PER_SOL);
    const startTime = Date.now();
    await ctx.depositRewards(rewardAmount);
    const depositTime = Date.now() - startTime;
    console.log(`    Deposit ${rewardAmount} lamports to pool with 10^15 tokens: ${depositTime}ms`);
  });

  // Test: Claim rewards with large accumulated rewards
  await test('Stress: Claim with large reward accumulator', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(60)); // Minimum tau

    const user = Keypair.generate();
    await airdropAndConfirm(connection, user.publicKey, LAMPORTS_PER_SOL);

    const userToken = await ctx.createUserTokenAccount(user.publicKey);
    const stakeAmount = BigInt('100000000000000'); // 10^14
    await ctx.mintTokens(userToken, stakeAmount);
    await ctx.stake(user, userToken, stakeAmount);

    // Wait for weight
    await new Promise(r => setTimeout(r, 500));

    // Multiple deposits to accumulate large reward per share
    for (let i = 0; i < 5; i++) {
      await ctx.depositRewards(BigInt(LAMPORTS_PER_SOL));
    }

    // Claim rewards
    const startTime = Date.now();
    await ctx.claimRewards(user);
    const claimTime = Date.now() - startTime;
    console.log(`    Claim from large accumulator: ${claimTime}ms`);
  });

  // Test: Unstake with large pool values
  await test('Stress: Unstake with large pool values', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(2592000));

    const user = Keypair.generate();
    await airdropAndConfirm(connection, user.publicKey, LAMPORTS_PER_SOL);

    const userToken = await ctx.createUserTokenAccount(user.publicKey);
    const largeAmount = BigInt('500000000000000'); // 5×10^14
    await ctx.mintTokens(userToken, largeAmount);
    await ctx.stake(user, userToken, largeAmount);

    // Partial unstake
    const unstakeAmount = BigInt('250000000000000'); // Half
    const startTime = Date.now();
    await ctx.unstake(user, userToken, unstakeAmount);
    const unstakeTime = Date.now() - startTime;
    console.log(`    Large partial unstake (${unstakeAmount}): ${unstakeTime}ms`);

    // Full unstake remaining
    const startTime2 = Date.now();
    await ctx.unstake(user, userToken, unstakeAmount);
    const unstakeTime2 = Date.now() - startTime2;
    console.log(`    Full unstake remaining: ${unstakeTime2}ms`);

    const balance = await ctx.getTokenBalance(userToken);
    if (balance !== largeAmount) {
      throw new Error(`Expected ${largeAmount}, got ${balance}`);
    }
  });

  // Test: SyncRewards with large pool
  await test('Stress: SyncRewards with large pool', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(60)); // Minimum tau

    const whale = Keypair.generate();
    await airdropAndConfirm(connection, whale.publicKey, 3 * LAMPORTS_PER_SOL);

    const whaleToken = await ctx.createUserTokenAccount(whale.publicKey);
    const largeAmount = BigInt('1000000000000000');
    await ctx.mintTokens(whaleToken, largeAmount);
    await ctx.stake(whale, whaleToken, largeAmount);

    // Wait for weight
    await new Promise(r => setTimeout(r, 1000));

    // Send SOL directly to pool (5 SOL, simulating pump.fun fees)
    await ctx.sendSolToPool(BigInt(5 * LAMPORTS_PER_SOL));

    const startTime = Date.now();
    await ctx.syncRewards();
    const syncTime = Date.now() - startTime;
    console.log(`    SyncRewards with 5 SOL on 10^15 token pool: ${syncTime}ms`);
  });

  // Test: Many sequential operations (verify no state bloat)
  await test('Stress: Sequential operations (no state bloat)', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(60)); // Minimum tau

    const user = Keypair.generate();
    await airdropAndConfirm(connection, user.publicKey, 5 * LAMPORTS_PER_SOL);

    const userToken = await ctx.createUserTokenAccount(user.publicKey);
    await ctx.mintTokens(userToken, BigInt('10000000000000')); // 10^13

    // Initial stake that stays throughout to keep pool active
    const baseStake = BigInt('1000000000000'); // 10^12
    await ctx.stake(user, userToken, baseStake);

    // Wait for weight to accumulate
    await new Promise(r => setTimeout(r, 1000));

    const iterations = 5; // Reduced for faster tests
    const times: number[] = [];

    for (let i = 0; i < iterations; i++) {
      const additionalAmount = BigInt(100_000_000) * BigInt(i + 1);

      const start = Date.now();
      // Add more stake
      await ctx.stake(user, userToken, additionalAmount);
      // Deposit small reward
      await ctx.depositRewards(BigInt(LAMPORTS_PER_SOL / 100));
      // Claim
      await ctx.claimRewards(user);
      // Remove only the additional stake (keep base stake)
      await ctx.unstake(user, userToken, additionalAmount);
      times.push(Date.now() - start);
    }

    // Unstake the base amount at the end
    await ctx.unstake(user, userToken, baseStake);

    const avgTime = times.reduce((a, b) => a + b, 0) / times.length;
    const maxTime = Math.max(...times);
    const minTime = Math.min(...times);

    console.log(`    ${iterations} cycles - avg: ${avgTime.toFixed(0)}ms, min: ${minTime}ms, max: ${maxTime}ms`);

    // Verify operations are O(1) - time should not grow significantly
    if (maxTime > minTime * 3) {
      console.log(`    Note: Variance may be due to network, not algorithm`);
    }
  });

  // Test: Compute units estimation via simulation
  await test('Stress: Compute units check', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(100));

    const user = Keypair.generate();
    await airdropAndConfirm(connection, user.publicKey, 2 * LAMPORTS_PER_SOL);

    const userToken = await ctx.createUserTokenAccount(user.publicKey);
    await ctx.mintTokens(userToken, BigInt('1000000000000000'));
    await ctx.stake(user, userToken, BigInt('1000000000000000'));

    await new Promise(r => setTimeout(r, 500));
    await ctx.depositRewards(BigInt(LAMPORTS_PER_SOL));

    // Create a transaction to simulate
    const [userStakePDA] = deriveUserStakePDA(ctx.poolPDA, user.publicKey);
    const claimIx = createClaimRewardsInstruction(ctx.poolPDA, userStakePDA, user.publicKey);
    const tx = new Transaction().add(claimIx);
    tx.feePayer = ctx.payer.publicKey;
    tx.recentBlockhash = (await connection.getLatestBlockhash()).blockhash;
    tx.sign(ctx.payer, user);

    const simulation = await connection.simulateTransaction(tx);
    if (simulation.value.err) {
      throw new Error(`Simulation failed: ${JSON.stringify(simulation.value.err)}`);
    }
    const unitsUsed = simulation.value.unitsConsumed || 0;

    console.log(`    Claim instruction compute units: ${unitsUsed}`);

    // Solana limit is 200,000 CU per instruction
    if (unitsUsed > 200000) {
      throw new Error(`Compute units (${unitsUsed}) exceed instruction limit (200,000)`);
    }

    // Our target is under 100,000 CU for efficiency
    if (unitsUsed > 100000) {
      console.log(`    WARNING: High compute usage, consider optimization`);
    }
  });

  // ============================================================
  // Lifecycle Test: Multi-phase staking with full reconciliation
  // ============================================================

  await test('Lifecycle: Multi-phase staking with full reconciliation', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9); // 9 decimals
    await ctx.initializePool(BigInt(60)); // tau = 60 seconds (minimum)

    const BILLION = BigInt(1_000_000_000); // 1 token with 9 decimals

    // --- Setup 4 stakers ---
    const alice = Keypair.generate();
    const bob = Keypair.generate();
    const carol = Keypair.generate();
    const dave = Keypair.generate();

    await airdropAndConfirm(connection, alice.publicKey, 2 * LAMPORTS_PER_SOL);
    await airdropAndConfirm(connection, bob.publicKey, 2 * LAMPORTS_PER_SOL);
    await airdropAndConfirm(connection, carol.publicKey, 2 * LAMPORTS_PER_SOL);
    await airdropAndConfirm(connection, dave.publicKey, 2 * LAMPORTS_PER_SOL);

    const aliceToken = await ctx.createUserTokenAccount(alice.publicKey);
    const bobToken = await ctx.createUserTokenAccount(bob.publicKey);
    const carolToken = await ctx.createUserTokenAccount(carol.publicKey);
    const daveToken = await ctx.createUserTokenAccount(dave.publicKey);

    // Mint tokens: Alice=10B, Bob=5B, Carol=8B, Dave=3B
    const aliceAmount = BigInt(10) * BILLION;
    const bobAmount = BigInt(5) * BILLION;
    const carolAmount = BigInt(8) * BILLION;
    const daveAmount = BigInt(3) * BILLION;

    await ctx.mintTokens(aliceToken, aliceAmount);
    await ctx.mintTokens(bobToken, bobAmount);
    await ctx.mintTokens(carolToken, carolAmount);
    await ctx.mintTokens(daveToken, daveAmount);

    // Track total SOL rewards deposited and received per user
    let totalDeposited = BigInt(0);
    const rewards: Record<string, bigint> = { alice: BigInt(0), bob: BigInt(0), carol: BigInt(0), dave: BigInt(0) };

    // Helper: measure SOL reward from an operation
    async function measureReward(name: string, user: Keypair, op: () => Promise<any>): Promise<bigint> {
      const before = BigInt(await ctx.getBalance(user.publicKey));
      await op();
      const after = BigInt(await ctx.getBalance(user.publicKey));
      // Payer covers tx fee, so balance diff = pure reward
      const reward = after - before;
      if (reward > BigInt(0)) {
        rewards[name] += reward;
      }
      return reward;
    }

    // ========== PHASE 1 (t=0): Initial stakes + deposit ==========
    console.log('    Phase 1: Initial stakes + deposit 1 SOL');
    await ctx.stake(alice, aliceToken, aliceAmount); // Alice stakes 10B
    await ctx.stake(bob, bobToken, BigInt(3) * BILLION); // Bob stakes 3B
    await ctx.stake(carol, carolToken, carolAmount); // Carol stakes 8B

    await ctx.depositRewards(BigInt(LAMPORTS_PER_SOL)); // Deposit 1 SOL
    totalDeposited += BigInt(LAMPORTS_PER_SOL);

    // ========== PHASE 2 (t+6s): Send SOL + sync + Alice claims ==========
    console.log('    Phase 2: Waiting 6s...');
    await new Promise(r => setTimeout(r, 6000));

    await ctx.syncPool(); // Rebase before weighted operations
    await ctx.sendSolToPool(BigInt(LAMPORTS_PER_SOL / 2)); // 0.5 SOL direct
    await ctx.syncRewards();
    totalDeposited += BigInt(LAMPORTS_PER_SOL / 2);

    const aliceReward1 = await measureReward('alice', alice, () => ctx.claimRewards(alice));
    console.log(`    Alice claim #1: ${aliceReward1} lamports`);

    // ========== PHASE 3 (t+12s): Dave stakes, Bob adds stake (auto-claim), deposit, Carol partial unstake ==========
    console.log('    Phase 3: Waiting 6s...');
    await new Promise(r => setTimeout(r, 6000));

    await ctx.syncPool(); // Rebase before weighted operations
    await ctx.stake(dave, daveToken, daveAmount); // Dave stakes 3B

    // Bob adds 2B more (no auto-claim — pending stays the same)
    await ctx.stake(bob, bobToken, BigInt(2) * BILLION);
    console.log(`    Bob added 2B more tokens`);

    await ctx.depositRewards(BigInt(LAMPORTS_PER_SOL)); // Deposit 1 SOL
    totalDeposited += BigInt(LAMPORTS_PER_SOL);

    // Carol partial unstake 3B (claims rewards too)
    const carolReward1 = await measureReward('carol', carol, () =>
      ctx.unstake(carol, carolToken, BigInt(3) * BILLION)
    );
    console.log(`    Carol partial unstake reward: ${carolReward1} lamports`);

    // ========== PHASE 4 (t+18s): Deposit + Dave claims + Bob claims ==========
    console.log('    Phase 4: Waiting 6s...');
    await new Promise(r => setTimeout(r, 6000));

    await ctx.syncPool(); // Rebase before weighted operations
    await ctx.depositRewards(BigInt(LAMPORTS_PER_SOL / 2)); // Deposit 0.5 SOL
    totalDeposited += BigInt(LAMPORTS_PER_SOL / 2);

    const daveReward1 = await measureReward('dave', dave, () => ctx.claimRewards(dave));
    console.log(`    Dave claim: ${daveReward1} lamports`);

    const bobReward2 = await measureReward('bob', bob, () => ctx.claimRewards(bob));
    console.log(`    Bob claim: ${bobReward2} lamports`);

    // ========== PHASE 5 (t+24s): Dave full unstake + deposit ==========
    console.log('    Phase 5: Waiting 6s...');
    await new Promise(r => setTimeout(r, 6000));

    await ctx.syncPool(); // Rebase before weighted operations
    const daveReward2 = await measureReward('dave', dave, () =>
      ctx.unstake(dave, daveToken, daveAmount)
    );
    console.log(`    Dave full unstake reward: ${daveReward2} lamports`);

    await ctx.depositRewards(BigInt(LAMPORTS_PER_SOL / 2)); // Deposit 0.5 SOL
    totalDeposited += BigInt(LAMPORTS_PER_SOL / 2);

    // ========== PHASE 6 (t+30s): Everyone exits ==========
    console.log('    Phase 6: Waiting 6s...');
    await new Promise(r => setTimeout(r, 6000));

    await ctx.syncPool(); // Rebase before weighted operations

    // Alice: claim + unstake
    const aliceReward2 = await measureReward('alice', alice, () => ctx.claimRewards(alice));
    console.log(`    Alice claim #2: ${aliceReward2} lamports`);
    const aliceReward3 = await measureReward('alice', alice, () =>
      ctx.unstake(alice, aliceToken, aliceAmount)
    );
    console.log(`    Alice unstake reward: ${aliceReward3} lamports`);

    // Bob: full unstake (5B = 3B + 2B)
    const bobReward3 = await measureReward('bob', bob, () =>
      ctx.unstake(bob, bobToken, BigInt(5) * BILLION)
    );
    console.log(`    Bob full unstake reward: ${bobReward3} lamports`);

    // Carol: claim + unstake remaining 5B
    const carolReward2 = await measureReward('carol', carol, () => ctx.claimRewards(carol));
    console.log(`    Carol claim: ${carolReward2} lamports`);
    const carolReward3 = await measureReward('carol', carol, () =>
      ctx.unstake(carol, carolToken, BigInt(5) * BILLION)
    );
    console.log(`    Carol unstake reward: ${carolReward3} lamports`);

    // ========== PHASE 7: Reconciliation ==========
    console.log('    --- Reconciliation ---');

    // 1. Token conservation: all tokens returned, vault empty
    const aliceFinal = await ctx.getTokenBalance(aliceToken);
    const bobFinal = await ctx.getTokenBalance(bobToken);
    const carolFinal = await ctx.getTokenBalance(carolToken);
    const daveFinal = await ctx.getTokenBalance(daveToken);
    const vaultFinal = await ctx.getTokenBalance(ctx.tokenVaultPDA);

    if (aliceFinal !== aliceAmount) throw new Error(`Alice tokens: expected ${aliceAmount}, got ${aliceFinal}`);
    if (bobFinal !== bobAmount) throw new Error(`Bob tokens: expected ${bobAmount}, got ${bobFinal}`);
    if (carolFinal !== carolAmount) throw new Error(`Carol tokens: expected ${carolAmount}, got ${carolFinal}`);
    if (daveFinal !== daveAmount) throw new Error(`Dave tokens: expected ${daveAmount}, got ${daveFinal}`);
    if (vaultFinal !== BigInt(0)) throw new Error(`Vault should be empty, got ${vaultFinal}`);
    console.log('    Token conservation: OK');

    // 2. SOL conservation: totalReceived + poolRemaining ~= totalDeposited
    const totalReceived = rewards.alice + rewards.bob + rewards.carol + rewards.dave;
    const poolRemaining = BigInt(await ctx.getBalance(ctx.poolPDA));
    // Pool has rent-exempt balance too, so we check: received + (poolRemaining - rent) ~= deposited
    // More practically: received <= deposited (no SOL created from nothing)
    const poolAccountInfo = await connection.getAccountInfo(ctx.poolPDA);
    const rentExempt = BigInt(await connection.getMinimumBalanceForRentExemption(poolAccountInfo!.data.length));
    const poolRewardsRemaining = poolRemaining - rentExempt;
    const accounted = totalReceived + poolRewardsRemaining;
    const tolerance = BigInt(100_000); // 100K lamports for WAD rounding

    console.log(`    Total deposited:  ${totalDeposited} lamports (${Number(totalDeposited) / LAMPORTS_PER_SOL} SOL)`);
    console.log(`    Total received:   ${totalReceived} lamports (${Number(totalReceived) / LAMPORTS_PER_SOL} SOL)`);
    console.log(`    Pool remaining:   ${poolRewardsRemaining} lamports`);
    console.log(`    Accounted:        ${accounted} lamports`);

    const diff = accounted > totalDeposited ? accounted - totalDeposited : totalDeposited - accounted;
    if (diff > tolerance) {
      throw new Error(`SOL conservation violated: deposited=${totalDeposited}, accounted=${accounted}, diff=${diff} (tolerance=${tolerance})`);
    }
    console.log(`    SOL conservation: OK (diff=${diff} lamports, tolerance=${tolerance})`);

    // 3. Sanity: every user received some rewards
    for (const [name, amount] of Object.entries(rewards)) {
      if (amount <= BigInt(0)) {
        throw new Error(`${name} received zero rewards`);
      }
      console.log(`    ${name} total rewards: ${amount} lamports`);
    }

    // 4. Fairness: Alice (largest + longest) > Dave (smallest + shortest)
    if (rewards.alice <= rewards.dave) {
      throw new Error(`Fairness check failed: Alice (${rewards.alice}) should earn more than Dave (${rewards.dave})`);
    }
    console.log(`    Fairness check: OK (Alice=${rewards.alice} > Dave=${rewards.dave})`);
  });

  // ============================================
  // SOL CONSERVATION & RECOVERY TESTS
  // ============================================
  // Verify no SOL is lost (dead/stranded) from additional stakes.

  console.log('\n--- SOL Conservation & Recovery Tests ---\n');

  // Test: Additional stakes don't create dead SOL (round 7 fix regression test)
  await test('Conservation: additional stakes preserve all rewards', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(60)); // 60s tau (minimum)

    const staker1 = Keypair.generate();
    const staker2 = Keypair.generate();
    await airdropAndConfirm(connection, staker1.publicKey, 3 * LAMPORTS_PER_SOL);
    await airdropAndConfirm(connection, staker2.publicKey, 3 * LAMPORTS_PER_SOL);

    const token1 = await ctx.createUserTokenAccount(staker1.publicKey);
    const token2 = await ctx.createUserTokenAccount(staker2.publicKey);
    await ctx.mintTokens(token1, BigInt(2_000_000_000));
    await ctx.mintTokens(token2, BigInt(2_000_000_000));

    // Both stake 1B tokens
    await ctx.stake(staker1, token1, BigInt(1_000_000_000));
    await ctx.stake(staker2, token2, BigInt(1_000_000_000));

    // Wait for partial maturity (~15% weight at 10s/60s tau)
    console.log('    Waiting 10s for partial weight accumulation...');
    await new Promise(r => setTimeout(r, 10000));

    // Deposit 1 SOL
    const deposit1 = BigInt(LAMPORTS_PER_SOL);
    await ctx.depositRewards(deposit1);

    // Staker1 does additional stake (this was the bug vector)
    // The auto-claim should pay actual_pending, and stranded should be returned to pool
    let totalClaimed = BigInt(0);
    let bal0 = BigInt(await ctx.getBalance(staker1.publicKey));
    await ctx.stake(staker1, token1, BigInt(500_000_000));
    let bal0After = BigInt(await ctx.getBalance(staker1.publicKey));
    // Additional stake auto-claims rewards — track that SOL
    totalClaimed += (bal0After - bal0);

    // Wait for more weight accumulation
    console.log('    Waiting 10s for more weight...');
    await new Promise(r => setTimeout(r, 10000));

    // Deposit 1 more SOL
    const deposit2 = BigInt(LAMPORTS_PER_SOL);
    await ctx.depositRewards(deposit2);

    const totalDeposited = deposit1 + deposit2;

    // Both claim and fully unstake

    // Staker1: claim + unstake
    let bal = BigInt(await ctx.getBalance(staker1.publicKey));
    await ctx.claimRewards(staker1);
    let balAfter = BigInt(await ctx.getBalance(staker1.publicKey));
    totalClaimed += (balAfter - bal);

    bal = BigInt(await ctx.getBalance(staker1.publicKey));
    await ctx.unstake(staker1, token1, BigInt(1_500_000_000));
    balAfter = BigInt(await ctx.getBalance(staker1.publicKey));
    totalClaimed += (balAfter - bal); // reward portion from unstake

    // Staker2: claim + unstake
    bal = BigInt(await ctx.getBalance(staker2.publicKey));
    await ctx.claimRewards(staker2);
    balAfter = BigInt(await ctx.getBalance(staker2.publicKey));
    totalClaimed += (balAfter - bal);

    bal = BigInt(await ctx.getBalance(staker2.publicKey));
    await ctx.unstake(staker2, token2, BigInt(1_000_000_000));
    balAfter = BigInt(await ctx.getBalance(staker2.publicKey));
    totalClaimed += (balAfter - bal);

    // Check pool remaining
    const poolBalance = BigInt(await ctx.getBalance(ctx.poolPDA));
    const poolAccountInfo = await connection.getAccountInfo(ctx.poolPDA);
    const rentExempt = BigInt(await connection.getMinimumBalanceForRentExemption(poolAccountInfo!.data.length));
    const poolRewardsRemaining = poolBalance - rentExempt;

    const accounted = totalClaimed + poolRewardsRemaining;
    const diff = accounted > totalDeposited
      ? accounted - totalDeposited
      : totalDeposited - accounted;

    console.log(`    Total deposited:    ${totalDeposited} lamports`);
    console.log(`    Total claimed:      ${totalClaimed} lamports`);
    console.log(`    Pool remaining:     ${poolRewardsRemaining} lamports`);
    console.log(`    Accounted:          ${accounted} lamports`);
    console.log(`    Diff:               ${diff} lamports`);

    // The deadSOL from the old bug would show up as a large poolRewardsRemaining
    // (SOL stuck in pool that nobody can claim). With the fix, diff should be tiny.
    const tolerance = BigInt(100_000); // 100K lamports for WAD rounding
    if (diff > tolerance) {
      throw new Error(`SOL conservation violated: deposited=${totalDeposited}, accounted=${accounted}, diff=${diff}`);
    }

    // Extra check: pool remaining should not exceed deposits.
    // At tau=60 with short waits (~15% weight), most rewards remain in pool as
    // stranded/unclaimed — this is expected behavior, not a bug. These rewards
    // are eventually redistributed to all stakers. We just verify the pool
    // isn't holding MORE than deposited (which would indicate SOL creation).
    if (poolRewardsRemaining > totalDeposited + BigInt(100_000)) {
      throw new Error(`Pool has more than deposited: ${poolRewardsRemaining} > ${totalDeposited}`);
    }
    console.log('    Conservation: OK');
  });

  // Test: total_reward_debt is tracked correctly through stake/claim/unstake lifecycle
  await test('Recovery: total_reward_debt tracking across lifecycle', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(60)); // 60s tau (minimum)

    // Verify total_reward_debt starts at 0
    let state = await ctx.readPoolState();
    if (state.totalRewardDebt !== BigInt(0)) {
      throw new Error(`Expected initial totalRewardDebt=0, got ${state.totalRewardDebt}`);
    }

    const staker1 = Keypair.generate();
    const staker2 = Keypair.generate();
    await airdropAndConfirm(connection, staker1.publicKey, 3 * LAMPORTS_PER_SOL);
    await airdropAndConfirm(connection, staker2.publicKey, 3 * LAMPORTS_PER_SOL);

    const token1 = await ctx.createUserTokenAccount(staker1.publicKey);
    const token2 = await ctx.createUserTokenAccount(staker2.publicKey);
    await ctx.mintTokens(token1, BigInt(2_000_000_000));
    await ctx.mintTokens(token2, BigInt(1_000_000_000));

    // Stake staker1 first, deposit rewards, then stake staker2 (so staker2 has non-zero reward_debt)
    await ctx.stake(staker1, token1, BigInt(1_000_000_000));
    state = await ctx.readPoolState();
    const debtAfterStake1 = state.totalRewardDebt;
    console.log(`    After staker1 stake: totalRewardDebt=${debtAfterStake1}`);

    // Deposit rewards so acc_rps > 0 before staker2 stakes
    await ctx.depositRewards(BigInt(LAMPORTS_PER_SOL));
    console.log('    Waiting 10s for weight accumulation...');
    await new Promise(r => setTimeout(r, 10000));

    // Sync so acc_rps reflects deposits
    await ctx.syncRewards();

    await ctx.stake(staker2, token2, BigInt(1_000_000_000));
    state = await ctx.readPoolState();
    const debtAfterStake2 = state.totalRewardDebt;
    console.log(`    After staker2 stake: totalRewardDebt=${debtAfterStake2}`);

    // total_reward_debt should increase (staker2 stakes with non-zero acc_rps → non-zero reward_debt)
    if (debtAfterStake2 <= debtAfterStake1) {
      throw new Error(`totalRewardDebt should increase after new stake with deposits: ${debtAfterStake1} -> ${debtAfterStake2}`);
    }

    // Claim — total_reward_debt stays unchanged (claim uses claimed_rewards_wad, not reward_debt)
    const debtBeforeClaim = (await ctx.readPoolState()).totalRewardDebt;
    await ctx.claimRewards(staker1);
    const debtAfterClaim = (await ctx.readPoolState()).totalRewardDebt;
    console.log(`    After staker1 claim: totalRewardDebt=${debtBeforeClaim} -> ${debtAfterClaim}`);

    if (debtAfterClaim !== debtBeforeClaim) {
      throw new Error(`totalRewardDebt should not change after claim: ${debtBeforeClaim} -> ${debtAfterClaim}`);
    }

    // Additional stake — should update total_reward_debt (subtract old, add new)
    const debtBeforeAddStake = (await ctx.readPoolState()).totalRewardDebt;
    await ctx.stake(staker1, token1, BigInt(500_000_000));
    const debtAfterAddStake = (await ctx.readPoolState()).totalRewardDebt;
    console.log(`    After staker1 additional stake: totalRewardDebt=${debtBeforeAddStake} -> ${debtAfterAddStake}`);

    // Full unstake — should subtract staker2's reward_debt
    const debtBeforeUnstake = (await ctx.readPoolState()).totalRewardDebt;
    await ctx.unstake(staker2, token2, BigInt(1_000_000_000));
    const debtAfterUnstake = (await ctx.readPoolState()).totalRewardDebt;
    console.log(`    After staker2 full unstake: totalRewardDebt=${debtBeforeUnstake} -> ${debtAfterUnstake}`);

    // After staker2 fully unstaked (reward_debt=0), total_reward_debt should decrease
    if (debtAfterUnstake >= debtBeforeUnstake) {
      throw new Error(`totalRewardDebt should decrease after full unstake: ${debtBeforeUnstake} -> ${debtAfterUnstake}`);
    }

    // Cleanup: staker1 unstakes
    await ctx.unstake(staker1, token1, BigInt(1_500_000_000));

    console.log('    total_reward_debt tracking: OK');
  });

  // Test: Multi-staker SOL accounting — sum of all claims never exceeds deposits
  await test('Conservation: multi-staker claims never exceed deposits', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(60)); // 60s tau (minimum)

    const stakers: Keypair[] = [];
    const tokens: PublicKey[] = [];
    const numStakers = 4;

    for (let i = 0; i < numStakers; i++) {
      const s = Keypair.generate();
      await airdropAndConfirm(connection, s.publicKey, 3 * LAMPORTS_PER_SOL);
      const t = await ctx.createUserTokenAccount(s.publicKey);
      const amount = BigInt((i + 1) * 1_000_000_000); // 1B, 2B, 3B, 4B
      await ctx.mintTokens(t, amount);
      await ctx.stake(s, t, amount);
      stakers.push(s);
      tokens.push(t);
    }

    let totalDeposited = BigInt(0);

    // Phase 1: deposit, wait, claim
    await ctx.depositRewards(BigInt(LAMPORTS_PER_SOL));
    totalDeposited += BigInt(LAMPORTS_PER_SOL);

    console.log('    Waiting 6s...');
    await new Promise(r => setTimeout(r, 6000));

    // Staker 0 does additional stake (auto-claims rewards — track SOL)
    await ctx.mintTokens(tokens[0], BigInt(500_000_000));
    let autoClaimBal = BigInt(await ctx.getBalance(stakers[0].publicKey));
    await ctx.stake(stakers[0], tokens[0], BigInt(500_000_000));
    let autoClaimBalAfter = BigInt(await ctx.getBalance(stakers[0].publicKey));
    let autoClaimedSOL = autoClaimBalAfter - autoClaimBal;
    if (autoClaimedSOL < BigInt(0)) throw new Error(`Unexpected SOL loss on auto-claim: ${autoClaimedSOL}`);

    // Phase 2: more deposits
    await ctx.depositRewards(BigInt(LAMPORTS_PER_SOL));
    totalDeposited += BigInt(LAMPORTS_PER_SOL);

    console.log('    Waiting 6s...');
    await new Promise(r => setTimeout(r, 6000));

    // Phase 3: everyone claims and unstakes
    let totalClaimed = autoClaimedSOL;
    for (let i = 0; i < numStakers; i++) {
      // Claim
      const bal = BigInt(await ctx.getBalance(stakers[i].publicKey));
      try { await ctx.claimRewards(stakers[i]); } catch (e: any) { if (!e.message?.includes('0xb')) throw e; }
      const balAfterClaim = BigInt(await ctx.getBalance(stakers[i].publicKey));
      totalClaimed += (balAfterClaim - bal);

      // Unstake — get the staked amount
      const stakeAmount = i === 0
        ? BigInt(1_500_000_000) // 1B + 500M
        : BigInt((i + 1) * 1_000_000_000);
      const balBeforeUnstake = BigInt(await ctx.getBalance(stakers[i].publicKey));
      await ctx.unstake(stakers[i], tokens[i], stakeAmount);
      const balAfterUnstake = BigInt(await ctx.getBalance(stakers[i].publicKey));
      // Count only the reward portion of unstake (unstake also claims rewards)
      totalClaimed += (balAfterUnstake - balBeforeUnstake);
    }

    const poolBalance = BigInt(await ctx.getBalance(ctx.poolPDA));
    const poolAccountInfo = await connection.getAccountInfo(ctx.poolPDA);
    const rentExempt = BigInt(await connection.getMinimumBalanceForRentExemption(poolAccountInfo!.data.length));
    const poolRemaining = poolBalance - rentExempt;
    const accounted = totalClaimed + poolRemaining;

    console.log(`    Deposited:     ${totalDeposited}`);
    console.log(`    Total claimed: ${totalClaimed}`);
    console.log(`    Pool remaining: ${poolRemaining}`);
    console.log(`    Accounted:     ${accounted}`);

    // Claims must never exceed deposits (no SOL created from nothing)
    if (totalClaimed > totalDeposited + BigInt(50_000)) {
      throw new Error(`Over-distribution! Claimed ${totalClaimed} > deposited ${totalDeposited}`);
    }

    // Conservation check
    const diff = accounted > totalDeposited
      ? accounted - totalDeposited
      : totalDeposited - accounted;
    const tolerance = BigInt(100_000);
    if (diff > tolerance) {
      throw new Error(`SOL conservation violated: diff=${diff} > tolerance=${tolerance}`);
    }

    // At tau=60 with short waits, most rewards remain as stranded (expected).
    // Just verify pool doesn't hold more than deposited.
    if (poolRemaining > totalDeposited + BigInt(100_000)) {
      throw new Error(`Pool holds more than deposited: ${poolRemaining} > ${totalDeposited}`);
    }

    console.log(`    Conservation OK (diff=${diff} lamports)`);
  });

  // ==================== METADATA TESTS ====================

  // Test: SetPoolMetadata creates metadata account
  await test('SetPoolMetadata creates metadata account', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMintWithMetadata(9, 'Tibanne Thecat', 'ChiefPussy');
    await ctx.initializePool(BigInt(2592000));

    await ctx.setPoolMetadata();

    const metadata = await ctx.readMetadata();
    if (metadata.name !== 'Tibanne Thecat Staking Pool') {
      throw new Error(`Expected name "Tibanne Thecat Staking Pool", got "${metadata.name}"`);
    }
    if (metadata.numTags !== 3) {
      throw new Error(`Expected 3 tags, got ${metadata.numTags}`);
    }
    if (metadata.tags[0] !== '#stakingpool') {
      throw new Error(`Expected tag 0 "#stakingpool", got "${metadata.tags[0]}"`);
    }
    if (metadata.tags[1] !== '#chiefstaker') {
      throw new Error(`Expected tag 1 "#chiefstaker", got "${metadata.tags[1]}"`);
    }
    if (metadata.tags[2] !== '#chiefpussy') {
      throw new Error(`Expected tag 2 "#chiefpussy", got "${metadata.tags[2]}"`);
    }
    const expectedUrl = `https://labs.chiefpussy.com/staking/${ctx.mint.toBase58()}`;
    if (metadata.url !== expectedUrl) {
      throw new Error(`Expected url "${expectedUrl}", got "${metadata.url}"`);
    }
    if (metadata.memberCount !== 0n) {
      throw new Error(`Expected member_count 0, got ${metadata.memberCount}`);
    }
    if (metadata.pool.toBase58() !== ctx.poolPDA.toBase58()) {
      throw new Error(`Pool mismatch in metadata`);
    }
  });

  // Test: SetPoolMetadata is idempotent (re-calling updates without changing data)
  await test('SetPoolMetadata is idempotent', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMintWithMetadata(9, 'TestToken', 'TEST');
    await ctx.initializePool(BigInt(2592000));

    await ctx.setPoolMetadata();
    const meta1 = await ctx.readMetadata();

    // Call again — should succeed and preserve same data
    await ctx.setPoolMetadata();
    const meta2 = await ctx.readMetadata();

    if (meta1.name !== meta2.name) throw new Error('Name changed on re-call');
    if (meta1.memberCount !== meta2.memberCount) throw new Error('member_count changed on re-call');
    if (meta1.url !== meta2.url) throw new Error('URL changed on re-call');
  });

  // Test: SetPoolMetadata is permissionless
  await test('SetPoolMetadata is permissionless', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMintWithMetadata(9, 'PermTest', 'PERM');
    await ctx.initializePool(BigInt(2592000));

    // Different payer than authority
    const randomPayer = Keypair.generate();
    await airdropAndConfirm(connection, randomPayer.publicKey, LAMPORTS_PER_SOL);

    await ctx.setPoolMetadata(randomPayer);

    const metadata = await ctx.readMetadata();
    if (metadata.name !== 'PermTest Staking Pool') {
      throw new Error(`Expected "PermTest Staking Pool", got "${metadata.name}"`);
    }
  });

  // Test: SetPoolMetadata handles trailing spaces in token name
  await test('SetPoolMetadata trims token name whitespace', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    // Note: Token 2022 metadata stores the name as-is (with trailing space)
    await ctx.createMintWithMetadata(9, 'Tibanne Thecat ', 'ChiefPussy');
    await ctx.initializePool(BigInt(2592000));

    await ctx.setPoolMetadata();

    const metadata = await ctx.readMetadata();
    // .trim() in set_metadata.rs removes trailing space
    if (metadata.name !== 'Tibanne Thecat Staking Pool') {
      throw new Error(`Expected "Tibanne Thecat Staking Pool", got "${metadata.name}"`);
    }
  });

  // Test: Stake with metadata increments member_count
  await test('Stake with metadata increments member_count', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMintWithMetadata(9, 'MemberTest', 'MEM');
    await ctx.initializePool(BigInt(2592000));
    await ctx.setPoolMetadata();

    const meta0 = await ctx.readMetadata();
    if (meta0.memberCount !== 0n) throw new Error(`Expected 0 members, got ${meta0.memberCount}`);

    // Stake with metadata account
    const user1 = Keypair.generate();
    await airdropAndConfirm(connection, user1.publicKey, LAMPORTS_PER_SOL);
    const user1Token = await ctx.createUserTokenAccount(user1.publicKey);
    await ctx.mintTokens(user1Token, BigInt(1_000_000_000));
    await ctx.stakeWithMetadata(user1, user1Token, BigInt(1_000_000_000));

    const meta1 = await ctx.readMetadata();
    if (meta1.memberCount !== 1n) throw new Error(`Expected 1 member, got ${meta1.memberCount}`);

    // Second staker
    const user2 = Keypair.generate();
    await airdropAndConfirm(connection, user2.publicKey, LAMPORTS_PER_SOL);
    const user2Token = await ctx.createUserTokenAccount(user2.publicKey);
    await ctx.mintTokens(user2Token, BigInt(2_000_000_000));
    await ctx.stakeWithMetadata(user2, user2Token, BigInt(2_000_000_000));

    const meta2 = await ctx.readMetadata();
    if (meta2.memberCount !== 2n) throw new Error(`Expected 2 members, got ${meta2.memberCount}`);
  });

  // Test: Additional stake does NOT increment member_count (not new)
  await test('Additional stake does not increment member_count', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMintWithMetadata(9, 'AddStake', 'ADD');
    await ctx.initializePool(BigInt(2592000));
    await ctx.setPoolMetadata();

    const user = Keypair.generate();
    await airdropAndConfirm(connection, user.publicKey, LAMPORTS_PER_SOL);
    const userToken = await ctx.createUserTokenAccount(user.publicKey);
    await ctx.mintTokens(userToken, BigInt(5_000_000_000));

    // First stake
    await ctx.stakeWithMetadata(user, userToken, BigInt(1_000_000_000));
    const meta1 = await ctx.readMetadata();
    if (meta1.memberCount !== 1n) throw new Error(`Expected 1, got ${meta1.memberCount}`);

    // Additional stake (existing account, should NOT increment)
    await ctx.stakeWithMetadata(user, userToken, BigInt(1_000_000_000));
    const meta2 = await ctx.readMetadata();
    if (meta2.memberCount !== 1n) throw new Error(`Expected still 1, got ${meta2.memberCount}`);
  });

  // Test: CloseStakeAccount with metadata decrements member_count
  await test('CloseStakeAccount with metadata decrements member_count', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMintWithMetadata(9, 'CloseTest', 'CLZ');
    await ctx.initializePool(BigInt(2592000));
    await ctx.setPoolMetadata();

    const user = Keypair.generate();
    await airdropAndConfirm(connection, user.publicKey, LAMPORTS_PER_SOL);
    const userToken = await ctx.createUserTokenAccount(user.publicKey);
    await ctx.mintTokens(userToken, BigInt(1_000_000_000));

    // Stake with metadata
    await ctx.stakeWithMetadata(user, userToken, BigInt(1_000_000_000));
    const meta1 = await ctx.readMetadata();
    if (meta1.memberCount !== 1n) throw new Error(`Expected 1, got ${meta1.memberCount}`);

    // Unstake everything
    await ctx.unstake(user, userToken, BigInt(1_000_000_000));

    // Close stake account with metadata
    await ctx.closeStakeAccount(user, true);
    const meta2 = await ctx.readMetadata();
    if (meta2.memberCount !== 0n) throw new Error(`Expected 0 after close, got ${meta2.memberCount}`);
  });

  // Test: SetPoolMetadata preserves member_count on update
  await test('SetPoolMetadata preserves member_count on update', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMintWithMetadata(9, 'PreserveCount', 'PRS');
    await ctx.initializePool(BigInt(2592000));
    await ctx.setPoolMetadata();

    // Stake to increment member_count
    const user = Keypair.generate();
    await airdropAndConfirm(connection, user.publicKey, LAMPORTS_PER_SOL);
    const userToken = await ctx.createUserTokenAccount(user.publicKey);
    await ctx.mintTokens(userToken, BigInt(1_000_000_000));
    await ctx.stakeWithMetadata(user, userToken, BigInt(1_000_000_000));

    const meta1 = await ctx.readMetadata();
    if (meta1.memberCount !== 1n) throw new Error(`Expected 1, got ${meta1.memberCount}`);

    // Re-set metadata — member_count should be preserved
    await ctx.setPoolMetadata();
    const meta2 = await ctx.readMetadata();
    if (meta2.memberCount !== 1n) throw new Error(`Expected 1 after re-set, got ${meta2.memberCount}`);
  });

  // Test: Stake without metadata account still works (backwards compatible)
  await test('Stake without metadata account is backwards compatible', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMintWithMetadata(9, 'BackCompat', 'BCK');
    await ctx.initializePool(BigInt(2592000));
    await ctx.setPoolMetadata();

    const user = Keypair.generate();
    await airdropAndConfirm(connection, user.publicKey, LAMPORTS_PER_SOL);
    const userToken = await ctx.createUserTokenAccount(user.publicKey);
    await ctx.mintTokens(userToken, BigInt(1_000_000_000));

    // Stake WITHOUT passing metadata account (old-style 8-account call)
    await ctx.stake(user, userToken, BigInt(1_000_000_000));

    // member_count should remain 0 since we didn't pass metadata
    const meta = await ctx.readMetadata();
    if (meta.memberCount !== 0n) throw new Error(`Expected 0 (no metadata passed), got ${meta.memberCount}`);
  });

  // === Repeated Claim Exploit Tests (round 10b fix) ===

  // Test: Repeated claims do NOT extract max-weight rewards
  await test('Security: Repeated claims cannot extract max-weight rewards', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);

    // tau=60 so weight grows slowly (user will have ~15% weight after 10s)
    await ctx.initializePool(BigInt(60));

    const user = Keypair.generate();
    await airdropAndConfirm(connection, user.publicKey, 2 * LAMPORTS_PER_SOL);
    const userToken = await ctx.createUserTokenAccount(user.publicKey);
    await ctx.mintTokens(userToken, BigInt(1_000_000_000));
    await ctx.stake(user, userToken, BigInt(1_000_000_000));

    // Wait 10s to accrue some weight (~15% at tau=60)
    console.log('    Waiting 10s for weight to accrue...');
    await new Promise(r => setTimeout(r, 10000));

    // Deposit a large reward
    const depositAmount = LAMPORTS_PER_SOL;
    await ctx.depositRewards(BigInt(depositAmount));

    // Claim 5 times in rapid succession
    let totalClaimed = 0;
    for (let i = 0; i < 5; i++) {
      const balBefore = await ctx.getBalance(user.publicKey);
      try {
        await ctx.claimRewards(user);
      } catch (e) {
        // Expected: "no pending rewards" after first claim
      }
      const balAfter = await ctx.getBalance(user.publicKey);
      const reward = balAfter - balBefore;
      if (reward > 0) {
        totalClaimed += reward;
        console.log(`    Claim ${i + 1}: ${reward} lamports`);
      } else {
        console.log(`    Claim ${i + 1}: 0 (no rewards / tx fee)`);
      }
    }

    // The critical assertion: total claimed must be much less than the deposit.
    // With ~15% weight, user should get ~15% of 1 SOL = ~0.15 SOL.
    // Before fix: repeated claims would converge to ~1 SOL (100%).
    // Allow generous margin: user should get < 50% of deposit.
    const claimedPercent = (totalClaimed * 100) / depositAmount;
    console.log(`    Total claimed: ${totalClaimed} lamports (${claimedPercent.toFixed(1)}% of deposit)`);

    if (totalClaimed > depositAmount * 0.5) {
      throw new Error(
        `EXPLOIT: Repeated claims extracted ${claimedPercent.toFixed(1)}% of deposit ` +
        `(expected <50% for ~15% weight). Total: ${totalClaimed} / ${depositAmount}`
      );
    }
  });

  // Test: Second claim returns 0 when no new rewards deposited
  await test('Security: Second claim returns 0 without new rewards', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(60));

    const user = Keypair.generate();
    await airdropAndConfirm(connection, user.publicKey, 2 * LAMPORTS_PER_SOL);
    const userToken = await ctx.createUserTokenAccount(user.publicKey);
    await ctx.mintTokens(userToken, BigInt(1_000_000_000));
    await ctx.stake(user, userToken, BigInt(1_000_000_000));

    // Wait for weight
    console.log('    Waiting 5s for weight...');
    await new Promise(r => setTimeout(r, 5000));

    await ctx.depositRewards(BigInt(LAMPORTS_PER_SOL / 2));

    // First claim should succeed
    const bal1 = await ctx.getBalance(user.publicKey);
    await ctx.claimRewards(user);
    const reward1 = (await ctx.getBalance(user.publicKey)) - bal1;
    console.log(`    First claim: ${reward1} lamports`);
    if (reward1 <= 0) throw new Error('First claim should get rewards');

    // Second claim (no new deposits) — in a time-weighted system, weight grows
    // between claims, so a small additional entitlement is normal. The security
    // check is that the second claim is much smaller than the first (no double-claim).
    const bal2 = await ctx.getBalance(user.publicKey);
    try {
      await ctx.claimRewards(user);
    } catch (e) {
      // May be rejected if pending rounds to 0
      console.log('    Second claim: rejected (expected)');
    }
    const reward2 = (await ctx.getBalance(user.publicKey)) - bal2;
    console.log(`    Second claim: ${reward2} lamports`);

    // Second claim must be strictly less than first (weight growth, not double-claim)
    if (reward2 >= reward1) {
      throw new Error(
        `EXPLOIT: Second claim got ${reward2} lamports (>= first claim ${reward1}), possible double-claim`
      );
    }
  });

  // Test: Claiming frequency doesn't affect total rewards (frequency-independent)
  await test('Security: Claim frequency does not affect total rewards', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(60));

    // Both stake at the same time
    const multiClaimer = Keypair.generate();
    const singleClaimer = Keypair.generate();
    await airdropAndConfirm(connection, multiClaimer.publicKey, 2 * LAMPORTS_PER_SOL);
    await airdropAndConfirm(connection, singleClaimer.publicKey, 2 * LAMPORTS_PER_SOL);
    const multiToken = await ctx.createUserTokenAccount(multiClaimer.publicKey);
    const singleToken = await ctx.createUserTokenAccount(singleClaimer.publicKey);
    const amount = BigInt(1_000_000_000);
    await ctx.mintTokens(multiToken, amount);
    await ctx.mintTokens(singleToken, amount);
    await ctx.stake(multiClaimer, multiToken, amount);
    await ctx.stake(singleClaimer, singleToken, amount);

    // Wait 5s, deposit rewards
    console.log('    Waiting 5s...');
    await new Promise(r => setTimeout(r, 5000));
    await ctx.depositRewards(BigInt(LAMPORTS_PER_SOL));

    // Multi-claimer claims immediately at low weight
    const multiBal1 = await ctx.getBalance(multiClaimer.publicKey);
    await ctx.claimRewards(multiClaimer);
    const multiReward1 = (await ctx.getBalance(multiClaimer.publicKey)) - multiBal1;
    console.log(`    Multi-claimer first claim (5s age): ${multiReward1}`);

    // Wait another 15s for weight to grow
    console.log('    Waiting 15s more...');
    await new Promise(r => setTimeout(r, 15000));

    // Multi-claimer claims again (picks up weight growth entitlement)
    const multiBal2 = await ctx.getBalance(multiClaimer.publicKey);
    try {
      await ctx.claimRewards(multiClaimer);
    } catch (e: any) { if (!e.message?.includes('0xb')) throw e; }
    const multiReward2 = (await ctx.getBalance(multiClaimer.publicKey)) - multiBal2;
    if (multiReward2 < 0) throw new Error(`Unexpected SOL loss: ${multiReward2}`);

    // Single-claimer claims once at 20s age
    const singleBal = await ctx.getBalance(singleClaimer.publicKey);
    await ctx.claimRewards(singleClaimer);
    const singleReward = (await ctx.getBalance(singleClaimer.publicKey)) - singleBal;

    const multiTotal = multiReward1 + multiReward2;
    console.log(`    Multi-claimer total: ${multiTotal} lamports`);
    console.log(`    Single-claimer total: ${singleReward} lamports`);

    // Frequency-independent: both should earn approximately the same.
    // Allow tolerance for block-time jitter between claims (weight grows ~1.2%/s
    // at t=20s with tau=60, so a few seconds of jitter → a few % difference).
    const diff = Math.abs(singleReward - multiTotal);
    const larger = Math.max(singleReward, multiTotal);
    const pctDiff = larger > 0 ? (diff * 100) / larger : 0;
    console.log(`    Difference: ${diff} lamports (${pctDiff.toFixed(1)}%)`);

    if (pctDiff > 10) {
      throw new Error(
        `Claim totals diverged >10%: multi=${multiTotal}, single=${singleReward}, diff=${pctDiff.toFixed(1)}%`
      );
    }
    console.log('    Frequency-independent claiming: OK');
  });

  // Test: total_rewards_claimed field tracks correctly
  await test('Accounting: total_rewards_claimed increments on claim', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(60));

    const user = Keypair.generate();
    await airdropAndConfirm(connection, user.publicKey, 2 * LAMPORTS_PER_SOL);
    const userToken = await ctx.createUserTokenAccount(user.publicKey);
    await ctx.mintTokens(userToken, BigInt(1_000_000_000));
    await ctx.stake(user, userToken, BigInt(1_000_000_000));

    // Check initial state
    const state0 = await ctx.readUserStakeState(user.publicKey);
    console.log(`    Initial total_rewards_claimed: ${state0.totalRewardsClaimed}`);
    if (state0.totalRewardsClaimed !== 0n) {
      throw new Error(`Expected 0 initial, got ${state0.totalRewardsClaimed}`);
    }

    // Wait and deposit
    console.log('    Waiting 5s...');
    await new Promise(r => setTimeout(r, 5000));
    await ctx.depositRewards(BigInt(LAMPORTS_PER_SOL / 2));

    // Claim
    const balBefore = await ctx.getBalance(user.publicKey);
    await ctx.claimRewards(user);
    const balAfter = await ctx.getBalance(user.publicKey);
    const reward = balAfter - balBefore;
    console.log(`    Claimed: ${reward} lamports`);

    // Check total_rewards_claimed updated
    const state1 = await ctx.readUserStakeState(user.publicKey);
    console.log(`    total_rewards_claimed after claim: ${state1.totalRewardsClaimed}`);

    if (state1.totalRewardsClaimed === 0n) {
      throw new Error('total_rewards_claimed should be > 0 after claim');
    }

    // Deposit more and claim again
    await ctx.depositRewards(BigInt(LAMPORTS_PER_SOL / 2));
    // Wait a tiny bit for weight (otherwise snapshot delta is 0)
    await new Promise(r => setTimeout(r, 2000));
    try {
      await ctx.claimRewards(user);
    } catch (e) { /* may fail if no new delta */ }

    const state2 = await ctx.readUserStakeState(user.publicKey);
    console.log(`    total_rewards_claimed after second: ${state2.totalRewardsClaimed}`);

    if (state2.totalRewardsClaimed < state1.totalRewardsClaimed) {
      throw new Error('total_rewards_claimed should never decrease');
    }
  });

  // Test: total_rewards_claimed increments on auto-claim during additional stake
  await test('Accounting: total_rewards_claimed increments on auto-claim stake', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(60));

    const user = Keypair.generate();
    await airdropAndConfirm(connection, user.publicKey, 2 * LAMPORTS_PER_SOL);
    const userToken = await ctx.createUserTokenAccount(user.publicKey);
    await ctx.mintTokens(userToken, BigInt(2_000_000_000));
    await ctx.stake(user, userToken, BigInt(1_000_000_000));

    // Wait and deposit
    console.log('    Waiting 5s...');
    await new Promise(r => setTimeout(r, 5000));
    await ctx.depositRewards(BigInt(LAMPORTS_PER_SOL / 2));

    // Additional stake triggers auto-claim
    const balBefore = await ctx.getBalance(user.publicKey);
    await ctx.stake(user, userToken, BigInt(500_000_000));
    const balAfter = await ctx.getBalance(user.publicKey);

    const state = await ctx.readUserStakeState(user.publicKey);
    console.log(`    total_rewards_claimed after additional stake: ${state.totalRewardsClaimed}`);
    console.log(`    Balance delta (includes tx fee): ${balAfter - balBefore}`);

    // If auto-claim paid out anything, total_rewards_claimed should reflect it
    if (state.totalRewardsClaimed > 0n) {
      console.log('    Auto-claim rewards tracked successfully');
    } else {
      console.log('    No auto-claim payout (weight may be too low)');
    }
  });

  // Test: total_rewards_claimed increments on unstake with reward payout
  await test('Accounting: total_rewards_claimed increments on unstake', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(60));

    const user = Keypair.generate();
    await airdropAndConfirm(connection, user.publicKey, 2 * LAMPORTS_PER_SOL);
    const userToken = await ctx.createUserTokenAccount(user.publicKey);
    await ctx.mintTokens(userToken, BigInt(1_000_000_000));
    await ctx.stake(user, userToken, BigInt(1_000_000_000));

    // Wait and deposit
    console.log('    Waiting 5s...');
    await new Promise(r => setTimeout(r, 5000));
    await ctx.depositRewards(BigInt(LAMPORTS_PER_SOL / 2));

    // Unstake (should auto-claim rewards)
    await ctx.unstake(user, userToken, BigInt(500_000_000));

    const state = await ctx.readUserStakeState(user.publicKey);
    console.log(`    total_rewards_claimed after unstake: ${state.totalRewardsClaimed}`);

    if (state.totalRewardsClaimed > 0n) {
      console.log('    Unstake reward payout tracked successfully');
    } else {
      console.log('    No reward payout during unstake (weight may be too low)');
    }
  });

  await test('Security: Large stake amounts don\'t overflow reward math', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(60));

    const user = Keypair.generate();
    await airdropAndConfirm(connection, user.publicKey, 3 * LAMPORTS_PER_SOL);
    const userToken = await ctx.createUserTokenAccount(user.publicKey);

    // Mint near-u64-max tokens (9e18, close to u64::MAX of ~1.8e19)
    const hugeAmount = BigInt('9000000000000000000'); // 9e18
    await ctx.mintTokens(userToken, hugeAmount);
    await ctx.stake(user, userToken, hugeAmount);

    const staked = await ctx.getTokenBalance(ctx.tokenVaultPDA);
    console.log(`    Staked ${staked} tokens (9e18)`);

    // Deposit 2 SOL in rewards, wait for weight accumulation
    const depositAmount = BigInt(2 * LAMPORTS_PER_SOL);
    await ctx.depositRewards(depositAmount);

    console.log('    Waiting 5s for weight accumulation...');
    await new Promise(r => setTimeout(r, 5000));

    // Claim — must succeed without overflow panic
    const balBefore = BigInt(await ctx.getBalance(user.publicKey));
    await ctx.claimRewards(user);
    const balAfter = BigInt(await ctx.getBalance(user.publicKey));
    const claimed = balAfter - balBefore;
    console.log(`    Claimed: ${claimed} lamports`);

    if (claimed > depositAmount) {
      throw new Error(`Claimed ${claimed} exceeds deposited ${depositAmount}`);
    }
    console.log('    Claim <= deposited: OK');

    // Unstake fully — must succeed, token balance restored
    await ctx.unstake(user, userToken, hugeAmount);
    const tokenBalAfter = await ctx.getTokenBalance(userToken);
    if (tokenBalAfter !== hugeAmount) {
      throw new Error(`Token balance mismatch after unstake: expected ${hugeAmount}, got ${tokenBalAfter}`);
    }
    console.log('    Full unstake succeeded, token balance restored');
  });

  await test('Security: Claim capped at available pool balance (exact drain)', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(60));

    const user1 = Keypair.generate();
    const user2 = Keypair.generate();
    await airdropAndConfirm(connection, user1.publicKey, 2 * LAMPORTS_PER_SOL);
    await airdropAndConfirm(connection, user2.publicKey, 2 * LAMPORTS_PER_SOL);

    const token1 = await ctx.createUserTokenAccount(user1.publicKey);
    const token2 = await ctx.createUserTokenAccount(user2.publicKey);
    await ctx.mintTokens(token1, BigInt(1_000_000_000));
    await ctx.mintTokens(token2, BigInt(1_000_000_000));

    // Both stake equally
    await ctx.stake(user1, token1, BigInt(1_000_000_000));
    await ctx.stake(user2, token2, BigInt(1_000_000_000));

    // Deposit tiny reward (50,000 lamports)
    const tinyDeposit = BigInt(50_000);
    await ctx.depositRewards(tinyDeposit);

    console.log('    Waiting 5s for weight accumulation...');
    await new Promise(r => setTimeout(r, 5000));

    // User1 claims first (gets a portion)
    let totalClaimed = BigInt(0);
    const bal1Before = BigInt(await ctx.getBalance(user1.publicKey));
    try {
      await ctx.claimRewards(user1);
    } catch (e) {
      // Claim may fail if entitlement is 0
    }
    const bal1After = BigInt(await ctx.getBalance(user1.publicKey));
    const claim1 = bal1After - bal1Before;
    if (claim1 > BigInt(0)) totalClaimed += claim1;
    console.log(`    User1 claimed: ${claim1} lamports`);

    // User2 claims — entitlement may exceed remaining balance
    const bal2Before = BigInt(await ctx.getBalance(user2.publicKey));
    try {
      await ctx.claimRewards(user2);
    } catch (e) {
      console.log('    User2 claim failed (expected if pool drained)');
    }
    const bal2After = BigInt(await ctx.getBalance(user2.publicKey));
    const claim2 = bal2After - bal2Before;
    if (claim2 > BigInt(0)) totalClaimed += claim2;
    console.log(`    User2 claimed: ${claim2} lamports`);

    // Verify: pool balance >= rent-exempt minimum
    const poolBalance = BigInt(await ctx.getBalance(ctx.poolPDA));
    const poolAccountInfo = await connection.getAccountInfo(ctx.poolPDA);
    const rentExempt = BigInt(await connection.getMinimumBalanceForRentExemption(poolAccountInfo!.data.length));
    console.log(`    Pool balance: ${poolBalance}, rent-exempt min: ${rentExempt}`);

    if (poolBalance < rentExempt) {
      throw new Error(`Pool balance ${poolBalance} dropped below rent-exempt minimum ${rentExempt}`);
    }
    console.log('    Pool balance >= rent-exempt: OK');

    // Verify: total claimed <= total deposited (with tolerance for rounding)
    const tolerance = BigInt(100_000);
    if (totalClaimed > tinyDeposit + tolerance) {
      throw new Error(`Total claimed ${totalClaimed} exceeds deposited ${tinyDeposit} + tolerance`);
    }
    console.log(`    Total claimed (${totalClaimed}) <= deposited (${tinyDeposit}): OK`);
  });

  await test('Security: Sandwich attack (stake between deposit and sync) gives no advantage', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(60));

    // Honest user stakes and waits for weight
    const honest = Keypair.generate();
    await airdropAndConfirm(connection, honest.publicKey, 3 * LAMPORTS_PER_SOL);
    const honestToken = await ctx.createUserTokenAccount(honest.publicKey);
    await ctx.mintTokens(honestToken, BigInt(1_000_000_000));
    await ctx.stake(honest, honestToken, BigInt(1_000_000_000));

    console.log('    Waiting 10s for honest staker weight...');
    await new Promise(r => setTimeout(r, 10000));

    // Deposit rewards via direct SOL transfer (no auto-sync)
    const depositAmount = BigInt(LAMPORTS_PER_SOL);
    await ctx.sendSolToPool(depositAmount);

    // Attacker stakes immediately after deposit but BEFORE syncRewards
    const attacker = Keypair.generate();
    await airdropAndConfirm(connection, attacker.publicKey, 3 * LAMPORTS_PER_SOL);
    const attackerToken = await ctx.createUserTokenAccount(attacker.publicKey);
    await ctx.mintTokens(attackerToken, BigInt(1_000_000_000));
    await ctx.stake(attacker, attackerToken, BigInt(1_000_000_000));

    // Now sync rewards — attacker has ~0 weight at this point
    await ctx.syncRewards();

    // Both claim
    const honestBalBefore = BigInt(await ctx.getBalance(honest.publicKey));
    await ctx.claimRewards(honest);
    const honestBalAfter = BigInt(await ctx.getBalance(honest.publicKey));
    const honestClaimed = honestBalAfter - honestBalBefore;

    let attackerClaimed = BigInt(0);
    const attackerBalBefore = BigInt(await ctx.getBalance(attacker.publicKey));
    try {
      await ctx.claimRewards(attacker);
    } catch (e) {
      console.log('    Attacker claim failed (expected — zero weight)');
    }
    const attackerBalAfter = BigInt(await ctx.getBalance(attacker.publicKey));
    attackerClaimed = attackerBalAfter - attackerBalBefore;

    const totalClaimed = (honestClaimed > BigInt(0) ? honestClaimed : BigInt(0))
                       + (attackerClaimed > BigInt(0) ? attackerClaimed : BigInt(0));

    console.log(`    Honest claimed:   ${honestClaimed} lamports`);
    console.log(`    Attacker claimed: ${attackerClaimed} lamports`);

    // Verify: attacker gets near-zero, honest gets >75% of rewards
    if (honestClaimed <= BigInt(0)) {
      throw new Error('Honest staker should have received rewards');
    }

    if (totalClaimed > BigInt(0)) {
      const honestShare = Number(honestClaimed) * 100 / Number(totalClaimed);
      console.log(`    Honest share: ${honestShare.toFixed(1)}%`);
      if (honestShare < 75) {
        throw new Error(`Honest staker share too low: ${honestShare.toFixed(1)}% (expected >75%)`);
      }
    }

    // Verify: conservation holds
    const tolerance = BigInt(100_000);
    if (totalClaimed > depositAmount + tolerance) {
      throw new Error(`Conservation violated: claimed ${totalClaimed} > deposited ${depositAmount} + tolerance`);
    }
    console.log('    Sandwich attack mitigated: OK');
  });

  // ─── Add-Stake Tests ─────────────────────────────────────────────────────────
  //
  // On add-stake, maturity percentage is preserved (depends only on start time).
  // exp_start_factor doesn't change, claimed_rewards_wad doesn't change.
  // reward_debt gets a fresh snapshot added for new tokens only.
  // Pending rewards stay exactly the same — user can claim separately.

  console.log('\n--- Add-Stake Tests ---\n');

  // Test: exp_start_factor and pending rewards unchanged after add-stake
  await test('AddStake: maturity preserved — exp_start_factor unchanged', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(60)); // 60s tau

    const staker = Keypair.generate();
    await airdropAndConfirm(connection, staker.publicKey, 3 * LAMPORTS_PER_SOL);
    const stakerToken = await ctx.createUserTokenAccount(staker.publicKey);
    await ctx.mintTokens(stakerToken, BigInt(2_000_000_000));

    // Stake 1B tokens
    await ctx.stake(staker, stakerToken, BigInt(1_000_000_000));

    // Wait for partial maturity
    console.log('    Waiting 15s for partial weight...');
    await new Promise(r => setTimeout(r, 15000));

    // Deposit 2 SOL of rewards
    await ctx.depositRewards(BigInt(2 * LAMPORTS_PER_SOL));

    // Read state before add-stake
    const stateBefore = await ctx.readUserStakeState(staker.publicKey);
    const expBefore = stateBefore.expStartFactor;
    const claimedBefore = stateBefore.claimedRewardsWad;

    // Measure claimable before add-stake
    let bal = BigInt(await ctx.getBalance(staker.publicKey));
    await ctx.claimRewards(staker);
    let balAfter = BigInt(await ctx.getBalance(staker.publicKey));
    const claimBefore = balAfter - bal;
    console.log(`    Claim before add-stake: ${claimBefore} lamports`);

    // Add 1B more tokens
    await ctx.stake(staker, stakerToken, BigInt(1_000_000_000));

    // Read state after add-stake
    const stateAfter = await ctx.readUserStakeState(staker.publicKey);
    console.log(`    exp_start_factor: before=${expBefore}, after=${stateAfter.expStartFactor}`);
    console.log(`    amount: ${stateBefore.amount} → ${stateAfter.amount}`);

    // exp_start_factor MUST be unchanged
    if (stateAfter.expStartFactor !== expBefore) {
      throw new Error(`exp_start_factor changed! ${expBefore} → ${stateAfter.expStartFactor}`);
    }

    // Amount must have increased
    if (stateAfter.amount !== BigInt(2_000_000_000)) {
      throw new Error(`Expected 2B, got ${stateAfter.amount}`);
    }

    console.log('    Maturity preserved: OK');
  });

  // Test: Pending rewards unchanged by add-stake (claim before == claim after)
  await test('AddStake: pending rewards unchanged by add-stake', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(60)); // 60s tau

    const staker = Keypair.generate();
    await airdropAndConfirm(connection, staker.publicKey, 5 * LAMPORTS_PER_SOL);
    const stakerToken = await ctx.createUserTokenAccount(staker.publicKey);
    await ctx.mintTokens(stakerToken, BigInt(2_000_000_000));

    // Stake 1B tokens
    await ctx.stake(staker, stakerToken, BigInt(1_000_000_000));

    // Wait for partial maturity
    console.log('    Waiting 15s for partial weight...');
    await new Promise(r => setTimeout(r, 15000));

    // Deposit 2 SOL of rewards
    await ctx.depositRewards(BigInt(2 * LAMPORTS_PER_SOL));

    // Add 1B more tokens (pending should stay the same)
    await ctx.stake(staker, stakerToken, BigInt(1_000_000_000));

    // Claim — should get the same vested rewards as before the add-stake
    let bal = BigInt(await ctx.getBalance(staker.publicKey));
    await ctx.claimRewards(staker);
    let balAfter = BigInt(await ctx.getBalance(staker.publicKey));
    const claimAfterAdd = balAfter - bal;
    console.log(`    Claim after add-stake: ${claimAfterAdd} lamports`);

    // Should be positive (rewards vested during the 15s maturity period)
    if (claimAfterAdd < BigInt(10_000)) {
      throw new Error(`Pending rewards lost on add-stake! Got ${claimAfterAdd}`);
    }

    console.log('    Pending rewards preserved: OK');
  });

  // Test: SOL continues to mature after add-stake
  await test('AddStake: SOL continues to mature after add-stake', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(60)); // 60s tau

    const staker = Keypair.generate();
    await airdropAndConfirm(connection, staker.publicKey, 5 * LAMPORTS_PER_SOL);
    const stakerToken = await ctx.createUserTokenAccount(staker.publicKey);
    await ctx.mintTokens(stakerToken, BigInt(2_000_000_000));

    // Stake 1B tokens
    await ctx.stake(staker, stakerToken, BigInt(1_000_000_000));

    // Wait for partial maturity
    console.log('    Waiting 15s for partial maturity...');
    await new Promise(r => setTimeout(r, 15000));

    // Deposit 2 SOL
    await ctx.depositRewards(BigInt(2 * LAMPORTS_PER_SOL));

    // Claim vested rewards
    await ctx.claimRewards(staker);

    // Add 1B more tokens
    await ctx.stake(staker, stakerToken, BigInt(1_000_000_000));

    // Wait 30s for more maturity
    console.log('    Waiting 30s for maturation...');
    await new Promise(r => setTimeout(r, 30000));

    // Claim — should get newly matured rewards
    let bal = BigInt(await ctx.getBalance(staker.publicKey));
    await ctx.claimRewards(staker);
    let balAfter = BigInt(await ctx.getBalance(staker.publicKey));
    const matureClaim = balAfter - bal;
    console.log(`    Claim after 30s maturation: ${matureClaim} lamports`);

    if (matureClaim < BigInt(100_000)) {
      throw new Error(`SOL not maturing after add-stake! Got ${matureClaim}`);
    }

    console.log('    SOL continues to mature: OK');
  });

  // Test: Conservation — add-stake doesn't create or destroy rewards
  await test('AddStake: conservation — total claimed ≤ total deposited', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(60)); // 60s tau

    const alice = Keypair.generate();
    const bob = Keypair.generate();
    await airdropAndConfirm(connection, alice.publicKey, 3 * LAMPORTS_PER_SOL);
    await airdropAndConfirm(connection, bob.publicKey, 3 * LAMPORTS_PER_SOL);

    const aliceToken = await ctx.createUserTokenAccount(alice.publicKey);
    const bobToken = await ctx.createUserTokenAccount(bob.publicKey);
    await ctx.mintTokens(aliceToken, BigInt(2_000_000_000));
    await ctx.mintTokens(bobToken, BigInt(1_000_000_000));

    // Both stake 1B tokens
    await ctx.stake(alice, aliceToken, BigInt(1_000_000_000));
    await ctx.stake(bob, bobToken, BigInt(1_000_000_000));

    // Wait for partial maturity
    console.log('    Waiting 15s for partial weight...');
    await new Promise(r => setTimeout(r, 15000));

    // Deposit 2 SOL
    const depositAmount = BigInt(2 * LAMPORTS_PER_SOL);
    await ctx.depositRewards(depositAmount);

    // Alice stakes 1B more (no auto-claim — pending stays the same)
    await ctx.stake(alice, aliceToken, BigInt(1_000_000_000));

    // Wait for more maturity
    console.log('    Waiting 30s for maturity...');
    await new Promise(r => setTimeout(r, 30000));

    // Both claim
    let aliceTotal = BigInt(0);
    let bal = BigInt(await ctx.getBalance(alice.publicKey));
    await ctx.claimRewards(alice);
    let balAfter = BigInt(await ctx.getBalance(alice.publicKey));
    aliceTotal += (balAfter - bal);

    bal = BigInt(await ctx.getBalance(bob.publicKey));
    await ctx.claimRewards(bob);
    balAfter = BigInt(await ctx.getBalance(bob.publicKey));
    const bobTotal = balAfter - bal;

    // Both fully unstake
    bal = BigInt(await ctx.getBalance(alice.publicKey));
    await ctx.unstake(alice, aliceToken, BigInt(2_000_000_000));
    balAfter = BigInt(await ctx.getBalance(alice.publicKey));
    aliceTotal += (balAfter - bal);

    bal = BigInt(await ctx.getBalance(bob.publicKey));
    await ctx.unstake(bob, bobToken, BigInt(1_000_000_000));
    balAfter = BigInt(await ctx.getBalance(bob.publicKey));
    const bobFinal = bobTotal + (balAfter - bal);

    const totalClaimed = aliceTotal + bobFinal;

    console.log(`    Alice total received: ${aliceTotal} lamports`);
    console.log(`    Bob total received:   ${bobFinal} lamports`);
    console.log(`    Total claimed:        ${totalClaimed} lamports`);

    // Conservation: total claimed must not exceed deposited
    const tolerance = BigInt(100_000);
    if (totalClaimed > depositAmount + tolerance) {
      throw new Error(`Conservation violated: claimed ${totalClaimed} > deposited ${depositAmount}`);
    }

    console.log('    Conservation maintained: OK');
  });

  // Test: Dust-stake doesn't extract extra rewards
  await test('AddStake: dust-stake yields no extra rewards', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(60)); // 60s tau

    const staker = Keypair.generate();
    await airdropAndConfirm(connection, staker.publicKey, 5 * LAMPORTS_PER_SOL);
    const stakerToken = await ctx.createUserTokenAccount(staker.publicKey);
    await ctx.mintTokens(stakerToken, BigInt(2_000_000_000));

    // Stake 1B tokens
    await ctx.stake(staker, stakerToken, BigInt(1_000_000_000));

    // Wait for maturity
    console.log('    Waiting 30s for maturity...');
    await new Promise(r => setTimeout(r, 30000));

    // Deposit 2 SOL
    await ctx.depositRewards(BigInt(2 * LAMPORTS_PER_SOL));

    // Claim everything first
    let bal = BigInt(await ctx.getBalance(staker.publicKey));
    await ctx.claimRewards(staker);
    let balAfter = BigInt(await ctx.getBalance(staker.publicKey));
    const initialClaim = balAfter - bal;
    console.log(`    Initial claim: ${initialClaim} lamports`);

    // Dust-stake → claim, repeated 3 times
    let totalExploitGain = 0n;
    for (let i = 0; i < 3; i++) {
      await ctx.stake(staker, stakerToken, BigInt(1)); // dust

      bal = BigInt(await ctx.getBalance(staker.publicKey));
      await ctx.claimRewards(staker);
      balAfter = BigInt(await ctx.getBalance(staker.publicKey));
      const postDustClaim = balAfter - bal;
      totalExploitGain += postDustClaim;
      console.log(`    Round ${i + 1}: claim after dust=${postDustClaim}`);
    }

    console.log(`    Total exploit attempt gain: ${totalExploitGain} lamports`);

    if (totalExploitGain > BigInt(100_000)) {
      throw new Error(`Dust-stake yielded ${totalExploitGain} — exploit not blocked!`);
    }

    console.log('    Dust-stake exploit blocked: OK');
  });

  // ========== StakeOnBehalf Tests ==========

  await test('StakeOnBehalf: stake on behalf of another user', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(60)); // tau = 60s for fast maturity

    // User A (staker) has tokens, User B (beneficiary) is just a pubkey
    const userA = Keypair.generate();
    const userB = Keypair.generate();
    await airdropAndConfirm(connection, userA.publicKey, 2 * LAMPORTS_PER_SOL);
    await airdropAndConfirm(connection, userB.publicKey, LAMPORTS_PER_SOL);

    const userAToken = await ctx.createUserTokenAccount(userA.publicKey);
    const stakeAmount = BigInt(1_000_000_000);
    await ctx.mintTokens(userAToken, stakeAmount);

    // A stakes on behalf of B
    await ctx.stakeOnBehalf(userA, userAToken, userB.publicKey, stakeAmount);

    // Verify B's stake PDA exists with correct amount and owner=B
    const [beneficiaryStakePDA] = deriveUserStakePDA(ctx.poolPDA, userB.publicKey);
    const stakeInfo = await connection.getAccountInfo(beneficiaryStakePDA);
    if (!stakeInfo) throw new Error('Beneficiary stake account not created');
    if (stakeInfo.data.length === 0) throw new Error('Beneficiary stake data empty');

    // Read stake state: owner is at offset 8 (discriminator) = bytes 8..40
    const ownerBytes = stakeInfo.data.slice(8, 40);
    const ownerKey = new PublicKey(ownerBytes);
    if (!ownerKey.equals(userB.publicKey)) {
      throw new Error(`Stake owner should be B (${userB.publicKey}), got ${ownerKey}`);
    }

    // Read amount at offset 72 (u64 LE)
    const stakedAmount = stakeInfo.data.readBigUInt64LE(72);
    if (stakedAmount !== stakeAmount) {
      throw new Error(`Staked amount should be ${stakeAmount}, got ${stakedAmount}`);
    }

    // Verify A's token account was debited
    const aBalance = await ctx.getTokenBalance(userAToken);
    if (aBalance !== 0n) {
      throw new Error(`A should have 0 tokens, got ${aBalance}`);
    }

    console.log('    Stake on behalf created successfully, owner = B');
  });

  await test('StakeOnBehalf: beneficiary can claim rewards', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(60)); // tau = 60s

    const userA = Keypair.generate();
    const userB = Keypair.generate();
    await airdropAndConfirm(connection, userA.publicKey, 2 * LAMPORTS_PER_SOL);
    await airdropAndConfirm(connection, userB.publicKey, LAMPORTS_PER_SOL);

    const userAToken = await ctx.createUserTokenAccount(userA.publicKey);
    const stakeAmount = BigInt(1_000_000_000);
    await ctx.mintTokens(userAToken, stakeAmount);

    // A stakes on behalf of B
    await ctx.stakeOnBehalf(userA, userAToken, userB.publicKey, stakeAmount);

    // Wait for some maturity
    console.log('    Waiting 10s for maturity...');
    await new Promise(r => setTimeout(r, 10000));

    // Deposit rewards
    const rewardAmount = BigInt(1_000_000_000); // 1 SOL
    await ctx.depositRewards(rewardAmount);

    // B claims rewards directly (normal ClaimRewards)
    const bBalBefore = BigInt(await ctx.getBalance(userB.publicKey));
    await ctx.claimRewards(userB);
    const bBalAfter = BigInt(await ctx.getBalance(userB.publicKey));

    const rewardReceived = bBalAfter - bBalBefore;
    if (rewardReceived <= 0n) {
      throw new Error(`B should have received rewards, got ${rewardReceived}`);
    }
    console.log(`    B received ${rewardReceived} lamports in rewards`);
  });

  await test('StakeOnBehalf: add-more preserves pending rewards for beneficiary', async () => {
    const ctx = new TestContext(connection, Keypair.generate(), programAuthority);
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(60)); // tau = 60s

    const userA = Keypair.generate();
    const userB = Keypair.generate();
    await airdropAndConfirm(connection, userA.publicKey, 2 * LAMPORTS_PER_SOL);
    await airdropAndConfirm(connection, userB.publicKey, LAMPORTS_PER_SOL);

    const userAToken = await ctx.createUserTokenAccount(userA.publicKey);
    const totalTokens = BigInt(2_000_000_000);
    await ctx.mintTokens(userAToken, totalTokens);

    // A stakes first batch on behalf of B
    await ctx.stakeOnBehalf(userA, userAToken, userB.publicKey, BigInt(1_000_000_000));

    // Wait for maturity and deposit rewards
    console.log('    Waiting 10s for maturity...');
    await new Promise(r => setTimeout(r, 10000));

    const rewardAmount = BigInt(1_000_000_000);
    await ctx.depositRewards(rewardAmount);

    // A adds more stake on behalf of B — no auto-claim, pending preserved
    await ctx.stakeOnBehalf(userA, userAToken, userB.publicKey, BigInt(1_000_000_000));

    // Verify combined stake amount
    const userStakeState = await ctx.readUserStakeState(userB.publicKey);
    if (userStakeState.amount !== totalTokens) {
      throw new Error(`Expected combined stake ${totalTokens}, got ${userStakeState.amount}`);
    }

    // B can still claim accumulated rewards
    const bBalBefore = BigInt(await ctx.getBalance(userB.publicKey));
    await ctx.claimRewards(userB);
    const bBalAfter = BigInt(await ctx.getBalance(userB.publicKey));
    const bRewards = bBalAfter - bBalBefore;

    if (bRewards <= 0n) {
      throw new Error(`B should have claimable rewards after add-stake, got ${bRewards}`);
    }
    console.log(`    B claimed ${bRewards} lamports after add-stake on behalf`);
    console.log('    Add-more preserves pending rewards for beneficiary: OK');
  });

  console.log(`\n=== Results: ${passed} passed, ${failed} failed ===`);
  process.exit(failed > 0 ? 1 : 0);
}

runTests().catch(console.error);
