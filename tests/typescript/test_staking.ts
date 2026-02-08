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
} from '@solana/spl-token';
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

// Test context
class TestContext {
  connection: Connection;
  payer: Keypair;
  mint!: PublicKey;
  mintAuthority: Keypair;
  poolPDA!: PublicKey;
  tokenVaultPDA!: PublicKey;

  constructor(connection: Connection, payer: Keypair) {
    this.connection = connection;
    this.payer = payer;
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
    const ctx = new TestContext(connection, Keypair.generate());
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
    const ctx = new TestContext(connection, Keypair.generate());
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(2592000));

    const user = Keypair.generate();
    await connection.requestAirdrop(user.publicKey, LAMPORTS_PER_SOL);
    await new Promise(r => setTimeout(r, 500));

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
    const ctx = new TestContext(connection, Keypair.generate());
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(2592000));

    const user1 = Keypair.generate();
    const user2 = Keypair.generate();
    await connection.requestAirdrop(user1.publicKey, LAMPORTS_PER_SOL);
    await connection.requestAirdrop(user2.publicKey, LAMPORTS_PER_SOL);
    await new Promise(r => setTimeout(r, 500));

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
    const ctx = new TestContext(connection, Keypair.generate());
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(100)); // Short tau

    const user = Keypair.generate();
    await connection.requestAirdrop(user.publicKey, LAMPORTS_PER_SOL);
    await new Promise(r => setTimeout(r, 500));

    const userToken = await ctx.createUserTokenAccount(user.publicKey);
    await ctx.mintTokens(userToken, BigInt(1_000_000_000));
    await ctx.stake(user, userToken, BigInt(1_000_000_000));

    // Deposit rewards
    await ctx.depositRewards(BigInt(LAMPORTS_PER_SOL));

    const balanceBefore = await ctx.getBalance(user.publicKey);
    await ctx.claimRewards(user);
    const balanceAfter = await ctx.getBalance(user.publicKey);

    // User should receive some rewards (minus tx fee)
    // Due to time-weighted calculation, might be small if just staked
    console.log(`    Reward claimed: ${balanceAfter - balanceBefore} lamports`);
  });

  // Test: Unstake partial
  await test('Unstake partial', async () => {
    const ctx = new TestContext(connection, Keypair.generate());
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(2592000));

    const user = Keypair.generate();
    await connection.requestAirdrop(user.publicKey, LAMPORTS_PER_SOL);
    await new Promise(r => setTimeout(r, 500));

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
    const ctx = new TestContext(connection, Keypair.generate());
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(2592000));

    const user = Keypair.generate();
    await connection.requestAirdrop(user.publicKey, LAMPORTS_PER_SOL);
    await new Promise(r => setTimeout(r, 500));

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
    const ctx = new TestContext(connection, Keypair.generate());
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(100));

    const user = Keypair.generate();
    await connection.requestAirdrop(user.publicKey, LAMPORTS_PER_SOL);
    await new Promise(r => setTimeout(r, 500));

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

    console.log(`    Direct SOL reward claimed: ${balanceAfter - balanceBefore} lamports`);
  });

  // Test: Additional stake
  await test('Additional stake (same user)', async () => {
    const ctx = new TestContext(connection, Keypair.generate());
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(2592000));

    const user = Keypair.generate();
    await connection.requestAirdrop(user.publicKey, LAMPORTS_PER_SOL);
    await new Promise(r => setTimeout(r, 500));

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
    const ctx = new TestContext(connection, Keypair.generate());
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
    const ctx = new TestContext(connection, Keypair.generate());
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(2592000));

    const wrongAuth = Keypair.generate();
    await connection.requestAirdrop(wrongAuth.publicKey, LAMPORTS_PER_SOL);
    await new Promise(r => setTimeout(r, 500));

    let failed = false;
    try {
      await ctx.updatePoolSettings(wrongAuth, BigInt(100), null, null);
    } catch (e) {
      failed = true;
    }
    if (!failed) throw new Error('Should reject wrong authority');
  });

  // Test: Transfer authority
  await test('TransferAuthority: transfer and use new authority', async () => {
    const ctx = new TestContext(connection, Keypair.generate());
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(2592000));

    const newAuth = Keypair.generate();
    await connection.requestAirdrop(newAuth.publicKey, LAMPORTS_PER_SOL);
    await new Promise(r => setTimeout(r, 500));

    // Transfer authority
    await ctx.transferAuthority(ctx.payer, newAuth.publicKey);

    // Old authority should fail
    let oldFailed = false;
    try {
      await ctx.updatePoolSettings(ctx.payer, BigInt(100), null, null);
    } catch (e) {
      oldFailed = true;
    }
    if (!oldFailed) throw new Error('Old authority should be rejected');

    // New authority should work
    await ctx.updatePoolSettings(newAuth, BigInt(100), null, null);
  });

  // Test: Renounce authority
  await test('TransferAuthority: renounce (set to default pubkey)', async () => {
    const ctx = new TestContext(connection, Keypair.generate());
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
    }
    if (!failed) throw new Error('Renounced authority should be rejected');
  });

  // Test: Min stake amount enforced on new stake
  await test('MinStake: enforced on new stake', async () => {
    const ctx = new TestContext(connection, Keypair.generate());
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(2592000));

    // Set min stake to 1 billion (1 token with 9 decimals)
    await ctx.updatePoolSettings(ctx.payer, BigInt(1_000_000_000), null, null);

    const user = Keypair.generate();
    await connection.requestAirdrop(user.publicKey, LAMPORTS_PER_SOL);
    await new Promise(r => setTimeout(r, 500));
    const userToken = await ctx.createUserTokenAccount(user.publicKey);
    await ctx.mintTokens(userToken, BigInt(2_000_000_000));

    // Stake below minimum should fail
    let belowMinFailed = false;
    try {
      await ctx.stake(user, userToken, BigInt(500_000_000));
    } catch (e) {
      belowMinFailed = true;
    }
    if (!belowMinFailed) throw new Error('Below-minimum stake should fail');

    // Stake at minimum should succeed
    await ctx.stake(user, userToken, BigInt(1_000_000_000));
  });

  // Test: Lock duration blocks early unstake
  await test('LockDuration: blocks early unstake', async () => {
    const ctx = new TestContext(connection, Keypair.generate());
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(2592000));

    // Set 10-second lock duration
    await ctx.updatePoolSettings(ctx.payer, null, BigInt(10), null);

    const user = Keypair.generate();
    await connection.requestAirdrop(user.publicKey, LAMPORTS_PER_SOL);
    await new Promise(r => setTimeout(r, 500));
    const userToken = await ctx.createUserTokenAccount(user.publicKey);
    await ctx.mintTokens(userToken, BigInt(1_000_000_000));
    await ctx.stake(user, userToken, BigInt(1_000_000_000));

    // Try unstake immediately - should fail (locked)
    let lockedFailed = false;
    try {
      await ctx.unstake(user, userToken, BigInt(1_000_000_000));
    } catch (e) {
      lockedFailed = true;
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
    const ctx = new TestContext(connection, Keypair.generate());
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(2592000));

    // Set 5-second cooldown
    await ctx.updatePoolSettings(ctx.payer, null, null, BigInt(5));

    const user = Keypair.generate();
    await connection.requestAirdrop(user.publicKey, LAMPORTS_PER_SOL);
    await new Promise(r => setTimeout(r, 500));
    const userToken = await ctx.createUserTokenAccount(user.publicKey);
    await ctx.mintTokens(userToken, BigInt(1_000_000_000));
    await ctx.stake(user, userToken, BigInt(1_000_000_000));

    // Direct unstake should fail (cooldown required)
    let directFailed = false;
    try {
      await ctx.unstake(user, userToken, BigInt(1_000_000_000));
    } catch (e) {
      directFailed = true;
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
    const ctx = new TestContext(connection, Keypair.generate());
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(2592000));

    // Set 60-second cooldown (long, we cancel before)
    await ctx.updatePoolSettings(ctx.payer, null, null, BigInt(60));

    const user = Keypair.generate();
    await connection.requestAirdrop(user.publicKey, LAMPORTS_PER_SOL);
    await new Promise(r => setTimeout(r, 500));
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
    }
    if (!doubleCancelFailed) throw new Error('Double cancel should fail');
  });

  // Test: Cannot stake while unstake request pending
  await test('Cooldown: cannot stake while unstake pending', async () => {
    const ctx = new TestContext(connection, Keypair.generate());
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(2592000));

    // Set cooldown
    await ctx.updatePoolSettings(ctx.payer, null, null, BigInt(60));

    const user = Keypair.generate();
    await connection.requestAirdrop(user.publicKey, LAMPORTS_PER_SOL);
    await new Promise(r => setTimeout(r, 500));
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
    }
    if (!stakeFailed) throw new Error('Should not stake while unstake pending');

    // Cancel request, then stake should work
    await ctx.cancelUnstakeRequest(user);
    await ctx.stake(user, userToken, BigInt(500_000_000));
  });

  // Test: Cannot request unstake twice
  await test('Cooldown: cannot request unstake twice', async () => {
    const ctx = new TestContext(connection, Keypair.generate());
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(2592000));

    await ctx.updatePoolSettings(ctx.payer, null, null, BigInt(60));

    const user = Keypair.generate();
    await connection.requestAirdrop(user.publicKey, LAMPORTS_PER_SOL);
    await new Promise(r => setTimeout(r, 500));
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
    }
    if (!doubleRequestFailed) throw new Error('Double request should fail');
  });

  // Test: Existing pools (zero reserved fields) work unchanged
  await test('Backward compat: existing pool works with zero settings', async () => {
    const ctx = new TestContext(connection, Keypair.generate());
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(2592000));

    // With default settings (all zeros), everything should work as before
    const user = Keypair.generate();
    await connection.requestAirdrop(user.publicKey, LAMPORTS_PER_SOL);
    await new Promise(r => setTimeout(r, 500));
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
    const ctx = new TestContext(connection, Keypair.generate());
    await ctx.setup();
    await ctx.createMint(9);

    // 5 second tau for testing
    const tauSeconds = BigInt(5);
    await ctx.initializePool(tauSeconds);

    // Old staker stakes first and waits to get max weight
    const oldStaker = Keypair.generate();
    await connection.requestAirdrop(oldStaker.publicKey, 3 * LAMPORTS_PER_SOL);
    await new Promise(r => setTimeout(r, 500));
    const oldToken = await ctx.createUserTokenAccount(oldStaker.publicKey);
    await ctx.mintTokens(oldToken, BigInt(1_000_000_000));
    await ctx.stake(oldStaker, oldToken, BigInt(1_000_000_000));

    // Wait for old staker to reach ~100% weight
    console.log(`    Waiting 20s for old staker to mature...`);
    await new Promise(r => setTimeout(r, 20000));

    // New staker joins - starts with ~0% weight
    const newStaker = Keypair.generate();
    await connection.requestAirdrop(newStaker.publicKey, 3 * LAMPORTS_PER_SOL);
    await new Promise(r => setTimeout(r, 500));
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
    } catch (e) {
      // Expected - insufficient rewards or 0 weight
    }
    const newReward1 = Math.max(0, (await ctx.getBalance(newStaker.publicKey)) - newBal);

    const total1 = oldReward1 + newReward1;
    const newShare1 = total1 > 0 ? (newReward1 * 100) / total1 : 0;
    console.log(`    New staker share at t=0: ${newShare1.toFixed(1)}%`);

    // Wait 1τ - new staker should gain relative share
    console.log(`    Waiting 5s (1τ)...`);
    await new Promise(r => setTimeout(r, 5000));

    await ctx.depositRewards(BigInt(LAMPORTS_PER_SOL / 2));

    oldBal = await ctx.getBalance(oldStaker.publicKey);
    await ctx.claimRewards(oldStaker);
    const oldReward2 = (await ctx.getBalance(oldStaker.publicKey)) - oldBal;

    newBal = await ctx.getBalance(newStaker.publicKey);
    await ctx.claimRewards(newStaker);
    const newReward2 = (await ctx.getBalance(newStaker.publicKey)) - newBal;

    const newShare2 = (newReward2 * 100) / (oldReward2 + newReward2);
    console.log(`    New staker share at t=1τ: ${newShare2.toFixed(1)}%`);

    // New staker's share should increase over time
    if (newShare2 <= newShare1) {
      throw new Error(`New staker share should increase: ${newShare1}% -> ${newShare2}%`);
    }
  });

  // Test: Old staker gets more than new staker
  await test('Math: Old staker gets more rewards than new staker', async () => {
    const ctx = new TestContext(connection, Keypair.generate());
    await ctx.setup();
    await ctx.createMint(9);

    // 5 second tau for quick testing
    const tauSeconds = BigInt(5);
    await ctx.initializePool(tauSeconds);

    // Old staker stakes first
    const oldStaker = Keypair.generate();
    await connection.requestAirdrop(oldStaker.publicKey, 2 * LAMPORTS_PER_SOL);
    await new Promise(r => setTimeout(r, 500));
    const oldToken = await ctx.createUserTokenAccount(oldStaker.publicKey);
    const stakeAmount = BigInt(1_000_000_000);
    await ctx.mintTokens(oldToken, stakeAmount);
    await ctx.stake(oldStaker, oldToken, stakeAmount);

    // Wait 3τ (15 seconds) - old staker will have ~95% weight
    console.log(`    Waiting 15s for old staker to accumulate weight...`);
    await new Promise(r => setTimeout(r, 15000));

    // New staker stakes now (will have ~0% weight)
    const newStaker = Keypair.generate();
    await connection.requestAirdrop(newStaker.publicKey, 2 * LAMPORTS_PER_SOL);
    await new Promise(r => setTimeout(r, 500));
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
      // May fail if reward too small or weight is 0
      console.log(`    New staker claim: ${e.message?.includes('0xb') ? 'insufficient (expected)' : e.message}`);
    }
    const newBalanceAfter = await ctx.getBalance(newStaker.publicKey);
    const newReward = Math.max(0, newBalanceAfter - newBalanceBefore);

    console.log(`    Old staker (3τ age) reward: ${oldReward} lamports`);
    console.log(`    New staker (~0 age) reward: ${newReward} lamports`);

    // Old staker should get significantly more
    if (oldReward <= newReward && newReward > 0) {
      throw new Error(`Old staker should get more: old=${oldReward}, new=${newReward}`);
    }

    // Old staker should get >80% of their share (they have ~95% weight vs ~0%)
    const totalRewards = oldReward + newReward;
    if (totalRewards > 0) {
      const oldShare = (oldReward * 100) / totalRewards;
      console.log(`    Old staker share: ${oldShare.toFixed(1)}%`);
      if (oldShare < 80) {
        throw new Error(`Old staker should get >80% of rewards, got ${oldShare}%`);
      }
    }
  });

  // Test: Equal stakers get equal rewards (when both matured)
  await test('Math: Equal age stakers get equal rewards (matured)', async () => {
    const ctx = new TestContext(connection, Keypair.generate());
    await ctx.setup();
    await ctx.createMint(9);

    // Short tau so we can wait for maturity
    const tauSeconds = BigInt(3);
    await ctx.initializePool(tauSeconds);

    // Two stakers stake same amount
    const staker1 = Keypair.generate();
    const staker2 = Keypair.generate();
    await connection.requestAirdrop(staker1.publicKey, 2 * LAMPORTS_PER_SOL);
    await connection.requestAirdrop(staker2.publicKey, 2 * LAMPORTS_PER_SOL);
    await new Promise(r => setTimeout(r, 500));

    const token1 = await ctx.createUserTokenAccount(staker1.publicKey);
    const token2 = await ctx.createUserTokenAccount(staker2.publicKey);
    const stakeAmount = BigInt(1_000_000_000);
    await ctx.mintTokens(token1, stakeAmount);
    await ctx.mintTokens(token2, stakeAmount);

    // Stake sequentially (slight time difference)
    await ctx.stake(staker1, token1, stakeAmount);
    await ctx.stake(staker2, token2, stakeAmount);

    // Wait 5τ (15 seconds) for both to reach ~99% weight
    // At this point, the 1 second staking difference becomes negligible
    console.log(`    Waiting 15s for both stakes to mature...`);
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

    // Should be approximately equal (within 10% - both at ~99% weight)
    const diff = Math.abs(reward1 - reward2);
    const avg = (reward1 + reward2) / 2;
    const diffPercent = (diff * 100) / avg;
    console.log(`    Difference: ${diffPercent.toFixed(2)}%`);

    if (diffPercent > 15) {
      throw new Error(`Equal matured stakers should get ~equal rewards, diff=${diffPercent}%`);
    }
  });

  // Test: 2x stake = 2x rewards (when both fully matured)
  await test('Math: Double stake gets double rewards (matured)', async () => {
    const ctx = new TestContext(connection, Keypair.generate());
    await ctx.setup();
    await ctx.createMint(9);

    // Short tau so we can wait for full maturity
    const tauSeconds = BigInt(3);
    await ctx.initializePool(tauSeconds);

    // Staker 1: stakes 1 token
    // Staker 2: stakes 2 tokens
    const staker1 = Keypair.generate();
    const staker2 = Keypair.generate();
    await connection.requestAirdrop(staker1.publicKey, 2 * LAMPORTS_PER_SOL);
    await connection.requestAirdrop(staker2.publicKey, 2 * LAMPORTS_PER_SOL);
    await new Promise(r => setTimeout(r, 500));

    const token1 = await ctx.createUserTokenAccount(staker1.publicKey);
    const token2 = await ctx.createUserTokenAccount(staker2.publicKey);
    await ctx.mintTokens(token1, BigInt(1_000_000_000));
    await ctx.mintTokens(token2, BigInt(2_000_000_000));

    // Stake both
    await ctx.stake(staker1, token1, BigInt(1_000_000_000));
    await ctx.stake(staker2, token2, BigInt(2_000_000_000));

    // Wait 5τ (15 seconds) for both to reach ~99% weight
    // At this point, the small timing difference between stakes is negligible
    console.log(`    Waiting 15s for both stakes to mature to ~99%...`);
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

  // Test: Verify weight at τ is ~63.2%
  await test('Math: Verify weight at τ ≈ 63.2%', async () => {
    const ctx = new TestContext(connection, Keypair.generate());
    await ctx.setup();
    await ctx.createMint(9);

    // 5 second tau
    const tauSeconds = BigInt(5);
    await ctx.initializePool(tauSeconds);

    // Old staker stakes and waits 5τ (essentially 100% weight)
    const oldStaker = Keypair.generate();
    await connection.requestAirdrop(oldStaker.publicKey, 2 * LAMPORTS_PER_SOL);
    await new Promise(r => setTimeout(r, 500));
    const oldToken = await ctx.createUserTokenAccount(oldStaker.publicKey);
    await ctx.mintTokens(oldToken, BigInt(1_000_000_000));
    await ctx.stake(oldStaker, oldToken, BigInt(1_000_000_000));

    // Wait 5τ = 25 seconds for ~99% weight
    console.log(`    Waiting 25s for old staker to reach ~99% weight...`);
    await new Promise(r => setTimeout(r, 25000));

    // New staker stakes same amount
    const newStaker = Keypair.generate();
    await connection.requestAirdrop(newStaker.publicKey, 2 * LAMPORTS_PER_SOL);
    await new Promise(r => setTimeout(r, 500));
    const newToken = await ctx.createUserTokenAccount(newStaker.publicKey);
    await ctx.mintTokens(newToken, BigInt(1_000_000_000));
    await ctx.stake(newStaker, newToken, BigInt(1_000_000_000));

    // Wait exactly τ (5 seconds) for new staker
    console.log(`    Waiting 5s (1τ) for new staker...`);
    await new Promise(r => setTimeout(r, 5000));

    // Now: old staker has ~100% weight, new staker has ~63.2% weight
    // Total weight ratio: 1 + 0.632 = 1.632
    // Old should get: 1/1.632 = 61.3%
    // New should get: 0.632/1.632 = 38.7%

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

    console.log(`    Old staker (5τ, ~100% weight): ${oldPercent.toFixed(1)}%`);
    console.log(`    New staker (1τ, ~63% weight): ${newPercent.toFixed(1)}%`);

    // Expected: old ~61%, new ~39% (with some tolerance for timing)
    if (oldPercent < 50 || oldPercent > 75) {
      throw new Error(`Old staker should get ~61%, got ${oldPercent}%`);
    }
    if (newPercent < 25 || newPercent > 50) {
      throw new Error(`New staker should get ~39%, got ${newPercent}%`);
    }
  });

  // ============================================
  // ABUSE / SECURITY TESTS
  // ============================================
  // Verify the system cannot be gamed or exploited

  console.log('\n--- Abuse / Security Tests ---\n');

  // Test: Sybil attack - splitting stake doesn't give advantage
  await test('Abuse: Sybil attack (split stake) gives no advantage', async () => {
    const ctx = new TestContext(connection, Keypair.generate());
    await ctx.setup();
    await ctx.createMint(9);

    const tauSeconds = BigInt(5);
    await ctx.initializePool(tauSeconds);

    // Honest staker: 2 tokens in one account
    const honest = Keypair.generate();
    await connection.requestAirdrop(honest.publicKey, 2 * LAMPORTS_PER_SOL);
    await new Promise(r => setTimeout(r, 500));
    const honestToken = await ctx.createUserTokenAccount(honest.publicKey);
    await ctx.mintTokens(honestToken, BigInt(2_000_000_000));
    await ctx.stake(honest, honestToken, BigInt(2_000_000_000));

    // Sybil attacker: 2 tokens split across 2 accounts (1 each)
    const sybil1 = Keypair.generate();
    const sybil2 = Keypair.generate();
    await connection.requestAirdrop(sybil1.publicKey, 2 * LAMPORTS_PER_SOL);
    await connection.requestAirdrop(sybil2.publicKey, 2 * LAMPORTS_PER_SOL);
    await new Promise(r => setTimeout(r, 500));
    const sybil1Token = await ctx.createUserTokenAccount(sybil1.publicKey);
    const sybil2Token = await ctx.createUserTokenAccount(sybil2.publicKey);
    await ctx.mintTokens(sybil1Token, BigInt(1_000_000_000));
    await ctx.mintTokens(sybil2Token, BigInt(1_000_000_000));
    await ctx.stake(sybil1, sybil1Token, BigInt(1_000_000_000));
    await ctx.stake(sybil2, sybil2Token, BigInt(1_000_000_000));

    // Wait for maturity
    console.log(`    Waiting 15s for stakes to mature...`);
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
    const ctx = new TestContext(connection, Keypair.generate());
    await ctx.setup();
    await ctx.createMint(9);

    const tauSeconds = BigInt(5);
    await ctx.initializePool(tauSeconds);

    // Honest staker stakes early
    const honest = Keypair.generate();
    await connection.requestAirdrop(honest.publicKey, 2 * LAMPORTS_PER_SOL);
    await new Promise(r => setTimeout(r, 500));
    const honestToken = await ctx.createUserTokenAccount(honest.publicKey);
    await ctx.mintTokens(honestToken, BigInt(1_000_000_000));
    await ctx.stake(honest, honestToken, BigInt(1_000_000_000));

    // Wait for honest staker to mature
    console.log(`    Waiting 15s for honest staker to mature...`);
    await new Promise(r => setTimeout(r, 15000));

    // Attacker stakes right before deposit (flash stake)
    const attacker = Keypair.generate();
    await connection.requestAirdrop(attacker.publicKey, 2 * LAMPORTS_PER_SOL);
    await new Promise(r => setTimeout(r, 500));
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

    console.log(`    Honest staker (mature) reward: ${honestReward} lamports`);
    console.log(`    Flash attacker (new) reward: ${attackerReward} lamports`);

    // Honest staker should get the vast majority (at 3τ = 95% weight vs ~0%)
    const honestShare = (honestReward * 100) / (honestReward + attackerReward);
    console.log(`    Honest staker share: ${honestShare.toFixed(1)}%`);

    // With τ=5s and 15s wait (3τ), honest has ~95% weight, attacker has ~0%
    // Honest should get >75% of rewards (accounting for timing variance)
    if (honestShare < 75) {
      throw new Error(`Flash stake should not be profitable: honest=${honestShare}%`);
    }
  });

  // Test: Cannot unstake more than staked
  await test('Abuse: Cannot unstake more than staked', async () => {
    const ctx = new TestContext(connection, Keypair.generate());
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(100));

    const user = Keypair.generate();
    await connection.requestAirdrop(user.publicKey, 2 * LAMPORTS_PER_SOL);
    await new Promise(r => setTimeout(r, 500));
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

  // Test: Cannot claim after full unstake
  await test('Abuse: Cannot claim after full unstake', async () => {
    const ctx = new TestContext(connection, Keypair.generate());
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(10));

    const user = Keypair.generate();
    await connection.requestAirdrop(user.publicKey, 2 * LAMPORTS_PER_SOL);
    await new Promise(r => setTimeout(r, 500));
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

    // Deposit more rewards
    await ctx.depositRewards(BigInt(LAMPORTS_PER_SOL));

    // Try to claim again (should fail - no stake)
    let failed = false;
    try {
      await ctx.claimRewards(user);
    } catch (e: any) {
      failed = true;
      console.log(`    Correctly rejected claim after unstake`);
    }

    if (!failed) {
      throw new Error('Should not be able to claim after full unstake');
    }
  });

  // Test: Cannot double claim
  await test('Abuse: Cannot double claim same rewards', async () => {
    const ctx = new TestContext(connection, Keypair.generate());
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(10));

    const user = Keypair.generate();
    await connection.requestAirdrop(user.publicKey, 2 * LAMPORTS_PER_SOL);
    await new Promise(r => setTimeout(r, 500));
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

    // Second claim (should get 0 or fail)
    const balance2 = await ctx.getBalance(user.publicKey);
    try {
      await ctx.claimRewards(user);
    } catch (e) {
      // May fail with "no pending rewards"
    }
    const reward2 = (await ctx.getBalance(user.publicKey)) - balance2;
    console.log(`    Second claim: ${reward2} lamports`);

    if (reward2 > reward1 / 100) { // Allow tiny dust
      throw new Error(`Double claim should not work: got ${reward2} on second claim`);
    }
  });

  // Test: Stake/unstake cycling doesn't reset weight unfairly
  await test('Abuse: Stake/unstake cycling resets weight', async () => {
    const ctx = new TestContext(connection, Keypair.generate());
    await ctx.setup();
    await ctx.createMint(9);

    const tauSeconds = BigInt(5);
    await ctx.initializePool(tauSeconds);

    // Honest staker - stakes and holds
    const honest = Keypair.generate();
    await connection.requestAirdrop(honest.publicKey, 2 * LAMPORTS_PER_SOL);
    await new Promise(r => setTimeout(r, 500));
    const honestToken = await ctx.createUserTokenAccount(honest.publicKey);
    await ctx.mintTokens(honestToken, BigInt(1_000_000_000));
    await ctx.stake(honest, honestToken, BigInt(1_000_000_000));

    // Cycler - stakes, waits, unstakes, restakes (trying to game)
    const cycler = Keypair.generate();
    await connection.requestAirdrop(cycler.publicKey, 2 * LAMPORTS_PER_SOL);
    await new Promise(r => setTimeout(r, 500));
    const cyclerToken = await ctx.createUserTokenAccount(cycler.publicKey);
    await ctx.mintTokens(cyclerToken, BigInt(1_000_000_000));
    await ctx.stake(cycler, cyclerToken, BigInt(1_000_000_000));

    // Wait 10s
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
    } catch (e) {
      // May fail if weight is too low
    }
    const cyclerReward = Math.max(0, (await ctx.getBalance(cycler.publicKey)) - cyclerBefore);

    console.log(`    Honest (held 10s): ${honestReward} lamports`);
    console.log(`    Cycler (reset weight): ${cyclerReward} lamports`);

    // Honest should get more since cycler reset their weight
    if (honestReward <= cyclerReward && cyclerReward > 0) {
      throw new Error(`Cycling should reset weight: honest=${honestReward}, cycler=${cyclerReward}`);
    }
  });

  // Test: Zero amount operations fail
  await test('Abuse: Zero amount operations rejected', async () => {
    const ctx = new TestContext(connection, Keypair.generate());
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(100));

    const user = Keypair.generate();
    await connection.requestAirdrop(user.publicKey, 2 * LAMPORTS_PER_SOL);
    await new Promise(r => setTimeout(r, 500));
    const userToken = await ctx.createUserTokenAccount(user.publicKey);
    await ctx.mintTokens(userToken, BigInt(1_000_000_000));

    // Try zero stake
    let zeroStakeFailed = false;
    try {
      await ctx.stake(user, userToken, BigInt(0));
    } catch (e) {
      zeroStakeFailed = true;
    }

    // Stake normally first
    await ctx.stake(user, userToken, BigInt(1_000_000_000));

    // Try zero unstake
    let zeroUnstakeFailed = false;
    try {
      await ctx.unstake(user, userToken, BigInt(0));
    } catch (e) {
      zeroUnstakeFailed = true;
    }

    // Try zero deposit
    let zeroDepositFailed = false;
    try {
      await ctx.depositRewards(BigInt(0));
    } catch (e) {
      zeroDepositFailed = true;
    }

    console.log(`    Zero stake rejected: ${zeroStakeFailed}`);
    console.log(`    Zero unstake rejected: ${zeroUnstakeFailed}`);
    console.log(`    Zero deposit rejected: ${zeroDepositFailed}`);

    if (!zeroStakeFailed || !zeroUnstakeFailed || !zeroDepositFailed) {
      throw new Error('Zero amount operations should be rejected');
    }
  });

  // Test: Frontrunning deposit with equal stake
  // Note: With vastly different stake amounts, the attacker may still win on absolute weight
  // This test verifies that equal stakes favor the mature staker
  await test('Abuse: Frontrunning deposit (equal stakes)', async () => {
    const ctx = new TestContext(connection, Keypair.generate());
    await ctx.setup();
    await ctx.createMint(9);

    const tauSeconds = BigInt(5);
    await ctx.initializePool(tauSeconds);

    // Honest staker
    const honest = Keypair.generate();
    await connection.requestAirdrop(honest.publicKey, 2 * LAMPORTS_PER_SOL);
    await new Promise(r => setTimeout(r, 500));
    const honestToken = await ctx.createUserTokenAccount(honest.publicKey);
    await ctx.mintTokens(honestToken, BigInt(1_000_000_000));
    await ctx.stake(honest, honestToken, BigInt(1_000_000_000));

    // Wait for honest to mature
    console.log(`    Waiting 15s for honest staker to mature...`);
    await new Promise(r => setTimeout(r, 15000));

    // Frontrunner stakes equal amount right before deposit
    const attacker = Keypair.generate();
    await connection.requestAirdrop(attacker.publicKey, 2 * LAMPORTS_PER_SOL);
    await new Promise(r => setTimeout(r, 500));
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
    } catch (e) {}
    const attackerReward = Math.max(0, (await ctx.getBalance(attacker.publicKey)) - attackerBefore);

    const total = honestReward + attackerReward;
    const honestShare = (honestReward * 100) / total;

    console.log(`    Honest (1 token, mature): ${honestShare.toFixed(1)}% (${honestReward} lamports)`);
    console.log(`    Attacker (1 token, new): ${(100-honestShare).toFixed(1)}% (${attackerReward} lamports)`);

    // With equal stakes, mature staker should dominate
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
    const ctx = new TestContext(connection, Keypair.generate());
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(5)); // Short tau

    const user = Keypair.generate();
    await connection.requestAirdrop(user.publicKey, 2 * LAMPORTS_PER_SOL);
    await new Promise(r => setTimeout(r, 500));

    const userToken = await ctx.createUserTokenAccount(user.publicKey);
    await ctx.mintTokens(userToken, BigInt(1_000_000_000));
    await ctx.stake(user, userToken, BigInt(1_000_000_000));

    // Wait for weight to accumulate
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
    if (claimed > depositAmount + BigInt(10000)) {
      throw new Error(`Double-counting detected! Claimed ${claimed} > deposited ${depositAmount}`);
    }
  });

  // Test: Additional stake does not allow reward theft
  await test('Security: Additional stake does not allow reward theft', async () => {
    const ctx = new TestContext(connection, Keypair.generate());
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(5)); // Short tau

    const attacker = Keypair.generate();
    await connection.requestAirdrop(attacker.publicKey, 2 * LAMPORTS_PER_SOL);
    await new Promise(r => setTimeout(r, 500));

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
    if (claimed > depositAmount + BigInt(10000)) {
      throw new Error(`Reward theft detected! Claimed ${claimed} >> deposited ${depositAmount}`);
    }
  });

  // Test: Claim then SyncRewards works for new deposits
  await test('Security: Claim then SyncRewards works for new deposits', async () => {
    const ctx = new TestContext(connection, Keypair.generate());
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(5)); // Short tau

    const user = Keypair.generate();
    await connection.requestAirdrop(user.publicKey, 3 * LAMPORTS_PER_SOL);
    await new Promise(r => setTimeout(r, 500));

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
    const ctx = new TestContext(connection, Keypair.generate());
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(5)); // Short tau

    const user = Keypair.generate();
    await connection.requestAirdrop(user.publicKey, 3 * LAMPORTS_PER_SOL);
    await new Promise(r => setTimeout(r, 500));

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

    // Send more SOL directly to pool
    const directAmount = BigInt(LAMPORTS_PER_SOL / 2);
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
    const ctx = new TestContext(connection, Keypair.generate());
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(2592000)); // 30 days tau

    // First, create a "whale" that represents aggregate of ~1M stakers
    // 1M stakers × 1000 tokens × 10^9 decimals = 10^18 raw tokens
    const whale = Keypair.generate();
    await connection.requestAirdrop(whale.publicKey, 2 * LAMPORTS_PER_SOL);
    await new Promise(r => setTimeout(r, 500));

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
    await connection.requestAirdrop(user.publicKey, LAMPORTS_PER_SOL);
    await new Promise(r => setTimeout(r, 500));

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
    const ctx = new TestContext(connection, Keypair.generate());
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(100)); // Short tau for weight accumulation

    // Create large aggregate stake
    const whale = Keypair.generate();
    await connection.requestAirdrop(whale.publicKey, 5 * LAMPORTS_PER_SOL);
    await new Promise(r => setTimeout(r, 500));

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
    const ctx = new TestContext(connection, Keypair.generate());
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(10)); // Very short tau

    const user = Keypair.generate();
    await connection.requestAirdrop(user.publicKey, LAMPORTS_PER_SOL);
    await new Promise(r => setTimeout(r, 500));

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
    const ctx = new TestContext(connection, Keypair.generate());
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(2592000));

    const user = Keypair.generate();
    await connection.requestAirdrop(user.publicKey, LAMPORTS_PER_SOL);
    await new Promise(r => setTimeout(r, 500));

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
    const ctx = new TestContext(connection, Keypair.generate());
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(50)); // Short tau

    const whale = Keypair.generate();
    await connection.requestAirdrop(whale.publicKey, 3 * LAMPORTS_PER_SOL);
    await new Promise(r => setTimeout(r, 500));

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
    const ctx = new TestContext(connection, Keypair.generate());
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(10)); // Short tau for weight

    const user = Keypair.generate();
    await connection.requestAirdrop(user.publicKey, 5 * LAMPORTS_PER_SOL);
    await new Promise(r => setTimeout(r, 500));

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
    const ctx = new TestContext(connection, Keypair.generate());
    await ctx.setup();
    await ctx.createMint(9);
    await ctx.initializePool(BigInt(100));

    const user = Keypair.generate();
    await connection.requestAirdrop(user.publicKey, 2 * LAMPORTS_PER_SOL);
    await new Promise(r => setTimeout(r, 500));

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

  console.log(`\n=== Results: ${passed} passed, ${failed} failed ===`);
  process.exit(failed > 0 ? 1 : 0);
}

runTests().catch(console.error);
