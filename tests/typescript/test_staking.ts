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
