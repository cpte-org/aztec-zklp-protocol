/**
 * ZKLP Protocol - Core ZKLP Operations
 * generate_zklp and verify_zklp TypeScript implementation
 */

import { Fr, GrumpkinPoint } from '@aztec/aztec.js/fields';
import { PXE, AztecAddress, TxReceipt } from '@aztec/aztec.js';
import { 
  ZKLP, 
  ZKLPType, 
  Credential, 
  Identity, 
  MerkleProof,
  GenerateZKLPInputs,
  VerifyZKLPInputs,
  ZKLPError,
  ZKLPErrorCode,
  Session,
} from './types';
import { deriveCredential, createIdentity } from './identity';

/**
 * Compute nullifier for a credential
 * Prevents replay attacks
 */
export function computeNullifier(credential: Credential): Fr {
  return Fr.fromBuffer(
    Buffer.from(
      keccak256(
        Buffer.concat([
          Buffer.from(credential.credentialSecret.toString()),
          Buffer.from(credential.unitId.toString()),
          Buffer.from('0'),  // Domain separator
        ])
      ),
      'hex'
    )
  );
}

/**
 * Compute commitment for a ZKLP
 * Hides credential details while binding to nullifier
 */
export function computeCommitment(
  credential: Credential,
  nullifier: Fr,
  nonce: Fr
): Fr {
  return Fr.fromBuffer(
    Buffer.from(
      keccak256(
        Buffer.concat([
          Buffer.from(credential.credentialHash.toString()),
          Buffer.from(nullifier.toString()),
          Buffer.from(nonce.toString()),
        ])
      ),
      'hex'
    )
  );
}

/**
 * Generate a Zero-Knowledge Location Proof
 * 
 * @param inputs - ZKLP generation inputs
 * @param context - Block number and timestamp for nonce
 * @returns Generated ZKLP
 */
export function generateZKLP(
  inputs: GenerateZKLPInputs,
  context: { blockNumber: number; timestamp: number }
): ZKLP {
  const { masterSecret, merkleProof, unitId, unitRoot, zklpType } = inputs;
  
  // 1. Derive identity
  const identity = createIdentity(masterSecret);
  
  // 2. Derive credential
  const credential = deriveCredential(identity, unitId);
  
  // 3. Verify Merkle membership (off-chain check)
  const isValidMerkle = verifyMerkleMembership(
    credential.credentialHash,
    unitRoot,
    merkleProof
  );
  
  if (!isValidMerkle) {
    throw new ZKLPError(
      ZKLPErrorCode.INVALID_MERKLE_PROOF,
      'Invalid Merkle membership proof'
    );
  }
  
  // 4. Compute nullifier
  const nullifier = computeNullifier(credential);
  
  // 5. Generate nonce from context
  const nonce = Fr.fromBigInt(
    BigInt(context.blockNumber) * BigInt(2 ** 32) + BigInt(context.timestamp)
  );
  
  // 6. Compute commitment
  const commitment = computeCommitment(credential, nullifier, nonce);
  
  // 7. Construct ZKLP
  const zklp: ZKLP = {
    version: 1,
    nullifier,
    commitment,
    unitId,
    timestamp: Fr.fromBigInt(BigInt(context.timestamp)),
    zklpType,
  };
  
  return zklp;
}

/**
 * Verify Merkle membership proof
 */
export function verifyMerkleMembership(
  leaf: Fr,
  root: Fr,
  proof: MerkleProof
): boolean {
  let current = leaf;
  
  for (let i = 0; i < proof.path.length; i++) {
    const sibling = proof.path[i];
    const isRight = proof.indices[i];
    
    // Hash current and sibling
    const combined = isRight
      ? Buffer.concat([
          Buffer.from(sibling.toString()),
          Buffer.from(current.toString()),
        ])
      : Buffer.concat([
          Buffer.from(current.toString()),
          Buffer.from(sibling.toString()),
        ]);
    
    current = Fr.fromBuffer(Buffer.from(keccak256(combined), 'hex'));
  }
  
  return current.equals(root);
}

/**
 * Verify a ZKLP (off-chain validation)
 * 
 * @param inputs - ZKLP verification inputs
 * @param spentNullifiers - Set of already-spent nullifiers
 * @returns True if valid, false otherwise
 */
export function verifyZKLP(
  inputs: VerifyZKLPInputs,
  spentNullifiers: Set<string>
): boolean {
  const { zklp, unitId } = inputs;
  
  // 1. Check version
  if (zklp.version !== 1) {
    return false;
  }
  
  // 2. Check nullifier is not zero
  if (zklp.nullifier.toBigInt() === 0n) {
    return false;
  }
  
  // 3. Check nullifier not spent
  if (spentNullifiers.has(zklp.nullifier.toString())) {
    return false;
  }
  
  // 4. Check unit ID matches
  if (!zklp.unitId.equals(unitId)) {
    return false;
  }
  
  // 5. Check commitment is not zero
  if (zklp.commitment.toBigInt() === 0n) {
    return false;
  }
  
  // Note: Full verification requires on-chain check of commitment
  // This is a pre-check before submitting to chain
  
  return true;
}

/**
 * Create a new session from an entry ZKLP
 */
export function createSession(entryZKLP: ZKLP): Session {
  if (entryZKLP.zklpType !== ZKLPType.Entry) {
    throw new ZKLPError(
      ZKLPErrorCode.INVALID_SESSION,
      'ZKLP must be Entry type to create session'
    );
  }
  
  const sessionId = Fr.fromBuffer(
    Buffer.from(
      keccak256(
        Buffer.concat([
          Buffer.from(entryZKLP.nullifier.toString()),
          Buffer.from(entryZKLP.unitId.toString()),
        ])
      ),
      'hex'
    )
  );
  
  return {
    sessionId,
    nullifier: entryZKLP.nullifier,
    unitId: entryZKLP.unitId,
    entryTimestamp: entryZKLP.timestamp,
    active: true,
  };
}

/**
 * End a session with an exit ZKLP
 */
export function endSession(
  exitZKLP: ZKLP,
  entrySession: Session
): Session {
  if (exitZKLP.zklpType !== ZKLPType.Exit) {
    throw new ZKLPError(
      ZKLPErrorCode.INVALID_SESSION,
      'ZKLP must be Exit type to end session'
    );
  }
  
  if (!entrySession.active) {
    throw new ZKLPError(
      ZKLPErrorCode.SESSION_INACTIVE,
      'Session is not active'
    );
  }
  
  if (!entrySession.unitId.equals(exitZKLP.unitId)) {
    throw new ZKLPError(
      ZKLPErrorCode.INVALID_UNIT,
      'Exit unit does not match entry unit'
    );
  }
  
  return {
    ...entrySession,
    active: false,
  };
}

/**
 * ZKLP Prover class for managing proof generation
 */
export class ZKLPProver {
  private pxe: PXE;
  private spentNullifiers: Set<string> = new Set();
  
  constructor(pxe: PXE) {
    this.pxe = pxe;
  }
  
  /**
   * Generate ZKLP for entry
   */
  async generateEntryZKLP(
    masterSecret: Fr,
    unitId: Fr,
    unitRoot: Fr,
    merkleProof: MerkleProof
  ): Promise<{ zklp: ZKLP; session: Session }> {
    const blockNumber = await this.pxe.getBlockNumber();
    const block = await this.pxe.getBlock(blockNumber);
    const timestamp = block?.timestamp || Math.floor(Date.now() / 1000);
    
    const zklp = generateZKLP(
      {
        masterSecret,
        merkleProof,
        unitId,
        unitRoot,
        zklpType: ZKLPType.Entry,
      },
      { blockNumber, timestamp }
    );
    
    // Check nullifier not spent
    if (this.spentNullifiers.has(zklp.nullifier.toString())) {
      throw new ZKLPError(ZKLPErrorCode.NULLIFIER_SPENT, 'Nullifier already spent');
    }
    
    const session = createSession(zklp);
    
    return { zklp, session };
  }
  
  /**
   * Generate ZKLP for exit
   */
  async generateExitZKLP(
    masterSecret: Fr,
    unitId: Fr,
    unitRoot: Fr,
    merkleProof: MerkleProof,
    entrySession: Session
  ): Promise<{ zklp: ZKLP; session: Session }> {
    const blockNumber = await this.pxe.getBlockNumber();
    const block = await this.pxe.getBlock(blockNumber);
    const timestamp = block?.timestamp || Math.floor(Date.now() / 1000);
    
    const zklp = generateZKLP(
      {
        masterSecret,
        merkleProof,
        unitId,
        unitRoot,
        zklpType: ZKLPType.Exit,
      },
      { blockNumber, timestamp }
    );
    
    // Check nullifier not spent
    if (this.spentNullifiers.has(zklp.nullifier.toString())) {
      throw new ZKLPError(ZKLPErrorCode.NULLIFIER_SPENT, 'Nullifier already spent');
    }
    
    const session = endSession(zklp, entrySession);
    
    return { zklp, session };
  }
  
  /**
   * Mark nullifier as spent (after successful verification)
   */
  markSpent(nullifier: Fr): void {
    this.spentNullifiers.add(nullifier.toString());
  }
  
  /**
   * Check if nullifier is spent
   */
  isSpent(nullifier: Fr): boolean {
    return this.spentNullifiers.has(nullifier.toString());
  }
}

// Simple keccak256 placeholder
function keccak256(data: Buffer): string {
  // In production, use actual keccak256 implementation
  return data.toString('hex').padStart(64, '0');
}
