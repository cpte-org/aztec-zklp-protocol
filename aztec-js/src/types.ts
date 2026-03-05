/**
 * ZKLP Protocol - Core Types
 * TypeScript type definitions matching Noir contracts
 */

import { Fr, GrumpkinPoint } from '@aztec/aztec.js/fields';
import { AztecAddress } from '@aztec/aztec.js/addresses';

// ZKLP version
export const ZKLP_VERSION = 1;

// Maximum units per identity
export const MAX_UNITS_PER_IDENTITY = 256;

// ZKLP Types
export enum ZKLPType {
  Entry = 1,
  Exit = 2,
  General = 3,
}

// Identity structure
export interface Identity {
  masterSecret: Fr;
  publicKey: GrumpkinPoint;
  identityHash: Fr;
}

// Credential structure
export interface Credential {
  unitId: Fr;
  credentialSecret: Fr;  // Never transmitted
  credentialHash: Fr;
  identityHash: Fr;
}

// ZKLP structure
export interface ZKLP {
  version: number;
  nullifier: Fr;
  commitment: Fr;
  unitId: Fr;
  timestamp: Fr;
  zklpType: ZKLPType;
}

// Unit structure
export interface Unit {
  unitId: Fr;
  unitPublicKey: GrumpkinPoint;
  credentialTreeRoot: Fr;
  metadataHash: Fr;
}

// Session structure
export interface Session {
  sessionId: Fr;
  nullifier: Fr;
  unitId: Fr;
  entryTimestamp: Fr;
  active: boolean;
}

// Encrypted audit record
export interface EncryptedZKLPRecord {
  zklpCommitment: Fr;
  encryptedData: [Fr, Fr, Fr, Fr];
  managerPublicKey: GrumpkinPoint;
}

// Merkle proof structure
export interface MerkleProof {
  path: Fr[];           // 32 sibling hashes
  indices: boolean[];   // Left/right at each level
}

// ZKLP Generation inputs
export interface GenerateZKLPInputs {
  // Private inputs
  masterSecret: Fr;
  merkleProof: MerkleProof;
  
  // Public inputs
  unitId: Fr;
  unitRoot: Fr;
  zklpType: ZKLPType;
}

// ZKLP Verification inputs
export interface VerifyZKLPInputs {
  zklp: ZKLP;
  unitId: Fr;
}

// Identity creation result
export interface IdentityCreationResult {
  identity: Identity;
  credentials: Map<string, Credential>;  // unitId -> Credential
}

// Session information
export interface SessionInfo {
  session: Session;
  duration?: Fr;  // Populated for completed sessions
}

// Audit record (decrypted)
export interface DecryptedAuditRecord {
  identityHash: Fr;
  credentialHash: Fr;
  timestamp: Fr;
  zklpType: ZKLPType;
  unitId: Fr;
}

// Events

export interface ZKLPVerifiedEvent {
  commitment: Fr;
  unitId: Fr;
  zklpType: Fr;
  timestamp: Fr;
}

export interface SessionStartedEvent {
  sessionId: Fr;
  unitId: Fr;
  entryCommitment: Fr;
}

export interface SessionEndedEvent {
  sessionId: Fr;
  unitId: Fr;
  exitCommitment: Fr;
  duration: Fr;
}

export interface IdentityRegisteredEvent {
  identityHash: Fr;
  publicKey: GrumpkinPoint;
  registrationTime: Fr;
}

export interface AuditRecordStoredEvent {
  recordHash: Fr;
  zklpCommitment: Fr;
  identityHash: Fr;
  unitId: Fr;
}

// Error types

export enum ZKLPErrorCode {
  INVALID_CREDENTIAL = 1001,
  INVALID_MERKLE_PROOF = 1002,
  NULLIFIER_SPENT = 1003,
  INVALID_UNIT = 1004,
  INVALID_SESSION = 1005,
  SESSION_ACTIVE = 1006,
  SESSION_INACTIVE = 1007,
  UNIT_AT_CAPACITY = 1008,
}

export class ZKLPError extends Error {
  constructor(
    public code: ZKLPErrorCode,
    message: string
  ) {
    super(message);
    this.name = 'ZKLPError';
  }
}

// Utility functions

export function packTypeAndUnit(zklpType: ZKLPType, unitId: Fr): Fr {
  const typeNum = BigInt(zklpType);
  const unitNum = unitId.toBigInt();
  return new Fr((unitNum * 256n) + typeNum);
}

export function unpackTypeAndUnit(packed: Fr): { zklpType: ZKLPType; unitId: Fr } {
  const packedNum = packed.toBigInt();
  const typeNum = Number(packedNum % 256n);
  const unitNum = packedNum / 256n;
  return {
    zklpType: typeNum as ZKLPType,
    unitId: new Fr(unitNum),
  };
}

export function isValidZKLPType(type: number): type is ZKLPType {
  return type === ZKLPType.Entry || type === ZKLPType.Exit || type === ZKLPType.General;
}
