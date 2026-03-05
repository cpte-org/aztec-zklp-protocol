/**
 * ZKLP Protocol - Nullifier Management
 * Replay protection and session management
 */

import { Fr } from '@aztec/aztec.js/fields';
import { Session, ZKLP, ZKLPType, ZKLPError, ZKLPErrorCode } from './types';

/**
 * Nullifier Set for tracking spent nullifiers
 */
export class NullifierSet {
  private spent: Set<string> = new Set();
  private spentAt: Map<string, number> = new Map();
  private nullifierToZKLP: Map<string, string> = new Map();
  
  /**
   * Spend a nullifier
   * @returns true if successful, false if already spent
   */
  spend(nullifier: Fr, zklpCommitment: Fr, blockHeight: number): boolean {
    const key = nullifier.toString();
    
    if (this.spent.has(key)) {
      return false;
    }
    
    this.spent.add(key);
    this.spentAt.set(key, blockHeight);
    this.nullifierToZKLP.set(key, zklpCommitment.toString());
    
    return true;
  }
  
  /**
   * Check if nullifier is spent
   */
  isSpent(nullifier: Fr): boolean {
    return this.spent.has(nullifier.toString());
  }
  
  /**
   * Get block height when nullifier was spent
   */
  getSpentAt(nullifier: Fr): number | undefined {
    return this.spentAt.get(nullifier.toString());
  }
  
  /**
   * Get ZKLP commitment for a spent nullifier
   */
  getZKLPCommitment(nullifier: Fr): string | undefined {
    return this.nullifierToZKLP.get(nullifier.toString());
  }
  
  /**
   * Batch spend nullifiers
   */
  spendBatch(
    nullifiers: Fr[],
    zklpCommitments: Fr[],
    blockHeight: number
  ): boolean[] {
    return nullifiers.map((nullifier, i) => 
      this.spend(nullifier, zklpCommitments[i] || Fr.ZERO, blockHeight)
    );
  }
  
  /**
   * Get all spent nullifiers
   */
  getAllSpent(): string[] {
    return Array.from(this.spent);
  }
  
  /**
   * Clear all nullifiers (use with caution)
   */
  clear(): void {
    this.spent.clear();
    this.spentAt.clear();
    this.nullifierToZKLP.clear();
  }
}

/**
 * Session Registry for managing active sessions
 */
export class SessionRegistry {
  private activeSessions: Map<string, Session> = new Map();
  private sessionHistory: Map<string, Session> = new Map();
  private unitSessionCount: Map<string, number> = new Map();
  private maxSessionsPerUnit: number;
  
  constructor(maxSessionsPerUnit: number = 100) {
    this.maxSessionsPerUnit = maxSessionsPerUnit;
  }
  
  /**
   * Create a new session from entry ZKLP
   */
  createSession(entryZKLP: ZKLP): Session {
    if (entryZKLP.zklpType !== ZKLPType.Entry) {
      throw new ZKLPError(
        ZKLPErrorCode.INVALID_SESSION,
        'ZKLP must be Entry type'
      );
    }
    
    const nullifierKey = entryZKLP.nullifier.toString();
    
    // Check no existing active session
    if (this.activeSessions.has(nullifierKey)) {
      throw new ZKLPError(
        ZKLPErrorCode.SESSION_ACTIVE,
        'Session already active for this nullifier'
      );
    }
    
    // Check unit capacity
    const unitKey = entryZKLP.unitId.toString();
    const currentCount = this.unitSessionCount.get(unitKey) || 0;
    if (currentCount >= this.maxSessionsPerUnit) {
      throw new ZKLPError(
        ZKLPErrorCode.UNIT_AT_CAPACITY,
        'Unit at maximum session capacity'
      );
    }
    
    // Create session
    const sessionId = computeSessionId(entryZKLP.nullifier, entryZKLP.unitId);
    const session: Session = {
      sessionId,
      nullifier: entryZKLP.nullifier,
      unitId: entryZKLP.unitId,
      entryTimestamp: entryZKLP.timestamp,
      active: true,
    };
    
    // Store session
    this.activeSessions.set(nullifierKey, session);
    this.sessionHistory.set(sessionId.toString(), session);
    this.unitSessionCount.set(unitKey, currentCount + 1);
    
    return session;
  }
  
  /**
   * End a session with exit ZKLP
   */
  endSession(exitZKLP: ZKLP, entryNullifier: Fr): Session {
    if (exitZKLP.zklpType !== ZKLPType.Exit) {
      throw new ZKLPError(
        ZKLPErrorCode.INVALID_SESSION,
        'ZKLP must be Exit type'
      );
    }
    
    const nullifierKey = entryNullifier.toString();
    const session = this.activeSessions.get(nullifierKey);
    
    if (!session) {
      throw new ZKLPError(
        ZKLPErrorCode.SESSION_INACTIVE,
        'No active session found'
      );
    }
    
    if (!session.unitId.equals(exitZKLP.unitId)) {
      throw new ZKLPError(
        ZKLPErrorCode.INVALID_UNIT,
        'Exit unit does not match entry unit'
      );
    }
    
    // Mark as inactive
    const endedSession: Session = { ...session, active: false };
    
    // Update storage
    this.activeSessions.delete(nullifierKey);
    this.sessionHistory.set(session.sessionId.toString(), endedSession);
    
    // Decrement unit count
    const unitKey = session.unitId.toString();
    const currentCount = this.unitSessionCount.get(unitKey) || 0;
    this.unitSessionCount.set(unitKey, Math.max(0, currentCount - 1));
    
    return endedSession;
  }
  
  /**
   * Get active session by entry nullifier
   */
  getActiveSession(entryNullifier: Fr): Session | undefined {
    return this.activeSessions.get(entryNullifier.toString());
  }
  
  /**
   * Get session by session ID
   */
  getSession(sessionId: Fr): Session | undefined {
    return this.sessionHistory.get(sessionId.toString());
  }
  
  /**
   * Force end a session (admin only)
   */
  forceEndSession(entryNullifier: Fr, adminAddress: string, callerAddress: string): Session {
    if (adminAddress !== callerAddress) {
      throw new ZKLPError(
        ZKLPErrorCode.INVALID_CREDENTIAL,
        'Only admin can force end sessions'
      );
    }
    
    const session = this.activeSessions.get(entryNullifier.toString());
    if (!session) {
      throw new ZKLPError(
        ZKLPErrorCode.SESSION_INACTIVE,
        'Session not active'
      );
    }
    
    const endedSession: Session = { ...session, active: false };
    
    this.activeSessions.delete(entryNullifier.toString());
    this.sessionHistory.set(session.sessionId.toString(), endedSession);
    
    const unitKey = session.unitId.toString();
    const currentCount = this.unitSessionCount.get(unitKey) || 0;
    this.unitSessionCount.set(unitKey, Math.max(0, currentCount - 1));
    
    return endedSession;
  }
  
  /**
   * Get active session count for a unit
   */
  getUnitActiveCount(unitId: Fr): number {
    return this.unitSessionCount.get(unitId.toString()) || 0;
  }
  
  /**
   * Get all active sessions
   */
  getAllActiveSessions(): Session[] {
    return Array.from(this.activeSessions.values());
  }
  
  /**
   * Get all sessions (including historical)
   */
  getAllSessions(): Session[] {
    return Array.from(this.sessionHistory.values());
  }
  
  /**
   * Clean up inactive sessions from active set
   */
  cleanupInactive(): number {
    let cleaned = 0;
    for (const [key, session] of this.activeSessions) {
      if (!session.active) {
        this.activeSessions.delete(key);
        cleaned++;
      }
    }
    return cleaned;
  }
}

/**
 * Compute session ID from nullifier and unit ID
 */
function computeSessionId(nullifier: Fr, unitId: Fr): Fr {
  // Simple hash-based session ID
  const combined = nullifier.toString() + unitId.toString();
  return Fr.fromBuffer(
    Buffer.from(combined).slice(0, 32)
  );
}

// Simple hash function
function keccak256(data: string): string {
  return data.slice(0, 64).padStart(64, '0');
}
