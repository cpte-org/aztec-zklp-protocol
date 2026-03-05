// ZKLP Protocol - Nullifier Management
// Replay protection and session management

use dep::aztec::prelude::{Field, Map, Set};
use crate::types::{ZKLP, Session, ZKLPType};

// Nullifier set storage
pub struct NullifierSet {
    // Set of all spent nullifiers
    pub spent: Set<Field>,
    
    // Mapping from nullifier -> block height when spent
    pub spent_at: Map<Field, Field>,
    
    // Mapping from nullifier -> ZKLP commitment
    pub nullifier_to_zklp: Map<Field, Field>,
}

// Session registry
pub struct SessionRegistry {
    // Active sessions (nullifier -> Session)
    pub active_sessions: Map<Field, Session>,
    
    // Session history (session_id -> Session)
    pub session_history: Map<Field, Session>,
    
    // Unit -> active session count (for capacity management)
    pub unit_session_count: Map<Field, Field>,
    
    // Maximum sessions per unit (safety limit)
    pub max_sessions_per_unit: Field,
}

// Spend a nullifier (mark as used)
// Returns true if successful, false if already spent
#[public]
pub fn spend_nullifier(
    nullifier: Field,
    zklp_commitment: Field,
    nullifier_set: &mut NullifierSet,
    block_height: Field,
) -> bool {
    // Check not already spent
    if nullifier_set.spent.contains(nullifier) {
        return false;
    }
    
    // Add to spent set
    nullifier_set.spent.insert(nullifier);
    nullifier_set.spent_at.insert(nullifier, block_height);
    nullifier_set.nullifier_to_zklp.insert(nullifier, zklp_commitment);
    
    true
}

// Check if a nullifier has been spent
#[public]
pub fn is_spent(
    nullifier: Field,
    nullifier_set: &NullifierSet,
) -> bool {
    nullifier_set.spent.contains(nullifier)
}

// Batch spend nullifiers (for efficiency)
#[public]
pub fn spend_nullifiers_batch(
    nullifiers: [Field; 10],
    zklp_commitments: [Field; 10],
    nullifier_set: &mut NullifierSet,
    block_height: Field,
) -> [bool; 10] {
    let mut results = [false; 10];
    
    for i in 0..10 {
        if nullifiers[i] != 0 {
            results[i] = spend_nullifier(
                nullifiers[i],
                zklp_commitments[i],
                nullifier_set,
                block_height,
            );
        }
    }
    
    results
}

// Create a new session from an entry ZKLP
#[public]
pub fn create_session(
    entry_zklp: ZKLP,
    registry: &mut SessionRegistry,
) -> Session {
    // Verify it's an entry ZKLP
    assert(entry_zklp.zklp_type == ZKLPType::Entry, "ZKLP must be Entry type");
    
    // Check no existing active session for this nullifier
    let existing = registry.active_sessions.get(entry_zklp.nullifier);
    assert(!existing.active, "Session already active for this nullifier");
    
    // Check unit capacity
    let current_count = registry.unit_session_count.get(entry_zklp.unit_id);
    assert(current_count < registry.max_sessions_per_unit, "Unit at capacity");
    
    // Create session
    let session = Session::new(entry_zklp);
    
    // Store session
    registry.active_sessions.insert(entry_zklp.nullifier, session);
    registry.session_history.insert(session.session_id, session);
    registry.unit_session_count.insert(entry_zklp.unit_id, current_count + 1);
    
    session
}

// End a session with an exit ZKLP
#[public]
pub fn end_session(
    exit_zklp: ZKLP,
    entry_nullifier: Field,
    registry: &mut SessionRegistry,
) -> Session {
    // Verify it's an exit ZKLP
    assert(exit_zklp.zklp_type == ZKLPType::Exit, "ZKLP must be Exit type");
    
    // Get active session
    let mut session = registry.active_sessions.get(entry_nullifier);
    assert(session.active, "No active session found");
    
    // Verify unit matches
    assert(session.unit_id == exit_zklp.unit_id, "Exit unit does not match entry unit");
    
    // Mark session as inactive
    session.active = false;
    
    // Update storage
    registry.active_sessions.insert(entry_nullifier, session);
    registry.session_history.insert(session.session_id, session);
    
    // Decrement unit session count
    let current_count = registry.unit_session_count.get(session.unit_id);
    registry.unit_session_count.insert(session.unit_id, current_count - 1);
    
    session
}

// Get active session by entry nullifier
#[public]
pub fn get_active_session(
    entry_nullifier: Field,
    registry: &SessionRegistry,
) -> Option<Session> {
    let session = registry.active_sessions.get(entry_nullifier);
    
    if session.active {
        Option::some(session)
    } else {
        Option::none()
    }
}

// Force end a session (admin only, for emergencies)
#[public]
pub fn force_end_session(
    entry_nullifier: Field,
    admin: Field,
    caller: Field,
    registry: &mut SessionRegistry,
) -> Session {
    // Verify caller is admin
    assert(caller == admin, "Only admin can force end sessions");
    
    // Get and end session
    let mut session = registry.active_sessions.get(entry_nullifier);
    assert(session.active, "Session not active");
    
    session.active = false;
    registry.active_sessions.insert(entry_nullifier, session);
    registry.session_history.insert(session.session_id, session);
    
    // Decrement unit session count
    let current_count = registry.unit_session_count.get(session.unit_id);
    registry.unit_session_count.insert(session.unit_id, current_count - 1);
    
    session
}

// Cleanup old sessions (gas refund mechanism)
// Can be called by anyone to clean up old inactive sessions
#[public]
pub fn cleanup_inactive_session(
    session_id: Field,
    registry: &mut SessionRegistry,
) -> bool {
    let session = registry.session_history.get(session_id);
    
    // Only clean up inactive sessions
    if session.active {
        return false;
    }
    
    // Remove from active_sessions mapping if present
    // (This is a no-op if already removed, but ensures cleanup)
    let empty_session = Session {
        session_id: 0,
        nullifier: 0,
        unit_id: 0,
        entry_timestamp: 0,
        active: false,
    };
    
    registry.active_sessions.insert(session.nullifier, empty_session);
    
    true
}

// Get session statistics for a unit
#[public]
pub fn get_unit_session_stats(
    unit_id: Field,
    registry: &SessionRegistry,
) -> (Field, Field) {  // (active_count, total_count)
    let active_count = registry.unit_session_count.get(unit_id);
    
    // Note: Total count would require iteration, not directly supported
    // This would need to be tracked separately or computed off-chain
    (active_count, active_count)  // Simplified
}

// Nullifier events

// Emitted when nullifier is spent
#[event]
struct NullifierSpent {
    nullifier: Field,
    zklp_commitment: Field,
    block_height: Field,
}

// Emitted when session is created
#[event]
struct SessionCreated {
    session_id: Field,
    entry_nullifier: Field,
    unit_id: Field,
    entry_time: Field,
}

// Emitted when session is ended
#[event]
struct SessionEnded {
    session_id: Field,
    exit_nullifier: Field,
    unit_id: Field,
    duration: Field,
}

// Emitted when session is force-ended
#[event]
struct SessionForceEnded {
    session_id: Field,
    unit_id: Field,
    admin: Field,
    reason: Field,  // Encoded reason
}

// Tests
#[test]
fn test_nullifier_spending() {
    let mut nullifier_set = NullifierSet {
        spent: Set::new(),
        spent_at: Map::new(),
        nullifier_to_zklp: Map::new(),
    };
    
    let nullifier = 12345;
    let commitment = 67890;
    let block = 100;
    
    // First spend should succeed
    assert(spend_nullifier(nullifier, commitment, &mut nullifier_set, block));
    
    // Check spent
    assert(is_spent(nullifier, &nullifier_set));
    
    // Second spend should fail
    assert(!spend_nullifier(nullifier, commitment, &mut nullifier_set, block + 1));
}

#[test]
fn test_session_lifecycle() {
    // This would need full storage setup for integration test
    // Unit test of logic here
    
    let entry_zklp = ZKLP {
        version: 1,
        nullifier: 12345,
        commitment: 67890,
        unit_id: 100,
        timestamp: 1000,
        zklp_type: ZKLPType::Entry,
    };
    
    let session = Session::new(entry_zklp);
    
    assert(session.nullifier == entry_zklp.nullifier);
    assert(session.unit_id == entry_zklp.unit_id);
    assert(session.active);
    assert(session.session_id != 0);
}

#[test]
fn test_nullifier_batch() {
    let mut nullifier_set = NullifierSet {
        spent: Set::new(),
        spent_at: Map::new(),
        nullifier_to_zklp: Map::new(),
    };
    
    let nullifiers = [1, 2, 3, 4, 5, 0, 0, 0, 0, 0];
    let commitments = [10, 20, 30, 40, 50, 0, 0, 0, 0, 0];
    
    let results = spend_nullifiers_batch(nullifiers, commitments, &mut nullifier_set, 100);
    
    // First 5 should succeed
    assert(results[0]);
    assert(results[1]);
    assert(results[2]);
    assert(results[3]);
    assert(results[4]);
    
    // Last 5 should be skipped (nullifier = 0)
    assert(!results[5]);
}
