// ZKLP Protocol - Nullifier and Session Management

use crate::types::{Session, ZKLP};

// Nullifier set for replay protection
pub struct NullifierSet {
    // Handled by contract storage
}

// Session registry for managing active sessions
pub struct SessionRegistry {
    // Handled by contract storage
}

impl Session {
    // Create a new session from an entry ZKLP
    pub fn new(entry_zklp: ZKLP) -> Self {
        let session_id = std::hash::pedersen_hash([entry_zklp.nullifier, entry_zklp.unit_id]);
        
        Session {
            session_id,
            nullifier: entry_zklp.nullifier,
            unit_id: entry_zklp.unit_id,
            entry_timestamp: entry_zklp.timestamp,
            active: true,
        }
    }
}
