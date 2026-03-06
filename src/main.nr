// ZKLP Protocol - Zero-Knowledge Location Proofs
// Aztec Contract Implementation
//
// This contract provides privacy-preserving location attestation
// using zero-knowledge proofs on the Aztec Network.

use ::aztec::macros::aztec;

#[aztec]
pub contract ZKLPProtocol {
    use ::aztec::{
        macros::{functions::{external, initializer, only_self}, storage::storage},
        note::note_getter_options::NoteGetterOptions,
        oracle::logging::debug_log_format,
    };
    use ::aztec::protocol::{address::AztecAddress, traits::ToField};
    use ::aztec::state_vars::{Map, PublicMutable, PrivateSet};

    // Import our library modules
    use crate::types::{Identity, Credential, ZKLP, Session, EncryptedZKLPRecord, ZKLPType, ZKLP_VERSION, ZKLP_TYPE_ENTRY, ZKLP_TYPE_EXIT};
    use crate::identity::{IdentityRecord, IdentityRegistry};
    use crate::nullifiers::{NullifierSet, SessionRegistry};
    use crate::unit::Unit;

    // Global constants
    global MAX_UNITS_PER_IDENTITY: u32 = 256;

    // docs:start:storage
    #[storage]
    struct Storage<Context> {
        // Contract administrator
        admin: PublicMutable<AztecAddress, Context>,
        
        // Identity registry - maps identity_hash -> IdentityRecord
        identities: Map<Field, PublicMutable<IdentityRecord, Context>, Context>,
        
        // Public key index - maps public_key -> identity_hash
        public_key_index: Map<Field, PublicMutable<Field, Context>, Context>,
        
        // Spent nullifiers - prevents replay attacks
        spent_nullifiers: Map<Field, PublicMutable<bool, Context>, Context>,
        
        // Active sessions - maps nullifier -> Session
        active_sessions: Map<Field, PublicMutable<Session, Context>, Context>,
        
        // Unit registry - maps unit_id -> Unit
        units: Map<Field, PublicMutable<Unit, Context>, Context>,
        
        // Viewing keys for audit - maps entity_id -> public_key
        viewing_keys: Map<Field, PublicMutable<Field, Context>, Context>,
    }
    // docs:end:storage

    // docs:start:constructor
    #[external("public")]
    #[initializer]
    fn constructor(admin: AztecAddress) {
        debug_log_format("Initializing ZKLP Protocol contract with admin {0}", [admin.to_field()]);
        self.storage.admin.write(admin);
    }
    // docs:end:constructor

    // docs:start:register-identity
    // Register a new identity with the protocol
    // Callable by anyone - creates a new identity record
    #[external("public")]
    fn register_identity(identity_hash: Field, public_key_x: Field, public_key_y: Field) {
        debug_log_format("Registering identity {0}", [identity_hash]);
        
        // Check identity doesn't already exist
        let existing = self.storage.identities.at(identity_hash).read();
        assert(existing.identity_hash == 0, "Identity already exists");
        
        // Create identity record
        let record = IdentityRecord {
            identity_hash,
            public_key_x,
            public_key_y,
            active: true,
            credential_count: 0,
        };
        
        self.storage.identities.at(identity_hash).write(record);
        self.storage.public_key_index.at(public_key_x).write(identity_hash);
        
        debug_log_format("Identity {0} registered successfully", [identity_hash]);
    }
    // docs:end:register-identity

    // docs:start:register-unit
    // Register a new unit/location
    // Only callable by admin
    #[external("public")]
    fn register_unit(
        unit_id: Field,
        unit_public_key_x: Field,
        unit_public_key_y: Field,
        credential_tree_root: Field,
        metadata_hash: Field,
    ) {
        debug_log_format("Registering unit {0}", [unit_id]);
        
        // Only admin can register units
        let caller = self.context.maybe_msg_sender().unwrap();
        let admin = self.storage.admin.read();
        assert(caller.eq(admin), "Only admin can register units");
        
        // Check unit doesn't already exist
        let existing = self.storage.units.at(unit_id).read();
        assert(existing.unit_id == 0, "Unit already exists");
        
        // Create unit
        let unit = Unit::new(
            unit_id,
            unit_public_key_x,
            unit_public_key_y,
            credential_tree_root,
            metadata_hash,
        );
        
        self.storage.units.at(unit_id).write(unit);
        debug_log_format("Unit {0} registered successfully", [unit_id]);
    }
    // docs:end:register-unit

    // docs:start:generate-zklp
    // Generate a Zero-Knowledge Location Proof
    // This is a PRIVATE function - keeps credential secret
    #[external("private")]
    fn generate_zklp(
        master_secret: Field,
        unit_id: Field,
        zklp_type: Field,  // 1 = Entry, 2 = Exit
    ) -> ZKLP {
        debug_log_format("Generating ZKLP for unit {0}", [unit_id]);
        
        let sender = self.context.maybe_msg_sender().unwrap();
        
        // Derive identity from master secret (inline computation)
        let public_key_x = std::hash::pedersen_hash([master_secret, 1]);
        let public_key_y = std::hash::pedersen_hash([master_secret, 2]);
        let identity_hash = std::hash::pedersen_hash([master_secret, public_key_x, public_key_y]);
        let identity = Identity {
            master_secret,
            public_key_x,
            public_key_y,
            identity_hash,
        };
        
        // Derive credential for this unit (inline computation)
        let credential_secret = std::hash::pedersen_hash([identity.master_secret, unit_id]);
        let credential_hash = std::hash::pedersen_hash([credential_secret, unit_id, identity.identity_hash]);
        let credential = Credential {
            unit_id,
            credential_secret,
            credential_hash,
            identity_hash: identity.identity_hash,
        };
        
        // Compute nullifier (inline computation)
        let nullifier = std::hash::pedersen_hash([credential.credential_secret, credential.unit_id, 0]);
        
        // Check nullifier not spent (in public state)
        self.enqueue(ZKLPProtocol::at(self.context.this_address()).check_nullifier(nullifier));
        
        // Generate nonce from nullifier (deterministic)
        let nonce = nullifier;
        
        // Compute commitment (inline computation)
        let commitment = std::hash::pedersen_hash([credential.credential_hash, nullifier, nonce]);
        
        // Create ZKLP
        let zklp = ZKLP {
            version: ZKLP_VERSION,
            nullifier,
            commitment,
            unit_id,
            timestamp: nonce,
            zklp_type,
        };
        
        // If entry type, create session
        if zklp_type == ZKLP_TYPE_ENTRY {
            self.enqueue(ZKLPProtocol::at(self.context.this_address()).create_session(nullifier, unit_id));
        } else if zklp_type == ZKLP_TYPE_EXIT {
            self.enqueue(ZKLPProtocol::at(self.context.this_address()).end_session(nullifier, unit_id));
        }
        
        // Mark nullifier as spent
        self.enqueue(ZKLPProtocol::at(self.context.this_address()).spend_nullifier(nullifier));
        
        debug_log_format("ZKLP generated with nullifier {0}", [nullifier]);
        zklp
    }
    // docs:end:generate-zklp

    // docs:start:check-nullifier
    // Internal: Check if nullifier is already spent
    #[external("public")]
    #[only_self]
    fn check_nullifier(nullifier: Field) {
        let spent = self.storage.spent_nullifiers.at(nullifier).read();
        assert(!spent, "Nullifier already spent");
    }
    // docs:end:check-nullifier

    // docs:start:spend-nullifier
    // Internal: Mark nullifier as spent
    #[external("public")]
    #[only_self]
    fn spend_nullifier(nullifier: Field) {
        self.storage.spent_nullifiers.at(nullifier).write(true);
        debug_log_format("Nullifier {0} spent", [nullifier]);
    }
    // docs:end:spend-nullifier

    // docs:start:create-session
    // Internal: Create a new session
    #[external("public")]
    #[only_self]
    fn create_session(nullifier: Field, unit_id: Field) {
        debug_log_format("Creating session for nullifier {0}", [nullifier]);
        
        let session_id = std::hash::pedersen_hash([nullifier, unit_id]);
        let session = Session {
            session_id,
            nullifier,
            unit_id,
            entry_timestamp: self.context.block_number() as Field,
            active: true,
        };
        
        self.storage.active_sessions.at(nullifier).write(session);
        debug_log_format("Session {0} created", [session_id]);
    }
    // docs:end:create-session

    // docs:start:end-session
    // Internal: End an active session
    #[external("public")]
    #[only_self]
    fn end_session(nullifier: Field, unit_id: Field) {
        debug_log_format("Ending session for nullifier {0}", [nullifier]);
        
        let mut session = self.storage.active_sessions.at(nullifier).read();
        assert(session.active, "No active session");
        assert(session.unit_id == unit_id, "Session unit mismatch");
        
        session.active = false;
        self.storage.active_sessions.at(nullifier).write(session);
        debug_log_format("Session ended for nullifier {0}", [nullifier]);
    }
    // docs:end:end-session

    // docs:start:register-viewing-key
    // Register a viewing key for audit purposes
    // Only callable by admin
    #[external("public")]
    fn register_viewing_key(entity_id: Field, public_key_x: Field) {
        debug_log_format("Registering viewing key for entity {0}", [entity_id]);
        
        let caller = self.context.maybe_msg_sender().unwrap();
        let admin = self.storage.admin.read();
        assert(caller.eq(admin), "Only admin can register viewing keys");
        
        self.storage.viewing_keys.at(entity_id).write(public_key_x);
        debug_log_format("Viewing key registered for entity {0}", [entity_id]);
    }
    // docs:end:register-viewing-key

    // docs:start:get-identity
    // Get identity record (public view)
    #[external("public")]
    fn get_identity(identity_hash: Field) -> pub IdentityRecord {
        self.storage.identities.at(identity_hash).read()
    }
    // docs:end:get-identity

    // docs:start:get-unit
    // Get unit info (public view)
    #[external("public")]
    fn get_unit(unit_id: Field) -> pub Unit {
        self.storage.units.at(unit_id).read()
    }
    // docs:end:get-unit

    // docs:start:get-session
    // Get session info (public view)
    #[external("public")]
    fn get_session(nullifier: Field) -> pub Session {
        self.storage.active_sessions.at(nullifier).read()
    }
    // docs:end:get-session

    // docs:start:is-nullifier-spent
    // Check if nullifier is spent (public view)
    #[external("public")]
    fn is_nullifier_spent(nullifier: Field) -> pub bool {
        self.storage.spent_nullifiers.at(nullifier).read()
    }
    // docs:end:is-nullifier-spent

    // Utility: Hash a single field (for use with pedersen)
    #[external("utility")]
    unconstrained fn hash_single(input: Field) -> pub Field {
        std::hash::pedersen_hash([input])
    }
}

// Include library modules
mod types;
mod identity;
mod nullifiers;
mod unit;
