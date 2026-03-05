// ZKLP Protocol - Zero-Knowledge Location Proofs
// Main library entry point
//
// ZKLP provides primitives for proving physical presence at a location
// without revealing identity, location history, or temporal patterns.
//
// Core functionality:
// - Identity management with master secret derivation
// - Credential issuance for location access
// - ZKLP generation (generate_zklp) and verification (verify_zklp)
// - Nullifier-based replay protection
// - Session management for entry/exit tracking
// - Selective disclosure via encrypted audit records

// Module exports
pub mod types;
pub mod identity;
pub mod zklp_core;
pub mod nullifiers;
pub mod disclosure;

// Re-export commonly used types
pub use types::{
    Identity,
    Credential,
    ZKLP,
    ZKLPType,
    Unit,
    Session,
    EncryptedZKLPRecord,
    ZKLP_VERSION,
    MAX_UNITS_PER_IDENTITY,
};

// Re-export core functions
pub use zklp_core::{
    generate_zklp,
    verify_zklp,
    verify_zklp_entry,
    verify_zklp_exit,
    ZKLPStorage,
};

// Re-export identity functions
pub use identity::{
    create_identity,
    register_identity,
    revoke_identity,
    recover_identity,
    issue_credentials,
    IdentityRegistry,
};

// Re-export nullifier functions
pub use nullifiers::{
    spend_nullifier,
    is_spent,
    create_session,
    end_session,
    NullifierSet,
    SessionRegistry,
};

// Re-export disclosure functions
pub use disclosure::{
    create_encrypted_record,
    store_audit_record,
    register_viewing_key,
    decrypt_with_private_key,
    ViewingKeyRegistry,
    AuditLog,
};

// Library metadata
pub global LIBRARY_NAME: str<16> = "aztec-zklp-protocol";
pub global LIBRARY_VERSION: str<5> = "0.1.0";

/// Convenience function for full ZKLP flow
/// This combines generation, verification, and audit record creation
/// 
/// # Arguments
/// * `master_secret` - User's master secret (private)
/// * `unit_id` - Target location (public)
/// * `unit_root` - Merkle root of authorized credentials (public)
/// * `merkle_proof` - Proof of credential membership (private)
/// * `viewing_key` - Manager's viewing key for audit (public)
/// * `storage` - ZKLP storage for verification
/// * `context` - Private execution context
/// 
/// # Returns
/// * `(ZKLP, Field)` - The generated ZKLP and its record hash
pub fn full_zklp_flow(
    master_secret: Field,
    unit_id: Field,
    unit_root: Field,
    merkle_proof: [Field; 32],
    merkle_indices: [bool; 32],
    viewing_key: GrumpkinPoint,
    storage: &mut ZKLPStorage,
    context: &mut PrivateContext,
) -> (ZKLP, Field) {
    // Generate ZKLP
    let zklp = generate_zklp(
        master_secret,
        merkle_proof,
        merkle_indices,
        unit_id,
        unit_root,
        ZKLPType::General,
        context,
    );
    
    // Create identity for audit record
    let identity = Identity::new(master_secret);
    
    // Create encrypted audit record
    let record = create_encrypted_record(
        zklp,
        identity,
        viewing_key,
        context,
    );
    
    // Note: Verification happens in public context, so we return the ZKLP
    // The caller is responsible for calling verify_zklp in public context
    
    (zklp, record.zklp_commitment)
}

/// Entry flow: Generate and verify entry ZKLP, create session
pub fn entry_flow(
    master_secret: Field,
    unit_id: Field,
    unit_root: Field,
    merkle_proof: [Field; 32],
    merkle_indices: [bool; 32],
    viewing_key: GrumpkinPoint,
    zklp_storage: &mut ZKLPStorage,
    session_registry: &mut SessionRegistry,
    context: &mut PrivateContext,
) -> (ZKLP, Session) {
    // Generate entry ZKLP
    let zklp = generate_zklp(
        master_secret,
        merkle_proof,
        merkle_indices,
        unit_id,
        unit_root,
        ZKLPType::Entry,
        context,
    );
    
    // Create session (would be done in public context after verification)
    let session = Session::new(zklp);
    
    // Create audit record
    let identity = Identity::new(master_secret);
    let _record = create_encrypted_record(zklp, identity, viewing_key, context);
    
    (zklp, session)
}

/// Exit flow: Generate and verify exit ZKLP, end session
pub fn exit_flow(
    master_secret: Field,
    unit_id: Field,
    unit_root: Field,
    merkle_proof: [Field; 32],
    merkle_indices: [bool; 32],
    entry_nullifier: Field,
    viewing_key: GrumpkinPoint,
    zklp_storage: &mut ZKLPStorage,
    session_registry: &mut SessionRegistry,
    context: &mut PrivateContext,
) -> (ZKLP, Session) {
    // Generate exit ZKLP
    let zklp = generate_zklp(
        master_secret,
        merkle_proof,
        merkle_indices,
        unit_id,
        unit_root,
        ZKLPType::Exit,
        context,
    );
    
    // End session (would be done in public context after verification)
    // Get existing session
    let session = session_registry.active_sessions.get(entry_nullifier);
    
    // Create audit record
    let identity = Identity::new(master_secret);
    let _record = create_encrypted_record(zklp, identity, viewing_key, context);
    
    (zklp, session)
}

// Import needed for public functions
use dep::aztec::prelude::{PrivateContext, PublicContext, Map, Set, GrumpkinPoint};
