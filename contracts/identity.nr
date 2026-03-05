// ZKLP Protocol - Identity Management
// Identity creation, derivation, and management

use dep::aztec::prelude::{Field, PrivateContext, PublicContext};
use dep::aztec::protocol_types::grumpkin_point::GrumpkinPoint;
use crate::types::{Identity, Credential, ZKLP_VERSION};

// Identity registry storage
pub struct IdentityRegistry {
    // Mapping from identity_hash -> registration status
    pub registered_identities: Map<Field, IdentityRecord>,
    
    // Mapping from public_key -> identity_hash (for lookup)
    pub public_key_index: Map<GrumpkinPoint, Field>,
    
    // Admin who can register new identities
    pub admin: Field,
}

// Identity registration record
pub struct IdentityRecord {
    pub identity_hash: Field,
    pub public_key: GrumpkinPoint,
    pub registration_time: Field,
    pub active: bool,
    pub metadata_hash: Field,  // Encrypted metadata
}

// Credential issuance record
pub struct CredentialIssuance {
    pub credential_hash: Field,
    pub unit_id: Field,
    pub issued_at: Field,
    pub expires_at: Field,  // 0 = no expiration
}

// Create a new identity with a randomly generated master secret
// Returns the new identity (user must securely store master_secret)
#[private]
pub fn create_identity(
    entropy: Field,  // Additional entropy for randomness
    context: &mut PrivateContext,
) -> Identity {
    // Derive master secret from entropy and private context
    let master_secret = std::hash::pedersen_hash([
        entropy,
        context.msg_sender(),
        context.block_number(),
    ]);
    
    Identity::new(master_secret)
}

// Register an identity in the registry
// Called by admin after verifying off-chain identity
#[public]
pub fn register_identity(
    identity_hash: Field,
    public_key: GrumpkinPoint,
    metadata_hash: Field,
    registry: &mut IdentityRegistry,
    context: &mut PublicContext,
) {
    // Verify caller is admin
    assert(context.msg_sender() == registry.admin, "Only admin can register identities");
    
    // Check not already registered
    assert(!registry.registered_identities.get(identity_hash).active, "Identity already registered");
    
    // Create registration record
    let record = IdentityRecord {
        identity_hash,
        public_key,
        registration_time: context.timestamp(),
        active: true,
        metadata_hash,
    };
    
    // Store in registry
    registry.registered_identities.insert(identity_hash, record);
    registry.public_key_index.insert(public_key, identity_hash);
}

// Revoke an identity (soft delete)
#[public]
pub fn revoke_identity(
    identity_hash: Field,
    registry: &mut IdentityRegistry,
    context: &mut PublicContext,
) {
    // Verify caller is admin
    assert(context.msg_sender() == registry.admin, "Only admin can revoke identities");
    
    // Get and update record
    let mut record = registry.registered_identities.get(identity_hash);
    assert(record.active, "Identity not active");
    
    record.active = false;
    registry.registered_identities.insert(identity_hash, record);
}

// Lookup identity by public key
#[public]
pub fn lookup_identity(
    public_key: GrumpkinPoint,
    registry: &IdentityRegistry,
) -> Option<IdentityRecord> {
    let identity_hash = registry.public_key_index.get(public_key);
    
    if identity_hash == 0 {
        Option::none()
    } else {
        Option::some(registry.registered_identities.get(identity_hash))
    }
}

// Verify identity is registered and active
#[public]
pub fn verify_identity_active(
    identity_hash: Field,
    registry: &IdentityRegistry,
) -> bool {
    let record = registry.registered_identities.get(identity_hash);
    record.active
}

// Issue credentials to an identity for a specific unit
// This updates the unit's credential Merkle tree off-chain
// and returns the new root to be updated on-chain
#[private]
pub fn issue_credentials(
    identity: Identity,
    unit_ids: [Field; 10],  // Up to 10 units at once
    context: &mut PrivateContext,
) -> [Credential; 10] {
    let mut credentials = [Credential::empty(); 10];
    
    for i in 0..10 {
        if unit_ids[i] != 0 {
            credentials[i] = identity.derive_credential(unit_ids[i]);
        }
    }
    
    credentials
}

// Revoke credentials (mark as revoked in the tree)
// Similar to issuance, this requires Merkle tree update off-chain
#[private]
pub fn revoke_credentials(
    identity: Identity,
    unit_ids: [Field; 10],
    context: &mut PrivateContext,
) -> [Field; 10] {  // Returns nullifiers to be marked as spent
    let mut nullifiers = [0; 10];
    
    for i in 0..10 {
        if unit_ids[i] != 0 {
            let credential = identity.derive_credential(unit_ids[i]);
            nullifiers[i] = credential.compute_nullifier();
        }
    }
    
    nullifiers
}

// Recover identity (in case of lost device)
// Admin can generate new credentials with a new master secret
// Old credentials are revoked
#[public]
pub fn recover_identity(
    old_identity_hash: Field,
    new_public_key: GrumpkinPoint,
    new_metadata_hash: Field,
    registry: &mut IdentityRegistry,
    context: &mut PublicContext,
) -> Field {  // Returns new identity hash
    // Verify caller is admin
    assert(context.msg_sender() == registry.admin, "Only admin can recover identities");
    
    // Revoke old identity
    let mut old_record = registry.registered_identities.get(old_identity_hash);
    old_record.active = false;
    registry.registered_identities.insert(old_identity_hash, old_record);
    
    // Create new identity record (master secret generated off-chain)
    let new_identity_hash = std::hash::pedersen_hash([
        new_public_key.x,
        new_public_key.y,
        context.timestamp(),
    ]);
    
    let new_record = IdentityRecord {
        identity_hash: new_identity_hash,
        public_key: new_public_key,
        registration_time: context.timestamp(),
        active: true,
        metadata_hash: new_metadata_hash,
    };
    
    registry.registered_identities.insert(new_identity_hash, new_record);
    registry.public_key_index.insert(new_public_key, new_identity_hash);
    
    new_identity_hash
}

// Helper: Empty credential (for array initialization)
impl Credential {
    pub fn empty() -> Self {
        Credential {
            unit_id: 0,
            credential_secret: 0,
            credential_hash: 0,
            identity_hash: 0,
        }
    }
}

// Identity events

// Emitted when identity is registered
#[event]
struct IdentityRegistered {
    identity_hash: Field,
    public_key: GrumpkinPoint,
    registration_time: Field,
}

// Emitted when identity is revoked
#[event]
struct IdentityRevoked {
    identity_hash: Field,
    revocation_time: Field,
}

// Emitted when identity is recovered
#[event]
struct IdentityRecovered {
    old_identity_hash: Field,
    new_identity_hash: Field,
    recovery_time: Field,
}

// Tests
#[test]
fn test_identity_lifecycle() {
    let entropy = 12345;
    let mut context = PrivateContext::new();
    
    // Create identity
    let identity = create_identity(entropy, &mut context);
    
    // Verify properties
    assert(identity.master_secret != 0);
    assert(identity.identity_hash != 0);
    
    // Derive credentials
    let unit_id = 100;
    let credential = identity.derive_credential(unit_id);
    
    assert(credential.unit_id == unit_id);
    assert(credential.identity_hash == identity.identity_hash);
    assert(identity.verify_credential(credential));
}

#[test]
fn test_credential_consistency() {
    let identity = Identity::new(12345);
    let unit_id = 100;
    
    // Derive same credential twice
    let cred1 = identity.derive_credential(unit_id);
    let cred2 = identity.derive_credential(unit_id);
    
    // Should be identical
    assert(cred1.credential_hash == cred2.credential_hash);
    assert(cred1.credential_secret == cred2.credential_secret);
}

#[test]
fn test_different_units_different_credentials() {
    let identity = Identity::new(12345);
    
    let cred1 = identity.derive_credential(100);
    let cred2 = identity.derive_credential(200);
    
    // Different credentials for different units
    assert(cred1.credential_hash != cred2.credential_hash);
}
