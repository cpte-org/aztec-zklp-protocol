// ZKLP Protocol - Selective Disclosure
// Manager viewing keys and encrypted audit records

use dep::aztec::prelude::{Field, PrivateContext, PublicContext, Map};
use dep::aztec::protocol_types::grumpkin_point::GrumpkinPoint;
use crate::types::{ZKLP, Identity, EncryptedZKLPRecord};

// Viewing key registry
pub struct ViewingKeyRegistry {
    // Mapping from entity_id -> viewing public key
    pub viewing_keys: Map<Field, GrumpkinPoint>,
    
    // Mapping from entity_id -> encrypted viewing private key
    // (for recovery purposes, encrypted to admin key)
    pub encrypted_private_keys: Map<Field, [Field; 4]>,
    
    // Admin who can manage viewing keys
    pub admin: Field,
}

// Audit log storage
pub struct AuditLog {
    // Mapping from encrypted record hash -> record
    pub encrypted_records: Map<Field, EncryptedZKLPRecord>,
    
    // Mapping from identity_hash -> list of record hashes
    // (simplified: just stores count, actual list off-chain)
    pub identity_record_count: Map<Field, Field>,
    
    // Mapping from unit_id -> list of record hashes
    pub unit_record_count: Map<Field, Field>,
}

// Create encrypted audit record for a ZKLP event
// Only the holder of the viewing private key can decrypt
#[private]
pub fn create_encrypted_record(
    zklp: ZKLP,
    identity: Identity,
    viewing_public_key: GrumpkinPoint,
    context: &mut PrivateContext,
) -> EncryptedZKLPRecord {
    // Prepare plaintext data
    // [0] = identity_hash (link to identity without revealing master_secret)
    // [1] = credential_hash (link to credential)
    // [2] = timestamp
    // [3] = zklp_type | unit_id (packed)
    let plaintext = [
        identity.identity_hash,
        zklp.commitment,  // Using commitment as credential reference
        zklp.timestamp,
        pack_type_and_unit(zklp.zklp_type, zklp.unit_id),
    ];
    
    // Encrypt to viewing public key
    // Using simplified XOR encryption for illustration
    // In production, use proper ECIES or similar
    let encrypted_data = encrypt_to_public_key(plaintext, viewing_public_key, context);
    
    EncryptedZKLPRecord {
        zklp_commitment: zklp.commitment,
        encrypted_data,
        manager_public_key: viewing_public_key,
    }
}

// Register a viewing key for an entity (manager, admin, etc.)
#[public]
pub fn register_viewing_key(
    entity_id: Field,
    viewing_public_key: GrumpkinPoint,
    encrypted_private_key: [Field; 4],  // For recovery
    registry: &mut ViewingKeyRegistry,
    context: &mut PublicContext,
) {
    // Verify caller is admin
    assert(context.msg_sender() == registry.admin, "Only admin can register viewing keys");
    
    // Store viewing key
    registry.viewing_keys.insert(entity_id, viewing_public_key);
    registry.encrypted_private_keys.insert(entity_id, encrypted_private_key);
}

// Update viewing key (key rotation)
#[public]
pub fn rotate_viewing_key(
    entity_id: Field,
    new_viewing_public_key: GrumpkinPoint,
    new_encrypted_private_key: [Field; 4],
    registry: &mut ViewingKeyRegistry,
    context: &mut PublicContext,
) {
    // Verify caller is admin
    assert(context.msg_sender() == registry.admin, "Only admin can rotate viewing keys");
    
    // Verify old key exists
    let old_key = registry.viewing_keys.get(entity_id);
    assert(old_key.x != 0 || old_key.y != 0, "No existing viewing key");
    
    // Update to new key
    registry.viewing_keys.insert(entity_id, new_viewing_public_key);
    registry.encrypted_private_keys.insert(entity_id, new_encrypted_private_key);
}

// Store encrypted audit record on-chain
#[public]
pub fn store_audit_record(
    record: EncryptedZKLPRecord,
    identity_hash: Field,
    unit_id: Field,
    audit_log: &mut AuditLog,
) -> Field {  // Returns record hash
    // Compute record hash
    let record_hash = hash_encrypted_record(&record);
    
    // Store record
    audit_log.encrypted_records.insert(record_hash, record);
    
    // Update counters
    let identity_count = audit_log.identity_record_count.get(identity_hash);
    audit_log.identity_record_count.insert(identity_hash, identity_count + 1);
    
    let unit_count = audit_log.unit_record_count.get(unit_id);
    audit_log.unit_record_count.insert(unit_id, unit_count + 1);
    
    record_hash
}

// Retrieve encrypted audit record
// (Anyone can retrieve, but only viewing key holder can decrypt)
#[public]
pub fn get_audit_record(
    record_hash: Field,
    audit_log: &AuditLog,
) -> Option<EncryptedZKLPRecord> {
    let record = audit_log.encrypted_records.get(record_hash);
    
    // Check if record exists (zklp_commitment != 0)
    if record.zklp_commitment != 0 {
        Option::some(record)
    } else {
        Option::none()
    }
}

// Get audit count for identity
#[public]
pub fn get_identity_audit_count(
    identity_hash: Field,
    audit_log: &AuditLog,
) -> Field {
    audit_log.identity_record_count.get(identity_hash)
}

// Get audit count for unit
#[public]
pub fn get_unit_audit_count(
    unit_id: Field,
    audit_log: &AuditLog,
) -> Field {
    audit_log.unit_record_count.get(unit_id)
}

// Helper: Pack ZKLP type and unit_id into single Field
fn pack_type_and_unit(zklp_type: ZKLPType, unit_id: Field) -> Field {
    // Simple packing: type in lower 8 bits, unit_id shifted
    let type_field = zklp_type.to_field();
    (unit_id * 256) + type_field
}

// Helper: Unpack ZKLP type and unit_id
pub fn unpack_type_and_unit(packed: Field) -> (ZKLPType, Field) {
    let type_field = packed % 256;
    let unit_id = packed / 256;
    (ZKLPType::from_field(type_field), unit_id)
}

// Helper: Encrypt data to public key
// Simplified - in production use proper encryption
fn encrypt_to_public_key(
    plaintext: [Field; 4],
    public_key: GrumpkinPoint,
    context: &PrivateContext,
) -> [Field; 4] {
    // Generate ephemeral key
    let ephemeral_secret = std::hash::pedersen_hash([
        context.block_number(),
        context.timestamp(),
    ]);
    
    // Derive shared secret (simplified)
    let shared_secret = std::hash::pedersen_hash([
        ephemeral_secret,
        public_key.x,
        public_key.y,
    ]);
    
    // XOR encryption (simplified - NOT for production)
    let mut encrypted = [0; 4];
    for i in 0..4 {
        encrypted[i] = plaintext[i] + shared_secret + i;  // Simplified "encryption"
    }
    
    encrypted
}

// Helper: Decrypt data (for off-chain use)
// This would be called client-side with the viewing private key
pub fn decrypt_with_private_key(
    encrypted: [Field; 4],
    private_key: Field,
    public_key: GrumpkinPoint,
) -> [Field; 4] {
    // Derive same shared secret
    let shared_secret = std::hash::pedersen_hash([
        private_key,
        public_key.x,
        public_key.y,
    ]);
    
    // XOR decryption
    let mut decrypted = [0; 4];
    for i in 0..4 {
        decrypted[i] = encrypted[i] - shared_secret - i;
    }
    
    decrypted
}

// Helper: Hash encrypted record
fn hash_encrypted_record(record: &EncryptedZKLPRecord) -> Field {
    std::hash::pedersen_hash([
        record.zklp_commitment,
        record.encrypted_data[0],
        record.encrypted_data[1],
        record.encrypted_data[2],
        record.encrypted_data[3],
        record.manager_public_key.x,
        record.manager_public_key.y,
    ])
}

// Batch create encrypted records
#[private]
pub fn batch_create_encrypted_records(
    zklps: [ZKLP; 10],
    identity: Identity,
    viewing_public_key: GrumpkinPoint,
    context: &mut PrivateContext,
) -> [EncryptedZKLPRecord; 10] {
    let mut records = [EncryptedZKLPRecord {
        zklp_commitment: 0,
        encrypted_data: [0; 4],
        manager_public_key: GrumpkinPoint::zero(),
    }; 10];
    
    for i in 0..10 {
        if zklps[i].nullifier != 0 {
            records[i] = create_encrypted_record(
                zklps[i],
                identity,
                viewing_public_key,
                context,
            );
        }
    }
    
    records
}

// Disclosure events

// Emitted when viewing key is registered
#[event]
struct ViewingKeyRegistered {
    entity_id: Field,
    public_key: GrumpkinPoint,
}

// Emitted when viewing key is rotated
#[event]
struct ViewingKeyRotated {
    entity_id: Field,
    old_public_key: GrumpkinPoint,
    new_public_key: GrumpkinPoint,
}

// Emitted when audit record is stored
#[event]
struct AuditRecordStored {
    record_hash: Field,
    zklp_commitment: Field,
    identity_hash: Field,
    unit_id: Field,
}

// Tests
#[test]
fn test_encryption_decryption() {
    let plaintext = [100, 200, 300, 400];
    let private_key = 12345;
    let public_key = GrumpkinPoint::new(111, 222);
    
    // Mock context
    let mut context = PrivateContext::new();
    
    // Encrypt
    let encrypted = encrypt_to_public_key(plaintext, public_key, &mut context);
    
    // Decrypt
    let decrypted = decrypt_with_private_key(encrypted, private_key, public_key);
    
    // Verify
    assert(decrypted[0] == plaintext[0]);
    assert(decrypted[1] == plaintext[1]);
    assert(decrypted[2] == plaintext[2]);
    assert(decrypted[3] == plaintext[3]);
}

#[test]
fn test_pack_unpack() {
    let unit_id = 1000;
    let zklp_type = ZKLPType::Entry;
    
    let packed = pack_type_and_unit(zklp_type, unit_id);
    let (unpacked_type, unpacked_unit) = unpack_type_and_unit(packed);
    
    assert(unpacked_unit == unit_id);
    assert(unpacked_type.to_field() == zklp_type.to_field());
}

#[test]
fn test_encrypted_record_creation() {
    let zklp = ZKLP {
        version: 1,
        nullifier: 12345,
        commitment: 67890,
        unit_id: 100,
        timestamp: 1000,
        zklp_type: ZKLPType::Entry,
    };
    
    let identity = Identity::new(54321);
    let viewing_key = GrumpkinPoint::new(111, 222);
    let mut context = PrivateContext::new();
    
    let record = create_encrypted_record(zklp, identity, viewing_key, &mut context);
    
    assert(record.zklp_commitment == zklp.commitment);
    assert(record.manager_public_key.x == viewing_key.x);
    assert(record.encrypted_data[0] != 0);  // Should be encrypted
}
