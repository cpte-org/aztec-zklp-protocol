// ZKLP Protocol - Core Types
// Zero-Knowledge Location Proof primitive types

use dep::aztec::protocol::traits::{Serialize, Deserialize, Packable};

// Global constants
pub global ZKLP_VERSION: Field = 1;
pub global MAX_UNITS_PER_IDENTITY: Field = 256;

// ZKLP Type constants (replaces enum)
pub global ZKLP_TYPE_ENTRY: Field = 1;
pub global ZKLP_TYPE_EXIT: Field = 2;
pub global ZKLP_TYPE_GENERAL: Field = 3;

// Identity structure - master secret derivation
#[derive(Serialize, Deserialize)]
pub struct Identity {
    pub master_secret: Field,
    pub public_key_x: Field,
    pub public_key_y: Field,
    pub identity_hash: Field,
}

// Credential - proof of authorization for a specific unit
#[derive(Serialize, Deserialize)]
pub struct Credential {
    pub unit_id: Field,
    pub credential_secret: Field,
    pub credential_hash: Field,
    pub identity_hash: Field,
}

// ZKLP - Zero-Knowledge Location Proof
#[derive(Serialize, Deserialize, Packable)]
pub struct ZKLP {
    pub version: Field,
    pub nullifier: Field,
    pub commitment: Field,
    pub unit_id: Field,
    pub timestamp: Field,
    pub zklp_type: Field,
}

// Session - tracks active ZKLP sessions
#[derive(Serialize, Deserialize, Packable)]
pub struct Session {
    pub session_id: Field,
    pub nullifier: Field,
    pub unit_id: Field,
    pub entry_timestamp: Field,
    pub active: bool,
}

// Encrypted audit record for manager viewing
#[derive(Serialize, Deserialize)]
pub struct EncryptedZKLPRecord {
    pub zklp_commitment: Field,
    pub encrypted_data: [Field; 4],
    pub manager_public_key_x: Field,
    pub manager_public_key_y: Field,
}

// ZKLP Type enum for TypeScript compatibility
pub struct ZKLPType {}

impl ZKLPType {
    pub fn Entry() -> Field { ZKLP_TYPE_ENTRY }
    pub fn Exit() -> Field { ZKLP_TYPE_EXIT }
    pub fn General() -> Field { ZKLP_TYPE_GENERAL }
}
