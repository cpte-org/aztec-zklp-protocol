// ZKLP Protocol Library
// Re-exports for library usage

pub mod types;
pub mod identity;
pub mod nullifiers;
pub mod unit;

// Re-export commonly used types
pub use types::{
    Identity,
    Credential,
    ZKLP,
    Session,
    EncryptedZKLPRecord,
    ZKLP_VERSION,
    MAX_UNITS_PER_IDENTITY,
    ZKLP_TYPE_ENTRY,
    ZKLP_TYPE_EXIT,
    ZKLP_TYPE_GENERAL,
};

// Re-export identity types
pub use identity::{
    IdentityRecord,
    IdentityRegistry,
};

// Re-export nullifier types
pub use nullifiers::{
    NullifierSet,
    SessionRegistry,
};
