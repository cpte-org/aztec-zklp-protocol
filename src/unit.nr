// ZKLP Protocol - Unit (Location) Types

use dep::aztec::protocol::traits::{Serialize, Deserialize, Packable};

// Unit structure for storage
#[derive(Serialize, Deserialize, Packable)]
pub struct Unit {
    pub unit_id: Field,
    pub unit_public_key_x: Field,
    pub unit_public_key_y: Field,
    pub credential_tree_root: Field,
    pub metadata_hash: Field,
    pub active: bool,
}

impl Unit {
    pub fn new(
        unit_id: Field,
        unit_public_key_x: Field,
        unit_public_key_y: Field,
        credential_tree_root: Field,
        metadata_hash: Field,
    ) -> Self {
        Self {
            unit_id,
            unit_public_key_x,
            unit_public_key_y,
            credential_tree_root,
            metadata_hash,
            active: true,
        }
    }
}
