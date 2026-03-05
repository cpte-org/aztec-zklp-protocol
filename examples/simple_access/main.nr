// Simple Access Control Example
// Demonstrates basic ZKLP usage for door access

use aztec_zklp_protocol::{
    create_identity,
    generate_zklp,
    verify_zklp,
    ZKLPType,
    ZKLPStorage,
};

// Mock contract for door access
contract DoorAccess {
    // Storage
    storage {
        zklp_storage: ZKLPStorage,
        authorized_units: Map<Field, Field>,  // unit_id -> merkle_root
    }
    
    // Initialize contract with authorized units
    #[public]
    fn constructor(admin: Field) {
        storage.zklp_storage.admin = admin;
    }
    
    // Add authorized unit with credential Merkle root
    #[public]
    fn add_unit(unit_id: Field, credential_root: Field) {
        // Only admin can add units
        assert(context.msg_sender() == storage.zklp_storage.admin);
        storage.authorized_units.insert(unit_id, credential_root);
    }
    
    // Request access with ZKLP
    #[private]
    fn request_access(
        master_secret: Field,
        unit_id: Field,
        merkle_proof: [Field; 32],
        merkle_indices: [bool; 32],
    ) -> bool {
        // Get unit's credential root
        let unit_root = storage.authorized_units.get(unit_id);
        assert(unit_root != 0, "Unit not found");
        
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
        
        // Return ZKLP for public verification
        zklp.nullifier
    }
    
    // Verify access (called by door hardware)
    #[public]
    fn verify_access(
        zklp: ZKLP,
    ) -> bool {
        // Verify ZKLP
        let valid = verify_zklp(zklp, &mut storage.zklp_storage);
        
        if valid {
            // Emit access granted event
            emit AccessGranted(zklp.nullifier, zklp.unit_id);
        }
        
        valid
    }
}

// Event for successful access
#[event]
struct AccessGranted {
    nullifier: Field,
    unit_id: Field,
}

// Test scenario
#[test]
fn test_door_access_flow() {
    // 1. Setup - Admin creates unit
    let admin = 12345;
    let unit_id = 100;
    
    // Create credentials Merkle tree (simplified)
    let credential_hash = 67890;  // Hash of user's credential
    let merkle_root = credential_hash;  // Simplified: single credential
    
    // 2. User generates ZKLP
    let master_secret = 11111;
    let merkle_proof = [0; 32];
    let merkle_indices = [false; 32];
    
    // 3. Door verifies ZKLP
    // (In production, this would be full contract interaction)
}
