# ZKLP Protocol - Zero-Knowledge Location Proofs

A privacy-preserving protocol for proving physical presence at a location without revealing identity, location history, or temporal patterns. Built on the Aztec Network using Noir.

## What is ZKLP?

**ZKLP** (Zero-Knowledge Location Proof) enables:
- **Anonymous access control** - Prove you're authorized without revealing who you are
- **Non-transferable credentials** - Credentials bound to identity, useless if stolen
- **Replay protection** - Each proof can only be used once
- **Session management** - Track entry/exit without exposing patterns
- **Selective disclosure** - Authorized auditors can view encrypted records

## Core Concepts

### Identity & Credentials

```rust
// Create identity from master secret
let identity = Identity::new(master_secret);

// Derive credential for specific location
let credential = identity.derive_credential(unit_id);
```

### ZKLP Generation

```rust
// Generate proof of access (private function)
let zklp = generate_zklp(
    master_secret,      // Hidden
    merkle_proof,       // Hidden
    unit_id,            // Public
    unit_root,          // Public
    ZKLPType::Entry,    // Public
    context,
);
```

### ZKLP Verification

```rust
// Verify proof (public function)
let valid = verify_zklp(zklp, storage);
// Smart lock learns: "authorized person" ✓
// Smart lock learns: NOTHING about identity
```

## Repository Structure

```
aztec-zklp-protocol/
├── contracts/              # Noir smart contracts
│   ├── lib.nr             # Main library entry
│   ├── types.nr           # Core type definitions
│   ├── identity.nr        # Identity management
│   ├── zklp_core.nr       # generate_zklp, verify_zklp
│   ├── nullifiers.nr      # Replay protection
│   └── disclosure.nr      # Manager viewing keys
├── aztec-js/              # TypeScript SDK
│   ├── src/
│   │   ├── index.ts       # Main exports
│   │   ├── types.ts       # TypeScript types
│   │   ├── identity.ts    # Identity operations
│   │   ├── zklp.ts        # ZKLP generation/verification
│   │   └── nullifier.ts   # Session management
│   └── package.json
├── tests/                 # Test suite
├── docs/                  # Documentation
└── examples/              # Usage examples
    └── simple_access/     # Minimal example
```

## Installation

### Noir Contracts

Add to your `Nargo.toml`:

```toml
[dependencies]
zklp_protocol = { git = "https://github.com/[user]/aztec-zklp-protocol", tag = "v0.1.0" }
```

### TypeScript SDK

```bash
npm install @poa/zklp-protocol
```

## Usage

### TypeScript SDK

```typescript
import { 
  createIdentity, 
  generateZKLP, 
  verifyZKLP,
  ZKLPProver,
  ZKLPType 
} from '@poa/zklp-protocol';
import { PXE } from '@aztec/aztec.js';

// Create identity
const identity = createIdentity(masterSecret);

// Generate ZKLP
const inputs = {
  masterSecret,
  merkleProof,
  unitId,
  unitRoot,
  zklpType: ZKLPType.Entry,
};

const zklp = generateZKLP(inputs, { blockNumber, timestamp });

// Verify ZKLP
const valid = verifyZKLP({ zklp, unitId }, spentNullifiers);
```

### Noir Contracts

```rust
use zklp_protocol::{
    generate_zklp,
    verify_zklp,
    create_identity,
    Identity,
    ZKLP,
    ZKLPType,
};

#[private]
fn access_control(
    master_secret: Field,
    unit_id: Field,
    context: &mut PrivateContext,
) -> ZKLP {
    // Generate ZKLP for access
    let zklp = generate_zklp(
        master_secret,
        merkle_proof,
        merkle_indices,
        unit_id,
        unit_root,
        ZKLPType::General,
        context,
    );
    
    zklp
}
```

## Privacy Model

| Data | Verifier | Public Chain | Manager |
|------|----------|--------------|---------|
| Identity | ❌ Hidden | ❌ Hidden | ✅ Visible |
| Location | ✅ Known | ❌ Hidden | ✅ Visible |
| Timestamp | ✅ Known | ❌ Hidden | ✅ Visible |
| History | ❌ Hidden | ❌ Hidden | ✅ Visible |

## Architecture

```
┌────────────────────────────────────────────────────────┐
│                  EMPLOYEE DEVICE                       │
│  ┌────────────────────────────────────────────────┐    │
│  │ Master Secret (secure enclave)                 │    │
│  │ └── Derives credentials per location          │    │
│  └────────────────────────────────────────────────┘    │
└────────────────────────────────────────────────────────┘
                          │
                          ▼ Generates ZKLP
┌────────────────────────────────────────────────────────┐
│                   SMART LOCK                           │
│  Receives: ZKLP + Nullifier                            │
│  Verifies: verify_zklp()                               │
│  Learns:   "Authorized" ✓                              │
│  Action:   Grant access, store nullifier               │
└────────────────────────────────────────────────────────┘
                          │
                          ▼ Encrypted audit
┌────────────────────────────────────────────────────────┐
│                MANAGER DASHBOARD                       │
│  Decrypts: Viewing key required                        │
│  Sees:     Full audit trail                            │
└────────────────────────────────────────────────────────┘
```

## API Reference

### Core Functions

#### `generate_zklp`
Generates a Zero-Knowledge Location Proof.

**Parameters:**
- `master_secret: Field` - User's master secret (private)
- `merkle_proof: [Field; 32]` - Merkle membership proof (private)
- `merkle_indices: [bool; 32]` - Path indices (private)
- `unit_id: Field` - Target location (public)
- `unit_root: Field` - Merkle root of authorized credentials (public)
- `zklp_type: ZKLPType` - Entry, Exit, or General (public)

**Returns:** `ZKLP` - The generated proof

#### `verify_zklp`
Verifies a ZKLP.

**Parameters:**
- `zklp: ZKLP` - The proof to verify
- `storage: &mut ZKLPStorage` - Storage for nullifier tracking

**Returns:** `bool` - True if valid

### Types

```rust
struct ZKLP {
    version: Field,
    nullifier: Field,
    commitment: Field,
    unit_id: Field,
    timestamp: Field,
    zklp_type: ZKLPType,
}

enum ZKLPType {
    Entry,
    Exit,
    General,
}
```

## Development

### Prerequisites

- [Aztec Sandbox](https://docs.aztec.network/developers/getting-started)
- [Noir](https://noir-lang.org/docs/getting_started/installation)
- Node.js 18+

### Build

```bash
# Build Noir contracts
cd contracts
nargo build

# Build TypeScript SDK
cd ../aztec-js
npm install
npm run build
```

### Test

```bash
# Run Noir tests
nargo test

# Run TypeScript tests
npm test
```

## Security

### Threat Model

| Threat | Mitigation |
|--------|-----------|
| Stolen device | Credentials bound to master secret (biometric/PIN) |
| Replay attack | Nullifier prevents double-spending |
| Fake location | Units registered with public keys |
| Collusion | Smart lock doesn't know identity |
| Forgery | Cryptographic soundness of ZK circuits |

### Audit

This protocol has not yet been audited. Use at your own risk.

## License

MIT License - See [LICENSE](LICENSE) file

## Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

## Related Projects

- [POA Attendance](https://github.com/[user]/poa-attendance) - Attendance tracking using ZKLP
- [Aztec Network](https://aztec.network/) - Privacy-focused zk-rollup
- [Noir](https://noir-lang.org/) - ZK programming language

## Acknowledgments

- Aztec team for the Aztec.nr framework
- Noir team for the language and tooling
- Semaphore protocol for membership proof patterns

---

**ZKLP Protocol** - Privacy-preserving location proofs for the decentralized world.
