# zp-trust: ZeroPoint Trust Infrastructure

The trust infrastructure crate for ZeroPoint v2, providing secure credential vault management, policy-based credential injection, and cryptographic signing for trust tiers.

## Components

### 1. Credential Vault (`vault.rs`)

Secure encrypted storage for credentials at rest.

**Features:**
- ChaCha20-Poly1305 authenticated encryption
- Per-credential random nonces for semantic security
- Automatic zeroization of sensitive data on drop
- In-memory HashMap storage (SQLite persistence planned)

**API:**
```rust
let master_key = &[0u8; 32];
let mut vault = CredentialVault::new(master_key);

// Store encrypted credentials
vault.store("db-password", b"super-secret")?;

// Retrieve and decrypt
let plaintext = vault.retrieve("db-password")?;

// List credential names (not values)
let names = vault.list();

// Remove credentials
vault.remove("db-password")?;
```

### 2. Credential Injector (`injector.rs`)

Policy-based credential injection for controlled skill access.

**Features:**
- Fine-grained access control via policy functions
- Host-boundary enforcement through PolicyContext
- Audit logging of credential access (names only, never values)
- Support for single and batch credential injection

**API:**
```rust
// Define a policy function
fn my_policy(skill_id: &str, credential: &str, context: &PolicyContext) -> InjectorResult<()> {
    if skill_id == "trusted-skill" && credential.starts_with("public-") {
        Ok(())
    } else {
        Err(InjectorError::PolicyDenied("access denied".to_string()))
    }
}

let injector = CredentialInjector::new(&vault, my_policy);

let context = PolicyContext::new("prod-boundary".to_string())
    .with_environment("production".to_string());

// Inject single credential
let cred = injector.inject_single("skill-id", "cred-name", &context)?;

// Inject multiple credentials
let creds = injector.inject("skill-id", &["cred1", "cred2"], &context)?;
```

### 3. Signer (`signer.rs`)

Ed25519 cryptographic signing infrastructure for trust tiers.

**Features:**
- Deterministic signing using Ed25519
- Hex-encoded signature representation
- Key generation and key recovery from bytes
- Signature verification with strict variant

**API:**
```rust
// Generate new keypair
let signer = Signer::generate();

// Or from existing secret
let secret = &[0u8; 32];
let signer = Signer::from_secret(secret)?;

// Sign data
let signature = signer.sign(b"data to sign");

// Verify with public key
let public_key = signer.public_key();
let is_valid = Signer::verify(&public_key, b"data to sign", &signature)?;
```

## Security Guarantees

1. **Confidentiality**: All credentials encrypted with ChaCha20-Poly1305 using unique nonces
2. **Authentication**: Poly1305 authentication tags prevent tampering
3. **Zeroization**: All sensitive data zeroized on drop via `Zeroize` trait
4. **Audit Trail**: Access logging without exposing credential values
5. **Deterministic Signing**: Ed25519 produces reproducible signatures

## Architecture

### Host-Boundary Injection

Skills request credentials through the injector, which:
1. Checks the requesting skill against the PolicyContext boundary
2. Evaluates the policy function for each credential
3. Retrieves and decrypts only authorized credentials
4. Returns a HashMap for immediate use (credentials dropped after use)

This ensures credentials are never stored in skill memory but injected at request time.

### Credential Lifecycle

```
Store -> Encrypted in Vault -> Policy Check -> Inject -> Use -> Drop (zeroized)
```

## Dependencies

- `ed25519-dalek`: Ed25519 signing and verification
- `chacha20poly1305`: AEAD encryption for vault
- `zeroize`: Automatic sensitive data cleanup
- `rand`: Cryptographically secure random generation
- `tracing`: Structured logging for access audit
- `serde`/`serde_json`: Serialization support
- `thiserror`: Error handling

## Testing

All modules include comprehensive test suites:

```bash
cargo test --lib
```

Tests cover:
- Credential storage, retrieval, and removal
- Encryption isolation (different nonces)
- Policy enforcement (allow, deny, invalid context)
- Signature generation and verification
- Cross-verification with static methods

## Future Enhancements

- SQLite persistence for credential vault
- Hardware security module (HSM) integration for master key
- Cryptographic key rotation
- Audit log export
- Role-based access control (RBAC) policies
- Credential refresh/rotation triggers
