# zp-trust Code Overview

## Module Relationships

```
┌─────────────────────────────────────────────────────────────────┐
│                        zp-trust Library                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────┐  │
│  │   vault.rs       │  │  injector.rs     │  │  signer.rs   │  │
│  ├──────────────────┤  ├──────────────────┤  ├──────────────┤  │
│  │ CredentialVault  │  │ CredentialInj.   │  │ Signer       │  │
│  │ Encrypted Cred   │  │ PolicyContext    │  │ SignerResult │  │
│  │ VaultError       │  │ InjectorError    │  │ SignerError  │  │
│  │ VaultResult      │  │ InjectorResult   │  │              │  │
│  └────────┬─────────┘  └────────┬─────────┘  └──────────────┘  │
│           │                     │                               │
│           └─────────┬───────────┘                               │
│                     │                                           │
│            Skills / Applications                                │
│            (Use via lib.rs exports)                            │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Vault Module Flow

```
┌─────────────────────────────────┐
│  Application Code               │
│  vault.store("pwd", b"secret")  │
└──────────────┬──────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────────┐
│ CredentialVault::store()                                │
│  1. Generate random nonce (12 bytes)                   │
│  2. Create ChaCha20Poly1305 cipher                     │
│  3. Encrypt value with (nonce, value)                 │
│  4. Store EncryptedCredential in HashMap              │
└──────────────┬────────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────┐
│  HashMap<String,                │
│    EncryptedCredential {        │
│      nonce: [u8; 12],          │
│      ciphertext: Vec<u8>,      │
│    }                            │
│  >                              │
└─────────────────────────────────┘
       │
       │ (later)
       ▼
┌─────────────────────────────────────────────────────────┐
│ CredentialVault::retrieve()                             │
│  1. Find encrypted credential by name                  │
│  2. Create ChaCha20Poly1305 cipher (same key)         │
│  3. Decrypt with (nonce, ciphertext)                  │
│  4. Return plaintext Vec<u8>                          │
└──────────────┬────────────────────────────────────────┘
               │
               ▼
┌──────────────────────────────┐
│ Plaintext credential         │
│ Vec<u8> (automatic zeroize  │
│  when dropped)               │
└──────────────────────────────┘
```

## Injector Module Flow

```
┌──────────────────────────────────────────────────────┐
│  Application / Skill                                 │
│  injector.inject("skill-1", &["db-pwd"], &context)  │
└────────────────┬─────────────────────────────────────┘
                 │
                 ▼
    ┌────────────────────────────────────┐
    │ CredentialInjector::inject()       │
    │ For each credential_ref:           │
    └────────────────┬───────────────────┘
                     │
        ┌────────────┴────────────┐
        │                         │
        ▼                         ▼
┌──────────────────┐     ┌───────────────────────┐
│ PolicyCheck:     │     │ Vault::retrieve():    │
│ policy_check(    │     │                       │
│   skill_id,      │     │ Decrypt credential    │
│   cred_name,     │     │ from encrypted store  │
│   context        │     │                       │
│ )                │     │ Returns Vec<u8>      │
│                  │     │                       │
│ Allowed?         │     │ (on success)          │
│ ✓ Yes → Ok       │     │                       │
│ ✗ No  → PolicyDenied  │                       │
└──────┬───────────┘     └──────────┬────────────┘
       │                           │
       └────────────┬──────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────┐
│ Return HashMap<String, Vec<u8>>             │
│ {                                           │
│   "db-pwd": [decrypted plaintext],         │
│   ... (more credentials if multiple)       │
│ }                                           │
│                                             │
│ Auto-zeroized when HashMap dropped         │
└─────────────────────────────────────────────┘
```

## Signer Module Flow

### Key Generation
```
┌──────────────────────┐
│ Signer::generate()   │
└──────────┬───────────┘
           │
           ▼
┌────────────────────────────────┐
│ rand::thread_rng().fill_bytes  │
│ 32 bytes → seed                │
└────────────┬───────────────────┘
             │
             ▼
┌────────────────────────────────┐
│ SigningKey::generate()         │
│ (ed25519-dalek)                │
│ Produces:                      │
│  - Secret key (32 bytes)       │
│  - Verifying key (32 bytes)    │
└────────────┬───────────────────┘
             │
             ▼
┌────────────────────────────────┐
│ Signer {                       │
│   signing_key: SigningKey,     │
│   // auto-zeroizes on drop    │
│ }                              │
└────────────────────────────────┘
```

### Signing
```
┌──────────────────────────────┐
│ signer.sign(b"data")         │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│ signing_key.sign(data)       │
│ (Ed25519 deterministic)      │
│ Produces: Signature(64 bytes)│
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│ hex::encode(sig_bytes)       │
│ "a1b2c3d4..." (128 chars)    │
│ Returns: String              │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│ Hex-encoded signature        │
│ Ready for transmission       │
└──────────────────────────────┘
```

### Verification
```
┌────────────────────────────────────────┐
│ Signer::verify(pubkey, data, sig_hex) │
└───────────────┬────────────────────────┘
                │
        ┌───────┴────────┐
        │                │
        ▼                ▼
┌──────────────┐   ┌─────────────────┐
│ hex::decode  │   │ Validate sig    │
│ sig_hex      │   │ == 64 bytes     │
│              │   │                 │
│ -> [u8; 64]  │   │ Ok / InvalidFmt │
└──────┬───────┘   └────────┬────────┘
       │                    │
       └──────────┬─────────┘
                  │
                  ▼
       ┌──────────────────────┐
       │ VerifyingKey::from   │
       │ _bytes(pubkey)       │
       │                      │
       │ Create verifier      │
       └──────────┬───────────┘
                  │
                  ▼
       ┌──────────────────────────┐
       │ verifier.verify_strict() │
       │ (strict Ed25519)         │
       └──────────┬───────────────┘
                  │
        ┌─────────┴─────────┐
        │                   │
        ▼                   ▼
    ┌────────┐         ┌────────┐
    │ Ok(()) │         │ Err    │
    └───┬────┘         └───┬────┘
        │                  │
        ▼                  ▼
    ┌──────────┐      ┌──────────┐
    │ true     │      │ false    │
    │ (valid)  │      │ (invalid)│
    └──────────┘      └──────────┘
```

## Data Structures

### EncryptedCredential
```rust
pub struct EncryptedCredential {
    pub nonce: [u8; 12],        // Random nonce for this credential
    pub ciphertext: Vec<u8>,    // Encrypted data + auth tag
}
// Size: 12 + len(data) + 16 (auth tag) bytes
// Zeroized on drop
```

### PolicyContext
```rust
pub struct PolicyContext {
    pub boundary: String,                   // "prod-boundary", "dev-boundary"
    pub environment: Option<String>,        // "production", "staging", "dev"
    pub metadata: HashMap<String, String>,  // Custom key-value pairs
}
// Immutable after creation (no secrets)
```

## Error Handling Chain

```
Application Code
     │
     ▼ (calls library)
┌────────────────────┐
│ Library Function   │
└────┬───────────────┘
     │
     ▼ (may fail)
┌────────────────────────┐
│ Typed Error            │
│ (VaultError /          │
│  SignerError /         │
│  InjectorError)        │
└────┬───────────────────┘
     │
     ▼ (implements Display)
│ Descriptive message    │
│ via thiserror          │
└────────────────────────┘

Application chooses to:
  ✓ Handle specifically: match on error variant
  ✓ Propagate: ? operator
  ✓ Log & continue: .ok()
  ✓ Panic: .unwrap()
```

## Memory Safety

### Zeroization Points
```
Create Sensitive Data:
  ↓
Use Sensitive Data:
  ↓
Drop: {
  1. Call zeroize() on data
  2. Fill with zeros
  3. Release memory
}
```

### Credential Lifecycle
```
Store         Retrieve      Use           Drop
  │              │           │              │
  ▼              ▼           ▼              ▼
plaintext  encrypted    plaintext      ZEROIZED
(caller)   (vault)      (caller)       (auto)
```

## Concurrency Notes

**Current Design (v0.1.0):**
- Vault: Single-threaded, mutable reference required for store/remove
- Injector: Immutable reference to vault (read-only)
- Signer: Immutable reference to signing key

**Thread Safety:**
- CredentialVault: Not thread-safe (would need Arc<Mutex<>> for multi-threaded use)
- PolicyContext: Thread-safe (no interior mutability)
- Signer: Thread-safe if wrapped in Arc

**Future Versions:**
- RwLock<> for concurrent vault reads with exclusive writes
- Arc<CredentialVault> pattern support
- Async credential injection

## Testing Structure

```
Each module has #[cfg(test)] mod tests {
  - Helper functions (policies, contexts)
  - Individual test functions
  - Assertions on behavior
}

Coverage:
  ✓ Happy path (success cases)
  ✓ Error cases (all error variants)
  ✓ Edge cases (empty, missing, invalid)
  ✓ Security properties (isolation, zeroization)
```

## Public API Surface

```
lib.rs exports:
  ├── vault::CredentialVault
  ├── vault::EncryptedCredential
  ├── vault::VaultError / VaultResult
  │
  ├── injector::CredentialInjector
  ├── injector::PolicyContext
  ├── injector::PolicyCheckFn
  ├── injector::InjectorError / InjectorResult
  │
  └── signer::Signer
      signer::SignerError / SignerResult

All error types implement:
  ✓ std::error::Error
  ✓ Display
  ✓ Debug
  ✓ thiserror integration
```
