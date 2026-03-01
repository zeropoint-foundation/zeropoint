# zp-trust Feature Matrix

## Credential Vault

| Feature | Status | Details |
|---------|--------|---------|
| Encrypted Storage | ✓ Complete | ChaCha20-Poly1305 with random nonces |
| Master Key Support | ✓ Complete | 32-byte key with direct usage |
| Store Credentials | ✓ Complete | Encrypt and store in HashMap |
| Retrieve Credentials | ✓ Complete | Decrypt on-demand access |
| Remove Credentials | ✓ Complete | Delete from vault |
| List Credentials | ✓ Complete | Returns names only, never values |
| Zeroization | ✓ Complete | Automatic on drop via Zeroize trait |
| In-Memory Storage | ✓ Complete | HashMap<String, EncryptedCredential> |
| SQLite Persistence | ⏳ Planned | Future version |
| Key Rotation | ⏳ Planned | Credential re-encryption with new master key |
| Credential Expiry | ⏳ Planned | TTL-based credential invalidation |
| Audit Logging | ⏳ Planned | Persistent access log |

## Credential Injector

| Feature | Status | Details |
|---------|--------|---------|
| Policy-Based Access | ✓ Complete | Custom policy function per injector |
| Single Credential Injection | ✓ Complete | inject_single() method |
| Batch Injection | ✓ Complete | inject() accepts multiple credentials |
| Boundary Enforcement | ✓ Complete | PolicyContext with boundary field |
| Environment Validation | ✓ Complete | Optional environment in context |
| Metadata Support | ✓ Complete | HashMap<String, String> metadata |
| Access Logging | ✓ Complete | Tracing integration, names only |
| Fail-Secure | ✓ Complete | Policy checked before vault access |
| Context Validation | ✓ Complete | Prevents empty boundaries |
| Builder Pattern | ✓ Complete | Fluent API for PolicyContext |
| Scope-Based Access | ⏳ Planned | Credential access scoping |
| Time-Based Policies | ⏳ Planned | Access windows |
| RBAC Integration | ⏳ Planned | Role-based rule engine |

## Cryptographic Signer

| Feature | Status | Details |
|---------|--------|---------|
| Key Generation | ✓ Complete | Random keypair via OsRng |
| Key Recovery | ✓ Complete | from_secret() from 32-byte key |
| Signing | ✓ Complete | Ed25519 deterministic signatures |
| Signature Verification | ✓ Complete | Static verify() with public key |
| Hex Encoding | ✓ Complete | Signatures as hex strings |
| Strict Verification | ✓ Complete | Rejects weak public keys |
| Determinism | ✓ Complete | Same input → same signature |
| Public Key Access | ✓ Complete | public_key() returns [u8; 32] |
| Secret Key Access | ✓ Complete | secret_key() for serialization |
| Zeroization | ✓ Complete | Automatic on drop |
| Batch Signing | ⏳ Planned | Sign multiple messages efficiently |
| Key Derivation | ⏳ Planned | KDF from passphrases |
| HSM Integration | ⏳ Planned | Hardware security module support |
| Key Rotation | ⏳ Planned | Safe key versioning |

## Security Features

| Feature | Status | Implementation |
|---------|--------|-----------------|
| AEAD Encryption | ✓ Complete | ChaCha20-Poly1305 with auth tags |
| Random Nonces | ✓ Complete | 12-byte per-credential nonce |
| Deterministic Signing | ✓ Complete | Ed25519 (RFC 8032) |
| Zeroization | ✓ Complete | Zeroize crate on drop |
| CSPRNG | ✓ Complete | rand::thread_rng for nonces |
| Error Handling | ✓ Complete | Typed errors with thiserror |
| No Plaintext Logs | ✓ Complete | Access logs never include values |
| Fail-Secure | ✓ Complete | Policy-first access control |
| Strict Verification | ✓ Complete | Ed25519 strict mode |

## Error Handling

### Vault Errors
| Error | Cause | Handling |
|-------|-------|----------|
| EncryptionFailed | Cipher operation | Check master key validity |
| DecryptionFailed | Auth tag mismatch | Data corruption or wrong key |
| CredentialNotFound | Missing credential | Verify credential name |
| InvalidKeyMaterial | Bad key format | Check key is 32 bytes |

### Signer Errors
| Error | Cause | Handling |
|-------|-------|----------|
| VerificationFailed | Weak public key | Use stronger key |
| InvalidSignatureFormat | Bad hex or size | Check signature encoding |
| InvalidKeyMaterial | Bad key format | Verify key is 32 bytes |
| SigningFailed | Operation error | Retry or check data size |

### Injector Errors
| Error | Cause | Handling |
|-------|-------|----------|
| PolicyDenied | Policy rejected | Check credentials, boundary, role |
| VaultError | Wrapped vault error | See vault errors |
| CredentialMissing | Not in vault | Store credential first |
| InvalidContext | Bad context | Ensure boundary non-empty |

## Testing Coverage

| Module | Tests | Coverage |
|--------|-------|----------|
| vault.rs | 6 tests | Store/retrieve, list, remove, isolation |
| signer.rs | 6 tests | Generate, sign/verify, determinism |
| injector.rs | 7 tests | Access, policy, context, batch |
| **Total** | **19 tests** | **100% of public APIs** |

## Dependencies

### Core Cryptography
- `ed25519-dalek`: Ed25519 signatures
- `chacha20poly1305`: AEAD encryption

### Data & Memory Safety
- `serde` + `serde_json`: Serialization
- `zeroize`: Sensitive data cleanup
- `rand`: Random number generation

### Error & Logging
- `thiserror`: Error types
- `tracing`: Structured logging

### Utilities
- `hex`: Hex encoding/decoding
- `blake3`: Future hashing use

## Workspace Dependencies

All non-path dependencies use workspace versions for consistency:
```toml
[workspace]
members = ["crates/zp-core", "crates/zp-trust", ...]

[workspace.dependencies]
ed25519-dalek = "2.x"
chacha20poly1305 = "0.10"
zeroize = { version = "1.x", features = ["derive"] }
rand = "0.8"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
thiserror = "1.0"
tracing = "0.1"
hex = "0.4"
blake3 = "1.x"
```

## Performance Profile

| Operation | Complexity | Notes |
|-----------|-----------|-------|
| Store | O(m) | m = credential size |
| Retrieve | O(m) | Decryption cost |
| List | O(n) | n = credential count |
| Remove | O(1) | HashMap deletion |
| Sign | O(n) | n = data size |
| Verify | O(n) | Signature validation |
| Inject | O(k*m) | k = credential count, m = avg size |

## Compliance & Standards

| Standard | Support |
|----------|---------|
| RFC 8032 (Ed25519) | ✓ Full compliance |
| AEAD (NIST) | ✓ ChaCha20-Poly1305 |
| OWASP Secrets | ✓ Encrypted at rest |
| OWASP Auth | ✓ Policy-based control |
| Rust Safety | ✓ No unsafe code |

## Future Roadmap

### v0.2.0
- [ ] SQLite persistence for vault
- [ ] Credential metadata and TTL
- [ ] Audit log export

### v0.3.0
- [ ] RBAC policy engine
- [ ] Time-based access control
- [ ] Scope restrictions

### v0.4.0
- [ ] HSM integration
- [ ] Master key rotation
- [ ] Distributed key generation

### v0.5.0
- [ ] Encrypted backup/restore
- [ ] Credential sharing between boundaries
- [ ] Metrics and observability
