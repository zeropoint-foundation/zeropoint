# zp-trust Documentation Index

Welcome to the zp-trust crate documentation. This index helps you find the right documentation for your needs.

## Quick Navigation

### For First-Time Users
1. **[README.md](README.md)** - Start here! Overview of the crate and its components
2. **[QUICKSTART.md](QUICKSTART.md)** - Code examples and usage patterns
3. **Run the tests**: `cargo test --lib`

### For Developers
1. **[CODE_OVERVIEW.md](CODE_OVERVIEW.md)** - Architecture, data flows, and design decisions
2. **[IMPLEMENTATION.md](IMPLEMENTATION.md)** - Technical details of each module
3. **[src/lib.rs](src/lib.rs)** - Module declarations and public API
4. **In-code documentation** - Full docstrings in .rs files

### For Reviewers & Maintainers
1. **[BUILD_SUMMARY.md](BUILD_SUMMARY.md)** - Build statistics and completion status
2. **[REQUIREMENTS_CHECKLIST.md](REQUIREMENTS_CHECKLIST.md)** - All requirements verification
3. **[FEATURES.md](FEATURES.md)** - Feature matrix and roadmap
4. **[PROJECT_STRUCTURE.txt](PROJECT_STRUCTURE.txt)** - Visual project layout

## Documentation Files by Purpose

### User Documentation
| File | Purpose | Best For |
|------|---------|----------|
| [README.md](README.md) | Overview and API examples | Getting started |
| [QUICKSTART.md](QUICKSTART.md) | Code patterns and recipes | Implementing features |

### Technical Documentation
| File | Purpose | Best For |
|------|---------|----------|
| [CODE_OVERVIEW.md](CODE_OVERVIEW.md) | Architecture and flows | Understanding design |
| [IMPLEMENTATION.md](IMPLEMENTATION.md) | Module internals | Deep technical review |
| [FEATURES.md](FEATURES.md) | Feature matrix | Checking status/roadmap |

### Project Documentation
| File | Purpose | Best For |
|------|---------|----------|
| [BUILD_SUMMARY.md](BUILD_SUMMARY.md) | Build metrics | Project overview |
| [REQUIREMENTS_CHECKLIST.md](REQUIREMENTS_CHECKLIST.md) | Requirement verification | QA/Release |
| [PROJECT_STRUCTURE.txt](PROJECT_STRUCTURE.txt) | Visual layout | Project overview |
| [INDEX.md](INDEX.md) | Documentation index | Navigation (this file) |

## Source Files by Component

### Core Modules

#### Credential Vault (`src/vault.rs`)
- **Purpose**: Secure encrypted credential storage at rest
- **Key Type**: `CredentialVault`
- **Key Methods**: `new()`, `store()`, `retrieve()`, `remove()`, `list()`
- **Encryption**: ChaCha20-Poly1305 with random nonces
- **Tests**: 6 unit tests

#### Cryptographic Signer (`src/signer.rs`)
- **Purpose**: Ed25519 signing infrastructure for trust tiers
- **Key Type**: `Signer`
- **Key Methods**: `generate()`, `from_secret()`, `sign()`, `verify()`, `public_key()`
- **Algorithm**: Ed25519 deterministic signatures
- **Tests**: 6 unit tests

#### Credential Injector (`src/injector.rs`)
- **Purpose**: Policy-based credential injection with access control
- **Key Type**: `CredentialInjector`
- **Key Methods**: `new()`, `inject()`, `inject_single()`
- **Policy**: Custom policy functions for fine-grained control
- **Tests**: 7 unit tests

#### Library Root (`src/lib.rs`)
- **Purpose**: Module organization and public API
- **Contents**: Module declarations and re-exports
- **Documentation**: Crate-level docs with component overview

## Common Tasks

### Learning the API
1. Read [README.md](README.md) for component overview
2. Browse [QUICKSTART.md](QUICKSTART.md) for code examples
3. Check in-code documentation with `cargo doc --open`

### Implementing a Feature
1. Review [CODE_OVERVIEW.md](CODE_OVERVIEW.md) for architecture
2. Study [QUICKSTART.md](QUICKSTART.md) for patterns
3. Examine test cases in relevant module
4. Follow the same patterns

### Contributing Code
1. Read [IMPLEMENTATION.md](IMPLEMENTATION.md) for details
2. Check test coverage in relevant module
3. Ensure error handling matches existing patterns
4. Add tests for new functionality

### Reviewing Code
1. Check [REQUIREMENTS_CHECKLIST.md](REQUIREMENTS_CHECKLIST.md)
2. Verify against [FEATURES.md](FEATURES.md) feature matrix
3. Review [CODE_OVERVIEW.md](CODE_OVERVIEW.md) for design
4. Run `cargo test --lib` and `cargo clippy`

### Preparing Release
1. Update version in [Cargo.toml](Cargo.toml)
2. Review [BUILD_SUMMARY.md](BUILD_SUMMARY.md) for metrics
3. Verify [REQUIREMENTS_CHECKLIST.md](REQUIREMENTS_CHECKLIST.md)
4. Update [FEATURES.md](FEATURES.md) roadmap if needed
5. Run full test suite

## Documentation Conventions

### Code Examples
- Inline examples shown with `///` doc comments
- Full examples in QUICKSTART.md
- Test cases show API usage

### Error Handling
- Each module has typed `Error` enum (VaultError, SignerError, InjectorError)
- Each module has `Result<T>` type alias
- See [IMPLEMENTATION.md](IMPLEMENTATION.md#error-handling) for error types

### Security Notes
- Marked with security property descriptions
- See [FEATURES.md](FEATURES.md#security-features) for overview
- Zeroization details in [CODE_OVERVIEW.md](CODE_OVERVIEW.md#memory-safety)

## Module Dependencies

```
lib.rs (module root)
├── vault.rs
│   ├── chacha20poly1305 (encryption)
│   ├── zeroize (memory safety)
│   ├── rand (random nonce generation)
│   └── serde (serialization)
│
├── signer.rs
│   ├── ed25519-dalek (signing)
│   ├── zeroize (memory safety)
│   └── rand (key generation)
│
└── injector.rs
    ├── vault (credential retrieval)
    ├── tracing (audit logging)
    └── serde (context serialization)
```

## Testing Guide

### Running Tests
```bash
# All tests
cargo test --lib

# Specific module
cargo test --lib vault
cargo test --lib signer
cargo test --lib injector

# Verbose output
cargo test --lib -- --nocapture
```

### Test Organization
Each module has:
- Helper functions for common setups
- Test for happy path
- Tests for error cases
- Tests for edge cases
- Security property tests

See [IMPLEMENTATION.md#testing-strategy](IMPLEMENTATION.md#testing-strategy) for details.

## API Reference

### Quick Reference
- **Vault**: `CredentialVault`, `EncryptedCredential`, `VaultError`, `VaultResult`
- **Signer**: `Signer`, `SignerError`, `SignerResult`
- **Injector**: `CredentialInjector`, `PolicyContext`, `PolicyCheckFn`, `InjectorError`, `InjectorResult`

### Full Reference
For complete API documentation, run:
```bash
cargo doc --open
```

This generates and opens HTML documentation from code comments.

## Frequently Asked Questions

### Q: How do I use the credential vault?
**A**: See [QUICKSTART.md - Basic Usage](QUICKSTART.md#1-initialize-vault-and-store-credentials)

### Q: How do I define a policy?
**A**: See [QUICKSTART.md - Inject Credentials with Policy](QUICKSTART.md#2-inject-credentials-with-policy)

### Q: How are credentials encrypted?
**A**: See [CODE_OVERVIEW.md - Vault Module Flow](CODE_OVERVIEW.md#vault-module-flow)

### Q: What happens on drop?
**A**: See [CODE_OVERVIEW.md - Memory Safety](CODE_OVERVIEW.md#memory-safety)

### Q: Is this production-ready?
**A**: Yes! See [BUILD_SUMMARY.md - Production Readiness](BUILD_SUMMARY.md#production-readiness)

### Q: What's the roadmap?
**A**: See [FEATURES.md - Future Roadmap](FEATURES.md#future-roadmap)

## Getting Help

1. **API Questions**: Check [README.md](README.md) and in-code documentation
2. **Usage Examples**: See [QUICKSTART.md](QUICKSTART.md)
3. **Technical Details**: Read [IMPLEMENTATION.md](IMPLEMENTATION.md)
4. **Architecture**: Review [CODE_OVERVIEW.md](CODE_OVERVIEW.md)
5. **Test Cases**: Study relevant test module

## Document Versions

All documentation is current as of:
- **Build Date**: February 21, 2026
- **Version**: zp-trust v0.1.0
- **Status**: Production-Ready

See [BUILD_SUMMARY.md](BUILD_SUMMARY.md) for build information.

## Related Documentation

This crate is part of the ZeroPoint v2 project:
- **zp-core**: Core types and traits (path dependency)
- **Other crates**: See workspace root documentation

## Feedback & Improvements

Documentation locations:
- **API Docs**: In-code comments in `src/*.rs`
- **User Guide**: [README.md](README.md) and [QUICKSTART.md](QUICKSTART.md)
- **Technical**: [IMPLEMENTATION.md](IMPLEMENTATION.md)
- **Architecture**: [CODE_OVERVIEW.md](CODE_OVERVIEW.md)

---

**Last Updated**: February 21, 2026
**Crate**: zp-trust v0.1.0
**Status**: COMPLETE
