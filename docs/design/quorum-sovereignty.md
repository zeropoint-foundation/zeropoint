# Quorum Sovereignty Direction

## Architecture Direction: Multi-Signing / Quorum Sovereignty

The sovereignty provider system should be designed from the ground up for multi-device quorum support (e.g., 2-of-3 Trezors, or 1 Trezor + 1 YubiKey). Architectural implications:

| Area | Current (1:1) | Target (M-of-N) |
|------|---------------|------------------|
| **Enrollment** | One device, one `{mode}_enrollment.json` | Multiple enrolled devices, each with own enrollment + share |
| **Wrapping** | Single wrapping key encrypts Genesis | Shamir Secret Sharing or threshold encryption across N devices |
| **Ceremony** | One device confirms | M-of-N devices must confirm (sequential or parallel) |
| **Recovery** | 24-word BIP-39 mnemonic | Mnemonic covers the combined secret; individual device loss tolerated if M threshold met |
| **Storage** | `{mode}_genesis.encrypted` | Per-device share files + quorum metadata |
| **Provider trait** | `save_secret(&[u8; 32])` takes whole secret | Needs `save_share(share: &Share, quorum: &QuorumConfig)` |

**Near-term**: Don't break the 1:1 path — it's correct for personal sovereignty. But keep the door open:
- `EnrollmentMetadata.provider_data` should anticipate quorum fields (share_index, threshold, quorum_id)
- File naming should tolerate multiple enrollments per mode (`trezor_0_enrollment.json`, `trezor_1_enrollment.json`)
- The `SovereigntyProvider` trait may need a `QuorumProvider` extension trait rather than modifying the base trait

**Key decision**: Shamir Secret Sharing (split Genesis into shares) vs. threshold signatures (each device signs independently, combine). SSS is simpler for wrapping key derivation; threshold sigs are more powerful for agent certificate issuance. Both may be needed at different layers.

## HW Wallet Architecture Notes

**Shared infrastructure** (`sovereignty/hardware/mod.rs`): Provides `encrypt_secret`/`decrypt_secret` (ChaCha20-Poly1305 with deterministic BLAKE3 nonce), `EnrollmentMetadata`, and file I/O for `{mode}_enrollment.json` + `{mode}_genesis.encrypted`. Each device only needs to produce a 32-byte wrapping key.

**Feature-aware readiness**: Only Trezor has `cfg!(feature = "hw-trezor")` → `Ready` in `implementation_status()`. When YubiKey/Ledger/OnlyKey get implemented, each needs the same pattern. Consider a macro to reduce copy-paste.

**Enrollment `provider_data`**: Currently untyped `serde_json::Value`. Works for v0.1 but should evolve to a `ProviderData` enum with per-device variants for compile-time safety when multiple devices are in play.

## Deferred HW Wallet Tasks

| Item | Context |
|------|---------|
| **Trezor passphrase support** | `derive_wrapping_key()` auto-responds with empty string to `PassphraseRequest`. Add passphrase prompt path for users with passphrase-protected wallets. Consider TrezorConnect web bridge for richer device interaction |
| **Touch ID v0.2 (Secure Enclave)** | Replace `bioutil -w` application-layer check with `security-framework` crate using `kSecAccessControlBiometryCurrentSet` for OS-level enforcement |
| **Face enrollment v0.2** | Replace BLAKE3 pixel hashing with proper face embeddings (FaceNet/ArcFace via ONNX) for lighting-invariant matching |
| **Windows Hello v0.2 (native WinRT)** | Replace PowerShell shims with `windows` crate WinRT bindings for `UserConsentVerifier` and `KeyCredentialManager`. Direct TPM-backed key creation with biometric access policy |
| **YubiKey v0.3** | FIDO2 hmac-secret extension for wrapping key derivation. Needs `ctap-hid-fido2` + `hidapi` crates. Resident credential creation, credential ID persistence, feature-aware `Ready` status like Trezor |
| **Ledger v0.3** | BIP-32 derivation via APDU commands. Needs `ledger-transport-hid` + `ledger-apdu` crates. Key export API unclear — may need HMAC-based derivation instead of raw key |
| **OnlyKey v0.3** | HMAC-SHA1 challenge-response via configured slot. Simplest protocol after Trezor CipherKeyValue — good next candidate |
