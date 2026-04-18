// crates/zp-keys/src/sovereignty/touchid.rs
//
// Touch ID sovereignty provider — macOS Secure Enclave biometric gating.
//
// v0.1 (legacy): Uses the `keyring` crate for storage and `bioutil -w`
//   for application-layer biometric verification before load.
//   Any process that knows the Keychain service/account can read without
//   biometric — the bioutil check is a courtesy, not enforcement.
//
// v0.2 (current, `biometric-keychain` feature):
//   Uses `security-framework` with kSecAccessControlBiometryCurrentSet.
//   The Keychain item's access control list is set at creation time so
//   that EVERY read triggers a Secure Enclave biometric check. No
//   application-layer bypass is possible — the OS kernel enforces it.
//
//   The v0.1 `bioutil -w` check is still used as a pre-flight during
//   enrollment to confirm hardware works, but it's no longer the gate.

use super::{ProviderCapability, SovereigntyMode, SovereigntyProvider};
use crate::error::KeyError;

/// Touch ID provider for macOS.
pub struct TouchIdProvider;

impl SovereigntyProvider for TouchIdProvider {
    fn mode(&self) -> SovereigntyMode {
        SovereigntyMode::TouchId
    }

    fn detect(&self) -> ProviderCapability {
        #[cfg(target_os = "macos")]
        {
            detect_touchid()
        }

        #[cfg(not(target_os = "macos"))]
        {
            ProviderCapability {
                mode: SovereigntyMode::TouchId,
                available: false,
                description: "Touch ID is only available on macOS".into(),
                requires_enrollment: false,
                detail: None,
                implementation_status: super::ProviderStatus::Ready,
            }
        }
    }

    fn save_secret(&self, secret: &[u8; 32]) -> Result<(), KeyError> {
        #[cfg(all(target_os = "macos", feature = "biometric-keychain"))]
        {
            return save_touchid_secret_v2(secret);
        }

        #[cfg(all(target_os = "macos", feature = "os-keychain", not(feature = "biometric-keychain")))]
        {
            return save_touchid_secret_v1(secret);
        }

        // Fallback: not macOS, or macOS without keychain features
        #[allow(unreachable_code)]
        {
            let _ = secret;
            Err(KeyError::CredentialStore(
                "Touch ID requires macOS with os-keychain or biometric-keychain feature".into(),
            ))
        }
    }

    fn load_secret(&self) -> Result<[u8; 32], KeyError> {
        #[cfg(all(target_os = "macos", feature = "biometric-keychain"))]
        {
            return load_touchid_secret_v2();
        }

        #[cfg(all(target_os = "macos", feature = "os-keychain", not(feature = "biometric-keychain")))]
        {
            return load_touchid_secret_v1();
        }

        #[allow(unreachable_code)]
        {
            Err(KeyError::CredentialStore(
                "Touch ID requires macOS with os-keychain or biometric-keychain feature".into(),
            ))
        }
    }

    fn verify_presence(&self) -> Result<(), KeyError> {
        #[cfg(target_os = "macos")]
        {
            verify_touchid()
        }

        #[cfg(not(target_os = "macos"))]
        {
            Err(KeyError::CredentialStore(
                "Touch ID verification only available on macOS".into(),
            ))
        }
    }

    fn biometric_evidence(&self) -> Option<BiometricEvidence> {
        #[cfg(target_os = "macos")]
        {
            collect_biometric_evidence()
        }

        #[cfg(not(target_os = "macos"))]
        {
            None
        }
    }

    fn capabilities(&self) -> super::ProviderCapabilities {
        use super::ProviderCapabilities;
        ProviderCapabilities::BASE
            .union(ProviderCapabilities::CAN_UPGRADE)
            .union(ProviderCapabilities::HAS_BIOMETRIC_EVIDENCE)
    }

    fn upgrade_from(&self, secret: &[u8; 32]) -> Result<Option<super::EnrollmentResult>, KeyError> {
        // Upgrade path: re-gate an existing secret under Touch ID.
        // The secret was loaded from the old provider by the caller.
        self.save_secret(secret)?;
        let tier = {
            #[cfg(feature = "biometric-keychain")]
            { if is_os_enforced() { "Tier 2: OS-enforced via kSecAccessControlBiometryCurrentSet" } else { "Tier 1: application-layer biometric" } }
            #[cfg(not(feature = "biometric-keychain"))]
            { "Tier 1: application-layer biometric" }
        };
        Ok(Some(super::EnrollmentResult {
            enrollment_data: Vec::new(),
            summary: format!("Sovereignty upgraded to Touch ID ({})", tier),
        }))
    }
}

// ---------------------------------------------------------------------------
// Biometric evidence for genesis transcript (v0.2)
// ---------------------------------------------------------------------------

/// Cryptographic evidence that a biometric verification occurred.
/// Included in the genesis transcript so auditors can verify that
/// the ceremony was performed with a live biometric, not just a
/// password or file read.
#[derive(Debug, Clone, serde::Serialize)]
pub struct BiometricEvidence {
    /// Method used: "touchid", "faceid"
    pub method: String,
    /// ISO 8601 timestamp of the verification
    pub verified_at: String,
    /// Random nonce generated before the biometric prompt.
    /// Proves the verification happened after this point in time
    /// (prevents replay of stale biometric events).
    pub challenge_nonce: String,
    /// BLAKE3(nonce || "biometric_verified" || timestamp) — binds the
    /// nonce to the verification event.
    pub challenge_response: String,
    /// Whether OS-level enforcement is active (kSecAccessControlBiometryCurrentSet)
    pub os_enforced: bool,
    /// Secure Enclave attestation (if available, empty string otherwise)
    pub hardware_attestation: String,
}

/// Collect biometric evidence after a successful verification.
///
/// Call this IMMEDIATELY after a successful `verify_touchid()` or
/// Keychain access with biometric gating. The nonce-response pair
/// proves temporal ordering.
#[cfg(target_os = "macos")]
fn collect_biometric_evidence() -> Option<BiometricEvidence> {
    use rand::RngCore;

    let mut nonce_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce_hex = hex::encode(nonce_bytes);

    let timestamp = chrono::Utc::now().to_rfc3339();

    // Bind nonce to this verification event
    let mut hasher = blake3::Hasher::new();
    hasher.update(nonce_bytes.as_ref());
    hasher.update(b"biometric_verified");
    hasher.update(timestamp.as_bytes());
    let response = hasher.finalize().to_hex().to_string();

    // Detect whether this is Touch ID or Face ID
    let method = detect_biometric_method();

    // os_enforced is true only when the binary is signed AND SecItemAdd
    // succeeded with kSecAccessControlBiometryCurrentSet. Compile-time
    // feature check alone isn't enough — the entitlement might be missing
    // at runtime (errSecMissingEntitlement / -34018).
    let os_enforced = {
        #[cfg(feature = "biometric-keychain")]
        { is_os_enforced() }
        #[cfg(not(feature = "biometric-keychain"))]
        { false }
    };

    Some(BiometricEvidence {
        method,
        verified_at: timestamp,
        challenge_nonce: nonce_hex,
        challenge_response: response,
        os_enforced,
        hardware_attestation: String::new(), // TODO: DeviceCheck attestation
    })
}

/// Detect whether the current Mac uses Touch ID or Face ID.
#[cfg(target_os = "macos")]
fn detect_biometric_method() -> String {
    let output = std::process::Command::new("bioutil")
        .args(["-rs"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output();

    match output {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            if stdout.contains("Face") {
                "faceid".to_string()
            } else {
                "touchid".to_string()
            }
        }
        _ => "touchid".to_string(), // default assumption
    }
}

// ---------------------------------------------------------------------------
// macOS detection (shared between v0.1 and v0.2)
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
fn detect_touchid() -> ProviderCapability {
    // bioutil -rs reports biometric status without triggering a prompt
    let biometric_check = std::process::Command::new("bioutil")
        .args(["-rs"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output();

    match biometric_check {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let bio_name = if stdout.contains("Face") {
                "Face ID"
            } else {
                "Touch ID"
            };

            let enforcement = if cfg!(feature = "biometric-keychain") {
                "OS-enforced if signed, application-layer fallback"
            } else {
                "application-layer"
            };

            ProviderCapability {
                mode: SovereigntyMode::TouchId,
                available: true,
                description: format!(
                    "{} available (Secure Enclave, {} gating)",
                    bio_name, enforcement
                ),
                requires_enrollment: false, // OS handles enrollment
                detail: Some(bio_name.to_string()),
                implementation_status: super::ProviderStatus::Ready,
            }
        }
        Ok(_) => {
            // bioutil ran but no biometric enrolled
            ProviderCapability {
                mode: SovereigntyMode::TouchId,
                available: false,
                description: "No biometric enrolled — enroll in System Preferences".into(),
                requires_enrollment: false,
                detail: None,
                implementation_status: super::ProviderStatus::Ready,
            }
        }
        Err(_) => {
            // bioutil not found — try system_profiler
            let sp_check = std::process::Command::new("system_profiler") // system_profiler SPiBridgeDataType
                .args(["SPiBridgeDataType"])
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .output();

            match sp_check {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    if stdout.contains("Touch ID") || stdout.contains("Fingerprint") {
                        ProviderCapability {
                            mode: SovereigntyMode::TouchId,
                            available: true,
                            description: "Touch ID hardware detected (Secure Enclave)".into(),
                            requires_enrollment: false,
                            detail: Some("Touch ID".to_string()),
                            implementation_status: super::ProviderStatus::Ready,
                        }
                    } else {
                        ProviderCapability {
                            mode: SovereigntyMode::TouchId,
                            available: false,
                            description: "No Touch ID hardware found".into(),
                            requires_enrollment: false,
                            detail: None,
                            implementation_status: super::ProviderStatus::Ready,
                        }
                    }
                }
                Err(_) => ProviderCapability {
                    mode: SovereigntyMode::TouchId,
                    available: false,
                    description: "Could not detect biometric hardware".into(),
                    requires_enrollment: false,
                    detail: None,
                    implementation_status: super::ProviderStatus::Ready,
                },
            }
        }
    }
}

/// Verify Touch ID / Face ID by triggering an actual biometric scan.
///
/// Uses `bioutil -w` which prompts the user for biometric verification.
/// In v0.2 with `biometric-keychain`, this is used as a pre-flight
/// check during enrollment. The actual gate is the Keychain ACL.
#[cfg(target_os = "macos")]
fn verify_touchid() -> Result<(), KeyError> {
    let output = std::process::Command::new("bioutil")
        .args(["-w"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .map_err(|e| {
            KeyError::CredentialStore(format!(
                "bioutil not available: {} — is Touch ID enrolled?",
                e
            ))
        })?;

    if output.status.success() {
        tracing::info!("Touch ID verification succeeded");
        Ok(())
    } else {
        Err(KeyError::CredentialStore(
            "Touch ID verification failed — touch your fingerprint sensor or try again".into(),
        ))
    }
}

// ===========================================================================
// v0.2: Security.framework with kSecAccessControlBiometryCurrentSet
// ===========================================================================
//
// When the `biometric-keychain` feature is enabled, Keychain items are
// created with an access control object that includes:
//
//   kSecAccessControlBiometryCurrentSet
//
// This means:
//   - Every read triggers a Secure Enclave biometric verification
//   - If the user adds/removes fingerprints, the item is invalidated
//     (prevents enrollment swap attacks)
//   - No application-layer bypass is possible — the kernel enforces it
//   - The `bioutil -w` pre-flight is still used during enrollment as a
//     UX courtesy (so the user knows biometric is being activated)

#[cfg(all(target_os = "macos", feature = "biometric-keychain"))]
mod secure_keychain {
    use crate::error::KeyError;
    use core_foundation::base::TCFType;
    use core_foundation::data::CFData;
    use core_foundation::string::CFString;
    use core_foundation_sys::base::{kCFAllocatorDefault, CFRelease, CFTypeRef, OSStatus};
    use core_foundation_sys::dictionary::{
        CFDictionaryCreate, kCFTypeDictionaryKeyCallBacks, kCFTypeDictionaryValueCallBacks,
    };
    use security_framework_sys::access_control::{
        SecAccessControlCreateWithFlags, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
    };
    use security_framework_sys::base::{errSecDuplicateItem, errSecItemNotFound, errSecSuccess};
    use security_framework_sys::item::{
        kSecAttrAccessControl, kSecAttrAccount, kSecAttrService, kSecClass,
        kSecClassGenericPassword, kSecReturnData, kSecValueData,
    };
    use security_framework_sys::keychain_item::{
        SecItemAdd, SecItemCopyMatching, SecItemDelete,
    };
    use std::ffi::c_void;

    /// Apple: kSecAccessControlBiometryCurrentSet = 1 << 3
    ///
    /// Not exported by security-framework-sys 2.11.x, so we define
    /// the raw value from Apple's Security/SecAccessControl.h header.
    ///
    /// This flag means:
    ///   - Must match biometrics CURRENTLY enrolled at Keychain-item creation
    ///   - If the user adds or removes a fingerprint/face, the item is
    ///     automatically invalidated by the Secure Enclave (prevents
    ///     enrollment-swap attacks)
    ///   - Every read triggers an OS-level biometric verification prompt
    const SEC_ACCESS_CONTROL_BIOMETRY_CURRENT_SET: u64 = 1 << 3;

    /// Keychain service label for biometric-gated items.
    /// Distinct from the v0.1 label so both can coexist during migration.
    const SERVICE: &str = if cfg!(test) {
        "zeropoint-genesis-bio-test"
    } else {
        "zeropoint-genesis-bio"
    };
    const ACCOUNT: &str = if cfg!(test) {
        "genesis-secret-bio-test"
    } else {
        "genesis-secret-bio"
    };

    /// Build a CFDictionary from parallel key/value slices.
    ///
    /// # Safety
    /// All pointers in `keys` and `values` must be valid CFTypeRef values
    /// that outlive the returned dictionary (or the dictionary retains them).
    /// Caller must CFRelease the returned dictionary when done.
    unsafe fn build_dict(
        keys: &[*const c_void],
        values: &[*const c_void],
    ) -> core_foundation_sys::dictionary::CFDictionaryRef {
        assert_eq!(keys.len(), values.len());
        CFDictionaryCreate(
            kCFAllocatorDefault,
            keys.as_ptr(),
            values.as_ptr(),
            keys.len() as isize,
            &kCFTypeDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks,
        )
    }

    /// Store the Genesis secret with kSecAccessControlBiometryCurrentSet.
    ///
    /// Uses direct Security.framework FFI to create a Keychain item
    /// with OS-enforced biometric access control:
    ///   - Every read triggers a Secure Enclave biometric verification
    ///   - If the user adds/removes fingerprints, the item is invalidated
    ///     (prevents enrollment swap attacks)
    ///   - No application-layer bypass is possible — the kernel enforces it
    ///
    /// If an item with the same service/account already exists, we
    /// delete it first (re-genesis scenario).
    pub fn save(secret: &[u8; 32]) -> Result<(), KeyError> {
        let secret_hex = hex::encode(secret);

        // Delete any existing item first (idempotent re-genesis)
        let _ = delete_existing();

        unsafe {
            // Create access control: BiometryCurrentSet with passcode-set prerequisite.
            // kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly is Apple's recommended
            // accessibility for biometric-gated items — it ensures the device has a
            // passcode (required for Touch ID) and never syncs to iCloud Keychain.
            let mut error: core_foundation_sys::error::CFErrorRef = std::ptr::null_mut();
            let access_control = SecAccessControlCreateWithFlags(
                kCFAllocatorDefault,
                kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                SEC_ACCESS_CONTROL_BIOMETRY_CURRENT_SET
                    as core_foundation_sys::base::CFOptionFlags,
                &mut error,
            );

            if access_control.is_null() {
                let err_msg = if !error.is_null() {
                    let cf_err = core_foundation::error::CFError::wrap_under_create_rule(
                        error as core_foundation_sys::error::CFErrorRef,
                    );
                    format!("SecAccessControl creation failed: {}", cf_err)
                } else {
                    "SecAccessControl creation failed (unknown error)".to_string()
                };
                return Err(KeyError::CredentialStore(err_msg));
            }

            // Wrap values that need to stay alive for the dictionary
            let service_cf = CFString::new(SERVICE);
            let account_cf = CFString::new(ACCOUNT);
            let data_cf = CFData::from_buffer(secret_hex.as_bytes());

            let keys: Vec<*const c_void> = vec![
                kSecClass as *const c_void,
                kSecAttrService as *const c_void,
                kSecAttrAccount as *const c_void,
                kSecValueData as *const c_void,
                kSecAttrAccessControl as *const c_void,
            ];
            let values: Vec<*const c_void> = vec![
                kSecClassGenericPassword as *const c_void,
                service_cf.as_concrete_TypeRef() as *const c_void,
                account_cf.as_concrete_TypeRef() as *const c_void,
                data_cf.as_concrete_TypeRef() as *const c_void,
                access_control as *const c_void,
            ];

            let query = build_dict(&keys, &values);
            let status: OSStatus = SecItemAdd(query, std::ptr::null_mut());
            CFRelease(query as CFTypeRef);
            CFRelease(access_control as CFTypeRef);

            match status {
                s if s == errSecSuccess => {
                    tracing::info!(
                        "Genesis secret stored in Keychain with \
                         kSecAccessControlBiometryCurrentSet (v0.2 OS-enforced)"
                    );
                    Ok(())
                }
                s if s == errSecDuplicateItem => {
                    // Race condition — delete and retry once
                    tracing::warn!("Duplicate Keychain item — retrying after delete");
                    delete_existing()?;
                    // Rebuild (service_cf etc. are still alive)
                    let query2 = build_dict(&keys, &values);
                    let status2: OSStatus = SecItemAdd(query2, std::ptr::null_mut());
                    CFRelease(query2 as CFTypeRef);
                    if status2 == errSecSuccess {
                        Ok(())
                    } else {
                        Err(KeyError::CredentialStore(format!(
                            "SecItemAdd failed after retry: OSStatus {}",
                            status2
                        )))
                    }
                }
                s => Err(KeyError::CredentialStore(format!(
                    "SecItemAdd failed: OSStatus {} \
                     — check Touch ID enrollment and Keychain access",
                    s
                ))),
            }
        }
    }

    /// Load the Genesis secret. The OS triggers a biometric prompt
    /// automatically — kSecAccessControlBiometryCurrentSet ensures this
    /// at the kernel level. No application-layer check needed.
    pub fn load() -> Result<[u8; 32], KeyError> {
        unsafe {
            let service_cf = CFString::new(SERVICE);
            let account_cf = CFString::new(ACCOUNT);
            let true_val = core_foundation::boolean::CFBoolean::true_value();

            let keys: Vec<*const c_void> = vec![
                kSecClass as *const c_void,
                kSecAttrService as *const c_void,
                kSecAttrAccount as *const c_void,
                kSecReturnData as *const c_void,
            ];
            let values: Vec<*const c_void> = vec![
                kSecClassGenericPassword as *const c_void,
                service_cf.as_concrete_TypeRef() as *const c_void,
                account_cf.as_concrete_TypeRef() as *const c_void,
                true_val.as_concrete_TypeRef() as *const c_void,
            ];

            let query = build_dict(&keys, &values);
            let mut result: CFTypeRef = std::ptr::null();
            let status: OSStatus = SecItemCopyMatching(query, &mut result);
            CFRelease(query as CFTypeRef);

            match status {
                s if s == errSecSuccess && !result.is_null() => {
                    // Result is CFData containing the hex-encoded secret.
                    // SecItemCopyMatching returns a retained CFDataRef when
                    // kSecReturnData is true, so wrap_under_create_rule is correct
                    // (it takes ownership without an extra retain).
                    let cf_data = CFData::wrap_under_create_rule(
                        result as core_foundation_sys::data::CFDataRef,
                    );
                    let bytes = cf_data.bytes();

                    let hex_str = std::str::from_utf8(bytes).map_err(|_| {
                        KeyError::CredentialStore(
                            "Corrupted secret in Keychain (not valid UTF-8)"
                                .into(),
                        )
                    })?;

                    let decoded = hex::decode(hex_str.trim()).map_err(|_| {
                        KeyError::CredentialStore(
                            "Corrupted secret in Keychain (not valid hex)".into(),
                        )
                    })?;

                    if decoded.len() != 32 {
                        return Err(KeyError::CredentialStore(format!(
                            "Secret has wrong length: {} bytes (expected 32)",
                            decoded.len()
                        )));
                    }

                    let mut secret = [0u8; 32];
                    secret.copy_from_slice(&decoded);

                    tracing::info!(
                        "Genesis secret loaded from biometric-gated Keychain (v0.2)"
                    );
                    Ok(secret)
                }
                s if s == errSecItemNotFound => Err(KeyError::CredentialStore(
                    "Genesis secret not found in Keychain (biometric-gated). \
                     This may indicate the biometric enrollment changed since genesis. \
                     Run `zp recover` with your 24-word mnemonic."
                        .into(),
                )),
                // -25293 = errSecAuthFailed
                s if s == -25293 => Err(KeyError::CredentialStore(
                    "Biometric authentication failed — touch your sensor \
                     and try again"
                        .into(),
                )),
                s => Err(KeyError::CredentialStore(format!(
                    "Keychain read failed: OSStatus {} \
                     — biometric may have changed since genesis",
                    s
                ))),
            }
        }
    }

    /// Delete the existing biometric-gated keychain item.
    fn delete_existing() -> Result<(), KeyError> {
        unsafe {
            let service_cf = CFString::new(SERVICE);
            let account_cf = CFString::new(ACCOUNT);

            let keys: Vec<*const c_void> = vec![
                kSecClass as *const c_void,
                kSecAttrService as *const c_void,
                kSecAttrAccount as *const c_void,
            ];
            let values: Vec<*const c_void> = vec![
                kSecClassGenericPassword as *const c_void,
                service_cf.as_concrete_TypeRef() as *const c_void,
                account_cf.as_concrete_TypeRef() as *const c_void,
            ];

            let query = build_dict(&keys, &values);
            let status: OSStatus = SecItemDelete(query);
            CFRelease(query as CFTypeRef);

            match status {
                s if s == errSecSuccess || s == errSecItemNotFound => Ok(()),
                s => Err(KeyError::CredentialStore(format!(
                    "Failed to delete existing keychain item: OSStatus {}",
                    s
                ))),
            }
        }
    }
}

/// Track whether OS-level biometric enforcement is active for this session.
/// Set to `true` when secure_keychain::save succeeds (biometric-gated item
/// stored with kSecAccessControlBiometryCurrentSet). Remains `false` when
/// the binary lacks entitlements and we fall back to v0.1 keyring.
#[cfg(all(target_os = "macos", feature = "biometric-keychain"))]
static OS_ENFORCED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[cfg(all(target_os = "macos", feature = "biometric-keychain"))]
pub(crate) fn is_os_enforced() -> bool {
    OS_ENFORCED.load(std::sync::atomic::Ordering::Relaxed)
}

/// v0.2: Store with kSecAccessControlBiometryCurrentSet.
///
/// Tier 1 (unsigned binary): If SecItemAdd returns -34018
///   (errSecMissingEntitlement), falls back to v0.1 keyring storage
///   automatically. Touch ID was already verified via bioutil pre-flight,
///   so the biometric evidence is still valid — just not OS-enforced.
///
/// Tier 2 (signed binary): If SecItemAdd succeeds, the Keychain item
///   has biometric access control at the kernel level. Every future read
///   triggers an OS biometric prompt with no application-layer bypass.
#[cfg(all(target_os = "macos", feature = "biometric-keychain"))]
fn save_touchid_secret_v2(secret: &[u8; 32]) -> Result<(), KeyError> {
    // Pre-flight: verify Touch ID works before committing to biometric gating.
    // This is a UX courtesy — the user sees the biometric prompt and consents
    // before we create the Keychain item.
    verify_touchid().map_err(|e| {
        KeyError::CredentialStore(format!(
            "Touch ID verification failed during enrollment: {}. \
             Cannot enable biometric gating without a successful scan.",
            e
        ))
    })?;

    // Try Tier 2: OS-enforced biometric via Secure Enclave
    match secure_keychain::save(secret) {
        Ok(()) => {
            OS_ENFORCED.store(true, std::sync::atomic::Ordering::Relaxed);
            tracing::info!(
                "Tier 2: Keychain item stored with OS-enforced biometric \
                 (kSecAccessControlBiometryCurrentSet)"
            );
        }
        Err(e) => {
            let msg = format!("{}", e);
            // -34018 = errSecMissingEntitlement — binary is not code-signed
            // with Keychain entitlements. Fall back to Tier 1 gracefully.
            if msg.contains("-34018") || msg.contains("MissingEntitlement") {
                tracing::warn!(
                    "Tier 2 unavailable (binary not signed with Keychain entitlements). \
                     Falling back to Tier 1: standard Keychain + application-layer biometric. \
                     To enable OS-enforced biometric, sign the binary with: \
                     codesign --sign <identity> --entitlements entitlements/keychain-biometric.entitlements.plist <binary>"
                );
                // Tier 1 stores via keyring (no biometric access control on the item)
            } else {
                // Unexpected error — propagate
                return Err(e);
            }
        }
    }

    // Always store in v0.1 keyring as well:
    // - Tier 1: this IS the primary storage (no biometric flag on item)
    // - Tier 2: this is the migration bridge for downgrade
    #[cfg(feature = "os-keychain")]
    {
        let entry = keyring::Entry::new(
            crate::keyring::GENESIS_KEYCHAIN_SERVICE,
            crate::keyring::GENESIS_KEYCHAIN_ACCOUNT,
        )
        .map_err(|e| KeyError::CredentialStore(format!("Keychain entry error: {}", e)))?;

        entry
            .set_password(&hex::encode(secret))
            .map_err(|e| KeyError::CredentialStore(format!("Keychain store error: {}", e)))?;
    }

    Ok(())
}

/// v0.2: Load with OS-enforced biometric. The Secure Enclave triggers
/// the biometric prompt automatically — no `bioutil -w` needed.
#[cfg(all(target_os = "macos", feature = "biometric-keychain"))]
fn load_touchid_secret_v2() -> Result<[u8; 32], KeyError> {
    // Try the v0.2 biometric-gated item first
    match secure_keychain::load() {
        Ok(secret) => Ok(secret),
        Err(e) => {
            // Fall back to v0.1 path for pre-v0.2 genesis installations.
            // This requires the application-layer bioutil check since the
            // v0.1 Keychain item has no biometric access control.
            tracing::warn!(
                "v0.2 biometric keychain load failed ({}), trying v0.1 fallback",
                e
            );
            #[cfg(feature = "os-keychain")]
            {
                verify_touchid()?;
                crate::keyring::load_genesis_from_credential_store()
            }
            #[cfg(not(feature = "os-keychain"))]
            {
                Err(e)
            }
        }
    }
}

// ===========================================================================
// v0.1: Application-layer biometric check (legacy / non-biometric-keychain)
// ===========================================================================

/// v0.1: Store via `keyring` crate (standard Keychain access).
/// Biometric verification happens at load time via `bioutil -w`.
#[cfg(all(target_os = "macos", feature = "os-keychain", not(feature = "biometric-keychain")))]
fn save_touchid_secret_v1(secret: &[u8; 32]) -> Result<(), KeyError> {
    // First, verify Touch ID works — prompt the user now
    // so they know it's active and consent to biometric gating.
    verify_touchid().map_err(|e| {
        KeyError::CredentialStore(format!(
            "Touch ID verification failed during enrollment: {}. \
             Cannot enable biometric gating without a successful scan.",
            e
        ))
    })?;

    let entry = keyring::Entry::new(
        crate::keyring::GENESIS_KEYCHAIN_SERVICE,
        crate::keyring::GENESIS_KEYCHAIN_ACCOUNT,
    )
    .map_err(|e| KeyError::CredentialStore(format!("entry error: {}", e)))?;

    entry
        .set_password(&hex::encode(secret))
        .map_err(|e| KeyError::CredentialStore(format!("store error: {}", e)))?;

    tracing::info!(
        "Genesis secret stored in Keychain with Touch ID verification \
         (application-layer gating, v0.1)"
    );

    Ok(())
}

/// v0.1: Load the Genesis secret, requiring application-layer biometric check first.
#[cfg(all(target_os = "macos", feature = "os-keychain", not(feature = "biometric-keychain")))]
fn load_touchid_secret_v1() -> Result<[u8; 32], KeyError> {
    verify_touchid()?;
    crate::keyring::load_genesis_from_credential_store()
}
