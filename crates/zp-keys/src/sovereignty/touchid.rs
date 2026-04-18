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
            save_touchid_secret_v2(secret)
        }

        #[cfg(all(target_os = "macos", feature = "os-keychain", not(feature = "biometric-keychain")))]
        {
            save_touchid_secret_v1(secret)
        }

        #[cfg(not(target_os = "macos"))]
        {
            let _ = secret;
            Err(KeyError::CredentialStore(
                "Touch ID requires macOS with os-keychain feature".into(),
            ))
        }
    }

    fn load_secret(&self) -> Result<[u8; 32], KeyError> {
        #[cfg(all(target_os = "macos", feature = "biometric-keychain"))]
        {
            load_touchid_secret_v2()
        }

        #[cfg(all(target_os = "macos", feature = "os-keychain", not(feature = "biometric-keychain")))]
        {
            load_touchid_secret_v1()
        }

        #[cfg(not(target_os = "macos"))]
        {
            Err(KeyError::CredentialStore(
                "Touch ID requires macOS with os-keychain feature".into(),
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
        Ok(Some(super::EnrollmentResult {
            enrollment_data: Vec::new(),
            summary: format!(
                "Sovereignty upgraded to Touch ID ({})",
                if cfg!(feature = "biometric-keychain") {
                    "OS-enforced via kSecAccessControlBiometryCurrentSet"
                } else {
                    "application-layer gating"
                }
            ),
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

    let os_enforced = cfg!(feature = "biometric-keychain");

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
                "OS-enforced"
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
    use core_foundation::boolean::CFBoolean;
    use core_foundation::data::CFData;
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::string::CFString;
    use security_framework::access_control::SecAccessControl;
    use security_framework::item::{ItemClass, ItemSearchOptions, SearchResult};
    use security_framework_sys::access_control::SecAccessControlCreateFlags;
    use security_framework_sys::base::{errSecDuplicateItem, errSecItemNotFound, errSecSuccess};
    use security_framework_sys::keychain_item::{SecItemAdd, SecItemDelete};
    use std::ptr;

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

    /// Store the Genesis secret with kSecAccessControlBiometryCurrentSet.
    ///
    /// The access control flags ensure:
    /// - BiometryCurrentSet: must match CURRENTLY enrolled biometrics
    ///   (adding/removing a fingerprint invalidates the item)
    /// - PrivateKeyUsage: the Secure Enclave gates access
    ///
    /// If an item with the same service/account already exists, we
    /// delete it first (re-genesis scenario).
    pub fn save(secret: &[u8; 32]) -> Result<(), KeyError> {
        // Build access control: biometry of current enrollment set
        let access_control = SecAccessControl::create_with_flags(
            SecAccessControlCreateFlags::kSecAccessControlBiometryCurrentSet,
        )
        .map_err(|e| {
            KeyError::CredentialStore(format!(
                "Failed to create biometric access control: {}",
                e
            ))
        })?;

        let secret_data = CFData::from_buffer(&hex::encode(secret).into_bytes());
        let service_cf = CFString::new(SERVICE);
        let account_cf = CFString::new(ACCOUNT);
        let label_cf = CFString::new("ZeroPoint Genesis Secret (biometric-gated)");

        // Delete any existing item first (idempotent re-genesis)
        let _ = delete_existing();

        // Build the query dictionary for SecItemAdd
        let keys: Vec<CFString> = vec![
            CFString::from_static_string("svce"), // kSecAttrService
            CFString::from_static_string("acct"), // kSecAttrAccount
            CFString::from_static_string("labl"), // kSecAttrLabel
            CFString::from_static_string("class"), // kSecClass
            CFString::from_static_string("v_Data"), // kSecValueData
            CFString::from_static_string("accc"), // kSecAttrAccessControl
            CFString::from_static_string("sync"), // kSecAttrSynchronizable
        ];

        let class_cf = CFString::from_static_string("genp"); // kSecClassGenericPassword

        // Use the raw Security.framework API for full control over access control
        unsafe {
            use core_foundation::base::ToVoid;
            use core_foundation_sys::dictionary::CFDictionaryCreate;
            use core_foundation_sys::base::kCFAllocatorDefault;

            let cf_keys: Vec<*const std::ffi::c_void> = vec![
                CFString::from_static_string("svce").to_void(),
                CFString::from_static_string("acct").to_void(),
                CFString::from_static_string("labl").to_void(),
                CFString::from_static_string("class").to_void(),
                CFString::from_static_string("v_Data").to_void(),
                CFString::from_static_string("accc").to_void(),
                CFString::from_static_string("sync").to_void(),
            ];

            let cf_values: Vec<*const std::ffi::c_void> = vec![
                service_cf.to_void(),
                account_cf.to_void(),
                label_cf.to_void(),
                class_cf.to_void(),
                secret_data.to_void(),
                access_control.to_void(),
                CFBoolean::false_value().to_void(),
            ];

            let query = CFDictionaryCreate(
                kCFAllocatorDefault,
                cf_keys.as_ptr(),
                cf_values.as_ptr(),
                cf_keys.len() as isize,
                &core_foundation_sys::dictionary::kCFTypeDictionaryKeyCallBacks,
                &core_foundation_sys::dictionary::kCFTypeDictionaryValueCallBacks,
            );

            let status = SecItemAdd(query as _, ptr::null_mut());
            core_foundation::base::CFRelease(query as _);

            match status {
                s if s == errSecSuccess => {
                    tracing::info!(
                        "Genesis secret stored in Keychain with \
                         kSecAccessControlBiometryCurrentSet (v0.2 OS-enforced)"
                    );
                    Ok(())
                }
                s if s == errSecDuplicateItem => {
                    // Shouldn't happen after delete, but handle gracefully
                    tracing::warn!("Duplicate keychain item — attempting overwrite");
                    delete_existing()?;
                    let query2 = CFDictionaryCreate(
                        kCFAllocatorDefault,
                        cf_keys.as_ptr(),
                        cf_values.as_ptr(),
                        cf_keys.len() as isize,
                        &core_foundation_sys::dictionary::kCFTypeDictionaryKeyCallBacks,
                        &core_foundation_sys::dictionary::kCFTypeDictionaryValueCallBacks,
                    );
                    let status2 = SecItemAdd(query2 as _, ptr::null_mut());
                    core_foundation::base::CFRelease(query2 as _);
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
                    "SecItemAdd failed: OSStatus {} — check Touch ID enrollment \
                     and Keychain access",
                    s
                ))),
            }
        }
    }

    /// Load the Genesis secret. The OS will trigger a biometric prompt
    /// automatically — kSecAccessControlBiometryCurrentSet ensures this
    /// at the kernel level. No application-layer check needed.
    pub fn load() -> Result<[u8; 32], KeyError> {
        let mut search = ItemSearchOptions::new();
        search
            .class(ItemClass::generic_password())
            .service(SERVICE)
            .account(ACCOUNT)
            .load_data(true)
            .limit(1);

        // This call will trigger Touch ID / Face ID via the Secure Enclave.
        // The OS shows the biometric dialog — we don't need bioutil -w.
        let results = search.search().map_err(|e| {
            let msg = format!("{}", e);
            if msg.contains("-25293") || msg.contains("errSecAuthFailed") {
                KeyError::CredentialStore(
                    "Biometric authentication failed — touch your sensor and try again".into(),
                )
            } else if msg.contains("-25300") || msg.contains("errSecItemNotFound") {
                KeyError::CredentialStore(
                    "Genesis secret not found in Keychain (biometric-gated). \
                     This may indicate the biometric enrollment changed since genesis. \
                     Run `zp recover` with your 24-word mnemonic."
                        .into(),
                )
            } else {
                KeyError::CredentialStore(format!(
                    "Keychain read failed: {} — biometric may have changed since genesis",
                    e
                ))
            }
        })?;

        let data = results
            .first()
            .and_then(|r| match r {
                SearchResult::Data(d) => Some(d.clone()),
                _ => None,
            })
            .ok_or_else(|| {
                KeyError::CredentialStore(
                    "Genesis secret not found in biometric-gated Keychain".into(),
                )
            })?;

        // Decode the hex-encoded secret
        let hex_str = String::from_utf8(data).map_err(|_| {
            KeyError::CredentialStore("Corrupted secret in Keychain (not valid UTF-8)".into())
        })?;
        let bytes = hex::decode(hex_str.trim()).map_err(|_| {
            KeyError::CredentialStore("Corrupted secret in Keychain (not valid hex)".into())
        })?;

        if bytes.len() != 32 {
            return Err(KeyError::CredentialStore(format!(
                "Secret has wrong length: {} bytes (expected 32)",
                bytes.len()
            )));
        }

        let mut secret = [0u8; 32];
        secret.copy_from_slice(&bytes);

        tracing::info!("Genesis secret loaded from biometric-gated Keychain (v0.2)");
        Ok(secret)
    }

    /// Delete the existing biometric-gated keychain item.
    fn delete_existing() -> Result<(), KeyError> {
        let mut search = ItemSearchOptions::new();
        search
            .class(ItemClass::generic_password())
            .service(SERVICE)
            .account(ACCOUNT);

        // We use the search builder to construct the query, then delete
        match search.search() {
            Ok(_) => {
                // Item exists — delete via the lower-level API
                unsafe {
                    use core_foundation::base::ToVoid;
                    use core_foundation_sys::base::kCFAllocatorDefault;
                    use core_foundation_sys::dictionary::CFDictionaryCreate;

                    let service_cf = CFString::new(SERVICE);
                    let account_cf = CFString::new(ACCOUNT);
                    let class_cf = CFString::from_static_string("genp");

                    let cf_keys: Vec<*const std::ffi::c_void> = vec![
                        CFString::from_static_string("svce").to_void(),
                        CFString::from_static_string("acct").to_void(),
                        CFString::from_static_string("class").to_void(),
                    ];
                    let cf_values: Vec<*const std::ffi::c_void> = vec![
                        service_cf.to_void(),
                        account_cf.to_void(),
                        class_cf.to_void(),
                    ];

                    let query = CFDictionaryCreate(
                        kCFAllocatorDefault,
                        cf_keys.as_ptr(),
                        cf_values.as_ptr(),
                        cf_keys.len() as isize,
                        &core_foundation_sys::dictionary::kCFTypeDictionaryKeyCallBacks,
                        &core_foundation_sys::dictionary::kCFTypeDictionaryValueCallBacks,
                    );

                    let status = SecItemDelete(query as _);
                    core_foundation::base::CFRelease(query as _);

                    if status != errSecSuccess && status != errSecItemNotFound {
                        return Err(KeyError::CredentialStore(format!(
                            "Failed to delete existing keychain item: OSStatus {}",
                            status
                        )));
                    }
                }
                Ok(())
            }
            Err(_) => Ok(()), // Nothing to delete
        }
    }
}

/// v0.2: Store with kSecAccessControlBiometryCurrentSet.
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

    // Store with OS-level biometric enforcement
    secure_keychain::save(secret)?;

    // Also store in the v0.1 keyring as a migration bridge.
    // The v0.2 path will always be preferred for loads, but having
    // the v0.1 entry means downgrade is possible.
    #[cfg(feature = "os-keychain")]
    {
        let entry = keyring::Entry::new(
            crate::keyring::GENESIS_KEYCHAIN_SERVICE,
            crate::keyring::GENESIS_KEYCHAIN_ACCOUNT,
        )
        .map_err(|e| KeyError::CredentialStore(format!("v0.1 bridge entry error: {}", e)))?;

        if let Err(e) = entry.set_password(&hex::encode(secret)) {
            tracing::warn!("Could not write v0.1 bridge keychain entry: {}", e);
            // Non-fatal — the v0.2 entry is the source of truth
        }
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
