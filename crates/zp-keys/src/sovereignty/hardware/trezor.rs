// crates/zp-keys/src/sovereignty/hardware/trezor.rs
//
// Trezor hardware wallet sovereignty provider.
//
// Uses Trezor's CipherKeyValue message to deterministically derive a 32-byte
// wrapping key from a BIP-32 path + key name. The Genesis secret is encrypted
// with this key (ChaCha20-Poly1305) and stored locally. To unlock, the user
// must confirm on the Trezor display — physical presence proven.
//
// Key derivation path:  m/10016'/0  (Trezor CipherKeyValue standard path)
// Key name:             "ZeroPoint Genesis"
// Encrypt:              true
// Ask on encrypt:       true  (requires physical confirmation)
// Ask on decrypt:       true  (requires physical confirmation)
//
// The 32-byte "value" we encrypt on the device is a fixed domain-separation
// constant. The device returns 32 bytes of deterministic ciphertext which we
// use as the wrapping key. This is NOT the Genesis secret — it's the key that
// wraps the Genesis secret for local storage.
//
// Dependencies: feature-gated behind `hw-trezor`
// - `trezor-client` for USB communication and CipherKeyValue protobuf

use super::super::{
    EnrollmentResult, ProviderCapabilities, ProviderCapability, ProviderStatus, SovereigntyMode,
    SovereigntyProvider,
};
use crate::error::KeyError;

/// Trezor sovereignty provider.
pub struct TrezorProvider;

/// BIP-32 path for CipherKeyValue derivation: m/10016'/0
///
/// 10016' is the Trezor-standard CipherKeyValue path (0x80002720).
/// This path is conventionally used for symmetric encryption operations.
#[allow(dead_code)]
const CIPHER_KEY_VALUE_PATH: &[u32] = &[0x80002720, 0];

/// Key name shown on the Trezor display during confirmation.
const CIPHER_KEY_NAME: &str = "ZeroPoint Genesis";

/// Fixed 32-byte value used as input to CipherKeyValue.
///
/// We encrypt this constant using the device's path-derived AES key.
/// The output is deterministic for a given device + path + key name,
/// giving us a stable 32-byte wrapping key without ever sending
/// the Genesis secret to the device.
#[allow(dead_code)]
const CIPHER_DOMAIN_SEPARATOR: &[u8; 32] = b"zeropoint-trezor-wrapping-key-v1";

impl SovereigntyProvider for TrezorProvider {
    fn mode(&self) -> SovereigntyMode {
        SovereigntyMode::Trezor
    }

    fn detect(&self) -> ProviderCapability {
        detect_trezor()
    }

    fn save_secret(&self, secret: &[u8; 32]) -> Result<(), KeyError> {
        // 1. Derive wrapping key from Trezor (requires user confirmation on device)
        let (wrapping_key, device_label) = derive_wrapping_key()?;

        // 2. Encrypt the Genesis secret with the device-derived wrapping key
        let ciphertext = super::encrypt_secret(secret, &wrapping_key)?;

        // 3. Save the encrypted blob
        super::save_encrypted_secret("trezor", &ciphertext)?;

        // 4. Save enrollment metadata
        let enrollment = super::EnrollmentMetadata {
            version: "2".into(),
            mode: "trezor".into(),
            device_id: device_label.clone(),
            device_description: format!("Trezor ({})", device_label),
            enrolled_at: chrono::Utc::now().to_rfc3339(),
            provider_data: serde_json::json!({
                "path": "m/10016'/0",
                "key_name": CIPHER_KEY_NAME,
                "protocol": "CipherKeyValue",
                "wrapping_version": 1,
                "ciphertext_version": 1,
            }),
            // No cryptographic attestation available from Trezor CipherKeyValue yet.
            // When Trezor firmware adds device attestation signing, populate this
            // with the signed attestation blob.
            attestation: None,
            // 1:1 model — no quorum fields
            share_index: None,
            quorum_id: None,
            threshold: None,
        };
        super::save_enrollment(&enrollment)?;

        tracing::info!(
            device = %device_label,
            "Genesis secret encrypted and sealed by Trezor CipherKeyValue"
        );

        Ok(())
    }

    fn load_secret(&self) -> Result<[u8; 32], KeyError> {
        // Verify enrollment exists
        let enrollment = super::load_enrollment("trezor")?;

        // Load encrypted blob
        let ciphertext = super::load_encrypted_secret("trezor")?;

        // Re-derive wrapping key (requires user confirmation on device)
        let (wrapping_key, device_label) = derive_wrapping_key()?;

        // Verify device identity matches enrollment
        if device_label != enrollment.device_id {
            return Err(KeyError::DeviceMismatch(format!(
                "Enrolled with '{}', but connected device is '{}'. \
                 Connect the original Trezor to unlock.",
                enrollment.device_id, device_label
            )));
        }

        // Decrypt
        let secret = super::decrypt_secret(&ciphertext, &wrapping_key)?;

        tracing::info!(
            device = %device_label,
            "Genesis secret decrypted via Trezor CipherKeyValue"
        );

        Ok(secret)
    }

    fn verify_presence(&self) -> Result<(), KeyError> {
        // Verify by attempting to connect and ping the device
        #[cfg(feature = "hw-trezor")]
        {
            let trezor = connect_trezor()?;
            // If we got here, the device is connected and initialized
            let _ = trezor;
            Ok(())
        }

        #[cfg(not(feature = "hw-trezor"))]
        {
            Err(KeyError::NotImplemented(
                "Trezor support requires the hw-trezor feature".into(),
            ))
        }
    }

    fn enroll(&self) -> Result<Option<EnrollmentResult>, KeyError> {
        // Enrollment for Trezor is implicit in save_secret —
        // the CipherKeyValue derivation IS the enrollment.
        // We return a summary here for the onboarding terminal.
        #[cfg(feature = "hw-trezor")]
        {
            let trezor = connect_trezor()?;
            let features = trezor.features().ok_or_else(|| {
                KeyError::DeviceNotFound("Trezor connected but features unavailable".into())
            })?;

            let label = features.label().to_string();
            let model = features.model().to_string();

            Ok(Some(EnrollmentResult {
                enrollment_data: Vec::new(), // Trezor enrollment is stateless (path-based)
                summary: format!(
                    "Trezor {} ('{}') ready for CipherKeyValue at m/10016'/0",
                    model, label
                ),
            }))
        }

        #[cfg(not(feature = "hw-trezor"))]
        {
            Err(KeyError::NotImplemented(
                "Trezor support requires the hw-trezor feature".into(),
            ))
        }
    }

    fn capabilities(&self) -> ProviderCapabilities {
        // Trezor supports: rewrap (via CipherKeyValue re-derivation on new device),
        // passphrase (Trezor's native passphrase feature), and device storage
        // (BIP-32 path is deterministic on the device's seed).
        //
        // CAN_ATTEST: Trezor doesn't have a standard attestation flow yet —
        // we could hash the features response, but it's not a cryptographic
        // attestation. Reserved for when Trezor firmware adds signing.
        //
        // CAN_QUORUM: reserved for future Shamir + multi-Trezor support.
        let caps = ProviderCapabilities::CAN_REWRAP;
        #[cfg(feature = "hw-trezor")]
        {
            let caps = caps.union(ProviderCapabilities::CAN_PASSPHRASE);
            let caps = caps.union(ProviderCapabilities::HAS_DEVICE_STORAGE);
            return caps;
        }
        #[cfg(not(feature = "hw-trezor"))]
        caps
    }
}

// ---------------------------------------------------------------------------
// Trezor communication (feature-gated)
// ---------------------------------------------------------------------------

/// Detect a connected Trezor device.
///
/// When the `hw-trezor` feature is enabled, this uses `trezor-client` for
/// real USB detection. Otherwise, falls back to system-level USB scanning.
fn detect_trezor() -> ProviderCapability {
    #[cfg(feature = "hw-trezor")]
    {
        detect_trezor_usb()
    }

    #[cfg(not(feature = "hw-trezor"))]
    {
        detect_trezor_basic()
    }
}

/// USB detection via trezor-client (hw-trezor feature enabled).
#[cfg(feature = "hw-trezor")]
fn detect_trezor_usb() -> ProviderCapability {
    use trezor_client::find_devices;

    let devices = find_devices(false);
    let found = !devices.is_empty();
    let count = devices.len();

    ProviderCapability {
        mode: SovereigntyMode::Trezor,
        available: found,
        description: if found {
            format!(
                "Trezor detected ({} device{})",
                count,
                if count == 1 { "" } else { "s" }
            )
        } else {
            "No Trezor device detected — connect your Trezor via USB".into()
        },
        requires_enrollment: true,
        detail: if found {
            Some(format!("{} device(s) found", count))
        } else {
            None
        },
        implementation_status: ProviderStatus::Ready,
    }
}

/// Connect to the first available Trezor device.
#[cfg(feature = "hw-trezor")]
fn connect_trezor() -> Result<trezor_client::Trezor, KeyError> {
    use trezor_client::find_devices;

    let devices = find_devices(false);

    let device = devices.into_iter().next().ok_or_else(|| {
        KeyError::DeviceNotFound(
            "No Trezor device found. Ensure your Trezor is connected via USB and unlocked.".into(),
        )
    })?;

    let mut trezor = device
        .connect()
        .map_err(|e| KeyError::DeviceNotFound(format!("Failed to connect to Trezor: {}", e)))?;

    // Initialize the session
    trezor
        .init_device(None)
        .map_err(|e| KeyError::DeviceNotFound(format!("Trezor initialization failed: {}", e)))?;

    Ok(trezor)
}

/// Derive a 32-byte wrapping key using Trezor CipherKeyValue.
///
/// This sends a CipherKeyValue request to the device at path m/10016'/0
/// with key name "ZeroPoint Genesis". The user must confirm on the Trezor
/// display. The device returns 32 bytes of deterministic ciphertext which
/// we use as the wrapping key for the Genesis secret.
///
/// Uses the high-level `trezor.call()` API which handles ButtonRequest,
/// PinMatrixRequest, and PassphraseRequest flows automatically via
/// `TrezorResponse` variants.
///
/// Returns (wrapping_key, device_label).
#[cfg(feature = "hw-trezor")]
fn derive_wrapping_key() -> Result<([u8; 32], String), KeyError> {
    use trezor_client::protos::{CipherKeyValue, CipheredKeyValue};
    use trezor_client::TrezorResponse;

    let mut trezor = connect_trezor()?;

    // Get device label for enrollment identity
    let device_label = trezor
        .features()
        .map(|f| f.label().to_string())
        .unwrap_or_else(|| "Trezor".to_string());

    // Build CipherKeyValue request
    let mut msg = CipherKeyValue::new();
    msg.address_n = CIPHER_KEY_VALUE_PATH.to_vec();
    msg.set_key(CIPHER_KEY_NAME.to_string());
    msg.set_value(CIPHER_DOMAIN_SEPARATOR.to_vec());
    msg.set_encrypt(true);
    msg.set_ask_on_encrypt(true);
    msg.set_ask_on_decrypt(true);

    tracing::info!("Requesting CipherKeyValue from Trezor — confirm on device");

    // Send via the high-level call() API.
    // The result_handler extracts the CipheredKeyValue into raw bytes.
    let result_handler: Box<
        dyn Fn(&mut trezor_client::Trezor, CipheredKeyValue) -> trezor_client::Result<Vec<u8>>,
    > = Box::new(|_client, response| Ok(response.value().to_vec()));

    let mut response = trezor
        .call(msg, result_handler)
        .map_err(|e| KeyError::DeviceNotFound(format!("Trezor communication failed: {}", e)))?;

    // Handle the interactive flow: ButtonRequest, PinMatrix, Passphrase
    let result = loop {
        match response {
            TrezorResponse::Ok(value) => break value,

            TrezorResponse::Failure(failure) => {
                let msg = failure.message().to_string();
                if msg.contains("cancelled") || msg.contains("Cancelled") {
                    return Err(KeyError::UserCancelled(format!(
                        "Operation cancelled on Trezor: {}",
                        msg
                    )));
                }
                return Err(KeyError::CredentialStore(format!(
                    "Trezor rejected operation: {}",
                    msg
                )));
            }

            TrezorResponse::ButtonRequest(br) => {
                tracing::info!("Waiting for user confirmation on Trezor...");
                response = br.ack().map_err(|e| {
                    KeyError::UserCancelled(format!("Trezor button acknowledgment failed: {}", e))
                })?;
            }

            TrezorResponse::PinMatrixRequest(_) => {
                // We can't prompt for PIN in headless mode.
                // The user should unlock the device via Trezor Suite first.
                return Err(KeyError::DeviceNotFound(
                    "Trezor is locked. Please unlock your Trezor with Trezor Suite \
                     or enter your PIN on the device, then try again."
                        .into(),
                ));
            }

            TrezorResponse::PassphraseRequest(pr) => {
                // Send empty passphrase — ZeroPoint uses the base wallet
                response = pr.ack_passphrase(String::new()).map_err(|e| {
                    KeyError::CredentialStore(format!("Trezor passphrase flow failed: {}", e))
                })?;
            }
        }
    };

    // Extract the 32-byte ciphered value
    if result.len() < 32 {
        return Err(KeyError::InvalidKeyMaterial(format!(
            "Trezor CipherKeyValue returned {} bytes (expected >= 32)",
            result.len()
        )));
    }

    let mut wrapping_key = [0u8; 32];
    wrapping_key.copy_from_slice(&result[..32]);

    Ok((wrapping_key, device_label))
}

/// Wrapping key derivation without hw-trezor feature.
#[cfg(not(feature = "hw-trezor"))]
fn derive_wrapping_key() -> Result<([u8; 32], String), KeyError> {
    Err(KeyError::NotImplemented(
        "Trezor support requires the hw-trezor feature flag. \
         Rebuild with: cargo build --features hw-trezor"
            .into(),
    ))
}

// ---------------------------------------------------------------------------
// Fallback detection (no trezor-client)
// ---------------------------------------------------------------------------

/// Basic USB detection without `trezor-client` crate.
///
/// Uses system commands (ioreg/lsusb) to check for Trezor USB vendor/product IDs.
/// This is used when the hw-trezor feature is not enabled — the provider
/// appears as DetectionOnly in the UI.
#[cfg(not(feature = "hw-trezor"))]
fn detect_trezor_basic() -> ProviderCapability {
    let found = if cfg!(target_os = "macos") {
        std::process::Command::new("ioreg")
            .args(["-p", "IOUSB", "-l"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
            .map(|o| {
                let stdout = String::from_utf8_lossy(&o.stdout);
                // SatoshiLabs USB vendor ID: 0x1209, product: 0x53c1 (Trezor One), 0x53c0 (Model T)
                stdout.contains("1209:53c1")
                    || stdout.contains("1209:53c0")
                    || stdout.contains("Trezor")
            })
            .unwrap_or(false)
    } else if cfg!(target_os = "linux") {
        std::process::Command::new("lsusb")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
            .map(|o| {
                let stdout = String::from_utf8_lossy(&o.stdout);
                stdout.contains("1209:53c1") || stdout.contains("1209:53c0")
            })
            .unwrap_or(false)
    } else {
        false
    };

    ProviderCapability {
        mode: SovereigntyMode::Trezor,
        available: found,
        description: if found {
            "Trezor detected — enable hw-trezor feature for full support".into()
        } else {
            "No Trezor device detected — connect your Trezor to use this mode".into()
        },
        requires_enrollment: true,
        detail: None,
        // Without the feature flag, detection only. With it, Ready.
        implementation_status: ProviderStatus::DetectionOnly,
    }
}
