//! Genesis ceremony integrity verification.
//!
//! The Genesis ceremony writes two files:
//!   * `~/ZeroPoint/genesis.json`             — canonical record (unsigned)
//!   * `~/ZeroPoint/genesis_transcript.json`  — signed attestation
//!
//! The transcript contains every substantive field from `genesis.json`
//! plus additional ceremony metadata (platform, provider capabilities,
//! software version, genesis fingerprint), and is signed with the Genesis
//! key itself over a BLAKE3 hash of the canonical-serialized transcript.
//! Possession of a valid transcript whose fields match `genesis.json` is
//! proof that the ceremony completed and the record hasn't been tampered
//! with post-hoc.
//!
//! This module exposes `verify()` which returns a `Verdict` enum consumed
//! by the security check in `security.rs`. Pure function: reads both
//! files, does cryptographic and field-consistency checks, no side
//! effects.
//!
//! History note — this file was added in response to ARTEMIS result 035
//! issue 2, where the dashboard reported "Genesis record exists but
//! signature missing — integrity unverifiable" despite a valid signed
//! transcript being on disk. The prior `security.rs` check was looking
//! for a file named `genesis.sig` that the ceremony has never written.

use std::path::Path;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// Verification verdict for a Genesis ceremony on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// `genesis.json` + signed transcript both present, signature valid,
    /// cross-referenced fields match. Sovereign identity is anchored.
    Verified,

    /// `genesis.json` present but no transcript on disk. Most likely the
    /// ceremony was interrupted after the record was written but before
    /// the transcript was signed (see result 028). Integrity is
    /// unverifiable; the user should re-run onboarding.
    NoTranscript,

    /// `genesis.json` present, transcript present but unparseable or
    /// missing required fields. Suggests truncation or a partial write.
    MalformedTranscript(&'static str),

    /// Transcript parseable but its Ed25519 signature does not verify
    /// against the genesis public key embedded in the transcript.
    /// Either the transcript or the embedded public key was tampered
    /// with post-ceremony.
    SignatureInvalid,

    /// Transcript's signature verifies, but one or more fields in
    /// `genesis.json` disagree with the corresponding fields inside the
    /// signed transcript (e.g. operator name or public key differs).
    /// Whichever file was modified after the ceremony is suspect.
    FieldMismatch(&'static str),

    /// No `genesis.json` on disk. Ceremony has not been run.
    NotEstablished,
}

impl Verdict {
    /// Human-readable summary for UI surfaces.
    pub fn detail(&self) -> String {
        match self {
            Verdict::Verified => {
                "Genesis record verified against signed transcript — sovereign identity anchored"
                    .into()
            }
            Verdict::NoTranscript => {
                "Genesis record present but ceremony transcript missing — ceremony likely \
                 interrupted; re-run onboarding to restore integrity"
                    .into()
            }
            Verdict::MalformedTranscript(why) => {
                format!("Ceremony transcript unreadable ({}) — integrity unverifiable", why)
            }
            Verdict::SignatureInvalid => {
                "Ceremony transcript signature failed verification — record may have been \
                 tampered with"
                    .into()
            }
            Verdict::FieldMismatch(field) => {
                format!(
                    "genesis.json disagrees with signed transcript on `{}` — record may have been \
                     tampered with",
                    field
                )
            }
            Verdict::NotEstablished => {
                "Genesis not established — run onboarding to create identity".into()
            }
        }
    }
}

/// Inspect the Genesis ceremony artifacts under `zeropoint_home` and
/// return a `Verdict`. `zeropoint_home` is typically the result of
/// `zp_core::paths::home()`.
pub fn verify(zeropoint_home: &Path) -> Verdict {
    let genesis_path = zeropoint_home.join("genesis.json");
    let transcript_path = zeropoint_home.join("genesis_transcript.json");

    if !genesis_path.exists() {
        return Verdict::NotEstablished;
    }

    if !transcript_path.exists() {
        return Verdict::NoTranscript;
    }

    let transcript_raw = match std::fs::read_to_string(&transcript_path) {
        Ok(s) => s,
        Err(_) => return Verdict::MalformedTranscript("read failed"),
    };
    let signed: serde_json::Value = match serde_json::from_str(&transcript_raw) {
        Ok(v) => v,
        Err(_) => return Verdict::MalformedTranscript("json parse failed"),
    };

    let transcript = match signed.get("transcript") {
        Some(t) if t.is_object() => t,
        _ => return Verdict::MalformedTranscript("missing transcript object"),
    };
    let signature_value = match signed
        .get("signature")
        .and_then(|s| s.get("value"))
        .and_then(|v| v.as_str())
    {
        Some(v) => v,
        None => return Verdict::MalformedTranscript("missing signature.value"),
    };

    // Signer is the Genesis key itself, embedded in the transcript.
    let pk_hex = match transcript.get("genesis_public_key").and_then(|v| v.as_str()) {
        Some(v) => v,
        None => return Verdict::MalformedTranscript("transcript missing genesis_public_key"),
    };

    // Decode public key + signature
    let pk_bytes = match hex::decode(pk_hex) {
        Ok(b) if b.len() == 32 => b,
        _ => return Verdict::MalformedTranscript("genesis_public_key not 32-byte hex"),
    };
    let pk_array: [u8; 32] = pk_bytes.try_into().unwrap(); // len checked above
    let verifying_key = match VerifyingKey::from_bytes(&pk_array) {
        Ok(vk) => vk,
        Err(_) => return Verdict::MalformedTranscript("genesis_public_key not on curve"),
    };

    let sig_bytes = match hex::decode(signature_value) {
        Ok(b) if b.len() == 64 => b,
        _ => return Verdict::MalformedTranscript("signature not 64-byte hex"),
    };
    let sig_array: [u8; 64] = sig_bytes.try_into().unwrap(); // len checked above
    let signature = Signature::from_bytes(&sig_array);

    // Re-serialize the transcript sub-value. serde_json Value is backed
    // by a BTreeMap (no `preserve_order` feature in this workspace), so
    // `to_vec` emits keys in alphabetical order. The signing path in
    // onboard/genesis.rs builds the transcript via `json!{}` and calls
    // `serde_json::to_vec` on it directly, so both paths produce
    // byte-identical input to BLAKE3.
    let transcript_bytes = match serde_json::to_vec(transcript) {
        Ok(b) => b,
        Err(_) => return Verdict::MalformedTranscript("transcript re-serialize failed"),
    };
    let transcript_hash = blake3::hash(&transcript_bytes);

    if verifying_key
        .verify(transcript_hash.as_bytes(), &signature)
        .is_err()
    {
        return Verdict::SignatureInvalid;
    }

    // Signature checks out. Cross-check `genesis.json` against the
    // signed transcript to catch post-ceremony tampering of the
    // unsigned record.
    let genesis_raw = match std::fs::read_to_string(&genesis_path) {
        Ok(s) => s,
        Err(_) => return Verdict::MalformedTranscript("genesis.json read failed"),
    };
    let genesis: serde_json::Value = match serde_json::from_str(&genesis_raw) {
        Ok(v) => v,
        Err(_) => return Verdict::MalformedTranscript("genesis.json parse failed"),
    };

    // Fields that both files carry. If the ceremony didn't populate one
    // of these on either side, treat the field as absent on BOTH and
    // move on — we're checking for disagreement, not completeness.
    const CROSS_FIELDS: &[&str] = &[
        "operator",
        "genesis_public_key",
        "operator_public_key",
        "constitutional_hash",
        "sovereignty_mode",
        "algorithm",
        "timestamp",
    ];
    for field in CROSS_FIELDS {
        let g = genesis.get(*field);
        let t = transcript.get(*field);
        if g != t {
            return Verdict::FieldMismatch(field);
        }
    }

    Verdict::Verified
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Drop-guarded temp directory so we don't pull in the `tempfile`
    /// crate just for tests (matches the pattern used by auth.rs).
    struct Scratch {
        path: std::path::PathBuf,
    }
    impl Scratch {
        fn new() -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let pid = std::process::id();
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let path = std::env::temp_dir().join(format!("zp-genverify-{}-{}-{}", pid, ts, n));
            fs::create_dir_all(&path).unwrap();
            Self { path }
        }
        fn path(&self) -> &Path {
            &self.path
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    /// Mirror the real ceremony write path in miniature so the test can't
    /// drift from the signing code. Writes `genesis.json` +
    /// `genesis_transcript.json` under `dir`.
    fn write_valid_ceremony(dir: &Path) -> String {
        use ed25519_dalek::{Signer, SigningKey};

        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let vk = sk.verifying_key();
        let genesis_pub_hex = hex::encode(vk.to_bytes());
        let operator_pub_hex =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
        let constitutional_hash =
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string();
        let timestamp = "2026-04-14T12:00:00+00:00".to_string();

        let transcript = serde_json::json!({
            "ceremony": "genesis",
            "version": "1.0",
            "timestamp": &timestamp,
            "operator": "alice",
            "sovereignty_mode": "Touch_id",
            "sovereignty_category": "Biometric",
            "provider_capabilities": {"secure_element": true},
            "genesis_public_key": &genesis_pub_hex,
            "genesis_fingerprint": "abcd1234",
            "operator_public_key": &operator_pub_hex,
            "constitutional_hash": &constitutional_hash,
            "algorithm": "Ed25519",
            "software_version": "0.1.0",
            "platform": "linux",
        });

        let transcript_bytes = serde_json::to_vec(&transcript).unwrap();
        let sig = sk.sign(blake3::hash(&transcript_bytes).as_bytes());

        let signed = serde_json::json!({
            "transcript": transcript,
            "signature": {
                "algorithm": "Ed25519",
                "hash": "BLAKE3",
                "value": hex::encode(sig.to_bytes()),
            },
        });

        fs::write(
            dir.join("genesis_transcript.json"),
            serde_json::to_string_pretty(&signed).unwrap(),
        )
        .unwrap();

        let genesis = serde_json::json!({
            "version": "2.0",
            "timestamp": &timestamp,
            "operator": "alice",
            "genesis_public_key": &genesis_pub_hex,
            "operator_public_key": &operator_pub_hex,
            "constitutional_hash": &constitutional_hash,
            "algorithm": "Ed25519",
            "sovereignty_mode": "Touch_id",
        });
        fs::write(
            dir.join("genesis.json"),
            serde_json::to_string_pretty(&genesis).unwrap(),
        )
        .unwrap();

        genesis_pub_hex
    }

    #[test]
    fn verify_happy_path() {
        let tmp = Scratch::new();
        write_valid_ceremony(tmp.path());
        assert_eq!(verify(tmp.path()), Verdict::Verified);
    }

    #[test]
    fn not_established_when_no_genesis_json() {
        let tmp = Scratch::new();
        assert_eq!(verify(tmp.path()), Verdict::NotEstablished);
    }

    #[test]
    fn no_transcript_when_genesis_but_not_transcript() {
        let tmp = Scratch::new();
        fs::write(tmp.path().join("genesis.json"), r#"{"operator":"x"}"#).unwrap();
        assert_eq!(verify(tmp.path()), Verdict::NoTranscript);
    }

    #[test]
    fn malformed_transcript_not_json() {
        let tmp = Scratch::new();
        fs::write(tmp.path().join("genesis.json"), r#"{"operator":"x"}"#).unwrap();
        fs::write(
            tmp.path().join("genesis_transcript.json"),
            "not json at all",
        )
        .unwrap();
        assert!(matches!(
            verify(tmp.path()),
            Verdict::MalformedTranscript(_)
        ));
    }

    #[test]
    fn malformed_transcript_missing_signature() {
        let tmp = Scratch::new();
        fs::write(tmp.path().join("genesis.json"), r#"{"operator":"x"}"#).unwrap();
        fs::write(
            tmp.path().join("genesis_transcript.json"),
            r#"{"transcript":{"genesis_public_key":"00"}}"#,
        )
        .unwrap();
        assert!(matches!(
            verify(tmp.path()),
            Verdict::MalformedTranscript(_)
        ));
    }

    #[test]
    fn signature_invalid_when_transcript_tampered() {
        let tmp = Scratch::new();
        write_valid_ceremony(tmp.path());

        // Mutate the transcript's operator in-place. The signature was
        // computed over the pre-mutation bytes, so verify must fail.
        let raw = fs::read_to_string(tmp.path().join("genesis_transcript.json")).unwrap();
        let mut signed: serde_json::Value = serde_json::from_str(&raw).unwrap();
        signed["transcript"]["operator"] = serde_json::Value::String("mallory".into());
        fs::write(
            tmp.path().join("genesis_transcript.json"),
            serde_json::to_string_pretty(&signed).unwrap(),
        )
        .unwrap();

        assert_eq!(verify(tmp.path()), Verdict::SignatureInvalid);
    }

    #[test]
    fn field_mismatch_when_genesis_json_tampered() {
        let tmp = Scratch::new();
        write_valid_ceremony(tmp.path());

        // Change operator in genesis.json but leave the signed transcript
        // alone — the signature stays valid, but cross-check catches it.
        let raw = fs::read_to_string(tmp.path().join("genesis.json")).unwrap();
        let mut genesis: serde_json::Value = serde_json::from_str(&raw).unwrap();
        genesis["operator"] = serde_json::Value::String("mallory".into());
        fs::write(
            tmp.path().join("genesis.json"),
            serde_json::to_string_pretty(&genesis).unwrap(),
        )
        .unwrap();

        assert_eq!(
            verify(tmp.path()),
            Verdict::FieldMismatch("operator")
        );
    }

    #[test]
    fn detail_strings_are_reasonable() {
        // Sanity-check all branches have non-empty messages.
        for v in [
            Verdict::Verified,
            Verdict::NoTranscript,
            Verdict::MalformedTranscript("test"),
            Verdict::SignatureInvalid,
            Verdict::FieldMismatch("x"),
            Verdict::NotEstablished,
        ] {
            assert!(!v.detail().is_empty());
        }
    }
}
