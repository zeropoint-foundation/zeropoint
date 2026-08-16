//! # `zp-anchor-ots` — the anchor floor
//!
//! An [`OtsAnchor`] implements [`zp_anchor::TruthAnchor`] against
//! OpenTimestamps: a chain head hash is submitted to several Bitcoin calendar
//! servers, and the returned proof eventually links that hash to a Bitcoin
//! block header.
//!
//! Per `docs/design/ANCHOR-BACKEND-SELECTION-2026-08.md` §3.4 this is the
//! **floor**, not the only backend. It is chosen as the default because
//! enabling it asks nothing of the operator — no account, no funded balance,
//! no registration — so the air-gapped and unbanked deployments anchor too.
//! `zp-anchor-hedera` is the **escalation**, and answers the property this
//! crate structurally cannot: a third party cannot confirm a commitment exists
//! without the operator producing the proof, because the proof is a file the
//! operator holds.
//!
//! ## Two phases, and the trait models one
//!
//! This is the sharpest impedance mismatch and it is not papered over.
//!
//! OTS timestamping is two-phase. Submission returns in about a second with a
//! *partial* proof — a commitment the calendar promises to attest. Bitcoin
//! confirmation follows, typically within hours, and only then can the proof be
//! *upgraded* into one that stands on its own.
//!
//! [`zp_anchor::AnchorReceipt`] has one `consensus_timestamp` and no notion of
//! a provisional state. This crate resolves that honestly rather than
//! conveniently:
//!
//! - `anchor()` stores the partial proof and returns a receipt whose
//!   `consensus_timestamp` is the **submission** time, with
//!   [`OtsProof::attested`] false inside `ledger_proof`.
//! - `verify()` reports `anchor_valid: false` for any proof that is not yet
//!   attested, with a summary saying so. An unupgraded proof is not yet
//!   evidence of precedence, and reporting it as valid would be the same
//!   fail-open shape this substrate spent Phase 1 removing.
//!
//! ## What this crate does not yet do — read before trusting it
//!
//! **AT2 is not met.** `docs/design/ANCHOR-BACKEND-SELECTION-2026-08.md` §4
//! requires that an upgraded proof verify with every calendar server
//! unreachable. That needs two things this crate does not have:
//!
//! 1. **Proof replay.** Parsing the `.ots` commitment-operation tree and
//!    playing it forward to a Bitcoin merkle root.
//!    [`opentimestamps`](https://crates.io/crates/opentimestamps) does exactly
//!    this and nothing else useful here — it parses and serialises `.ots` and
//!    computes the eventual hash, and explicitly does *not* create timestamps,
//!    verify them, or talk to calendars. It is the right dependency for this
//!    step and is deliberately not yet taken, because taking it changes what
//!    `verify()` may claim.
//! 2. **A block-header source whose honesty does not matter.** Headers may be
//!    fetched from anywhere provided proof-of-work and linkage are checked
//!    locally; that is what keeps "verifies offline" true in the sense that
//!    matters — no *particular* party must be trusted or reachable.
//!
//! Until both land, `verify()` confirms that a completed proof is *retrievable*
//! and says plainly that it has not been independently replayed. That is a
//! weaker claim than AT2 and the code says so rather than implying otherwise.
//!
//! ## Calendars are contacted concurrently, and that is a correctness property
//!
//! All three calendar round-trips — submit, upgrade, reachability — fan out
//! rather than iterate. Serially, three calendars at a 10-second timeout cost
//! up to 30 seconds, and because anchoring is event-driven that stall lands
//! inside a governance flow rather than in a background job: a gate denial or
//! a dispute is exactly when an anchor fires and exactly when a 30-second block
//! is least acceptable. Fanning out bounds the worst case at one timeout.
//!
//! **This does not make anchoring free.** One timeout is still up to ten
//! seconds of awaiting inside whatever called it. Whether `anchor()` should be
//! awaited on a governance path at all, or dispatched and reconciled later, is
//! a question for the pipeline that owns the trigger rather than for this
//! crate — noted here because the concurrency fix improves the number without
//! changing the shape.
//!
//! ## Payload
//!
//! Only the chain head hash is submitted. Not the sequence, not the trigger,
//! not the signature — per the edit sheet's E6, `chain_sequence` hands an
//! observer the substrate's growth rate and buys the verifier nothing. The
//! operator signature stays in the local chain, where it proves *who asserted*
//! the head; the timestamp proves only that the head *existed by* a time, and
//! that decomposition is correct rather than a shortcut.

mod calendar;

use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use zp_anchor::{
    AnchorCommitment, AnchorError, AnchorReceipt, AnchorVerification, Result, TruthAnchor,
};

pub use calendar::CALENDARS;

const BACKEND: &str = "opentimestamps";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// What this crate stores in [`AnchorReceipt::ledger_proof`], as JSON.
///
/// The trait documents that field as "opaque ledger-specific verification
/// data", and for OTS the useful contents are the per-calendar partial proofs
/// plus whether an attestation has landed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtsProof {
    /// The 32-byte digest submitted, hex-encoded. This is the chain head hash.
    pub digest_hex: String,

    /// Raw partial-proof bytes per calendar that accepted the submission.
    pub partial: Vec<CalendarProof>,

    /// A completed, Bitcoin-attested proof, once `verify()` has upgraded one.
    pub attested_proof: Option<Vec<u8>>,

    /// False until an attested proof has been retrieved. See the crate docs on
    /// why this is not collapsed into the receipt's timestamp.
    pub attested: bool,

    /// When the digest was submitted. **Not** a consensus timestamp — the local
    /// clock, recorded so the gap to attestation is measurable.
    pub submitted_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalendarProof {
    pub calendar: String,
    #[serde(with = "hex_bytes")]
    pub bytes: Vec<u8>,
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

/// OpenTimestamps anchor backend.
pub struct OtsAnchor {
    client: reqwest::Client,
    calendars: Vec<String>,
    /// Where receipts are persisted. `query_range` reads this directory;
    /// there is no remote index, which is the custody property the memo names.
    store_dir: PathBuf,
    timeout: Duration,
}

impl OtsAnchor {
    /// Construct with the default public calendars.
    pub fn new(store_dir: impl Into<PathBuf>) -> Self {
        Self::with_calendars(store_dir, CALENDARS.iter().map(|s| s.to_string()).collect())
    }

    pub fn with_calendars(store_dir: impl Into<PathBuf>, calendars: Vec<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            calendars,
            store_dir: store_dir.into(),
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Decode the commitment's chain head hash into the 32 bytes to submit.
    ///
    /// Rejects anything that is not exactly 32 bytes of hex. A short or
    /// malformed head is a programming error upstream, and submitting a
    /// truncated digest would produce a proof of the wrong thing — which
    /// verifies cleanly and attests nothing.
    fn digest_of(commitment: &AnchorCommitment) -> Result<[u8; 32]> {
        let raw = hex::decode(&commitment.chain_head_hash)
            .map_err(|e| AnchorError::Internal(format!("chain_head_hash is not hex: {e}")))?;
        let arr: [u8; 32] = raw.as_slice().try_into().map_err(|_| {
            AnchorError::Internal(format!(
                "chain_head_hash decoded to {} bytes, expected 32",
                raw.len()
            ))
        })?;
        Ok(arr)
    }

    fn receipt_path(&self, digest_hex: &str) -> PathBuf {
        self.store_dir.join(format!("{digest_hex}.json"))
    }

    async fn persist(&self, receipt: &AnchorReceipt) -> Result<()> {
        tokio::fs::create_dir_all(&self.store_dir)
            .await
            .map_err(|e| AnchorError::Internal(format!("creating {:?}: {e}", self.store_dir)))?;

        let proof = Self::decode_proof(receipt)?;
        let path = self.receipt_path(&proof.digest_hex);
        let json = serde_json::to_vec_pretty(receipt)
            .map_err(|e| AnchorError::Internal(format!("serialising receipt: {e}")))?;

        tokio::fs::write(&path, json)
            .await
            .map_err(|e| AnchorError::Internal(format!("writing {path:?}: {e}")))
    }

    fn decode_proof(receipt: &AnchorReceipt) -> Result<OtsProof> {
        serde_json::from_slice(&receipt.ledger_proof).map_err(|e| AnchorError::VerificationFailed {
            reason: format!("ledger_proof is not an OtsProof: {e}"),
        })
    }

    fn encode_proof(proof: &OtsProof) -> Result<Vec<u8>> {
        serde_json::to_vec(proof)
            .map_err(|e| AnchorError::Internal(format!("serialising OtsProof: {e}")))
    }
}

#[async_trait]
impl TruthAnchor for OtsAnchor {
    /// Submit the chain head to every configured calendar; keep what answers.
    ///
    /// One calendar succeeding is enough to return a receipt — the redundancy
    /// exists so that a single stalled operator cannot stall the commitment,
    /// not because a quorum is required. All failing is an error, because a
    /// commitment nobody accepted was not made.
    async fn anchor(&self, commitment: AnchorCommitment) -> Result<AnchorReceipt> {
        let digest = Self::digest_of(&commitment)?;
        let submitted_at = Utc::now();

        let mut partial = Vec::new();
        let mut failures = Vec::new();

        // Concurrent, not sequential. Submitted serially with a 10s per-call
        // timeout, three calendars cost up to 30s of blocking — and anchoring
        // is event-driven, so that stall lands inside a governance flow
        // (a gate denial, a dispute) rather than in a background job. Fanning
        // out bounds the worst case at one timeout instead of N.
        let client = &self.client;
        let timeout = self.timeout;
        let outcomes = futures::future::join_all(self.calendars.iter().map(|cal| async move {
            (
                cal.clone(),
                calendar::submit(client, cal, &digest, timeout).await,
            )
        }))
        .await;

        for (cal, outcome) in outcomes {
            match outcome {
                Ok(p) => {
                    debug!(calendar = %p.calendar, bytes = p.bytes.len(), "ots: partial proof");
                    partial.push(CalendarProof {
                        calendar: p.calendar,
                        bytes: p.bytes,
                    });
                }
                Err(e) => {
                    warn!(calendar = %cal, error = %e, "ots: calendar submission failed");
                    failures.push(format!("{cal}: {e}"));
                }
            }
        }

        if partial.is_empty() {
            return Err(AnchorError::Network(format!(
                "no calendar accepted the commitment ({} tried): {}",
                self.calendars.len(),
                failures.join("; ")
            )));
        }

        let proof = OtsProof {
            digest_hex: hex::encode(digest),
            partial,
            attested_proof: None,
            attested: false,
            submitted_at,
        };

        let receipt = AnchorReceipt {
            external_id: proof.digest_hex.clone(),
            // Submission time, NOT a consensus timestamp. See the crate docs —
            // `attested` is the field that says whether Bitcoin has spoken.
            consensus_timestamp: submitted_at,
            commitment,
            ledger_proof: Self::encode_proof(&proof)?,
            backend: BACKEND.to_string(),
        };

        self.persist(&receipt).await?;
        Ok(receipt)
    }

    /// Attempt to upgrade, then report honestly.
    ///
    /// Never returns `anchor_valid: true` today. Retrieving a completed proof
    /// shows the calendar has attested; it does not show that *we* replayed the
    /// proof to a Bitcoin header, and only the latter is verification. See the
    /// crate docs on AT2.
    async fn verify(&self, receipt: &AnchorReceipt) -> Result<AnchorVerification> {
        let mut proof = Self::decode_proof(receipt)?;
        let digest: [u8; 32] = hex::decode(&proof.digest_hex)
            .ok()
            .and_then(|v| v.as_slice().try_into().ok())
            .ok_or_else(|| AnchorError::VerificationFailed {
                reason: "stored digest is not 32 bytes of hex".to_string(),
            })?;

        let chain_matches = receipt.commitment.chain_head_hash == proof.digest_hex;

        if !proof.attested {
            // Concurrent for the same reason as `anchor`. This gives up the
            // old short-circuit — every calendar is now asked even when the
            // first already has the attestation — which costs two extra
            // requests and buys a worst case of one timeout rather than three.
            // At three calendars and event-driven cadence that trade is clear.
            let client = &self.client;
            let timeout = self.timeout;
            let outcomes = futures::future::join_all(self.calendars.iter().map(|cal| async move {
                (
                    cal.clone(),
                    calendar::upgrade(client, cal, &digest, timeout).await,
                )
            }))
            .await;

            for (cal, outcome) in outcomes {
                match outcome {
                    Ok(Some(bytes)) => {
                        proof.attested_proof = Some(bytes);
                        proof.attested = true;
                        break;
                    }
                    Ok(None) => {}
                    Err(e) => warn!(calendar = %cal, error = %e, "ots: upgrade attempt failed"),
                }
            }
        }

        let waited = Utc::now() - proof.submitted_at;

        let summary = if !chain_matches {
            "chain head does not match the anchored digest".to_string()
        } else if proof.attested {
            format!(
                "attested proof retrieved after {}h — NOT independently verified: \
                 proof replay against a Bitcoin header is unimplemented (see crate docs, AT2)",
                waited.num_hours()
            )
        } else {
            format!(
                "pending Bitcoin attestation, {}h since submission — \
                 an unupgraded proof is not yet evidence of precedence",
                waited.num_hours()
            )
        };

        Ok(AnchorVerification {
            chain_matches,
            // Deliberately never true yet. Reporting retrievability as validity
            // is the fail-open shape Phase 1 removed elsewhere.
            anchor_valid: false,
            drift: waited,
            summary,
        })
    }

    /// Read locally stored receipts in a time range.
    ///
    /// Local by necessity, not by choice: OTS has no queryable index, which is
    /// exactly the non-suppressibility gap the memo names and Hedera answers.
    async fn query_range(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<Vec<AnchorReceipt>> {
        let mut out = Vec::new();

        let mut dir = match tokio::fs::read_dir(&self.store_dir).await {
            Ok(d) => d,
            // No directory means nothing has been anchored, which is an empty
            // answer rather than a fault.
            Err(_) => return Ok(out),
        };

        while let Ok(Some(entry)) = dir.next_entry().await {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let Ok(bytes) = tokio::fs::read(&path).await else {
                continue;
            };
            let Ok(receipt) = serde_json::from_slice::<AnchorReceipt>(&bytes) else {
                warn!(?path, "ots: unreadable receipt in store, skipping");
                continue;
            };
            if receipt.consensus_timestamp >= from && receipt.consensus_timestamp <= to {
                out.push(receipt);
            }
        }

        out.sort_by_key(|r| r.consensus_timestamp);
        Ok(out)
    }

    fn backend_name(&self) -> &str {
        BACKEND
    }

    async fn is_available(&self) -> bool {
        // Concurrent: an all-unreachable check was the worst case here, and it
        // is exactly the case a caller asks about.
        let client = &self.client;
        let timeout = self.timeout;
        futures::future::join_all(
            self.calendars
                .iter()
                .map(|cal| calendar::reachable(client, cal, timeout)),
        )
        .await
        .into_iter()
        .any(|reachable| reachable)
    }
}

/// Where receipts live by default, relative to a caller-supplied data dir.
pub fn default_store_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("anchors").join("ots")
}

#[cfg(test)]
mod tests {
    use super::*;
    use zp_anchor::{AnchorTrigger, ChainType};

    fn commitment(head: &str) -> AnchorCommitment {
        AnchorCommitment {
            chain_head_hash: head.to_string(),
            chain_sequence: 42,
            prev_anchor_hash: None,
            operator_signature: "deadbeef".to_string(),
            chain_type: ChainType::AuditChain,
            trigger: AnchorTrigger::ComplianceCheckpoint {
                reason: "test".to_string(),
            },
        }
    }

    #[test]
    fn digest_accepts_a_32_byte_head() {
        let head = "ab".repeat(32);
        let d = OtsAnchor::digest_of(&commitment(&head)).expect("should decode");
        assert_eq!(d, [0xabu8; 32]);
    }

    /// A truncated head must not be padded or accepted. A proof of the wrong
    /// bytes verifies cleanly and attests nothing, which is the worst failure
    /// mode available here.
    #[test]
    fn digest_rejects_a_short_head() {
        let err = OtsAnchor::digest_of(&commitment(&"ab".repeat(16))).unwrap_err();
        assert!(
            format!("{err}").contains("expected 32"),
            "error should name the length problem, got: {err}"
        );
    }

    #[test]
    fn digest_rejects_non_hex() {
        assert!(OtsAnchor::digest_of(&commitment("zzzz")).is_err());
    }

    #[test]
    fn proof_round_trips_through_ledger_proof() {
        let proof = OtsProof {
            digest_hex: "ab".repeat(32),
            partial: vec![CalendarProof {
                calendar: "https://example.invalid".to_string(),
                bytes: vec![1, 2, 3],
            }],
            attested_proof: None,
            attested: false,
            submitted_at: Utc::now(),
        };
        let encoded = OtsAnchor::encode_proof(&proof).unwrap();
        let receipt = AnchorReceipt {
            external_id: proof.digest_hex.clone(),
            consensus_timestamp: Utc::now(),
            commitment: commitment(&proof.digest_hex),
            ledger_proof: encoded,
            backend: BACKEND.to_string(),
        };
        let back = OtsAnchor::decode_proof(&receipt).unwrap();
        assert_eq!(back.digest_hex, proof.digest_hex);
        assert_eq!(back.partial[0].bytes, vec![1, 2, 3]);
        assert!(!back.attested);
    }

    /// The property the crate docs promise: an unattested proof is never
    /// reported as valid. If this ever passes with `anchor_valid: true`, the
    /// crate has started claiming precedence it cannot demonstrate.
    #[tokio::test]
    async fn unattested_proof_is_not_reported_valid() {
        let tmp = tempfile::tempdir().unwrap();
        // No reachable calendars — upgrade attempts fail, which must not
        // promote the verdict.
        let anchor = OtsAnchor::with_calendars(
            tmp.path().to_path_buf(),
            vec!["https://calendar.invalid".to_string()],
        );

        let head = "cd".repeat(32);
        let proof = OtsProof {
            digest_hex: head.clone(),
            partial: vec![],
            attested_proof: None,
            attested: false,
            submitted_at: Utc::now() - chrono::Duration::hours(3),
        };
        let receipt = AnchorReceipt {
            external_id: head.clone(),
            consensus_timestamp: Utc::now(),
            commitment: commitment(&head),
            ledger_proof: OtsAnchor::encode_proof(&proof).unwrap(),
            backend: BACKEND.to_string(),
        };

        let v = anchor.verify(&receipt).await.unwrap();
        assert!(v.chain_matches, "digest matches the head it was made from");
        assert!(
            !v.anchor_valid,
            "an unattested proof must never read as valid"
        );
        assert!(
            v.summary.contains("pending Bitcoin attestation"),
            "summary should name the pending state, got: {}",
            v.summary
        );
    }

    #[tokio::test]
    async fn query_range_on_an_empty_store_is_empty_not_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let anchor = OtsAnchor::new(tmp.path().join("nonexistent"));
        let out = anchor
            .query_range(Utc::now() - chrono::Duration::days(1), Utc::now())
            .await
            .unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn default_store_dir_is_under_the_data_dir() {
        let p = default_store_dir(Path::new("/tmp/zp/data"));
        assert!(p.ends_with("anchors/ots"));
    }
}
