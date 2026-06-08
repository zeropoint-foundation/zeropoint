//! Foundation Worker → Operator zp-server receipt relay.
//!
//! Exposes two endpoints consumed by the Cloudflare-hosted Foundation
//! Edge worker:
//!
//! - `POST /v1/foundation-receipts` — accepts a *receipt-intent* envelope
//!   from the worker, verifies the envelope's Ed25519 signature against
//!   the worker's registered pubkey, builds and signs the canonical
//!   `Receipt`, appends it to the operator's audit chain, and returns
//!   the signed receipt JSON.
//!
//! - `GET /v1/foundation-receipts` — proxied chain query path. Same
//!   envelope auth. Returns paginated signed receipts.
//!
//! The worker holds an Ed25519 *envelope* keypair derived from Genesis
//! via `zp.foundation.edge.v1` (see `zp_keys::foundation_edge_signer`)
//! and stored as a Cloudflare secret. The envelope key attests
//! "this HTTP body originated from the legitimate Foundation Edge
//! identity" — it does **not** sign canonical receipts. Receipt
//! signing happens on the operator's `zp-server` using the operator's
//! own signing key, so the canonical chain never depends on edge-stored
//! key material.
//!
//! Pubkey registry lives at `~/ZeroPoint/config/foundation-edge-keys.json`,
//! maintained by `zp keys derive foundation-edge`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::AppState;
use zp_audit::UnsealedEntry;
use zp_core::{ActorId, AuditAction, ConversationId, PolicyDecision};
use zp_receipt::{
    Action, ActionType, ClaimSemantics, ReceiptBuilder, ReceiptType, Status, TrustGrade,
};

// ── Registry ──────────────────────────────────────────────────────────────────

/// One entry in the worker pubkey registry (mirrors the on-disk shape produced
/// by `zp keys derive foundation-edge`).
#[derive(Debug, Clone, Deserialize, Serialize)]
struct RegistryEntry {
    id: String,
    pubkey: String,
    #[allow(dead_code)]
    added_at: Option<String>,
    /// `null` while active; tag of the successor key when this one has
    /// been rotated out.
    rotated_to: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct RegistryFile {
    keys: Vec<RegistryEntry>,
}

/// In-memory snapshot of the on-disk registry, keyed by `pubkey_id`.
struct RegistrySnapshot {
    /// pubkey_id → parsed VerifyingKey + active flag
    keys: HashMap<String, RegistrySnapshotEntry>,
    /// File mtime at the last load; we reload when it changes.
    mtime: Option<SystemTime>,
}

struct RegistrySnapshotEntry {
    verifying_key: VerifyingKey,
    active: bool,
}

/// Thread-safe registry loader with mtime-based cache invalidation.
///
/// Cheap to consult per request; only re-reads the JSON file when the
/// on-disk mtime changes. Manual editing of the file (per the
/// handoff doc's persistence note) takes effect on the next request.
pub struct PubkeyRegistry {
    path: PathBuf,
    snapshot: RwLock<RegistrySnapshot>,
}

impl PubkeyRegistry {
    /// Construct an empty registry rooted at the given config path.
    /// Does not read the file — the first `verify()` call lazy-loads.
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            snapshot: RwLock::new(RegistrySnapshot {
                keys: HashMap::new(),
                mtime: None,
            }),
        }
    }

    /// Construct using the default location (`~/ZeroPoint/config/foundation-edge-keys.json`)
    /// derived from the supplied `ZeroPoint` home directory.
    pub fn at_zp_home(zp_home: &Path) -> Self {
        Self::new(zp_home.join("config").join("foundation-edge-keys.json"))
    }

    /// Verify an envelope signature against the canonical body bytes.
    ///
    /// Returns `Ok(())` if the registry contains `pubkey_id`, that entry
    /// is currently active (`rotated_to == null`), and the Ed25519
    /// signature checks out against the body. Otherwise `Err` with a
    /// short reason suitable for an HTTP 401.
    pub fn verify(
        &self,
        pubkey_id: &str,
        signature_b64: &str,
        body: &[u8],
    ) -> Result<(), String> {
        self.reload_if_changed();

        let snap = self.snapshot.read().map_err(|_| "registry poisoned")?;
        let entry = snap
            .keys
            .get(pubkey_id)
            .ok_or_else(|| format!("unknown pubkey_id: {}", pubkey_id))?;
        if !entry.active {
            return Err(format!("pubkey_id {} is rotated out", pubkey_id));
        }

        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(signature_b64)
            .map_err(|_| "signature is not valid base64".to_string())?;
        if sig_bytes.len() != 64 {
            return Err(format!(
                "signature must be 64 bytes, got {}",
                sig_bytes.len()
            ));
        }
        let sig = Signature::from_slice(&sig_bytes)
            .map_err(|_| "signature failed to parse".to_string())?;

        entry
            .verifying_key
            .verify_strict(body, &sig)
            .map_err(|_| "signature did not verify".to_string())
    }

    fn reload_if_changed(&self) {
        let current_mtime = std::fs::metadata(&self.path)
            .and_then(|m| m.modified())
            .ok();

        {
            let snap = match self.snapshot.read() {
                Ok(s) => s,
                Err(_) => return,
            };
            if snap.mtime == current_mtime {
                return;
            }
        }

        let bytes = match std::fs::read(&self.path) {
            Ok(b) => b,
            Err(_) => {
                // No file = empty registry; verify() will return
                // "unknown pubkey_id" for everything. That's the right
                // posture before the operator runs `zp keys derive
                // foundation-edge` even once.
                let mut snap = match self.snapshot.write() {
                    Ok(s) => s,
                    Err(_) => return,
                };
                snap.keys.clear();
                snap.mtime = None;
                return;
            }
        };

        let parsed: RegistryFile = match serde_json::from_slice(&bytes) {
            Ok(p) => p,
            Err(_) => {
                // Malformed JSON: leave the previous snapshot in place,
                // log the error. Don't blow up active sessions because
                // the operator's editor saved a half-state.
                tracing::warn!(
                    "foundation-edge-keys.json failed to parse; keeping previous snapshot"
                );
                return;
            }
        };

        let mut new_keys: HashMap<String, RegistrySnapshotEntry> = HashMap::new();
        for entry in parsed.keys {
            let pk_bytes = match hex::decode(&entry.pubkey) {
                Ok(b) if b.len() == 32 => b,
                _ => {
                    tracing::warn!(
                        "foundation-edge-keys.json: entry {} has invalid pubkey (not 32 hex bytes); skipping",
                        entry.id
                    );
                    continue;
                }
            };
            let pk_arr: [u8; 32] = match pk_bytes.try_into() {
                Ok(a) => a,
                Err(_) => continue,
            };
            let verifying_key = match VerifyingKey::from_bytes(&pk_arr) {
                Ok(k) => k,
                Err(_) => {
                    tracing::warn!(
                        "foundation-edge-keys.json: entry {} pubkey rejected by ed25519_dalek; skipping",
                        entry.id
                    );
                    continue;
                }
            };
            new_keys.insert(
                entry.id,
                RegistrySnapshotEntry {
                    verifying_key,
                    active: entry.rotated_to.is_none(),
                },
            );
        }

        let mut snap = match self.snapshot.write() {
            Ok(s) => s,
            Err(_) => return,
        };
        snap.keys = new_keys;
        snap.mtime = current_mtime;
    }
}

// ── Intent ────────────────────────────────────────────────────────────────────

/// Incoming receipt-intent envelope from the Foundation Edge worker.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReceiptIntent {
    pub intent_id: String,
    pub operator_id: String,
    pub claim: String,
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default)]
    pub capability_used: Option<String>,
    #[serde(default)]
    pub metadata: Option<Value>,
    pub requested_at: DateTime<Utc>,
}

impl ReceiptIntent {
    /// Validate the basic shape of an incoming intent.
    ///
    /// - `requested_at` must be within ±5 minutes of the operator's
    ///   clock (replay window).
    /// - `intent_id`, `operator_id`, and `claim` must be non-empty.
    fn validate(&self, now: DateTime<Utc>) -> Result<(), String> {
        if self.intent_id.is_empty() {
            return Err("intent_id is required".to_string());
        }
        if self.operator_id.is_empty() {
            return Err("operator_id is required".to_string());
        }
        if self.claim.is_empty() {
            return Err("claim is required".to_string());
        }
        let skew = now.signed_duration_since(self.requested_at);
        let allowed = Duration::minutes(5);
        if skew > allowed || skew < -allowed {
            return Err(format!(
                "requested_at clock skew {}s exceeds ±5min window",
                skew.num_seconds()
            ));
        }
        Ok(())
    }
}

// ── Envelope auth extraction ──────────────────────────────────────────────────

const HEADER_PUBKEY_ID: &str = "x-foundation-worker-pubkey-id";
const HEADER_SIGNATURE: &str = "x-foundation-worker-signature";

fn extract_envelope_headers(headers: &HeaderMap) -> Result<(String, String), Response> {
    let pubkey_id = headers
        .get(HEADER_PUBKEY_ID)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| auth_error("missing X-Foundation-Worker-Pubkey-Id"))?
        .to_string();
    let signature = headers
        .get(HEADER_SIGNATURE)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| auth_error("missing X-Foundation-Worker-Signature"))?
        .to_string();
    Ok((pubkey_id, signature))
}

fn auth_error(reason: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({ "error": "envelope_auth_failed", "reason": reason })),
    )
        .into_response()
}

// ── POST handler ──────────────────────────────────────────────────────────────

/// `POST /v1/foundation-receipts` — accept intent, sign canonical receipt,
/// append to chain, return signed receipt.
pub async fn post_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let registry = match &state.0.foundation_edge_registry {
        Some(r) => r.clone(),
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": "registry_unavailable",
                    "reason": "foundation-edge pubkey registry not initialized"
                })),
            )
                .into_response();
        }
    };

    // Verify envelope auth against the raw body bytes (before any parsing).
    let (pubkey_id, signature) = match extract_envelope_headers(&headers) {
        Ok(pair) => pair,
        Err(resp) => return resp,
    };

    if let Err(reason) = registry.verify(&pubkey_id, &signature, &body) {
        tracing::warn!(target: "foundation_relay", "envelope auth failed: {}", reason);
        return auth_error(&reason);
    }

    // Parse the intent.
    let intent: ReceiptIntent = match serde_json::from_slice(&body) {
        Ok(i) => i,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "intent_parse_failed",
                    "reason": e.to_string()
                })),
            )
                .into_response();
        }
    };

    let now = Utc::now();
    if let Err(reason) = intent.validate(now) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "intent_invalid", "reason": reason })),
        )
            .into_response();
    }

    // Dedupe by intent_id.
    {
        let mut seen = state.0.foundation_edge_seen_intents.lock().unwrap();
        if seen.contains_recent(&intent.intent_id, now) {
            // Idempotent replay: return the prior signed receipt if we have it.
            // For now we just 409 — surfacing the prior receipt would require
            // persisting the intent_id→receipt_id map. Worker should treat 409
            // as success-equivalent and not retry the underlying action.
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": "duplicate_intent_id",
                    "intent_id": intent.intent_id
                })),
            )
                .into_response();
        }
        seen.record(&intent.intent_id, now);
    }

    // Build the canonical receipt.
    let executor_id = &state.0.identity.destination_hash;
    let action_detail = serde_json::json!({
        "claim": intent.claim,
        "subject": intent.subject,
        "capability_used": intent.capability_used,
        "metadata": intent.metadata,
        "edge_pubkey_id": pubkey_id,
    });
    let action = Action {
        action_type: ActionType::ApiRequest,
        name: Some(intent.claim.clone()),
        input_hash: None,
        output_hash: None,
        exit_code: None,
        detail: Some(action_detail),
    };

    let receipt = ReceiptBuilder::new(ReceiptType::Access, executor_id)
        .status(Status::Success)
        .trust_grade(TrustGrade::B)
        .action(action)
        .claim_semantics(ClaimSemantics::AuthorizationGrant)
        .finalize();

    // Append to the audit chain. The store signs the sealed entry hash
    // automatically (hash-then-sign discipline in zp-audit).
    let unsealed = UnsealedEntry::new(
        ActorId::User(intent.operator_id.clone()),
        AuditAction::SystemEvent {
            event: format!("foundation_relay:{}", intent.claim),
        },
        ConversationId::new(),
        PolicyDecision::Allow { conditions: vec![] },
        "foundation-relay",
    )
    .with_receipt(receipt.clone());

    let sealed = {
        let mut store = match state.0.audit_store.lock() {
            Ok(s) => s,
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error": "audit_store_poisoned" })),
                )
                    .into_response();
            }
        };
        match store.append(unsealed) {
            Ok(entry) => entry,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": "audit_append_failed",
                        "reason": e.to_string()
                    })),
                )
                    .into_response();
            }
        }
    };

    // Pull the signed receipt out of the sealed entry. The audit store
    // populated `sealed.receipt`'s signatures vec as part of appending.
    let signed_receipt = sealed.receipt.unwrap_or(receipt);

    (StatusCode::OK, Json(serde_json::to_value(&signed_receipt).unwrap_or(Value::Null)))
        .into_response()
}

// ── GET handler ───────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct GetQuery {
    pub operator_id: String,
    #[serde(default)]
    pub limit: Option<usize>,
    /// ISO-8601 timestamp lower bound (exclusive). Ignored when `cursor` is set.
    #[serde(default)]
    pub after: Option<DateTime<Utc>>,
    #[serde(default)]
    pub before: Option<DateTime<Utc>>,
    #[serde(default)]
    pub claim: Option<String>,
    /// Opaque forward-pagination cursor emitted by a prior response's
    /// `next_cursor`. When present takes precedence over `after` — using
    /// both in the same request returns HTTP 400.
    #[serde(default)]
    pub cursor: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct GetResponse {
    pub receipts: Vec<Value>,
    pub count: usize,
    /// Opaque cursor for the next page. Present only when more entries exist
    /// beyond the current page. Clients pass this as `?cursor=<value>` on
    /// the next request. The cursor is stable: re-requesting with the same
    /// cursor returns the same next page even if new entries arrive.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

// ── Cursor helpers ────────────────────────────────────────────────────────────

/// Encode a SQLite rowid as an opaque base64 cursor.
///
/// Encoding: big-endian i64 bytes, standard base64. Big-endian so that
/// lexicographic order of raw bytes matches numeric order — a minor
/// convenience if cursor values are ever inspected or compared.
fn encode_cursor(rowid: i64) -> String {
    base64::engine::general_purpose::STANDARD.encode(rowid.to_be_bytes())
}

/// Decode a cursor produced by `encode_cursor`. Returns `Err` on any
/// malformed input so the caller can surface HTTP 400.
fn decode_cursor(cursor: &str) -> Result<i64, String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(cursor)
        .map_err(|_| "cursor is not valid base64".to_string())?;
    if bytes.len() != 8 {
        return Err(format!(
            "cursor must decode to 8 bytes, got {}",
            bytes.len()
        ));
    }
    let arr: [u8; 8] = bytes.try_into().unwrap();
    Ok(i64::from_be_bytes(arr))
}

/// `GET /v1/foundation-receipts` — paginated chain query.
pub async fn get_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<GetQuery>,
    body: axum::body::Bytes,
) -> Response {
    let registry = match &state.0.foundation_edge_registry {
        Some(r) => r.clone(),
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "error": "registry_unavailable" })),
            )
                .into_response();
        }
    };

    let (pubkey_id, signature) = match extract_envelope_headers(&headers) {
        Ok(pair) => pair,
        Err(resp) => return resp,
    };

    // GET requests typically have an empty body; the signature still
    // covers it. The worker computes the signature over the (possibly
    // empty) byte sequence; we do the same.
    if let Err(reason) = registry.verify(&pubkey_id, &signature, &body) {
        return auth_error(&reason);
    }

    // Reject cursor + after together — pick one mode.
    if params.cursor.is_some() && params.after.is_some() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "ambiguous_pagination",
                "reason": "use either `cursor` or `after`, not both"
            })),
        )
            .into_response();
    }

    let limit = params.limit.unwrap_or(50).min(500);

    // Decode cursor into a rowid lower-bound (exclusive). When no cursor is
    // present we use 0 (= "from the beginning"), then apply the optional
    // ISO-timestamp `after` filter in the post-query pass below.
    let after_rowid: i64 = match &params.cursor {
        Some(cur) => match decode_cursor(cur) {
            Ok(rid) => rid,
            Err(reason) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": "invalid_cursor", "reason": reason })),
                )
                    .into_response();
            }
        },
        None => 0,
    };

    // Fetch limit+1 so we can tell whether a next page exists without a
    // second COUNT query. The extra entry is never included in the response.
    let fetch_limit = limit + 1;

    let rows = {
        let store = match state.0.audit_store.lock() {
            Ok(s) => s,
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error": "audit_store_poisoned" })),
                )
                    .into_response();
            }
        };
        store
            .export_entries_after_rowid(after_rowid, fetch_limit)
            .unwrap_or_default()
    };

    let has_more = rows.len() > limit;
    let rows: Vec<(i64, _)> = rows.into_iter().take(limit).collect();

    let target_actor = ActorId::User(params.operator_id.clone());
    let mut last_rowid: Option<i64> = None;
    let receipts: Vec<Value> = rows
        .into_iter()
        .filter(|(_, e)| {
            matches!(&e.action, AuditAction::SystemEvent { event } if event.starts_with("foundation_relay:"))
        })
        .filter(|(_, e)| e.actor == target_actor)
        .filter(|(_, e)| {
            // ISO-timestamp `after` filter — only applied in non-cursor mode.
            if params.cursor.is_none() {
                if let Some(after) = params.after {
                    if e.timestamp <= after {
                        return false;
                    }
                }
            }
            if let Some(before) = params.before {
                if e.timestamp >= before {
                    return false;
                }
            }
            if let Some(claim) = &params.claim {
                if let AuditAction::SystemEvent { event } = &e.action {
                    let want = format!("foundation_relay:{}", claim);
                    if event != &want {
                        return false;
                    }
                }
            }
            true
        })
        .filter_map(|(rowid, e)| {
            let v = e.receipt.as_ref().and_then(|r| serde_json::to_value(r).ok())?;
            last_rowid = Some(rowid);
            Some(v)
        })
        .collect();

    // Emit next_cursor only when the store had more rows beyond this page.
    let next_cursor = if has_more {
        last_rowid.map(encode_cursor)
    } else {
        None
    };

    let count = receipts.len();
    (StatusCode::OK, Json(GetResponse { receipts, count, next_cursor })).into_response()
}

// ── Intent dedup cache ────────────────────────────────────────────────────────

/// Bounded LRU-ish cache of seen intent_ids with a 24-hour TTL.
///
/// Keeps memory bounded under any traffic by evicting the oldest entries
/// when the cache exceeds `MAX_ENTRIES`. Reasonable for a single-operator
/// foundation; revisit if multi-tenant traffic grows.
pub struct SeenIntents {
    entries: HashMap<String, DateTime<Utc>>,
    max_entries: usize,
    ttl: Duration,
}

impl SeenIntents {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            max_entries: 10_000,
            ttl: Duration::hours(24),
        }
    }

    pub fn contains_recent(&self, intent_id: &str, now: DateTime<Utc>) -> bool {
        match self.entries.get(intent_id) {
            Some(seen_at) => now.signed_duration_since(*seen_at) < self.ttl,
            None => false,
        }
    }

    pub fn record(&mut self, intent_id: &str, now: DateTime<Utc>) {
        // Opportunistic GC: drop entries older than TTL when we're at/near
        // capacity. Cheap because it's bounded by max_entries.
        if self.entries.len() >= self.max_entries {
            self.entries
                .retain(|_, t| now.signed_duration_since(*t) < self.ttl);
        }
        self.entries.insert(intent_id.to_string(), now);
    }
}

impl Default for SeenIntents {
    fn default() -> Self {
        Self::new()
    }
}

pub type SeenIntentsArc = Arc<std::sync::Mutex<SeenIntents>>;
pub type PubkeyRegistryArc = Arc<PubkeyRegistry>;

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use tempfile::TempDir;

    fn write_registry(dir: &TempDir, entries: &[(String, [u8; 32], bool)]) -> PathBuf {
        let config_dir = dir.path().join("config");
        std::fs::create_dir_all(&config_dir).unwrap();
        let path = config_dir.join("foundation-edge-keys.json");
        let keys: Vec<serde_json::Value> = entries
            .iter()
            .map(|(id, pk_bytes, active)| {
                serde_json::json!({
                    "id": id,
                    "pubkey": hex::encode(pk_bytes),
                    "added_at": Utc::now().to_rfc3339(),
                    "rotated_to": if *active { Value::Null } else { Value::String("fwed-successor".to_string()) },
                })
            })
            .collect();
        let body = serde_json::json!({ "keys": keys });
        std::fs::write(&path, serde_json::to_vec_pretty(&body).unwrap()).unwrap();
        path
    }

    #[test]
    fn registry_verifies_valid_signature() {
        let dir = TempDir::new().unwrap();
        let sk = SigningKey::from_bytes(&[0x42u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        let path = write_registry(&dir, &[("fwed-test-001".into(), pk, true)]);
        let reg = PubkeyRegistry::new(path);

        let body = b"hello world";
        let sig = sk.sign(body);
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());

        assert!(reg.verify("fwed-test-001", &sig_b64, body).is_ok());
    }

    #[test]
    fn registry_rejects_wrong_pubkey_id() {
        let dir = TempDir::new().unwrap();
        let sk = SigningKey::from_bytes(&[0x42u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        let path = write_registry(&dir, &[("fwed-test-001".into(), pk, true)]);
        let reg = PubkeyRegistry::new(path);

        let body = b"hello world";
        let sig = sk.sign(body);
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());

        assert!(reg.verify("fwed-unknown", &sig_b64, body).is_err());
    }

    #[test]
    fn registry_rejects_tampered_body() {
        let dir = TempDir::new().unwrap();
        let sk = SigningKey::from_bytes(&[0x42u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        let path = write_registry(&dir, &[("fwed-test-001".into(), pk, true)]);
        let reg = PubkeyRegistry::new(path);

        let original = b"hello world";
        let sig = sk.sign(original);
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());

        let tampered = b"hello WORLD";
        assert!(reg.verify("fwed-test-001", &sig_b64, tampered).is_err());
    }

    #[test]
    fn registry_rejects_rotated_key() {
        let dir = TempDir::new().unwrap();
        let sk = SigningKey::from_bytes(&[0x42u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        let path = write_registry(&dir, &[("fwed-test-001".into(), pk, false)]);
        let reg = PubkeyRegistry::new(path);

        let body = b"hello world";
        let sig = sk.sign(body);
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());

        let err = reg
            .verify("fwed-test-001", &sig_b64, body)
            .expect_err("rotated key must be rejected");
        assert!(err.contains("rotated out"));
    }

    #[test]
    fn registry_reload_on_mtime_change() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("config").join("foundation-edge-keys.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();

        // Start with no file; verify must fail.
        let reg = PubkeyRegistry::new(path.clone());
        assert!(reg.verify("fwed-test-001", "AAAA", b"x").is_err());

        // Write a registry entry.
        let sk = SigningKey::from_bytes(&[0xAAu8; 32]);
        let pk = sk.verifying_key().to_bytes();
        let body = serde_json::json!({
            "keys": [{
                "id": "fwed-test-001",
                "pubkey": hex::encode(pk),
                "added_at": Utc::now().to_rfc3339(),
                "rotated_to": Value::Null,
            }]
        });
        // Ensure mtime is detectably newer.
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&path, serde_json::to_vec_pretty(&body).unwrap()).unwrap();

        let body_bytes = b"hello world";
        let sig = sk.sign(body_bytes);
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());

        assert!(reg.verify("fwed-test-001", &sig_b64, body_bytes).is_ok());
    }

    #[test]
    fn intent_validates_clock_skew() {
        let now = Utc::now();
        let intent = ReceiptIntent {
            intent_id: "intn-001".into(),
            operator_id: "op-test".into(),
            claim: "mail:read".into(),
            subject: None,
            capability_used: None,
            metadata: None,
            requested_at: now - Duration::minutes(10),
        };
        assert!(intent.validate(now).is_err(), "10min skew must reject");

        let fresh = ReceiptIntent {
            requested_at: now - Duration::minutes(2),
            ..intent
        };
        assert!(fresh.validate(now).is_ok(), "2min skew must accept");
    }

    #[test]
    fn intent_validates_required_fields() {
        let now = Utc::now();
        let bad = ReceiptIntent {
            intent_id: "".into(),
            operator_id: "op-test".into(),
            claim: "mail:read".into(),
            subject: None,
            capability_used: None,
            metadata: None,
            requested_at: now,
        };
        assert!(bad.validate(now).is_err());

        let bad2 = ReceiptIntent {
            intent_id: "intn-001".into(),
            operator_id: "".into(),
            claim: "mail:read".into(),
            subject: None,
            capability_used: None,
            metadata: None,
            requested_at: now,
        };
        assert!(bad2.validate(now).is_err());

        let bad3 = ReceiptIntent {
            intent_id: "intn-001".into(),
            operator_id: "op-test".into(),
            claim: "".into(),
            subject: None,
            capability_used: None,
            metadata: None,
            requested_at: now,
        };
        assert!(bad3.validate(now).is_err());
    }

    #[test]
    fn seen_intents_dedupes_within_ttl() {
        let mut seen = SeenIntents::new();
        let now = Utc::now();
        assert!(!seen.contains_recent("intn-1", now));
        seen.record("intn-1", now);
        assert!(seen.contains_recent("intn-1", now));
        assert!(seen.contains_recent("intn-1", now + Duration::hours(1)));
        assert!(!seen.contains_recent("intn-1", now + Duration::hours(25)));
    }

    // ── Cursor helpers ────────────────────────────────────────────────────

    #[test]
    fn cursor_round_trips() {
        for rowid in [0_i64, 1, 42, i64::MAX, -1] {
            let encoded = encode_cursor(rowid);
            let decoded = decode_cursor(&encoded).expect("round-trip must succeed");
            assert_eq!(decoded, rowid, "rowid {rowid} failed round-trip");
        }
    }

    #[test]
    fn cursor_rejects_malformed_input() {
        assert!(decode_cursor("not-base64!").is_err());
        // Valid base64 but wrong byte length (4 bytes instead of 8).
        let short = base64::engine::general_purpose::STANDARD.encode([0u8; 4]);
        assert!(decode_cursor(&short).is_err());
    }

    // ── Pagination across in-memory chain ────────────────────────────────

    /// Build an in-memory AuditStore with `n` foundation_relay entries for
    /// `operator_id` and return it together with the tempdir it lives in
    /// (must be kept alive for the store's lifetime).
    fn store_with_entries(
        n: usize,
        operator_id: &str,
    ) -> (tempfile::TempDir, zp_audit::AuditStore) {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("audit.db");
        let mut store = zp_audit::AuditStore::open_unsigned(&path).unwrap();
        for i in 0..n {
            let unsealed = zp_audit::UnsealedEntry::new(
                zp_core::ActorId::User(operator_id.to_string()),
                zp_core::AuditAction::SystemEvent {
                    event: format!("foundation_relay:test.event.{i}"),
                },
                zp_core::ConversationId(uuid::Uuid::now_v7()),
                zp_core::PolicyDecision::Allow { conditions: vec![] },
                "test",
            );
            store.append(unsealed).unwrap();
        }
        (dir, store)
    }

    #[test]
    fn cursor_pagination_advances_monotonically() {
        let (_dir, store) = store_with_entries(10, "op-ken");

        // Page through 10 entries in pages of 3. Collect cursors and entry
        // counts along the way.
        let page_size = 3_usize;
        let mut cursors: Vec<Option<String>> = Vec::new();
        let mut after_rowid = 0_i64;

        loop {
            // fetch page_size+1 to detect "has more".
            let rows = store
                .export_entries_after_rowid(after_rowid, page_size + 1)
                .unwrap();
            let has_more = rows.len() > page_size;
            let page: Vec<(i64, _)> = rows.into_iter().take(page_size).collect();

            let last_rid = page.last().map(|(r, _)| *r);
            let next_cursor = if has_more { last_rid.map(encode_cursor) } else { None };
            cursors.push(next_cursor.clone());

            if let Some(rid) = last_rid {
                // rowid must be strictly greater than the previous lower bound.
                assert!(rid > after_rowid, "cursor must advance");
                after_rowid = rid;
            }

            if next_cursor.is_none() {
                break;
            }
        }

        // 10 entries / 3 per page → pages: [3, 3, 3, 1].
        // Pages 0–2 should carry a cursor; page 3 should not.
        assert_eq!(cursors.len(), 4, "expected 4 pages for 10 entries at page_size=3");
        assert!(cursors[0].is_some());
        assert!(cursors[1].is_some());
        assert!(cursors[2].is_some());
        assert!(cursors[3].is_none(), "last page must have no next_cursor");
    }

    #[test]
    fn same_cursor_returns_same_next_page() {
        let (_dir, store) = store_with_entries(6, "op-replay");

        // Fetch the first page of 2 and note the cursor.
        let first_page = store.export_entries_after_rowid(0, 3).unwrap();
        assert!(first_page.len() > 2, "need >2 entries for this test");
        let cursor_rowid = first_page[1].0; // rowid of 2nd entry → cursor after page 1
        let cursor = encode_cursor(cursor_rowid);

        // Fetch page 2 twice with the same cursor; both must match.
        let page2a = store
            .export_entries_after_rowid(decode_cursor(&cursor).unwrap(), 2)
            .unwrap();
        let page2b = store
            .export_entries_after_rowid(decode_cursor(&cursor).unwrap(), 2)
            .unwrap();

        let ids_a: Vec<_> = page2a.iter().map(|(r, _)| *r).collect();
        let ids_b: Vec<_> = page2b.iter().map(|(r, _)| *r).collect();
        assert_eq!(ids_a, ids_b, "same cursor must return identical rowids");
    }

    #[test]
    fn empty_chain_returns_no_cursor() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("audit.db");
        let store = zp_audit::AuditStore::open_unsigned(&path).unwrap();

        let rows = store.export_entries_after_rowid(0, 10).unwrap();
        assert!(rows.is_empty());
        // No rows → no cursor.
        let last_rid = rows.last().map(|(r, _)| *r);
        let next_cursor: Option<String> = last_rid.map(encode_cursor);
        assert!(next_cursor.is_none());
    }

    #[test]
    fn single_entry_chain_exhausts_on_first_page() {
        let (_dir, store) = store_with_entries(1, "op-solo");

        // Fetch up to 5; chain has 1. has_more = (returned > limit) = false.
        let rows = store.export_entries_after_rowid(0, 6).unwrap(); // fetch limit+1=6, limit=5
        let has_more = rows.len() > 5;
        assert!(!has_more, "single-entry chain must not produce next_cursor");
        assert_eq!(rows.len(), 1);
    }

    #[test]
    fn stale_cursor_still_returns_correct_next_page() {
        // A cursor pointing to rowid N is unconditionally valid as long as N
        // still exists — even if entries beyond N were added after the cursor
        // was issued. The response is whatever comes after rowid N at read
        // time.
        let (_dir, mut store) = store_with_entries(3, "op-stale");

        // Cursor after entry 2 (rowid 2).
        let first_rows = store.export_entries_after_rowid(0, 4).unwrap();
        assert!(first_rows.len() >= 2);
        let cursor_rowid = first_rows[1].0;

        // Add 3 more entries AFTER the cursor was "issued".
        for i in 3..6_usize {
            let unsealed = zp_audit::UnsealedEntry::new(
                zp_core::ActorId::User("op-stale".to_string()),
                zp_core::AuditAction::SystemEvent {
                    event: format!("foundation_relay:late.{i}"),
                },
                zp_core::ConversationId(uuid::Uuid::now_v7()),
                zp_core::PolicyDecision::Allow { conditions: vec![] },
                "test",
            );
            store.append(unsealed).unwrap();
        }

        // Replay the cursor — should now see entries after rowid cursor_rowid
        // (originally 1 entry, now 4 entries are visible beyond it).
        let after_rows = store.export_entries_after_rowid(cursor_rowid, 10).unwrap();
        assert!(
            after_rows.len() > 1,
            "new entries appended after cursor was issued must appear on replay"
        );
        for (rid, _) in &after_rows {
            assert!(
                *rid > cursor_rowid,
                "all returned rowids must be strictly after the cursor rowid"
            );
        }
    }
}
