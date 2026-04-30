//! Standing-delegation heartbeat client (P4 / #197).
//!
//! On a delegate node (e.g., ARTEMIS, playground) the heartbeat task is
//! responsible for keeping the node's `CapabilityGrant` lease alive: at
//! `renewal_interval` cadence it POSTs to one of the grant's
//! `renewal_authorities`. Genesis nodes (APOLLO in the canonical fleet)
//! do not heartbeat — they ARE the renewal authority.
//!
//! ## Lifecycle
//!
//! ```text
//!   tick → POST /api/v1/lease/renew → success ─────► reset failure counter
//!                                  └─► failure ───► increment counter
//!                                                   counter == max  ──► grace
//!                                                   grace expired   ──► failure_mode
//! ```
//!
//! ## Configuration
//!
//! The heartbeat task is configured via `~/ZeroPoint/lease.toml`:
//!
//! ```toml
//! grant_id = "grant-019dd07e-..."
//! subject_node_id = "artemis"
//! subject_signing_key_hex = "abc..."   # 64-hex Ed25519 secret key, required
//! renewal_authorities = ["http://apollo.local:3000", "http://sentinel.local:3000"]
//! renewal_interval_secs = 7200
//! max_consecutive_failures = 3
//! grace_period_secs = 1800
//! failure_mode = "halt"                # halt | degrade | flag
//! ```
//!
//! If the file is absent at startup, no heartbeat task spawns and the
//! server runs as a non-delegate node.

use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::time::Duration;
use tracing::{error, info, warn};

use zp_core::LeaseFailureMode;

/// Operator-supplied heartbeat configuration. Loaded from
/// `~/ZeroPoint/lease.toml` at server startup. All fields are required.
///
/// `subject_signing_key_hex` is the delegate's Ed25519 secret key — the
/// private half of the public key that was bound to the grant at issuance.
/// The renewal endpoint authenticates by verifying the signature this key
/// produces; without it, heartbeats fail. The chain never sees this key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseHeartbeatConfig {
    pub grant_id: String,
    pub subject_node_id: String,
    /// Hex-encoded Ed25519 secret key (32 bytes / 64 hex chars). REQUIRED —
    /// fleet authentication is signature-based, not session-based.
    pub subject_signing_key_hex: String,
    /// Ordered list of renewal authority base URLs. Each tick the client
    /// tries them in this order until one returns 200.
    pub renewal_authorities: Vec<String>,
    pub renewal_interval_secs: u64,
    pub max_consecutive_failures: u32,
    pub grace_period_secs: u64,
    /// `halt`, `degrade`, or `flag`. Mirrors the on-grant
    /// `lease_policy.failure_mode`.
    pub failure_mode: String,
}

impl LeaseHeartbeatConfig {
    pub fn parse_failure_mode(&self) -> LeaseFailureMode {
        match self.failure_mode.as_str() {
            "degrade" | "degrade-on-expiry" => LeaseFailureMode::DegradeOnExpiry,
            "flag" | "continue-with-flag" => LeaseFailureMode::ContinueWithFlag,
            _ => LeaseFailureMode::HaltOnExpiry,
        }
    }

    /// Read the config from a path. Returns `Ok(None)` when the file does
    /// not exist (the common, non-delegate case).
    pub fn load(path: &Path) -> Result<Option<Self>, String> {
        match std::fs::read_to_string(path) {
            Ok(s) => {
                let cfg: LeaseHeartbeatConfig =
                    toml::from_str(&s).map_err(|e| format!("{}: {}", path.display(), e))?;
                Ok(Some(cfg))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("{}: {}", path.display(), e)),
        }
    }
}

/// Atomic flags shared between the heartbeat task and the rest of the
/// server. The gate consults these on every request so a heartbeat
/// failure-mode is honoured without races.
#[derive(Debug, Default)]
pub struct LeaseHeartbeatState {
    /// `true` when the lease is past `expires_at + grace_period` AND the
    /// failure mode is `HaltOnExpiry`. The gate refuses every tool call
    /// while this is set.
    pub halted: AtomicBool,
    /// `true` when the lease is past grace AND the failure mode is
    /// `DegradeOnExpiry`. The gate forces tier 0 for any grant that
    /// requires a higher tier.
    pub degraded: AtomicBool,
    /// Consecutive renewal failures observed so far in this lifetime.
    pub consecutive_failures: AtomicU64,
    /// Total successful renewals so far.
    pub renewal_count: AtomicU64,
}

impl LeaseHeartbeatState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_alive(&self) -> bool {
        !self.halted.load(Ordering::Relaxed) && !self.degraded.load(Ordering::Relaxed)
    }

    pub fn snapshot(&self) -> serde_json::Value {
        serde_json::json!({
            "halted": self.halted.load(Ordering::Relaxed),
            "degraded": self.degraded.load(Ordering::Relaxed),
            "consecutive_failures": self.consecutive_failures.load(Ordering::Relaxed),
            "renewal_count": self.renewal_count.load(Ordering::Relaxed),
        })
    }
}

/// Spawn the heartbeat task. Returns the shared state handle so the gate
/// (and a future cockpit Fleet Grants tile) can introspect it.
///
/// The returned `Arc<LeaseHeartbeatState>` lives for the duration of the
/// process; the task itself runs until the runtime is dropped.
pub fn start(config: LeaseHeartbeatConfig) -> Arc<LeaseHeartbeatState> {
    let state = Arc::new(LeaseHeartbeatState::new());
    let state_for_task = state.clone();

    tokio::spawn(async move {
        run_heartbeat_loop(config, state_for_task).await;
    });

    state
}

/// The actual heartbeat loop. Public for tests.
pub async fn run_heartbeat_loop(config: LeaseHeartbeatConfig, state: Arc<LeaseHeartbeatState>) {
    let interval = Duration::from_secs(config.renewal_interval_secs);
    let grace = Duration::from_secs(config.grace_period_secs);
    let failure_mode = config.parse_failure_mode();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .expect("reqwest client builds");

    info!(
        grant_id = %config.grant_id,
        subject = %config.subject_node_id,
        authorities = config.renewal_authorities.len(),
        renewal_interval_secs = config.renewal_interval_secs,
        failure_mode = ?failure_mode,
        "lease heartbeat task started"
    );

    let mut grace_started_at: Option<std::time::Instant> = None;

    loop {
        // Attempt renewal against each authority in order.
        let renewed = try_renew_once(&client, &config).await;

        if renewed {
            state.consecutive_failures.store(0, Ordering::Relaxed);
            state.renewal_count.fetch_add(1, Ordering::Relaxed);
            // Recovering from a prior grace state.
            grace_started_at = None;
            state.halted.store(false, Ordering::Relaxed);
            state.degraded.store(false, Ordering::Relaxed);
            info!(
                grant_id = %config.grant_id,
                subject = %config.subject_node_id,
                "lease renewed"
            );
        } else {
            let n = state.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
            warn!(
                grant_id = %config.grant_id,
                consecutive_failures = n,
                "lease renewal failed against all authorities"
            );

            if n as u32 >= config.max_consecutive_failures && grace_started_at.is_none() {
                warn!(
                    grant_id = %config.grant_id,
                    "max_consecutive_failures reached — entering grace period"
                );
                grace_started_at = Some(std::time::Instant::now());
            }

            if let Some(grace_start) = grace_started_at {
                if grace_start.elapsed() > grace {
                    error!(
                        grant_id = %config.grant_id,
                        failure_mode = ?failure_mode,
                        "grace period expired — executing failure_mode"
                    );
                    match failure_mode {
                        LeaseFailureMode::HaltOnExpiry => {
                            state.halted.store(true, Ordering::Relaxed);
                        }
                        LeaseFailureMode::DegradeOnExpiry => {
                            state.degraded.store(true, Ordering::Relaxed);
                        }
                        LeaseFailureMode::ContinueWithFlag => {
                            // Flag-only mode — log was sufficient.
                        }
                    }
                }
            }
        }

        tokio::time::sleep(interval).await;
    }
}

/// One renewal attempt: try each authority in order, return true on first 2xx.
async fn try_renew_once(client: &reqwest::Client, config: &LeaseHeartbeatConfig) -> bool {
    let ts_ms = chrono::Utc::now().timestamp_millis();
    let payload_to_sign = format!("{}|{}", config.grant_id, ts_ms);

    let (sig_hex, _pk_hex) = sign_with_hex_key(
        &config.subject_signing_key_hex,
        payload_to_sign.as_bytes(),
    );
    let Some(sig_hex) = sig_hex else {
        warn!("subject_signing_key_hex is malformed (expected 64 hex chars); cannot heartbeat");
        return false;
    };

    let body = serde_json::json!({
        "grant_id": config.grant_id,
        "subject_node_id": config.subject_node_id,
        "subject_signature": sig_hex,
        "timestamp_ms": ts_ms,
    });

    for base in &config.renewal_authorities {
        let url = format!("{}/api/v1/lease/renew", base.trim_end_matches('/'));
        match client.post(&url).json(&body).send().await {
            Ok(r) if r.status().is_success() => {
                return true;
            }
            Ok(r) => {
                warn!(authority = %base, status = %r.status(), "renewal authority returned non-2xx");
            }
            Err(e) => {
                warn!(authority = %base, error = %e, "renewal request failed");
            }
        }
    }
    false
}

/// Sign `payload` with the hex-encoded Ed25519 secret key, returning the
/// hex signature and the hex public key. Returns `(None, None)` if the
/// key cannot be parsed.
fn sign_with_hex_key(secret_hex: &str, payload: &[u8]) -> (Option<String>, Option<String>) {
    let Ok(bytes) = hex::decode(secret_hex) else {
        return (None, None);
    };
    if bytes.len() != 32 {
        return (None, None);
    }
    let mut sk_arr = [0u8; 32];
    sk_arr.copy_from_slice(&bytes);
    let signing = ed25519_dalek::SigningKey::from_bytes(&sk_arr);
    use ed25519_dalek::Signer;
    let sig = signing.sign(payload);
    (
        Some(hex::encode(sig.to_bytes())),
        Some(hex::encode(signing.verifying_key().to_bytes())),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_failure_mode_defaults_to_halt() {
        let cfg = LeaseHeartbeatConfig {
            grant_id: "g".into(),
            subject_node_id: "s".into(),
            subject_signing_key_hex: "00".repeat(32),
            renewal_authorities: vec![],
            renewal_interval_secs: 60,
            max_consecutive_failures: 3,
            grace_period_secs: 60,
            failure_mode: "garbage".into(),
        };
        assert_eq!(cfg.parse_failure_mode(), LeaseFailureMode::HaltOnExpiry);
    }

    #[test]
    fn parse_failure_mode_recognises_degrade_and_flag() {
        let mut cfg = LeaseHeartbeatConfig {
            grant_id: "g".into(),
            subject_node_id: "s".into(),
            subject_signing_key_hex: "00".repeat(32),
            renewal_authorities: vec![],
            renewal_interval_secs: 60,
            max_consecutive_failures: 3,
            grace_period_secs: 60,
            failure_mode: "degrade".into(),
        };
        assert_eq!(cfg.parse_failure_mode(), LeaseFailureMode::DegradeOnExpiry);
        cfg.failure_mode = "flag".into();
        assert_eq!(
            cfg.parse_failure_mode(),
            LeaseFailureMode::ContinueWithFlag
        );
    }

    #[test]
    fn load_returns_none_for_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("absent.toml");
        let r = LeaseHeartbeatConfig::load(&path).unwrap();
        assert!(r.is_none());
    }

    #[test]
    fn load_parses_valid_toml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lease.toml");
        std::fs::write(
            &path,
            r#"
grant_id = "grant-abc"
subject_node_id = "artemis"
subject_signing_key_hex = "0000000000000000000000000000000000000000000000000000000000000000"
renewal_authorities = ["http://localhost:3000"]
renewal_interval_secs = 120
max_consecutive_failures = 3
grace_period_secs = 60
failure_mode = "halt"
"#,
        )
        .unwrap();
        let cfg = LeaseHeartbeatConfig::load(&path).unwrap().unwrap();
        assert_eq!(cfg.grant_id, "grant-abc");
        assert_eq!(cfg.subject_node_id, "artemis");
        assert_eq!(cfg.renewal_authorities.len(), 1);
        assert_eq!(cfg.parse_failure_mode(), LeaseFailureMode::HaltOnExpiry);
    }

    #[test]
    fn state_snapshot_round_trips() {
        let s = LeaseHeartbeatState::new();
        s.consecutive_failures.store(2, Ordering::Relaxed);
        s.renewal_count.store(7, Ordering::Relaxed);
        let snap = s.snapshot();
        assert_eq!(snap["consecutive_failures"], 2);
        assert_eq!(snap["renewal_count"], 7);
        assert_eq!(snap["halted"], false);
        assert_eq!(snap["degraded"], false);
    }

    #[test]
    fn sign_with_invalid_hex_returns_none() {
        let (sig, pk) = sign_with_hex_key("not-hex", b"payload");
        assert!(sig.is_none());
        assert!(pk.is_none());
    }

    #[test]
    fn sign_with_valid_hex_returns_signature() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let secret_hex = hex::encode(key.to_bytes());
        let (sig, pk) = sign_with_hex_key(&secret_hex, b"payload");
        assert!(sig.is_some());
        assert!(pk.is_some());
        // The returned public key must match the source key's vk.
        let expected = hex::encode(key.verifying_key().to_bytes());
        assert_eq!(pk.unwrap(), expected);
    }

    /// Failure-path simulation: manually drive `try_renew_once` against
    /// authorities that don't exist. We do this in a tokio runtime to keep
    /// the test environment realistic.
    #[tokio::test]
    async fn try_renew_returns_false_for_unreachable_authorities() {
        let cfg = LeaseHeartbeatConfig {
            grant_id: "g".into(),
            subject_node_id: "s".into(),
            subject_signing_key_hex: "00".repeat(32),
            renewal_authorities: vec!["http://127.0.0.1:1".into()], // unreachable
            renewal_interval_secs: 60,
            max_consecutive_failures: 3,
            grace_period_secs: 60,
            failure_mode: "halt".into(),
        };
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .unwrap();
        let r = try_renew_once(&client, &cfg).await;
        assert!(!r);
    }

    #[tokio::test]
    async fn state_transitions_to_halt_after_grace_when_unreachable() {
        // Drive the loop manually for a few iterations using a config with
        // tiny intervals so the test wraps inside a couple of seconds.
        let cfg = LeaseHeartbeatConfig {
            grant_id: "g".into(),
            subject_node_id: "s".into(),
            subject_signing_key_hex: "00".repeat(32),
            renewal_authorities: vec!["http://127.0.0.1:1".into()],
            renewal_interval_secs: 1,
            max_consecutive_failures: 1,
            grace_period_secs: 0, // immediate grace expiry
            failure_mode: "halt".into(),
        };
        let state = Arc::new(LeaseHeartbeatState::new());
        let state_for_task = state.clone();
        let handle = tokio::spawn(async move {
            run_heartbeat_loop(cfg, state_for_task).await;
        });

        // Wait for the loop to fail twice and trip into halt.
        for _ in 0..30 {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            if state.halted.load(Ordering::Relaxed) {
                break;
            }
        }
        assert!(
            state.halted.load(Ordering::Relaxed),
            "halt flag must trip after grace"
        );

        handle.abort();
    }
}
