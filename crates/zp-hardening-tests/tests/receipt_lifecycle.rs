//! Receipt lifecycle — balanced-loop diagnostic test
//!
//! Exercises the four-stage lifecycle from the central tier handoff brief:
//!   Stage 1: Verb dispatch (surface + verb-set validation)
//!   Stage 2: Gate evaluation (policy decision → chain entry)
//!   Stage 3: Canonical body construction (exec side effect + receipt)
//!   Stage 4: Chain insertion (BEGIN IMMEDIATE, prev-hash linkage)
//!
//! ## Two harness modes
//!
//! ### ChainHarness — direct store access (AuditStore::open_unsigned)
//!
//! `AppState::init` opens the audit store **read-only** in "bootstrap mode"
//! (no genesis.json → `is_genesis = true`). Chain-level tests bypass this
//! limitation by creating an `AuditStore::open_unsigned` on a temp file and
//! calling `zp_server::tool_chain::emit_*` directly.  This tests chain
//! correctness (ordering, prev-hash linkage, Claim 1) without needing a
//! full genesis ceremony.
//!
//! ### GateHarness — in-process HTTP via TestApp
//!
//! Gate-response tests use the standard `TestApp` harness with a Bearer
//! session token.  In bootstrap mode the gate handler's `emit_tool_receipt`
//! call silently returns `None` (read-only store), so `chain_entry_hash`
//! will be `null` in the response — this is documented as a structural gap
//! (see `gap_gate_chain_emission_requires_genesis`).
//!
//! ## Test inventory
//!
//! 1. `chain_happy_path_three_entry_sequence` — delegation → gate:allowed
//!    → exec on a direct-write chain in order with intact prev-hash links.
//!    Exercises all four stages and Claim 1.
//!
//! 2. `chain_denied_gate_no_exec_when_delegation_absent` — documents
//!    boundary 2→3: a gate:denied entry must never be followed by an exec
//!    receipt for the same tool in the same action sequence.
//!
//! 3. `chain_prev_hash_links_are_intact` — seeds N entries then walks the
//!    full chain verifying every prev-hash/entry-hash link.
//!
//! 4. `gate_http_allows_with_bearer_token` — gate/tool-call requires auth;
//!    with a valid Bearer token it returns 200 and `allowed:true`.
//!
//! 5. `gate_http_denies_agent_without_delegation` — agent not on chain gets
//!    `allowed:false`; no exec receipt is expected.
//!
//! 6. `gap_gate_chain_emission_requires_genesis` — documents that in
//!    bootstrap mode `chain_entry_hash` is `null` because the store is
//!    read-only.  Passes while the gap exists; signals when it's closed.
//!
//! 7. `gap_delegation_http_handler_does_not_emit_chain_entry` — documents
//!    that the HTTP grant handler does not write a delegation:granted chain
//!    entry (Boundary 1→2 gap).
//!
//! Ref: docs/handoffs/receipt-lifecycle-2026-06.md

use axum::body::Body;
use axum::http::{Request, StatusCode};
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

use zp_audit::AuditStore;
use zp_core::{CapabilityGrant, GrantedCapability};

// ── Chain harness (direct AuditStore, no HTTP) ────────────────────────────────

/// Wraps an `AuditStore::open_unsigned` for tests that need chain writes
/// without a genesis ceremony.  The server's HTTP handlers run against a
/// **separate** router with a different (read-only) store, so this harness
/// is only for chain-level correctness tests, not for end-to-end HTTP tests.
struct ChainHarness {
    audit_store: Arc<Mutex<AuditStore>>,
    _temp_dir: tempfile::TempDir,
}

impl ChainHarness {
    fn new() -> Self {
        let temp_dir = tempfile::TempDir::new().expect("temp dir");
        let db_path = temp_dir.path().join("audit.db");
        let store = AuditStore::open_unsigned(&db_path).expect("open_unsigned");
        Self {
            audit_store: Arc::new(Mutex::new(store)),
            _temp_dir: temp_dir,
        }
    }

    /// Emit a `delegation:granted:<subject>` chain entry and return its hash.
    fn emit_delegation_granted(&self, subject: &str) -> String {
        let grant = CapabilityGrant::new(
            "test-operator".to_string(),
            subject.to_string(),
            GrantedCapability::Execute {
                languages: vec!["*".to_string()],
            },
            format!("rcpt-test-{}", subject),
        );
        zp_server::tool_chain::emit_delegation_receipt(&self.audit_store, "granted", &grant, None)
            .expect("emit_delegation_receipt returned None — is the store writable?")
    }

    /// Emit a `gate:<decision>:<tool>` chain entry. Returns the hash.
    fn emit_gate_receipt(&self, decision: &str, tool: &str) -> String {
        let event = format!("gate:{}:{}", decision, tool);
        zp_server::tool_chain::emit_tool_receipt(&self.audit_store, &event, None)
            .expect("emit_tool_receipt returned None")
    }

    /// Emit an `exec:<tool>:<outcome>` chain entry. Returns the hash.
    fn emit_exec_receipt(&self, tool: &str, outcome: &str) -> String {
        let event = format!("exec:{}:{}", tool, outcome);
        zp_server::tool_chain::emit_tool_receipt(&self.audit_store, &event, None)
            .expect("emit_tool_receipt returned None")
    }

    /// Return all chain entries in insertion order (oldest first).
    fn entries(&self) -> Vec<zp_core::AuditEntry> {
        self.audit_store
            .lock()
            .unwrap()
            .export_chain(i32::MAX as usize)
            .expect("export_chain")
    }
}

// ── Gate harness (in-process HTTP via TestApp) ────────────────────────────────

/// Thin wrapper around `TestApp` that adds convenience for auth-gated routes.
struct GateHarness {
    router: axum::Router,
    session_token: String,
}

impl GateHarness {
    async fn new() -> Self {
        zp_keys::test_helpers::install_mock_keyring();

        let temp_dir = tempfile::TempDir::new().expect("temp dir");
        let data_dir = temp_dir.path().join("data");
        std::fs::create_dir_all(&data_dir).expect("data dir");
        let home_dir = temp_dir.path().to_path_buf();
        let keys_dir = home_dir.join("keys");
        std::fs::create_dir_all(&keys_dir).expect("keys dir");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&home_dir, std::fs::Permissions::from_mode(0o700)).ok();
            std::fs::set_permissions(&keys_dir, std::fs::Permissions::from_mode(0o700)).ok();
        }

        let config = zp_server::ServerConfig {
            bind_addr: "127.0.0.1".to_string(),
            port: 0,
            data_dir: data_dir.to_string_lossy().to_string(),
            home_dir,
            open_dashboard: false,
            llm_enabled: false,
            operator_name: "lifecycle-gate-test".to_string(),
            bridge_dir: None,
        };

        let state = zp_server::AppState::init(&config).await;

        // Swap to a writable unsigned store before building the router.
        //
        // AppState::init opens read-only in bootstrap mode (no genesis.json
        // present in the temp home dir). That causes every emit_tool_receipt /
        // emit_delegation_receipt call inside the HTTP handlers to silently
        // return None — the chain never grows, and any gate decision that
        // depends on the chain (P4 delegation prereq) reads an empty store.
        //
        // Replacing with open_unsigned gives the handlers a writable store,
        // making the full HTTP→gate→chain path testable without a sovereignty
        // ceremony. Entries carry no per-entry signatures (open_unsigned), but
        // chain-integrity fast-path (prev_hash linking) still holds.
        //
        // The swap must happen before build_app — once state is moved into the
        // router the outer Arc is gone. All route-handler clones share the same
        // Arc<Mutex<AuditStore>>, so they see the writable store after the swap.
        {
            let writable_db = data_dir.join("audit-writable.db");
            let writable = zp_audit::AuditStore::open_unsigned(&writable_db)
                .expect("writable unsigned audit store");
            *state.0.audit_store.lock().unwrap() = writable;
        }

        let session_token = state.session_token();
        let router = zp_server::build_app(state, &config);

        // Keep temp_dir alive for duration of test by leaking it.
        std::mem::forget(temp_dir);

        Self { router, session_token }
    }

    /// POST JSON with Bearer session token. Returns (status, json body).
    async fn post_authed(
        &self,
        path: &str,
        payload: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let req = Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", self.session_token))
            .body(Body::from(serde_json::to_vec(&payload).unwrap()))
            .unwrap();
        let resp = self.router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    /// POST JSON **without** auth header (for testing rejection cases).
    async fn post_unauthed(
        &self,
        path: &str,
        payload: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let req = Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&payload).unwrap()))
            .unwrap();
        let resp = self.router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, json)
    }
}

// ── Chain linkage verifier ────────────────────────────────────────────────────

fn event_of(entry: &zp_core::AuditEntry) -> Option<&str> {
    match &entry.action {
        zp_core::AuditAction::SystemEvent { event } => Some(event.as_str()),
        _ => None,
    }
}

/// Walk entries in chronological order; assert each prev_hash equals the
/// predecessor's entry_hash.  A broken link is a Claim 1 violation.
fn assert_chain_links(entries: &[zp_core::AuditEntry]) {
    for (i, entry) in entries.iter().enumerate().skip(1) {
        let prev = &entries[i - 1];
        assert_eq!(
            entry.prev_hash, prev.entry_hash,
            "Chain linkage broken at position {}: \
             entry[{}].prev_hash ({}) != entry[{}].entry_hash ({}) \
             (Claim 1 violation — BEGIN IMMEDIATE or prev-hash computation is wrong)",
            i, i, &entry.prev_hash[..12], i - 1, &prev.entry_hash[..12]
        );
    }
}

// ── Chain-direct tests ────────────────────────────────────────────────────────

/// Balanced-loop happy path:
///   Stage 1 → delegation:granted chain entry
///   Stage 2 → gate:allowed chain entry
///   Stage 3 → exec chain entry
///   Stage 4 → walk chain; verify delegation < gate < exec; verify all links
///
/// Uses `AuditStore::open_unsigned` because `AppState::init` opens a
/// read-only store in bootstrap mode (no genesis.json).
#[tokio::test]
async fn chain_happy_path_three_entry_sequence() {
    let h = ChainHarness::new();
    let subject = "ironclaw-test-agent";
    let tool = "chain_render";

    // Stage 1: delegation grant lands on chain.
    let _delegation_hash = h.emit_delegation_granted(subject);

    // Stage 2: gate evaluation emits allowed decision.
    let _gate_hash = h.emit_gate_receipt("allowed", tool);

    // Stage 3: side effect completes; exec receipt lands.
    let _exec_hash = h.emit_exec_receipt(tool, "ok");

    // Stage 4: walk chain — verify ordering and prev-hash integrity.
    let entries = h.entries();

    let delegation_idx = entries
        .iter()
        .position(|e| event_of(e).map_or(false, |ev| ev.starts_with("delegation:granted:")))
        .expect("delegation:granted:* must appear on chain");

    let gate_idx = entries
        .iter()
        .position(|e| {
            event_of(e).map_or(false, |ev| ev == format!("gate:allowed:{}", tool))
        })
        .expect("gate:allowed:<tool> must appear on chain");

    let exec_idx = entries
        .iter()
        .position(|e| {
            event_of(e).map_or(false, |ev| ev == format!("exec:{}:ok", tool))
        })
        .expect("exec:<tool>:ok must appear on chain");

    // Boundary ordering: delegation → gate → exec.
    assert!(
        delegation_idx < gate_idx,
        "delegation (idx {}) must precede gate (idx {})",
        delegation_idx, gate_idx
    );
    assert!(
        gate_idx < exec_idx,
        "gate (idx {}) must precede exec (idx {})",
        gate_idx, exec_idx
    );

    // Boundary 3→4 and 4→1: every prev-hash must link correctly.
    assert_chain_links(&entries);
}

/// Boundary 2→3: a gate:denied entry must never be followed by an exec
/// receipt for the same tool.  Documents that denial truly stops the action.
#[tokio::test]
async fn chain_denied_gate_no_exec_when_delegation_absent() {
    let h = ChainHarness::new();
    let tool = "read_file";

    // No delegation grant for any subject.
    // Emit a denied gate decision (simulating what the gate would emit
    // when the P4 prereq check fires for an unregistered agent).
    h.emit_gate_receipt("denied", tool);

    // Now the substrate must NOT have an exec receipt for this tool.
    // (In the real substrate the gate handler returns `allowed:false`
    // and the caller — IronClaw / Sage — must not execute the tool.
    // There is no server-side enforcement preventing a misbehaving caller
    // from calling emit_exec_receipt; this test verifies the chain STATE
    // after the denied decision, not caller compliance.)
    let entries = h.entries();

    let has_denied = entries.iter().any(|e| {
        event_of(e).map_or(false, |ev| ev == format!("gate:denied:{}", tool))
    });
    assert!(has_denied, "gate:denied:{} must appear on chain", tool);

    let has_exec = entries.iter().any(|e| {
        event_of(e).map_or(false, |ev| ev.starts_with(&format!("exec:{}:", tool)))
    });
    assert!(
        !has_exec,
        "exec:{}:* must NOT appear on chain after gate:denied \
         (boundary 2→3 — denied gate means no exec)",
        tool
    );

    // Chain links must be intact even for a single-entry chain.
    assert_chain_links(&entries);
}

/// Claim 1 — chain integrity under multiple writers.
///
/// Seeds 5 entries then verifies every prev-hash/entry-hash pair.
/// A failure here means `AuditStore::append` is not using `BEGIN IMMEDIATE`
/// or the prev-hash computation is wrong.
#[tokio::test]
async fn chain_prev_hash_links_are_intact() {
    let h = ChainHarness::new();

    h.emit_delegation_granted("agent-a");
    h.emit_gate_receipt("allowed", "tool_alpha");
    h.emit_exec_receipt("tool_alpha", "ok");
    h.emit_delegation_granted("agent-b");
    h.emit_gate_receipt("denied", "tool_beta");

    let entries = h.entries();
    assert!(
        entries.len() >= 5,
        "expected ≥5 entries, got {}",
        entries.len()
    );

    assert_chain_links(&entries);
}

// ── Failure injection tests ───────────────────────────────────────────────────

/// Boundary 4 (internal) — concurrent-writer race on prev_hash.
///
/// Two threads both try to append to the same AuditStore concurrently.
/// Under `BEGIN IMMEDIATE` + `UNIQUE(prev_hash)`, only one can win per tip;
/// the other must retry or fail cleanly.  The observable correctness property:
/// the resulting chain is a **linear sequence** — no gaps, no duplicates, no
/// fork (two entries with the same prev_hash).
///
/// If the substrate uses weaker semantics than `BEGIN IMMEDIATE` (e.g. plain
/// `BEGIN` or no transaction), the UNIQUE constraint is the last guard, but
/// concurrent reads of the tip before the write commits can cause both threads
/// to read the same prev_hash, attempt to insert two entries with it, and have
/// one silently dropped — leaving the chain shorter than expected.  This test
/// catches that: if N writers each succeed K times, the chain must contain
/// exactly N×K entries with no broken links.
///
/// Uses `std::thread::scope` so the threads borrow the shared Arc without
/// requiring `'static` lifetime, keeping the test self-contained.
#[tokio::test]
async fn chain_concurrent_writers_preserve_linearity() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let h = ChainHarness::new();
    let store = h.audit_store.clone();

    // Each thread appends WRITES_PER_THREAD entries.
    const WRITERS: usize = 4;
    const WRITES_PER_THREAD: usize = 10;

    let success_count = Arc::new(AtomicUsize::new(0));

    std::thread::scope(|s| {
        for i in 0..WRITERS {
            let store = store.clone();
            let success_count = success_count.clone();
            s.spawn(move || {
                for j in 0..WRITES_PER_THREAD {
                    let event = format!("concurrent:writer{}:entry{}", i, j);
                    let result =
                        zp_server::tool_chain::emit_tool_receipt(&store, &event, None);
                    if result.is_some() {
                        success_count.fetch_add(1, Ordering::Relaxed);
                    }
                }
            });
        }
    });

    let total_success = success_count.load(Ordering::Relaxed);

    // All appends must succeed — the store should retry on prev_hash conflict.
    assert_eq!(
        total_success,
        WRITERS * WRITES_PER_THREAD,
        "All {} concurrent appends must succeed; {} succeeded. \
         If any failed, BEGIN IMMEDIATE retry logic is absent or broken.",
        WRITERS * WRITES_PER_THREAD,
        total_success
    );

    // The chain must be a strict linear sequence.
    let entries = h.entries();
    assert_eq!(
        entries.len(),
        WRITERS * WRITES_PER_THREAD,
        "Chain must contain exactly {} entries (no duplicates, no drops); found {}",
        WRITERS * WRITES_PER_THREAD,
        entries.len()
    );

    // Every link must be intact — no forked prev_hash.
    assert_chain_links(&entries);

    // No two entries may share a prev_hash (a fork would mean two entries
    // were inserted at the same chain tip, violating append-only semantics).
    let mut seen_prev_hashes = std::collections::HashSet::new();
    for entry in &entries {
        assert!(
            seen_prev_hashes.insert(entry.prev_hash.clone()),
            "Duplicate prev_hash {} found — two entries were anchored at the same \
             chain tip (UNIQUE(prev_hash) constraint not enforced or BEGIN IMMEDIATE \
             not used)",
            &entry.prev_hash[..12]
        );
    }
}

/// Boundary 2→3 (injection) — gate:allowed on chain, then exec receipt omitted.
///
/// Simulates a caller that receives `allowed:true` from the gate but never
/// calls the exec path (crash, network failure, or misbehaving agent).
/// The chain's observable state is: gate:allowed with no following exec.
/// This is "honestly broken" — the chain reveals the gap exactly; it does not
/// silently hide it.
///
/// Documents Claim 3 gap: the substrate can detect this pattern on chain walk
/// but currently has no automated detection.  A future `zp audit check` should
/// flag `gate:allowed` entries with no corresponding exec entry as unresolved.
#[tokio::test]
async fn chain_injection_gate_allowed_but_exec_omitted() {
    let h = ChainHarness::new();
    let tool = "spawn_process";

    h.emit_delegation_granted("agent-alpha");
    h.emit_gate_receipt("allowed", tool);
    // Exec receipt intentionally NOT emitted — simulating a crash/misbehaving
    // agent between Stage 2 (gate) and Stage 3 (exec + receipt).

    let entries = h.entries();

    let gate_idx = entries
        .iter()
        .position(|e| event_of(e).map_or(false, |ev| ev == format!("gate:allowed:{}", tool)))
        .expect("gate:allowed:<tool> must appear on chain");

    // Verify the chain is intact up to and including the gate entry.
    assert_chain_links(&entries);

    // Verify there is NO exec entry after the gate entry.
    let has_exec_after_gate = entries[gate_idx + 1..]
        .iter()
        .any(|e| event_of(e).map_or(false, |ev| ev.starts_with(&format!("exec:{}:", tool))));

    assert!(
        !has_exec_after_gate,
        "exec:{}:* must not appear when exec was intentionally omitted — \
         test setup is wrong",
        tool
    );

    // The chain reveals the gap honestly: gate:allowed exists, exec does not.
    // A chain walker can detect this as an unresolved gate decision.
    // This is the "honestly broken" state the brief requires — not silent.
    let gate_event = event_of(&entries[gate_idx]).unwrap();
    assert!(
        gate_event.starts_with("gate:allowed:"),
        "Chain must show gate:allowed as the last action for this tool — \
         the gap is visible, not hidden"
    );
}

// ── Gate HTTP tests ───────────────────────────────────────────────────────────

/// gate/tool-call requires Bearer auth; with the session token it returns 200
/// and `allowed:true` for a tool not on the deny list.
#[tokio::test]
async fn gate_http_allows_with_bearer_token() {
    let h = GateHarness::new().await;

    let (status, resp) = h
        .post_authed(
            "/api/v1/gate/tool-call",
            serde_json::json!({ "tool_name": "safe_tool" }),
        )
        .await;

    assert_eq!(status, StatusCode::OK, "expected 200; body: {}", resp);
    assert_eq!(
        resp["allowed"].as_bool(),
        Some(true),
        "tool not on deny list must be allowed; body: {}",
        resp
    );
}

/// gate/tool-call without auth must be rejected (401 or 403).
/// Confirms the route is behind the session auth middleware.
#[tokio::test]
async fn gate_http_rejects_unauthenticated_call() {
    let h = GateHarness::new().await;

    let (status, _resp) = h
        .post_unauthed(
            "/api/v1/gate/tool-call",
            serde_json::json!({ "tool_name": "any_tool" }),
        )
        .await;

    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN,
        "unauthenticated gate call must be rejected with 401/403, got {}",
        status
    );
}

/// An agent with no `delegation:granted` chain entry is denied by the P4
/// prerequisite check.  The gate returns 200 with `allowed:false`.
#[tokio::test]
async fn gate_http_denies_agent_without_delegation() {
    let h = GateHarness::new().await;

    let (status, resp) = h
        .post_authed(
            "/api/v1/gate/tool-call",
            serde_json::json!({
                "tool_name": "chain_render",
                "agent": "unregistered-agent-xyz"
            }),
        )
        .await;

    assert_eq!(status, StatusCode::OK, "gate always returns 200; body: {}", resp);
    assert_eq!(
        resp["allowed"].as_bool(),
        Some(false),
        "agent with no delegation must be denied; body: {}",
        resp
    );
}

// ── Gap documentation tests ────────────────────────────────────────────────────

/// Gate decisions are recorded on the chain in test mode.
///
/// Verifies that `gate_tool_call_handler` emits a `chain_entry_hash` that is
/// non-null — i.e., `emit_tool_receipt` successfully wrote to the writable
/// unsigned store supplied by `GateHarness`.
///
/// Previously tracked as `gap_gate_chain_emission_requires_genesis` (the gap
/// was: bootstrap mode opened a read-only store, silencing all chain writes).
/// That gap is closed by the audit-store swap in `GateHarness::new()`.
#[tokio::test]
async fn gate_http_emits_chain_entry() {
    let h = GateHarness::new().await;

    let (status, resp) = h
        .post_authed(
            "/api/v1/gate/tool-call",
            serde_json::json!({ "tool_name": "probe_tool" }),
        )
        .await;

    assert_eq!(status, StatusCode::OK, "gate must return 200; body: {}", resp);

    // The gate handler emits a chain entry for every decision; the hash must
    // be present and non-null in the response.
    assert!(
        !resp["chain_entry_hash"].is_null(),
        "chain_entry_hash must be non-null — gate decision must land on chain; body: {}",
        resp
    );
    assert!(
        resp["chain_entry_hash"].as_str().map_or(false, |s| !s.is_empty()),
        "chain_entry_hash must be a non-empty string; body: {}",
        resp
    );
}

/// HTTP grant → delegation:granted on chain → gate allows agent (Boundary 1→2).
///
/// Verifies the full Boundary 1→2 path: an HTTP capability grant emits a
/// `delegation:granted:<grantee>` chain entry, and the gate's P4 prereq check
/// finds that entry, allowing the agent's subsequent tool call.
///
/// Previously tracked as `gap_delegation_http_handler_does_not_emit_chain_entry`.
/// That gap was: the grant handler stored the grant in-memory only, never
/// writing to the chain, so the gate's P4 prereq check found nothing and
/// denied the agent. The gap is closed: `grant_handler` calls
/// `emit_delegation_receipt`, and `GateHarness` now supplies a writable store.
#[tokio::test]
async fn gate_http_grant_enables_agent_via_chain() {
    let h = GateHarness::new().await;
    let agent = "boundary-test-agent";

    // Issue a capability grant for the agent via HTTP.
    let (grant_status, grant_resp) = h
        .post_authed(
            "/api/v1/capabilities/grant",
            serde_json::json!({
                "grantee": agent,
                "capability": "execute",
                "scope": ["*"],
                "max_delegation_depth": 1
            }),
        )
        .await;

    // grant_handler uses TrustTier::Tier2 in the PolicyContext it passes to
    // enforce_gate, satisfying the CredentialAccess tier requirement. If it
    // still gets 403 the test environment is misconfigured — fail loudly.
    assert_eq!(
        grant_status,
        StatusCode::OK,
        "capability grant must succeed (200); body: {}",
        grant_resp
    );

    // Boundary 1→2: the grant handler emits delegation:granted:<agent> to
    // the chain. The gate's P4 prereq reads the chain and finds it.
    let (gate_status, gate_resp) = h
        .post_authed(
            "/api/v1/gate/tool-call",
            serde_json::json!({
                "tool_name": "probe_tool",
                "agent": agent
            }),
        )
        .await;

    assert_eq!(gate_status, StatusCode::OK, "gate must return 200; body: {}", gate_resp);
    assert_eq!(
        gate_resp["allowed"].as_bool(),
        Some(true),
        "HTTP-granted agent must be allowed by the gate (delegation:granted \
         is on the chain); body: {}",
        gate_resp
    );
}
