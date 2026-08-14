//! Receipt chain stress tests — end-to-end HTTP lifecycle exercising.
//!
//! These tests boot zp-server in-process via `TestApp` and exercise the
//! full HTTP path: gate calls, grant issuance, chain emission, chain reads,
//! and chain integrity verification under concurrent load.
//!
//! They are the production-path complement to the unit-level hardening tests
//! (claim2_collective_audit, delegation_narrowing, chain_integrity). Where
//! those tests prove individual invariants in isolation, these tests prove
//! the invariants hold end-to-end through the HTTP layer.
//!
//! Run with:
//! ```bash
//! cargo test -p zp-hardening-tests stress
//! ```

// `#[cfg(test)]` on the imports, not just the tests. Every item below is
// `#[tokio::test]`, which expands to `#[test]` and is therefore excluded from
// non-test builds — so in the *lib* target these imports read as unused,
// rustc warns, and `cargo clippy --fix` deletes them. It did exactly that on
// 2026-08-12, breaking the lib-test target with 29 errors. Gating the imports
// the same way the items are gated makes this crate safe to run `--fix` over.
// `claim2_collective_audit.rs` already used this pattern for `uuid::Uuid`.
#[cfg(test)]
use crate::harness::TestApp;
#[cfg(test)]
use axum::http::StatusCode;
#[cfg(test)]
use serde_json::json;

// ─── Chain growth via gate calls ─────────────────────────────────────────────

/// Fire N agentless gate calls (allowed by empty deny-list) and verify:
/// 1. Each call returns `allowed: true` with a `chain_entry_hash`
/// 2. `GET /audit/entries` count reflects the emissions
/// 3. `GET /audit/verify` reports `valid: true` — chain is coherent
#[tokio::test]
async fn stress_gate_calls_grow_chain_and_verify_clean() {
    let app = TestApp::new().await;
    let token = app.session_token.clone();
    const N: usize = 10;

    for i in 0..N {
        let (status, body) = app
            .post_json_authed(
                "/api/v1/gate/tool-call",
                json!({"tool_name": format!("stress-tool-{i}")}),
                &token,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "gate call {i} failed");
        assert_eq!(body["allowed"], true, "agentless call {i} must be allowed");
        assert!(
            body["chain_entry_hash"].is_string(),
            "gate call {i} must emit a chain entry"
        );
    }

    // Chain integrity must hold after N writes.
    let (status, verify) = app.get_authed("/api/v1/audit/verify", &token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        verify["valid"], true,
        "chain must be valid after {N} gate calls: {verify}"
    );
    assert_eq!(verify["has_tampered_entries"], false);

    // Audit entries endpoint must reflect the chain activity.
    let (status, entries) = app
        .get_authed("/api/v1/audit/entries?limit=100", &token)
        .await;
    assert_eq!(status, StatusCode::OK);
    let count = entries["count"].as_u64().unwrap_or(0);
    assert!(
        count >= N as u64,
        "audit entries count {count} must be >= {N}"
    );
}

// ─── Chain head advances ─────────────────────────────────────────────────────

/// The chain head hash must change after gate activity, confirming new entries
/// are actually being appended (not silently dropped).
#[tokio::test]
async fn stress_chain_head_advances_on_gate_activity() {
    let app = TestApp::new().await;
    let token = app.session_token.clone();

    let (status, head0) = app.get_authed("/api/v1/audit/chain-head", &token).await;
    assert_eq!(status, StatusCode::OK);
    let hash0 = head0["latest_hash"].as_str().unwrap_or("").to_string();
    assert_eq!(head0["chain_algorithm"], "Blake3");

    // Fire one gate call.
    app.post_json_authed(
        "/api/v1/gate/tool-call",
        json!({"tool_name": "head-advance-probe"}),
        &token,
    )
    .await;

    let (_, head1) = app.get_authed("/api/v1/audit/chain-head", &token).await;
    let hash1 = head1["latest_hash"].as_str().unwrap_or("").to_string();

    assert!(!hash1.is_empty(), "chain head must be non-empty after a gate call");
    assert_ne!(hash0, hash1, "chain head must advance after a gate call");
}

// ─── ToolCall grant emits delegation receipt on chain ────────────────────────

/// Issue a ToolCall grant via HTTP (the Claim 4 HTTP path added in the gap fix)
/// and verify:
/// 1. The grant is accepted (200)
/// 2. A `delegation:granted` receipt lands on the audit chain
/// 3. Chain integrity still holds
#[tokio::test]
async fn stress_tool_call_grant_emits_delegation_receipt_on_chain() {
    let app = TestApp::new().await;
    let token = app.session_token.clone();

    let (_, before) = app
        .get_authed("/api/v1/audit/entries?limit=100", &token)
        .await;
    let count_before = before["count"].as_u64().unwrap_or(0);

    // Issue a ToolCall grant scoped to ["bash", "read"].
    let (status, grant_resp) = app
        .post_json_authed(
            "/api/v1/capabilities/grant",
            json!({
                "grantee": "stress-agent-alpha",
                "capability": "tool_call",
                "scope": ["bash", "read"]
            }),
            &token,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "ToolCall grant must be accepted: {grant_resp}"
    );
    assert!(
        grant_resp["receipt_id"].is_string(),
        "grant response must include receipt_id"
    );
    assert_eq!(grant_resp["signed"], true);

    // Chain must have grown by at least 1 (the delegation:granted entry).
    let (_, after) = app
        .get_authed("/api/v1/audit/entries?limit=100", &token)
        .await;
    let count_after = after["count"].as_u64().unwrap_or(0);
    assert!(
        count_after > count_before,
        "chain must grow after grant issuance: before={count_before} after={count_after}"
    );

    // Chain must still be valid.
    let (_, verify) = app.get_authed("/api/v1/audit/verify", &token).await;
    assert_eq!(
        verify["valid"], true,
        "chain must be valid after grant: {verify}"
    );
}

// ─── Full Claim 4 HTTP lifecycle ─────────────────────────────────────────────

/// Grant → gate-allow (in-scope tool) → gate-deny (out-of-scope tool) → chain coherent.
///
/// This is the full Claim 4 lifecycle exercised through HTTP:
/// 1. Issue ToolCall grant scoped to ["bash"]
/// 2. Gate call for "bash" with agent tagged → allowed (grant covers it)
/// 3. Gate call for "write_file" with agent tagged → denied (scope exceeded)
/// 4. Both decisions are on the chain; chain verifies clean
#[tokio::test]
async fn stress_claim4_http_lifecycle_grant_allow_deny() {
    let app = TestApp::new().await;
    let token = app.session_token.clone();

    // Issue a narrow ToolCall grant: only "bash" is authorised.
    let (status, grant_resp) = app
        .post_json_authed(
            "/api/v1/capabilities/grant",
            json!({
                "grantee": "stress-agent-beta",
                "capability": "tool_call",
                "scope": ["bash"]
            }),
            &token,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "narrow grant must succeed: {grant_resp}");

    // The gate's prereq check walks the audit chain for delegation:granted receipts.
    // "bash" is in scope → allowed.
    let (status, allow_resp) = app
        .post_json_authed(
            "/api/v1/gate/tool-call",
            json!({"tool_name": "bash", "agent": "stress-agent-beta"}),
            &token,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        allow_resp["allowed"], true,
        "bash must be allowed for stress-agent-beta: {allow_resp}"
    );
    assert!(allow_resp["chain_entry_hash"].is_string());

    // "write_file" is NOT in scope → denied with capability_scope_exceeded.
    let (status, deny_resp) = app
        .post_json_authed(
            "/api/v1/gate/tool-call",
            json!({"tool_name": "write_file", "agent": "stress-agent-beta"}),
            &token,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        deny_resp["allowed"], false,
        "write_file must be denied for stress-agent-beta: {deny_resp}"
    );
    assert_eq!(deny_resp["reason"], "capability_scope_exceeded");
    assert!(deny_resp["chain_entry_hash"].is_string());

    // Chain must still be coherent after allow + deny entries.
    let (_, verify) = app.get_authed("/api/v1/audit/verify", &token).await;
    assert_eq!(
        verify["valid"], true,
        "chain must be valid after allow+deny: {verify}"
    );
}

// ─── Agent with no delegation emits denial receipt ───────────────────────────

/// A gate call identifying an unknown agent (no live delegation) must be denied
/// AND must land a `gate:denied` chain entry.
#[tokio::test]
async fn stress_unknown_agent_denied_and_chained() {
    let app = TestApp::new().await;
    let token = app.session_token.clone();

    let (status, body) = app
        .post_json_authed(
            "/api/v1/gate/tool-call",
            json!({"tool_name": "bash", "agent": "unknown-agent-xyz"}),
            &token,
        )
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["allowed"], false, "unknown agent must be denied: {body}");
    assert_eq!(body["reason"], "no_valid_delegation");
    assert!(
        body["chain_entry_hash"].is_string(),
        "denial must emit a chain entry"
    );

    // Chain must still be valid after the denial entry.
    let (_, verify) = app.get_authed("/api/v1/audit/verify", &token).await;
    assert_eq!(
        verify["valid"], true,
        "chain must be valid after denial: {verify}"
    );
}

// ─── Concurrent burst ─────────────────────────────────────────────────────────

/// Concurrently fire gate calls from multiple tasks and verify the chain
/// remains coherent. Tests that Mutex-protected audit store writes are
/// correct under concurrent load.
#[tokio::test]
async fn stress_concurrent_gate_calls_produce_coherent_chain() {
    use axum::body::Body;
    use axum::http::Request;
    use std::sync::Arc;
    use tower::ServiceExt;

    let app = Arc::new(TestApp::new().await);
    let token = app.session_token.clone();
    const CONCURRENT: usize = 8;
    const CALLS_PER_TASK: usize = 3;

    let mut handles = Vec::with_capacity(CONCURRENT);
    for task in 0..CONCURRENT {
        let router = app.router.clone();
        let tok = token.clone();
        handles.push(tokio::spawn(async move {
            for i in 0..CALLS_PER_TASK {
                let payload = json!({"tool_name": format!("concurrent-{task}-{i}")});
                let req = Request::builder()
                    .method("POST")
                    .uri("/api/v1/gate/tool-call")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {tok}"))
                    .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                    .unwrap();
                let _ = router.clone().oneshot(req).await;
            }
        }));
    }
    for h in handles {
        h.await.expect("concurrent task panicked");
    }

    // After CONCURRENT * CALLS_PER_TASK concurrent writes, chain must verify.
    let (_, verify) = app.get_authed("/api/v1/audit/verify", &token).await;
    assert_eq!(
        verify["valid"], true,
        "chain must be valid after concurrent burst: {verify}"
    );

    let (_, entries) = app
        .get_authed("/api/v1/audit/entries?limit=100", &token)
        .await;
    let count = entries["count"].as_u64().unwrap_or(0);
    assert!(
        count >= (CONCURRENT * CALLS_PER_TASK) as u64,
        "expected >= {} entries after burst, got {count}",
        CONCURRENT * CALLS_PER_TASK
    );
}

// ─── Wildcard ToolCall grant allows any tool ──────────────────────────────────

/// A wildcard ToolCall grant (scope ["*"]) must allow any tool name via the
/// HTTP gate. This exercises the `tools.contains("*")` path in matches_action.
#[tokio::test]
async fn stress_wildcard_tool_call_grant_allows_any_tool() {
    let app = TestApp::new().await;
    let token = app.session_token.clone();

    // Issue wildcard grant.
    let (status, _) = app
        .post_json_authed(
            "/api/v1/capabilities/grant",
            json!({
                "grantee": "stress-agent-gamma",
                "capability": "tool_call",
                "scope": ["*"]
            }),
            &token,
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    // Arbitrary tool names must all be allowed.
    for tool in &["bash", "read", "write_file", "list_dir", "anything_goes"] {
        let (status, body) = app
            .post_json_authed(
                "/api/v1/gate/tool-call",
                json!({"tool_name": tool, "agent": "stress-agent-gamma"}),
                &token,
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body["allowed"], true,
            "wildcard grant must allow tool '{tool}': {body}"
        );
    }

    // Chain coherent.
    let (_, verify) = app.get_authed("/api/v1/audit/verify", &token).await;
    assert_eq!(verify["valid"], true, "chain must be valid: {verify}");
}
