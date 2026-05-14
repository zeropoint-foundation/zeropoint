//! ZP_SESSION_TOKEN gate integration tests (task #153, PoC #147).
//!
//! Verifies three invariants:
//!
//! 1. The gate endpoint rejects requests without a session token (401).
//! 2. The gate endpoint accepts the server's live session token (200 + allow).
//! 3. Exec-injected token matches what the server verifies — the round-trip
//!    that unblocks IronClaw's gov hook.
//!
//! These tests exercise the real call shape:
//!   token mint (AppState::init) → gate endpoint auth check → allow decision
//!
//! The harness boots zp-server in-process so no external process or live
//! ~/ZeroPoint directory is needed.

use axum::http::StatusCode;
use zp_hardening_tests::harness::TestApp;

// ── Gate auth: no token → 401 ─────────────────────────────────────────────

/// Gate endpoint must reject requests with no Authorization header.
///
/// Regression guard: if auth middleware is ever removed from the gate route,
/// this test catches it. Complement to the AUTH-VULN-01 sweep in
/// phase0_1_auth.rs (which covers the gate via PROTECTED_ENDPOINTS_POST).
#[tokio::test]
async fn test_gate_requires_auth() {
    let app = TestApp::new().await;
    let (status, body) = app
        .post_json(
            "/api/v1/gate/tool-call",
            serde_json::json!({"tool_name": "chain_render", "args_hash": "abc123"}),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "gate must reject unauthenticated requests; got {} body={}",
        status,
        body
    );
}

/// Gate endpoint must reject a stale/invalid bearer token.
#[tokio::test]
async fn test_gate_rejects_invalid_token() {
    let app = TestApp::new().await;
    let (status, _body) = app
        .post_json_authed(
            "/api/v1/gate/tool-call",
            serde_json::json!({"tool_name": "chain_render", "args_hash": "abc123"}),
            "totally-invalid-token",
        )
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "gate must reject invalid bearer token"
    );
}

// ── Gate auth: valid token → 200 + allow ─────────────────────────────────

/// Gate endpoint allows a benign tool name when authenticated with the live
/// session token — the happy path that exec-injected ZP_SESSION_TOKEN enables.
///
/// Note: `agent` is omitted intentionally. Providing an agent ID triggers the
/// delegation-prerequisite check (P4 #197), which requires a standing lease
/// that the test harness does not provision. Agentless callers use the
/// permissive legacy path, which is the correct shape for this auth test.
#[tokio::test]
async fn test_gate_allows_with_valid_token() {
    let app = TestApp::new().await;
    let (status, body) = app
        .post_json_authed(
            "/api/v1/gate/tool-call",
            serde_json::json!({
                "tool_name": "chain_render",
                "args_hash": "deadbeef01020304"
            }),
            &app.session_token,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "gate must return 200 for valid token; body={}",
        body
    );
    // The gate returns `allow` (legacy) and `allowed` (canonical).
    // Either field present and truthy is a pass.
    let allowed = body["allowed"]
        .as_bool()
        .or_else(|| body["allow"].as_bool());
    assert_eq!(
        allowed,
        Some(true),
        "gate must return allow=true for benign tool; body={}",
        body
    );
}

/// Gate response includes a receipt_id — confirming the decision is journaled
/// into the audit chain (the chain-render accountability requirement).
#[tokio::test]
async fn test_gate_response_includes_receipt_id() {
    let app = TestApp::new().await;
    let (status, body) = app
        .post_json_authed(
            "/api/v1/gate/tool-call",
            serde_json::json!({
                "tool_name": "chain_render",
                "args_hash": "cafebabe00000000"
            }),
            &app.session_token,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body["receipt_id"].is_string(),
        "gate response must include a receipt_id; body={}",
        body
    );
}

// ── Token round-trip: session.json ↔ gate verify ─────────────────────────

/// Verifies that a token read from the server's persisted session.json would
/// pass gate authentication — the invariant that exec-injection relies on.
///
/// The harness does not write a real session.json (it uses an isolated temp
/// dir), so this test reconstructs the same invariant: `state.session_token()`
/// returns exactly the token the auth middleware will accept. If the server
/// ever mints a token different from what it verifies, this test catches it.
#[tokio::test]
async fn test_session_token_round_trip() {
    let app = TestApp::new().await;
    let token = app.session_token.clone();

    // Token must be a 64-char hex string (32-byte SHA-256 output).
    assert_eq!(
        token.len(),
        64,
        "session token must be 64 hex chars; got {:?}",
        token
    );
    assert!(
        token.chars().all(|c| c.is_ascii_hexdigit()),
        "session token must be hex; got {:?}",
        token
    );

    // The same token authenticates a gate request — proving the value that
    // `read_zp_session_token_from(session.json)` would return is the one the
    // server accepts.
    let (status, body) = app
        .post_json_authed(
            "/api/v1/gate/tool-call",
            serde_json::json!({"tool_name": "chain_render", "args_hash": "00000001"}),
            &token,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "token from state.session_token() must authenticate the gate; body={}",
        body
    );
}

// ── Regression: gate token unaffected by irrelevant field variations ──────

/// Gate accepts the minimal required payload (tool_name only); optional
/// fields (args_hash, agent, thread_id, run_id) are not required.
#[tokio::test]
async fn test_gate_minimal_payload() {
    let app = TestApp::new().await;
    let (status, body) = app
        .post_json_authed(
            "/api/v1/gate/tool-call",
            serde_json::json!({"tool_name": "memory"}),
            &app.session_token,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "gate must accept minimal payload; body={}",
        body
    );
}
