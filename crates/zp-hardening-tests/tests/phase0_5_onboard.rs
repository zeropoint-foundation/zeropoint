//! Phase 0.5 — Onboarding WebSocket lockdown regression tests.
//!
//! Tests that the onboarding WebSocket enforces:
//! - AUTH-VULN-05: Unauthenticated credential vault injection
//! - AUTHZ-VULN-19: Unauthenticated credential injection (duplicate)
//! - AUTHZ-VULN-20: Arbitrary scan path via onboard configure
//! - INJ-VULN-05: Path traversal via unauth scan_path
//!
//! These tests require a live TCP server for WebSocket connections.
//!
//! Before Phase 0.5 lands, these tests SHOULD FAIL.
//! After Phase 0.5, they MUST PASS.

use futures::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;
use zp_hardening_tests::harness::TestServer;
use zp_hardening_tests::payloads::{authz, injection};

/// Helper: send an onboard WebSocket payload and assert it's rejected.
///
/// "Rejected" means one of:
/// - Connection upgrade is refused (401 before upgrade)
/// - Server sends an error event
/// - Server closes the connection
async fn ws_onboard_expect_rejected(server: &TestServer, payload: serde_json::Value) {
    let ws_url = server.ws_url("/api/onboard/ws");
    let result = tokio_tungstenite::connect_async(&ws_url).await;

    match result {
        Ok((mut ws, _resp)) => {
            let msg = serde_json::to_string(&payload).unwrap();
            ws.send(Message::Text(msg)).await.expect("send failed");

            // Read response — should be an error or the action should be denied
            if let Some(Ok(Message::Text(text))) = ws.next().await {
                let resp: serde_json::Value =
                    serde_json::from_str(&text).unwrap_or_default();
                let event = resp
                    .get("event")
                    .and_then(|e| e.as_str())
                    .unwrap_or("");
                let resp_type = resp
                    .get("type")
                    .and_then(|t| t.as_str())
                    .unwrap_or("");

                // The action should be denied. Accepted events are "error",
                // "blocked", or a state-ordering violation.
                // What we do NOT want is a success event for vault_store or
                // configure from an unauthenticated context.
                let is_success = event == "vault_stored"
                    || event == "configured"
                    || event == "scan_complete"
                    || resp_type == "success";
                assert!(
                    !is_success,
                    "Onboard WS accepted dangerous action without auth: event='{}' for payload: {}",
                    event,
                    serde_json::to_string_pretty(&payload).unwrap()
                );
            }
            // Connection closed = also acceptable
        }
        Err(_) => {
            // Connection refused or upgrade denied — this is correct behavior
            // after auth middleware is wired to the onboard WS endpoint.
        }
    }
}

// ============================================================================
// AUTH-VULN-05 / AUTHZ-VULN-19: Unauthenticated credential vault injection
// ============================================================================

/// AUTH-VULN-05: vault_store via onboard WS without auth must be rejected.
///
/// Shannon's finding: anyone could inject API keys into the credential vault
/// by sending a vault_store action through the unprotected onboard WebSocket.
#[tokio::test]
async fn test_auth_vuln_05_unauth_vault_store() {
    let server = TestServer::new().await;
    ws_onboard_expect_rejected(&server, authz::onboard_vault_store()).await;
}

/// AUTH-VULN-05: vault_store must be rejected even when sent as the first
/// message (skipping the expected onboard flow steps).
#[tokio::test]
async fn test_auth_vuln_05_vault_store_step_skip() {
    let server = TestServer::new().await;
    // Send vault_store without completing prior onboard steps
    // (detect → genesis → scan → configure → THEN vault_store)
    ws_onboard_expect_rejected(&server, authz::onboard_vault_store()).await;
}

// ============================================================================
// AUTHZ-VULN-20: Onboard configure — arbitrary scan path
// ============================================================================

/// AUTHZ-VULN-20: configure with arbitrary scan_path must be rejected.
///
/// Shannon's finding: the configure action accepted any filesystem path
/// for scanning, allowing enumeration of the entire filesystem.
#[tokio::test]
async fn test_authz_vuln_20_arbitrary_scan_path() {
    let server = TestServer::new().await;
    ws_onboard_expect_rejected(&server, authz::onboard_arbitrary_scan()).await;
}

// ============================================================================
// INJ-VULN-05: Path traversal via unauth scan_path
// ============================================================================

/// INJ-VULN-05: scan_path = /etc must be rejected.
#[tokio::test]
async fn test_inj_vuln_05_scan_path_etc() {
    let server = TestServer::new().await;
    ws_onboard_expect_rejected(&server, injection::onboard_scan_path_traversal()).await;
}

/// INJ-VULN-05: scan_path = ~/.ssh must be rejected.
#[tokio::test]
async fn test_inj_vuln_05_scan_path_dotfiles() {
    let server = TestServer::new().await;
    ws_onboard_expect_rejected(&server, injection::onboard_scan_dotfiles()).await;
}
