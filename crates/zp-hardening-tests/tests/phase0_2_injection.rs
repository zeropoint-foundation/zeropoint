//! Phase 0.2 — INJ-VULN and SSRF-VULN regression tests.
//!
//! Tests that the exec WebSocket rejects dangerous commands including:
//! - Double-space blocklist bypass (INJ-VULN-01)
//! - Make/cargo in attacker-controlled cwd (INJ-VULN-02)
//! - Path traversal via cwd (INJ-VULN-03)
//! - Curl/wget file exfiltration (INJ-VULN-04)
//! - SSRF via curl/wget to internal services (SSRF-VULN-01)
//! - Shell metacharacter injection
//!
//! These tests require a live TCP server because WebSocket upgrade
//! needs a real connection. They use TestServer on a random port.
//!
//! Before Phase 0.2 lands, these tests SHOULD FAIL.
//! After Phase 0.2, they MUST PASS.

use futures::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;
use zp_hardening_tests::harness::TestServer;
use zp_hardening_tests::payloads::{injection, ssrf};

/// Helper: send a JSON payload over WebSocket and read the response.
async fn ws_exec_expect_blocked(server: &TestServer, payload: serde_json::Value) {
    let ws_url = server.ws_url("/ws/exec");
    let (mut ws, _resp) = tokio_tungstenite::connect_async(&ws_url)
        .await
        .expect("WebSocket connect failed");

    let msg = serde_json::to_string(&payload).unwrap();
    ws.send(Message::Text(msg)).await.expect("send failed");

    // Read the response — should be an error, not stdout from the command
    if let Some(Ok(Message::Text(text))) = ws.next().await {
        let resp: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
        let resp_type = resp.get("type").and_then(|t| t.as_str()).unwrap_or("");
        assert!(
            resp_type == "error" || resp_type == "blocked",
            "Expected exec to be blocked, got type='{}' for payload: {}",
            resp_type,
            serde_json::to_string_pretty(&payload).unwrap()
        );
    }
    // If the connection was closed, that's also acceptable (server rejected)
}

// ============================================================================
// INJ-VULN-01: Command injection — double-space blocklist bypass
// ============================================================================

/// INJ-VULN-01: Double-space in `rm  -rf` should not bypass the blocklist.
#[tokio::test]
async fn test_inj_vuln_01_double_space_bypass() {
    let server = TestServer::new().await;
    ws_exec_expect_blocked(&server, injection::double_space_bypass()).await;
}

/// INJ-VULN-01 variant: Tab character in command.
#[tokio::test]
async fn test_inj_vuln_01_tab_bypass() {
    let server = TestServer::new().await;
    ws_exec_expect_blocked(&server, injection::tab_bypass()).await;
}

// ============================================================================
// INJ-VULN-02: Command injection — make in attacker cwd
// ============================================================================

/// INJ-VULN-02: `make` with attacker-controlled cwd must be blocked.
#[tokio::test]
async fn test_inj_vuln_02_make_attacker_cwd() {
    let server = TestServer::new().await;
    ws_exec_expect_blocked(&server, injection::make_in_attacker_cwd()).await;
}

/// INJ-VULN-02 variant: `cargo run` with attacker-controlled cwd.
#[tokio::test]
async fn test_inj_vuln_02_cargo_run_attacker_cwd() {
    let server = TestServer::new().await;
    ws_exec_expect_blocked(&server, injection::cargo_run_attacker_cwd()).await;
}

// ============================================================================
// INJ-VULN-03: Path traversal — unrestricted cwd
// ============================================================================

/// INJ-VULN-03: Relative path traversal in cwd (`../../etc`).
#[tokio::test]
async fn test_inj_vuln_03_path_traversal_cwd() {
    let server = TestServer::new().await;
    ws_exec_expect_blocked(&server, injection::path_traversal_cwd()).await;
}

/// INJ-VULN-03 variant: Absolute system path as cwd.
#[tokio::test]
async fn test_inj_vuln_03_absolute_system_path() {
    let server = TestServer::new().await;
    ws_exec_expect_blocked(&server, injection::absolute_system_path()).await;
}

// ============================================================================
// INJ-VULN-04: Command injection — curl file exfiltration
// ============================================================================

/// INJ-VULN-04: curl with -d @/etc/passwd must be blocked.
#[tokio::test]
async fn test_inj_vuln_04_curl_exfiltration() {
    let server = TestServer::new().await;
    ws_exec_expect_blocked(&server, injection::curl_exfiltration()).await;
}

/// INJ-VULN-04 variant: wget --post-file exfiltration.
#[tokio::test]
async fn test_inj_vuln_04_wget_exfiltration() {
    let server = TestServer::new().await;
    ws_exec_expect_blocked(&server, injection::wget_exfiltration()).await;
}

// ============================================================================
// SSRF-VULN-01: Full SSRF via exec curl/wget
// ============================================================================

/// SSRF-VULN-01: curl to cloud metadata endpoint.
#[tokio::test]
async fn test_ssrf_vuln_01_cloud_metadata() {
    let server = TestServer::new().await;
    ws_exec_expect_blocked(&server, ssrf::cloud_metadata_curl()).await;
}

/// SSRF-VULN-01 variant: wget to internal network.
#[tokio::test]
async fn test_ssrf_vuln_01_internal_network() {
    let server = TestServer::new().await;
    ws_exec_expect_blocked(&server, ssrf::internal_network_wget()).await;
}

/// SSRF-VULN-01 variant: curl to localhost Redis.
#[tokio::test]
async fn test_ssrf_vuln_01_localhost_probe() {
    let server = TestServer::new().await;
    ws_exec_expect_blocked(&server, ssrf::localhost_probe()).await;
}

// ============================================================================
// Shell metacharacter injection (extends INJ-VULN-01 through 04)
// ============================================================================

/// Semicolon chaining: `echo hello; cat /etc/passwd`.
#[tokio::test]
async fn test_shell_metachar_semicolon() {
    let server = TestServer::new().await;
    ws_exec_expect_blocked(&server, injection::semicolon_chain()).await;
}

/// Backtick command substitution.
#[tokio::test]
async fn test_shell_metachar_backtick() {
    let server = TestServer::new().await;
    ws_exec_expect_blocked(&server, injection::backtick_injection()).await;
}

/// $() command substitution.
#[tokio::test]
async fn test_shell_metachar_dollar_paren() {
    let server = TestServer::new().await;
    ws_exec_expect_blocked(&server, injection::dollar_paren_injection()).await;
}

/// Pipe to external service.
#[tokio::test]
async fn test_shell_metachar_pipe_external() {
    let server = TestServer::new().await;
    ws_exec_expect_blocked(&server, injection::pipe_to_external()).await;
}
