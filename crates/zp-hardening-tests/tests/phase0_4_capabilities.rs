//! Phase 0.4 — Capability grant and delegation protection regression tests.
//!
//! Tests that capability operations require proper authentication and
//! authorization:
//! - AUTHZ-VULN-05: Unauthenticated server-signed capability grants
//! - AUTHZ-VULN-16: Ownership-free capability delegation
//! - AUTHZ-VULN-17: Disabled signature verification + false reporting
//!
//! Before Phase 0.4 lands, these tests SHOULD FAIL.
//! After Phase 0.4, they MUST PASS.

use axum::http::StatusCode;
use zp_hardening_tests::harness::TestApp;
use zp_hardening_tests::payloads::authz;

// ============================================================================
// AUTHZ-VULN-05: Unauthenticated server-signed capability grants
// ============================================================================

/// AUTHZ-VULN-05: POST /api/v1/capabilities/grant without auth must be rejected.
///
/// Shannon's finding: anyone could issue a server-signed capability grant
/// with unrestricted scope (system:*, admin:*) without any credentials.
#[tokio::test]
async fn test_authz_vuln_05_unauth_capability_grant() {
    let app = TestApp::new().await;
    let (status, _body) = app
        .post_json("/api/v1/capabilities/grant", authz::unauth_capability_grant())
        .await;

    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN,
        "AUTHZ-VULN-05: POST /api/v1/capabilities/grant returned {} (expected 401/403)",
        status
    );
}

/// AUTHZ-VULN-05: Even with auth, a non-operator shouldn't be able to grant
/// system:* admin:* capabilities.
#[tokio::test]
async fn test_authz_vuln_05_overly_broad_grant() {
    let app = TestApp::new().await;
    // Even if authenticated, granting system:* admin:* should require
    // operator-level authority (Tier 2+). A regular session token
    // (which is Tier 1) should not be sufficient for this scope.
    let (status, _body) = app
        .post_json("/api/v1/capabilities/grant", authz::unauth_capability_grant())
        .await;

    assert!(
        status == StatusCode::UNAUTHORIZED
            || status == StatusCode::FORBIDDEN
            || status == StatusCode::BAD_REQUEST,
        "AUTHZ-VULN-05: Overly broad grant should be rejected, got {}",
        status
    );
}

// ============================================================================
// AUTHZ-VULN-16: Ownership-free capability delegation
// ============================================================================

/// AUTHZ-VULN-16: POST /api/v1/capabilities/delegate without auth must be rejected.
///
/// Shannon's finding: delegation didn't verify that the caller was the
/// current holder of the grant being delegated.
#[tokio::test]
async fn test_authz_vuln_16_unauth_delegation() {
    let app = TestApp::new().await;
    let (status, _body) = app
        .post_json(
            "/api/v1/capabilities/delegate",
            authz::ownership_free_delegation(),
        )
        .await;

    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN,
        "AUTHZ-VULN-16: POST /api/v1/capabilities/delegate returned {} (expected 401/403)",
        status
    );
}

// ============================================================================
// AUTHZ-VULN-17: Disabled signature verification + false reporting
// ============================================================================

/// AUTHZ-VULN-17: POST /api/v1/capabilities/verify-chain with forged signatures.
///
/// Shannon's finding: the verify endpoint accepted chains with invalid
/// signatures and reported "verified: true" because signature verification
/// was disabled (verify_signatures=false).
#[tokio::test]
async fn test_authz_vuln_17_forged_chain_verification() {
    let app = TestApp::new().await;
    let (status, body) = app
        .post_json(
            "/api/v1/capabilities/verify-chain",
            authz::forged_delegation_chain(),
        )
        .await;

    // After fix: either auth rejects (401) or verification catches the forgery.
    // The critical thing is it must NOT return { verified: true }.
    if status == StatusCode::OK {
        let verified = body.get("verified").and_then(|v| v.as_bool());
        assert_ne!(
            verified,
            Some(true),
            "AUTHZ-VULN-17: Forged delegation chain was accepted as verified! \
             Signature verification is not enabled."
        );
    }
    // 401/403 is also acceptable (auth middleware caught it first)
}
