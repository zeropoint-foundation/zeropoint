//! Integration tests for the `require_auth` middleware's envelope path.
//!
//! Asserts the migration's headline properties:
//!
//! 1. A valid `Authorization: ZP-Sig …` envelope authenticates the request
//!    end-to-end through the real middleware (body-buffer + verify + forward).
//! 2. The legacy `Authorization: Bearer …` path still works during the
//!    backwards-compat window (Step 2 of the migration; removed at Step 4).
//! 3. Specific failure modes surface as 401 + `X-Auth-Reason` codes the
//!    caller can act on (envelope-signer for kid drift, envelope-drift for
//!    clock skew, envelope-replay for nonce reuse).

use std::sync::Arc;

use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, StatusCode},
    middleware::{from_fn, Next},
    routing::post,
    Router,
};
use ed25519_dalek::{Signer, SigningKey};
use tower::ServiceExt;

use zp_gate_envelope::{
    body_hash_hex, build_header, random_nonce_b64, EnvelopeClaims, SCHEME_VERSION,
};
use zp_receipt::Signable;
use zp_server::{
    auth::{require_auth, EndpointRateLimiter, FailedAuthLimiter, SessionAuth},
    envelope_state::EnvelopeVerifier,
};

const TEST_GENESIS: [u8; 32] = [0x77u8; 32];

fn gate_signer() -> SigningKey {
    let seed = zp_keys::derive_gate_signer_seed(&TEST_GENESIS);
    SigningKey::from_bytes(&seed)
}

fn build_app(envelope_verifier: Option<Arc<EnvelopeVerifier>>) -> (Router, Arc<SessionAuth>) {
    // SessionAuth derived from a deterministic signing-key for the test.
    let session_auth = Arc::new(SessionAuth::new_in_memory(&[0x11u8; 32]));
    let rate_limiter = Arc::new(FailedAuthLimiter::new());
    let endpoint_limiter = Arc::new(EndpointRateLimiter::new());

    let router = Router::new()
        .route("/api/v1/gate/tool-call", post(|| async { "ok" }))
        .layer(from_fn({
            let session_auth = session_auth.clone();
            let envelope_verifier = envelope_verifier.clone();
            let rate_limiter = rate_limiter.clone();
            let endpoint_limiter = endpoint_limiter.clone();
            move |req: Request<Body>, next: Next| {
                let session_auth = session_auth.clone();
                let envelope_verifier = envelope_verifier.clone();
                let rate_limiter = rate_limiter.clone();
                let endpoint_limiter = endpoint_limiter.clone();
                async move {
                    require_auth(
                        req,
                        next,
                        session_auth,
                        envelope_verifier,
                        rate_limiter,
                        endpoint_limiter,
                    )
                    .await
                }
            }
        }));

    (router, session_auth)
}

fn signed_envelope(
    sk: &SigningKey,
    method: &str,
    path: &str,
    body: &[u8],
    ts_offset: i64,
) -> String {
    let claims = EnvelopeClaims {
        v: SCHEME_VERSION,
        method: method.to_string(),
        path: path.to_string(),
        body_hash: body_hash_hex(body),
        ts: chrono::Utc::now().timestamp() + ts_offset,
        nonce: random_nonce_b64(),
    };
    let kid = sk.verifying_key().to_bytes();
    let sig = sk.sign(&claims.canonical_hash()).to_bytes();
    build_header(&claims, &kid, &sig)
}

#[tokio::test]
async fn envelope_authenticates_request_end_to_end() {
    let sk = gate_signer();
    let verifier = Arc::new(EnvelopeVerifier::new(sk.verifying_key().to_bytes()));
    let (app, _session) = build_app(Some(verifier));

    let body = br#"{"agent":"hermes","tool":"echo"}"#.to_vec();
    let header = signed_envelope(&sk, "POST", "/api/v1/gate/tool-call", &body, 0);

    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/gate/tool-call")
        .header(header::AUTHORIZATION, header)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "envelope should authenticate"
    );
}

#[tokio::test]
async fn legacy_bearer_token_still_works_during_migration() {
    let sk = gate_signer();
    let verifier = Arc::new(EnvelopeVerifier::new(sk.verifying_key().to_bytes()));
    let (app, session) = build_app(Some(verifier));

    let token = session.current_token();
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/gate/tool-call")
        .header(header::AUTHORIZATION, format!("Bearer {}", token))
        .body(Body::from("{}"))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "legacy bearer must continue working during the backwards-compat window"
    );
}

#[tokio::test]
async fn no_auth_returns_401_missing() {
    let sk = gate_signer();
    let verifier = Arc::new(EnvelopeVerifier::new(sk.verifying_key().to_bytes()));
    let (app, _) = build_app(Some(verifier));

    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/gate/tool-call")
        .body(Body::from("{}"))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let reason = resp
        .headers()
        .get("x-auth-reason")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(reason, "missing");
}

#[tokio::test]
async fn envelope_with_wrong_signer_yields_envelope_signer_reason() {
    let sk = gate_signer();
    // Verifier configured with a different signer's pubkey.
    let other_sk = SigningKey::from_bytes(&[0xAAu8; 32]);
    let verifier = Arc::new(EnvelopeVerifier::new(other_sk.verifying_key().to_bytes()));
    let (app, _) = build_app(Some(verifier));

    let body = b"{}".to_vec();
    let header = signed_envelope(&sk, "POST", "/api/v1/gate/tool-call", &body, 0);

    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/gate/tool-call")
        .header(header::AUTHORIZATION, header)
        .body(Body::from(body))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let reason = resp
        .headers()
        .get("x-auth-reason")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(reason, "envelope-signer");
}

#[tokio::test]
async fn envelope_outside_drift_window_yields_envelope_drift_reason() {
    let sk = gate_signer();
    let verifier = Arc::new(EnvelopeVerifier::new(sk.verifying_key().to_bytes()));
    let (app, _) = build_app(Some(verifier));

    let body = b"{}".to_vec();
    // 1 hour in the past — well outside the ±30s default drift window.
    let header = signed_envelope(&sk, "POST", "/api/v1/gate/tool-call", &body, -3600);

    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/gate/tool-call")
        .header(header::AUTHORIZATION, header)
        .body(Body::from(body))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let reason = resp
        .headers()
        .get("x-auth-reason")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(reason, "envelope-drift");
}

#[tokio::test]
async fn envelope_with_no_verifier_returns_envelope_not_configured() {
    let sk = gate_signer();
    // No verifier installed (pre-Genesis state).
    let (app, _) = build_app(None);

    let body = b"{}".to_vec();
    let header = signed_envelope(&sk, "POST", "/api/v1/gate/tool-call", &body, 0);

    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/gate/tool-call")
        .header(header::AUTHORIZATION, header)
        .body(Body::from(body))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let reason = resp
        .headers()
        .get("x-auth-reason")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(reason, "envelope-not-configured");
}

#[tokio::test]
async fn body_is_passed_through_to_handler_unchanged() {
    // Asserts the middleware's body-buffer-then-rebuild path doesn't mutate
    // bytes — downstream handlers see exactly what the signer signed.
    let sk = gate_signer();
    let verifier = Arc::new(EnvelopeVerifier::new(sk.verifying_key().to_bytes()));

    let session_auth = Arc::new(SessionAuth::new_in_memory(&[0x11u8; 32]));
    let rate_limiter = Arc::new(FailedAuthLimiter::new());
    let endpoint_limiter = Arc::new(EndpointRateLimiter::new());

    let app: Router = Router::new()
        .route(
            "/api/v1/gate/tool-call",
            post(|req: Request<Body>| async move {
                let body = to_bytes(req.into_body(), 1024 * 1024).await.unwrap();
                axum::http::Response::new(Body::from(body))
            }),
        )
        .layer(from_fn({
            let session_auth = session_auth.clone();
            let envelope_verifier = Some(verifier.clone());
            let rate_limiter = rate_limiter.clone();
            let endpoint_limiter = endpoint_limiter.clone();
            move |req: Request<Body>, next: Next| {
                let session_auth = session_auth.clone();
                let envelope_verifier = envelope_verifier.clone();
                let rate_limiter = rate_limiter.clone();
                let endpoint_limiter = endpoint_limiter.clone();
                async move {
                    require_auth(
                        req,
                        next,
                        session_auth,
                        envelope_verifier,
                        rate_limiter,
                        endpoint_limiter,
                    )
                    .await
                }
            }
        }));

    let body = br#"{"agent":"hermes","tool":"echo","args":[1,2,3]}"#.to_vec();
    let header = signed_envelope(&sk, "POST", "/api/v1/gate/tool-call", &body, 0);

    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/gate/tool-call")
        .header(header::AUTHORIZATION, header)
        .body(Body::from(body.clone()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let echoed = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    assert_eq!(
        echoed.as_ref(),
        body.as_slice(),
        "body must round-trip unchanged"
    );
}
