//! One-shot verification of the ZP-Sig envelope path against a live gate.
//!
//! Loads Genesis via `zp_keys::load_sovereign_root` (may prompt for Touch
//! ID), derives the gate signer with `zp_keys::derive_gate_signer_seed`,
//! builds an `Authorization: ZP-Sig …` envelope for
//! `POST /api/v1/gate/tool-call`, and posts to the running gate.
//!
//! Output: prints the derived `kid` (compare against `zp serve`'s
//! "envelope verifier ready: kid=…" log line) and the HTTP response.
//! A 200 means the envelope verified end-to-end; a 401 means it didn't,
//! and the `X-Auth-Reason` header explains why.

use std::env;

use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
use zp_gate_envelope::{
    body_hash_hex, build_header, random_nonce_b64, EnvelopeClaims, SCHEME_VERSION,
};
use zp_receipt::Signable;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // `ZP_GENESIS_PATH`, not `IRONCLAW_ZP_GENESIS_PATH`. The old name was the
    // last live coupling to a specific external tool anywhere in the substrate
    // — an env var that only one caller would ever think to set, naming a
    // project ZeroPoint does not depend on. Renamed 2026-08-06 during the
    // IronClaw purge. Any caller still exporting the old name falls through to
    // the canonical path resolver below, which is the correct default anyway.
    let genesis_path = env::var("ZP_GENESIS_PATH")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            zp_core::paths::genesis_record_path()
                .expect("resolve ~/ZeroPoint/genesis.json")
        });
    let base_url =
        env::var("ZP_BASE_URL").unwrap_or_else(|_| "http://localhost:17010".to_string());

    eprintln!("genesis: {}", genesis_path.display());
    eprintln!("gate   : {}", base_url);

    let genesis = zp_keys::load_sovereign_root(&genesis_path)
        .map_err(|e| anyhow::anyhow!("load_sovereign_root failed: {}", e))?;
    let seed = zp_keys::derive_gate_signer_seed(genesis);
    let signer = SigningKey::from_bytes(&seed);
    let kid = signer.verifying_key().to_bytes();
    println!("derived kid (hex): {}", hex::encode(kid));

    let body = json!({
        "tool_name": "gate-ping",
        "args_hash": body_hash_hex(b"verification probe"),
        "thread_id": null,
        "run_id": null,
        "agent": "gate-ping",
    });
    let body_bytes = serde_json::to_vec(&body)?;

    let claims = EnvelopeClaims {
        v: SCHEME_VERSION,
        method: "POST".to_string(),
        path: "/api/v1/gate/tool-call".to_string(),
        body_hash: body_hash_hex(&body_bytes),
        ts: chrono::Utc::now().timestamp(),
        nonce: random_nonce_b64(),
    };
    let sig = signer.sign(&claims.canonical_hash()).to_bytes();
    let header = build_header(&claims, &kid, &sig);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;
    let resp = client
        .post(format!("{}/api/v1/gate/tool-call", base_url))
        .header(reqwest::header::AUTHORIZATION, header)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body_bytes)
        .send()
        .await?;

    let status = resp.status();
    let reason = resp
        .headers()
        .get("x-auth-reason")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let text = resp.text().await.unwrap_or_default();

    println!("status: {}", status);
    if !reason.is_empty() {
        println!("X-Auth-Reason: {}", reason);
    }
    println!("body  : {}", text);

    if status == reqwest::StatusCode::UNAUTHORIZED {
        anyhow::bail!("envelope rejected: {}", reason);
    }
    Ok(())
}
