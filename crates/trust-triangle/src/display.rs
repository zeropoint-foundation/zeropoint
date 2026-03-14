//! Formatted terminal output for the Trust Triangle demo.
//!
//! Prints a step-by-step provenance report showing introductions,
//! policy decisions, data exchanges, and cryptographic receipts.

use zp_keys::certificate::CertificateChain;
use zp_receipt::Receipt;

use crate::node::NodeContext;
use crate::patient::ScenarioResult;
use crate::types::QueryResponse;

// ANSI color codes
const CYAN: &str = "\x1b[36m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const RED: &str = "\x1b[31m";
const DIM: &str = "\x1b[2m";
const BOLD: &str = "\x1b[1m";
const NC: &str = "\x1b[0m";

/// Print the header banner.
pub fn banner() {
    eprintln!();
    eprintln!("  {BOLD}╔════════════════════════════════════════════════════════════╗{NC}");
    eprintln!("  {BOLD}║  TRUST TRIANGLE — ZeroPoint Reference Implementation      ║{NC}");
    eprintln!("  {BOLD}║  Cross-Domain Governance Over Plain HTTPS                  ║{NC}");
    eprintln!("  {BOLD}╚════════════════════════════════════════════════════════════╝{NC}");
    eprintln!();
    eprintln!(
        "  {DIM}Scenario: Patient asks \"Why is my prescription late?\"{NC}"
    );
    eprintln!();
}

/// Print the intent receipt (root of provenance chain).
pub fn step_intent(ctx: &NodeContext, receipt: &Receipt) {
    eprintln!("  {BOLD}Step 0: Intent{NC}");
    eprintln!(
        "  {GREEN}✓{NC} Created intent receipt: {DIM}{}{NC}",
        &receipt.id
    );
    eprintln!(
        "    Genesis: {CYAN}{}{NC} (Patient Cloud)",
        ctx.genesis_fingerprint()
    );
    eprintln!();
}

/// Print a step start.
pub fn step_start(description: &str, endpoint: &str) {
    if endpoint.is_empty() {
        eprintln!("  {BOLD}→ {description}{NC}");
    } else {
        eprintln!("  {BOLD}→ {description}{NC} {DIM}({endpoint}){NC}");
    }
}

/// Print the result of an introduction.
pub fn step_introduction_result(
    peer_name: &str,
    peer_chain: &Option<CertificateChain>,
    decision: &str,
    our_ctx: &NodeContext,
) {
    if let Some(chain) = peer_chain {
        let peer_genesis = chain
            .genesis_public_key()
            .map(|k| hex::encode(&k[..8]))
            .unwrap_or_else(|_| "unknown".into());

        let our_genesis = our_ctx.genesis_fingerprint();
        let same = peer_genesis == our_genesis;

        eprintln!("    {GREEN}✓{NC} Introduction: {BOLD}{decision}{NC}");
        eprintln!("    Peer genesis:    {CYAN}{peer_genesis}{NC} ({peer_name})");
        eprintln!("    Our genesis:     {CYAN}{our_genesis}{NC} (Patient Cloud)");
        eprintln!(
            "    Same genesis:    {}{}{NC}",
            if same { GREEN } else { YELLOW },
            if same { "yes" } else { "NO — cross-domain trust" }
        );
        eprintln!(
            "    Chain length:    {} certificates",
            chain.len()
        );
    } else {
        eprintln!("    {YELLOW}⚠{NC} Introduction: {decision}");
    }
    eprintln!();
}

/// Print the result of a data query.
pub fn step_query_result(peer_name: &str, response: &QueryResponse) {
    eprintln!("    {GREEN}✓{NC} Query response from {BOLD}{peer_name}{NC}");

    // Show the data
    if let Some(obj) = response.data.as_object() {
        for (key, val) in obj {
            let display_val = match val {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Null => "—".into(),
                other => other.to_string(),
            };
            eprintln!("      {DIM}{key}:{NC} {display_val}");
        }
    } else if let Some(arr) = response.data.as_array() {
        for item in arr {
            if let Some(obj) = item.as_object() {
                for (key, val) in obj {
                    let display_val = match val {
                        serde_json::Value::String(s) => s.clone(),
                        serde_json::Value::Null => "—".into(),
                        other => other.to_string(),
                    };
                    eprintln!("      {DIM}{key}:{NC} {display_val}");
                }
            }
        }
    }

    eprintln!();
    eprintln!("    {DIM}Policy:{NC} {}", response.policy_decision);
    eprintln!(
        "    {DIM}Sanitized:{NC} {YELLOW}{} records redacted{NC}",
        response.redacted_count
    );

    // Receipt details
    let r = &response.receipt;
    eprintln!("    {DIM}Receipt:{NC} {}", r.id);
    if let Some(ref sig) = r.signature {
        let sig_short = if sig.len() > 24 { &sig[..24] } else { sig };
        eprintln!("    {DIM}Signature:{NC} {sig_short}…");
    }
    if let Some(ref pk) = r.signer_public_key {
        let pk_short = if pk.len() > 16 { &pk[..16] } else { pk };
        eprintln!("    {DIM}Signer PK:{NC} {pk_short}…");
    }
    eprintln!("    {DIM}Hash:{NC} {}", &r.content_hash[..32.min(r.content_hash.len())]);
    eprintln!();
}

/// Print the final synthesis report with full provenance.
pub fn final_report(result: &ScenarioResult) {
    eprintln!("  {BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{NC}");
    eprintln!("  {BOLD}SYNTHESIS{NC}");
    eprintln!("  {BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{NC}");
    eprintln!();

    // Extract the narrative from the data
    let clinic_data = &result.clinic_hop.query_response.data;
    let pharmacy_data = &result.pharmacy_hop.query_response.data;

    let appointment_status = clinic_data
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let scheduled_date = clinic_data
        .get("scheduled_date")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let previous_date = clinic_data
        .get("previous_date")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    // Pharmacy data might be an array
    let (medication, filled_date, rx_status) = if let Some(arr) = pharmacy_data.as_array() {
        let first = arr.first();
        (
            first
                .and_then(|v| v.get("medication"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown"),
            first
                .and_then(|v| v.get("filled_date"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown"),
            first
                .and_then(|v| v.get("status"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown"),
        )
    } else {
        (
            pharmacy_data
                .get("medication")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown"),
            pharmacy_data
                .get("filled_date")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown"),
            pharmacy_data
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown"),
        )
    };

    eprintln!(
        "  Your prescription ({CYAN}{medication}{NC}) was filled on {BOLD}{filled_date}{NC}"
    );
    eprintln!("  and is {GREEN}{rx_status}{NC}.");
    eprintln!();
    eprintln!(
        "  Your follow-up appointment was {YELLOW}{appointment_status}{NC}"
    );
    eprintln!("  from {previous_date} to {BOLD}{scheduled_date}{NC}, which delayed");
    eprintln!("  the pickup notification.");
    eprintln!();

    // Provenance chain
    eprintln!("  {BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{NC}");
    eprintln!("  {BOLD}CRYPTOGRAPHIC PROVENANCE{NC}");
    eprintln!("  {BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{NC}");
    eprintln!();

    // Trust domains
    eprintln!("  {BOLD}Trust Domains (3 independent genesis keys):{NC}");
    eprintln!(
        "    {CYAN}●{NC} Patient Cloud         {DIM}{}{NC}",
        result.patient_genesis_fingerprint
    );
    eprintln!(
        "    {CYAN}●{NC} MediCare Clinic       {DIM}{}{NC}",
        result.clinic_hop.peer_genesis_fingerprint
    );
    eprintln!(
        "    {CYAN}●{NC} QuickRx Pharmacy      {DIM}{}{NC}",
        result.pharmacy_hop.peer_genesis_fingerprint
    );
    eprintln!();

    // Receipt chain
    eprintln!("  {BOLD}Receipt Chain:{NC}");
    print_receipt_entry(1, "Intent", &result.intent_receipt);
    print_receipt_entry(
        2,
        "Clinic Access",
        &result.clinic_hop.query_response.receipt,
    );
    print_receipt_entry(
        3,
        "Pharmacy Access",
        &result.pharmacy_hop.query_response.receipt,
    );
    print_receipt_entry(4, "Synthesis", &result.synthesis_receipt);
    eprintln!();

    // Verification
    eprintln!("  {BOLD}Verification:{NC}");
    let labels = ["Intent", "Clinic Access", "Pharmacy Access", "Synthesis"];
    let receipts = [
        &result.intent_receipt,
        &result.clinic_hop.query_response.receipt,
        &result.pharmacy_hop.query_response.receipt,
        &result.synthesis_receipt,
    ];

    let mut all_verified = true;
    for (label, receipt) in labels.iter().zip(receipts.iter()) {
        let (ok, detail) = verify_receipt(receipt);
        if ok {
            eprintln!("  {GREEN}✓{NC} {label}: hash valid, signature present");
        } else {
            eprintln!("  {RED}✗{NC} {label}: {detail}");
            all_verified = false;
        }
    }

    if all_verified {
        eprintln!();
        eprintln!("  {GREEN}✓ All 4 receipts verified{NC}");
    }

    eprintln!();
    eprintln!("  {DIM}Every data exchange above is cryptographically signed,{NC}");
    eprintln!("  {DIM}policy-gated, and independently verifiable. No platform{NC}");
    eprintln!("  {DIM}database was consulted. Trust is in the math.{NC}");
    eprintln!();
}

fn print_receipt_entry(num: usize, label: &str, receipt: &Receipt) {
    let hash_short = if receipt.content_hash.len() >= 16 {
        &receipt.content_hash[..16]
    } else {
        &receipt.content_hash
    };
    let sig_status = if receipt.signature.is_some() {
        format!("{GREEN}signed{NC}")
    } else {
        format!("{DIM}unsigned{NC}")
    };
    eprintln!(
        "    {num}. {BOLD}{label}{NC}  {DIM}{}{NC}  [{sig_status}]  hash:{DIM}{hash_short}…{NC}",
        receipt.id
    );
}

fn verify_receipt(receipt: &Receipt) -> (bool, String) {
    if !receipt.verify_hash() {
        return (false, "hash mismatch".into());
    }
    if receipt.signature.is_none() {
        return (false, "missing signature".into());
    }
    (true, "ok".into())
}

/// Print a node startup message.
pub fn node_started(role: &str, node_name: &str, port: u16, genesis_fp: &str) {
    eprintln!();
    eprintln!(
        "  {GREEN}●{NC} {BOLD}{node_name}{NC} ({role}) started on port {CYAN}{port}{NC}"
    );
    eprintln!("    Genesis: {DIM}{genesis_fp}{NC}");
    eprintln!("    Endpoints:");
    eprintln!("      POST /api/v1/introduce");
    eprintln!("      POST /api/v1/query");
    eprintln!("      GET  /health");
    eprintln!();
    eprintln!("  {DIM}Waiting for connections...{NC}");
    eprintln!();
}
