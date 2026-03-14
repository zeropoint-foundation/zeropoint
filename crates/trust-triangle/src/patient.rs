//! Patient Assistant — orchestrates cross-domain queries.
//!
//! This module implements the full Trust Triangle scenario:
//! 1. Introduce to clinic (foreign genesis)
//! 2. Query clinic for appointment data
//! 3. Introduce to pharmacy (foreign genesis)
//! 4. Query pharmacy for prescription data
//! 5. Synthesize the answer with full provenance

use zp_introduction::request::IntroductionRequest;
use zp_introduction::response::{IntroductionDecision, IntroductionResponse};
use zp_keys::certificate::CertificateChain;
use zp_receipt::{Receipt, Status};

use crate::display;
use crate::node::NodeContext;
use crate::types::{QueryRequest, QueryResponse};

/// Result of one introduction + query hop.
pub struct HopResult {
    pub peer_name: String,
    pub peer_genesis_fingerprint: String,
    pub introduction_decision: String,
    pub query_response: QueryResponse,
}

/// The full scenario result.
pub struct ScenarioResult {
    pub patient_genesis_fingerprint: String,
    pub intent_receipt: Receipt,
    pub clinic_hop: HopResult,
    pub pharmacy_hop: HopResult,
    pub synthesis_receipt: Receipt,
}

/// Run the full Trust Triangle scenario.
pub async fn run_scenario(
    ctx: &NodeContext,
    clinic_endpoint: &str,
    pharmacy_endpoint: &str,
    patient_id: &str,
) -> anyhow::Result<ScenarioResult> {
    let client = reqwest::Client::new();

    // Step 0: Create an intent receipt (root of the provenance chain)
    let mut intent_receipt = Receipt::intent(&ctx.node_name)
        .status(Status::Success)
        .finalize();
    ctx.signer.sign(&mut intent_receipt);

    display::step_intent(ctx, &intent_receipt);

    // Step 1: Introduce to clinic
    display::step_start("Introducing to MediCare Clinic", clinic_endpoint);

    let (clinic_intro_decision, clinic_chain) =
        introduce_to_peer(ctx, &client, clinic_endpoint).await?;

    display::step_introduction_result(
        "MediCare Clinic",
        &clinic_chain,
        &clinic_intro_decision,
        ctx,
    );

    // Step 2: Query clinic
    display::step_start("Querying appointment data from clinic", "");

    let clinic_response = query_peer(
        ctx,
        &client,
        clinic_endpoint,
        patient_id,
        Some(&intent_receipt.id),
    )
    .await?;

    display::step_query_result("MediCare Clinic", &clinic_response);

    let clinic_genesis_fp = clinic_chain
        .map(|c| {
            let gk = c.genesis_public_key().unwrap_or([0u8; 32]);
            hex::encode(&gk[..8])
        })
        .unwrap_or_else(|| "unknown".into());

    // Step 3: Introduce to pharmacy
    display::step_start("Introducing to QuickRx Pharmacy", pharmacy_endpoint);

    let (pharmacy_intro_decision, pharmacy_chain) =
        introduce_to_peer(ctx, &client, pharmacy_endpoint).await?;

    display::step_introduction_result(
        "QuickRx Pharmacy",
        &pharmacy_chain,
        &pharmacy_intro_decision,
        ctx,
    );

    // Step 4: Query pharmacy
    display::step_start("Querying prescription data from pharmacy", "");

    let pharmacy_response = query_peer(
        ctx,
        &client,
        pharmacy_endpoint,
        patient_id,
        Some(&intent_receipt.id),
    )
    .await?;

    display::step_query_result("QuickRx Pharmacy", &pharmacy_response);

    let pharmacy_genesis_fp = pharmacy_chain
        .map(|c| {
            let gk = c.genesis_public_key().unwrap_or([0u8; 32]);
            hex::encode(&gk[..8])
        })
        .unwrap_or_else(|| "unknown".into());

    // Step 5: Build synthesis receipt
    let mut synthesis_receipt = Receipt::execution(&ctx.node_name)
        .status(Status::Success)
        .parent(&intent_receipt.id)
        .finalize();
    ctx.signer.sign(&mut synthesis_receipt);

    let result = ScenarioResult {
        patient_genesis_fingerprint: ctx.genesis_fingerprint(),
        intent_receipt,
        clinic_hop: HopResult {
            peer_name: "MediCare Clinic".into(),
            peer_genesis_fingerprint: clinic_genesis_fp,
            introduction_decision: clinic_intro_decision,
            query_response: clinic_response,
        },
        pharmacy_hop: HopResult {
            peer_name: "QuickRx Pharmacy".into(),
            peer_genesis_fingerprint: pharmacy_genesis_fp,
            introduction_decision: pharmacy_intro_decision,
            query_response: pharmacy_response,
        },
        synthesis_receipt,
    };

    display::final_report(&result);

    Ok(result)
}

/// Introduce ourselves to a peer node. Returns the decision string and
/// optionally the peer's verified certificate chain.
async fn introduce_to_peer(
    ctx: &NodeContext,
    client: &reqwest::Client,
    endpoint: &str,
) -> anyhow::Result<(String, Option<CertificateChain>)> {
    let request = IntroductionRequest::new(ctx.portable_chain(), Some("prescription query".into()));

    let response: IntroductionResponse = client
        .post(format!("{}/api/v1/introduce", endpoint))
        .json(&request)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    match &response.decision {
        IntroductionDecision::Accepted => {
            // Verify the peer's chain
            if let Some(ref chain_certs) = response.certificate_chain {
                let chain = CertificateChain::verify(chain_certs.clone())
                    .map_err(|e| anyhow::anyhow!("Peer chain invalid: {}", e))?;

                // Store peer as trusted
                let peer_key = chain.leaf().body.public_key.clone();
                ctx.trusted_peers
                    .write()
                    .map_err(|e| anyhow::anyhow!("Lock error: {}", e))?
                    .insert(peer_key, chain.clone());

                Ok(("Accepted".into(), Some(chain)))
            } else {
                Ok(("Accepted (no chain returned)".into(), None))
            }
        }
        IntroductionDecision::PendingReview { summary } => {
            Ok((format!("Pending Review: {}", summary), None))
        }
        IntroductionDecision::Denied { reason } => {
            anyhow::bail!("Introduction denied: {}", reason);
        }
    }
}

/// Query a peer node for data.
async fn query_peer(
    ctx: &NodeContext,
    client: &reqwest::Client,
    endpoint: &str,
    patient_id: &str,
    parent_receipt_id: Option<&str>,
) -> anyhow::Result<QueryResponse> {
    let request = QueryRequest {
        initiator_chain: ctx.portable_chain(),
        query: patient_id.into(),
        parent_receipt_id: parent_receipt_id.map(|s| s.to_string()),
    };

    let response: QueryResponse = client
        .post(format!("{}/api/v1/query", endpoint))
        .json(&request)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    Ok(response)
}
