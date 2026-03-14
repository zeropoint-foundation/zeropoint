//! QuickRx Pharmacy node — holds prescription fulfillment data.

use zp_core::policy::{ActionType, PolicyContext, TrustTier};
use zp_core::{Channel, ConversationId};
use zp_keys::certificate::CertificateChain;
use zp_receipt::{Action, ActionType as ReceiptActionType, Receipt, Status, TrustGrade};

use crate::data::PharmacyDb;
use crate::node::NodeContext;
use crate::types::{QueryRequest, QueryResponse};

/// Handle a data query from a trusted peer.
pub fn handle_query(
    ctx: &NodeContext,
    db: &PharmacyDb,
    request: &QueryRequest,
) -> Result<QueryResponse, String> {
    // Step 1: Verify the requester is a trusted peer
    let chain = CertificateChain::verify(request.initiator_chain.clone())
        .map_err(|e| format!("Invalid chain: {}", e))?;
    let peer_key = chain.leaf().body.public_key.clone();

    if !ctx.is_trusted_peer(&peer_key) {
        return Err("Peer not trusted. Complete introduction first.".into());
    }

    // Step 2: Build a policy context for the data access
    let policy_context = PolicyContext {
        action: ActionType::Read {
            target: "prescriptions".into(),
        },
        trust_tier: TrustTier::Tier1,
        channel: Channel::Api,
        conversation_id: ConversationId::new(),
        skill_ids: vec![],
        tool_names: vec![],
        mesh_context: None,
    };

    // Step 3: Evaluate policy
    let decision = ctx.evaluate_policy(&policy_context);
    let decision_description = format!("{:?}", decision);

    // Step 4: Query mock database (sanitized — only matching patient)
    let (records, redacted_count) = db.query_patient(&request.query);

    let data = if records.is_empty() {
        serde_json::json!({ "error": "No matching prescription records" })
    } else {
        serde_json::to_value(&records).unwrap_or_default()
    };

    // Step 5: Build and sign a receipt
    let mut builder = Receipt::access(&ctx.node_name)
        .status(Status::Success)
        .trust_grade(TrustGrade::B)
        .action(Action {
            action_type: ReceiptActionType::ContentAccess,
            name: Some("prescription_query".into()),
            input_hash: None,
            output_hash: None,
            exit_code: None,
            detail: Some(serde_json::json!({
                "query_patient_id": request.query,
                "records_returned": records.len(),
                "records_redacted": redacted_count,
            })),
        })
        .policy(zp_receipt::Decision::Allow);

    if let Some(ref parent_id) = request.parent_receipt_id {
        builder = builder.parent(parent_id);
    }

    let mut receipt = builder.finalize();
    ctx.signer.sign(&mut receipt);

    Ok(QueryResponse {
        data,
        receipt,
        policy_decision: decision_description,
        redacted_count,
    })
}
