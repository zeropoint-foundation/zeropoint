//! Composition rule stability tests.
//! The closer-drift class must be structurally impossible.

use chrono::Utc;
use zp_artifacts::kinds::chain_narration::{
    build_composition, build_middle_prompt, format_closer, format_opener, NormalizedReceipt,
};

fn receipt(id: &str, claim: &str) -> NormalizedReceipt {
    NormalizedReceipt {
        id: id.to_string(),
        claim: claim.to_string(),
        created_at: Utc::now(),
    }
}

#[test]
fn opener_is_pure_same_input_same_output() {
    let r = receipt("r1", "operator onboarded");
    let a = format_opener(&r);
    let b = format_opener(&r);
    assert_eq!(a, b, "format_opener must be deterministic");
}

#[test]
fn closer_is_pure_same_input_same_output() {
    let r = receipt("r5", "session ended");
    let a = format_closer(&r);
    let b = format_closer(&r);
    assert_eq!(a, b, "format_closer must be deterministic");
}

#[test]
fn middle_prompt_never_contains_last_receipt_claim() {
    let receipts = [
        receipt("r1", "first event"),
        receipt("r2", "middle event A"),
        receipt("r3", "middle event B"),
        receipt("r4", "LAST EVENT SENTINEL"),
    ];
    let middle = &receipts[1..receipts.len() - 1];
    let prompt = build_middle_prompt(middle, "You are the apex observer.");
    assert!(
        !prompt.contains("LAST EVENT SENTINEL"),
        "middle prompt must never contain the last receipt: {prompt}"
    );
}

#[test]
fn middle_prompt_empty_when_no_middle() {
    let prompt = build_middle_prompt(&[], "anchor");
    assert!(prompt.is_empty(), "empty middle must produce empty prompt");
}

#[test]
fn single_receipt_produces_valid_composition() {
    let receipts = vec![receipt("r1", "only receipt")];
    let comp = build_composition(&receipts, "anchor", "openai", "gpt-4o");
    assert!(comp.is_some());
    let comp = comp.unwrap();
    assert!(!comp.opener.is_empty());
    assert!(!comp.has_middle);
}

#[test]
fn two_receipts_no_middle() {
    let receipts = vec![receipt("r1", "first"), receipt("r2", "last")];
    let comp = build_composition(&receipts, "anchor", "openai", "gpt-4o").unwrap();
    assert!(!comp.has_middle);
    assert!(comp.middle_prompt.is_empty());
}

#[test]
fn three_receipts_has_middle() {
    let receipts = vec![
        receipt("r1", "first"),
        receipt("r2", "middle"),
        receipt("r3", "last"),
    ];
    let comp = build_composition(&receipts, "anchor", "openai", "gpt-4o").unwrap();
    assert!(comp.has_middle);
    assert!(!comp.middle_prompt.is_empty());
    assert!(comp.middle_prompt.contains("middle"));
    assert!(!comp.middle_prompt.contains("last"));
}

#[test]
fn composition_artifact_id_is_deterministic() {
    let receipts = vec![
        receipt("r1", "first"),
        receipt("r2", "middle"),
        receipt("r3", "last"),
    ];
    let c1 = build_composition(&receipts, "anchor", "openai", "gpt-4o").unwrap();
    let c2 = build_composition(&receipts, "anchor", "openai", "gpt-4o").unwrap();
    let id1 = zp_artifacts::compute_artifact_id(&c1.source_manifest, &c1.render_config);
    let id2 = zp_artifacts::compute_artifact_id(&c2.source_manifest, &c2.render_config);
    assert_eq!(id1, id2, "same inputs must produce same artifact_id");
}

#[test]
fn different_receipts_different_artifact_id() {
    let r1 = vec![receipt("r1", "event A"), receipt("r2", "event B")];
    let r2 = vec![receipt("r1", "event A"), receipt("r3", "event C")];
    let c1 = build_composition(&r1, "anchor", "openai", "gpt-4o").unwrap();
    let c2 = build_composition(&r2, "anchor", "openai", "gpt-4o").unwrap();
    let id1 = zp_artifacts::compute_artifact_id(&c1.source_manifest, &c1.render_config);
    let id2 = zp_artifacts::compute_artifact_id(&c2.source_manifest, &c2.render_config);
    assert_ne!(id1, id2);
}
