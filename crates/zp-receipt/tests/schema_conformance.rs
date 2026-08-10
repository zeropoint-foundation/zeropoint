//! Conformance: the declared schema must describe the built code.
//!
//! `spec/receipt.schema.json` is a real, versioned JSON-Schema document that
//! describes the receipt wire format. Until 2026-08-08 it was never executed —
//! no JSON-Schema validator existed anywhere in the workspace — and it had
//! drifted until it would have **rejected every receipt the system has ever
//! produced**:
//!
//! - `receipt_type` enumerated 6 values; [`ReceiptType`] had 40. The two types
//!   actually present on the live chain (`canonicalized_claim`,
//!   `observation_claim`) were not among the 6.
//! - `id` matched `^(rcpt|intn|dsgn|appr)-…`, so real ids beginning `cano-`
//!   and `obsv-` failed the pattern.
//! - Both the schema and [`RECEIPT_SCHEMA_VERSION`] still read `1.0.0`, so the
//!   version string asserted sameness across a total divergence. A version that
//!   does not change when the thing changes is worse than no version, because
//!   it actively claims agreement.
//!
//! Validating all 10 receipts on the live chain against the schema gave 10/10
//! failures before the fix and 0/10 after. This file is what stops that from
//! happening again.
//!
//! # What this test is, and what it is not
//!
//! It is a **declared-vs-built** check: does the artifact that claims to
//! describe the code still describe it? That is a mechanical join with no
//! judgement in it, which is exactly why it can be a test.
//!
//! It is *not* a declared-vs-deployed check. Whether a declared receipt type is
//! ever actually emitted is a different question, it needs the chain rather than
//! the crate, and it has a legitimate negative answer — a type may be reserved
//! on purpose. That question does not belong here; a reserved type is a
//! judgement someone has to record, not a fact this file can derive.
//!
//! # Why the list below is safe to hand-maintain
//!
//! `_exhaustiveness_guard` matches every variant with no wildcard arm. Adding a
//! variant to [`ReceiptType`] therefore fails to compile *here*, in the same
//! file as `ALL`, with the compiler naming the missing variant. The list cannot
//! silently fall behind the enum — which is the failure mode this whole file
//! exists to prevent, and it would be embarrassing to reproduce it.

use std::collections::BTreeSet;
use std::path::PathBuf;

use zp_receipt::{ReceiptType, RECEIPT_SCHEMA_VERSION};

/// Every variant of [`ReceiptType`]. Kept honest by `_exhaustiveness_guard`.
const ALL: &[ReceiptType] = &[
    ReceiptType::Intent,
    ReceiptType::Design,
    ReceiptType::Approval,
    ReceiptType::Execution,
    ReceiptType::Payment,
    ReceiptType::Access,
    ReceiptType::ObservationClaim,
    ReceiptType::PolicyClaim,
    ReceiptType::AuthorizationClaim,
    ReceiptType::MemoryPromotionClaim,
    ReceiptType::DelegationClaim,
    ReceiptType::NarrativeSynthesisClaim,
    ReceiptType::RevocationClaim,
    ReceiptType::ReflectionClaim,
    ReceiptType::ConfigurationClaim,
    ReceiptType::CanonicalizedClaim,
    ReceiptType::NodeDelegationAccepted,
    ReceiptType::NodeDelegationGranted,
    ReceiptType::NodeRoleTransition,
    ReceiptType::FleetMembershipGranted,
    ReceiptType::FleetMembershipAccepted,
    ReceiptType::ExternalAnchor,
    ReceiptType::FinancialCapabilityGrant,
    ReceiptType::PortAllocated,
    ReceiptType::PortReleased,
    ReceiptType::PricingRefreshClaim,
    ReceiptType::ArtifactSignedClaim,
    ReceiptType::MemoryIndexed,
    ReceiptType::MemoryRetrievedByAgent,
    ReceiptType::MemoryRevokedFromIndex,
    ReceiptType::ModelPreferenceSelected,
    ReceiptType::ModelPreferenceResolved,
    ReceiptType::ModelRouted,
    ReceiptType::PreferenceLlmPolicySet,
    ReceiptType::InferenceDispatched,
    ReceiptType::InferenceCompleted,
    ReceiptType::InferenceFailed,
    ReceiptType::ModelRegistered,
    ReceiptType::ModelCapabilityUpdated,
    ReceiptType::InferenceRouted,
];

/// Compile-time guard. No wildcard arm: adding a `ReceiptType` variant breaks
/// this match, and the fix is to add it to `ALL` directly above.
#[allow(dead_code)]
fn _exhaustiveness_guard(t: ReceiptType) {
    match t {
        ReceiptType::Intent
        | ReceiptType::Design
        | ReceiptType::Approval
        | ReceiptType::Execution
        | ReceiptType::Payment
        | ReceiptType::Access
        | ReceiptType::ObservationClaim
        | ReceiptType::PolicyClaim
        | ReceiptType::AuthorizationClaim
        | ReceiptType::MemoryPromotionClaim
        | ReceiptType::DelegationClaim
        | ReceiptType::NarrativeSynthesisClaim
        | ReceiptType::RevocationClaim
        | ReceiptType::ReflectionClaim
        | ReceiptType::ConfigurationClaim
        | ReceiptType::CanonicalizedClaim
        | ReceiptType::NodeDelegationAccepted
        | ReceiptType::NodeDelegationGranted
        | ReceiptType::NodeRoleTransition
        | ReceiptType::FleetMembershipGranted
        | ReceiptType::FleetMembershipAccepted
        | ReceiptType::ExternalAnchor
        | ReceiptType::FinancialCapabilityGrant
        | ReceiptType::PortAllocated
        | ReceiptType::PortReleased
        | ReceiptType::PricingRefreshClaim
        | ReceiptType::ArtifactSignedClaim
        | ReceiptType::MemoryIndexed
        | ReceiptType::MemoryRetrievedByAgent
        | ReceiptType::MemoryRevokedFromIndex
        | ReceiptType::ModelPreferenceSelected
        | ReceiptType::ModelPreferenceResolved
        | ReceiptType::ModelRouted
        | ReceiptType::PreferenceLlmPolicySet
        | ReceiptType::InferenceDispatched
        | ReceiptType::InferenceCompleted
        | ReceiptType::InferenceFailed
        | ReceiptType::ModelRegistered
        | ReceiptType::ModelCapabilityUpdated
        | ReceiptType::InferenceRouted => {}
    }
}

fn schema_path() -> PathBuf {
    // crates/zp-receipt -> repo root -> spec/
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../spec/receipt.schema.json")
}

fn schema() -> serde_json::Value {
    let p = schema_path();
    let raw = std::fs::read_to_string(&p).unwrap_or_else(|e| {
        panic!(
            "cannot read the declared schema at {}: {e}.\n\
             This test exists because that file is the substrate's public \
             description of the receipt wire format. If it has moved, this test \
             must move with it — do not delete the check.",
            p.display()
        )
    });
    serde_json::from_str(&raw).expect("spec/receipt.schema.json is not valid JSON")
}

/// The serde wire name of a variant — the thing that actually appears in the
/// `receipt_type` field on the chain. Derived, never spelled out, so a
/// `rename_all` change cannot slip past this test.
fn wire_name(t: &ReceiptType) -> String {
    match serde_json::to_value(t).expect("ReceiptType must serialize") {
        serde_json::Value::String(s) => s,
        other => panic!("ReceiptType must serialize to a JSON string, got {other}"),
    }
}

#[test]
fn schema_receipt_type_enum_matches_the_rust_enum() {
    let s = schema();
    let declared: BTreeSet<String> = s["properties"]["receipt_type"]["enum"]
        .as_array()
        .expect("schema properties.receipt_type.enum must be an array")
        .iter()
        .map(|v| v.as_str().expect("enum entries must be strings").to_string())
        .collect();

    let built: BTreeSet<String> = ALL.iter().map(wire_name).collect();

    let missing_from_schema: Vec<_> = built.difference(&declared).cloned().collect();
    let missing_from_code: Vec<_> = declared.difference(&built).cloned().collect();

    assert!(
        missing_from_schema.is_empty() && missing_from_code.is_empty(),
        "spec/receipt.schema.json has drifted from ReceiptType.\n\
         \n\
         In the code but NOT declared in the schema ({}): {:?}\n\
         Declared in the schema but NOT in the code ({}): {:?}\n\
         \n\
         A receipt whose type is absent from the schema is one the substrate \
         emits but does not admit to emitting. Update the schema's \
         properties.receipt_type.enum to match, and check whether id_prefix() \
         needs the same treatment.",
        missing_from_schema.len(),
        missing_from_schema,
        missing_from_code.len(),
        missing_from_code,
    );
}

#[test]
fn schema_id_pattern_admits_every_id_prefix() {
    let s = schema();
    let pattern = s["properties"]["id"]["pattern"]
        .as_str()
        .expect("schema properties.id.pattern must be a string");

    // Pattern shape is `^(a|b|c)-[a-f0-9]{8,}$`. Parse the alternation rather
    // than pulling in a regex crate: this crate is a protocol primitive and is
    // deliberately thin on dependencies.
    let alternation = pattern
        .split_once("^(")
        .and_then(|(_, rest)| rest.split_once(")-"))
        .map(|(alts, _)| alts)
        .unwrap_or_else(|| {
            panic!(
                "id pattern is no longer of the form ^(a|b|c)-… : {pattern}\n\
                 If the shape changed deliberately, update this parser; do not \
                 weaken the assertion."
            )
        });

    let declared: BTreeSet<&str> = alternation.split('|').collect();
    let built: BTreeSet<&str> = ALL.iter().map(|t| t.id_prefix()).collect();

    let missing: Vec<_> = built.difference(&declared).collect();
    assert!(
        missing.is_empty(),
        "id prefixes emitted by ReceiptType::id_prefix() that the schema's id \
         pattern would reject: {missing:?}\n\
         Pattern: {pattern}\n\
         A receipt that cannot match its own id pattern is unverifiable by any \
         third party using the published spec — which is the entire point of \
         publishing one.",
    );

    // The reverse direction is a warning, not a failure: an unused prefix is
    // harmless, but it is worth noticing rather than accumulating.
    let unused: Vec<_> = declared.difference(&built).collect();
    if !unused.is_empty() {
        eprintln!("note: id pattern declares prefixes no variant emits: {unused:?}");
    }
}

#[test]
fn schema_version_matches_the_crate_constant() {
    let s = schema();
    let declared = s["properties"]["version"]["const"]
        .as_str()
        .expect("schema properties.version.const must be a string");

    assert_eq!(
        declared, RECEIPT_SCHEMA_VERSION,
        "spec/receipt.schema.json declares version {declared} but the crate \
         constant RECEIPT_SCHEMA_VERSION is {RECEIPT_SCHEMA_VERSION}.\n\
         These must move together. Note that agreeing on the string is the \
         weakest possible form of agreement — the two read {declared} while the \
         schema described 6 receipt types and the code had 40. Bump it when the \
         wire format changes, and let the other tests in this file tell you when \
         it has."
    );
}

#[test]
fn schema_is_the_dialect_it_claims_to_be() {
    let s = schema();
    assert_eq!(
        s["$schema"].as_str(),
        Some("https://json-schema.org/draft/2020-12/schema"),
        "the schema's declared dialect changed; any validator wired against it \
         needs to change with it"
    );
    assert!(
        s["$id"].as_str().map_or(false, |v| v.contains("zeropoint")),
        "schema $id should identify this as a ZeroPoint schema"
    );
}
