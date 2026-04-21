//! Per-type receipt validation rules (C3-1).
//!
//! Each ReceiptType carries type-specific constraints that are enforced
//! at construction time (in `ReceiptBuilder::finalize()`) and can be
//! checked at verification time.
//!
//! Validation rules cover:
//! - Required ClaimSemantics (epistemic meaning of the signature)
//! - Maximum TTL before the claim expires
//! - Whether human review is required before downstream use
//! - Whether type-specific ClaimMetadata must be present
//! - ClaimMetadata variant must match the ReceiptType

use crate::types::{ClaimMetadata, ClaimSemantics, ReceiptType};
use std::fmt;

/// Validation errors from per-type receipt rules.
#[derive(Debug, Clone)]
pub enum ValidationError {
    /// The ClaimSemantics don't meet the minimum required for this type.
    SemanticsRequired {
        receipt_type: ReceiptType,
        required: ClaimSemantics,
        actual: ClaimSemantics,
    },
    /// ClaimMetadata is required but missing for this claim type.
    MissingClaimMetadata(ReceiptType),
    /// ClaimMetadata variant doesn't match the ReceiptType.
    MetadataMismatch {
        receipt_type: ReceiptType,
        metadata_variant: &'static str,
    },
    /// The explicit expiry exceeds the maximum TTL for this type.
    ExpiryExceedsMaxTtl {
        receipt_type: ReceiptType,
        max_hours: u64,
        actual_hours: u64,
    },
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationError::SemanticsRequired {
                receipt_type,
                required,
                actual,
            } => write!(
                f,
                "{} requires {:?} semantics, got {:?}",
                receipt_type, required, actual
            ),
            ValidationError::MissingClaimMetadata(rt) => {
                write!(f, "{} requires type-specific ClaimMetadata", rt)
            }
            ValidationError::MetadataMismatch {
                receipt_type,
                metadata_variant,
            } => write!(
                f,
                "{} received mismatched ClaimMetadata variant: {}",
                receipt_type, metadata_variant
            ),
            ValidationError::ExpiryExceedsMaxTtl {
                receipt_type,
                max_hours,
                actual_hours,
            } => write!(
                f,
                "{} max TTL is {}h, but expiry is {}h",
                receipt_type, max_hours, actual_hours
            ),
        }
    }
}

/// Per-type validation rules.
///
/// Each ReceiptType has specific constraints on what semantics,
/// metadata, and TTL are valid.
pub struct TypeRules {
    /// Minimum required ClaimSemantics. The actual semantics must be
    /// at least this strong.
    pub required_semantics: ClaimSemantics,
    /// Maximum TTL in hours. None = no limit.
    pub max_ttl_hours: Option<u64>,
    /// Whether human review is required before this claim can be
    /// used as evidence for memory promotion.
    pub requires_human_review: bool,
    /// Whether type-specific ClaimMetadata must be present.
    pub requires_claim_metadata: bool,
}

/// Get the validation rules for a given ReceiptType.
///
/// Per the v3 design spec:
///
/// | Claim Type              | Max TTL  | Required Semantics     | Human Review    |
/// |-------------------------|----------|------------------------|-----------------|
/// | ObservationClaim        | 24h      | AuthorshipProof        | No              |
/// | PolicyClaim             | None     | IntegrityAttestation   | No              |
/// | AuthorizationClaim      | 8h       | AuthorizationGrant     | No              |
/// | MemoryPromotionClaim    | None     | TruthAssertion         | Stage-dependent |
/// | DelegationClaim         | 720h(30d)| AuthorizationGrant     | Yes             |
/// | NarrativeSynthesisClaim | None     | TruthAssertion         | Yes             |
/// | RevocationClaim         | None     | IntegrityAttestation   | No              |
/// | ReflectionClaim         | 168h(7d) | AuthorshipProof        | No              |
pub fn rules_for(rt: ReceiptType) -> TypeRules {
    match rt {
        // --- Original provenance chain types: minimal constraints ---
        ReceiptType::Intent
        | ReceiptType::Design
        | ReceiptType::Approval
        | ReceiptType::Execution
        | ReceiptType::Payment
        | ReceiptType::Access => TypeRules {
            required_semantics: ClaimSemantics::AuthorshipProof,
            max_ttl_hours: None,
            requires_human_review: false,
            requires_claim_metadata: false,
        },

        // --- Typed claim extensions ---
        ReceiptType::ObservationClaim => TypeRules {
            required_semantics: ClaimSemantics::AuthorshipProof,
            max_ttl_hours: Some(24),
            requires_human_review: false,
            requires_claim_metadata: true,
        },
        ReceiptType::PolicyClaim => TypeRules {
            required_semantics: ClaimSemantics::IntegrityAttestation,
            max_ttl_hours: None,
            requires_human_review: false,
            requires_claim_metadata: true,
        },
        ReceiptType::AuthorizationClaim => TypeRules {
            required_semantics: ClaimSemantics::AuthorizationGrant,
            max_ttl_hours: Some(8),
            requires_human_review: false,
            requires_claim_metadata: true,
        },
        ReceiptType::MemoryPromotionClaim => TypeRules {
            required_semantics: ClaimSemantics::TruthAssertion,
            max_ttl_hours: None,
            requires_human_review: true, // Stage-dependent, default to true
            requires_claim_metadata: true,
        },
        ReceiptType::DelegationClaim => TypeRules {
            required_semantics: ClaimSemantics::AuthorizationGrant,
            max_ttl_hours: Some(720), // 30 days
            requires_human_review: true,
            requires_claim_metadata: true,
        },
        ReceiptType::NarrativeSynthesisClaim => TypeRules {
            required_semantics: ClaimSemantics::TruthAssertion,
            max_ttl_hours: None,
            requires_human_review: true,
            requires_claim_metadata: true,
        },
        ReceiptType::RevocationClaim => TypeRules {
            required_semantics: ClaimSemantics::IntegrityAttestation,
            max_ttl_hours: None,
            requires_human_review: false,
            requires_claim_metadata: true,
        },
        ReceiptType::ReflectionClaim => TypeRules {
            required_semantics: ClaimSemantics::AuthorshipProof,
            max_ttl_hours: Some(168), // 7 days
            requires_human_review: false,
            requires_claim_metadata: true,
        },
        ReceiptType::ConfigurationClaim => TypeRules {
            required_semantics: ClaimSemantics::AuthorshipProof,
            max_ttl_hours: None, // configuration records persist indefinitely
            requires_human_review: false,
            requires_claim_metadata: true,
        },
        ReceiptType::CanonicalizedClaim => TypeRules {
            required_semantics: ClaimSemantics::IntegrityAttestation,
            max_ttl_hours: None, // canonicalization anchors persist forever
            requires_human_review: false,
            requires_claim_metadata: true,
        },
    }
}

/// Semantics strength ordering for comparison.
/// Higher number = stronger assertion.
fn semantics_strength(s: ClaimSemantics) -> u8 {
    match s {
        ClaimSemantics::AuthorshipProof => 1,
        ClaimSemantics::IntegrityAttestation => 2,
        ClaimSemantics::TruthAssertion => 3,
        ClaimSemantics::AuthorizationGrant => 3, // Same level as TruthAssertion
    }
}

/// Check if `actual` semantics meets the `required` minimum.
///
/// AuthorizationGrant and TruthAssertion are treated as equally strong
/// but distinct — AuthorizationGrant satisfies AuthorizationGrant,
/// TruthAssertion satisfies TruthAssertion. Both satisfy
/// IntegrityAttestation and AuthorshipProof.
fn semantics_satisfies(actual: ClaimSemantics, required: ClaimSemantics) -> bool {
    if actual == required {
        return true;
    }
    semantics_strength(actual) >= semantics_strength(required)
}

/// Get the variant name of a ClaimMetadata for error reporting.
fn metadata_variant_name(cm: &ClaimMetadata) -> &'static str {
    match cm {
        ClaimMetadata::Observation { .. } => "Observation",
        ClaimMetadata::Policy { .. } => "Policy",
        ClaimMetadata::Authorization { .. } => "Authorization",
        ClaimMetadata::MemoryPromotion { .. } => "MemoryPromotion",
        ClaimMetadata::Delegation { .. } => "Delegation",
        ClaimMetadata::NarrativeSynthesis { .. } => "NarrativeSynthesis",
        ClaimMetadata::Reflection { .. } => "Reflection",
        ClaimMetadata::Revocation { .. } => "Revocation",
        ClaimMetadata::Configuration { .. } => "Configuration",
        ClaimMetadata::Canonicalization { .. } => "Canonicalization",
    }
}

/// Check that a ClaimMetadata variant matches the ReceiptType.
fn metadata_matches_type(rt: ReceiptType, cm: &ClaimMetadata) -> bool {
    matches!(
        (rt, cm),
        (ReceiptType::ObservationClaim, ClaimMetadata::Observation { .. })
            | (ReceiptType::PolicyClaim, ClaimMetadata::Policy { .. })
            | (ReceiptType::AuthorizationClaim, ClaimMetadata::Authorization { .. })
            | (ReceiptType::MemoryPromotionClaim, ClaimMetadata::MemoryPromotion { .. })
            | (ReceiptType::DelegationClaim, ClaimMetadata::Delegation { .. })
            | (
                ReceiptType::NarrativeSynthesisClaim,
                ClaimMetadata::NarrativeSynthesis { .. }
            )
            | (ReceiptType::RevocationClaim, ClaimMetadata::Revocation { .. })
            | (ReceiptType::ReflectionClaim, ClaimMetadata::Reflection { .. })
            | (ReceiptType::ConfigurationClaim, ClaimMetadata::Configuration { .. })
            | (ReceiptType::CanonicalizedClaim, ClaimMetadata::Canonicalization { .. })
    )
}

/// Validate a receipt's type-specific constraints.
///
/// Called from `ReceiptBuilder::finalize()` to enforce per-type rules
/// at construction time.
///
/// Returns `Ok(())` if all constraints are satisfied, or `Err` with
/// the first validation error found.
pub fn validate_receipt_type(
    receipt_type: ReceiptType,
    claim_semantics: ClaimSemantics,
    claim_metadata: Option<&ClaimMetadata>,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
    created_at: chrono::DateTime<chrono::Utc>,
) -> Result<(), ValidationError> {
    let rules = rules_for(receipt_type);

    // 1. Check semantics meet the minimum required
    if !semantics_satisfies(claim_semantics, rules.required_semantics) {
        return Err(ValidationError::SemanticsRequired {
            receipt_type,
            required: rules.required_semantics,
            actual: claim_semantics,
        });
    }

    // 2. Check claim metadata is present when required
    if rules.requires_claim_metadata {
        match claim_metadata {
            None => return Err(ValidationError::MissingClaimMetadata(receipt_type)),
            Some(cm) => {
                // 3. Check metadata variant matches receipt type
                if !metadata_matches_type(receipt_type, cm) {
                    return Err(ValidationError::MetadataMismatch {
                        receipt_type,
                        metadata_variant: metadata_variant_name(cm),
                    });
                }
            }
        }
    }

    // 4. Check expiry doesn't exceed max TTL (if one is set)
    if let Some(max_hours) = rules.max_ttl_hours {
        if let Some(exp) = expires_at {
            let actual_duration = exp - created_at;
            let actual_hours = actual_duration.num_hours() as u64;
            if actual_hours > max_hours {
                return Err(ValidationError::ExpiryExceedsMaxTtl {
                    receipt_type,
                    max_hours,
                    actual_hours,
                });
            }
        }
        // If no explicit expiry was set, default_expiry() handles it —
        // which is already within the max TTL by construction.
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_provenance_types_always_valid() {
        // Original provenance types have minimal constraints
        for rt in [
            ReceiptType::Intent,
            ReceiptType::Design,
            ReceiptType::Approval,
            ReceiptType::Execution,
        ] {
            assert!(validate_receipt_type(
                rt,
                ClaimSemantics::AuthorshipProof,
                None,
                None,
                Utc::now(),
            )
            .is_ok());
        }
    }

    #[test]
    fn test_observation_requires_metadata() {
        // Without metadata: fails
        assert!(matches!(
            validate_receipt_type(
                ReceiptType::ObservationClaim,
                ClaimSemantics::AuthorshipProof,
                None,
                None,
                Utc::now(),
            ),
            Err(ValidationError::MissingClaimMetadata(_))
        ));

        // With correct metadata: passes
        let meta = ClaimMetadata::Observation {
            observation_type: "test".to_string(),
            observer_id: "obs-1".to_string(),
            confidence: Some(0.9),
            tags: vec![],
        };
        assert!(validate_receipt_type(
            ReceiptType::ObservationClaim,
            ClaimSemantics::AuthorshipProof,
            Some(&meta),
            None,
            Utc::now(),
        )
        .is_ok());
    }

    #[test]
    fn test_policy_requires_integrity_attestation() {
        let meta = ClaimMetadata::Policy {
            rule_id: "rule-1".to_string(),
            principle: Some("safety".to_string()),
            satisfied: true,
            rationale: None,
        };

        // AuthorshipProof is too weak
        assert!(matches!(
            validate_receipt_type(
                ReceiptType::PolicyClaim,
                ClaimSemantics::AuthorshipProof,
                Some(&meta),
                None,
                Utc::now(),
            ),
            Err(ValidationError::SemanticsRequired { .. })
        ));

        // IntegrityAttestation is correct
        assert!(validate_receipt_type(
            ReceiptType::PolicyClaim,
            ClaimSemantics::IntegrityAttestation,
            Some(&meta),
            None,
            Utc::now(),
        )
        .is_ok());
    }

    #[test]
    fn test_authorization_requires_grant_semantics() {
        let meta = ClaimMetadata::Authorization {
            scope: "tool:launch".to_string(),
            grantor_id: "operator".to_string(),
            constraints: Default::default(),
        };

        // AuthorshipProof is too weak
        assert!(matches!(
            validate_receipt_type(
                ReceiptType::AuthorizationClaim,
                ClaimSemantics::AuthorshipProof,
                Some(&meta),
                None,
                Utc::now(),
            ),
            Err(ValidationError::SemanticsRequired { .. })
        ));

        // AuthorizationGrant is correct
        assert!(validate_receipt_type(
            ReceiptType::AuthorizationClaim,
            ClaimSemantics::AuthorizationGrant,
            Some(&meta),
            None,
            Utc::now(),
        )
        .is_ok());
    }

    #[test]
    fn test_memory_promotion_requires_truth_assertion() {
        let meta = ClaimMetadata::MemoryPromotion {
            source_stage: "observed".to_string(),
            target_stage: "interpreted".to_string(),
            promotion_evidence: String::new(),
            reviewer: None,
        };

        assert!(matches!(
            validate_receipt_type(
                ReceiptType::MemoryPromotionClaim,
                ClaimSemantics::AuthorshipProof,
                Some(&meta),
                None,
                Utc::now(),
            ),
            Err(ValidationError::SemanticsRequired { .. })
        ));

        assert!(validate_receipt_type(
            ReceiptType::MemoryPromotionClaim,
            ClaimSemantics::TruthAssertion,
            Some(&meta),
            None,
            Utc::now(),
        )
        .is_ok());
    }

    #[test]
    fn test_metadata_mismatch_rejected() {
        // Observation metadata on a PolicyClaim
        let wrong_meta = ClaimMetadata::Observation {
            observation_type: "test".to_string(),
            observer_id: "obs-1".to_string(),
            confidence: None,
            tags: vec![],
        };

        assert!(matches!(
            validate_receipt_type(
                ReceiptType::PolicyClaim,
                ClaimSemantics::IntegrityAttestation,
                Some(&wrong_meta),
                None,
                Utc::now(),
            ),
            Err(ValidationError::MetadataMismatch { .. })
        ));
    }

    #[test]
    fn test_authorization_max_ttl_enforced() {
        let meta = ClaimMetadata::Authorization {
            scope: "tool:launch".to_string(),
            grantor_id: "operator".to_string(),
            constraints: Default::default(),
        };
        let now = Utc::now();

        // 9 hours exceeds 8-hour max TTL
        let too_long = now + chrono::Duration::hours(9);
        assert!(matches!(
            validate_receipt_type(
                ReceiptType::AuthorizationClaim,
                ClaimSemantics::AuthorizationGrant,
                Some(&meta),
                Some(too_long),
                now,
            ),
            Err(ValidationError::ExpiryExceedsMaxTtl { .. })
        ));

        // 7 hours is within 8-hour max TTL
        let ok_expiry = now + chrono::Duration::hours(7);
        assert!(validate_receipt_type(
            ReceiptType::AuthorizationClaim,
            ClaimSemantics::AuthorizationGrant,
            Some(&meta),
            Some(ok_expiry),
            now,
        )
        .is_ok());
    }

    #[test]
    fn test_revocation_requires_integrity_attestation() {
        let meta = ClaimMetadata::Revocation {
            revoked_receipt_id: "rcpt-abc".to_string(),
            reason: "credential rotated".to_string(),
            revoker_id: "operator".to_string(),
        };

        assert!(validate_receipt_type(
            ReceiptType::RevocationClaim,
            ClaimSemantics::IntegrityAttestation,
            Some(&meta),
            None,
            Utc::now(),
        )
        .is_ok());
    }

    #[test]
    fn test_stronger_semantics_accepted() {
        // TruthAssertion (strength 3) should satisfy IntegrityAttestation (strength 2)
        let meta = ClaimMetadata::Policy {
            rule_id: "r1".to_string(),
            principle: Some("p1".to_string()),
            satisfied: true,
            rationale: None,
        };

        assert!(validate_receipt_type(
            ReceiptType::PolicyClaim,
            ClaimSemantics::TruthAssertion, // Stronger than required IntegrityAttestation
            Some(&meta),
            None,
            Utc::now(),
        )
        .is_ok());
    }

    #[test]
    fn test_configuration_claim_requires_metadata() {
        // Without metadata: fails
        assert!(matches!(
            validate_receipt_type(
                ReceiptType::ConfigurationClaim,
                ClaimSemantics::AuthorshipProof,
                None,
                None,
                Utc::now(),
            ),
            Err(ValidationError::MissingClaimMetadata(_))
        ));

        // With correct metadata: passes
        let meta = ClaimMetadata::Configuration {
            tool_id: "my-tool".to_string(),
            parameter: "max_tokens".to_string(),
            value: serde_json::json!(4096),
            source: crate::types::ConfigurationSource::ManifestDefault,
            previous_value: None,
        };
        assert!(validate_receipt_type(
            ReceiptType::ConfigurationClaim,
            ClaimSemantics::AuthorshipProof,
            Some(&meta),
            None,
            Utc::now(),
        )
        .is_ok());
    }

    #[test]
    fn test_configuration_claim_rules() {
        let rules = rules_for(ReceiptType::ConfigurationClaim);
        assert_eq!(rules.required_semantics, ClaimSemantics::AuthorshipProof);
        assert_eq!(rules.max_ttl_hours, None); // no TTL for configuration
        assert!(!rules.requires_human_review);
        assert!(rules.requires_claim_metadata);
    }

    #[test]
    fn test_configuration_claim_wrong_metadata_rejected() {
        let wrong_meta = ClaimMetadata::Observation {
            observation_type: "test".to_string(),
            observer_id: "obs-1".to_string(),
            confidence: None,
            tags: vec![],
        };
        assert!(matches!(
            validate_receipt_type(
                ReceiptType::ConfigurationClaim,
                ClaimSemantics::AuthorshipProof,
                Some(&wrong_meta),
                None,
                Utc::now(),
            ),
            Err(ValidationError::MetadataMismatch { .. })
        ));
    }

    #[test]
    fn test_rules_for_returns_correct_values() {
        let obs = rules_for(ReceiptType::ObservationClaim);
        assert_eq!(obs.required_semantics, ClaimSemantics::AuthorshipProof);
        assert_eq!(obs.max_ttl_hours, Some(24));
        assert!(!obs.requires_human_review);
        assert!(obs.requires_claim_metadata);

        let del = rules_for(ReceiptType::DelegationClaim);
        assert_eq!(del.required_semantics, ClaimSemantics::AuthorizationGrant);
        assert_eq!(del.max_ttl_hours, Some(720));
        assert!(del.requires_human_review);
        assert!(del.requires_claim_metadata);
    }
}
