//! Ergonomic builder for constructing receipts.

use crate::types::*;
use chrono::Utc;
use std::collections::HashMap;
use uuid::Uuid;

/// Builder for constructing a Receipt step by step.
pub struct ReceiptBuilder {
    receipt_type: ReceiptType,
    executor_id: String,
    parent_receipt_id: Option<String>,
    status: Status,
    trust_grade: TrustGrade,
    executor_type: Option<ExecutorType>,
    runtime: Option<String>,
    platform: Option<String>,
    framework: Option<String>,
    action: Option<Action>,
    timing: Option<Timing>,
    resources: Option<Resources>,
    outputs: Vec<OutputArtifact>,
    io_hashes: Option<IoHashes>,
    policy: Option<PolicyDecision>,
    error: Option<ErrorDetail>,
    redactions: Vec<Redaction>,
    chain: Option<ChainMetadata>,
    extensions: HashMap<String, serde_json::Value>,
    expires_at: Option<chrono::DateTime<Utc>>,
    claim_metadata: Option<ClaimMetadata>,
    claim_semantics: ClaimSemantics,
    supersedes: Vec<String>,
    revokes: Vec<String>,
    #[cfg(feature = "signing")]
    #[allow(dead_code)] // Placeholder for future auto-signing on finalize()
    signer: Option<&'static crate::Signer>,
}

impl ReceiptBuilder {
    /// Create a new builder for the given receipt type and executor.
    pub fn new(receipt_type: ReceiptType, executor_id: &str) -> Self {
        Self {
            receipt_type,
            executor_id: executor_id.to_string(),
            parent_receipt_id: None,
            status: Status::Pending,
            trust_grade: TrustGrade::D,
            executor_type: None,
            runtime: None,
            platform: None,
            framework: None,
            action: None,
            timing: None,
            resources: None,
            outputs: Vec::new(),
            io_hashes: None,
            policy: None,
            error: None,
            redactions: Vec::new(),
            chain: None,
            extensions: HashMap::new(),
            expires_at: None,
            claim_metadata: None,
            claim_semantics: ClaimSemantics::default(),
            supersedes: Vec::new(),
            revokes: Vec::new(),
            #[cfg(feature = "signing")]
            signer: None,
        }
    }

    /// Set the parent receipt for chain linkage.
    pub fn parent(mut self, parent_id: &str) -> Self {
        self.parent_receipt_id = Some(parent_id.to_string());
        self
    }

    /// Set the status.
    pub fn status(mut self, status: Status) -> Self {
        self.status = status;
        self
    }

    /// Set the trust grade.
    pub fn trust_grade(mut self, grade: TrustGrade) -> Self {
        self.trust_grade = grade;
        self
    }

    /// Set executor details.
    pub fn executor_type(mut self, et: ExecutorType) -> Self {
        self.executor_type = Some(et);
        self
    }

    pub fn runtime(mut self, rt: &str) -> Self {
        self.runtime = Some(rt.to_string());
        self
    }

    pub fn platform(mut self, p: &str) -> Self {
        self.platform = Some(p.to_string());
        self
    }

    pub fn framework(mut self, f: &str) -> Self {
        self.framework = Some(f.to_string());
        self
    }

    /// Set the action.
    pub fn action(mut self, action: Action) -> Self {
        self.action = Some(action);
        self
    }

    /// Set timing from start/end.
    pub fn timing(
        mut self,
        started_at: chrono::DateTime<Utc>,
        completed_at: chrono::DateTime<Utc>,
    ) -> Self {
        let duration_ms = (completed_at - started_at).num_milliseconds().max(0) as u64;
        self.timing = Some(Timing {
            started_at,
            completed_at,
            duration_ms,
            queued_ms: None,
        });
        self
    }

    /// Set timing with explicit duration.
    pub fn duration_ms(mut self, started_at: chrono::DateTime<Utc>, duration_ms: u64) -> Self {
        let completed_at = started_at + chrono::Duration::milliseconds(duration_ms as i64);
        self.timing = Some(Timing {
            started_at,
            completed_at,
            duration_ms,
            queued_ms: None,
        });
        self
    }

    /// Set resource usage.
    pub fn resources(mut self, resources: Resources) -> Self {
        self.resources = Some(resources);
        self
    }

    /// Add an output artifact.
    pub fn output(mut self, path: &str, hash: &str, size_bytes: u64) -> Self {
        self.outputs.push(OutputArtifact {
            path: path.to_string(),
            hash: hash.to_string(),
            size_bytes,
            mime_type: None,
        });
        self
    }

    /// Set I/O hashes.
    pub fn io_hashes(mut self, io: IoHashes) -> Self {
        self.io_hashes = Some(io);
        self
    }

    /// Set policy decision.
    pub fn policy(mut self, decision: Decision) -> Self {
        self.policy = Some(PolicyDecision {
            decision,
            policy_id: None,
            trust_tier: None,
            rationale: None,
        });
        self
    }

    /// Set policy decision with full details.
    pub fn policy_full(mut self, pd: PolicyDecision) -> Self {
        self.policy = Some(pd);
        self
    }

    /// Set error details.
    pub fn error(mut self, code: &str, message: &str) -> Self {
        self.error = Some(ErrorDetail {
            code: code.to_string(),
            message: message.to_string(),
            recoverable: false,
        });
        self
    }

    /// Add a redaction.
    pub fn redaction(mut self, target: &str, reason: &str, redaction_type: RedactionType) -> Self {
        self.redactions.push(Redaction {
            redaction_type: Some(redaction_type),
            target: target.to_string(),
            reason: reason.to_string(),
            original_hash: None,
        });
        self
    }

    /// Set chain metadata.
    pub fn chain(mut self, prev_hash: &str, sequence: u64, chain_id: &str) -> Self {
        self.chain = Some(ChainMetadata {
            prev_hash: Some(prev_hash.to_string()),
            sequence: Some(sequence),
            chain_id: Some(chain_id.to_string()),
        });
        self
    }

    /// Add a vendor extension.
    pub fn extension(mut self, key: &str, value: serde_json::Value) -> Self {
        self.extensions.insert(key.to_string(), value);
        self
    }

    /// Set an explicit expiration time.
    pub fn expires_at(mut self, expires: chrono::DateTime<Utc>) -> Self {
        self.expires_at = Some(expires);
        self
    }

    /// Set expiration as a duration from now.
    pub fn expires_in(mut self, duration: chrono::Duration) -> Self {
        self.expires_at = Some(Utc::now() + duration);
        self
    }

    /// Set the epistemic semantics of the signature.
    /// Defaults to AuthorshipProof. Use TruthAssertion for memory promotion claims.
    pub fn claim_semantics(mut self, semantics: ClaimSemantics) -> Self {
        self.claim_semantics = semantics;
        self
    }

    /// Set type-specific claim metadata.
    pub fn claim_metadata(mut self, metadata: ClaimMetadata) -> Self {
        self.claim_metadata = Some(metadata);
        self
    }

    /// Declare that this receipt supersedes a prior receipt.
    /// The prior receipt's claim is replaced by this one.
    pub fn supersedes(mut self, receipt_id: &str) -> Self {
        self.supersedes.push(receipt_id.to_string());
        self
    }

    /// Declare that this receipt supersedes multiple prior receipts.
    pub fn supersedes_all(mut self, receipt_ids: &[&str]) -> Self {
        self.supersedes.extend(receipt_ids.iter().map(|id| id.to_string()));
        self
    }

    /// Declare that this receipt revokes a prior receipt.
    /// The revoked receipt and its downstream dependents are void.
    pub fn revokes_receipt(mut self, receipt_id: &str) -> Self {
        self.revokes.push(receipt_id.to_string());
        self
    }

    /// Declare that this receipt revokes multiple prior receipts.
    pub fn revokes_all(mut self, receipt_ids: &[&str]) -> Self {
        self.revokes.extend(receipt_ids.iter().map(|id| id.to_string()));
        self
    }

    /// Finalize the receipt with full type validation.
    ///
    /// Returns `Err(ValidationError)` if the receipt violates per-type
    /// constraints (wrong semantics, missing metadata, TTL exceeded).
    /// Prefer this over `finalize()` for new code paths.
    pub fn try_finalize(self) -> Result<Receipt, crate::validation::ValidationError> {
        let created_at = chrono::Utc::now();

        // Compute expires_at early so we can validate it
        let expires_at = self
            .expires_at
            .or_else(|| self.receipt_type.default_expiry().map(|d| created_at + d));

        // Run per-type validation before constructing the receipt
        crate::validation::validate_receipt_type(
            self.receipt_type,
            self.claim_semantics,
            self.claim_metadata.as_ref(),
            expires_at,
            created_at,
        )?;

        Ok(self.finalize_inner(created_at, expires_at))
    }

    /// Finalize the receipt: generate ID, compute content hash.
    ///
    /// Logs a warning if per-type validation fails but still produces
    /// the receipt for backward compatibility. New code should prefer
    /// `try_finalize()`.
    pub fn finalize(self) -> Receipt {
        let created_at = Utc::now();

        // Apply default expiry if no explicit one was set
        let expires_at = self
            .expires_at
            .or_else(|| self.receipt_type.default_expiry().map(|d| created_at + d));

        // Run per-type validation; warn but don't fail for backward compat
        if let Err(e) = crate::validation::validate_receipt_type(
            self.receipt_type,
            self.claim_semantics,
            self.claim_metadata.as_ref(),
            expires_at,
            created_at,
        ) {
            eprintln!("[zp-receipt] validation warning: {}", e);
        }

        self.finalize_inner(created_at, expires_at)
    }

    /// Shared receipt construction — called by both `finalize()` and `try_finalize()`.
    fn finalize_inner(
        self,
        created_at: chrono::DateTime<Utc>,
        expires_at: Option<chrono::DateTime<Utc>>,
    ) -> Receipt {
        let id = generate_receipt_id(self.receipt_type);

        let executor = Some(Executor {
            id: self.executor_id,
            executor_type: self.executor_type,
            runtime: self.runtime,
            platform: self.platform,
            framework: self.framework,
        });

        let outputs = if self.outputs.is_empty() {
            None
        } else {
            Some(self.outputs)
        };
        let redactions = if self.redactions.is_empty() {
            None
        } else {
            Some(self.redactions)
        };
        let extensions = if self.extensions.is_empty() {
            None
        } else {
            Some(self.extensions)
        };

        let mut receipt = Receipt {
            id,
            version: RECEIPT_SCHEMA_VERSION.to_string(),
            receipt_type: self.receipt_type,
            parent_receipt_id: self.parent_receipt_id,
            status: self.status,
            content_hash: String::new(), // Computed below
            signature: None,
            signer_public_key: None,
            signatures: Vec::new(),
            trust_grade: self.trust_grade,
            created_at,
            executor,
            action: self.action,
            timing: self.timing,
            resources: self.resources,
            outputs,
            io_hashes: self.io_hashes,
            policy: self.policy,
            error: self.error,
            redactions,
            chain: self.chain,
            extensions,
            expires_at,
            claim_metadata: self.claim_metadata,
            claim_semantics: self.claim_semantics,
            supersedes: self.supersedes,
            revokes: self.revokes,
            superseded_by: None,
            revoked_at: None,
        };

        receipt.content_hash = crate::canonical_hash(&receipt);
        receipt
    }
}

/// Generate a receipt ID with the appropriate prefix.
fn generate_receipt_id(receipt_type: ReceiptType) -> String {
    let uuid = Uuid::now_v7();
    let hex = format!("{:x}", uuid.as_u128());
    // Take the last 12 hex chars for readability
    let suffix = &hex[hex.len().saturating_sub(12)..];
    format!("{}-{}", receipt_type.id_prefix(), suffix)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Action, ActionType};

    #[test]
    fn test_builder_minimal() {
        let receipt = Receipt::execution("test-executor")
            .status(Status::Success)
            .finalize();

        assert!(receipt.id.starts_with("rcpt-"));
        assert_eq!(receipt.version, "1.0.0");
        assert_eq!(receipt.receipt_type, ReceiptType::Execution);
        assert_eq!(receipt.status, Status::Success);
        assert!(!receipt.content_hash.is_empty());
        assert!(receipt.verify_hash());
    }

    #[test]
    fn test_builder_full() {
        let started = Utc::now();
        let completed = started + chrono::Duration::milliseconds(150);

        let receipt = Receipt::execution("agent-007")
            .status(Status::Success)
            .trust_grade(TrustGrade::C)
            .parent("appr-00000001")
            .executor_type(ExecutorType::Agent)
            .runtime("python-3.11")
            .platform("linux-x86_64")
            .framework("claude-code")
            .action(Action::code_execution("python", 0))
            .timing(started, completed)
            .resources(Resources {
                cpu_seconds: Some(0.15),
                memory_peak_bytes: Some(1024 * 1024 * 50),
                ..Default::default()
            })
            .output("/tmp/result.json", "abc123hash", 1024)
            .policy(Decision::Allow)
            .chain("prev-hash-xyz", 42, "chain-001")
            .finalize();

        assert!(receipt.id.starts_with("rcpt-"));
        assert_eq!(receipt.parent_receipt_id, Some("appr-00000001".to_string()));
        assert_eq!(receipt.trust_grade, TrustGrade::C);
        assert!(receipt.executor.as_ref().unwrap().runtime.as_ref().unwrap() == "python-3.11");
        assert!(receipt.action.as_ref().unwrap().action_type == ActionType::CodeExecution);
        assert!(receipt.timing.as_ref().unwrap().duration_ms == 150);
        assert!(receipt.outputs.as_ref().unwrap().len() == 1);
        assert!(receipt.verify_hash());
    }

    #[test]
    fn test_builder_intent_chain_root() {
        let receipt = Receipt::intent("user-session")
            .status(Status::Success)
            .finalize();

        assert!(receipt.id.starts_with("intn-"));
        assert!(receipt.is_root());
    }

    #[test]
    fn test_builder_payment_receipt() {
        let receipt = Receipt::payment("agent-wallet-001")
            .status(Status::Success)
            .action(Action::payment(29.99, "merchant-xyz"))
            .parent("rcpt-00000001")
            .finalize();

        assert!(receipt.id.starts_with("pymt-"));
        assert_eq!(receipt.receipt_type, ReceiptType::Payment);
        let detail = receipt.action.as_ref().unwrap().detail.as_ref().unwrap();
        assert_eq!(detail["amount_usd"], 29.99);
    }

    #[test]
    fn test_builder_configuration_receipt() {
        let meta = crate::types::ClaimMetadata::Configuration {
            tool_id: "my-tool".to_string(),
            parameter: "max_tokens".to_string(),
            value: serde_json::json!(4096),
            source: crate::types::ConfigurationSource::ManifestDefault,
            previous_value: None,
        };

        let receipt = Receipt::configuration("zp-preflight")
            .status(Status::Success)
            .claim_metadata(meta)
            .finalize();

        assert!(receipt.id.starts_with("cfgr-"));
        assert_eq!(receipt.receipt_type, ReceiptType::ConfigurationClaim);
        assert!(receipt.verify_hash());
        assert!(receipt.claim_metadata.is_some());
        if let Some(crate::types::ClaimMetadata::Configuration { tool_id, parameter, value, .. }) =
            &receipt.claim_metadata
        {
            assert_eq!(tool_id, "my-tool");
            assert_eq!(parameter, "max_tokens");
            assert_eq!(*value, serde_json::json!(4096));
        } else {
            panic!("Expected Configuration metadata");
        }
    }

    #[test]
    fn test_builder_configuration_with_previous_value() {
        let meta = crate::types::ClaimMetadata::Configuration {
            tool_id: "my-tool".to_string(),
            parameter: "temperature".to_string(),
            value: serde_json::json!(0.7),
            source: crate::types::ConfigurationSource::OperatorOverride,
            previous_value: Some(serde_json::json!(1.0)),
        };

        let receipt = Receipt::configuration("operator")
            .status(Status::Success)
            .claim_metadata(meta)
            .finalize();

        assert!(receipt.id.starts_with("cfgr-"));
        if let Some(crate::types::ClaimMetadata::Configuration { previous_value, source, .. }) =
            &receipt.claim_metadata
        {
            assert_eq!(*previous_value, Some(serde_json::json!(1.0)));
            assert!(matches!(source, crate::types::ConfigurationSource::OperatorOverride));
        } else {
            panic!("Expected Configuration metadata");
        }
    }
}
