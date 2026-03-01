//! Default Gate Policy — ZeroPoint v2 Tier 0
//!
//! The permissive-by-default policy:
//! - Allow everything except catastrophic actions
//! - Audit everything silently
//! - Block only credential exfiltration, self-modification, and unbounded resource consumption
//!
//! This is the "weightless parachute" — users don't know it's there until they need it.
//! See ARCHITECTURE-V2.md §13.

use serde::{Deserialize, Serialize};

/// Policy input — what the engine sends to this module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyInput {
    pub action_type: String,
    pub target: Option<String>,
    pub skill_id: Option<String>,
    pub trust_tier: u8,
}

/// Policy output — what this module returns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyOutput {
    pub decision: String, // "allow", "block", "warn", "review", "sanitize"
    pub reason: Option<String>,
    pub conditions: Vec<String>,
}

/// Evaluate a request against the default Tier 0 policy.
///
/// This function will be the WASM export in Phase 2.
/// For now it's called directly from zp-policy.
pub fn evaluate(input: &PolicyInput) -> PolicyOutput {
    // Catastrophic action checks
    if is_credential_exfiltration(input) {
        return PolicyOutput {
            decision: "block".to_string(),
            reason: Some("Credential exfiltration detected. This action is blocked by your safety configuration.".to_string()),
            conditions: vec![],
        };
    }

    if is_self_modification(input) {
        return PolicyOutput {
            decision: "block".to_string(),
            reason: Some("Self-modification of safety configuration is not permitted.".to_string()),
            conditions: vec![],
        };
    }

    if is_unbounded_resource(input) {
        return PolicyOutput {
            decision: "warn".to_string(),
            reason: Some("This action may consume significant resources.".to_string()),
            conditions: vec!["user_ack".to_string()],
        };
    }

    // Bulk destructive operations get a warning
    if is_bulk_destructive(input) {
        return PolicyOutput {
            decision: "warn".to_string(),
            reason: Some("This action will modify or delete multiple items.".to_string()),
            conditions: vec!["user_ack".to_string()],
        };
    }

    // Everything else: allow.
    PolicyOutput {
        decision: "allow".to_string(),
        reason: None,
        conditions: vec![],
    }
}

fn is_credential_exfiltration(input: &PolicyInput) -> bool {
    let target = input.target.as_deref().unwrap_or("");
    let action = input.action_type.as_str();

    // Sending credentials to external endpoints
    if action == "api_call" && target.contains("credential") {
        return true;
    }

    // Writing credentials to publicly accessible locations
    if action == "file_write" {
        let lower = target.to_lowercase();
        if lower.contains("/tmp/")
            && (lower.contains("key")
                || lower.contains("secret")
                || lower.contains("token")
                || lower.contains("credential"))
        {
            return true;
        }
    }

    false
}

fn is_self_modification(input: &PolicyInput) -> bool {
    let target = input.target.as_deref().unwrap_or("").to_lowercase();

    // Modifying policy modules, safety config, or operator prompts
    target.contains("policy") && input.action_type == "file_write"
        || target.contains("safety_config") && input.action_type == "config_change"
        || target.contains("operator_prompt") && input.action_type == "config_change"
}

fn is_unbounded_resource(input: &PolicyInput) -> bool {
    let target = input.target.as_deref().unwrap_or("");

    // Recursive operations without bounds
    if input.action_type == "execute" && (target.contains("while true") || target.contains("fork"))
    {
        return true;
    }

    false
}

fn is_bulk_destructive(input: &PolicyInput) -> bool {
    let target = input.target.as_deref().unwrap_or("");

    // File deletion with glob patterns or recursive paths
    if input.action_type == "file_delete" {
        return target.contains('*') || target.contains("**") || target.ends_with('/');
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normal_chat_allowed() {
        let input = PolicyInput {
            action_type: "chat".to_string(),
            target: None,
            skill_id: None,
            trust_tier: 0,
        };
        let output = evaluate(&input);
        assert_eq!(output.decision, "allow");
    }

    #[test]
    fn test_file_read_allowed() {
        let input = PolicyInput {
            action_type: "file_read".to_string(),
            target: Some("/home/user/document.txt".to_string()),
            skill_id: None,
            trust_tier: 0,
        };
        let output = evaluate(&input);
        assert_eq!(output.decision, "allow");
    }

    #[test]
    fn test_credential_exfiltration_blocked() {
        let input = PolicyInput {
            action_type: "file_write".to_string(),
            target: Some("/tmp/stolen_secret_key.txt".to_string()),
            skill_id: None,
            trust_tier: 0,
        };
        let output = evaluate(&input);
        assert_eq!(output.decision, "block");
    }

    #[test]
    fn test_self_modification_blocked() {
        let input = PolicyInput {
            action_type: "config_change".to_string(),
            target: Some("safety_config".to_string()),
            skill_id: None,
            trust_tier: 0,
        };
        let output = evaluate(&input);
        assert_eq!(output.decision, "block");
    }

    #[test]
    fn test_bulk_delete_warns() {
        let input = PolicyInput {
            action_type: "file_delete".to_string(),
            target: Some("/home/user/projects/**".to_string()),
            skill_id: None,
            trust_tier: 0,
        };
        let output = evaluate(&input);
        assert_eq!(output.decision, "warn");
    }

    #[test]
    fn test_fork_bomb_warns() {
        let input = PolicyInput {
            action_type: "execute".to_string(),
            target: Some(":(){ :|:& };: fork".to_string()),
            skill_id: None,
            trust_tier: 0,
        };
        let output = evaluate(&input);
        assert_eq!(output.decision, "warn");
    }
}
