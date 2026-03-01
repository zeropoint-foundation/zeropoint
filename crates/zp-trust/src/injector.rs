//! Credential injector for policy-based credential access.
//!
//! Provides controlled access to credentials from the vault based on policies.

use crate::vault::{CredentialVault, VaultError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use tracing::{debug, warn};

/// Errors that can occur during credential injection.
#[derive(Error, Debug)]
pub enum InjectorError {
    /// Policy denied access to the requested credential.
    #[error("Policy denied access: {0}")]
    PolicyDenied(String),

    /// An error occurred in the underlying credential vault.
    #[error("Vault error: {0}")]
    VaultError(#[from] VaultError),

    /// The requested credential was not found.
    #[error("Missing credential: {0}")]
    CredentialMissing(String),

    /// The provided injection context is invalid.
    #[error("Invalid context")]
    InvalidContext,
}

/// Result type for credential injection operations.
pub type InjectorResult<T> = Result<T, InjectorError>;

/// Policy context for credential access control.
///
/// Contains information about the access request that policies can evaluate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyContext {
    /// The originating host or boundary
    pub boundary: String,
    /// Optional environment or deployment context
    pub environment: Option<String>,
    /// Additional metadata for policy evaluation
    pub metadata: HashMap<String, String>,
}

impl PolicyContext {
    /// Create a new policy context.
    pub fn new(boundary: String) -> Self {
        Self {
            boundary,
            environment: None,
            metadata: HashMap::new(),
        }
    }

    /// Set the environment for this context.
    pub fn with_environment(mut self, environment: String) -> Self {
        self.environment = Some(environment);
        self
    }

    /// Add metadata to this context.
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }
}

/// Type for policy check function.
///
/// Takes (skill_id, credential_name, context) and returns Ok(()) if allowed, Err if denied.
pub type PolicyCheckFn = fn(&str, &str, &PolicyContext) -> InjectorResult<()>;

/// Credential injector for controlled credential access.
///
/// Mediates access between skills and the credential vault based on policies.
pub struct CredentialInjector<'a> {
    /// Reference to the credential vault
    vault: &'a CredentialVault,
    /// Policy check function
    policy_check: PolicyCheckFn,
}

impl<'a> CredentialInjector<'a> {
    /// Create a new credential injector.
    ///
    /// # Arguments
    /// * `vault` - Reference to the credential vault
    /// * `policy_check` - Function to check if a skill can access a credential
    pub fn new(vault: &'a CredentialVault, policy_check: PolicyCheckFn) -> Self {
        Self {
            vault,
            policy_check,
        }
    }

    /// Inject credentials for a skill based on policy.
    ///
    /// # Arguments
    /// * `skill_id` - The identifier of the requesting skill
    /// * `credential_refs` - List of credential names to inject
    /// * `context` - Policy context for access control
    ///
    /// # Returns
    /// Ok(HashMap of credential_name -> decrypted_value) if access allowed and all credentials found
    /// Err(InjectorError) if policy denies access or credentials not found
    pub fn inject(
        &self,
        skill_id: &str,
        credential_refs: &[String],
        context: &PolicyContext,
    ) -> InjectorResult<HashMap<String, Vec<u8>>> {
        // Validate context
        if skill_id.is_empty() || context.boundary.is_empty() {
            return Err(InjectorError::InvalidContext);
        }

        let mut credentials = HashMap::new();

        // Process each credential reference
        for credential_name in credential_refs {
            // Check policy first
            if let Err(e) = (self.policy_check)(skill_id, credential_name, context) {
                warn!(
                    skill_id = skill_id,
                    credential = credential_name,
                    boundary = context.boundary,
                    "Policy denied credential access"
                );
                return Err(e);
            }

            // Retrieve from vault
            let credential_value = self.vault.retrieve(credential_name).map_err(|e| {
                warn!(
                    skill_id = skill_id,
                    credential = credential_name,
                    "Failed to retrieve credential from vault: {:?}",
                    e
                );
                InjectorError::CredentialMissing(credential_name.clone())
            })?;

            // Log access (credential name only, never the value)
            debug!(
                skill_id = skill_id,
                credential = credential_name,
                boundary = context.boundary,
                "Credential injected for skill"
            );

            credentials.insert(credential_name.clone(), credential_value);
        }

        Ok(credentials)
    }

    /// Inject a single credential for a skill.
    ///
    /// # Arguments
    /// * `skill_id` - The identifier of the requesting skill
    /// * `credential_ref` - The name of the credential to inject
    /// * `context` - Policy context for access control
    ///
    /// # Returns
    /// Ok(credential_value) if access allowed and credential found
    /// Err(InjectorError) if policy denies access or credential not found
    pub fn inject_single(
        &self,
        skill_id: &str,
        credential_ref: &str,
        context: &PolicyContext,
    ) -> InjectorResult<Vec<u8>> {
        let credentials = self.inject(skill_id, &[credential_ref.to_string()], context)?;
        credentials
            .get(credential_ref)
            .cloned()
            .ok_or_else(|| InjectorError::CredentialMissing(credential_ref.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test policy that allows access to credentials prefixed with "public-"
    fn permissive_policy(
        _skill_id: &str,
        credential_name: &str,
        _context: &PolicyContext,
    ) -> InjectorResult<()> {
        if credential_name.starts_with("public-") {
            Ok(())
        } else {
            Err(InjectorError::PolicyDenied(
                "credential is private".to_string(),
            ))
        }
    }

    // Test policy that denies all access
    fn restrictive_policy(
        _skill_id: &str,
        _credential_name: &str,
        _context: &PolicyContext,
    ) -> InjectorResult<()> {
        Err(InjectorError::PolicyDenied("all access denied".to_string()))
    }

    // Test policy that allows all access
    fn allow_all_policy(
        _skill_id: &str,
        _credential_name: &str,
        _context: &PolicyContext,
    ) -> InjectorResult<()> {
        Ok(())
    }

    #[test]
    fn test_injector_basic_access() {
        let master_key = [0x42u8; 32];
        let mut vault = CredentialVault::new(&master_key);

        vault.store("public-api-key", b"test-api-key").unwrap();

        let injector = CredentialInjector::new(&vault, permissive_policy);
        let context = PolicyContext::new("test-boundary".to_string());

        let result = injector.inject_single("test-skill", "public-api-key", &context);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"test-api-key".to_vec());
    }

    #[test]
    fn test_injector_policy_denied() {
        let master_key = [0x42u8; 32];
        let mut vault = CredentialVault::new(&master_key);

        vault.store("private-key", b"secret-key").unwrap();

        let injector = CredentialInjector::new(&vault, permissive_policy);
        let context = PolicyContext::new("test-boundary".to_string());

        let result = injector.inject_single("test-skill", "private-key", &context);
        assert!(matches!(result, Err(InjectorError::PolicyDenied(_))));
    }

    #[test]
    fn test_injector_credential_not_found() {
        let master_key = [0x42u8; 32];
        let vault = CredentialVault::new(&master_key);

        let injector = CredentialInjector::new(&vault, allow_all_policy);
        let context = PolicyContext::new("test-boundary".to_string());

        let result = injector.inject_single("test-skill", "non-existent", &context);
        assert!(matches!(result, Err(InjectorError::CredentialMissing(_))));
    }

    #[test]
    fn test_injector_multiple_credentials() {
        let master_key = [0x42u8; 32];
        let mut vault = CredentialVault::new(&master_key);

        vault.store("public-key1", b"value1").unwrap();
        vault.store("public-key2", b"value2").unwrap();
        vault.store("public-key3", b"value3").unwrap();

        let injector = CredentialInjector::new(&vault, permissive_policy);
        let context = PolicyContext::new("test-boundary".to_string());

        let cred_refs = vec![
            "public-key1".to_string(),
            "public-key2".to_string(),
            "public-key3".to_string(),
        ];

        let result = injector.inject("test-skill", &cred_refs, &context);
        assert!(result.is_ok());

        let credentials = result.unwrap();
        assert_eq!(credentials.len(), 3);
        assert_eq!(credentials.get("public-key1").unwrap(), &b"value1".to_vec());
        assert_eq!(credentials.get("public-key2").unwrap(), &b"value2".to_vec());
        assert_eq!(credentials.get("public-key3").unwrap(), &b"value3".to_vec());
    }

    #[test]
    fn test_injector_restrictive_policy() {
        let master_key = [0x42u8; 32];
        let mut vault = CredentialVault::new(&master_key);

        vault.store("public-api-key", b"test-api-key").unwrap();

        let injector = CredentialInjector::new(&vault, restrictive_policy);
        let context = PolicyContext::new("test-boundary".to_string());

        let result = injector.inject_single("test-skill", "public-api-key", &context);
        assert!(matches!(result, Err(InjectorError::PolicyDenied(_))));
    }

    #[test]
    fn test_policy_context_builder() {
        let context = PolicyContext::new("boundary1".to_string())
            .with_environment("production".to_string())
            .with_metadata("region".to_string(), "us-east-1".to_string());

        assert_eq!(context.boundary, "boundary1");
        assert_eq!(context.environment, Some("production".to_string()));
        assert_eq!(context.metadata.get("region").unwrap(), "us-east-1");
    }

    #[test]
    fn test_injector_invalid_context() {
        let master_key = [0x42u8; 32];
        let vault = CredentialVault::new(&master_key);

        let injector = CredentialInjector::new(&vault, allow_all_policy);
        let empty_context = PolicyContext::new("".to_string());

        let result = injector.inject_single("test-skill", "cred", &empty_context);
        assert!(matches!(result, Err(InjectorError::InvalidContext)));
    }
}
