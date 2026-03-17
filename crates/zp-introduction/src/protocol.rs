//! Introduction protocol logic — chain verification and PolicyContext generation.
//!
//! This module is the bridge between `zp-keys` (mechanism) and `zp-policy` (governance).
//! It verifies incoming certificate chains and produces the `PolicyContext` that the
//! policy engine evaluates. It does NOT make policy decisions itself.

use zp_core::policy::{ActionType, PolicyContext, TrustTier};
use zp_core::{Channel, ConversationId};
use zp_keys::certificate::{CertificateChain, KeyRole};

use crate::error::IntroductionError;
use crate::request::IntroductionRequest;

/// The result of verifying an introduction request.
///
/// Contains the verified chain and a pre-built PolicyContext ready for
/// evaluation by the policy engine.
#[derive(Debug)]
pub struct IntroductionOutcome {
    /// The verified certificate chain from the peer.
    pub verified_chain: CertificateChain,
    /// A PolicyContext suitable for evaluation by the policy engine.
    /// The caller should pass this to `PolicyEngine::evaluate()`.
    pub policy_context: PolicyContext,
    /// The peer's leaf public key (hex-encoded).
    pub peer_public_key: String,
    /// Whether the peer's genesis matches ours.
    pub same_genesis: bool,
}

/// Verify an introduction request and produce a PolicyContext for evaluation.
///
/// This function:
/// 1. Deserializes and validates the certificate chain
/// 2. Optionally checks if the peer's genesis matches our own
/// 3. Builds a `PolicyContext` with `ActionType::PeerIntroduction`
///
/// The caller is responsible for passing the resulting PolicyContext to
/// the policy engine and acting on the decision.
///
/// # Arguments
/// * `request` - The incoming introduction request
/// * `our_genesis_public_key` - Our genesis public key (to check same_genesis)
/// * `our_trust_tier` - Our current trust tier
/// * `our_channel` - The channel this request came in on
pub fn verify_introduction(
    request: &IntroductionRequest,
    our_genesis_public_key: Option<&[u8; 32]>,
    our_trust_tier: TrustTier,
    our_channel: Channel,
) -> Result<IntroductionOutcome, IntroductionError> {
    // Version check
    if request.version != 1 {
        return Err(IntroductionError::InvalidRequest(format!(
            "unsupported protocol version: {}",
            request.version
        )));
    }

    // Verify the certificate chain
    let chain = CertificateChain::verify(request.certificate_chain.clone())?;

    // Extract peer info
    let leaf = chain.leaf();
    let peer_public_key = leaf.body.public_key.clone();
    let peer_role = leaf.body.role;

    // Check genesis match
    let genesis_pub = chain.genesis_public_key()?;
    let genesis_fingerprint = hex::encode(&genesis_pub[..8]);

    let same_genesis = our_genesis_public_key
        .map(|our_key| *our_key == genesis_pub)
        .unwrap_or(false);

    let peer_genesis_fingerprint = genesis_fingerprint.clone();

    // Build the policy context
    let policy_context = PolicyContext {
        action: ActionType::PeerIntroduction {
            peer_address: peer_public_key.clone(),
            peer_role: peer_role.to_string(),
            peer_genesis_fingerprint,
            same_genesis,
        },
        trust_tier: our_trust_tier,
        channel: our_channel,
        conversation_id: ConversationId::new(),
        skill_ids: vec![],
        tool_names: vec![],
        mesh_context: None,
    };

    Ok(IntroductionOutcome {
        verified_chain: chain,
        policy_context,
        peer_public_key,
        same_genesis,
    })
}

/// Build a PolicyContext for a key delegation action.
///
/// Call this before issuing a new certificate to get the policy engine's
/// approval. This makes key delegation a governed action.
///
/// # Arguments
/// * `target_role` - The role being delegated to
/// * `target_subject` - The name of the entity receiving the key
/// * `genesis_public_key` - The genesis key backing this delegation
/// * `trust_tier` - Current trust tier
pub fn build_delegation_context(
    target_role: KeyRole,
    target_subject: &str,
    genesis_public_key: &[u8; 32],
    trust_tier: TrustTier,
) -> PolicyContext {
    let genesis_fingerprint = hex::encode(&genesis_public_key[..8]);

    PolicyContext {
        action: ActionType::KeyDelegation {
            target_role: target_role.to_string(),
            target_subject: target_subject.to_string(),
            genesis_fingerprint,
        },
        trust_tier,
        channel: Channel::Cli,
        conversation_id: ConversationId::new(),
        skill_ids: vec![],
        tool_names: vec![],
        mesh_context: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zp_keys::hierarchy::{AgentKey, GenesisKey, OperatorKey};

    #[test]
    fn test_verify_introduction_same_genesis() {
        let genesis = GenesisKey::generate("test-genesis");
        let operator = OperatorKey::generate("op-1", &genesis, None);
        let agent = AgentKey::generate("agent-1", &operator, None);

        let request = crate::request::IntroductionRequest::new(
            agent.portable_chain(),
            Some("test introduction".into()),
        );

        let outcome = verify_introduction(
            &request,
            Some(&genesis.public_key()),
            TrustTier::Tier1,
            Channel::Cli,
        )
        .unwrap();

        assert!(outcome.same_genesis);
        assert_eq!(outcome.peer_public_key, hex::encode(agent.public_key()));

        // Check the policy context
        match &outcome.policy_context.action {
            ActionType::PeerIntroduction {
                same_genesis,
                peer_role,
                ..
            } => {
                assert!(same_genesis);
                assert_eq!(peer_role, "agent");
            }
            other => panic!("expected PeerIntroduction, got {:?}", other),
        }
    }

    #[test]
    fn test_verify_introduction_different_genesis() {
        let genesis_a = GenesisKey::generate("genesis-a");
        let genesis_b = GenesisKey::generate("genesis-b");
        let operator = OperatorKey::generate("op-b", &genesis_b, None);
        let agent = AgentKey::generate("agent-b", &operator, None);

        let request = crate::request::IntroductionRequest::new(agent.portable_chain(), None);

        // Verify against genesis A — should report different genesis
        let outcome = verify_introduction(
            &request,
            Some(&genesis_a.public_key()),
            TrustTier::Tier2,
            Channel::Cli,
        )
        .unwrap();

        assert!(!outcome.same_genesis);
        match &outcome.policy_context.action {
            ActionType::PeerIntroduction { same_genesis, .. } => {
                assert!(!same_genesis);
            }
            other => panic!("expected PeerIntroduction, got {:?}", other),
        }
    }

    #[test]
    fn test_verify_introduction_invalid_chain() {
        let genesis = GenesisKey::generate("g");
        let operator = OperatorKey::generate("o", &genesis, None);
        let agent = AgentKey::generate("a", &operator, None);

        let mut chain = agent.portable_chain();
        // Tamper: swap operator and agent certificates
        chain.swap(1, 2);

        let request = crate::request::IntroductionRequest::new(chain, None);

        let err = verify_introduction(
            &request,
            Some(&genesis.public_key()),
            TrustTier::Tier0,
            Channel::Cli,
        )
        .unwrap_err();

        assert!(matches!(err, IntroductionError::ChainVerification(_)));
    }

    #[test]
    fn test_build_delegation_context() {
        let genesis = GenesisKey::generate("g");
        let ctx = build_delegation_context(
            KeyRole::Operator,
            "new-operator",
            &genesis.public_key(),
            TrustTier::Tier2,
        );

        match &ctx.action {
            ActionType::KeyDelegation {
                target_role,
                target_subject,
                ..
            } => {
                assert_eq!(target_role, "operator");
                assert_eq!(target_subject, "new-operator");
            }
            other => panic!("expected KeyDelegation, got {:?}", other),
        }
        assert_eq!(ctx.trust_tier, TrustTier::Tier2);
    }

    #[test]
    fn test_request_serialization_roundtrip() {
        let genesis = GenesisKey::generate("g");
        let operator = OperatorKey::generate("o", &genesis, None);
        let agent = AgentKey::generate("a", &operator, None);

        let request =
            crate::request::IntroductionRequest::new(agent.portable_chain(), Some("hello".into()));

        let bytes = request.to_bytes().unwrap();
        let restored = crate::request::IntroductionRequest::from_bytes(&bytes).unwrap();

        assert_eq!(restored.version, 1);
        assert_eq!(restored.certificate_chain.len(), 3);
        assert_eq!(restored.reason.as_deref(), Some("hello"));
        assert_eq!(restored.challenge_nonce, request.challenge_nonce);
    }

    #[test]
    fn test_response_serialization_roundtrip() {
        let response = crate::response::IntroductionResponse::deny("not trusted".into());
        let bytes = response.to_bytes().unwrap();
        let restored = crate::response::IntroductionResponse::from_bytes(&bytes).unwrap();

        assert_eq!(
            restored.decision,
            crate::response::IntroductionDecision::Denied {
                reason: "not trusted".into()
            }
        );
    }
}
