//! NodeContext — shared infrastructure for all Trust Triangle nodes.
//!
//! Each node holds its own key hierarchy (genesis → operator → agent),
//! a policy engine, a receipt signer, and a set of trusted peers established
//! via the introduction protocol.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use zp_core::policy::{PolicyContext, PolicyDecision, TrustTier};
use zp_core::Channel;
use zp_introduction::request::IntroductionRequest;
use zp_introduction::response::IntroductionResponse;
use zp_introduction::verify_introduction;
use zp_keys::certificate::{Certificate, CertificateChain};
use zp_keys::hierarchy::{AgentKey, GenesisKey, OperatorKey};
use zp_policy::PolicyEngine;
use zp_receipt::Signer;

/// The shared context for a Trust Triangle node.
pub struct NodeContext {
    /// Human-readable name for this node.
    pub node_name: String,
    /// The genesis key (root of trust for this organization).
    pub genesis: GenesisKey,
    /// The operator key (signed by genesis).
    pub operator: OperatorKey,
    /// The agent key (signed by operator).
    pub agent: AgentKey,
    /// The policy engine for evaluating governance decisions.
    pub engine: PolicyEngine,
    /// Receipt signer derived from the agent's secret key.
    pub signer: Signer,
    /// Trusted peers: maps peer public key (hex) to their verified chain.
    pub trusted_peers: Arc<RwLock<HashMap<String, CertificateChain>>>,
}

impl NodeContext {
    /// Create a new node with a fresh key hierarchy.
    pub fn new(node_name: &str, genesis_subject: &str) -> Self {
        let genesis = GenesisKey::generate(genesis_subject);
        let operator = OperatorKey::generate(
            &format!("{}-operator", node_name),
            &genesis,
            None,
        );
        let agent = AgentKey::generate(
            &format!("{}-agent", node_name),
            &operator,
            None,
        );

        // Create a receipt signer from the agent's secret key
        let signer = Signer::from_secret(&agent.secret_key());

        let engine = PolicyEngine::new();

        Self {
            node_name: node_name.to_string(),
            genesis,
            operator,
            agent,
            engine,
            signer,
            trusted_peers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// The genesis public key fingerprint (first 16 hex chars).
    pub fn genesis_fingerprint(&self) -> String {
        hex::encode(&self.genesis.public_key()[..8])
    }

    /// The agent's portable certificate chain (genesis → operator → agent).
    pub fn portable_chain(&self) -> Vec<Certificate> {
        self.agent.portable_chain()
    }

    /// Handle an incoming introduction request.
    ///
    /// Verifies the peer's certificate chain, evaluates the introduction
    /// against the policy engine, and returns an introduction response.
    pub fn handle_introduction(
        &self,
        request: &IntroductionRequest,
    ) -> Result<(IntroductionResponse, PolicyDecision), String> {
        // Step 1: Verify the certificate chain and build policy context
        let outcome = verify_introduction(
            request,
            Some(&self.genesis.public_key()),
            TrustTier::Tier1,
            Channel::Api,
        )
        .map_err(|e| format!("Chain verification failed: {}", e))?;

        // Step 2: Evaluate the policy engine
        let decision = self.engine.evaluate(&outcome.policy_context);

        // Step 3: Decide based on policy
        let response = match &decision {
            PolicyDecision::Block { reason, .. } => {
                IntroductionResponse::deny(format!("Policy blocked: {}", reason))
            }
            PolicyDecision::Review { summary, .. } => {
                IntroductionResponse::pending_review(summary.clone())
            }
            _ => {
                // Allow, Warn, or Sanitize all result in acceptance
                // Store the peer as trusted
                let peer_key = outcome.peer_public_key.clone();
                self.trusted_peers
                    .write()
                    .map_err(|e| format!("Lock error: {}", e))?
                    .insert(peer_key, outcome.verified_chain);

                // Sign the challenge nonce to prove we own our chain
                let signed_challenge = self.sign_challenge(&request.challenge_nonce);

                IntroductionResponse::accept(self.portable_chain(), signed_challenge)
            }
        };

        Ok((response, decision))
    }

    /// Check if a peer (by their leaf public key hex) is trusted.
    pub fn is_trusted_peer(&self, peer_public_key: &str) -> bool {
        self.trusted_peers
            .read()
            .map(|peers| peers.contains_key(peer_public_key))
            .unwrap_or(false)
    }

    /// Evaluate a policy context and return the decision.
    pub fn evaluate_policy(&self, context: &PolicyContext) -> PolicyDecision {
        self.engine.evaluate(context)
    }

    /// Sign a challenge nonce with the agent's key.
    fn sign_challenge(&self, nonce: &str) -> String {
        use ed25519_dalek::Signer as DalekSigner;
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&self.agent.secret_key());
        let sig = signing_key.sign(nonce.as_bytes());
        hex::encode(sig.to_bytes())
    }
}

impl std::fmt::Debug for NodeContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeContext")
            .field("node_name", &self.node_name)
            .field("genesis_fingerprint", &self.genesis_fingerprint())
            .finish()
    }
}
