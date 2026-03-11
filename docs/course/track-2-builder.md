# Track 2: Builder

## ZeroPoint Developer Course — From Zero to Governed Agent Fleet

**Prerequisites:** Rust toolchain (rustup, cargo), basic Rust literacy (ownership, traits, Result), a terminal.
**Duration:** ~20 hours self-paced
**Outcome:** You deploy a governed multi-agent system with Tier 2 key chains, constrained capability grants, hash-chained audit trails, epoch compaction, and mesh-connected peer verification.

---

## Course Philosophy

Every module follows the same structure:

1. **Concept** — What you're building and why it matters (drawn from the book, kept short)
2. **Lab** — Hands-on code you write and run against a real ZeroPoint instance
3. **Checkpoint** — A verification exercise that proves you understood the module

You should type the code, not copy it. The muscle memory matters. When a lab says "verify that X," it means run the code and confirm the output matches expectations. When a checkpoint asks you to build something, build it from scratch — the earlier labs gave you the pieces.

The modules are sequential. Each builds on the previous. Do not skip ahead.

---

## Module 1: Your First Key

### Concept

Everything in ZeroPoint flows from a key. Identity is a key pair. Authentication is a signature. Authority originates from a genesis key held by a human and flows downward through a signed hierarchy: Genesis → Operator → Agent.

This module creates that hierarchy from scratch.

### Lab

Create a new Rust project that depends on `zp-keys` and `zp-trust`:

```bash
cargo new zp-lab && cd zp-lab
```

Add dependencies to `Cargo.toml` (use path dependencies pointing to your ZeroPoint checkout):

```toml
[dependencies]
zp-keys = { path = "../zeropoint/crates/zp-keys" }
zp-trust = { path = "../zeropoint/crates/zp-trust" }
chrono = { version = "0.4", features = ["serde"] }
hex = "0.4"
```

Write `src/main.rs`:

```rust
use zp_keys::{GenesisKey, OperatorKey, AgentKey, KeyRole};
use chrono::{Utc, Duration};

fn main() {
    // Step 1: Generate the genesis key
    let genesis = GenesisKey::generate("alice");
    println!("Genesis public key: {}", hex::encode(genesis.public_key()));
    println!("Genesis role: {:?}", genesis.certificate().body.role);

    // Step 2: Issue an operator key (expires in 365 days)
    let operator = OperatorKey::generate(
        "operator-alpha",
        &genesis,
        Some(Utc::now() + Duration::days(365)),
    );
    println!("\nOperator public key: {}", hex::encode(operator.public_key()));
    println!("Operator issuer: {}", operator.certificate().body.issuer_public_key);

    // Step 3: Issue an agent key (expires in 30 days)
    let agent = AgentKey::generate(
        "agent-001",
        &operator,
        Some(Utc::now() + Duration::days(30)),
    );
    println!("\nAgent public key: {}", hex::encode(agent.public_key()));
    println!("Agent depth: {}", agent.certificate().body.depth);

    // Step 4: Verify the chain
    // Agent's issuer should be operator's public key
    assert_eq!(
        agent.certificate().body.issuer_public_key,
        hex::encode(operator.public_key()),
        "Agent's issuer must be the operator"
    );

    // Operator's issuer should be genesis's public key
    assert_eq!(
        operator.certificate().body.issuer_public_key,
        hex::encode(genesis.public_key()),
        "Operator's issuer must be genesis"
    );

    // Verify signatures
    agent.certificate().verify(&operator.public_key())
        .expect("Agent certificate signature must verify against operator");
    operator.certificate().verify(&genesis.public_key())
        .expect("Operator certificate signature must verify against genesis");

    println!("\n✓ Full chain verified: Genesis → Operator → Agent");
    println!("  Depths: 0 → 1 → 2");
    println!("  Every signature verifies.");
}
```

Run it:

```bash
cargo run
```

You should see the full key hierarchy printed, with verification passing.

### Checkpoint

**Without looking at the lab code**, write a program that:

1. Generates a genesis key for a subject named "my-org"
2. Issues two operator keys: "ops-east" and "ops-west"
3. Issues three agent keys under "ops-east" and two under "ops-west"
4. Verifies every certificate in every chain
5. Prints the full hierarchy as a tree

If every assertion passes, you understand key hierarchies.

---

## Module 2: Signing and Verification

### Concept

A key pair is useless until it signs something. Ed25519 signatures are the cryptographic primitive that makes receipts verifiable, audit entries attributable, and capability grants authentic. This module builds fluency with signing and verification.

### Lab

```rust
use zp_trust::Signer;

fn main() {
    // Generate a signer (Ed25519 key pair)
    let signer = Signer::generate();
    println!("Public key: {}", hex::encode(signer.public_key()));

    // Sign arbitrary data
    let message = b"This agent is authorized to read /data/reports/*";
    let signature = signer.sign(message);
    println!("Signature: {}...{}", &signature[..16], &signature[signature.len()-16..]);

    // Verify — anyone with the public key can do this
    let valid = Signer::verify(&signer.public_key(), message, &signature)
        .expect("Verification should not error");
    assert!(valid, "Signature must verify");
    println!("✓ Signature verified");

    // Tamper with the message — verification must fail
    let tampered = b"This agent is authorized to read /data/secrets/*";
    let still_valid = Signer::verify(&signer.public_key(), tampered, &signature)
        .expect("Verification should not error");
    assert!(!still_valid, "Tampered message must not verify");
    println!("✓ Tampered message correctly rejected");

    // Tamper with the signature — verification must fail
    let mut bad_sig = signature.clone();
    // Flip a character in the hex string
    let bytes: Vec<u8> = hex::decode(&bad_sig).unwrap();
    let mut flipped = bytes;
    flipped[0] ^= 0xFF;
    bad_sig = hex::encode(flipped);

    let still_valid = Signer::verify(&signer.public_key(), message, &bad_sig)
        .unwrap_or(false);
    assert!(!still_valid, "Tampered signature must not verify");
    println!("✓ Tampered signature correctly rejected");

    // Restore signer from secret key (persistence)
    let secret = signer.secret_key();
    let restored = Signer::from_secret(&secret)
        .expect("Should restore from secret");
    assert_eq!(signer.public_key(), restored.public_key());
    println!("✓ Signer restored from secret key");
}
```

### Checkpoint

Write a function `sign_and_verify(data: &[u8]) -> bool` that generates a fresh signer, signs the data, and verifies the signature. Then write a function `cross_verify_fails(data: &[u8]) -> bool` that generates *two* signers, signs with one, and attempts to verify with the other's public key. The first should return true, the second false.

---

## Module 3: The Credential Vault

### Concept

Agents need secrets — API keys, database credentials, tokens. The credential vault stores them encrypted with ChaCha20-Poly1305, retrieves them by reference (never exposing the master key), and zeroizes all sensitive material on drop. This module teaches secure credential handling.

### Lab

```rust
use zp_trust::CredentialVault;
use rand::RngCore;

fn main() {
    // Generate a random 256-bit master key
    let mut master_key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut master_key);

    // Create the vault
    let mut vault = CredentialVault::new(&master_key);

    // Store credentials
    vault.store("db-production", b"postgres://user:pass@db.internal:5432/prod")
        .expect("Should store credential");
    vault.store("api-key-weather", b"sk-weather-abc123def456")
        .expect("Should store credential");
    vault.store("api-key-maps", b"sk-maps-xyz789")
        .expect("Should store credential");

    // List — only names, never values
    let names = vault.list();
    println!("Stored credentials: {:?}", names);
    assert_eq!(names.len(), 3);

    // Retrieve — decrypts on demand
    let db_cred = vault.retrieve("db-production")
        .expect("Should retrieve credential");
    assert_eq!(db_cred, b"postgres://user:pass@db.internal:5432/prod");
    println!("✓ Retrieved and decrypted db-production");

    // Retrieve with wrong name — fails
    let result = vault.retrieve("db-staging");
    assert!(result.is_err(), "Non-existent credential should error");
    println!("✓ Non-existent credential correctly rejected");

    // Remove
    vault.remove("api-key-maps").expect("Should remove");
    assert_eq!(vault.list().len(), 2);
    println!("✓ Credential removed, {} remaining", vault.list().len());
}
```

### Checkpoint

Build a program that stores 5 credentials, retrieves each one, verifies the values match, removes 2 of them, and confirms the list shows exactly 3. Then drop the vault and create a new one with the *same* master key — can you retrieve the credentials? (Hint: the current vault is in-memory. Think about what persistence would require.)

---

## Module 4: Capability Grants and Constraints

### Concept

A capability grant is a signed, portable authorization token. It specifies what an agent can do, what constraints apply, and who issued it. This module builds grants with real constraints and explores how they compose.

### Lab

```rust
use zp_core::capability_grant::{CapabilityGrant, GrantedCapability, Constraint};
use zp_core::policy::TrustTier;
use chrono::{Utc, Duration};

fn main() {
    let grantor = "operator-alpha-hash";
    let grantee = "agent-001-hash";

    // Build a grant with multiple constraints
    let grant = CapabilityGrant::new(
        grantor.to_string(),
        grantee.to_string(),
        GrantedCapability::Read { scope: vec!["data/reports/*".into()] },
        "receipt-001".to_string(),
    )
    .with_constraint(Constraint::MaxCost(0.50))
    .with_constraint(Constraint::RateLimit {
        max_actions: 100,
        window_secs: 3600,
    })
    .with_constraint(Constraint::TimeWindow {
        start_hour: 9,
        end_hour: 17,
    })
    .with_constraint(Constraint::RequireReceipt)
    .with_trust_tier(TrustTier::Tier2)
    .with_expiration(Utc::now() + Duration::days(30))
    .with_max_delegation_depth(2);

    println!("Grant ID: {}", grant.id);
    println!("Capability: {:?}", grant.capability);
    println!("Constraints: {}", grant.constraints.len());
    for c in &grant.constraints {
        println!("  - {:?}", c);
    }
    println!("Trust tier: {:?}", grant.trust_tier);
    println!("Max delegation depth: {:?}", grant.max_delegation_depth);
    println!("Expires: {:?}", grant.expires_at);

    // Now build an ApiCall grant with scope restriction
    let api_grant = CapabilityGrant::new(
        grantor.to_string(),
        grantee.to_string(),
        GrantedCapability::ApiCall {
            endpoints: vec!["api.weather.com/**".into()],
        },
        "receipt-002".to_string(),
    )
    .with_constraint(Constraint::MaxCost(0.01))
    .with_constraint(Constraint::RateLimit {
        max_actions: 10,
        window_secs: 60,
    })
    .with_constraint(Constraint::ScopeRestriction {
        allowed: vec!["api.weather.com/v2/**".into()],
        denied: vec!["api.weather.com/v2/admin/**".into()],
    });

    println!("\nAPI Grant scope restriction:");
    for c in &api_grant.constraints {
        if let Constraint::ScopeRestriction { allowed, denied } = c {
            println!("  Allowed: {:?}", allowed);
            println!("  Denied: {:?}", denied);
        }
    }
    println!("✓ Both grants constructed with constraints");
}
```

### Checkpoint

Build grants for all eight capability types (Read, Write, Execute, CredentialAccess, ApiCall, ConfigChange, MeshSend, Custom). Each grant should have at least two constraints. Print a summary table showing capability type, constraint count, and expiration for each.

---

## Module 5: Delegation Chains

### Concept

Authority flows downward through signed grants. Each link narrows the scope, tightens the constraints, and shortens the expiration. Eight invariants are enforced in code. This module builds a three-level delegation chain and verifies it.

### Lab

```rust
use zp_core::capability_grant::{CapabilityGrant, GrantedCapability, Constraint};
use zp_core::delegation_chain::DelegationChain;
use zp_core::policy::TrustTier;
use chrono::{Utc, Duration};

fn main() {
    // Root grant: human → operator
    let root = CapabilityGrant::new(
        "genesis-hash".to_string(),
        "operator-hash".to_string(),
        GrantedCapability::Read { scope: vec!["data/**".into()] },
        "receipt-root".to_string(),
    )
    .with_trust_tier(TrustTier::Tier2)
    .with_expiration(Utc::now() + Duration::days(365))
    .with_max_delegation_depth(3);

    // Level 1: operator → agent (narrower scope, tighter constraints)
    let level1 = CapabilityGrant::new(
        "operator-hash".to_string(),
        "agent-hash".to_string(),
        GrantedCapability::Read { scope: vec!["data/reports/**".into()] },
        "receipt-level1".to_string(),
    )
    .with_trust_tier(TrustTier::Tier2)
    .with_expiration(Utc::now() + Duration::days(90))
    .with_constraint(Constraint::RateLimit { max_actions: 100, window_secs: 3600 })
    .with_constraint(Constraint::RequireReceipt);

    // Level 2: agent → sub-agent (narrowest scope, tightest constraints)
    let level2 = CapabilityGrant::new(
        "agent-hash".to_string(),
        "sub-agent-hash".to_string(),
        GrantedCapability::Read { scope: vec!["data/reports/billing/*".into()] },
        "receipt-level2".to_string(),
    )
    .with_trust_tier(TrustTier::Tier2)
    .with_expiration(Utc::now() + Duration::days(7))
    .with_constraint(Constraint::RateLimit { max_actions: 20, window_secs: 3600 })
    .with_constraint(Constraint::RequireReceipt)
    .with_constraint(Constraint::TimeWindow { start_hour: 9, end_hour: 17 });

    // Verify the chain
    match DelegationChain::verify(vec![root, level1, level2]) {
        Ok(chain) => {
            println!("✓ Delegation chain verified ({} grants)", chain.grants().len());
            for (i, grant) in chain.grants().iter().enumerate() {
                println!("  Level {}: {} → {}", i, grant.grantor, grant.grantee);
                println!("    Scope: {:?}", grant.capability);
                println!("    Constraints: {}", grant.constraints.len());
            }
        }
        Err(e) => {
            println!("✗ Chain verification failed: {:?}", e);
        }
    }
}
```

### Checkpoint

Build a chain that **violates** each of the eight invariants, one at a time. For each violation, verify that `DelegationChain::verify()` returns the appropriate error. Document which invariant each test case violates and what the error message says. This is the most important checkpoint in the course — understanding how the invariants fail teaches you what they protect.

---

## Module 6: The Policy Engine

### Concept

The policy engine evaluates actions against rules and returns graduated decisions. Constitutional rules (HarmPrinciple, Sovereignty) are immovable. Operational rules compose on top. The most restrictive decision wins. This module builds a policy engine, fires actions through it, and observes graduated decisions.

### Lab

```rust
use zp_policy::{PolicyEngine, GovernanceGate, GateResult};
use zp_core::policy::{ActionType, PolicyContext, PolicyDecision, TrustTier};
use zp_core::audit::ActorId;
use chrono::Utc;

fn main() {
    // Create engine with default rules
    // (HarmPrinciple, Sovereignty, Catastrophic, BulkOperation, ReputationGate, DefaultAllow)
    let engine = PolicyEngine::new();

    // Low-risk action: Chat
    let chat_context = PolicyContext {
        action: ActionType::Chat,
        trust_tier: TrustTier::Tier1,
        ..Default::default()
    };
    let decision = engine.evaluate(&chat_context);
    println!("Chat decision: {:?}", decision);
    // Should be Allow

    // High-risk action: Execute
    let exec_context = PolicyContext {
        action: ActionType::Execute { language: "python".into() },
        trust_tier: TrustTier::Tier1,
        ..Default::default()
    };
    let decision = engine.evaluate(&exec_context);
    println!("Execute decision: {:?}", decision);

    // Critical action: CredentialAccess
    let cred_context = PolicyContext {
        action: ActionType::CredentialAccess {
            credential_ref: "db-production".into(),
        },
        trust_tier: TrustTier::Tier0,
        ..Default::default()
    };
    let decision = engine.evaluate(&cred_context);
    println!("CredentialAccess at Tier0: {:?}", decision);
    // CatastrophicActionRule should block or warn

    // Use the GovernanceGate for full pipeline
    let gate = GovernanceGate::new("lab-gate");
    let result = gate.evaluate(&chat_context, ActorId::User("alice".into()));

    println!("\nGovernanceGate result:");
    println!("  Decision: {:?}", result.decision);
    println!("  Risk level: {:?}", result.risk_level);
    println!("  Trust tier: {:?}", result.trust_tier);
    println!("  Applied rules: {:?}", result.applied_rules);
    println!("  Audit entry ID: {:?}", result.audit_entry.id);
    println!("  is_allowed: {}", result.is_allowed());
    println!("  is_blocked: {}", result.is_blocked());
    println!("  needs_interaction: {}", result.needs_interaction());
}
```

### Checkpoint

Write a program that evaluates all 11 ActionType variants through the GovernanceGate at each of the three trust tiers (Tier0, Tier1, Tier2). Print a matrix: action type × trust tier → decision. Identify which combinations produce Block, which produce Warn, and which produce Allow. This matrix is your deployment's security profile.

---

## Module 7: Receipts and Receipt Chains

### Concept

The receipt is the atomic unit of accountability. Every governed action produces one, signed by the actor, hash-chained to the previous. This module creates receipts, chains them, and verifies the chain's integrity.

### Lab

```rust
use zp_receipt::{Receipt, ReceiptChain};
use zp_receipt::types::{Status, Action, TrustGrade};
use zp_trust::Signer;

fn main() {
    let signer = Signer::generate();

    // Create an Intent receipt (root of provenance chain)
    let intent = Receipt::intent("user-alice")
        .status(Status::Success)
        .trust_grade(TrustGrade::B)
        .finalize();
    println!("Intent receipt: {}", intent.id);
    assert!(intent.verify_hash(), "Hash must verify");

    // Create an Execution receipt linked to the intent
    let execution = Receipt::execution("agent-001")
        .parent(&intent.id)
        .status(Status::Success)
        .action(Action::code_execution("python", 0))
        .trust_grade(TrustGrade::B)
        .finalize();
    println!("Execution receipt: {}", execution.id);
    assert!(execution.verify_hash(), "Hash must verify");

    // Chain them
    let mut chain = ReceiptChain::new();
    chain.add_receipt(intent).expect("Should add root");
    chain.add_receipt(execution).expect("Should add child");

    // Verify the chain
    chain.verify().expect("Chain should verify");
    println!("\n✓ Receipt chain verified ({} entries)", chain.entries().len());

    // Print chain structure
    for entry in chain.entries() {
        println!("  seq={} hash={}...{}",
            entry.sequence,
            &entry.content_hash[..8],
            &entry.content_hash[entry.content_hash.len()-8..],
        );
    }
}
```

### Checkpoint

Build a provenance chain with all six receipt types: Intent → Design → Approval → Execution → Payment → Access. Each receipt should reference its parent. Verify the full chain. Then tamper with one receipt (modify a field after creation) and confirm that `chain.verify()` fails. Identify which entry the failure points to.

---

## Module 8: The Audit Trail

### Concept

The audit trail records every governance decision in a hash-chained, persisted sequence. It is the evidence that makes everything else verifiable after the fact. This module creates an audit store, appends entries, and verifies the chain.

### Lab

```rust
use zp_audit::{AuditStore, ChainBuilder, ChainVerifier};
use zp_core::audit::{ActorId, AuditAction};
use zp_core::policy::PolicyDecision;
use zp_core::types::ConversationId;

fn main() {
    // Open a persistent audit store
    let store = AuditStore::open("./lab-audit.db")
        .expect("Should open audit store");

    let conv_id = ConversationId::new();

    // Build genesis entry (first in chain)
    let entry1 = ChainBuilder::build_entry_from_genesis(
        ActorId::User("alice".into()),
        AuditAction::MessageReceived {
            content_hash: "abc123".into(),
        },
        conv_id.clone(),
        PolicyDecision::Allow { conditions: vec![] },
        "default-allow".into(),
        None,
        None,
    );
    println!("Entry 1: {} (genesis)", entry1.id);
    store.append(entry1.clone()).expect("Should append");

    // Build second entry (chained to first)
    let entry2 = ChainBuilder::build_entry(
        entry1.entry_hash.clone(), // prev_hash
        ActorId::Operator,
        AuditAction::ResponseGenerated {
            model: "claude-3".into(),
            content_hash: "def456".into(),
        },
        conv_id.clone(),
        PolicyDecision::Allow { conditions: vec![] },
        "default-allow".into(),
        None,
        None,
    );
    println!("Entry 2: {} (prev={}...)", entry2.id, &entry2.prev_hash[..8]);
    store.append(entry2.clone()).expect("Should append");

    // Build third entry
    let entry3 = ChainBuilder::build_entry(
        entry2.entry_hash.clone(),
        ActorId::Skill("code-executor".into()),
        AuditAction::ToolInvoked {
            tool_name: "python".into(),
            arguments_hash: "ghi789".into(),
        },
        conv_id.clone(),
        PolicyDecision::Warn {
            message: "High-risk execution".into(),
            require_ack: true,
        },
        "catastrophic-action-rule".into(),
        None,
        None,
    );
    store.append(entry3).expect("Should append");

    // Retrieve and verify
    let entries = store.get_entries_by_conversation(&conv_id)
        .expect("Should retrieve");
    println!("\nRetrieved {} entries", entries.len());

    let report = ChainVerifier::verify(&entries)
        .expect("Should verify");
    println!("Chain valid: {}", report.is_valid);
    println!("✓ Audit chain verified");
}
```

### Checkpoint

Create 20 audit entries across 3 different conversations. Retrieve each conversation's entries separately. Verify each conversation's chain independently. Then retrieve all entries by time range and verify the combined chain. How does cross-conversation verification differ from within-conversation verification?

---

## Module 9: The Governance Gate — End to End

### Concept

This module wires everything together. A request enters the GovernanceGate, passes through Guard → Policy → Audit, and produces a GateResult with a full audit entry hash-chained to the previous. This is the integration point where ZeroPoint's guarantees become operational.

### Lab

```rust
use zp_policy::{GovernanceGate, PolicyEngine};
use zp_core::policy::{ActionType, PolicyContext, TrustTier};
use zp_core::audit::ActorId;

fn main() {
    // Build a gate with default policy engine
    let gate = GovernanceGate::new("production-gate");

    // Simulate a sequence of actions through the gate
    let actions = vec![
        ("alice", ActionType::Chat, TrustTier::Tier1),
        ("alice", ActionType::Read { target: "reports/q4.pdf".into() }, TrustTier::Tier1),
        ("agent-001", ActionType::Execute { language: "python".into() }, TrustTier::Tier2),
        ("agent-001", ActionType::Write { target: "output/results.json".into() }, TrustTier::Tier2),
        ("agent-002", ActionType::CredentialAccess { credential_ref: "api-key".into() }, TrustTier::Tier0),
    ];

    println!("Action Sequence Through GovernanceGate:\n");
    println!("{:<12} {:<25} {:<8} {:<10} {:<8}",
        "Actor", "Action", "Tier", "Decision", "Rules");
    println!("{}", "-".repeat(70));

    for (actor, action, tier) in actions {
        let context = PolicyContext {
            action: action.clone(),
            trust_tier: tier,
            ..Default::default()
        };
        let actor_id = ActorId::User(actor.into());
        let result = gate.evaluate(&context, actor_id);

        let action_name = format!("{:?}", action);
        let action_short = if action_name.len() > 24 {
            format!("{}...", &action_name[..21])
        } else {
            action_name
        };

        println!("{:<12} {:<25} {:<8} {:<10} {}",
            actor,
            action_short,
            format!("{:?}", tier),
            if result.is_allowed() { "Allow" }
            else if result.is_blocked() { "Block" }
            else { "Interact" },
            result.applied_rules.join(", "),
        );
    }

    println!("\n✓ All actions evaluated through GovernanceGate");
    println!("  Each produced an audit entry hash-chained to the previous.");
}
```

### Checkpoint

Build a complete request lifecycle: create a GovernanceGate, evaluate an action sequence that includes at least one Allow, one Warn, and one Block decision. For each result, print the full GateResult including the audit entry's prev_hash. Verify that each audit entry's prev_hash matches the previous entry's entry_hash. This is the chain in action.

---

## Module 10: Mesh Identity and Node Setup

### Concept

The mesh extends governance beyond a single node. Each node has a MeshIdentity (Ed25519 for signing + X25519 for encryption), a unique address derived from its public key, and the ability to communicate over any transport. This module creates a mesh node and prepares it for peer communication.

### Lab

```rust
use zp_mesh::{MeshIdentity, MeshNode};
use zp_mesh::destination::DestinationHash;
use zp_trust::Signer;

fn main() {
    // Method 1: Generate a fresh mesh identity
    let identity = MeshIdentity::generate();
    println!("Signing key:    {}", hex::encode(identity.signing_public_key()));
    println!("Encryption key: {}", hex::encode(identity.encryption_public_key()));

    // The address is a 128-bit hash of the combined public key
    let address = DestinationHash::from_public_key(&identity.combined_public_key());
    println!("Mesh address:   {}", address.to_hex());

    // Method 2: Promote an existing Signer to mesh identity
    let signer = Signer::generate();
    let mesh_id = MeshIdentity::from_signer(&signer)
        .expect("Should promote signer to mesh identity");
    println!("\nPromoted signer to mesh identity");
    println!("  Signer pub:  {}", hex::encode(signer.public_key()));
    println!("  Mesh signing: {}", hex::encode(mesh_id.signing_public_key()));
    assert_eq!(signer.public_key(), mesh_id.signing_public_key());

    // Create a mesh node
    let node = MeshNode::new(identity);
    println!("\nMesh node created");
    println!("  Node address: {}", node.address());

    // The address is deterministic — same key always produces same address
    let identity2 = MeshIdentity::from_ed25519_secret(&signer.secret_key())
        .expect("Should restore identity");
    let node2 = MeshNode::new(identity2);
    let node3_id = MeshIdentity::from_ed25519_secret(&signer.secret_key())
        .expect("Should restore identity");
    let node3 = MeshNode::new(node3_id);
    assert_eq!(node2.address(), node3.address());
    println!("✓ Deterministic addressing: same key → same address");
}
```

### Checkpoint

Create three mesh nodes with three different identities. Print each node's address. Verify that no two addresses collide (they won't — 128-bit hashes — but confirm it). Then restore one node from its secret key and verify the address is identical to the original.

---

## Module 11: Peer Communication

### Concept

Mesh nodes communicate through interfaces (TCP, LoRa, serial) and establish encrypted links through a three-packet handshake. This module sets up two nodes on TCP and exchanges messages.

### Lab

This lab requires two terminal windows (or async tasks). Set up two nodes:

```rust
use zp_mesh::{MeshIdentity, MeshNode};
use zp_mesh::interface::TcpServerInterface;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    // Node A
    let id_a = MeshIdentity::generate();
    let mut node_a = MeshNode::new(id_a);
    let tcp_a = Arc::new(TcpServerInterface::new("127.0.0.1:4242").unwrap());
    node_a.add_interface(tcp_a).unwrap();
    println!("Node A: {}", node_a.address());

    // Node B
    let id_b = MeshIdentity::generate();
    let mut node_b = MeshNode::new(id_b);
    let tcp_b = Arc::new(TcpServerInterface::new("127.0.0.1:4243").unwrap());
    node_b.add_interface(tcp_b).unwrap();
    println!("Node B: {}", node_b.address());

    // Establish link from A to B
    let link = node_a.establish_link(&node_b.address()).await
        .expect("Should establish link");
    println!("Link state: {:?}", link.state());
    println!("✓ Encrypted link established between A and B");

    // Send a receipt from A to B
    let receipt = create_sample_receipt(); // (helper from Module 7)
    node_a.send_receipt(&node_b.address(), &receipt).await
        .expect("Should send receipt");
    println!("✓ Receipt sent from A to B");
}
```

### Checkpoint

Set up three nodes (A, B, C) on different TCP ports. Establish links A↔B and B↔C. Send a receipt from A to C through B. Verify the receipt arrived intact. This is mesh relay in action.

---

## Module 12: Audit Challenges and Attestations

### Concept

A node's audit chain is self-attested until a peer verifies it. The challenge/response protocol lets peers request proof of chain integrity and produce signed attestations of what they found. This module exercises the full verification flow.

### Lab

```rust
use zp_audit::{AuditStore, ChainBuilder, verify_peer_chain};
use zp_audit::{AuditChallenge, AuditResponse, PeerAuditAttestation};
use zp_core::audit::{ActorId, AuditAction};
use zp_core::policy::PolicyDecision;
use zp_core::types::ConversationId;

fn main() {
    // Create a store with 10 entries (simulating a node's history)
    let store = AuditStore::open("./lab-challenge.db").unwrap();
    let conv = ConversationId::new();

    let mut prev_hash = String::new();
    for i in 0..10 {
        let entry = if i == 0 {
            ChainBuilder::build_entry_from_genesis(
                ActorId::User("alice".into()),
                AuditAction::MessageReceived { content_hash: format!("msg-{}", i) },
                conv.clone(),
                PolicyDecision::Allow { conditions: vec![] },
                "default-allow".into(),
                None, None,
            )
        } else {
            ChainBuilder::build_entry(
                prev_hash.clone(),
                ActorId::Operator,
                AuditAction::ResponseGenerated {
                    model: "claude-3".into(),
                    content_hash: format!("resp-{}", i),
                },
                conv.clone(),
                PolicyDecision::Allow { conditions: vec![] },
                "default-allow".into(),
                None, None,
            )
        };
        prev_hash = entry.entry_hash.clone();
        store.append(entry).unwrap();
    }
    println!("Created 10 audit entries");

    // Peer creates a challenge: "show me your last 5 entries"
    let challenge = AuditChallenge::recent(5);
    println!("Challenge: requesting last 5 entries");

    // Node responds (in real mesh, this travels over the wire)
    let entries = store.get_entries_by_conversation(&conv).unwrap();
    let recent: Vec<_> = entries.into_iter().rev().take(5).collect();

    // Peer verifies the chain
    let report = zp_audit::ChainVerifier::verify(&recent).unwrap();
    println!("Verification: chain_valid={}", report.is_valid);

    // Peer produces attestation
    println!("\n✓ Peer attestation:");
    println!("  Entries verified: 5");
    println!("  Chain valid: {}", report.is_valid);
    println!("  (In production: signed by peer's Ed25519 key)");
}
```

### Checkpoint

Create two separate audit stores (simulating two nodes). Populate each with 20 entries. Have each node challenge the other's chain. Produce attestations from both directions. Verify that both attestations confirm valid chains. Then tamper with one entry in one store and re-challenge — the attestation should report an invalid chain.

---

## Module 13: WASM Policy Modules

### Concept

The policy engine supports WebAssembly modules — sandboxed, portable policy rules that can be shared between peers. This module loads a WASM policy module, evaluates it alongside native rules, and observes the most-restrictive-wins composition.

### Lab

First, create a simple WASM policy module (a Rust crate compiled to wasm32-wasi):

```rust
// wasm-policy/src/lib.rs
// Compile with: cargo build --target wasm32-wasi --release

#[no_mangle]
pub extern "C" fn evaluate(action_type: i32, trust_tier: i32) -> i32 {
    // Block Execute actions at Tier0
    if action_type == 4 && trust_tier == 0 {  // Execute = 4, Tier0 = 0
        return 5; // Block
    }
    // Warn on Write at Tier1
    if action_type == 2 && trust_tier == 1 {  // Write = 2, Tier1 = 1
        return 3; // Warn
    }
    1 // Allow
}
```

Then load it in the policy engine:

```rust
use zp_policy::{PolicyEngine, PolicyModuleRegistry};

fn main() {
    // Load WASM bytes
    let wasm_bytes = std::fs::read("./wasm-policy/target/wasm32-wasi/release/policy.wasm")
        .expect("Should read WASM file");

    // Create registry and load module
    let mut registry = PolicyModuleRegistry::new()
        .expect("Should create WASM runtime");
    let metadata = registry.load(&wasm_bytes)
        .expect("Should load module");
    println!("Loaded WASM module: {}", metadata.content_hash);

    // Create engine with WASM
    let engine = PolicyEngine::with_wasm(registry);

    // Evaluate — WASM module participates alongside native rules
    // ... (use same evaluation pattern as Module 6)
}
```

### Checkpoint

Create two different WASM policy modules with different rules. Load both into the same engine. Evaluate an action that triggers rules from both modules and from native rules. Verify that the most restrictive decision from all three sources wins. This demonstrates the composition model across native and WASM boundaries.

---

## Module 14: Capstone — Governed Agent Fleet

### Concept

This is the integration exercise. You build a complete governed agent system from the primitives you've learned: key hierarchy, capability grants, delegation chains, policy engine, receipt chains, audit trail, and mesh communication. No hand-holding — only the requirements.

### Requirements

Build a system with:

1. **One genesis key** ("fleet-command")
2. **Two operator keys** ("ops-primary", "ops-secondary")
3. **Three agents** under ops-primary ("reader-01", "writer-01", "executor-01") and **two agents** under ops-secondary ("reader-02", "analyst-01")
4. **Capability grants** for each agent:
   - reader-01: Read scope `data/**`, rate limit 200/hour, RequireReceipt
   - writer-01: Write scope `output/**`, MaxCost(1.00), rate limit 50/hour, RequireReceipt
   - executor-01: Execute Python only, MaxCost(5.00), rate limit 10/hour, TimeWindow 9-17, RequireReceipt
   - reader-02: Read scope `data/public/**`, rate limit 100/hour
   - analyst-01: Read scope `data/**` + ApiCall scope `analytics.internal/**`, rate limit 30/hour, RequireReceipt
5. **Delegation from executor-01 to a sub-agent** ("sandbox-01") with narrower scope: Execute Python only, MaxCost(0.50), rate limit 5/hour, TimeWindow 10-16
6. **Verify all delegation chains**
7. **A GovernanceGate** with default policy engine
8. **Run 20 actions** through the gate (mix of reads, writes, executes, API calls, credential accesses across different agents and tiers)
9. **Produce a receipt for each action** and chain them
10. **Persist the audit trail** to SQLite
11. **Verify the full audit chain**
12. **Set up two mesh nodes** (ops-primary and ops-secondary)
13. **Exchange receipts** between the nodes
14. **Challenge each node's audit chain** from the other
15. **Produce signed attestations** from both nodes

### Deliverable

A single Rust binary that performs all of the above and prints:

```
FLEET SUMMARY
─────────────
Genesis: fleet-command
Operators: 2
Agents: 5 (+ 1 sub-agent)
Delegation chains: 6 verified ✓

GOVERNANCE RUN
──────────────
Actions evaluated: 20
  Allowed: 16
  Warned: 3
  Blocked: 1
Receipts produced: 20
Receipt chain: verified ✓

AUDIT
─────
Entries: 20
Chain integrity: verified ✓
SQLite store: ./capstone-audit.db

MESH
────
Nodes: 2
Receipts exchanged: 20
Peer attestations: 2 (both valid ✓)

All systems operational.
```

### Verification

If your output matches the structure above (numbers may vary based on which actions you chose), you have built a governed agent fleet from scratch. You understand key hierarchies, capability grants, delegation chains, the policy engine, the governance gate, receipts, audit trails, mesh communication, and peer verification.

You are a ZeroPoint builder.

---

## What Comes Next

Track 2 gives you the primitives. Real deployments add:

- **Epoch compaction** (Chapter 12 of the book) — managing chain growth over months and years
- **WASM policy modules in production** — writing, testing, and exchanging policy rules between peers
- **Skill system integration** — connecting the learning loop to the governance pipeline
- **Key ceremony procedures** — secure genesis key generation for production deployments
- **Retention policy configuration** — deciding how long to keep what, and where to archive it
- **Monitoring and alerting** — watching the seal chain, attestation health, and policy decision distributions

These are Track 3 (Operator) topics. The book covers the architecture. This course gave you the code. Track 3 will give you the operations.
