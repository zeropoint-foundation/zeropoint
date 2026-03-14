`cF999

`c!ZeroPoint Architecture!

`cF777System Overview
`f

-

`c>>  Governance Gate Pipeline  `f

`lEvery action flows through the Governance Gate before
execution. Three stages, in order:

`Fddd  Guard`f    Local pre-check. Constitutional constraints.
             Sovereignty enforcement. No network needed.

`Fddd  Policy`f   Full policy evaluation. Trust tier gating.
             WASM sandboxed modules. Reputation checks.

`Fddd  Audit`f    Receipt generation. Chain linkage. Epoch
             compaction. Merkle proofs for verification.

`lThe Guard runs first and can block unconditionally.
No policy module, no operator override, and no consensus
vote can bypass a constitutional rule. This is a technical
property, not a policy promise.

-

`c>>  Crate Map  `f

`Fddd  zp-core`f       Types, traits, error model
`Fddd  zp-policy`f     Guard + PolicyEngine + WASM runtime
`Fddd  zp-audit`f      Chain builder + collective audit
`Fddd  zp-receipt`f    Receipt signing + Merkle epoch trees
`Fddd  zp-trust`f      Trust tier management + vault
`Fddd  zp-keys`f       Genesis/Operator/Agent key hierarchy
`Fddd  zp-mesh`f       Reticulum-compatible mesh transport
`Fddd  zp-pipeline`f   Orchestration pipeline + mesh bridge
`Fddd  zp-llm`f        LLM provider abstraction + validation
`Fddd  zp-skills`f     Capability-scoped skill registry
`Fddd  zp-learning`f   Behavioral pattern detection
`Fddd  zp-server`f     HTTP API (Axum)
`Fddd  zp-cli`f        Terminal interface

-

`c>>  Key Hierarchy  `f

`l  GenesisKey        Self-signed root of trust
    |
    +-- OperatorKey   Signed by genesis (per node)
         |
         +-- AgentKey Signed by operator (per agent)

`lEach level holds an Ed25519 keypair and a certificate
chain back to genesis. Any node can verify an agent's
identity by walking the chain -- offline, no network
required. Six invariants enforced: valid signatures,
issuer linkage, role hierarchy, monotonic depth, no
expired certificates, and hash linkage.

-

`c>>  Policy Evaluation Hierarchy  `f

`l  1. HarmPrincipleRule      Constitutional (always first)
  2. SovereigntyRule        Constitutional
  3. ReputationGateRule     Operational
  4. WASM policy modules    Peer-exchanged, sandboxed
  5. DefaultAllowRule       Fallback

`lConstitutional rules win over everything. The most
restrictive decision always wins:
  Block(5) > Review(4) > Warn(3) > Sanitize(2) > Allow(1)

-

`c`[Back to Index`:/page/index.mu]

`cF555ZeroPoint v0.1.0 | ThinkStream Labs`f

