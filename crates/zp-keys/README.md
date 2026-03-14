# zp-keys

Cryptographic key hierarchy for trust distribution in ZeroPoint.

Defines the three-level key hierarchy that underpins all trust relationships:

```
GenesisKey          ← self-signed root of trust (one per deployment)
  └─ OperatorKey    ← signed by genesis (one per node operator)
      └─ AgentKey   ← signed by operator (one per agent instance)
```

## Modules

- **hierarchy** — GenesisKey, OperatorKey, AgentKey generation and management
- **certificate** — Certificate creation, chain building, and role-based verification
- **keyring** — Secure key storage with zeroize-on-drop
- **error** — Key operation error types

## Design

The hierarchy is a cryptographic primitive — it exists below the policy engine and does not depend on it. Verification is deterministic: given a chain of certificates, you can verify it offline with no network or policy state required.

The policy engine can govern *when* delegation happens (via `ActionType::KeyDelegation`), but the mechanism itself is unconditional. This prevents circular dependencies between key distribution and policy evaluation.
