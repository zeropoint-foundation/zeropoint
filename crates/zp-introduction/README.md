# zp-introduction

Governed trust establishment between ZeroPoint nodes.

Implements the handshake protocol that allows two nodes from different trust domains to establish a relationship:

1. **Initiator** sends an `IntroductionRequest` containing its certificate chain
2. **Responder** verifies the chain using `zp-keys`
3. **Responder** evaluates a `PolicyContext` with `ActionType::PeerIntroduction` against the policy engine
4. If the policy engine allows it, responder sends an `IntroductionResponse` with its own chain
5. Both sides now have verified chains and can exchange capabilities

## Modules

- **protocol** — Core introduction flow and outcome types
- **request** — Introduction request construction and serialization
- **response** — Introduction response handling
- **error** — Introduction-specific error types

## Design

The introduction protocol does NOT implement policy decisions — it generates the `PolicyContext` that the policy engine evaluates. This keeps the separation between mechanism (`zp-keys`) and governance (`zp-policy`) clean.
