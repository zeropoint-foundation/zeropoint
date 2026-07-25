# Economic DLT Composition

**Tier 2 canonical elaboration.** Elaborates `KEEL-2026-07.md` §II.5 (Genesis-derived signing), §III.9 (delegation narrowing), §III.23 (coordination not oversight), §III.24 (aligned blindness), Part VII (Peer-Verification Contract), Part VIII (bounded operator sovereignty). Specifies how the substrate composes with external distributed ledger technologies (Hedera, Ethereum-family, and equivalents) for economic coordination that requires settlement, transaction, or contract primitives. Canonical claims live in KEEL.

Draft — 2026-07-11 — internal audience only. Composes with `CHAIN-WATCHER-AND-COMMITMENTS-2026-07.md` (commitment primitives referenced by economic operations), `PEER-TRUST-ANCHOR-2026-07.md` (counterparty trust informing contract selection), `SOVEREIGN-KINSHIP-PRIMITIVES-2026-07.md` (household and kindred economic coordination scopes), `SUBSTRATE-BLINDNESS-HEURISTICS-2026-07.md` (aligned blindness applied to public-chain metadata), `CRYPTOGRAPHIC-SOVEREIGNTY-AND-LEGAL-PROCESS-2026-07.md` (contract-related legal process composability), `CONSEQUENCE-AND-FEDERATION-DISCIPLINE-2026-07.md` (economic-misbehavior handling), `EXTENSION-SURFACE-2026-07.md` (DLT integrations arrive as capability-declared extensions).

## Framing

The substrate is trust/identity/coordination infrastructure. It is not a payment system, not a currency, not a transaction ledger, not a smart-contract execution environment. External distributed ledger technologies handle those concerns — Hedera for enterprise-oriented consensus and settlement, Ethereum and its family for programmable contract execution, Bitcoin for base-money settlement, various others for domain-specific needs. Substrate does not attempt to replace any of these.

What substrate provides that DLTs typically lack: Genesis-derived signing tied to a specific human sovereign; chain-anchored commitments between specific parties independent of consensus-level activity; peer trust anchor discipline that informs counterparty selection; aligned blindness that keeps operator-private data off any public chain; consequence discipline that handles bad-actor behavior via peer-mesh federation rather than protocol-level enforcement.

The composition is: substrate holds trust and identity; DLT holds settlement primitives; the two reference each other via chain-anchored provenance receipts. Operator's substrate authorizes contract execution via delegation; DLT executes and settles; substrate chain-anchors the DLT transaction reference alongside the substrate context (which commitment, which counterparty, which scope). Result: identity-bearing economic coordination that composes DLT settlement strength with substrate sovereignty discipline.

Three properties frame the composition:

1. **Substrate does not reinvent DLT primitives.** No substrate-native currency, no substrate consensus mechanism, no substrate transaction ledger competing with existing DLTs. When economic coordination needs settlement, substrate composes with existing DLTs.
2. **DLT does not know substrate identity.** Public DLTs operate on their own address schemes (Ethereum addresses, Hedera account IDs). Substrate's Genesis-derived identity is separate. Composition happens at the substrate operator layer — operator's substrate authorizes their DLT wallet to act on their behalf per declared delegation scope.
3. **Cross-chain provenance is chain-anchored on both sides.** Substrate chain records "commitment X executed via DLT transaction Y." DLT records transaction Y as ordinary transaction. Provenance verification walks from substrate commitment to DLT transaction to counterparty's DLT wallet to (if that counterparty runs substrate) their substrate commitment. Two chains linked at the transaction reference.

## The composition surface

Substrate composes with DLTs at three distinct surfaces, each with its own discipline.

### Surface 1 — Delegation to DLT wallet authority

Operator's DLT wallets (Ethereum EOAs, Hedera accounts, Bitcoin wallets) are held per whatever DLT-native custody discipline the operator uses. Substrate does not hold the DLT wallet private keys directly — that would violate KEEL §II.5 singular-sovereign-root discipline (Genesis is the only substrate-managed root; other keys can exist but substrate does not comingle them).

Instead, operator's substrate emits chain-anchored delegation receipts that authorize specific DLT wallet operations:

```
sovereign:delegation:dlt_wallet:granted:<delegation_id>
  fields:
    wallet_reference: {chain_type, chain_id, wallet_address}
    scope: <what operations authorized>
      - "sign_transaction": specific transaction categories
      - "execute_contract": specific contract categories
      - "settle_commitment": commitments matching specific chain-anchored commitment IDs
    limits: {max_value_per_tx, max_value_per_period, allowed_counterparties}
    duration: {start_time, end_time}
    signature: <operator Genesis signature>
```

DLT wallet's own signing infrastructure (hardware wallet, custody service, contract wallet) enforces the substrate delegation at wallet-operation time. Substrate does not directly hold wallet keys; substrate authorizes what the wallet is permitted to do on operator's behalf.

Composition patterns:

- **Hardware wallet integration**: substrate emits delegation; hardware wallet enforces (via extension that composes hardware wallet SDK with substrate delegation checks)
- **Custody service integration**: substrate emits delegation; custody service enforces via their own authorization mechanism composed with substrate delegation receipt verification
- **Contract wallet integration**: substrate delegation receipt is a required parameter to contract wallet's execution function; contract enforces at execution time

### Surface 2 — Cross-chain provenance receipts

Every DLT transaction operator's substrate authorizes gets a chain-anchored provenance receipt:

```
economic:dlt_transaction:provenance:<provenance_id>
  fields:
    substrate_context:
      commitment_id: <chain-anchored commitment being settled>
      counterparty: <peer Genesis pubkey if counterparty is sovereign>
      kinship_scope: <if operating under kinship scope>
      operator_delegation: <reference to delegation authorizing this>
    dlt_transaction:
      chain_type: <ethereum | hedera | bitcoin | other>
      chain_id: <mainnet | testnet | specific network>
      tx_hash: <DLT-native transaction identifier>
      tx_status: <pending | confirmed | reverted | finalized>
      block_reference: <block number or consensus timestamp>
    timestamp: <substrate timestamp>
    signature: <operator Genesis signature>
```

Provenance receipt is chain-anchored on operator's substrate chain. It's the substrate-side authoritative record of what DLT transaction was authorized for what substrate purpose. Post-hoc analysis walks: substrate commitment → provenance receipt → DLT transaction → block confirmation.

Counterparty who also runs substrate emits symmetric provenance receipt on their chain. Both parties' substrate chains reference the same DLT transaction — cross-chain provenance links two sovereign chains at the DLT transaction level.

### Surface 3 — DLT event chain-watching

Substrate chain-watchers can subscribe to DLT events (contract emissions, transaction confirmations, wallet activity) relevant to operator's chain-anchored context. When DLT event fires matching a watched pattern:

- Substrate emits `economic:dlt_event:observed:<event_id>` receipt referencing the DLT event
- Chain-watcher trigger fires substrate action (per CHAIN-WATCHER-AND-COMMITMENTS)
- Regent narration surfaces relevant events to operator per cognitive input plane discipline

Example: operator has commitment to pay peer X on delivery of asset Y. Chain-watcher watches for DLT event confirming asset Y received. When event fires: substrate chain-anchors observation, checks commitment status, either narrates to operator ("asset received per commitment; ready to authorize payment") or auto-executes payment per declared delegation scope.

This composes DLT event streams with substrate chain-watcher primitives without substrate having to natively index DLT state.

## Aligned blindness on public DLT metadata

Public DLTs (Ethereum, Bitcoin) publish transaction metadata that reveals substantial operator context if not disciplined:

- Wallet addresses linkable to identities via analysis
- Transaction values, timing, counterparties all publicly visible
- Contract interactions revealing what protocols operator uses
- Cross-transaction pattern analysis revealing behavioral signatures

Substrate aligned blindness (KEEL III.24) has specific implications for DLT composition:

**Substrate does NOT chain-anchor DLT metadata as substrate observation.** Substrate provenance receipts reference DLT transaction IDs; they do not embed DLT transaction contents. Operator can query DLT directly for metadata; substrate does not create a substrate-side searchable index of operator's DLT activity. Reduces the chain-anchored surface that a substrate breach could expose.

**Substrate does NOT recommend or default to public DLT usage for private coordination.** Operator declaring commitment with kindred sovereign for household coordination should not default to executing via public Ethereum where transaction is globally visible. Substrate surfaces the metadata-exposure implication and prefers private/permissioned DLT paths for private coordination (Hedera consensus with private topics, private Ethereum L2, direct bilateral state channels).

**Substrate does NOT expose peer DLT wallet addresses without peer authorization.** Peer's DLT wallet address is peer-private data unless peer has published it. Substrate treats peer DLT wallet as coordination-scope information — shared for specific commitment purposes under kinship scope, not published in commons.

**Substrate does NOT index cross-DLT operator profile.** Even if operator's substrate authorizes DLT transactions across multiple chains, substrate does not build a cross-chain operator profile. Each authorization is chain-anchored; aggregation happens per operator query, not as substrate discipline.

## Contract execution composition

Smart contracts executing on DLTs need specific composition patterns to preserve substrate discipline:

### Delegation-narrowed contract signing

Operator's substrate delegation authorizes contract execution up to specific scopes:

- Contract address (which contract can be called)
- Function signatures (which contract methods authorized)
- Argument constraints (values within declared ranges)
- Time bounds (delegation valid until specified time)
- Value limits (maximum transaction value)

Contract wallet or hardware-wallet-with-substrate-integration verifies delegation before signing. Attempts to sign transactions outside delegation scope fail at wallet layer.

Chain-anchored: `sovereign:delegation:contract:granted:<delegation_id>` receipt with all above fields.

### Dispute mechanism composition

Contract-level disputes (transaction reverted, contract execution deadlocked, on-chain arbitration invoked) compose with substrate dispute discipline:

- Contract dispute is chain-anchored on both DLT (native contract event) and substrate (substrate provenance receipt updated)
- Substrate peer trust anchor discipline informs which counterparty positions substrate accepts (substrate's own peer trust is upstream of DLT contract dispute resolution)
- Substrate consequence discipline applies to counterparties who breach commitments — peer trust anchor revocation, commons reputation flow — regardless of DLT dispute resolution outcome

Contract dispute happens at DLT layer per contract logic; substrate reputation and peer discipline continue independently.

### Multi-signature composition

When contract requires multi-signature authorization from multiple substrate operators (household jointly authorizing contract execution, community jointly authorizing treasury operation):

- Each participating operator's substrate emits their own delegation receipt
- Contract requires signatures matching declared delegations
- Substrate chain-anchors the multi-signature ceremony via `sovereign:multisig:contract:ceremony:<ceremony_id>` receipt
- Composition with kinship / household / community governance primitives per GOVERNANCE-COMPOSITION

## Custodial vs non-custodial patterns

Different custody models compose with substrate discipline differently:

### Non-custodial (operator holds keys directly)

Operator holds DLT wallet private keys via their own custody (hardware wallet, air-gapped signing, offline generation). Substrate emits delegation authorizing operator to sign specific transactions; operator physically authorizes via wallet UI; DLT confirms.

Highest sovereignty (operator keys never leave their control) but highest operator burden (they manage all custody).

### Contract wallet (multisig, social recovery)

Operator's authority represented via smart contract that enforces authorization logic (multisig, guardian recovery, spending limits). Substrate delegation composes with contract logic; substrate delegation is one input to contract's execution decision.

Balances sovereignty with operational convenience (loss of one key doesn't lose access; substrate delegation composes with contract-level constraints).

### Custody service (institutional or self-hosted)

Third-party or self-hosted custody service holds wallet keys per operator's account with the service. Substrate delegation is authorization the custody service enforces before signing transactions on operator's behalf.

Lower sovereignty (trust in custody service) but lowest operator burden (service handles custody complexity). Substrate discipline still applies at authorization layer.

Substrate does not prescribe custody model. Operator chooses per their sovereignty preferences. Substrate composes with all models via the delegation-authorization discipline.

## Composition with existing specs

- **CHAIN-WATCHER-AND-COMMITMENTS-2026-07.md**: economic commitments are one class of commitment primitive; DLT execution is one way to settle commitments; chain-watcher observes DLT events for commitment status changes.
- **PEER-TRUST-ANCHOR-2026-07.md**: peer trust anchor informs contract counterparty selection; operator does not enter into economic contracts with peers below their declared trust threshold.
- **SOVEREIGN-KINSHIP-PRIMITIVES-2026-07.md**: household economic coordination composes with `commitment_coordination` kinship scope; kindred sovereigns can jointly authorize contract execution under household governance.
- **HOUSEHOLD-COMPOSITION-2026-07.md**: household treasury (if any) can be a multi-signature contract with all household members as authorizers per household charter.
- **SUBSTRATE-BLINDNESS-HEURISTICS-2026-07.md**: aligned blindness applies to DLT metadata — substrate does not index operator DLT activity, does not expose peer wallet addresses, prefers private DLT paths for private coordination.
- **CRYPTOGRAPHIC-SOVEREIGNTY-AND-LEGAL-PROCESS-2026-07.md**: contract-level disputes may compose with legal process (contract enforcement, arbitration awards); substrate provides chain evidence supporting legal proceedings on both sides.
- **CONSEQUENCE-AND-FEDERATION-DISCIPLINE-2026-07.md**: economic misbehavior (contract breach, fraudulent transactions, promised-but-not-delivered) handled per federation-level consequence — peer trust anchor revocation, commons reputation, legal system as needed.
- **EXTENSION-SURFACE-2026-07.md**: DLT integrations arrive as extensions declaring specific capability classes (`capability:dlt:ethereum:sign`, `capability:dlt:hedera:submit`, etc.). Quarantine Plane admission ceremony applies.
- **EMPIRICAL-PROGRAM-2026-07.md**: economic outcome data (commitment fulfillment rates, contract execution success rates) feeds empirical program via chain-anchored provenance receipts.

## Attack model

- **Attacker steals operator DLT wallet keys**: substrate delegation cannot prevent unauthorized transactions from stolen keys; DLT-native security applies. Substrate consequence (peer trust anchor revocation) applies to substrate-side operator identity; but DLT-side transactions are irreversible per DLT consensus.
- **Attacker forges substrate delegation to authorize contract execution**: delegation receipts require operator Genesis signature; forgery requires Genesis compromise. Contract wallet verifies delegation before signing.
- **Attacker uses public DLT metadata to profile operator via wallet address linking**: substrate cannot prevent public-chain analysis. Mitigation via private DLT paths for sensitive coordination, wallet-per-purpose discipline, mixer-adjacent techniques (though substrate does not integrate mixers — that's outside substrate scope).
- **Attacker exploits contract vulnerability to drain operator funds**: substrate delegation cannot prevent contract-level exploits; contract security is DLT-side concern. Substrate delegation limits (max_value_per_tx) reduce blast radius.
- **Attacker impersonates counterparty to receive economic settlement**: substrate peer trust anchor discipline requires operator to have anchored trust in counterparty before commitment; impersonation would require compromising counterparty's substrate identity.
- **Attacker manipulates DLT event chain-watcher to trigger false substrate actions**: watched DLT events must be verifiable via DLT-native verification (transaction confirmations, block references); substrate chain-watcher trigger requires verified event.

## Failure modes

- **DLT transaction fails / reverts**: chain-watcher observes reversion; substrate provenance receipt updated; commitment state remains "pending" pending retry or renegotiation.
- **DLT confirmation slow / not finalizing**: substrate handles gracefully — provenance receipt marks status as "pending"; chain-watcher continues watching; operator sees status via dashboard.
- **DLT wallet unavailable when substrate delegation authorized transaction**: transaction not signed; substrate emits `sovereign:delegation:dlt_wallet:unfulfilled` receipt; operator notified.
- **Cross-substrate DLT provenance mismatch**: operator's provenance receipt says tx-X settled commitment-Y with counterparty; counterparty's provenance receipt says tx-X settled different commitment. Dispute resolution required.
- **DLT chain reorganization affects finalized transaction**: rare but possible; substrate re-observes DLT state and updates provenance receipt accordingly.
- **Extension bug in DLT integration causes incorrect delegation checks**: extension responsibility; substrate discipline surfaces via reproducibility ceremony and chain-anchored evidence of extension behavior.

## Non-goals

- **Not a payment system.** Substrate does not hold value directly, does not process payments, does not execute settlement.
- **Not a currency.** No substrate-native token, no substrate-issued asset.
- **Not a consensus mechanism.** Substrate does not run consensus; each substrate is a sovereign chain per operator.
- **Not a smart-contract execution environment.** Substrate does not execute contracts; DLTs do.
- **Not a DEX or trading platform.** Substrate does not match orders or execute trades.
- **Not a stablecoin issuer.** Substrate does not issue any financial instrument.
- **Not a bank.** Substrate does not custody funds, does not extend credit, does not provide banking services.
- **Not a compliance service.** KYC / AML / regulatory compliance is operator responsibility with their chosen DLT and financial service providers; substrate does not attempt regulatory intermediation.
- **Not opinionated on which DLTs to compose with.** Substrate provides composition primitives that work with any well-defined DLT; operator chooses which DLTs they use.

## Open positions

- **DLT integration extension canonical set**. Reference extensions for major DLTs (Ethereum, Hedera, Bitcoin, prominent L2s). Federation-hosted or community-maintained.
- **Multi-DLT delegation composition**. Operator authorizes commitment settlement via one of several DLTs; substrate composes with all authorized options.
- **Private DLT path defaults**. Which DLT paths does substrate default to for private-scope commitments? Trade-offs on privacy vs settlement speed vs cost.
- **Cross-substrate DLT provenance dispute protocol**. When two substrate chains disagree about a shared DLT transaction interpretation.
- **DLT transaction batching**. Operator authorizes multiple substrate commitments; substrate batches into single DLT transaction to reduce fees. Composition rules.
- **Contract wallet integration standards**. How substrate delegation composes with contract wallet architectures (Safe, Argent, various emergent standards).
- **DLT event observation cost budget**. Chain-watchers on DLT events cost RPC calls; substrate needs to budget observation cost per operator preference.
- **Post-settlement receipt integration**. Once DLT transaction finalizes, how does substrate finalize associated commitment? Automatic per delegation scope, or requires additional operator ceremony?

## What composes from here

Immediate design work:

1. **Delegation receipt schemas** for DLT wallet, contract execution, multi-signature ceremony
2. **Cross-chain provenance receipt schema**
3. **DLT event chain-watcher extension protocol** for reference DLT integrations
4. **Aligned-blindness-per-DLT policy** for public vs private DLT metadata handling
5. **Custody-model composition patterns** documented per canonical custody types

Near-term implementation:

1. **DLT integration extension framework** in `crates/zp-dlt/src/`
2. **Ethereum reference integration extension** (composing with prominent hardware wallet SDKs)
3. **Hedera reference integration extension**
4. **Cross-chain provenance receipt emitters**
5. **DLT event chain-watcher runtime**
6. **Dashboard economic panel**: active commitments, DLT transaction status, delegation authorizations, provenance timeline
7. **CLI verbs**: `zp dlt delegation grant|list|revoke`, `zp dlt provenance list`, `zp dlt watch <event_pattern>`

## Framing note

Economic DLT composition captures how substrate composes with external distributed ledger technologies without reinventing what they do. Same principle as chain-anchored discipline elsewhere: substrate provides identity/trust/coordination discipline; DLTs handle settlement/transaction/contract execution; composition happens at chain-anchored provenance receipts referencing DLT transaction identifiers.

The load-bearing insight: **substrate is not the payment system; substrate is the trust/identity/coordination layer that payment systems compose with.** Operators use existing DLTs per their own DLT-native choices; substrate provides the identity discipline (Genesis-derived delegation), commitment discipline (chain-anchored commitments referenced by DLT transactions), consequence discipline (peer-mesh federation for bad-actor behavior), and blindness discipline (aligned blindness applied to public-chain metadata exposure). Neither substrate nor DLT tries to replace the other; both compose to provide identity-bearing economic coordination that neither could deliver alone.

Combined with the substrate's structural discipline across every trust boundary, economic DLT composition closes the "economic coordination without becoming a payment system" gap. What was previously implicit — that substrate would need to work with external DLTs somehow — becomes structural: three composition surfaces (delegation to wallet authority, cross-chain provenance receipts, DLT event chain-watching), aligned blindness applied per DLT metadata class, custody-model-agnostic composition, contract execution composition with substrate delegation discipline. Sovereignty is preserved because operator holds their DLT wallet custody per their own discipline; safety is preserved because substrate delegation limits transaction scope and consequence discipline handles bad-actor behavior at substrate layer; identity is preserved because substrate Genesis remains the operator's sovereign root while DLT wallets are authorized derivatives.
