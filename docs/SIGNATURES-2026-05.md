# Document Signatures — Native to the Substrate

*Drafted 2026-05-10. Candidate for folding into `ARCHITECTURE-2026-05.md` as
section II.15. Companion to AGENTIC-SURFACE-2026-05.md (II.14) and
PUBLIC-PRIVATE-SEPARATION-2026-05.md.*

## The reframe

ZeroPoint was conceived as "trust infrastructure for the Agentic Age." The
positioning was correct for the moment but too narrow for what the substrate
actually is. Agent action governance and document signing are not different
problems — they are the same problem expressed at different cadences. Both
are about cryptographically attesting that a sovereign entity (human or
agent) committed to a specific action at a specific time, with a specific
chain of authority backing them.

ZP's primitives are signing primitives. Ed25519 over canonical preimages,
BLAKE3 content addressing, append-only audit chains, receipt composability,
delegation narrowing — these are not adjacent to "what document signing
needs." They *are* what document signing needs. Building a wrapper around
them via DocuSeal or DocuSign or any third-party signing service would be
the architectural equivalent of building HTTP around gRPC: wrapping the
actual thing in a less-clean version of itself.

This document specifies document signing as a **first-class capability of
the substrate**, not a feature built on top.

## Strategic positioning

The substrate's positioning expands:

> **Trust infrastructure for any commitment a sovereign entity makes — by
> an agent or by a human.**

Foundation's dogfood story expands correspondingly. Today: "every
governed agent action lands on the chain." After this: "every commitment
the Foundation makes — agent action OR legal agreement — lands on the same
chain." That's a sovereignty story no third-party signing service can
credibly tell, because they cannot share the chain that holds the
Foundation's agent governance receipts.

Markets that reach ZP via the agent-governance frame and decide it's not
for them today (because they don't run agents at scale) reach ZP via the
document-signing frame and stay. Conversely, organizations adopting ZP for
document signing are pre-onboarded onto the substrate the day they start
running agentic workflows. Same primitives, different entry points.

## What ZP already has

Every signing primitive needed lives in the substrate today. Document
signing is a recognition of existing capability, not new architecture:

| Signing requirement | ZP primitive (existing) |
|--------------------|------------------------|
| Cryptographic signature | Ed25519 over canonical preimages; ML-DSA-65 reserved for hybrid post-quantum (II.0 / common.proto) |
| Tamper-evident audit trail | BLAKE3-hashed append-only chain with SQLite triggers (Seam 1, Phase 1.C) |
| Attribution to signer | `ActorRef` + Operator key descended from Genesis (II.6) |
| Multi-party workflow | Delegation chains + receipt composability (V.7 reserved fields) |
| Content addressing | BLAKE3 `ContentHash` already the chain's primary key (common.proto) |
| Single canonical form | Seam 17 ZP-canonical-v1; Seam 20 Signable trait |
| Verification primitive | Seam 5 `verify_signature` — discipline-pinned single point |
| Discovery / streaming | Subscriptions service (proto/v1/subscriptions.proto) |

The new work is *additive*: new verbs on a new service, new receipt kinds,
document storage. None of it disturbs existing substrate guarantees;
all of it composes with what's already there.

## The `Signatures` service

Lives at `proto/v1/signatures.proto`. Six verbs cover the document signing
lifecycle:

| Verb | Purpose | Response category (Architecture VII.3) |
|------|---------|---------------------------------------|
| `CreateSigningRequest` | Initiator declares: this document needs signatures from these parties | Full receipt (kind `RECEIPT_KIND_SIGNING_REQUEST`) |
| `SubmitSignature` | A party signs (Ed25519 over canonical preimage of document + intent + signer identity) | Full receipt (kind `RECEIPT_KIND_DOCUMENT_SIGNATURE`) |
| `WatchSigningStatus` | Subscribe to progress events as parties sign | Stream of signed envelopes (rides on Subscriptions infra) |
| `GetSignedDocument` | Retrieve completed document + all party signatures + chain proofs | Signed envelope |
| `RevokeSigningRequest` | Initiator cancels before completion (state-changing, attested) | Full receipt (kind `RECEIPT_KIND_SIGNING_REVOCATION`) |
| `ListSigningRequests` | Filtered query for signing requests by status / actor / time range | Plain envelope (paginated) |

Adheres to Architecture II.7 (protobuf as verb-set schema) and II.13
(pure gRPC outer surface). All discipline pins that apply to the existing
verb set apply here unchanged (`verbs_must_match_schema`, etc.).

## Receipt kinds

Four new entries in `common.proto`'s `ReceiptKind` enum:

- `RECEIPT_KIND_SIGNING_REQUEST = N+0` — initiator emits to start a flow
- `RECEIPT_KIND_INTENT_TO_SIGN = N+1` — signer emits before `DOCUMENT_SIGNATURE` to record affirmative consent (separable from the signature itself; satisfies legal-validity "intent" requirement)
- `RECEIPT_KIND_DOCUMENT_SIGNATURE = N+2` — each signer emits one of these per document
- `RECEIPT_KIND_SIGNING_COMPLETION = N+3` — emitted automatically when all required signers have submitted; closes the flow

(Numeric values assigned at proto change time per existing receipt-kind
sequence.)

Each receipt cites the preceding receipts via `ReceiptHeader.references`
(reserved by V.7). The composition story:

```
SIGNING_REQUEST  ──┐
                   ├── INTENT_TO_SIGN (signer A) ── DOCUMENT_SIGNATURE (A)
                   ├── INTENT_TO_SIGN (signer B) ── DOCUMENT_SIGNATURE (B)
                   ├── INTENT_TO_SIGN (signer C) ── DOCUMENT_SIGNATURE (C)
                   └── SIGNING_COMPLETION  ─── (cites all DOCUMENT_SIGNATURE receipts)
```

Each receipt is independently verifiable. The COMPLETION receipt is the
authoritative "this document was signed by all required parties" attestation;
GetSignedDocument returns it along with the referenced signatures.

## Document storage

Documents are content-addressed by BLAKE3 hash. The document body is *not*
embedded in receipts (which would bloat the audit DB and conflate two
concerns). Receipts hold the hash + metadata; the body lives in a separate
document store.

**Storage layer:** `~/ZeroPoint/documents/<blake3-hash>/`, containing:

- `document.<extension>` — the original document bytes (PDF, plaintext, etc.)
- `meta.json` — metadata: original filename, MIME type, upload timestamp, signer manifest
- (private deployments) `document.encrypted` — encrypted document body, see "Document confidentiality" below

A `DocumentStore` abstraction in `zp-audit` or a new `zp-documents` crate
handles read/write with content-addressed paths. The store is referenced
by hash; the chain is the source of truth for which documents exist and who
signed them.

**Cross-machine document availability** (mesh / multi-tenant): for now,
documents live where they were uploaded. If signer B is on a different
machine from initiator A, the document is fetched via the existing mesh
adapter (libp2p, II.10) using BLAKE3 hash as the content identifier. This
plugs into V.5 trust portability cleanly.

## Counterparty model: external parties without ZP infrastructure

The hard case for any signing system: how does a partner sign a Foundation
document when they don't run ZP?

**ZP's answer: short-lived delegations.**

The Foundation issues a one-shot delegation to a key the partner supplies
(or an ephemeral key generated for them). The delegation:
- Authorizes exactly one action: `SubmitSignature` against one specific
  `SIGNING_REQUEST` receipt
- Expires after a configured window (e.g., 7 days)
- Cannot be re-used after expiration or use

The partner produces one Ed25519 signature, in any tool they choose (a
5-line Python script, a CLI, a hosted web flow — same standard primitive).
That signature lands on the Foundation's chain as a regular
`DOCUMENT_SIGNATURE` receipt, attested by the delegation chain.

Partner experience: receives an email with a signing URL → opens it in
browser → sees the document → confirms intent → clicks sign → done. Under
the hood, the browser runs WebCrypto Ed25519 (standard, in all major
browsers since 2022), produces the signature, posts it to ZP. No partner
account; no installation; no third-party service.

The Foundation hosts the web flow on `zeropoint.global` (or a Foundation
subdomain). It's a single-page application that calls ZP's signing verbs.
The substrate handles everything cryptographic; the page is just the UX.

## Legal validity mapping

ESIGN Act (US), UETA (US state), and eIDAS SES/AES (EU) all share a common
core: signatures are valid if they demonstrate **intent**, the signer
**consented to electronic records**, the signature is **attributable to
the signer**, and the **record is retained in a form that preserves
integrity**. ZP's primitives satisfy all four cryptographically:

| Requirement | How ZP satisfies it |
|-------------|--------------------|
| Intent to sign | `INTENT_TO_SIGN` receipt before `DOCUMENT_SIGNATURE`. Separable, deliberate, affirmative action; the signer cryptographically commits to "I am about to sign this specific document" before producing the signature. Cannot be replayed against a different document (canonical preimage includes the document hash). |
| Consent to electronic records | Implicit in operating on ZP. For high-stakes documents or external counterparties, an explicit consent receipt can be emitted as part of the flow. |
| Attribution | Ed25519 key + identity chain. For Foundation members: Operator key descends from Genesis (II.6). For external counterparties: delegation chain proves the partner's authority. Either way, the signature is bound to a specific identity. |
| Record retention with integrity | BLAKE3-hashed append-only chain. Any modification invalidates the chain's hash linkage; document body's hash is in the signature receipt's canonical preimage so the body is also tamper-evident. |

For eIDAS QES (Qualified Electronic Signatures, the highest tier requiring
hardware-attested signing): not covered by Foundation v1. QES requires
integration with a Qualified Trust Service Provider's hardware tokens.
This is a Phase 3 consideration when ZP adoption reaches organizations
requiring QES (e.g., EU notarial work).

## Document confidentiality: public-by-default vs. private-by-default

The audit chain is public-by-default — any party with chain read access can
see all receipts. Document bodies, however, may need to be confidential
(Foundation legal terms, partner financial details, member compensation).

**Design decision: private-by-default for document bodies, public-by-default
for receipts.**

- **Receipts are public** (within the chain's access model): they prove a
  signing event happened, by whom, with what intent, against which document
  hash. They never include document content.
- **Document bodies are encrypted at rest**, accessible only to the
  signers, the initiator, and any explicitly-granted readers (via
  delegation).

Encryption: ChaCha20-Poly1305 with a per-document key wrapped by the
document's authorized-readers' public keys (NaCl-style sealed envelopes).
Each signer-or-reader can decrypt the document using their own private key.
Document key rotation is supported by re-wrapping.

**Implication for verification**: a third party who knows the document
hash can verify that the document with that hash was signed by the named
parties at the named time, *without seeing the document's content*. This
is the right shape for many real-world scenarios (a court verifying a
contract was signed without exposing its contents to the docket clerk).

**The chain still proves the existence and signature chain of the
document.** Confidentiality protects the *body*, not the *fact of
signing*.

## CLI affordances

The substrate's CLI gets new subcommands so Foundation members can operate
on signing without waiting for the web UI:

| Command | Effect |
|---------|--------|
| `zp sign request --document <file> --signers <id,id,id>` | Upload document to local store, emit `SIGNING_REQUEST` receipt, notify signers (via Foundation channels) |
| `zp sign submit <request-id>` | Confirm intent (emit `INTENT_TO_SIGN`), produce Ed25519 signature, emit `DOCUMENT_SIGNATURE` receipt |
| `zp sign status <request-id>` | Show progress: who's signed, who's pending, when each event landed |
| `zp sign revoke <request-id>` | Initiator only; emit `SIGNING_REVOCATION`, halt the flow |
| `zp sign verify <document-file>` | Given a document file, verify all signatures and return who signed when |
| `zp sign list` | List signing requests, filterable by status |

CLI usage lets the Foundation pilot the substrate-native signing flow
before any web UI exists. The web UI is for *partners and members who
prefer GUI*; the CLI is sufficient for substrate-native operations.

## Sequencing

1. **Design ratification** (this doc + review) — captures the architectural shape before code.
2. **Proto + codegen** — `proto/v1/signatures.proto`, generate types via existing `zp-verbs` build.rs.
3. **Receipt kind additions** — extend `ReceiptKind` enum in `common.proto`, regenerate.
4. **Document store implementation** — content-addressed local store, BLAKE3 paths, plain-and-encrypted variants.
5. **Verb handlers** — implement Signatures service in zp-server (`crates/zp-server/src/grpc.rs` or sibling module).
6. **CLI affordances** — `zp sign` subcommand tree.
7. **Counterparty delegation flow** — short-lived single-use delegations for external signers; web flow on zeropoint.global.
8. **Web UI** — partners' browser signing experience; renders documents (PDF for now), captures intent + WebCrypto Ed25519 signature, posts to substrate.
9. **Migration** — DocuSign-signed Foundation documents stay in DocuSign as immutable evidence; new documents go through ZP; partners renew on ZP terms.

Steps 1-6 are substrate work. Steps 7-8 are foundation-stack / public-site
work. Step 9 is operational, not architectural.

Total estimated effort: 3-6 weeks of focused work for a Foundation-grade v1,
mostly because steps 4 (storage) and 8 (web UI) have real engineering surface.
Steps 1-3 are days. Steps 5-6 are 1-2 weeks. Step 7 is a 1-week project.
Step 8 is the largest single piece, 1-2 weeks.

## Open questions

- **PDF rendering for the web flow.** Pure-Rust PDF libraries
  (`lopdf`, `pdf-canvas`, `printpdf`) handle PDF *generation* well but
  rendering for display in a browser is typically done client-side via
  `pdfjs` or similar. The web flow probably embeds PDF.js for display
  and uses canvas for the signature mark, then posts the document hash +
  Ed25519 signature back to the substrate (the rendered PDF with the
  signature mark drawn on it is a separate artifact from the signed
  cryptographic record — the *signature* is the receipt, the *visual
  mark* is for the human consumer).

- **Signature visual artifact embedding.** Standard PDF digital signatures
  embed cryptographic signature data into the PDF itself (PKCS#7/CAdES).
  ZP's approach is the opposite: the signature is a chain receipt, the
  PDF is just the content. For interoperability with non-ZP verifiers
  (e.g., a lawyer with Acrobat), an optional "embed ZP receipt as PDF
  digital signature" path could be added — the receipt becomes a signed
  attestation embedded in the PDF that says "this document was signed via
  ZP chain at receipt X." Defer to a follow-up; Foundation members and
  ZP-aware partners don't need it.

- **PAdES Long-Term Validation (LTV).** For signatures that need to remain
  cryptographically verifiable after the signing certificate expires. ZP's
  approach is somewhat orthogonal — chain integrity is the long-term proof,
  not certificate validity — but for legal documents that need to survive
  decades, the question is worth asking. Probably an enhancement layer,
  not a v1 concern.

- **Notification/email infrastructure.** zp-server has channels infrastructure
  for events. Email-out for "you have a document to sign" can ride on that,
  or be handled by the foundation-stack onboarding repo's deployment
  configuration. Worth designing the abstraction once before either v1
  signing or v2 generic notifications add their own.

- **Bulk signing patterns.** Some Foundation workflows may need bulk
  document signing (e.g., onboarding 20 new members each receiving a
  member agreement). v1 model is one-document-at-a-time; bulk patterns are
  a v2 affordance.

- **Voiding / amending signed documents.** What's the substrate semantic
  for a document that was validly signed but later needs to be replaced
  (errata, amendment)? Composes with the compensating-receipts work
  (#75) — amendment is a new signing flow that cites the original. The
  original remains in the chain as evidence; the amendment supersedes it
  operationally.

## Status

Design selected: native ZP signatures via new `Signatures` service +
new receipt kinds + content-addressed document store + short-lived
delegations for external counterparties + private-by-default document
bodies on a public-by-default chain.

Implementation begins after L3 hardening (task #91) reaches a stable
operational baseline. The design exists now so the work is well-shaped
when the runway opens.

The Foundation's narrative shifts as a result: ZP is the substrate for
*any* cryptographic commitment a sovereign entity makes, agent action
or document signing alike. That's a substantially larger story than
"trust infrastructure for AI agents," and one no other product can
credibly tell because no other product runs both governance and signing
on the same chain.
