# MCP 2026-07-28 Composition Against the ZP Substrate

**Tier 2 canonical elaboration.** Composition analysis of the MCP 2026-07-28
final specification (stateless request/response, Multi Round-Trip Requests,
authorization hardening, extensions framework) against the substrate declared
in `KEEL-2026-07.md`. Elaborates KEEL §II.15 (substrate boundary planes),
§II.13 P9 (the system acts; the operator signs), §II.19 (canonical composition
primitive), §III.9 (human control at Genesis), Part V (Composition Contract),
and Part VII (Peer-Verification Contract). Composes with
`design/EXTENSION-SURFACE-2026-07.md`, `design/QUARANTINE-PLANE-2026-07.md`,
`AGENT-TOOL-CONTRACT-2026-06.md`, `EXECUTION-AUTHORITY-MODEL-2026-07.md`, and
`design/HARNESS-SEAM-2026-08.md`.

**Date:** 2026-08-22
**Origin:** Cowork `zp-ai-landscape-sweep` scheduled task surfaced MCP 2026-07-28
as load-bearing with three concrete compositional questions in its `Bearing:`
field (`docs/review/ai-landscape-log.md` §"2026-08-22"). Per the sweep's scope
rule the questions were named and not investigated. Operator asked for a
dedicated session; this is it.
**Model tier:** Opus. Architectural reasoning across the substrate, not
mechanical patching.
**Status:** Analysis. No code changes recommended by this document; §6
enumerates the follow-on session scopes this analysis makes reachable.

---

## §1 Framing: what MCP 2026-07-28 actually is

Read against the primary specification and its changelog against `2025-11-25`,
not against the release blog's summary.

### §1.1 The stateless core

MCP is now a stateless request/response protocol at the transport layer. Six
SEPs compose the change; the load-bearing ones for ZP:

- **SEP-2575 removes `initialize`/`notifications/initialized`.** Every request
  carries its own protocol version and client capabilities in `_meta`
  (`io.modelcontextprotocol/protocolVersion`,
  `io.modelcontextprotocol/clientCapabilities`). A new `server/discover` RPC
  advertises server-side identity and capability. Version mismatch is
  `UnsupportedProtocolVersionError`.
- **SEP-2567 removes the `Mcp-Session-Id` header** and the protocol-level
  session it identified. "Servers that need cross-call state use explicit,
  server-minted handles passed as ordinary tool arguments."
- **SEP-2575 removes SSE stream resumability and message redelivery** (the
  `Last-Event-ID` header and SSE event IDs). "A broken response stream loses
  the in-flight request; clients **MUST** re-issue it as a new request with a
  new request ID."
- **SEP-2575 replaces HTTP GET + `resources/subscribe`/`unsubscribe`** with
  `subscriptions/listen` — a single long-lived POST-response stream carrying
  opted-in change notifications tagged with
  `io.modelcontextprotocol/subscriptionId`.

The single-sentence load-bearing consequence quoted verbatim from the release
blog: *"any MCP request can land on any server instance, and the sticky
routing and shared session stores that horizontal deployments needed before
are no longer required at the protocol layer."*

### §1.2 Multi Round-Trip Requests (MRTR)

**SEP-2322.** Server-initiated requests (previously `roots/list`,
`sampling/createMessage`, `elicitation/create`) are gone as a distinct
mechanism. The server instead responds to an ordinary client request with an
`InputRequiredResult`:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "resultType": "input_required",
    "inputRequests": {
      "github_login": {
        "method": "elicitation/create",
        "params": { … }
      },
      "capital_of_france": {
        "method": "sampling/createMessage",
        "params": { … }
      }
    },
    "requestState": "AEAD-protected blob"
  }
}
```

Client-side rules quoted verbatim from `basic/patterns/mrtr`:

- *"If a client receives an `InputRequiredResult` that contains the
  `inputRequests` field, the client **MUST** construct the requested inputs
  before retrying the original request."*
- *"If an `InputRequiredResult` contains the `requestState` field, the client
  **MUST** echo back the exact value of that field when retrying the original
  request. Clients **MUST NOT** inspect, parse, modify, or make any
  assumptions about the `requestState` contents."*
- *"The JSON-RPC `id` **MUST** be different between the initial request and
  the retry, as they are independent requests."*
- *"All results now carry a required `resultType` field: `"complete"` for
  ordinary results and `"input_required"` for [multi round-trip request]
  interim results."*

Server-side rules quoted verbatim from `basic/patterns/mrtr`:

- *"Servers **MAY** respond to any supported client request with an
  `InputRequiredResult`."* Supported requests are exactly three:
  `prompts/get`, `resources/read`, `tools/call`. No others.
- *"`inputRequests` values are request objects that **MUST** be one of
  `ElicitRequest`, `CreateMessageRequest`, or `ListRootsRequest`"* — nothing
  else, ever.
- *"Servers **MUST** treat `requestState` as an attacker-controlled input. If
  `requestState` influences authorization, resource access, or business logic,
  servers **MUST** protect its integrity (e.g. HMAC or AEAD) and **MUST**
  reject state that fails verification."*

**What MRTR is used for, exhaustively, is what those three permitted request
types are used for**: (a) `ElicitRequest` — asking the *user* for a form-shaped
input the tool needs mid-call; (b) `CreateMessageRequest` — asking the
*client's LLM* to sample a completion the server can use in its work; (c)
`ListRootsRequest` — asking the *client* for its filesystem roots. This is
load-bearing for §3 (Q2).

### §1.3 Authorization hardening

Six SEPs. Load-bearing ones for ZP:

- **SEP-2468 (RFC 9207 iss validation).** Authorization servers *SHOULD*
  include `iss` in authorization responses (including error responses); MCP
  clients *MUST* record the issuer from validated AS metadata and validate a
  present `iss` against it via simple string comparison per RFC 3986 §6.2.1.
  On mismatch the client *MUST NOT* act on or display `error`,
  `error_description`, or `error_uri`. Closes the AS mix-up hole.
- **SEP-2352 (client credential binding).** "Clients **MUST** key persisted
  credentials by the issuer identifier, **MUST NOT** reuse them with a
  different authorization server, and **MUST** re-register when the
  authorization server changes." Pre-registered and DCR credentials are
  bound; **CIMD credentials are portable** because the URL is self-hosted and
  resolved on demand.
- **DCR deprecated in favor of CIMD (PR #2858).** Client ID Metadata
  Documents: `client_id` is an HTTPS URL with a path component that resolves
  to a JSON metadata document. Required fields: `client_id`, `client_name`,
  `redirect_uris`. `client_id` in the document *MUST* match the URL exactly.
  Authorization server fetches on encountering URL-formatted `client_id`,
  validates the document, uses `client_name` on the consent page, validates
  presented `redirect_uris` against the metadata's allowed list. Optional:
  `private_key_jwt` with JWKS for token endpoint auth. AS advertises support
  via `client_id_metadata_document_supported: true` in its metadata.
- **RFC 8707 Resource Indicators** (existing; now *MUST*). MCP clients *MUST*
  include the `resource` parameter in authorization and token requests, and
  it *MUST* be the canonical URI of the target MCP server. MCP servers *MUST*
  validate that tokens were issued specifically for them as audience. *"MCP
  servers **MUST NOT** accept or transit any other tokens."*
- **RFC 9728 Protected Resource Metadata** (now *MUST*). MCP servers *MUST*
  implement it; clients *MUST* use it for authorization server discovery.

The **Enterprise-Managed Authorization (EMA) extension** ships as the first
official extension, letting an organization manage MCP access through an
existing IdP such as Okta or Microsoft Entra ID. EMA is out of scope for this
composition analysis (§Standing follow-ups); noted here so the shape is
complete.

### §1.4 Extensions framework and adjacent moves

- **SEP-2133 introduces the `extensions` field** on `ClientCapabilities` and
  `ServerCapabilities`. Extensions are opt-in and negotiated on each request
  (since there is no handshake).
- **SEP-2577 deprecates Roots, Sampling, and Logging** as first-class
  features; twelve-month minimum deprecation window under the new feature
  lifecycle policy (SEP-2596). Suggested migrations: tool parameters and
  resource URIs replace Roots; direct integration with LLM provider APIs
  replaces Sampling; `stderr` (stdio) or OpenTelemetry replaces Logging.
- **SEP-2663 (Tasks extension).** Long-running work moves out of the core
  protocol into an official extension with polling via `tasks/get` and
  client-to-server input via `tasks/update`.
- **SEP-2106 (JSON Schema 2020-12).** `inputSchema` / `outputSchema` accept
  any JSON Schema 2020-12 keywords; `structuredContent` accepts any JSON
  value; `$ref` resolution requirements and composition-keyword resource
  bounds added.
- **SEP-2484 (conformance gate on Final).** Referenced by the release blog as
  the conformance mechanism that gates final release.
- **Governance move.** MCP is now "Model Context Protocol, a Series of LF
  Projects, LLC" per both blog posts' copyright footer. Same LF governance
  umbrella as AGNTCY (§4).

### §1.5 What MCP 2026-07-28 chose to be, in one sentence

It chose to be a stateless OAuth 2.1 resource-server protocol with a
transport-layer mid-flight input mechanism, deliberately optimized for
horizontal deployment behind a load balancer and for composition with existing
enterprise IdP identity systems. Everything ZP needs to reason about
downstream of that choice — Q1, Q2, Q3 — is a consequence of it.

---

## §2 Q1: Delegation ceremony ↔ MCP authorization + CIMD

**Question restated:** Does the substrate's delegation ceremony vocabulary
(`delegation:granted:*`, `delegation:withdrawn:*`, Genesis-signed authority
narrowing, chain-anchored capability tokens) map onto the MCP `authorization`
extension shape, and would a substrate-minted MCP server satisfy the new CIMD
binding rules?

**Short answer.** Two directions, two answers. **Substrate-as-MCP-resource-
server** (ZP publishing an MCP server): satisfied-by-construction on the
audience-binding and Genesis-signed-delegation semantics; the OAuth
transport-layer wrapper — RFC 9728 Protected Resource Metadata, `iss`
validation, `resource` parameter — is a shim, not a substrate change.
**Substrate-as-MCP-client** (Regent using an external MCP server): satisfied-
with-shim for CIMD; the substrate can serve a valid Client ID Metadata
Document from a Genesis-signed spec artifact without a substrate change, but
the *hosting* of that document requires a public HTTPS endpoint the current
substrate does not universally provide.

### §2.1 The MCP authorization surface, enumerated

The extension surface a substrate-emitted MCP server has to satisfy, drawn
from the primary spec (`specification/draft/basic/authorization` and
`.../client-registration`):

| Surface | Client obligation | Server obligation |
|---|---|---|
| **Protected Resource Metadata (RFC 9728)** | *MUST* fetch `/.well-known/oauth-protected-resource` and derive AS locations from it | *MUST* implement the endpoint; advertise associated authorization server(s) and `scopes_supported` |
| **AS metadata discovery (RFC 8414 or OIDC Discovery 1.0)** | *MUST* support both discovery mechanisms | AS *MUST* provide at least one |
| **RFC 9207 iss validation** | *MUST* record issuer at request time, *MUST* validate present `iss` on authorization response via string comparison (RFC 3986 §6.2.1) | AS *SHOULD* include `iss` in authorization responses; advertise via `authorization_response_iss_parameter_supported: true` |
| **Client registration — CIMD** | Client hosts JSON metadata at HTTPS URL; `client_id` *MUST* equal the URL; document *MUST* include `client_id`, `client_name`, `redirect_uris` | AS *SHOULD* fetch metadata; *MUST* validate URL match; *MUST* validate presented `redirect_uris` against metadata |
| **Client registration — DCR (deprecated)** | *MAY* fall back; *MUST* specify `application_type` (native \| web) | AS *MAY* implement `registration_endpoint` |
| **Client registration — pre-registration** | *MAY* use static credentials | Out-of-band relationship |
| **RFC 8707 Resource Indicators** | *MUST* include canonical MCP server URI in `resource` parameter (both authorization and token requests) | Server *MUST* validate token audience matches its own canonical URI; *MUST NOT* accept or transit tokens issued for any other resource |
| **Bearer token usage (RFC 6750)** | *MUST* use `Authorization: Bearer <token>` header on every request | *MUST* validate; return 401 on invalid, 403 on insufficient scope with `WWW-Authenticate` scope challenge |
| **Client credential binding (SEP-2352)** | Pre-registered / DCR credentials *MUST* be keyed by issuer; *MUST NOT* be reused across AS; *MUST* re-register on AS change. CIMD credentials are portable. | AS is authoritative for the issuer identifier |
| **Step-up authorization** | *SHOULD* handle `insufficient_scope` 403; *SHOULD* compute scope union and re-authorize with expanded scope | Server *SHOULD* emit `WWW-Authenticate` with `error="insufficient_scope"` and required `scope` value |

### §2.2 The ZP side of each surface — field-level correspondence

The substrate's authority-and-identity primitives, as they stand in
`KEEL-2026-07.md` §II.5 (Genesis-as-single-root), §IV.2 (key material),
§IV.5 (delegation / mandate / capability class), and elaborated in
`design/EXTENSION-SURFACE-2026-07.md` §"Delegation semantics" and
`design/QUARANTINE-PLANE-2026-07.md` §"The admission ceremony":

| MCP-side surface | Chain-anchored ZP source of truth | Gap |
|---|---|---|
| **`iss` (RFC 9207 issuer identifier)** | ZP's authority root is Genesis pubkey (KEEL §II.5, IV.1). An MCP-server-emitting substrate would derive an issuer identifier from Genesis (HKDF-derived signing key per surface, per QUARANTINE-PLANE §"Provenance"). | ZP has no notion of "issuer identifier URL" today. An issuer is a signing key; MCP wants a URL string. The mapping is not lossy but requires a canonical URL projection. |
| **AS metadata discovery endpoint** | ZP has no OAuth AS. Substrate-signed capability grants are the substrate's equivalent primitive. An MCP-adapting shim would need to expose an RFC 8414 metadata document derived from the operator's Genesis and current signing keys. | Substrate change *not* required; extension-shaped shim per EXTENSION-SURFACE §"ProtocolAdapterExtension" suffices. The shim is a substrate-side OAuth AS façade over Genesis-signed authority. |
| **Protected Resource Metadata (RFC 9728)** | Every substrate operational surface already emits chain-anchored evidence of what it is (§V.1–V.6 traits). An MCP-server-emitting shim would compute the metadata document from the substrate's declared capability manifest per EXTENSION-SURFACE §"Declaration structure". | Satisfied-with-shim; the substrate's capability manifest is strictly richer than RFC 9728 (fine-grained per QUARANTINE-PLANE §"Verification schema" and EXTENSION-SURFACE §"Fine-grained principles"). |
| **Bearer token — the token itself** | ZP-Sig — the per-request Genesis-signed request envelope emitted through `zp-gate-envelope` per HARNESS-SEAM §2.1 — is the substrate-native equivalent. It is body-bound (binds a BLAKE3 hash of the exact wire bytes) and cannot be expressed as a static `AuthStrategy`. See HARNESS-SEAM §6.1.1. | ZP-Sig and OAuth Bearer are **not the same shape**. ZP-Sig is per-request signed with the caller's Genesis-derived key; Bearer is a passed-through opaque token issued by a third party. A substrate-emitted MCP server that speaks Bearer is holding external tokens issued *about it* by an AS whose identity is not its Genesis. |
| **Token audience binding (RFC 8707 `resource`)** | Every ZP capability grant is scoped to a specific artifact by content hash: `delegation:granted:extension:<wasm_hash>` per EXTENSION-SURFACE §"Grant syntax". Audience binding is *stronger* on the substrate side — it is by content hash of the target, not by canonical URI of a service. | Satisfied-by-construction; the substrate-side audience is more specific than the MCP-side. A shim projects `<wasm_hash>` into a `resource` URI. |
| **CIMD `client_id`** | A substrate-minted MCP client's identity is a Genesis-derived signing key (KEEL §II.6 for the officer-signing analogue). CIMD wants an HTTPS URL. | Requires substrate to host a metadata document at a stable HTTPS URL. Under Sovereign Form the substrate is a NixOS OS with no obligation to run a public HTTPS endpoint; under Companion Form the OS may not permit one. This is the **substrate-side gap** for CIMD as client. See §2.3. |
| **CIMD `redirect_uris`** | Regent's active presence is on a specific device (KEEL §III.3); handoff is chain-anchored (V.4). A stable redirect URI implies a stable listener. | Composes with the presence receipt but not automatically; the redirect target must follow active-presence handoff or resolve through a substrate-mediated proxy. |
| **CIMD `client_name`** | Regent may or may not be named (`REGENT-NAMING-CEREMONY-2026-07`). A pre-named Regent has no `client_name` to offer; a named Regent has one that the operator canonicalized. | Composes cleanly with the naming ceremony. Pre-named substrate presents a stable non-name (e.g. `"ZP Substrate (pre-named)"`); post-naming the metadata document is re-canonicalized. |
| **`delegation:granted:extension:<wasm_hash>`** | Existing per EXTENSION-SURFACE §"Grant syntax". Fine-grained: chain_read filter patterns, chain_write receipt types, network egress endpoints, filesystem read/write scopes, inference bounds, host_functions list. Every grant is Genesis-signed, chain-anchored, revocable. | This is **richer than any OAuth scope**. OAuth scopes are space-separated strings; ZP scopes are typed capability structures with per-item justification (EXTENSION-SURFACE §"Fine-grained principles"). Projection from ZP → OAuth scope loses structure. Projection from OAuth scope → ZP is lossy the other direction — a bearer scope is opaque, while a ZP grant is structured. |
| **`delegation:withdrawn:*` / `delegation:revoked:*`** | Existing per EXTENSION-SURFACE §"Revocation" and QUARANTINE-PLANE §"Step 5: revocation (asymmetric to admission)". Asymmetric: revocation is faster than admission (operator signature only, no verification). | OAuth has no revocation primitive comparable — RFC 7009 exists but is not required by MCP; the closest analogue is token expiry. ZP revocation is stronger. |
| **Client credential binding (SEP-2352, non-CIMD)** | KEEL §II.6 already binds every officer's signing key to Genesis via provisioning receipt. Rotation is a chain-anchored ceremony. Rebinding to a "different authorization server" has no meaning under Genesis-as-single-root. | Non-issue for CIMD path (portable). For pre-registration / DCR fallback the substrate would need to track (issuer, client_id) pairs — that is an extension-side ledger, not a substrate change. |
| **Step-up authorization on `insufficient_scope`** | Per EXTENSION-SURFACE §"Operator review surface", operator can grant a *subset* of requested capabilities; extension emits `extension:capability_denied:<extension>:<capability>` when narrowed capability is invoked. Analogue exists. | ZP's step-up ceremony requires a chain-anchored delegation amendment, not an OAuth re-authorization. A shim maps OAuth's step-up into a substrate proposal (Phase 7 `regent:proposal:{verb}`); the operator signs the delegation extension. |

### §2.3 The CIMD-binding disposition

The single question: would a substrate-minted MCP server satisfy the new CIMD
binding rules?

**Reading the rules literally.** CIMD binding is a property of the *client
side* of the OAuth exchange. A substrate-minted MCP **server** does not have
CIMD obligations — those fall on its clients. What the substrate-minted MCP
server *does* have is the obligation to fetch and validate a client's CIMD
document when the client presents a URL-formatted `client_id`. That is a
straightforward HTTP-GET-and-parse against a JSON schema, satisfied-with-shim
by any extension implementing the ProtocolAdapterExtension trait per
EXTENSION-SURFACE §"Trait families".

**The question the sweep entry actually points at.** The interesting
composition is the inverse: a **substrate-minted MCP client** — the Regent
using an external MCP server that requires OAuth authorization. Here CIMD is
what the client presents. The `client_id` is an HTTPS URL owned by the
substrate; the document at that URL declares the substrate's identity and
allowed redirect URIs.

**Disposition:** **satisfied-with-shim, with a caveat.**

- The *content* of the CIMD document is derivable by construction from the
  substrate's already-existing state. Named Regent (§NAMING-CEREMONY) provides
  `client_name`. Active-presence receipt (V.4) provides `redirect_uris`.
  Genesis-derived signing key provides the optional JWKS for
  `private_key_jwt`. A canonicalization ceremony that emits an artifact whose
  content hash is the metadata document's hash makes the document itself
  chain-anchored and Genesis-signed at rest.
- The *hosting* is the caveat. CIMD requires an HTTPS URL that the
  authorization server can reach on demand. Sovereign Form (KEEL §XIV.1) is
  an OS on the operator's hardware — the operator is not obligated to run a
  public web server. Appliance Form is on dedicated hardware alongside the
  daily driver — sometimes reachable, sometimes not. Companion Form runs
  under a vendor OS with vendor-scoped network permissions — often
  categorically not reachable.

The substrate-side gap is not a Layer A change. It is a **hosting adapter**:
either the operator opts in to publishing the CIMD document via a delegated
public surface (foundation-run mirror, IPFS gateway, peer chain segment
under delegated read), or the substrate falls back to pre-registration for
its OAuth clients. Neither requires substrate binary change; both are Layer B
via canonicalization ceremony.

**Constraint that travels with the disposition.** Per QUARANTINE-PLANE
§Open positions (amended 2026-08-14): "a `quarantine:attestation:*` receipt
must never contribute to precedent." The analogous rule for CIMD: a metadata
document fetched from a substrate-external HTTPS URL, however verified, must
never be admitted as a substitute for operator-signed capability grant. CIMD
identifies the *client*; it does not authorize the client's actions. The
substrate's Phase 7 three-part precedent test applies to every action the
Regent takes via an MCP client, regardless of what CIMD document the AS
validated to issue the bearer token.

### §2.4 Field table summary

| MCP-side field | ZP-side chain-anchored source of truth | Disposition |
|---|---|---|
| `iss` (RFC 9207) | Genesis pubkey → URL projection | satisfied-with-shim |
| AS metadata (RFC 8414) | Genesis-signed spec artifact | satisfied-with-shim |
| Protected Resource Metadata (RFC 9728) | Substrate capability manifest | satisfied-with-shim |
| Bearer token | ZP-Sig envelope (not equivalent shape) | requires-shim (bridge); ZP-Sig is not passed-through |
| `resource` parameter (RFC 8707) | `<wasm_hash>` audience projection | satisfied-by-construction |
| CIMD `client_id` (as client) | Genesis-derived signing key → HTTPS URL | satisfied-with-shim + hosting adapter |
| CIMD `client_name` | Named Regent | satisfied-by-construction (post-naming) |
| CIMD `redirect_uris` | Active-presence receipt | satisfied-with-shim (proxy) |
| Fine-grained scopes | `delegation:granted:*` capability manifest | satisfied-by-construction (richer on ZP side) |
| Revocation | `delegation:revoked:*` (asymmetric) | satisfied-by-construction (stronger on ZP side) |
| SEP-2352 issuer binding | Genesis-as-single-root | non-issue for CIMD path; extension-side ledger otherwise |
| Step-up on `insufficient_scope` | `regent:proposal:{verb}` + delegation amendment | satisfied-with-shim (semantic bridge, not transport) |

### §2.5 What the operator delegation ceremony looks like for MCP servers

Read against EXTENSION-SURFACE §"Delegation semantics" and QUARANTINE-PLANE
§"The admission ceremony", the shape is already built:

1. **Intake:** MCP server manifest (or CIMD-parseable metadata for a
   substrate-external server) arrives at the quarantine plane's
   executable-artifact surface. `quarantine:entered:executable:<hash>`
   receipt with intake source, declared capabilities, timestamp.
2. **Verification:** signature verification (Genesis-derivable? or third-
   party attested with `authority: none` per QUARANTINE-PLANE §Step 2
   third-state amendment). Content-hash check. Capability audit against
   declared vs actually-imported host functions.
3. **Operator delegation:** operator reviews source, verification result,
   declared capabilities, third-party attestations (never as authority).
   Signs `delegation:granted:mcp_server:<content_hash>` — a specialization of
   the existing `delegation:granted:extension:*` shape, with the manifest's
   `resource` URI projection recorded.
4. **Admission:** substrate loads the adapter; every subsequent tool call
   passes through the gate carrying the admission delegation.
5. **Revocation:** `delegation:revoked:mcp_server:<content_hash>` at any time
   by operator signature; circuit breaker at extension scope.

**No new receipt family required.** The `delegation:granted:extension:*`
shape from EXTENSION-SURFACE covers MCP server admission by treating the MCP
adapter as an instance of `ProtocolAdapterExtension`. What is new is the
projection layer that maps between MCP wire-format authorization (Bearer
tokens, CIMD URLs, `resource` parameters) and the substrate's chain-anchored
delegation state.

---

## §3 Q2: MRTR ↔ P9 (the system acts; the operator signs)

**Question restated:** MCP's Multi Round-Trip Request pattern — server returns
`resultType: "input_required"` with an `inputRequests` map and an echoed
`requestState`, client re-issues with `inputResponses` — is structurally the
same shape as KEEL P9's proposes/signs primitive. Should they share
implementation surface, or should the substrate treat MRTR as a transport-
layer detail that composes underneath P9 without co-implementing it?

**Short answer.** They are **not the same shape**. They are two different
half-ceremonies with a superficial round-trip similarity. MRTR is a data
gathering primitive at the MCP transport layer — the tool needs an
*additional input* to complete an *already-authorized* action. P9 is an
authority ceremony at the substrate layer — the substrate needs the
*operator's signature* on a *not-yet-authorized* action. Co-implementing
them would conflate an inference-plane request-response mechanic with an
authority-plane ceremony, and the loss would be one-way toward MRTR: the
substrate would lose the ability to distinguish "I need more information"
from "I need your permission."

**Substrate disposition:** the substrate treats MRTR as a transport-layer
detail that composes *underneath* the extension surface. A subset of MRTR
events — described in §3.3 as "operator-consequential mid-flight input" —
are classified as P9-relevant and *route into* the P9 pipeline; the majority
are handled inside the extension's own delegation scope.

### §3.1 Where each mechanism lives

**P9's home.** KEEL §II.13.9 — *"The system acts; the operator signs — every
consequential action requires operator authority."* Elaborated in
`EXECUTION-AUTHORITY-MODEL-2026-07.md` Phase 7. The primitive is chain-
anchored `regent:proposal:{verb}` receipts, unsigned until the operator
signs, with the operator's signature being the creation of a precedent
receipt for `(finding_type, remediation_verb, context_signature)`. The three-
part authority test — *authority gate*, *pattern precedent*, *novel context*
— determines whether the action can proceed autonomously; failure at any
limb produces a proposal.

P9 concerns *authority*. What passes through P9 is a question about *who is
allowed to decide this*. The chain-anchored artifact is a delegation receipt
or a precedent receipt; the Genesis signature is the load-bearing element.

**MRTR's home.** MCP `specification/2026-07-28/basic/patterns/mrtr`. The
primitive is a JSON-RPC response with `resultType: "input_required"` carrying
an `inputRequests` map whose values are exactly one of `ElicitRequest`,
`CreateMessageRequest`, or `ListRootsRequest`. The client MUST construct the
inputs and retry the original request with a new JSON-RPC id and the
`requestState` echoed unchanged.

MRTR concerns *information*. What passes through MRTR is a question about
*what data does this tool call need to complete*. The chain-anchored artifact
is nothing — MRTR is transport-layer, and the server "encodes any needed
context into the `requestState` field, which the client echoes back on
retry" (mrtr §"Basic Workflow"). The `requestState` is opaque to the client;
the substrate does not sign it; it is not on chain.

### §3.2 Where the round-trip similarity misleads

Both mechanisms have a two-message shape. Both suspend a pending operation
until an out-of-band party provides input. The similarity ends there.

Structural asymmetries:

1. **What the "input" is.** MRTR's inputs are: user form data (`ElicitRequest`),
   an LLM completion (`CreateMessageRequest`), filesystem roots
   (`ListRootsRequest`). None of these is an *authorization signal*. P9's
   input is an Ed25519 signature over a proposal. The signature is not just
   data — it is the operator's *authority*, and its absence is the substrate's
   refusal to act.
2. **What the pending state is.** MRTR's pending state is opaque to the
   substrate (`requestState` is server-encoded and integrity-protected via
   HMAC or AEAD, not by substrate-side signing). P9's pending state is a
   `regent:proposal:{verb}` receipt on the chain, structured, signed by the
   Regent, visible to every officer, materialized into the ontology by the
   Cartographer.
3. **Who owns the transaction.** MRTR is owned by the MCP server. The server
   emits `InputRequiredResult`; the server verifies `requestState` on retry;
   the server decides what "sufficient input" means. P9 is owned by the
   substrate. The Regent emits the proposal; the substrate's gate evaluates
   the delegation; the operator signs at the substrate's UX surface.
4. **What "authorization" refers to.** MRTR's authorization is settled
   *before* the initial request: the client already holds an access token
   with sufficient scope, and the server has decided the caller is entitled
   to invoke the tool. MRTR-mid-flow is *within* an authorized session. P9's
   authorization is the *purpose of the ceremony*: the operator's signature
   IS the authorization. The action is not authorized until the signature
   lands.
5. **What survives across boots.** MRTR's `requestState` is a short-TTL
   in-flight artifact; the mrtr spec explicitly requires "a short expiry
   (TTL), rejecting state presented after it lapses." P9 proposals are on
   chain; they survive cognitive-cycle boots because commitments live on the
   chain per KEEL §II.18 and III.16. A pending P9 proposal is picked up by
   the next cognitive cycle via the Cognitive Input Plane's top-tier priority.

### §3.3 The classification rule

Not every MRTR event is symmetric to P9. Most are strictly narrower — the
tool call is fully authorized, and the server merely lacks a piece of data
(the user's GitHub username, the capital of France, the filesystem roots).
These do not enter the P9 pipeline.

**Classification rule (proposed):** an MRTR `inputRequest` is P9-relevant
iff the client's response would *change what the operator authorized*. Three
concrete subclasses:

1. **P9-relevant: an `ElicitRequest` whose form asks the operator to
   authorize an action.** Example: "Do you consent to send this email to
   these recipients?" — this is a consent gate wearing MRTR clothes. The
   substrate must route this to the P9 pipeline. The Regent emits a
   `regent:proposal:{verb}` receipt; the operator signs at the substrate's
   own delegation ceremony surface; the response to MRTR is derived from the
   signature landing on the chain. The MCP server sees `inputResponses`
   containing the elicitation acceptance; the substrate has a chain-anchored
   audit trail.
2. **P9-relevant: an `ElicitRequest` whose form widens the current
   delegation scope.** Example: "This tool needs additional filesystem
   access — grant?" — this is a delegation-widening request. Route to P9.
   The substrate treats it as an in-flight delegation amendment
   (`delegation:granted:*` receipt); the tool receives a delegation-scoped
   response, not the operator's consent-in-isolation.
3. **P9-strictly-narrower: `ListRootsRequest`, `CreateMessageRequest`,
   `ElicitRequest` for tool-internal data.** Example: form asking for a
   file path within already-granted scope; sampling for a text completion
   the tool will use internally; roots listing for an already-authorized
   filesystem operation. These do *not* enter the P9 pipeline. The
   substrate answers from its own state (roots from the active mandate;
   sampling from the inference-backend under the current mandate;
   elicitation-for-data from the operator via a lightweight prompt that
   does not become a `regent:proposal:*` receipt).

**How the classifier is implemented (proposed).** The substrate's MCP client
adapter reads each `inputRequest` and applies a schema-shaped test:

- `ListRootsRequest` → always subclass 3.
- `CreateMessageRequest` → always subclass 3 (sampling is inference, not
  authority; the sampling is scoped by the tool's already-granted inference
  mandate per V.3).
- `ElicitRequest` → classify by the form's semantic shape. Two mechanical
  signals: (a) does the form's `requestedSchema` contain a field the substrate
  recognizes as a consent-carrying type (`consent`, `authorize`, `approve`,
  etc.)? (b) does the operator's active delegation for this tool cover the
  action the elicitation is about? If either signal fires positive on
  subclass 1 or 2, route to P9. Otherwise subclass 3.

This is a classifier, not a policy. Getting it wrong in the safe direction
(subclass 1 or 2 when it is actually subclass 3) produces an unnecessary
`regent:proposal:{verb}` receipt — audit-visible, cheap. Getting it wrong
in the unsafe direction (subclass 3 when it is actually subclass 1 or 2)
produces an operator authorization that never reached the operator, which
is the exact failure mode P9 exists to prevent. The default is *conservative
classification toward subclass 1 or 2*.

### §3.4 What a substrate-emitted MCP server does with MRTR

The inverse: when the substrate *emits* an MCP server (a Regent verb exposed
via the ProtocolAdapterExtension trait), what should it use MRTR for?

**Rule (proposed):** a substrate-emitted MCP server represents as MRTR *only*
events that are (a) subclass-3 in the classifier above, or (b) queries for
sampling / roots for the substrate's own inference and filesystem tiers.
Anything that requires operator authority — arming a new delegation scope,
consenting to an action, expanding capability — is *never* MRTR from the
substrate side. It is a chain-anchored ceremony that returns to the caller
as either a successful `resultType: "complete"` with the action's result or
a `resultType: "complete"` with a substrate-side refusal.

**Rationale.** MRTR asks the caller's client to gather input mid-call.
Substrate-side ceremonies are load-bearing on the operator being *at the
substrate's UX surface*, not at the caller's UX surface. Routing an operator
authorization through an MRTR `ElicitRequest` returned to an external MCP
client would present the consent prompt on the wrong device, in the wrong
UX, without the substrate's own chain-anchored precedent context. That is a
category error P9 exists to prevent.

### §3.5 Composition summary

MRTR composes *underneath* the extension surface. P9 composes *through* it.
The classification rule in §3.3 is the seam between them.

- **Substrate as MCP client:** classify every inbound `inputRequest`;
  subclass 1/2 → P9 pipeline; subclass 3 → answer from substrate state
  without ceremony.
- **Substrate as MCP server:** emit MRTR *only* for subclass 3;
  operator-consequential events are chain-anchored ceremonies invisible to
  MRTR.
- **Neither direction co-implements MRTR and P9 as one mechanism.** They
  share no receipt schema, no signature key, no chain artifact, no UX
  surface, and no priority tier in the Cognitive Input Plane.

The classifier is the disposition. The substrate does not "adopt MRTR into
P9" and does not "replace P9 with MRTR"; it treats MRTR as an inference-
plane transport detail that composes with, but does not intersect, the
authority-plane ceremony P9 names.

---

## §4 Q3: Chain-anchored identity through three interop surfaces

**Question restated:** The MCP 2026-07-28 authorization model, AGNTCY's
Identity spec (W3C DIDs + Verifiable Credentials + IdP conventions), and the
IETF AAT/DRP/DAAP/PEDIGREE draft cluster together define at least three
overlapping "how does an identity present itself" surfaces. What does the
substrate's chain-anchored, Genesis-rooted identity look like when presented
through each?

**Short answer.** ZP's canonical identity vocabulary is Genesis-rooted,
chain-anchored, receipt-carried. Each surface projects a *different narrower
subset* of that vocabulary, and each subset is either lossless (structural
addition present or not required) or lossy in a specific, nameable way. The
smallest structural addition that would make all three surfaces lossless
simultaneously is a **canonical URL projection of Genesis** (the same
addition Q1 identifies for `iss` and CIMD `client_id`) plus a
**JCS-canonical serialization mode for receipts** matching RFC 8785.

### §4.1 Vocabulary alignment across surfaces

The four load-bearing concepts each surface names:

| ZP primitive (KEEL Part IV) | MCP 2026-07-28 | AGNTCY Identity | IETF AAT / cluster |
|---|---|---|---|
| **The identifier** | client_id (HTTPS URL under CIMD); issuer identifier (URL); resource identifier (URL under RFC 8707) | DID (W3C), IdP-issued account, well-known URL (Google A2A) | URI (`urn:agent:*`), agent_id, `aid:` URN (draft-drake) |
| **The proof** | Bearer access token (opaque); JWT if private_key_jwt is used; TLS certificate chain | Verifiable Credential (VC) bound to the identifier; ResolverMetadata for automated resolution | ECDSA P-256 signature over JCS-canonicalized record; TPM/PIV/enclave-anchored key (draft-drake) |
| **The delegation record** | OAuth authorization grant (transient; opaque); scope list; refresh token | Agent Badge (schema + metadata + locators); resolver-mediated (partial) | action_type: `delegation` record with parent chain (AAT §1) |
| **The audit trail** | (Effectively out of scope; OAuth is not an audit spec) | (Referenced as future work in AGNTCY docs; not the identity spec's focus) | SHA-256 hash chain per JCS canonicalization; monotonic timestamps; session-scoped; retention policies |

Two observations from this table:

1. **The four axes are not independent.** MCP's identifier is the same as
   its audit trail's identifier (both are the client_id URL); AAT's identifier
   is separate from its proof (the identifier is a URI; the proof is a
   signature over a JCS blob). ZP's four are structurally the same — Genesis
   is the identifier's root, receipts are both proof and audit trail, and
   delegation records are receipts of a specific type.
2. **Each surface names a subset ZP already carries as one thing.** ZP does
   not need to *add* audit-trail structure to interoperate with AAT; its
   receipt chain per KEEL §II.2 is the audit trail, richer than AAT's spec.
   ZP does not need to *add* a delegation-record type to interoperate with
   AGNTCY's Agent Badge; its `delegation:granted:*` receipts are the record,
   with per-capability justifications AGNTCY's schema does not describe.
   What ZP *does* need is projections — presenting the same underlying
   substrate identity in each surface's vocabulary.

### §4.2 Per-surface presentation of ZP identity

#### §4.2.1 Presenting ZP identity through MCP 2026-07-28

Direct field mapping, drawing on Q1 §2.4:

- **Identifier presented:** CIMD `client_id` derived as an HTTPS URL keyed
  on the Genesis pubkey fingerprint. Substrate hosts a JSON metadata document
  at that URL containing `client_id`, `client_name` (Regent's name if named;
  substrate identity string if pre-named), `redirect_uris` (proxied through
  substrate-controlled endpoint), and optionally JWKS derived from the
  substrate's signing keys.
- **Proof presented:** OAuth Bearer token issued by an authorization server
  the substrate has admitted. If the AS is substrate-hosted (substrate-as-AS
  shim), the token binds to Genesis-derived audience. If external, the token
  is opaque to the substrate — the shim adapter holds it.
- **Delegation record presented:** OAuth scope + `resource` parameter. The
  substrate's underlying `delegation:granted:*` receipt is *not* presented;
  only its projection into scope strings is.
- **Audit trail presented:** none. OAuth does not carry an audit trail in
  the presentation; the substrate retains its own chain-anchored evidence
  independently.

**Mapping quality:** identifier lossless-with-projection, proof lossy
(Bearer-as-passed-through drops signature semantics), delegation lossy
(scope strings drop capability structure), audit trail not-in-surface.

**Smallest structural addition for lossless mapping:** a `client_id` URL
scheme that resolves back to a Genesis pubkey via a deterministic reverse
projection. If the substrate's `client_id` is
`https://<genesis-fingerprint>.zp/client.json` (or resolves via a DNS-over-
HTTPS pattern with the fingerprint as subdomain), the URL round-trips to the
Genesis root without a directory lookup. This is a hosting adapter (same as
Q1 §2.3 caveat), not a substrate change.

#### §4.2.2 Presenting ZP identity through AGNTCY

- **Identifier presented:** two options match AGNTCY's supported formats.
  (a) DID (W3C): a `did:key` derived from Genesis pubkey is a lossless
  projection — Ed25519 encodes cleanly as `did:key:z6Mk*`. (b) well-known
  URL: same HTTPS-under-Genesis-fingerprint pattern as MCP CIMD, hosted at
  `/.well-known/agent.json` per Google A2A convention.
- **Proof presented:** a Verifiable Credential signed by Genesis, whose
  `credentialSubject.id` is the DID or well-known URL, and whose
  `credentialSubject` contains the substrate's declared capability manifest
  per EXTENSION-SURFACE §"Declaration structure". VCs are JSON-LD; the
  substrate's manifest is TOML — a serialization adapter is required. Signing
  is Ed25519 (compatible with W3C's `Ed25519Signature2020` proof suite).
- **Delegation record presented:** Agent Badge, populated from the
  substrate's `delegation:granted:*` receipts. Each active grant becomes a
  Badge entry; each revocation retires the Badge. Because Badge is 1:n
  (AGNTCY §3), multiple concurrent capability delegations project cleanly.
- **Audit trail presented:** AGNTCY does not require one; the substrate
  retains its chain locally. No projection required.

**Mapping quality:** identifier lossless (DID via `did:key`), proof lossless-
with-serialization-adapter, delegation lossless (structure preserved),
audit not-in-surface.

**Smallest structural addition for lossless mapping:** a JSON-LD serializer
for capability manifests that emits a VC-compatible envelope. This is
extension-side, not substrate-side. **No substrate change required.**

**Smallest structural addition for AGNTCY to consume ZP identity natively
(without translation):** AGNTCY would need to accept receipt-chain-anchored
delegation records as an alternative to VC-shaped Agent Badges. That is not
a ZP change — it is an AGNTCY spec change out of ZP's control. The
substrate presents through the translation layer.

#### §4.2.3 Presenting ZP identity through IETF-cluster (AAT as representative)

The IETF cluster (AAT, `draft-drake-agent-identity-registry`, `draft-sharif-
agent-audit-trail`, `draft-narajala-courtney-ansv2`, adjacent WIMSE and
agent-auth drafts) is not a single spec. Per the handoff's scope constraint,
this section treats the cluster as one surface with a summarized shape,
using AAT as the concrete instance because its normative content was read
at primary and the shape aligns with ZP most directly.

- **Identifier presented:** URI. AAT specifies `urn:agent:*` format; draft-
  drake specifies the `aid:` URN with TPM/PIV/enclave anchoring. Both are
  URI-shaped and both accept a substrate-side projection. ZP's canonical
  form under this surface: `urn:zp:genesis:<fingerprint>` (proposed; no
  such URN scheme is currently registered).
- **Proof presented:** ECDSA P-256 signature per AAT. **Mismatch with ZP.**
  KEEL §II.1 fixes Ed25519 as the substrate's signing algorithm. Two
  responses: (a) a per-emission co-signature — the substrate signs with
  Ed25519 for its own chain and additionally with an ECDSA-P256 key
  Genesis-certified via provisioning receipt (§II.6 shape), presented only
  when the AAT projection is emitted; (b) an algorithm-agility argument
  applied to AAT — advocate in the IETF cluster for Ed25519 acceptance. The
  first is the substrate-side change; the second is out of scope.
- **Delegation record presented:** AAT `action_type: "delegation"` records
  chain cleanly from `delegation:granted:*` receipts. AAT's per-record
  `parent_record_id` and `prev_hash` (SHA-256 over JCS-canonicalized prior
  record) can be projected from ZP's per-receipt Blake3 `ch` field plus the
  `pr` predecessor linkage (KEEL §II.2), but with an algorithm mismatch —
  ZP uses Blake3, AAT uses SHA-256. A projection adapter emits a
  SHA-256-hashed JCS record derived from each ZP receipt.
- **Audit trail presented:** the ZP receipt chain projects into an AAT
  session-scoped record chain. Both are append-only, both are hash-linked,
  both preserve monotonic timestamps. The projection is not lossless — ZP's
  chain semantics are richer (§V.2 Peer-Verification Contract; §II.11
  canonicalization ceremony; §III.13 chain-is-truth) — but the AAT-visible
  subset is preserved.

**Mapping quality:** identifier lossless-with-URN-registration (proposed
URN scheme), proof lossy (Ed25519 vs ECDSA P-256; requires co-signing or
IETF-side change), delegation lossy (hash algorithm mismatch; requires
projection adapter with SHA-256 re-hash), audit lossy (rich semantics
flattened to AAT's subset).

**Smallest structural addition for lossless mapping:** three separate things.
(a) Register a `urn:zp:*` URN namespace — not a substrate change; a public
process. (b) Add optional ECDSA-P-256 signing key derivation to KEEL §II.6
officer signing (a substrate binary change, KEEL §III.6 release chain). (c)
Ship a JCS-canonical projection mode for receipts alongside the current
MessagePack wire format (Layer B canonicalization ceremony; not a substrate
binary change). Only (b) is Layer A.

**Smallest structural addition for the IETF-cluster to consume ZP identity
natively:** the cluster would need to accept Ed25519 signatures (via
`draft-sharif` addendum) and Blake3 hashing (unlikely; Blake3 is not IETF-
standardized). More likely path: ZP publishes an IETF-adjacent bridge
document proposing algorithm agility. Not this session's work.

### §4.3 Cross-surface synthesis table

The three surfaces at once, per ZP primitive:

| ZP primitive | MCP presents as | AGNTCY presents as | IETF/AAT presents as |
|---|---|---|---|
| **Genesis pubkey** | CIMD `client_id` URL (Genesis-fingerprint-hosted) | `did:key:<Ed25519>` OR well-known URL | `urn:zp:genesis:<fingerprint>` (proposed) |
| **Genesis-signed receipt** | *(not in surface — held on chain locally)* | Verifiable Credential (VC) envelope | AAT record (JCS + SHA-256 rehash) |
| **Delegation receipt** | OAuth `scope` string projection + `resource` param | Agent Badge (1:n) | `action_type: "delegation"` AAT record |
| **Capability manifest** | Fine structure lost; scope strings only | Preserved in VC `credentialSubject` (JSON-LD) | Reduced to AAT `action_detail` JSON blob |
| **Revocation receipt** | *(not in surface — server-side token invalidation)* | Badge retirement | AAT `action_type: "delegation"` with `outcome: "denied"` supersession |
| **Provisioning receipt** | *(not in surface — implicit in AS trust)* | ResolverMetadata (1:1) | AAT genesis record (`parent_record_id: null`, `prev_hash: null`) |
| **Chain integrity** | *(not in surface)* | *(not in surface — AGNTCY does not carry chain semantics)* | Preserved via `prev_hash` chain (algorithm-mismatched but shape-preserved) |

### §4.4 The smallest structural addition summary

Consolidating across §4.2.1 – §4.2.3, the additions ZP *would* need to make
each surface lossless (from ZP → surface):

- **MCP:** a hosting adapter for CIMD documents at a Genesis-derivable
  HTTPS URL. Layer B; ceremony-amendable. **No substrate change.**
- **AGNTCY:** a JSON-LD serializer for capability manifests. Extension-side.
  **No substrate change.**
- **IETF-cluster (AAT):** URN namespace registration (public process); JCS
  canonical serialization mode for receipts (Layer B, ceremony-amendable);
  optional ECDSA-P-256 co-signing (Layer A, release chain — KEEL §III.6).

**One structural addition would satisfy all three at once:** a substrate-
side canonical URL projection of Genesis — the HTTPS URL from which the
substrate serves its own identity metadata document. Every surface's
identifier reduces to that URL (MCP: `client_id`; AGNTCY well-known: the URL
itself; IETF-cluster: the URL as the `agent_id` URI). The projection is a
hosting adapter and a canonicalization ceremony; it is not a Layer A
change.

The Layer A candidate — ECDSA-P-256 co-signing for IETF-cluster
interoperability — is called out here so future substrate binary work can
evaluate whether interoperability warrants the release-chain amendment cost
per §III.6. It is not this session's work to decide that.

### §4.5 Surfaces consuming ZP natively — the inverse direction

For each surface, the smallest structural addition the *surface* would need
to consume ZP identities natively (without a translation adapter):

- **MCP:** accept a receipt-chain-anchored delegation as an alternative to
  OAuth scope. Would require an MCP SEP; ZP could author.
- **AGNTCY:** accept a receipt-chain envelope as an alternative to VC.
  Would require an AGNTCY spec revision; ZP could contribute upstream.
- **IETF-cluster:** accept Ed25519 signatures and Blake3 hashing as
  alternatives to ECDSA P-256 and SHA-256. Unlikely to be adopted in the
  short term (both are established IETF choices); more realistically ZP
  proposes a `draft-*` extension.

All three inverses are external process work, not substrate work. Recording
them here is per the handoff's constraint: *"Name the design decisions;
leave implementation to a future session."*

---

## §5 Cross-cutting patterns

Three patterns appear in more than one of Q1/Q2/Q3 and may deserve
substrate-level naming. Named here per the handoff's instruction that
patterns become candidates for CLAUDE.md heuristics only after the two-
instance rule fires. Each is tagged with the sections that instantiate it.

### §5.1 Pattern: "Identifier projection over Genesis, hosted as URL"

Instances: Q1 §2.3 (CIMD `client_id` from Genesis fingerprint), Q3 §4.2.2
(AGNTCY well-known URL from Genesis fingerprint), Q3 §4.2.3 (`urn:zp:*` URN
from Genesis fingerprint), Q3 §4.4 (one addition to satisfy all three).

**Statement:** every mainstream identity interop surface wants an
identifier of the form URL-or-URN. The substrate's canonical identifier is
a Genesis pubkey. A single hosting adapter that publishes a canonical URL
derived from the Genesis pubkey fingerprint, at which the substrate's
identity metadata document is served, satisfies every surface's identifier
requirement simultaneously. Each surface then projects the metadata
document into its own vocabulary via a serialization adapter (JSON for
CIMD; JSON-LD for VC; JSON with URN for AAT).

**Two-instance test:** four instances across two questions; passes.
Candidate for CLAUDE.md heuristic: *One canonical URL projection of Genesis
satisfies every identity interop surface's identifier requirement.*

### §5.2 Pattern: "Transport-layer round-trip is not authority ceremony"

Instances: Q2 §3.2 (MRTR vs P9), and by structural analogue Q1 §2.4 (OAuth
step-up on `insufficient_scope` vs `regent:proposal:{verb}` +
delegation amendment).

**Statement:** MCP's various mid-flow request/response mechanics (MRTR for
data completion, step-up authorization for scope expansion, `WWW-
Authenticate` scope challenges) all have a superficial round-trip shape
that resembles the substrate's proposes/signs ceremony. In every instance
the two are structurally different: the transport-layer round-trip settles
*inside* an already-authorized session, whereas the substrate ceremony
settles *whether the session is authorized at all*. Co-implementing the two
loses the distinction between "I need more information" and "I need your
permission."

**Two-instance test:** two instances across one question (Q2's MRTR/P9 plus
Q1 §2.4's step-up/proposal); marginal. Not yet a candidate for CLAUDE.md
without a third instance from a future session.

### §5.3 Pattern: "Fine-grained ZP scopes are strictly richer than every
interop surface's authorization vocabulary"

Instances: Q1 §2.2 (OAuth scope strings vs `delegation:granted:extension:*`
capability manifest), Q3 §4.2.1 (MCP presentation loses capability
structure), Q3 §4.2.2 (AGNTCY VC preserves structure via JSON-LD; only
surface that does), Q3 §4.2.3 (AAT flattens capability manifest to JSON
blob in `action_detail`).

**Statement:** the substrate's declared capability manifest per
`EXTENSION-SURFACE-2026-07` §"Declaration structure" — fine-grained filter
patterns, per-capability justifications, endpoint allowlists, rate limits,
inference bounds — has strictly more structure than any interop surface's
authorization vocabulary. Projection from ZP → surface is lossy in every
direction *except* AGNTCY (which alone preserves structure via JSON-LD VCs).
When choosing which surface to lead with for interop, AGNTCY has the
lowest structural loss.

**Two-instance test:** four instances across two questions; passes.
Candidate for CLAUDE.md heuristic: *ZP's capability manifest is richer than
every OAuth-family authorization scope vocabulary; AGNTCY is the only
surface that preserves the structure end-to-end.*

Cross-cutting patterns beyond these three (e.g., "ZP revocation is
asymmetric-and-stronger than every surface's; ZP audit trail is richer than
every surface's carried metadata") appear only within one question and do
not meet the two-instance test.

---

## §6 What this composition analysis DOES NOT decide

Explicit non-decisions, each with a proposed follow-on session scope. Per
the handoff's success criterion, this is the "clean menu" of what the
analysis makes reachable.

### §6.0 The actual shape of the menu

Read as seven items, this section looks like a long queue. It is not. The
geometry:

- **One substantive addition that pays for itself three ways: §6.2** (the
  canonical URL projection of Genesis). Per §5.1 the *same* addition closes
  the identifier gap in Q1's CIMD `client_id`, Q3 §4.2.2's AGNTCY well-known
  URL, and Q3 §4.2.3's IETF-cluster URN. Most of "harmonizing MCP with the
  substrate" is that single hosting adapter.
- **One small independent piece: §6.4** (JCS-canonical receipt
  serialization mode). Layer B canonicalization ceremony, no dependencies,
  small scope.
- **Two gated on prior open work: §6.1 and §6.3.** §6.1 (MCP-as-Extension
  ceremony) is blocked on QUARANTINE-PLANE §Open positions "instruction-
  shaped artifacts carrying authority" — an unrelated design pass that has
  to land first. §6.3 (MRTR classifier) is blocked on §6.1. Neither is
  work this analysis unblocks.
- **Three parked by explicit statement: §6.5, §6.6, §6.7.** §6.5 (ECDSA
  co-signing) is a Layer A candidate this analysis explicitly declines to
  commit to. §6.6 (EMA / enterprise identity) is deliberately out of scope
  for this session *and* the six IETF/AGNTCY/MCP sessions already queued
  behind it. §6.7 is strategic, not implementation. All three are recorded
  so a future session does not rediscover them, not because they are
  queued for work.

**The honest shape:** most of MCP composes with the substrate *by
construction* — the field tables in §2.4 and §4.3 are dense with satisfied-
by-construction entries. What is genuinely new is one hosting adapter and
one canonicalization ceremony. The rest is either transport-side shim work
an extension can do without touching the substrate, or it is deferrals
with named preconditions.

### §6.1 The MCP-as-Extension canonicalization ceremony

**Reached by:** Q1 §2.5 (existing `delegation:granted:extension:*` shape
covers MCP server admission via ProtocolAdapterExtension).

**Not decided:** the specific Layer B canonicalization ceremony that binds
an MCP server adapter as a canonical extension, including:

- WASM module implementing ProtocolAdapterExtension trait for MCP protocol
- Manifest schema for the MCP-server-specific capability declarations
  (which tools, which resources, which OAuth scopes to request, which
  audience URI to advertise)
- Chain-anchored `mcp:server:admitted:<canonical_uri>:<content_hash>`
  receipt shape

**Follow-on session scope:** Sonnet-tier CLIC to author the MCP
ProtocolAdapterExtension trait implementation + manifest schema + admission
ceremony spec. Named blocked on: EXTENSION-SURFACE §Open positions
"instruction-shaped artifacts carrying authority" (referenced in
QUARANTINE-PLANE §Open positions 2026-08-14) — an MCP server's tool
descriptions are exactly instruction-shaped artifacts, and the constraint
that the substrate has no admission ceremony for them applies here directly.
Sequence this session *after* that design pass, not concurrently.

### §6.2 The CIMD hosting adapter

**Reached by:** Q1 §2.3 (CIMD requires HTTPS URL; substrate does not
universally provide one), Q3 §5.1 (single URL adapter satisfies every
surface).

**Not decided:** where the substrate hosts its canonical identity metadata
document, how the URL is derived from Genesis, how updates (Regent renaming,
active-presence handoff) propagate to the hosted document, how the substrate
falls back when hosting is unavailable.

**Follow-on session scope:** Opus-tier session on the identity hosting
adapter. Composes with: SUBSTRATE-FORM (per-Form hosting affordances),
NAMING-CEREMONY (client_name updates), V.4 handoff (redirect_uris updates),
PEER-DISCOVERY (fallback to peer-published metadata). This is a design pass
worth its own tier because it lands one addition that resolves the identifier
gap in all three interop surfaces.

**Landed 2026-09-01:** `docs/design/IDENTITY-HOSTING-ADAPTER-2026-09.md` is the follow-on session named above. It makes the four decisions precise — URL scheme, per-Form hosting model, JWKS scope, `client_name`/`redirect_uris` derivation — and hands each a recommendation for Ken to sign off on. It ships as a design proposal, plus an unregistered `crates/zp-identity-hosting/` scaffold (types and signatures, `todo!()` where a decision is still Ken's) — not a full implementation.

### §6.3 The MRTR classifier implementation

**Reached by:** Q2 §3.3 (classification rule) and §3.4 (substrate-emitted
MCP server rule).

**Not decided:** the specific schema-shape test that maps an inbound
`ElicitRequest` into subclass 1/2/3, the chain-anchored evidence a
subclass-1 elicitation produces (does it emit a `regent:proposal:*`
receipt or a more specific `mcp:elicitation:as_proposal:*` shape?), and
whether the classifier lives in the MCP adapter or in the gate.

**Follow-on session scope:** Sonnet-tier implementation session, blocked
on §6.1 (MCP adapter must exist first). Includes conservative-classification
defaults and adversarial tests for the failure modes named in §3.3.

### §6.4 The JCS-canonical receipt serialization mode

**Reached by:** Q3 §4.2.3 (AAT interop requires JCS canonicalization) and
§4.4 (one of two additions for lossless IETF-cluster mapping).

**Not decided:** whether the substrate ships a JCS mode alongside its
current canonical MessagePack wire format, at what tier of canonicalization
ceremony (per KEEL §II.11 tier gates), and whether the JCS output is
verified independently or derived deterministically from the MessagePack
canonical.

**Follow-on session scope:** Sonnet-tier canonicalization ceremony
authoring session. Small scope. Named blocked on: nothing — this can land
independently as a Tier 2 canonicalization amendment.

### §6.5 The ECDSA-P-256 co-signing option

**Reached by:** Q3 §4.2.3 (AAT/IETF-cluster proof mismatch) and §4.4
(Layer A candidate).

**Not decided:** whether the substrate accepts a KEEL amendment to §II.6
officer signing to include ECDSA P-256 as a permitted signing algorithm
alongside Ed25519, for the specific purpose of external attestation to
IETF-cluster consumers.

**Follow-on session scope:** Opus-tier substrate binary release discussion.
This is a KEEL §III.6 amendment (release chain, not ceremony); do not
sequence it until the IETF cluster's adoption trajectory is clearer per the
sweep log's "Low confidence on IETF direction of travel" framing.
Explicitly *do not* commit to this addition on the strength of this
composition analysis alone.

### §6.6 The EMA (Enterprise-Managed Authorization) composition surface

**Reached by:** §1.3 (EMA ships as MCP's first official extension).

**Not decided:** how a substrate operator whose employer uses Okta/Entra/Auth0
under the EMA extension composes their sovereign identity with the
employer's IdP-managed authorization. The composition of substrate
sovereignty with enterprise identity providers is exactly the case KEEL
§III.1 (sovereignty is not delegated upward) and §III.23 (coordination,
not oversight) frame.

**Follow-on session scope:** Opus-tier session on cross-authority
composition. Composes with: III.23 (coordination discipline), CROSS-SUBSTRATE-
PEER-CONTRACT-2026-06 (peer-to-peer trust anchor structure), and future
work on operator-in-employment-context (not currently a substrate concern
but likely to become one as substrate adoption enters enterprise settings).
This is deliberately out of scope for this analysis, and out of scope for
the six previous IETF/AGNTCY/MCP sessions the log has queued behind it.

### §6.7 The strategic decision — should ZP publish an MCP server per the
2026-07-28 spec at all

**Reached by:** the whole analysis. The composition is feasible; the
question of whether it should be undertaken is strategic.

**Not decided:** whether ZP publishes canonical MCP servers as the primary
interop surface, treats MCP as one adapter among many via
ProtocolAdapterExtension, or refuses MCP interop in favor of a substrate-
native protocol.

**Follow-on session scope:** strategic session, not a Sonnet or Opus
implementation. This analysis informs that decision but does not decide it.

---

## Appendix A — SEP-by-SEP notes taken during primary reads

Preserved per the handoff's discipline pin: raw notes so the next reader
can verify.

### Stateless core

- **SEP-2575:** removes `initialize` / `notifications/initialized`; every
  request carries protocol version + client capabilities in `_meta`; adds
  `server/discover` RPC (MUST implement server-side); replaces HTTP GET
  and `resources/subscribe`/`unsubscribe` with `subscriptions/listen`
  (single long-lived POST-response stream, opt-in change notifications);
  removes `ping`, `logging/setLevel`, `notifications/roots/list_changed`
  (log level now via `_meta`); removes SSE stream resumability (broken
  stream → client MUST re-issue as new request with new id).
- **SEP-2567:** removes `Mcp-Session-Id` header and the protocol-level
  session it identified. Servers needing cross-call state use server-
  minted handles as ordinary tool arguments.
- **SEP-2322:** MRTR — `InputRequiredResult` with `inputRequests` /
  `requestState`; all results carry `resultType` field (`"complete"` |
  `"input_required"`); replaces `roots/list` / `sampling/createMessage` /
  `elicitation/create` server-initiated pattern (breaking change);
  removes `notifications/elicitation/complete` and `elicitationId` fields
  from 2025-11-25 URL-mode elicitation.
- **SEP-2243:** requires `Mcp-Method` and `Mcp-Name` headers on Streamable
  HTTP POST; adds `x-mcp-header` for custom headers from tool parameters.
- **SEP-2549:** adds `ttlMs` and `cacheScope` (`"public"` | `"private"`) to
  list results via new `CacheableResult` interface; freshness hint for
  client-side caching; complements `listChanged` notifications.
- **SEP-414:** documents OpenTelemetry trace context propagation in
  `_meta` (`traceparent`, `tracestate`, `baggage`).

### Authorization hardening

- **SEP-2468:** RFC 9207 `iss` validation. AS SHOULD include `iss` in
  authorization responses (incl. error responses); if AS advertises
  `authorization_response_iss_parameter_supported: true`, present-`iss`
  MUST be compared to recorded issuer via simple string comparison (RFC
  3986 §6.2.1); on mismatch client MUST NOT act on / display `error`,
  `error_description`, `error_uri`. Third row of the validation table:
  local-policy provision — compare present `iss` to recorded even if AS
  didn't advertise.
- **SEP-837:** MCP clients using DCR MUST specify `application_type`
  (`"native"` vs `"web"`) to avoid OpenID Connect redirect URI conflicts.
- **SEP-2352:** client credentials bound to issuing AS — MUST key
  persisted credentials by issuer identifier; MUST NOT reuse with
  different AS; MUST re-register on AS change. CIMD credentials are
  portable (self-hosted URL resolved on demand).
- **SEP-2207:** identified in release blog but not surfaced in the
  changelog scan; possibly consolidated. Not read at primary this session.
- **SEP-2350:** same. Not read.
- **SEP-2351:** same. Not read.
- **PR #2858:** DCR deprecated in favor of CIMD. DCR remains for backwards
  compatibility with AS that do not support CIMD.

### Adjacent

- **SEP-2577:** deprecates Roots, Sampling, Logging; twelve-month minimum
  deprecation window; suggested migrations noted in §1.4.
- **SEP-2596:** feature lifecycle & deprecation policy (Active / Deprecated /
  Removed states); reclassifies HTTP+SSE transport and `includeContext`
  `"thisServer"` / `"allServers"` as Deprecated.
- **SEP-2663:** Tasks moves out of core into official extension
  (`io.modelcontextprotocol/tasks`); polling via `tasks/get`; client-to-
  server input via `tasks/update`; removes `tasks/list` and blocking
  `tasks/result`.
- **SEP-1865:** MCP Apps — interactive UI elements rendered inline. Named
  in overview; specification not read at primary this session.
- **SEP-2106:** JSON Schema 2020-12 for `inputSchema` / `outputSchema` /
  `structuredContent`; `$ref` resolution requirements; composition-keyword
  resource bounds.
- **SEP-2484:** conformance gate on Final. Referenced by release blog as
  the conformance mechanism gating final release; not read at primary this
  session.
- **SEP-2133:** extensions framework — `extensions` field on
  `ClientCapabilities` / `ServerCapabilities`.

Explicit not-read-at-primary-this-session (per handoff Rule 5 caveat):
SEP-2207, SEP-2350, SEP-2351, SEP-1865, SEP-2484. Their content is
represented in Appendix A only by the release blog's summary framing;
not carried into the load-bearing analysis in §2–§4.

---

## Appendix B — Verbatim quotes used as load-bearing evidence

Preserved so future readers can verify the primary-source grounding.

### From KEEL-2026-07.md

- **§II.13.9 (P9):** *"The system acts; the operator signs — every
  consequential action requires operator authority."*
- **§II.5 (Decision A):** *"Every sovereign has exactly one Genesis
  keypair as the single root of trust."*
- **§II.19:** *"The substrate has one composition primitive: WASM modules
  implementing declared trait interfaces, chain-anchored via
  canonicalization ceremony, with capability delegation Genesis-derived
  from the operator per EXTENSION-SURFACE-2026-07.md."*
- **§III.9:** *"Every action the substrate takes traces to threshold M-of-N
  humans consenting through their individual Geneses."*
- **§III.18 (Delegable safety):** *"Every structural restriction the
  substrate imposes must have a corresponding chain-anchored delegation
  path by which the operator can, deliberately and reversibly, grant
  admission — without disabling the restriction for anything else."*
- **§III.19 (Detectability):** *"Silence is the enemy, not compromise."*
- **§II.6:** *"Officers hold their own hardware-backed keys, locally
  generated on the substrate host's hardware, Genesis-certified via
  provisioning receipt."*

### From MCP 2026-07-28 spec

- **Changelog major #2 (SEP-2575):** *"Make MCP stateless: remove the
  initialize/notifications/initialized handshake. Every request now
  carries its protocol version and client capabilities in `_meta`."*
- **Changelog major #7 (SEP-2322):** *"Multi Round-Trip Requests (MRTR)
  pattern introduced which replaces the previous approach of sending
  server-initiated requests. […] Servers return an `InputRequiredResult`
  (`resultType: "input_required"`) whose `inputRequests` field carries
  the requests for the additional information needed to process the
  request. Clients respond with `inputResponses` on a retry of the
  original request providing the requested information."*
- **Changelog minor #7 (SEP-2468):** *"Authorization servers **SHOULD**
  include the `iss` parameter in authorization responses per RFC 9207,
  and MCP clients **MUST** validate a present `iss` against the recorded
  issuer before redeeming the authorization code."*
- **Changelog minor #9 (SEP-2352):** *"Clients **MUST** key persisted
  credentials by the issuer identifier, **MUST NOT** reuse them with a
  different authorization server, and **MUST** re-register when the
  authorization server changes."*
- **Client Registration §CIMD:** *"The `client_id` URL **MUST** use the
  "https" scheme and contain a path component […] The metadata document
  **MUST** include at least the following properties: `client_id`,
  `client_name`, `redirect_uris` […] Clients **MUST** ensure the
  `client_id` value in the metadata matches the document URL exactly."*
- **Client Registration §Authorization Server Binding:** *"Client IDs
  based on Client ID Metadata Documents are portable across authorization
  servers, since they are self-hosted HTTPS URLs resolved by the
  authorization server on demand. No re-registration is needed when the
  authorization server changes."*
- **MRTR spec, client requirements:** *"If a client receives an
  `InputRequiredResult` that contains the `inputRequests` field, the
  client **MUST** construct the requested inputs before retrying the
  original request. […] If an `InputRequiredResult` contains the
  `requestState` field, the client **MUST** echo back the exact value
  of that field when retrying the original request. Clients **MUST NOT**
  inspect, parse, modify, or make any assumptions about the
  `requestState` contents."*
- **MRTR spec, server requirements:** *"Servers **MUST** treat
  `requestState` as an attacker-controlled input. If `requestState`
  influences authorization, resource access, or business logic, servers
  **MUST** protect its integrity (e.g. HMAC or AEAD) and **MUST** reject
  state that fails verification."*
- **MRTR spec, supported requests:** *"Servers **MAY** send
  `InputRequiredResult` responses on the following client requests:
  `prompts/get`, `resources/read`, `tools/call`. Servers **MUST NOT**
  send `InputRequiredResult` responses on any other client requests."*
- **MRTR spec, input request types:** *"`inputRequests` values are
  request objects that **MUST** be one of `ElicitRequest`,
  `CreateMessageRequest`, or `ListRootsRequest`."*
- **Authorization §Overview #3:** *"Note that Dynamic Client Registration
  is deprecated and retained for backwards compatibility with
  authorization servers that do not support Client ID Metadata Documents."*
- **Authorization §Access Token Usage:** *"MCP servers **MUST** validate
  that access tokens were issued specifically for them as the intended
  audience […]. MCP servers **MUST NOT** accept or transit any other
  tokens."*

### From AGNTCY Identity spec

- **Identity requirements:** *"**Open**: No centralized authority is
  required for assigning identities. **Collision-free**: Each entity
  (Agent, MCP Server, or MAS) has a universally unique identifier.
  **Verifiable**: Each entity is backed by a Verifiable Credential (VC)
  that can be used to authenticate its ID and provenance."*
- **Scope:** *"This framework applies equally to: Agents, Model Context
  Protocol (MCP) Servers, MASs (Multi-Agent Systems)."*
- **Focus:** *"At this stage the main focus of the AGNTCY is to provide
  a common and trustworthy mechanism to present identifiers and to
  verify them."*
- **Agent Badge:** *"An `Agent` subject is tied to a unique identifier
  linked to one or more Verifiable Credentials (VCs), which contain
  information about the Agent, such as its ID, a schema definition
  (e.g., an OASF schema), and other metadata used for defining locators,
  authentication, MFA, etc."*

### From IETF draft-sharif-agent-audit-trail

- **Hash chaining:** *"Take the complete JSON object of the previous
  record, INCLUDING all fields (mandatory and optional) that were
  present in the record as stored. Serialize the JSON object using the
  JSON Canonicalization Scheme (JCS) defined in RFC 8785. Compute the
  SHA-256 hash of the canonical byte sequence."*
- **Signing:** *"Sign the hash using ECDSA P-256 with the agent's
  private key, per FIPS 186-5. Encode the signature as Base64url […]
  using IEEE P1363 fixed-length r||s encoding (64 bytes total: 32
  bytes r, 32 bytes s)."*
- **Chain invariant:** *"Each record's parent_record_id MUST equal the
  previous record's record_id […] Each record's prev_hash MUST equal
  hex(SHA-256(JCS(previous_record))) […] Timestamps MUST be
  monotonically non-decreasing."*
- **Genesis records:** *"parent_record_id MUST be null and prev_hash
  MUST be null."*
- **Compliance mapping:** *"direct mapping to EU AI Act Article 12
  requirements."*

### From ZP corpus (Tier 2)

- **EXTENSION-SURFACE-2026-07 §"Delegation semantics":** *"`delegation:
  granted:extension:<wasm_hash> { granted_by: operator_genesis,
  granted_at: timestamp, capabilities: { chain_read: [...], chain_write:
  [...], network_egress: [...], filesystem: { read: [...], write: [...] },
  inference_backend: { max_calls_per_hour: N, max_tokens_per_call: M },
  host_functions: [...] }, scope_narrowing_notes: "...", expiry:
  optional_timestamp, revocation_priority: high | normal, justification:
  "..." }`"*
- **EXTENSION-SURFACE-2026-07 §Framing:** *"The unifying insight: an
  extension is just a WASM module with a canonical trait interface,
  chain-anchored delegation, and Genesis-derived signing authority."*
- **QUARANTINE-PLANE-2026-07 §Step 2 amendment 2026-08-14:** *"A
  `quarantine:attestation:<surface>:<hash>` receipt carrying an explicit
  `authority: none` marker. […] It does not satisfy the signature check,
  does not advance the ceremony, and is never read by the gate — it is
  evidence placed in front of the operator at Step 3 and retained on
  chain so that a later compromise of the attesting party is traceable
  to everything it vouched for."*
- **AGENT-TOOL-CONTRACT-2026-06 §Required affordance 4:** *"An agent
  that does not declare […] cannot be gated. In MCP-tenancy mode, this
  is the tool call's named parameters and tool identifier."*
- **HARNESS-SEAM-2026-08 §5:** *"ZeroPoint is the only substrate in
  which the boundary can be cryptographically enforced. Inner can prove
  to outer what it did, via signed receipts. Outer can be granted narrow,
  revocable scope by inner, via delegation."*
- **EXECUTION-AUTHORITY-MODEL-2026-07 §Phase 7:** *"The three-part test:
  authority gate, pattern precedent, novel context. All three pass →
  act autonomously. Any fails → surface a regent:proposal:{verb}
  receipt."*

---

*Composition analysis. Amendments per KEEL Part VI (canonicalization
ceremony). Add to CANONICAL-CORPUS-INDEX-2026-07 under a new "External
protocol composition" heading once the ceremony has landed the follow-on
sessions of §6 into their own Tier 2 elaborations.*
