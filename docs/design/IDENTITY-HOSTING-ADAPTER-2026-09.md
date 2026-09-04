# Identity Hosting Adapter

**Tier 2 canonical elaboration.** Elaborates `KEEL-2026-07.md` §II.5 (Genesis-as-single-root), §XIV.1/§XIV.3 (Three Forms, Form Disclosure), §III.1 (sovereignty is not delegated upward), §III.3 (Regent's home is the operator), §III.19 (Detectability over invulnerability), and Part V.4 (Handoff protocol). Canonical claims live in KEEL.

Reached by `MCP-COMPOSITION-2026-08.md` §6.2 (the Opus-tier follow-on session named there). Composes with `SUBSTRATE-FORM-2026-07.md` (per-Form hosting affordances — the technical spec behind KEEL §XIV), `REGENT-NAMING-CEREMONY-2026-07.md` (`client_name` derivation and post-naming propagation), `EXTENSION-SURFACE-2026-07.md` §"Delegation semantics" (the admission-ceremony shape this reuses), `PEER-DISCOVERY-AS-OUTREACH-2026-07.md` and `DISCOVERY-AND-BOOTSTRAP-2026-07.md` (the substrate's existing well-known-URI precedent), and the Foundation edge-relay precedent (`docs/handoffs/foundation-worker-edge-proxy-2026-05.md`, `crates/zp-cloudflare`, `crates/zp-keys/src/foundation_edge_signer.rs`).

Draft — 2026-09-01 — internal audience only, written for operator (Ken) sign-off. Nothing in this document is canon until the decisions below are made and the doc is amended per KEEL Part VI.

---

## Framing

MCP 2026-07-28's Client ID Metadata Documents (CIMD) authorization surface requires that a client's `client_id` be an HTTPS URL that resolves, on demand, to a JSON metadata document describing that client. The same shape — an identifier that is a URL or URN, resolvable to a document describing the identity — recurs in AGNTCY's well-known-URL convention and in the IETF agent-identity cluster's URN identifiers. `MCP-COMPOSITION-2026-08.md` §5.1 names this as a single pattern: *"a single hosting adapter that publishes a canonical URL derived from the Genesis pubkey fingerprint, at which the substrate's identity metadata document is served, satisfies every surface's identifier requirement simultaneously."* The content of that document is already derivable by construction from state the substrate already has — Genesis pubkey, the naming ceremony's committed name, the active-presence handoff chain. What is not decided is the *hosting*: where the document actually lives on the public internet, reachable by an authorization server's on-demand `GET`, given that the substrate's three Forms have three different obligations and three different reaches (KEEL §XIV.1). That gap — and the three questions that ride alongside it (JWKS scope, `client_name` derivation, `redirect_uris` under a mobile active presence) — is this document's whole scope.

This document does not implement the hosting adapter. It makes the four decisions §6.2 named precise enough for Ken to pick, names what composes with each choice, and hands a future implementation session a scaffold that does not have to redo this reasoning.

---

## Decisions at a glance

| # | Decision | Recommendation |
|---|---|---|
| 1 | URL scheme | **Reject Option A** (DNS-under-controlled-TLD) outright — it is not just infrastructure ZP doesn't have, it is DNS-label-invalid for a full fingerprint and would need a KEEL-level axiom to build. Recommend a Form-scoped `HostingMode` choice between **Option B** (Foundation mirror, opt-in) and **Option D** (self-host on a domain the operator already controls) — never a literal `*.zp` TLD. |
| 2 | Hosting model per Form | **Sovereign:** Foundation mirror default, self-host override. **Appliance:** self-host default — "network reachable, unattended runtime" is Appliance Form's own defining commitment. **Companion:** Foundation mirror only, with mandatory Form Disclosure. **All Forms:** pre-registration fallback when the operator declines both. |
| 3 | JWKS scope | **Ship v1 with no JWKS** (PKCE + authorization code only — CIMD does not require it). Design, but do not build yet, a dedicated `client_auth_key` HKDF-derived from Genesis (a fourth sibling of `gate_signer` / `audit_signer` / `foundation_edge_signer`) for the day an external AS requires `private_key_jwt`. |
| 4 | `client_name` / `redirect_uris` | `client_name`: committed Regent name verbatim if named, else the fixed marker `"ZeroPoint Substrate (Regent pre-named)"`, re-published on the naming ceremony's existing post-naming propagation cycle. `redirect_uris`: **never** a per-device URL — one fixed URL at the hosting location itself, which captures the OAuth redirect server-side and lets whichever device is currently active presence collect it. This makes `redirect_uris` invariant under V.4 handoff by construction, so it never needs "updating" at all. |

---

## 1. URL scheme

### The options, read against what the substrate actually has

**Option A — `https://<genesis-fingerprint>.zp/client.json`.** Rejected, for two independent reasons, only one of which the handoff anticipated:

- The infrastructure problem the handoff named: `.zp` is not a registered TLD. Making this scheme real requires either registering/operating a real domain and wildcard-routing every possible fingerprint subdomain under it (which is Option B or D wearing an `A` costume), or a genuinely new piece of substrate-controlled DNS infrastructure. Per the stop-and-report trigger this analysis was given: committing to DNS-under-a-controlled-TLD is a KEEL-level infrastructure decision — it would need a new axiom (nothing in KEEL today asserts the substrate operates DNS infrastructure) and a release-chain-weight commitment neither this document nor a single Opus-tier design session should make on its own authority. **This document declines Option A specifically so that trigger does not have to be escalated further — the recommendation below needs no DNS axiom.**
- A finding this analysis turned up independently: `crates/zp-server/src/onboard/genesis.rs:359` computes `genesis_fingerprint` as `blake3::hash(genesis.public_key().as_ref()).to_hex()` — a full 64-character hex string (BLAKE3-256). A DNS label is capped at 63 octets (RFC 1035 §2.3.4). **The full fingerprint does not fit in a single DNS label at all**, independent of the TLD problem. Any subdomain-per-fingerprint scheme requires truncating the fingerprint (128 bits — 32 hex chars — still has effectively zero collision risk at ZP's expected sovereign-fleet scale, but truncation is itself a versioned decision this document is not making) or splitting it across labels. That is a second, independent point against Option A as literally specified, not a restatement of the first.

**Option C — IPFS or peer-published gateway.** The prompt names this as content-addressed and decentralized. Reading the actual substrate, this needs a correction: **the substrate does not implement IPFS anywhere.** `crates/zp-mesh` implements Reticulum- and libp2p-based peer transport (`reticulum_discovery.rs`, `libp2p_interface.rs`, `web_discovery.rs`) — that is ZP's actual peer-publication layer, and IPFS appears only as a surveyed-and-not-adopted candidate in `STORAGE-ABSTRACTION-2026-05.md`. More importantly, this option does not actually solve the stated problem on its own: the CIMD spec's client-registration text is unambiguous — *"The `client_id` URL **MUST** use the 'https' scheme."* An MCP authorization server has no reason to speak Reticulum, libp2p, or IPFS; it will issue a plain HTTPS `GET`. A peer-published document therefore still needs an HTTPS front door somewhere — which collapses Option C into "Option B or D, plus a peer-mesh replication layer underneath for resilience." **Recorded as a future distribution-layer enhancement in §7 (non-decisions), not as an independent fifth choice today.**

**Option B — Foundation-run mirror.** This is not new infrastructure for ZP; it is a direct sibling of infrastructure that already exists and already ships. `docs/handoffs/foundation-worker-edge-proxy-2026-05.md` plus `crates/zp-cloudflare` plus `crates/zp-keys/src/foundation_edge_signer.rs` already implement an opt-in Foundation-run Cloudflare Worker that relays operator-signed content, with a domain-separated `foundation-edge` key that can forge envelopes but never receipts — the worker's doc comment states the shape directly: *"The foundation-edge key lives on the edge, but it only signs envelopes... It never signs receipts."* A CIMD-document mirror is the same shape in the same direction: the Foundation hosts a JSON document the operator's own Genesis-derived key already signed; the Foundation cannot forge it, can only fail to serve it. That is an availability dependency, not an authority dependency — worth being precise about against KEEL §III.1 ("sovereignty is not delegated upward"): the operator's *authority* is not delegated to the Foundation by this design (nothing about substrate governance, delegation grants, or receipt signing routes through the mirror); only the *liveness* of one outward-facing interop identifier does. Per §III.19 ("Detectability over invulnerability") that dependency must be disclosed to the operator plainly, not hidden — see §2 below on Form Disclosure implications.

**Option D — substrate-hosted on the operator's own machine.** Fully viable, but its viability is Form-shaped, not universal. `SUBSTRATE-FORM-2026-07.md`'s own definition of Appliance Form's operator commitment is *"one piece of hardware, network reachable, unattended runtime"* — which is, verbatim, exactly what CIMD hosting needs. That is a strong, direct match, not an inference. Sovereign Form carries no such commitment (an operator's laptop sleeps, roams networks, sits behind NAT); Companion Form is ruled out categorically because it "runs within vendor permissions" and inbound public listeners are exactly the kind of thing vendor MDM and consumer OS network policy block. TLS and port-forwarding are real friction here (ACME HTTP-01 needs inbound 80/443; DNS-01 needs a domain the operator can add TXT records to) — this document does not pick an ACME strategy; that is implementation-session work, named in §6.

### Recommendation

Reject Option A. Treat Option C as a future replication layer under B or D, not a fifth choice. Offer a `HostingMode` that resolves to **Option B or Option D per Form**, decided in §2, with **pre-registration** as the universal no-hosting fallback for an operator who declines both (see §2, last row). No option in this recommendation requires a KEEL amendment; both B and D are Layer B (canonicalization ceremony / operator configuration), matching the disposition `MCP-COMPOSITION-2026-08.md` §2.3 already committed to: *"Neither requires substrate binary change; both are Layer B via canonicalization ceremony."*

---

## 2. Hosting model per Substrate Form

Per KEEL §XIV.1, each Form has a stated network reach. Reading that reach directly against the two surviving options from §1:

| Form | Default adapter | Why | Override / fallback |
|---|---|---|---|
| **Sovereign** | Foundation mirror (opt-in) | XIV.1: "the operator is not obligated to run a public web server." Nothing about Sovereign Form's definition implies network reachability; many sovereign operators run on laptops that sleep and roam. | Self-host (Option D), for an operator who already owns a reachable domain and is willing to run the substrate's own listener publicly. Never the default — Sovereign Form should not *require* a public surface to be a functioning MCP client. |
| **Appliance** | Self-host (Option D) | SUBSTRATE-FORM's own Appliance Form definition — "network reachable, unattended runtime" — is definitionally already true of this Form. No external dependency is needed for the common case. | Foundation mirror, for the CGNAT / ISP-blocks-inbound-443 case where "network reachable" holds on the LAN but not from the public internet. Appliance Form already delegates a daily-driver client through Genesis-signed pairing (XIV.1); this fallback is the same shape applied outward instead of inward. |
| **Companion** | Foundation mirror (only workable option) | XIV.1: "often categorically not reachable" under vendor network permissions. Option D is not offered as a choice here at all — presenting it as a live option on a Form that structurally cannot deliver it is worse than not offering it. | Pre-registration (below), for an operator who additionally declines the Foundation mirror. |
| **All Forms** | — | An operator on any Form can decline public hosting entirely. | **Pre-registration fallback**: the substrate does not silently fail to be an MCP client. Per `MCP-COMPOSITION-2026-08.md` §2.3's own framing and the spec's own "Overview #3" (DCR "retained for backwards compatibility with authorization servers that do not support CIMD"), the substrate can register static out-of-band credentials at each external AS the operator chooses to use, one at a time, operator-initiated. No hosting adapter runs; no fingerprint-derived URL exists; the substrate's Genesis identity is simply not what the external AS sees. This is not a degraded state to apologize for — it is the substrate declining an interop surface it was never obligated to offer. |

**Companion Form Disclosure implication.** XIV.3 requires Form Disclosure to be prominent, not buried, on non-canonical Forms. Because Companion Form's *only* workable CIMD-hosting path is the Foundation mirror, a Companion-Form operator who enables MCP-client interop is necessarily depending on both their OS vendor (per the existing Companion Form Disclosure text) *and* the Foundation for one identity surface. The existing disclosure string does not mention this; recommend the implementation session add one clause to the Companion Form Disclosure surface (not a new disclosure type) covering the case where CIMD hosting is active. That is a small, scoped addition — named in §6, not designed here.

---

## 3. JWKS scope

The CIMD document optionally carries a JWKS block, used for `private_key_jwt` token-endpoint authentication under confidential-client OAuth flows. The prompt names three options; reading them against the substrate's own key-derivation discipline:

- **All of Genesis-derived signing keys.** Rejected outright, and not narrowly — CIMD is published to the open internet by construction (that is the entire point of hosting it). Exposing "all of them" through a document any AS on the internet fetches is the single most externally-reachable surface any ZP key would ever sit behind. This is the wrong side of a decision the codebase has already made three times over (see below).
- **A dedicated `client_auth_key`, HKDF-derived from Genesis.** This is the shape that matches existing precedent exactly. `crates/zp-keys/src/gate_signer.rs`, `audit_signer.rs`, and `foundation_edge_signer.rs` are three near-identical modules, each deriving one purpose-scoped Ed25519 subkey via `blake3::Hasher::new_keyed(genesis_secret)` over a versioned domain-separation context string (`"zp.gate.request.v1"`, etc.), each with the same doc-comment shape explaining *why a subkey and not Genesis or a sibling key* — `gate_signer.rs`'s own words: *"Domain separation. The gate signer attests 'this HTTP request originated from an identity that holds Genesis.' Reusing Genesis directly would conflate root-of-trust authority with request-signing authority."* A CIMD-published JWKS key needs the same argument made a fourth time, for a new purpose ("this key proves possession of the identity CIMD's `client_id` names, to an external AS, nothing else") — reusing the gate signer would let a compromised JWKS entry forge gate requests; reusing the audit signer would let it forge chain-anchored evidence. Neither is acceptable for a key an external, un-vetted-by-the-operator authorization server holds a public half of. **This is the correct answer if and when a JWKS entry is needed at all** — but see the next point.
- **None — PKCE plus authorization code, no JWKS.** CIMD does not require it. The spec text this analysis already has on file only makes `client_id`, `client_name`, and `redirect_uris` mandatory; JWKS is present in CIMD specifically to support `private_key_jwt`, itself one optional token-endpoint auth method among several. A public client using PKCE has no token-endpoint credential to prove at all — the authorization code plus PKCE verifier is the whole proof. **Recommend shipping v1 with no JWKS.** This has no security cost — a key that does not exist cannot be compromised — and it removes an entire sub-decision (JWKS rotation policy, `kid` conventions, how a rotated `client_auth_key` gets announced to ASes that cached the old one) from the critical path of landing the hosting adapter at all.

### Recommendation

Ship v1 CIMD documents with `jwks` absent. Design (this document does; §8 has the scaffold) but do not build a `client_auth_key` derivation until a concrete external AS the substrate wants to speak to actually requires `private_key_jwt`. When that day comes, the derivation is a same-shaped fourth file beside `gate_signer.rs` / `audit_signer.rs` / `foundation_edge_signer.rs`, with its own versioned context tag (`"zp.cimd.client_auth.v1"` is reserved for it in the scaffold below) — not a new pattern to invent.

---

## 4. `client_name` and `redirect_uris` derivation

### `client_name`

`REGENT-NAMING-CEREMONY-2026-07.md` already fully specifies the two states this needs to distinguish:

- **Named.** Use the committed name verbatim — the same string Cleo narrates ("Your Regent is now Astra"), with no decoration. `client_name` is cosmetic per the CIMD spec (the AS does not use it for anything but human-readable display); the actual unique identifier is `client_id`, the hosted URL. Decorating the name (e.g. appending "— ZeroPoint") adds a formatting decision with no functional payoff.
- **Pre-named.** The naming ceremony's own vocabulary for this state, verbatim from its "Framing" section, is *"the Regent"* in substrate-generated language, with the standing correction reading *"You have not yet been named."* This document proposes the fixed marker string **`"ZeroPoint Substrate (Regent pre-named)"`** — stable across all pre-named operators (it must not leak any per-operator identifying detail before naming has happened), immediately recognizable as the pre-named case in any external AS's client list, and textually distinct enough from a real committed name that no future named Regent could collide with it by coincidence.

**Update path.** The naming ceremony's "Substrate propagation post-naming" section already lists every subsystem that re-composes on the next cognitive cycle after a naming, renaming, or retraction receipt lands (cognitive input plane, embodiment plane, Cleo narration, standing corrections, officer findings). Recommend the implementation session add exactly one more bullet to that existing list: *"CIMD hosted document (if a hosting adapter is configured) is regenerated and re-published."* This is not a new propagation mechanism — it is one more subscriber to a mechanism that already exists and already fires atomically on the naming ceremony's Genesis-signed commit.

### `redirect_uris`

This is the sharper of the two sub-questions, because the natural first framing — "the redirect URI should point at the active-presence device, and update on handoff" — is wrong, and reading V.4 closely says why.

`KEEL-2026-07.md` §V.4 describes active-presence handoff as a receipt chain (`regent:handoff:requested` → `accepted` → `complete`) with an explicit transition window during which *neither* device is accepting operator input, and a documented recovery path for a device that dies mid-transition. A `redirect_uris` entry that names a specific device's address would need to be kept in lockstep with that chain — re-published on every handoff, in a state where a handoff mid-flight (or a crashed handoff, or a stale-recovery handoff) leaves the CIMD document pointing at a device that is not currently authoritative. An external AS caches CIMD documents; a redirect target that moves on a timeline outside the AS's control is a source of exactly the kind of silent failure §III.19 ("Detectability over invulnerability... silence is the enemy") warns against.

The better answer follows from what a `redirect_uri` is actually for in the OAuth authorization-code flow: it is where the browser's final hop lands with a `code` parameter, once, per authorization. It does not need to be "the active Regent's address" — it needs to be **a stable place that can catch that one redirect and hold the code until whichever device is active presence is ready to consume it.**

**Recommendation:** `redirect_uris` contains exactly one URL, co-located with the hosted CIMD document itself (`{hosting_base}/oauth/callback` — same origin as `client_id`, satisfying the CIMD spec's expectation of a small fixed redirect set with no per-device entries). That endpoint's job is narrow: receive the redirect, capture `code` and `state`, and hand them off as an artifact the active-presence Regent picks up on its next cycle — a plain queued item today, or (once `MCP-COMPOSITION-2026-08.md` §6.1's MCP-as-Extension ceremony lands) a chain-anchored evidence receipt in the same family that ceremony defines. Because this endpoint lives at the hosting location, not on any operator device, **`redirect_uris` is invariant under V.4 handoff by construction — it never needs to be republished when active presence moves, which is the strongest possible answer to "how does it get updated": it doesn't have to be.**

This does mean the hosting adapter for Option D (self-host) needs its own `/oauth/callback` route in the substrate's own HTTP listener, and the Foundation-mirror adapter needs the Foundation Worker to grow an inbound capture endpoint — the mirror-image of the *outbound* relay its edge-proxy already does. Both are implementation-session work (§6); neither changes this decision.

---

## 5. Composition with KEEL and Tier 2 elaborations

| Composes with | What it supplies |
|---|---|
| `KEEL-2026-07.md` §II.5 | Genesis-as-single-root — the fingerprint every URL scheme in §1 derives from. |
| `KEEL-2026-07.md` §XIV.1, §XIV.3 | The three Forms' network reach (§2's table) and the Form Disclosure obligation this design adds one clause to. |
| `KEEL-2026-07.md` §III.1 | The authority-vs-availability distinction §1 makes explicit for the Foundation mirror option. |
| `KEEL-2026-07.md` §III.3, Part V.4 | Active-presence handoff — the mechanism §4's `redirect_uris` recommendation is built to be invariant under. |
| `SUBSTRATE-FORM-2026-07.md` | The technical spec behind KEEL §XIV; supplies the exact Appliance Form language ("network reachable, unattended runtime") that decides §2's Appliance default. |
| `REGENT-NAMING-CEREMONY-2026-07.md` | `client_name`'s two source states and the existing post-naming propagation list §4 proposes one bullet onto. |
| `EXTENSION-SURFACE-2026-07.md` §"Delegation semantics" | Per `MCP-COMPOSITION-2026-08.md` §2.5, opting a hosting adapter in at all is itself a delegation the operator grants — `delegation:granted:extension:<wasm_hash>`-shaped, once the hosting adapter is packaged as a `ProtocolAdapterExtension` (§6.1's territory, not this document's). |
| `PEER-DISCOVERY-AS-OUTREACH-2026-07.md`, `DISCOVERY-AND-BOOTSTRAP-2026-07.md` | The substrate already has a well-known-URI precedent — `https://<operator-domain>/.well-known/zeropoint/sovereign.json` — for self-hosted sovereign presence. §1's Option D self-host path should reuse that exact path shape (`/.well-known/zp/identity/<fingerprint>/client.json` or similar) rather than inventing a second convention; the implementation session should reconcile the two path schemes, not this document. |
| Foundation edge-relay precedent (`docs/handoffs/foundation-worker-edge-proxy-2026-05.md`, `crates/zp-cloudflare`, `crates/zp-keys/src/foundation_edge_signer.rs`) | The existing domain-separated-key, operator-signs / Foundation-relays shape that §1's Option B recommendation is structurally identical to. |
| `MCP-COMPOSITION-2026-08.md` §6.1 (not yet landed) | The MCP-as-Extension canonicalization ceremony this document's hosting adapter should eventually package as. §4's `redirect_uris` capture artifact names this ceremony as its eventual chain-anchored home. |

---

## 6. Code implementation work this unlocks, scoped by Form

This document does not build the hosting adapter. Once Ken signs off on §1–§4, the following becomes buildable — grouped by what depends on which decision:

**Independent of the Form/hosting-mode choice (buildable regardless of §1/§2's outcome):**
- `CimdDocument` construction from substrate state — Genesis fingerprint, naming-ceremony state, the fixed pre-named marker. Pure, testable, no network.
- `client_name` derivation exactly per §4, plus the one-bullet addition to the naming ceremony's post-naming propagation list.
- The `IdentityHostingAdapter` port trait (§8) — the shape every hosting mode implements against.

**Sovereign Form:**
- The Foundation-mirror adapter's client side — publish/update calls against the Foundation Worker, reusing the existing `zp-cloudflare` boundary-crossing-receipt discipline (rule 2 of that crate: "All ZP↔CF transitions emit receipts").
- The opt-in ceremony surface (dashboard panel: "publish your substrate's identity to the Foundation mirror?") — an instance of the operator-review-surface shape `EXTENSION-SURFACE-2026-07.md` §"Delegation semantics" already specifies.
- Optional self-host override path, gated behind an explicit "I have a domain and will keep it reachable" operator acknowledgment (this is where the DISCOVERY-AND-BOOTSTRAP well-known-URI reconciliation from §5 lands).

**Appliance Form:**
- The self-hosted adapter: an HTTP route on the substrate's own always-on listener serving the CIMD document plus the `/oauth/callback` capture endpoint from §4.
- ACME certificate management for that listener — the implementation session's first open sub-decision (§7 records it as such; this document does not pick HTTP-01 vs. DNS-01).
- Foundation-mirror fallback path for the CGNAT case, sharing code with the Sovereign-Form Foundation adapter.

**Companion Form:**
- Foundation-mirror-only wiring (no self-host branch offered in the UI at all).
- The Form Disclosure clause addition named in §2.

**Foundation-side (not a ZP-substrate-binary change — the Cloudflare Worker):**
- A new inbound route mirroring the existing outbound edge-relay pattern: accept a Genesis-signed CIMD document from an opted-in operator, serve it at `/{fingerprint}/client.json`, and forward `/oauth/callback` hits into the existing relay-to-operator path.

**Deferred (§3's recommendation):**
- `client_auth_key` derivation (`crates/zp-keys/src/cimd_signer.rs`, fourth sibling of the three existing derivation modules) and JWKS-block population — not built until a concrete AS requires `private_key_jwt`.

---

## 7. Explicit non-decisions and open positions

Recorded here deliberately, per the handoff's own discipline of naming what a session does not decide rather than letting it go unrecorded:

- **Which Form default actually ships first.** §2 gives all three Forms a recommended default; it does not decide implementation order. Reasonable to sequence Appliance-Form self-hosting first (fewest moving parts — no Foundation-side change needed) — but that is a scheduling call, not a design one.
- **ACME strategy for self-hosted Forms.** HTTP-01 vs. DNS-01 vs. a tunnel provider (Cloudflare Tunnel-shaped) for operators behind NAT/CGNAT with no port-forwarding path. Named in §6 as the Appliance-Form implementation session's first sub-decision; not resolved here because it is infrastructure-vendor-specific in a way the other three decisions are not.
- **Fingerprint truncation for any future DNS-label-constrained use.** §1 identifies the 64-hex-char-vs-63-octet mismatch but does not pick a truncation length or encoding, because the recommended options (B, D) never need to fit a fingerprint into a DNS label at all — it lives in a URL *path*, which has no such limit. If a future surface genuinely needs a DNS-label-shaped identifier (unlikely given B/D), that is its own small decision, not inherited from this one.
- **The well-known-URI path reconciliation** between this document's CIMD path and `DISCOVERY-AND-BOOTSTRAP-2026-07.md`'s existing `/.well-known/zeropoint/sovereign.json`. Named as a composition point in §5; the actual merged schema is implementation-session work.
- **Peer-mesh (Option C) as a resilience layer under B/D.** Recorded in §1 as a future enhancement, deliberately not designed further here — it was never a candidate hosting *mechanism* on its own, only a possible replication layer under whichever HTTPS front door §2 lands on.
- **The Foundation Worker's new inbound route** (§6, "Foundation-side") is Foundation-operated infrastructure, not substrate binary — its design is out of this document's authority in the same way `MCP-COMPOSITION-2026-08.md` §6.6 (EMA) named enterprise-IdP composition as out of scope for a substrate-authored document.
- **JWKS rotation policy**, once `client_auth_key` is eventually built (§3) — versioned-context-tag rotation exists as a pattern (`gate_signer.rs`'s own doc comment: "Rotation = bump the domain tag to v2") but CIMD-specific rotation (how a rotated key is discovered by an AS that cached the old JWKS) is not designed here because no JWKS is being built in this pass.
- **Whether the hosting adapter is packaged as a `ProtocolAdapterExtension`** (per `EXTENSION-SURFACE-2026-07.md`) or lands as substrate-native code ahead of that trait's admission ceremony. This tracks `MCP-COMPOSITION-2026-08.md` §6.1's own open status — that ceremony is explicitly sequenced *after* the QUARANTINE-PLANE "instruction-shaped artifacts carrying authority" open position resolves, and this document does not get ahead of that sequencing.

---

## 8. Scaffold

A minimal, unregistered scaffold lives at `crates/zp-identity-hosting/` (new crate, **not** added to the workspace `Cargo.toml` members list in this pass — deliberately, to avoid editing a file shared with the two other design sessions running in parallel this session; wiring it in is the implementation session's first step). It contains:

- `src/document.rs` — `CimdDocument`, `Jwk`/`Jwks` types, and `build_cimd_document(...)` with a `todo!()` body — the function signature captures exactly what §4 settled (name, redirect derivation) and takes the URL-scheme choice as a parameter rather than hard-coding it, so it does not have to be rewritten once §1/§2 are picked.
- `src/client_id.rs` — `ClientIdScheme` enum with exactly the two surviving options from §1 (`FoundationMirror`, `SelfHosted`) plus `PreRegistered` as the no-hosting fallback from §2; deliberately has no `DnsUnderControlledTld` variant.
- `src/adapter.rs` — the `IdentityHostingAdapter` port trait, mirroring `zp-cloudflare`'s stated ports/adapters/substitutable-adapters philosophy, with `todo!()` stub structs for `FoundationMirrorAdapter`, `SelfHostedAdapter`, `PreRegistrationAdapter`.
- `src/client_name.rs` — **not stubbed**; §4's `client_name` logic is fully settled, so this file has a real, non-`todo!()` implementation plus tests, ready to move into `zp-server` verbatim.
- `src/redirect.rs` — `redirect_uris(hosting_base)` fully implemented per §4 (always exactly one URL, hosting-location-relative); the callback-capture handler itself is `todo!()` since its wiring is Form/adapter-dependent.
- `src/client_auth_key.rs` — the §3 `client_auth_key` derivation, written to the exact pattern of `gate_signer.rs` / `audit_signer.rs` / `foundation_edge_signer.rs`, reserving the context tag `"zp.cimd.client_auth.v1"`. Marked in its own doc comment as **not to be built into v1** per §3's recommendation, and as belonging in `crates/zp-keys/src/cimd_signer.rs` once it is — not created there in this pass for the same shared-file reason the crate itself isn't registered yet.

None of this has been run through `cargo check` — it is not a workspace member, deliberately, so nothing in this session's parallel edits to `zp-config`, `zp-regent`, or `zp-server` can conflict with it. The implementation session's first two steps are: add the crate to workspace members, and run `cargo check -p zp-identity-hosting` before writing a single non-`todo!()` line beyond what's already here.

---

## What composes from here

Immediate next step: Ken reviews §1–§4 and either signs off on the recommendations as written or names which option he wants instead — this document is built so each recommendation is independently overridable without invalidating the others (§1's `HostingMode` parameter, §3's deferred-not-abandoned design, §4's settled derivations do not depend on §1/§2's outcome).

Once signed off:
1. Register `zp-identity-hosting` as a workspace member; `cargo check -p zp-identity-hosting`.
2. Build the Appliance-Form self-hosted adapter first (§6) — fewest external dependencies, validates the `CimdDocument` construction and the `/oauth/callback` capture shape end-to-end on one Form before the Foundation-side work begins.
3. Land the one-bullet addition to `REGENT-NAMING-CEREMONY-2026-07.md`'s post-naming propagation list.
4. Open the Foundation Worker's inbound-route design as its own small handoff, once an operator wants Sovereign- or Companion-Form Foundation-mirror hosting.
5. Defer `client_auth_key` (§3) until a concrete AS forces the question.

## Framing note

The whole reason this design pass exists is that it is disproportionately cheap for what it buys: one hosting adapter, decided once, closes the identifier gap in three unrelated interop surfaces at once (`MCP-COMPOSITION-2026-08.md` §5.1's own framing). Nothing in this document commits the substrate to a new trust root, a new signing algorithm, or a new axiom — every recommendation above is Layer B, reachable by canonicalization ceremony and operator configuration, and every non-decision left open is left open because it is either genuinely Ken's call, genuinely infrastructure-vendor-specific, or genuinely gated on another session's unresolved open position. The Foundation-edge precedent this document leans on twice (§1's Option B, §6's Foundation-side work) is not a new dependency being introduced here — it is the same opt-in, authority-preserving, availability-only relay shape the substrate already ships, applied to one more kind of content.
