# Regent Onboarding Ceremony

**Document type:** Tier 2 canonical elaboration.
**Status:** Design; unimplemented as of 2026-09-06.
**Elaborates:** KEEL §II.5 (Genesis-as-single-root), §II.13.9 (P9 — the system acts; the operator signs), §IV.2 (key material), §IV.5 (delegation / mandate / capability class).
**Composes with:** `SUBSTRATE-BOOT-INVARIANT-CEREMONY-2026-07.md` (the ceremony this one sequences after), `IDENTITY-HOSTING-ADAPTER-2026-09.md` (identity is one of the surfaces named in the persona charter), `MCP-COMPOSITION-2026-08.md` §6.0 (three surfaces, one identity — the Regent is *the* identity, projected).
**Date:** 2026-09-06.
**Origin:** first exercise of the Regent (2026-09-06) surfaced that the substrate boots with zero standing grants — every operator input, including trivial ones like `"Say ready."`, produced a PROPOSAL response with `"Blocked by: no mechanism"`. That is *not* the substrate's stated position; it is a de-facto outcome of unimplemented capabilities. This document names what the substrate's true initial position is: a Regent boots with an operator-signed seed set that scopes its baseline action space, granted through this ceremony.

---

## 1. The gap this ceremony closes

KEEL §II.13.9 P9 states *"the system acts; the operator signs."* The signing is *retrospective* attestation via receipt, not *prospective* authorization via approval. Under P9 read literally, the Regent should *act* on the operator's input within its scoped delegations and produce a receipt the operator countersigns after the fact. The Regent should not have to propose every action and wait for a per-action mechanism.

P9 works only when the Regent's action space is bounded. Otherwise *"the system acts"* means *"the system does anything and hopes the receipt covers it."* The bounding comes from the delegation graph: a set of standing grants that name what the Regent may do without a prior proposal cycle. Genesis-as-single-root (§II.5) is the authority that issues those grants; the Regent-as-cognitive-agent (§II.13.9) executes within them.

The substrate's true initial state is therefore not zero grants. It is:

> **The Regent boots with a seed set of operator-signed standing grants that scope the Regent's baseline action space. Genesis authenticates the signing. The ceremony that produces the signing runs once, immediately after Genesis, before the Regent's first cognitive cycle.**

Absent that ceremony, the substrate boots into a state where the entity called *a Regent* cannot behave as one — it can only propose to behave as one, forever. That state is nameable (§3.4 below) and refusable-into (§4) but is not the substrate's default.

## 2. The four-part ceremony

The ceremony is one bounded rite, executed exactly once between Genesis authentication and the Regent's first cognitive cycle. Each part produces an explicit operator choice, each choice produces a chain-anchored receipt, each receipt is Genesis-signed.

### 2.1 Naming

The operator names their Regent. This is a personal handle the operator addresses their delegate by — not the Genesis-derived identifier that the substrate uses internally. Same substrate distinction as personal-address vs. destination-hash at the network layer.

The name is one field, UTF-8, operator-chosen, no substrate-imposed constraint beyond a length ceiling and forbidden-characters set (`/`, `:`, control characters — the same characters that break the receipt-namespace scheme). Non-refusable: the operator must name their Regent. Anonymity is not a valid choice here — an unnamed delegate is a delegate whose actions cannot be attributed at the operator's own hearing.

Receipt: `regent:named:<name>`, body carries the name string, Genesis-signed.

### 2.2 Persona

Not a system-prompt in the shallow sense. A **charter** — a short text (targeting ≤2KB) that names what kind of cognitive partner the operator wants this Regent to be. Terseness, deference, cautionary bias, verbosity ceiling, refusal-shape, tone. The corpus reads in one voice; the Regent should inherit that voice as an explicit operator choice, not as a coincidence of training data.

The charter is hashed (`blake3` per substrate convention) and the hash is chain-committed. Full charter text is stored in the substrate's operator-scope, retrievable but not re-signable — the receipt binds the hash, not the text, so a compromised persona file is detectable by re-hash.

Refusable: an operator may decline to author a persona charter and accept a substrate-provided default. The default is *itself* an operator choice, not an absence — the operator selects "default charter" from a substrate-shipped catalog of persona presets. The refusal is legibly *"operator declined per-instance charter, accepted preset X."*

Receipt: `regent:persona:v1`, body carries `{charter_hash, source: "authored"|"preset:<name>"}`, Genesis-signed.

Re-charter later is a new ceremony (§5.2 below), emitting `regent:persona:v2` with the diff — same shape as key rotation.

### 2.3 Seed delegations

The ground-floor grants. Composed of two parts, per §II.13.9 Layer A / Layer B applied to the seed itself:

**Invariant floor (§3).** KEEL-mandated. Non-refusable. Announced-and-confirmed rather than picked. One receipt: `delegation:seed:invariant`, body carries the full invariant set (as of the substrate's build commit — the set is chain-committed so a later KEEL amendment producing a different floor is detectable).

**Extension catalog (§4).** Operator picks from a substrate-provided catalog. Zero or more grants. One receipt per pick: `delegation:seed:extension:<capability>`, body carries `{capability, scope, ceiling, revocation_conditions}`. The operator may take none, some, or all — the *set* they picked is what constitutes their Regent's *seeded* capability envelope beyond the floor.

The ceremony renders the catalog with defaults marked but every entry refusable individually. Refusing all extensions is a valid choice (§4.4 below).

### 2.4 Or not — the propose-only Regent

The ceremony explicitly permits the operator to decline the extension catalog entirely. The Regent is then in a nameable state:

> **A `regent:seeded:floor-only` Regent responds and observes within the invariant floor. It emits proposals for every capability outside the floor. The operator can extend the seed later via `zp regent extend` (see §5.1) at any time. This is a valid substrate configuration.**

The state is chain-anchored: `regent:seeded:floor-only` receipt is emitted if and only if the operator declined every extension. A later operator inspecting the chain sees exactly *"the operator who instantiated this Regent chose to keep it in floor-only mode."*

Refusing the invariant floor is not offered. A Regent without the floor is not a Regent — the substrate would refuse to boot.

## 3. The invariant floor

The floor is what the substrate commits to as *"true of being a Regent."* Small, KEEL-worthy, hard to add to (a change to the floor is a KEEL amendment, per §III.6). The initial floor proposed here is three capabilities. Each is defensible under the test *"if the Regent lacks this, it is not a Regent — it is something else."*

### 3.1 `respond`

The Regent may respond directly to operator input on the operator's own input channel. No proposal cycle for pure-response turns.

Scope: replies to operator-originated input arriving via the operator's authenticated cockpit surfaces (currently `CockpitSource::Cli`; future surfaces added by ceremony amendment, not by silent extension).

Rationale: an entity that cannot answer its operator is not a cognitive partner. Every operator interaction currently short-circuits into a proposal even when the operator is asking a *question* rather than requesting an *action*. That shape does not compose: the operator ends up authoring proposals to grant the Regent permission to say *"I don't know."*

### 3.2 `read:own-scope`

The Regent may read its own persona charter, its own name, its own receipt chain (filtered to `regent:*` and `cognitive:*` prefixes), and the substrate's governed corpus under `docs/` (Tier 1 and Tier 2, not Tier 3 without extension). Not `crates/`. Not `docs/handoffs/`. Not operator files outside those paths.

Scope: read-only. Path-anchored. No shell, no subprocess, no side effect. Emits `regent:read:*` receipts for observation.

Rationale: a Regent without self-knowledge cannot act coherently across turns. It needs to be able to read its own persona to know how to speak, its own name to know how it is addressed, its own chain to know what it has done. Without this, the Regent is memoryless-by-substrate not memoryless-by-choice, and the substrate's own corpus (its authored constitution) is invisible to it — pathological for a substrate whose product is *legibility*.

### 3.3 `emit:cognitive`

The Regent may emit `cognitive:*` receipts describing its own internal state — planning steps, self-observer classifications, drift-detection, proposal-generation reasoning. Not `substrate:*`. Not `gate:*`. Not `delegation:*`.

Scope: receipt emission only, in the `cognitive:` namespace. No side effect beyond chain append.

Rationale: P9 says *"the operator signs."* Signing what? Signing receipts. If the Regent cannot emit receipts of its own cognitive state, P9 has nothing to attest to and the operator has no evidence of what the Regent was thinking when it acted. `emit:cognitive` is the substrate observing the Regent's mind. Without it, the Cognitive Self-Observer (§ COGNITIVE-SELF-OBSERVER-2026-07.md) has no substrate to observe *into*.

### 3.4 What the floor does *not* include

Deliberately absent:

- **Read/write on `crates/` or substrate source.** A Regent that can rewrite the substrate that governs it is not governed. That capability is *always* extension-tier and *always* per-file-scoped.
- **Subprocess execution.** Even `cargo test` is out of the floor. A Regent that can execute arbitrary compiled code has escaped the substrate's boundary planes.
- **Network I/O.** Reaching outside the substrate is out of the floor. The MCP composition adapter (§ MCP-COMPOSITION-2026-08.md) is an extension-tier capability, not a birthright.
- **Chain writes beyond `cognitive:*`.** The Regent cannot write `gate:*`, `delegation:*`, `substrate:*`, or any receipt outside its declared namespaces. Anchoring, delegation issuance, substrate validation — all operator- or officer-authority, not Regent-authority.

## 4. The extension catalog

The catalog is the substrate's menu of *"optional capabilities the operator may seed at ceremony time or extend later."* Unlike the floor, the catalog is extensible without a KEEL amendment — a substrate release can add entries; the operator's choices at their Genesis remain valid because their receipts are commit-anchored.

### 4.1 Catalog entry shape

Every entry declares:

- `capability` — kebab-case name, e.g. `read:crates`, `read:tier-3`, `emit:artifact`, `chat:tools:chart-report`, `filesystem:scoped-write:<path>`, `subprocess:cargo-check`.
- `scope` — the parameters the capability accepts (path prefixes, tool names, receipt-namespace prefixes, subprocess argv shape).
- `ceiling` — the numeric or temporal cap (invocations per hour, total bytes read per session, max output length, expiration timestamp).
- `revocation_conditions` — the substrate-defined conditions that automatically revoke the grant without operator action (a discipline pin failure, a drift-detection above threshold, a receipt of a specific type appearing on the chain).
- `default` — recommended default at ceremony time (`grant` / `decline`), so the ceremony can render sensible defaults but the operator sees them.
- `rationale` — one-sentence *"why this exists and why an operator might want it."*

### 4.2 Starter set (candidate — first pass)

Not exhaustive. First pass proposal:

- `read:crates` — Regent may read `crates/**/*.rs`. Default: decline. Rationale: Regent needs source access to build substrate; not every operator wants that from day one.
- `read:tier-3` — Regent may read Tier 3 historical corpus. Default: decline. Rationale: historical docs carry authoring-frame assumptions; a Regent reading Tier 3 without operator awareness may quote stale positions as current.
- `read:handoffs` — Regent may read `docs/handoffs/*`. Default: decline. Rationale: handoffs are the operator's local reasoning trail; a Regent reading them by default is invasive.
- `emit:artifact` — Regent may emit artifacts through the existing `save_to_artifacts` tool. Default: grant. Rationale: producing artifacts is the Regent's primary output form for cognitive work.
- `chat:tools:chart-report` — Regent may invoke the existing `chart` and `report` tools during response construction. Default: grant. Rationale: these are the Regent's declared tool surface today.
- `propose:via-p9` — Regent may emit `PROPOSAL` shapes without a per-proposal grant. Default: grant. Rationale: the ability to *propose* is itself a capability, distinct from acting; without it the Regent falls silent instead of asking.
- `filesystem:scoped-write:<path>` — Regent may write files under an operator-named prefix (e.g. `~/regent-outputs/`). Default: decline. Rationale: file-write is a substrate boundary crossing; explicit per-operator scope required.
- `subprocess:cargo-check` — Regent may run `cargo check --workspace` and read its output. Default: decline. Rationale: subprocess is a boundary crossing; some operators want it, most should think about it.
- `subprocess:cargo-test:zp-discipline` — Regent may run the discipline-pin suite. Default: decline. Rationale: narrower than `cargo check`, safer to grant, useful for a Regent that iterates on pins.
- `mcp:client:<server>` — Regent may act as an MCP client against a named MCP server (per `MCP-COMPOSITION-2026-08.md`). Default: decline. Rationale: outward-facing composition; requires explicit operator awareness of the trust boundary.

### 4.3 Ceremony UX

The ceremony renders the catalog as a list. Each entry shows: name, one-sentence rationale, default choice, and an explicit `[grant]` / `[decline]` selector. The operator moves through the list once, picks, submits. The ceremony emits one `delegation:seed:extension:<capability>` receipt per `grant` choice and one summary `regent:seeded:complete` receipt naming the total set.

Refusal of *all* entries is a valid path and produces `regent:seeded:floor-only` per §2.4.

The catalog is *not* rendered again automatically. Adding an extension after the ceremony is `zp regent extend` (§5.1); adding one requires the operator to re-issue Genesis authentication.

### 4.4 Refusing every extension

A Regent seeded floor-only is a design-legitimate state, not a broken state. Two operator profiles motivate this path:

- **The observer profile.** The operator wants a Regent that can talk to them, read the corpus, and record its own thinking on the chain — nothing more. Every capability outside the floor is discussed and granted on-demand via proposal loops.
- **The audit profile.** The operator wants a chain that shows *"this Regent was constituted with only its floor capabilities."* The chain then records every extension proposal-and-grant as a distinct event, producing the most legible possible record of what the Regent was ever allowed to do.

The propose-only mode we saw during the 2026-09-06 first-exercise fire is *this state, arrived at by default rather than by choice*. The ceremony makes it a choice.

## 5. Composition points

### 5.1 Extending the seed later

`zp regent extend <capability> [--scope ...] [--ceiling ...]` — a CLI subcommand that runs a mini-ceremony to add a capability to the Regent's seeded set. Requires Genesis authentication for the operator's turn. Emits `delegation:seed:extension:<capability>` receipt with the same body shape as the original ceremony's receipts. Idempotent — extending an already-granted capability is a no-op that emits a `delegation:already-seeded` observation receipt.

Revocation: `zp regent revoke <capability>`. Emits `delegation:seed:revoked:<capability>`. The Regent's next cycle observes the revocation and drops the capability from its live set.

### 5.2 Re-charter

`zp regent recharter` — runs the persona part of the ceremony again, emitting `regent:persona:v<n+1>` with a diff-hash against the previous charter. The Regent's name is *not* re-negotiated by this call — renaming is `zp regent rename`, a separate rite that emits `regent:renamed:<old>-><new>` and updates the operator's addressable handle.

### 5.3 Sequencing after SUBSTRATE-BOOT-INVARIANT-CEREMONY

The four-part ceremony runs *after* the substrate boot ceremony (per `SUBSTRATE-BOOT-INVARIANT-CEREMONY-2026-07.md`, currently design-only, no code) completes. Specifically:

1. Substrate boot ceremony validates the substrate binary against its Genesis (B0–B4 phases per that doc).
2. Substrate boot emits `substrate:booted:<commit>` receipt.
3. If no prior `regent:named:*` receipt exists on the chain, the Regent Onboarding Ceremony runs.
4. If a prior `regent:named:*` exists, the substrate reads the existing seed set and boots the Regent with it — no re-onboarding on every start.

Case 4 is what makes this ceremony a *once-per-substrate-lifetime* rite rather than a boot-time gate.

### 5.4 The recursive property

The first substrate's Regent Onboarding Ceremony is authored by the substrate's designer (Ken, in the current session frame). The seed catalog's entries and defaults reflect that designer's stance about what a Regent should be by default.

Once a substrate's Regent has enough capability to help — specifically, once it has `read:crates`, `read:tier-3`, and `propose:via-p9` — it can *draft the seed catalog for a subsequent operator's Regent*. The subsequent operator either accepts the draft, edits it, or rejects it. The Regent-as-substrate-builder future arrives here: the substrate propagates by having its Regent draft the next Regent's constitution. Each generation is operator-signed at its own Genesis; no Regent authors its own seed.

## 6. Non-decisions and open positions

- **Whether persona charter presets ship with the substrate binary or live in a separate operator-fetchable catalog.** Deferred; the receipt shape (`{source: "preset:<name>"}`) accommodates either.
- **Whether the ceremony can be paused and resumed** (operator interrupts mid-catalog, comes back tomorrow). Deferred; the substrate boot receipt `substrate:booted:<commit>` combined with a `regent:onboarding:in-progress` receipt would support this, but no design work has been done. Simpler v1: the ceremony is atomic — completes or is abandoned.
- **Whether floor-only Regents can extend to acquire capabilities that require Genesis re-authentication.** Almost certainly yes (that is what §5.1 designs) — but the *rate* at which such extensions can be issued is undecided. A denial-of-Regent attack shape is possible: an operator under duress issues extensions rapidly. Rate limits or ceremony-per-day caps are candidate mitigations, not designed here.
- **Interaction with Substrate Form Disclosure.** The seed catalog may look different under Sovereign vs. Appliance vs. Companion Form. A Companion-Form Regent may not be allowed `subprocess:*` capabilities under any circumstance; a Sovereign-Form Regent may have them all in the catalog. Not designed here — this document targets Sovereign Form as the primary case and leaves Appliance/Companion adaptations open.
- **Whether the invariant floor is exactly three capabilities, or should include a fourth for `propose:via-p9`.** The current draft puts `propose:via-p9` in the extension catalog with default-grant. Argument for moving it to the floor: a Regent that cannot propose *at all* has no way to request its own extensions and is stuck at whatever seed the ceremony issued. Argument for keeping it in the catalog: propose-only mode is a chosen state under §2.4, and *"decline propose"* is a valid operator choice that produces a Regent that responds and observes but never asks. Position: leave in catalog for v1, revisit if usage surfaces the issue.
- **Persona charter length ceiling.** Named as ≤2KB above but not justified. Real analysis of what personas require, and what the substrate can chain-commit sensibly, is deferred.
- **Persona charter language.** Named as UTF-8 above but not internationalised. Whether personas in non-Latin scripts render correctly at every ceremony surface (CLI, dashboard, mobile) is undecided.

## 7. Implementation sketch

Not the full session's work — a pointer at where the code lives when someone builds this:

- `crates/zp-regent/src/onboarding/` (not yet written) — new module. Ceremony state machine (naming → persona → seed → confirm), catalog definition (as a `const` structure or config-derived — pick one during implementation), receipt emission wiring.
- `crates/zp-server/src/routes.rs` (not yet written) — new HTTP routes: `POST /api/v1/regent/onboard/name`, `POST /api/v1/regent/onboard/persona`, `POST /api/v1/regent/onboard/seed`, `POST /api/v1/regent/onboard/confirm`. One per ceremony phase — each phase authenticates against Genesis, emits its receipt, and either advances state or rejects.
- `crates/zp-cli/src/main.rs` — new subcommand: `zp regent onboard` (interactive walkthrough), `zp regent extend`, `zp regent revoke`, `zp regent recharter`, `zp regent rename`.
- `crates/zp-regent/src/loop_runner.rs` — modification: the Regent loop reads its seeded delegation set at startup and consults it before every proposal-vs-act decision. If the input names an action within the seeded set, act; if outside, propose.

Discipline pins to land alongside implementation:

- `regent_boots_only_after_onboarding` — the Regent loop cannot start cycles before `regent:named:*` and `regent:persona:v1` receipts are present on the chain.
- `no_regent_action_outside_seeded_scope` — a scan that walks Regent action-emission sites and confirms every action is gated by a live seeded-set lookup, no unconditional action-emission path.
- `invariant_floor_is_singly_declared` — the floor definition appears exactly once in the codebase (candidate location: `crates/zp-regent/src/onboarding/floor.rs` (not yet written)); no other file may declare a capability set for the floor.
