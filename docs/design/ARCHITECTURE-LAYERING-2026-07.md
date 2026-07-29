# Architecture Layering

**Document type:** Design note — the authored companion to a derived artifact. **Not** a Tier 2 canonical elaboration; it elaborates no KEEL section. `docs/ARCHITECTURE-MAP.md` is generated and states what the crates *are*; this states what the shape *means*, which no generator can produce.

**Date:** 2026-07-27, corrected 2026-07-29. **Status:** First reading, against commit `a952b50`; §Correction 2026-07-29 supersedes the unwired figures throughout and the generator has been changed to match. Numbers below will drift; the map regenerates, this does not.

**Motivation:** `ARCHITECTURE-2026-07.md` is a conceptual record, reclassified Historical, and names crates eleven times in 443 lines. Until 2026-07-27 nothing in the corpus answered *what are the 44 crates, which are load-bearing, and which are dead* — a question four separate agents each rediscovered the hard way in a single day. The map answers it mechanically. This document reads the answer.

**Composes with:** `ARCHITECTURE-MAP.md` (the derived half — regenerate it rather than trusting the figures quoted here), `CONNECTION-INTEGRITY-PROGRAM-2026-07.md` (its C2 condition is what the unwired column measures), `TRIAGE-FOR-COHERENCE-2026-07.md` (the undocumented-crate column is a coverage denominator question), `MACHINE-LEARNING-INVENTORY-2026-07.md` (found two of these unwired crates by sweep, hours apart, before the map existed), `KEEL-2026-07.md` §II.9 (the Layer A / Layer B split, which is a different axis from the dependency depth used here — see §Two meanings of "layer").

---

## Framing

**1. Depth is not importance, and reading it as such is the trap this document exists to prevent.** Dependency depth answers *what must compile first*. At Layer 0 sit both `zp-receipt` — 15 dependents, the crate everything eventually routes through — and `zp-cloudflare`, 109 lines with none. Same layer, opposite roles. The useful axis is the **pair**: depth tells you where a crate sits, fan-in tells you whether anything rests on it.

**2. The foundation is the receipt, not the key and not the chain.** `zp-receipt` is the only Layer 0 crate with substantial fan-in, and `zp-core` — 23 dependents, the widest in the tree — depends on exactly one sibling: `zp-receipt`. So the unit of record precedes identity, policy and transport in the build order, not merely in the prose. That is the architecture asserting itself in the dependency graph, and it is the strongest available evidence that *the chain is the substrate* is a real claim rather than a slogan.

**3. Mass is not depth.** `zp-server` is 38,456 lines at Layer 7 and `zp-cli` 19,188 at Layer 8 — together 30% of the tree, both near the top, both consumed by almost nothing. That is the expected shape for entrypoints, but it means nearly a third of the codebase sits where changes are cheap to make and impossible to reuse.

---

## Two meanings of "layer"

KEEL §II.9 already uses *layer* for the amendment boundary: **Layer A** is compiled Rust that canonicalization cannot touch; **Layer B** is chain-anchored spec, amendable by ceremony. That is a governance axis.

The map's layers are **dependency depth** — a build-order axis. The two are orthogonal and must not be conflated: `zp-receipt` is depth 0 and Layer A; a future WASM officer module would be depth-irrelevant and Layer B. Where this document says "Layer 3" it always means depth. Where a KEEL claim says "Layer A" it never does.

---

## The eight layers, read

**Depth 0 — bedrock and detritus, indistinguishable by depth alone.** Sixteen crates. One is bedrock: `zp-receipt` (7,348 lines, fan-in 15). Four are genuine shared infrastructure: `zp-config`, `zp-net`, `zp-anchor`, `zp-content`. Four are single-consumer specialisms: `mle-star-engine`, `monte-carlo-engine`, `zp-sensors`, `zp-verbs`. **Seven have fan-in 0** — `zp-bench`, `zp-cloudflare`, `zp-discipline`, `zp-emission-coherence`, `zp-inference-observer`, `zp-memory-index`, `zp-preflight`, 6,347 lines. The first reading of this document said those were *"lines that nothing in the tree reaches."* That was wrong, and §Correction 2026-07-29 records why: only `zp-cloudflare` and `zp-memory-index` are unreached. The rest are entered through a target kind the dependency graph does not contain.

**Depth 1 — identity and verification.** `zp-core` (fan-in 23) and `zp-verify` (3), plus two narrow carriers. The whole substrate's type vocabulary lives one step above the receipt.

**Depth 2 — the trust primitives.** `zp-audit` (10), `zp-trust` (7), `zp-keys` (6). This is where the corpus's headline claims actually live, and the fan-in confirms it: three of the four widest-used crates in the tree are here. `zp-gossip` sits at this depth with fan-in 0.

**Depth 3 — governance and transport.** `zp-policy` (6), `zp-mesh` (17,954 lines, 4), `zp-engine` (3), `zp-officers` (3). The mesh is the single largest non-entrypoint crate, which is worth noting given that its `DiscoveryManager` is unwired and its inbound authentication is feature-gated off.

**Depth 4 — mediation and cognition.** `zp-host` (fan-in 4) is the host-function boundary through which KEEL §II.8 requires every privileged side effect to pass — and at 767 lines it is one of the smallest crates carrying one of the largest claims. `zp-regent` is 12,113 lines with fan-in 1.

**Depths 5–6 — composition.** `execution-engine`, then `zp-pipeline` (6,928, fan-in 3). Thin.

**Depths 7–8 — entrypoints.** `zp-server` and `zp-cli`, plus `course-examples` and `zp-hardening-tests` riding at the top with no consumers, which is correct for tests and examples.

---

## What the shape says

**The waist is narrow and that is good.** Depths 5 and 6 hold one crate each. Composition happens late and thinly, which means the trust primitives at depths 1–3 are reusable independently of the server. A substrate whose primitives could only be exercised through its own entrypoint would be far harder to prove anything about.

**The unwired mass is small, and smaller than the first reading claimed.** Three crates are genuinely unreached — `zp-cloudflare` (109 lines), `zp-memory-index` (409), `zp-gossip` — totalling well under 1% of the tree rather than the 6,347 lines first reported. All three are libraries at depths 0–2, which is the good version of the problem: nothing depends on them, so wiring or removing them disturbs nothing. It is also the diagnostic version — a library written at depth 0 with no consumer is a capability built before its call site, which is C2 by construction. `zp-memory-index` names its waiting consumer in its own doc comment (the `memory:retrieve` gated tool), so it is wire-it rather than retire-it.

**`zp-host` is the highest-leverage small crate in the tree.** 767 lines, fan-in 4, and it carries §II.8's *"access side-effect primitives only through host-mediated interfaces that gate-check on the way out."* Its own doc comment anticipates WASM callers delegating to the same trait. Everything the executable-artifacts mapping proposes routes through it.

**Two crates are large enough to hide things.** `zp-server` at 38,456 lines and `zp-mesh` at 17,954. The mesh survey earlier today found unwired discovery, disabled inbound auth and unbounded intake inside the second one — none of which was visible from outside it.

---

## Where buildout should push

Stated as a reading, not a plan; sequencing is the operator's.

1. **Resolve the three unwired libraries before adding new ones.** `zp-cloudflare`, `zp-memory-index`, `zp-gossip`. Each is either wire-it or retire-it, and both are cheap now precisely because nothing depends on them. `zp-memory-index` has a named consumer waiting in the corpus, so it is the one with an obvious answer.
2. **Run the benches, or delete them.** `zp-bench` is a `[[bench]]` harness with no `src/` at all. Nothing in `.github/workflows` invokes `cargo bench`, so a governance-gate benchmark has been present and unexecuted for the life of the crate — the purest form of *built, not wired*, and invisible to every fan-in measure because a bench crate's fan-in is 0 by construction.
3. **Grow `zp-host` deliberately.** It is the narrowest point through which the widest claim passes, and the host-import layer that KEEL Part V specifies has no implementation. Work here has the highest ratio of claim-satisfied to lines-written in the tree.
4. **Split by extraction, not by addition, at depths 7–8.** 57,644 lines of entrypoint is where behaviour accumulates unreusably. Anything in `zp-server` that another crate could plausibly want belongs lower.
5. **Treat the eight undocumented crates as a corpus gap, not a code gap.** `zp-net` has four dependents and no governed document describing it. Under the triage denominator, a crate no document mentions is outside the measure entirely.

---

## Correction 2026-07-29 — five of eight "unwired" crates were false positives

The map's `unwired` column tested `no dependents AND no src/main.rs`. That is a fan-in test wearing a reachability label, and a dependency edge is only one of five ways into a crate. Re-run against target kinds — `[[bin]]`, `tests/`, `benches/`, `examples/` — the set of 8 falls to 3.

| Crate | Reached by | Was |
|---|---|---|
| `zp-discipline` | `tests/` — **19 structural pins**, run by `cargo test --workspace` in CI on every push | unwired |
| `zp-hardening-tests` | `tests/` — 9 files, same harness | unwired |
| `course-examples` | `examples/` — 16 files, compiled by `cargo test --workspace` | unwired |
| `zp-bench` | `benches/` — `[[bench]]`, `harness = false`, **no `src/` at all** | unwired |
| `trust-triangle` | `[[bin]]`, and excluded from the workspace by an explicit manifest comment | unwired |
| `zp-cloudflare`, `zp-memory-index`, `zp-gossip` | nothing | unwired — correctly |

Three things this costs and one it buys.

**The most consequential misread was `zp-discipline`.** It holds 19 pins — `no_raw_tcp_bind_outside_zp_net`, `no_non_strict_ed25519_verify`, `granted_tools_must_be_reachable`, `adapters_must_be_documented` and fifteen more — each a build-failing structural assertion over the whole tree. It is the closest thing the repo has to the *"make checks a consequence of actions already being taken"* instrument `TRIAGE-FOR-COHERENCE` argues for, it already exists, and the architecture map filed it under detritus. **The crate that mechanically enforces architecture across the tree read as unreachable to the architecture map**, because enforcement is expressed as tests and tests create no dependency edge.

**`zp-bench` could never have scored anything else.** No `src/`, so no library, so no possible dependent. Its fan-in is 0 by construction, and a measure that flags a structurally-fixed value is reporting its own shape.

**`trust-triangle`'s disposition already existed** — `Cargo.toml` carries `# trust-triangle excluded — standalone reference demo, not part of core build`. AL-B spent a paragraph asking a question the manifest answered. A disposition recorded where the corpus cannot see it is, for corpus purposes, not recorded.

What it buys: `zp-bench` turns out to be the *real* finding the false ones were hiding. Nothing in `.github/workflows` runs `cargo bench`, so the governance-gate benchmark has never executed in CI. Reachable, never reached — and no fan-in measure of any sophistication could have surfaced it, because the crate's fan-in is correct.

**This is the fifth instance of the pattern recorded in `TRIAGE-FOR-COHERENCE` §First run finding 4** — a measure moving for a reason other than the reality it names — and the first found after the day that produced the other four, which is what makes it a property rather than a coincidence. It is also the worst of the five: the earlier four moved a number, this one assigned a wrong label to six-sevenths of a set and the label was the whole point of the column.

---

## Verifiable outcomes (AL)

- **AL1** — Every crate is reachable from an entrypoint, or is explicitly recorded as deliberately standalone.
- **AL2** — No crate with **no reachable target of any kind** — not a dependent, `[[bin]]`, `tests/`, `benches/` or `examples/` — exists without a recorded disposition. *Restated 2026-07-29; the original said "fan-in 0 at depth 0", which the correction above shows tests the wrong predicate.*
- **AL2b** — Every declared target is actually invoked by something. `zp-bench` satisfies AL2 and fails this, which is why it needs to be separate.
- **AL3** — Every crate with fan-in ≥ 3 is described by at least one governed document.
- **AL4** — The map regenerates cleanly and its layer assignment stays acyclic.
- **AL5** — Entrypoint crates hold no logic another crate would want, measured by extraction candidates rather than by line count.

---

## Open positions

- **AL-A — Do the standalone crates rejoin the workspace?** `zp-emission-coherence` and `zp-inference-observer` declare their own `[workspace]`. That is defensible for independent build, and it also keeps them out of `cargo build --workspace` and therefore out of CI. *Resolution: an operator decision per crate, recorded in the crate's own manifest comment.*
- **AL-B — Is `trust-triangle` an orphan or a demo?** **RESOLVED 2026-07-29 — it was already answered.** The root `Cargo.toml` carries `# trust-triangle excluded — standalone reference demo, not part of core build` on the line where its membership would sit. The disposition existed; it was invisible because it lives in a manifest comment and nothing reads manifest comments. The open position should never have been opened, and the lesson is worth more than the answer: **before recording a question about a crate, read its manifest, including the comments.** Remaining live sub-question, narrower: whether that comment should be mirrored into a governed document so the corpus can see it. *Resolution: yes if any check comes to depend on it; otherwise leave it where the person editing membership will read it.*
- **AL-C — Should the map carry fan-in directly?** **RESOLVED 2026-07-27.** The map now carries a fan-in column, sorts each layer by it, and reports a *load-bearing* set (fan-in ≥ 3, currently 14 crates). The change surfaced a defect in a neighbouring check and it is recorded here rather than quietly fixed: adding this document to the corpus dropped the undocumented-crate count from 8 to 1, because a document that *lists* crates satisfies a check that only tests for a mention. The architecture documents are now excluded from that corpus scan — they enumerate every crate by construction, so counting them makes the measure self-satisfying. The honest count is 8. **A mention is not a description**, and any future check of this shape should assume the document doing the checking is the easiest way to game it.
- **AL-D — What is the right ceiling for an entrypoint crate?** No convention exists, and `zp-server` is 38,456 lines. *Resolution: either a stated ceiling that triggers extraction review, or an explicit position that entrypoint size is not a defect.*

---

## What is specified vs. what is shipped

Per A11: every figure here is read from `ARCHITECTURE-MAP.md` generated at commit `a952b50`, which derives from `Cargo.toml` manifests and `//!` module docs. Fan-in counts are derived from the map's used-by column. Nothing here is inferred from a crate's name.

Reachability figures are as of the 2026-07-29 generator change and were confirmed by direct inspection of each crate's `Cargo.toml` targets and directory layout, not by re-running the map — regenerate before quoting them.

Not verified: whether each crate's stated purpose matches what it does — the map reports what a crate *says* about itself, and the ML inventory found at least three cases (`zp-learning`, `MLEStarEngine`, `zp-inference-observer`) where the name promises more than the code delivers. A purpose-versus-behaviour audit is a separate pass.

---

## Non-goals

- **Not a refactoring plan.** It names where mass and leverage sit; what to do about either is decided per case.
- **Not a replacement for `ARCHITECTURE-2026-07.md`.** That document is the conceptual record and is frozen as Historical. This is a structural reading, not a reconceptualization.
- **Not a claim that depth is quality.** A deep crate is not worse than a shallow one. Depth is build order.
- **Not authoritative on Layer A / Layer B.** That axis is KEEL's and is untouched here.
