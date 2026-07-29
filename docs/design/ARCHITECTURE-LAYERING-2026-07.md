# Architecture Layering

**Document type:** Design note — the authored companion to a derived artifact. **Not** a Tier 2 canonical elaboration; it elaborates no KEEL section. `docs/ARCHITECTURE-MAP.md` is generated and states what the crates *are*; this states what the shape *means*, which no generator can produce.

**Date:** 2026-07-27. **Status:** First reading, against commit `a952b50`. Numbers below will drift; the map regenerates, this does not.

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

**Depth 0 — bedrock and detritus, indistinguishable by depth alone.** Sixteen crates. One is bedrock: `zp-receipt` (7,348 lines, fan-in 15). Four are genuine shared infrastructure: `zp-config`, `zp-net`, `zp-anchor`, `zp-content`. Four are single-consumer specialisms: `mle-star-engine`, `monte-carlo-engine`, `zp-sensors`, `zp-verbs`. **Seven have no consumer at all** — `zp-bench`, `zp-cloudflare`, `zp-discipline`, `zp-emission-coherence`, `zp-inference-observer`, `zp-memory-index`, `zp-preflight` — 6,347 lines that nothing in the tree reaches.

**Depth 1 — identity and verification.** `zp-core` (fan-in 23) and `zp-verify` (3), plus two narrow carriers. The whole substrate's type vocabulary lives one step above the receipt.

**Depth 2 — the trust primitives.** `zp-audit` (10), `zp-trust` (7), `zp-keys` (6). This is where the corpus's headline claims actually live, and the fan-in confirms it: three of the four widest-used crates in the tree are here. `zp-gossip` sits at this depth with fan-in 0.

**Depth 3 — governance and transport.** `zp-policy` (6), `zp-mesh` (17,954 lines, 4), `zp-engine` (3), `zp-officers` (3). The mesh is the single largest non-entrypoint crate, which is worth noting given that its `DiscoveryManager` is unwired and its inbound authentication is feature-gated off.

**Depth 4 — mediation and cognition.** `zp-host` (fan-in 4) is the host-function boundary through which KEEL §II.8 requires every privileged side effect to pass — and at 767 lines it is one of the smallest crates carrying one of the largest claims. `zp-regent` is 12,113 lines with fan-in 1.

**Depths 5–6 — composition.** `execution-engine`, then `zp-pipeline` (6,928, fan-in 3). Thin.

**Depths 7–8 — entrypoints.** `zp-server` and `zp-cli`, plus `course-examples` and `zp-hardening-tests` riding at the top with no consumers, which is correct for tests and examples.

---

## What the shape says

**The waist is narrow and that is good.** Depths 5 and 6 hold one crate each. Composition happens late and thinly, which means the trust primitives at depths 1–3 are reusable independently of the server. A substrate whose primitives could only be exercised through its own entrypoint would be far harder to prove anything about.

**The unwired mass is concentrated at depth 0.** Seven of eight unwired crates sit at the bottom, which is the good version of that problem — nothing depends on them, so wiring or removing them disturbs nothing. It is also the diagnostic version: a crate written at depth 0 with no consumer is a capability built before its call site, which is C2 by construction.

**`zp-host` is the highest-leverage small crate in the tree.** 767 lines, fan-in 4, and it carries §II.8's *"access side-effect primitives only through host-mediated interfaces that gate-check on the way out."* Its own doc comment anticipates WASM callers delegating to the same trait. Everything the executable-artifacts mapping proposes routes through it.

**Two crates are large enough to hide things.** `zp-server` at 38,456 lines and `zp-mesh` at 17,954. The mesh survey earlier today found unwired discovery, disabled inbound auth and unbounded intake inside the second one — none of which was visible from outside it.

---

## Where buildout should push

Stated as a reading, not a plan; sequencing is the operator's.

1. **Resolve the seven unwired depth-0 crates before adding new ones.** Each is either wire-it or retire-it, and both are cheap now precisely because nothing depends on them. `zp-memory-index` and `zp-emission-coherence` already have named consumers waiting in the corpus.
2. **Grow `zp-host` deliberately.** It is the narrowest point through which the widest claim passes, and the host-import layer that KEEL Part V specifies has no implementation. Work here has the highest ratio of claim-satisfied to lines-written in the tree.
3. **Split by extraction, not by addition, at depths 7–8.** 57,644 lines of entrypoint is where behaviour accumulates unreusably. Anything in `zp-server` that another crate could plausibly want belongs lower.
4. **Treat the eight undocumented crates as a corpus gap, not a code gap.** `zp-net` has four dependents and no governed document describing it. Under the triage denominator, a crate no document mentions is outside the measure entirely.

---

## Verifiable outcomes (AL)

- **AL1** — Every crate is reachable from an entrypoint, or is explicitly recorded as deliberately standalone.
- **AL2** — No crate at depth 0 has fan-in 0 without a recorded disposition.
- **AL3** — Every crate with fan-in ≥ 3 is described by at least one governed document.
- **AL4** — The map regenerates cleanly and its layer assignment stays acyclic.
- **AL5** — Entrypoint crates hold no logic another crate would want, measured by extraction candidates rather than by line count.

---

## Open positions

- **AL-A — Do the standalone crates rejoin the workspace?** `zp-emission-coherence` and `zp-inference-observer` declare their own `[workspace]`. That is defensible for independent build, and it also keeps them out of `cargo build --workspace` and therefore out of CI. *Resolution: an operator decision per crate, recorded in the crate's own manifest comment.*
- **AL-B — Is `trust-triangle` an orphan or a demo?** Neither a workspace member nor standalone, 1,348 lines, fan-in 0, no governed document. *Resolution: classify as example (join `course-examples`), retire, or adopt.*
- **AL-C — Should the map carry fan-in directly?** This document computed it by hand from the used-by column. It is derivable and would make the depth-0 split visible without a reader doing arithmetic. *Resolution: a small generator change; worth doing before the next reading.*
- **AL-D — What is the right ceiling for an entrypoint crate?** No convention exists, and `zp-server` is 38,456 lines. *Resolution: either a stated ceiling that triggers extraction review, or an explicit position that entrypoint size is not a defect.*

---

## What is specified vs. what is shipped

Per A11: every figure here is read from `ARCHITECTURE-MAP.md` generated at commit `a952b50`, which derives from `Cargo.toml` manifests and `//!` module docs. Fan-in counts are derived from the map's used-by column. Nothing here is inferred from a crate's name.

Not verified: whether each crate's stated purpose matches what it does — the map reports what a crate *says* about itself, and the ML inventory found at least three cases (`zp-learning`, `MLEStarEngine`, `zp-inference-observer`) where the name promises more than the code delivers. A purpose-versus-behaviour audit is a separate pass.

---

## Non-goals

- **Not a refactoring plan.** It names where mass and leverage sit; what to do about either is decided per case.
- **Not a replacement for `ARCHITECTURE-2026-07.md`.** That document is the conceptual record and is frozen as Historical. This is a structural reading, not a reconceptualization.
- **Not a claim that depth is quality.** A deep crate is not worse than a shallow one. Depth is build order.
- **Not authoritative on Layer A / Layer B.** That axis is KEEL's and is untouched here.
