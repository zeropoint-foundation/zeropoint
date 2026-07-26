# Connection Integrity Program

**Document type:** Program. Not a Tier 2 canonical elaboration — it elaborates no KEEL section. It defines a standing property the substrate does not currently have, names the eight ways that property has been violated, and specifies the work to establish it. Tier 3 input; supersedes nothing.

**Date:** 2026-07-26.

**Motivation:** Ten commits landed in one session. Every defect they closed was work that already existed and was not connected to the thing that would have made it count. Not one was a missing feature.

**Composes with:** `SUBSTRATE-LOOP-CLOSURE-2026-07.md` (the seven-edge audit this generalizes, and whose §6 declined the survey this program must not become), `AUTHORING-DISCIPLINE-2026-07.md` (A11 — distinguish specified from shipped), `IMPROVEMENT-LOOP-DISCIPLINE-2026-07.md` (Stage 1t tie-offs, the mechanism for declared absence), `SPEC-IMPLEMENTATION-COHERENCE-INVESTIGATION-2026-07.md` (§2, the audit method), `EMPIRICAL-PROGRAM-2026-07.md` (the four architectural claims this protects).

---

## 1. The finding this program exists to answer

The substrate's failures are not absences. They are **unrealized edges**: a dependency asserted in one place and not honoured in another, where both endpoints are individually correct and the connection between them is not.

This class is invisible to every instrument currently pointed at it. Nothing fails. Tests pass. The code compiles, the docs are internally consistent, the feature is present in the tree. The defect surfaces only when someone traverses the edge by hand and finds the far end.

Eight distinct varieties have now been observed. Each is listed below with the defect that revealed it, because a taxonomy derived from anything other than observed failures is a guess with a table around it.

## 2. Why the deliverable is not a map

`SUBSTRATE-LOOP-CLOSURE-2026-07.md` §6 considered a full corpus audit and declined it:

> *Unbounded, and its output is a document rather than a standing property — which reproduces the problem it diagnoses.*

That reasoning binds this program, and more strongly, because the scope here is larger. A hand-authored inventory of substrate connections would be the ninth variety of the same defect: an artifact asserting a structure, correct on the day it was written, drifting silently from the thing it describes, and read as current because it looks authoritative.

**The map is an output, not an input.** It is generated from detectors that run in CI, and it is only ever as true as the last run. If a connection is not covered by a detector, it does not appear on the map as "unknown" — it appears as a **defect**, because unclassified is the condition this program exists to eliminate.

The corresponding discipline for the program itself: **no phase of this work is complete until it has shipped a check that would fail.** A phase that produces only findings has not finished.

## 3. The eight conditions

Each condition is a way an edge can be unrealized. `Detector` records what exists today.

### C1 — Specified, not built
The corpus asserts a mechanism; no code implements it.

*Evidence:* 778 receipt types across 103 namespaces documented with no implementing family in the code registry (`corpus-lint receipt-coverage`, 2026-07-26) — `regent:` 86, `lens:` 54, `delegation:` 32. Zero `lens:applied` or `lens:declared` occurrences anywhere in `crates/`, against a primitive with four specified receipt types and a KEEL axiom. `prompts/{model_family}/` resolution, assumed by the model-prompt coupling invariant, absent from the code.

*Detector:* **Partial.** `corpus-lint receipt-coverage` catches this for receipt strings only, and reports it as a measurement rather than a defect — correctly, since the corpus is permitted to specify ahead of the code. What is missing is the *declaration*: a specified-not-built mechanism should say so in its own text, and nothing checks that it does.

### C2 — Built, not wired
An implementation exists and no path reaches it.

*Evidence:* `browser_use` carried a complete dispatch arm with six sub-actions, a domain gate, and harness integration, and was absent from `REGENT_TOOLS` — so no grant, no delegation, no reachability. Discovered only because a pin was written that happened to check the same list.

*Detector:* **Exists, narrowly.** `granted_tools_must_be_reachable` covers Regent tools. Nothing generalizes it.

### C3 — Built and wired, not known
The edge is live and the consumer that must select it has no knowledge of it.

*Evidence:* `self_configure` was granted, declared as a delegation, dispatched, and implemented — and absent from the routing model's hand-maintained menu. The routing tier could only emit `respond`. A standing correction requiring config verification before citing a model name therefore became unsatisfiable, and the Regent's refusal to answer read as evasion. She was obeying.

*Detector:* **Exists, narrowly.** The single-sourcing clause of the same pin. The general form — *every consumer that must choose among N things can enumerate all N* — has no instrument.

### C4 — Wired, not enforced
The check runs and does not check. **The most dangerous class, because it reads as green.**

*Evidence:* `browser_use`'s domain allowlist was a substring test against the whole URL; `https://evil.example/?x=localhost` passed, as did `https://zeropoint.global.attacker.net/`. The `js` action carried no URL and so never reached the gate at all. Separately, four discipline pins were correct, committed, and never enforced, because `cargo test` aborts remaining targets on first failure and one failing pin masked every pin after it.

*Detector:* **None.** Note that the masking case had no code defect at all — the pins were right; the harness invocation was wrong. Enforcement is a property of how a check is *run*, not only of how it is written.

### C5 — Emitted, not consumed
Output is produced that nothing reads.

*Evidence:* GLM-5.2 returns reasoning tokens in `reasoning_content`; the substrate's OpenAI parser reads only `choices[0].message.content`, so the tokens are generated, billed at $4.40/1M, and discarded — a cost defect no correctness test would catch, because the prose still arrives. `cognitive:act:recorded` now emits at four cycle exits with no consumer yet.

*Detector:* **None.**

### C6 — Configured, not honoured
A configuration surface whose readers disagree, or which nothing reads.

*Evidence:* `inference_endpoint` means *the local Ollama endpoint* to `route_from_config`, the `Evaluation` branch, and all of `inference.rs`, and *the cloud endpoint* to the dossier-scoring path — one field, two meanings, coherent within each frame. `web:allowed_domains` is a delegation scope selector nothing reads; `ALLOWED_DOMAINS` is a const in the dispatch arm. All five standing corrections carry `scope: {applies_to: [], surface: []}`, which matches everything, so a substrate-self-reference correction is in context when the operator says "Hi." Historically, eight config sections configured nothing.

*Detector:* **None.** The corpus records a manual method — *remove the field, see if the build still compiles* — which distinguishes operational consumers from self-referential validators. It has never been automated.

### C7 — Loaded, not versioned
The runtime reads a file that is not in the repository, or resolves it by a path that will not exist where the binary runs.

*Evidence:* All six `model_dossier.toml` files, plus `models/README.md` and `models/modelfiles/`, were untracked until 2026-07-26 — `models/` was ignored wholesale to exclude ~820MB of TTS weights. Zero files under it had ever been tracked. Tracking them turned out to be necessary and not sufficient: the loader resolves the corpus from `env!("CARGO_MANIFEST_DIR")`, the *build host's* path, so on any other machine the read fails, `load_from_dir` warns and returns empty, and every routing decision falls through to `route_from_config`. ARTEMIS has never exercised dossier-based routing.

*Detector:* **First slice shipped** — `no_build_time_paths_at_runtime` (2026-07-26). Covers build-time path leakage only. The general form is unbuilt: 102 runtime file-open sites exist across `crates/*/src/`, most resolving dynamically from config, which needs the P1 enumeration rather than a pattern match.

### C8 — Declared complete, not integrated
A corpus artifact claims membership in a structure that does not include it.

*Evidence:* `REGENT-DOOM-LOOP-DETECTION-2026-07.md` asserted in its header, its composition section, and its connects-to list that it *is* Class 8 of the Cognitive Self-Observer's verification catalog. The observer ships Classes 1–7. All three assertions read as settled because they were phrased as description.

*Detector:* **Partial.** `corpus-lint check_doc_crossrefs` resolves references to sections that exist. It cannot catch a claim of membership that the referenced document does not corroborate.

---

**Three conditions have narrow detectors, one has a first slice, four have none.** The detection surface for this entire class of defect is one day old.

## 4. The connection object

A **connection** is a directed edge `(source, target, kind, assertion_site, realization_site)` where the substrate depends on the target being reachable from the source.

Every connection carries exactly one status:

- **Live** — a detector exists that would fail if the edge broke. Not "it works today"; *its breaking would be caught.*
- **Tied off** — declared absent, with a disposition and a `reopen_condition`, per `IMPROVEMENT-LOOP-DISCIPLINE-2026-07.md` Stage 1t. Chain-anchored. A deliberate absence is a legitimate permanent state.
- **Defect** — neither of the above. Includes every edge nobody has classified.

There is no fourth status, and specifically no "known to work." An edge that works and would break silently is a defect that has not fired yet.

Stage 1t is load-bearing here and is reused rather than reinvented. The substrate already has a chain-anchored mechanism for declaring "this is deliberately not connected, and here is what would reopen it." The program needs no new ceremony. The first instance is in the tree: `crates/zp-server/src/regent.rs`, the dossier path, carrying a disposition and a reopen condition inline.

## 5. What "fully mature" means

Not zero broken connections. **Zero unclassified connections.**

```
maturity = |Live ∪ TiedOff| / |All connections|
```

with the target being `|Defect| = 0`, not `|TiedOff| = 0`. A substrate with 200 live edges and 60 tied-off ones is mature. A substrate with 260 working edges and no classification is not, because nothing distinguishes the ones that would break silently from the ones that would break loudly.

This is the *lsof test* generalized. That heuristic says the substrate is mature when the operator can read `lsof` output as a posture statement rather than a forensics exercise — every listening process traced to a receipt or explicitly out of scope. The same shape applied to internal structure: every connection traced to a detector or explicitly tied off.

It is also *detectability over invulnerability* applied inward. The program does not attempt to make every edge correct. It makes every edge's breakage visible.

## 6. The inventory is derivable, not authorable

Seven sources already in the tree can generate the connection set mechanically. This is the load-bearing claim of the program: **nobody writes the inventory.**

| Source | Edges it yields | State |
|---|---|---|
| `crates/zp-server/src/substrate_validate.rs` — `KNOWN_RECEIPT_PREFIXES` | code → chain receipt vocabulary | de-facto registry, already consumed by corpus-lint |
| `crates/zp-discipline/tests/` (19 pins) | structural rules with declared allowlists | each allowlist entry is a declared exception = a tie-off in all but name |
| `tools/corpus-lint/` (9 checks, 115 governed docs) | doc → doc, doc → KEEL, doc → receipt | running, 0 defects, 2 measurements |
| `graphify-out/graph.json` | code → code, EXTRACTED + INFERRED | present; underused for this purpose |
| `//! Spec:` module citations | code → corpus | **5 files.** Against 115 governed docs. E1 is ~4% instrumented |
| Cargo workspace dependency graph | crate → crate | complete and trustworthy by construction |
| `include_str!` / `read_to_string` / `File::open` sites | code → file artifact | 102 sites, unclassified |

The gap is stark in one row. Five files carry a spec citation. The corpus→code edge — the one that would tell you whether a specification has an implementation — is essentially uninstrumented, which is exactly why C1 and C8 are the conditions with the weakest detection.

## 7. Phases

Each phase ships a check. A phase that ships only findings is not done.

### P0 — The cheapest detector, as proof of shape — **shipped 2026-07-26**
`no_build_time_paths_at_runtime`. Runtime file resolution may not depend on build-time paths.

Deliberately first because C7 was the newest condition and the least theorised — if the program's shape is wrong, it is cheapest to discover here. It found one violation on its first run (the dossier corpus), which is tied off rather than fixed because the correct runtime location is a Substrate Form decision.

*Exit:* met. The pin exists, the violation is enumerated, and the tie-off carries a reopen condition.

### P1 — Enumerate from the seven sources
Build `tools/connection-map/` that emits `connections.json` from the sources in §6. No new analysis; only collation of what the tree already knows. Every edge lands as Live, TiedOff, or Defect by the §4 rule, and the initial Defect count will be large — that number is the baseline, and a large one is the expected result, not a failure of the tool.

*Ships:* the generator plus its first output, committed so drift is diffable. *Exit:* a number for `|Defect|`.

### P2 — Detectors for the unhandled conditions
In order of danger rather than ease.

**C4 (wired, not enforced)** first — it is the class that reads as green. Two sub-checks: gates that do not gate (a domain check that cannot reject, a scope selector with no reader, a validator whose only consumer is itself) and checks that do not run (`--no-fail-fast` is landed; the general form is that every declared check appears in an invocation path that CI actually executes).

**C6 (configured, not honoured)** second — automate the remove-the-field method. A config field whose deletion breaks only its own validator is not configuration.

**C5 (emitted, not consumed)** third — every receipt prefix in the registry and every response field parsed has at least one reader, or is tied off as write-only-for-audit, which is a legitimate disposition and must be declared rather than assumed.

**C8 (declared complete, not integrated)** fourth — membership claims are checked bidirectionally. If document A says it is part of structure B, B must corroborate.

### P3 — Close the corpus→code edge
The §6 table's worst row. Extend `//! Spec:` citation coverage from 5 files toward the governed-doc set, and make `corpus-lint check_spec_citations` bidirectional: every Tier 2 doc claiming an implementing module names one that exists, and every implementing module cites the doc it implements.

This is the phase that turns C1 from a measurement into a check, because it is what makes *specified* and *shipped* mechanically distinguishable rather than a matter of reading carefully.

### P4 — The ratio as a standing property
`connections.json` regenerates in CI. `|Defect|` is reported per run and is permitted to rise only with an accompanying tie-off. The map becomes an artifact like `docs/lenses/source-manifest.json` — regenerable, diffable, never hand-authored.

*Exit:* maturity is a number the substrate reports about itself.

---

## 8. What this program does not do

- **It does not fix the edges it finds.** Instrumentation before remediation, per the standing posture. P1's Defect count is expected to be large and is not a work queue by itself.
- **It does not replace the discipline pins.** It generalizes their coverage question — *what is not pinned?* — and the pins remain the enforcement mechanism.
- **It does not require the Cartographer.** Every source in §6 exists today. `SUBSTRATE-LOOP-CLOSURE` §2 re-prioritized the Cartographer as the highest-leverage single absence; this program is orthogonal and neither blocks it nor is blocked by it.
- **It is not a claim that the substrate is broken.** Every absence found so far was planned. The finding is that plans and reality diverge without anything noticing, and that the noticing is the missing organ.

## 9. Alternatives considered

Recorded as tie-offs per A6.

- **Hand-author the connection map first, instrument second.** *Declined.* It is the ninth variety of the defect — an authoritative-looking artifact drifting from what it describes. Reopen condition: if P1's generator cannot reach a subsystem at all, that subsystem needs a hand pass to establish what its edges even are, and the pass output must be a detector.
- **One detector per condition, no generated map.** *Declined.* Detectors answer "is this edge broken." Only an enumeration answers "which edges is nobody asking about," and the unasked edge is where all eight conditions have actually lived. Reopen condition: if P1's Defect count proves too noisy to act on, fall back to detectors alone and accept partial coverage.
- **Extend graphify rather than build `tools/connection-map/`.** *Deferred.* graphify already extracts code→code edges and has a query interface. It does not model corpus, chain, config, or artifact edges, and teaching it to would be a larger change than collating seven sources. Reopen condition: P1 complete, at which point the overlap is measurable rather than guessed.

## 10. Open positions

- **What is the unit of a connection?** §4 defines it structurally, but the granularity is unsettled — is `zp-regent → zp-audit` one edge or one per call site? Too coarse hides defects; too fine makes `|Defect|` meaningless. Resolution: P1's first run, empirically.
- **Does a tie-off need operator signature?** Stage 1t is chain-anchored, but tying off a connection is a claim that an absence is deliberate, and P9 says the operator signs consequential acts. If every unclassified edge needs a signature, the ceremony cost may exceed the program's value. Resolution: P1's Defect count.
- **Is `|Defect| = 0` reachable, or asymptotic?** Every new subsystem adds edges faster than detectors get written. The program may describe a gradient rather than a destination — which would still be useful, but should be said plainly rather than discovered later.
