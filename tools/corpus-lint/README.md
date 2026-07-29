# corpus-lint

Mechanical coherence checks over the governed corpus and its correspondence
with `crates/`. Instrumentation for the E1 and E2 edges of
`docs/design/SUBSTRATE-LOOP-CLOSURE-2026-07.md`.

    python3 tools/corpus-lint/corpus_lint.py .              # report
    python3 tools/corpus-lint/corpus_lint.py . --strict     # exit 1 on defect
    python3 tools/corpus-lint/corpus_lint.py . --json       # machine-readable
    python3 tools/corpus-lint/corpus_lint.py . --only crossref,keel-refs

## Scope

The **governed corpus** is what `CANONICAL-CORPUS-INDEX-2026-07.md` lists,
minus documents marked Tier 3 historical or superseded. Documents predating
the tier, index and receipt-registry conventions are a separate stratum:
linting them uniformly reports the corpus's age as defect, and the corpus's
own rule is that Tier 3 is frozen at authoring frame and never amended for
corpus pivots. They are counted, not flagged.

## Defects vs measurements

**Defects** fail `--strict`: a cited KEEL section that does not exist, a
referenced document that does not exist, a duplicate numbered section, a
dangling index entry, a missing tier declaration, a `//! Spec:` citation that
does not resolve, receipt drift within a live family.

**Measurements** never fail. They report the size of the pre-convention
stratum and of the specified-not-shipped receipt surface — properties of a
corpus mid-construction, not faults in it.

## Annotations the checks respect

Per `AUTHORING-DISCIPLINE-2026-07.md` A11, an author can declare status and
the tool will stop asking:

- a reference annotated `(not yet written)` is a declaration, not a dangle.
  The annotation is matched by head, so it may carry a detail clause —
  `(not yet written; neither function exists as of 2026-07-27)` still counts
- a path annotated `(external — …)` is declared to live in someone else's
  tree and is never resolved against this one
- a receipt near an `Implementation status: specified, not shipped` marker is
  exempt from drift reporting
- a document whose header declares Tier 3 historical or superseded is excluded
  from amendment-shaped checks entirely
- a line that reports a path as missing — "does not exist", "dangling",
  "absent from", "unbuilt" — is not flagged for naming it. An investigation
  quoting a dangling path is doing its job, not committing the defect
- `docs/handoffs/*` is never path-checked: handoffs are local notes by the
  convention in `CANONICAL-CORPUS-INDEX-2026-07.md`, and their paths are not
  expected to resolve in any clone

## Added 2026-07-27

Three checks from the first triage-for-coherence pass, each justified by a
real finding of that day rather than by a category someone imagined:

- **`doc-path`** (defect) — a backticked repo path in a governed doc that does
  not resolve. Motivated by `AGENT-TOOL-CONTRACT-2026-06.md` citing a Wasmtime
  capability schema for a runtime never present in this repo. File paths are
  the defect; directories are reported separately as `doc-path-prospective`,
  because "this will live here" is C1 and the corpus may specify ahead of code.
- **`doc-symbol`** (defect) — a backticked identifier in a Rust doc comment
  absent from its own crate. Motivated by `CapabilityGrant::delegate`
  documenting its scope check as enforced by a function that never existed.
  Expected to report zero: it is a regression guard. Backticks are invisible to
  rustdoc, so nothing else reaches this class.
- **`pub-consumer`** (measurement) — a public type with no non-test,
  non-import consumer. C2 of `CONNECTION-INTEGRITY-PROGRAM-2026-07.md` at type
  granularity, which that program records as ungeneralized. Motivated by
  `MerkleProof` in `zp-receipt`: complete, tested, re-exported, never called.
  Counting a re-export as a consumer is precisely what hides this, so imports
  are stripped before the index is built.

Every check is justified by a defect found on 2026-07-25; none is speculative.
Checks that could not find their motivating instance reliably were removed
rather than tuned.
