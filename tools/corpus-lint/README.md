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

- a reference annotated `(not yet written)` is a declaration, not a dangle
- a receipt near an `Implementation status: specified, not shipped` marker is
  exempt from drift reporting
- a document whose header declares Tier 3 historical or superseded is excluded
  from amendment-shaped checks entirely

Every check is justified by a defect found on 2026-07-25; none is speculative.
Checks that could not find their motivating instance reliably were removed
rather than tuned.
