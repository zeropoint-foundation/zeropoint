# ZeroPoint Foundations

This directory contains the formal artifacts that define ZeroPoint's correctness, vocabulary, and intellectual commitments. These are not documentation *about* the system — they are the system's formal layer, the thing the code exists to satisfy.

## Documents

- **[INVARIANT-CATALOG-v1.md](INVARIANT-CATALOG-v1.md)** — The grammar. 6 productions, 13 invariants, 4 cross-layer coherence rules, falsification procedures, claim status register with transition history. The specification of what it means for a ZeroPoint system to be well-formed. Lineage: v0 (2026-04-06, post-pentest) → v1 (2026-04-25, updated with canonicalization, governance-without-runtime, Claims 1/3 fixes).

- **[FORMAL-PRIMITIVES.md](FORMAL-PRIMITIVES.md)** — The four constitutive primitives: canonicalization as constitutive act, trust as trajectory, governance without runtime, receipts-are-canonical/protocols-are-projections. Each stated precisely enough to disagree with, extend, or prove properties about. Includes relationship to prior work and explicit novelty claims.

- **[FALSIFICATION-GUIDE.md](FALSIFICATION-GUIDE.md)** — How to test our claims. External-facing document for auditors, researchers, and skeptics. Eight concrete test procedures, each with specific falsifying conditions. Honest about which tests will produce falsifying results today.

- **[CLAIM-METHODOLOGY.md](CLAIM-METHODOLOGY.md)** — The meta-methodology: how claims are stated, how falsifiers are designed, how status transitions are recorded, how honesty is maintained. Exportable — any project can adopt this discipline.

## Relationship to Other Directories

- `docs/design/` — Design decisions, proposals, specs. The "what we're building and why."
- `docs/foundations/` — Formal commitments. The "what must be true and how we verify it."
- `security/pentest-*/` — Adversarial findings. The "what we found when we tried to break it."
- `docs/` (root) — Architecture, whitepaper, course material. The "how it works and how to use it."
