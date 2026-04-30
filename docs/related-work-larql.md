# Related Work: Model Decomposition, Reasoning Fingerprints, and Cognitive Accountability

*Draft entries for whitepaper §15 (Related Work). Status: stub for review.*
*Updated 2026-04-18: Added MEDS and three-layer accountability framing.*

---

## LARQL (Bytez, 2024)

LARQL is a query language and decomposition framework that reinterprets the
feed-forward network (FFN) layers of a transformer as a graph database:
entities as nodes, features as edges, relations as edge labels. Its Vindex
format decomposes dense FFN weights into an explicit graph structure, and
inference proceeds as a KNN graph walk over gate vectors rather than dense
matrix multiplication — producing equivalent outputs in a queryable form.
Attention remains standard QKV projections, acting as a navigator that routes
which FFN features matter for a given query. LARQL supports SQL-like
operations against this internal graph — DESCRIBE, SELECT, SHOW, INFER — and
a two-phase edit flow (INSERT to a patch overlay, then COMPILE back into
standard weight formats) for surgical knowledge modification without
retraining.

LARQL and ZeroPoint share a structural aesthetic: both treat legibility as
the prerequisite for accountability. Both externalize what was previously an
opaque substrate as an explicit, addressable graph — LARQL extracting a
relational schema from trained FFN weights, ZeroPoint constructing an
append-only evidence graph from Genesis forward. Both maintain a clean
separation between the substrate (FFN / receipt chain) and the navigator
(attention / policy engine), and both support a two-phase commit for
edits with an intermediate overlay.

The systems operate at different layers and under different threat models.
LARQL operates within a single trust boundary — the model operator
introspecting their own artifact — and does not carry intrinsic
tamper-evidence; the Vindex format is decomposable but not cryptographically
sealed. ZeroPoint operates across trust boundaries with mutually suspicious
participants, and its Blake3 hash chaining is forgery-resistant by
construction. LARQL's graph is *reverse-engineered* from a trained artifact
(inheriting polysemanticity); ZeroPoint's graph is *constructive*
(inheriting whatever typing discipline is imposed at receipt emission).

The systems compose naturally rather than compete. An agent operating under
ZeroPoint governance could carry LARQL-indexed knowledge, and ZeroPoint's
chain could record knowledge-edit events (INSERT/COMPILE) with the same
provenance properties as delegation events. This layering — cryptographic
provenance over model-internal decomposition — appears to be the productive
synthesis; neither system alone provides both legible internals and
verifiable accountability across parties.

See also: §15.x (Design Note — LARQL Integration) for a sketch of how
this composition might be realized inside `zp-skills`.

## MEDS (Memory-Enhanced Dynamic Reward Shaping, 2025)

MEDS is a reinforcement learning method that addresses mode collapse in
LLM training by remembering and penalizing recurring internal error
patterns. For each rollout, MEDS stores layer-wise logits at the final
answer token as a compact "logic fingerprint" of the reasoning trajectory.
It clusters these fingerprints using HDBSCAN to identify dense regions of
repeated errors — "stable error basins" — and dynamically scales up a
penalty when new rollouts land in those basins, forcing the policy to
explore new reasoning paths.

Two findings are architecturally significant for ZeroPoint:

First, MEDS demonstrates that layer-wise activations are a reliable
signature of reasoning structure, not just surface variation. Two rollouts
with different wording but the same faulty logic produce similar
fingerprints; genuinely different reasoning paths produce different
fingerprints. This validates the concept of trace commitments (§1):
internal activations carry enough signal to distinguish reasoning
trajectories, which means committing a trace hash to a receipt chain is
committing to the actual computation, not a post-hoc narrative about it.

Second, MEDS finds that only the last ~14 transformer layers give good
alignment between clusters and true logical error types, because deep
layers encode higher-level logic rather than surface grammar. This has
engineering implications for trace commitments: layer-selective commitments
(committing to deep-layer fingerprints for reasoning accountability,
full traces on demand) may be the right tiered approach to control
overhead without sacrificing audit fidelity.

MEDS and LARQL are complementary lenses on the same substrate. LARQL
decomposes what the model *knows* (FFN as queryable graph). MEDS
characterizes how the model *reasons* (activation fingerprints as
trajectory signatures). Together, they provide the two inputs needed for
full cognitive accountability: a decomposed knowledge state and a
classifiable reasoning trajectory.

MEDS's error-basin concept also gives ZeroPoint a concrete mechanism for
drift detection. An agent whose reasoning fingerprints consistently land
in dense clusters — even when outputs appear acceptable — is exhibiting
low cognitive diversity, which is a leading indicator of failure under
distribution shift. This signal, anchored to the receipt chain, becomes
an auditable property: not "we suspect the model is stuck" but "here
are the fingerprints, here is the clustering, here is the penalty
applied, here is the receipt."

See also: `docs/future-work/cognitive-accountability.md` for the
three-layer accountability architecture that integrates both LARQL and
MEDS with ZeroPoint's receipt chain.
