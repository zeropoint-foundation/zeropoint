# Standing Correction Receipt Schema

**Tier 2 canonical elaboration.** Elaborates `KEEL-2026-07.md` §II.17 (Cognitive discipline sandwich), §II.18 (Chain-anchored commitments), and §III.21 (Priority-weighted cognitive context). Specifies the chain-anchored schema for operator corrections that persist across cognitive cycles — corrections that today live only in operator memory and get repeatedly re-forgotten by Regent. Canonical claims live in KEEL.

Draft — 2026-07-11 — internal audience only. Composes with `COGNITIVE-INPUT-PLANE-2026-07.md` (priority-weighted context matrix reads standing corrections at Tier 1), `COGNITIVE-SELF-OBSERVER-2026-07.md` (observer flags when Regent's output contradicts a standing correction), `CHAIN-WATCHER-AND-COMMITMENTS-2026-07.md` (standing corrections are a specific form of commitment).

## Framing

Today's diagnostic sessions surfaced a recurring pattern: operator corrects Regent on a specific claim ("no, GLM 5.2 is stated destination, not current state; you're running Sonnet 4.6"), and next cognitive cycle Regent produces the same or similar mistake ("as I'm running GLM 5.2..."). Correction lives only in operator memory. Substrate has no structural mechanism for the correction to persist as authoritative input to future cognitive cycles.

Standing corrections are the substrate's structural response. Operator-signed chain receipts of the form: *"For the purposes of Regent's cognitive layer: this claim is authoritative; this claim is not."* Every cognitive cycle's Tier 1 context includes active standing corrections. Regent's outputs that contradict standing corrections are structurally flagged by Cognitive Self-Observer. Operator's cognitive-layer trust corpus accumulates via chain rather than through repeated re-teaching.

Three properties frame the schema:

1. **Standing corrections are chain-anchored operator claims about the world**. Not internal Regent state; not app config; chain receipts signed by operator's Genesis. Same trust discipline as any operator authority.
2. **Standing corrections have scope, precedence, and lifecycle**. Not permanent global overrides. Scoped to specific claim domains; may be superseded; may expire; may conflict with other standing corrections (operator resolves).
3. **Standing corrections compose with priority-weighted cognitive context**. Tier 1 (top priority) input to every cognitive cycle. Regent's cognitive input plane reads them before source-of-truth peers. Cognitive Self-Observer verifies outputs against them post-emission.

## The schema

Standing correction receipt structure:

```
{
  "receipt_type": "cognitive:correction:standing",
  "correction_id": "<content_hash>",
  "issued_at": "<timestamp>",
  "issued_by": "<operator_genesis_pubkey>",
  "signature": "<operator_signature>",

  "correction_type": "<factual | boundary | prohibition | preference>",
  "domain": "<domain_string>",
  "scope": {
    "applies_to": ["<context_class>", ...],
    "surface": ["<surface_class>", ...]
  },
  "content": {
    "assertion": "<what is authoritative>",
    "negation": "<what should NOT be claimed>",
    "context": "<why this correction exists>"
  },
  "priority": <integer>,
  "expiry": "<timestamp | null>",
  "supersedes": ["<prior_correction_id>", ...] | null,

  "chain_link": {
    "prev_hash": "<previous_receipt_hash>",
    "index": <chain_index>
  }
}
```

### Field specifications

**`correction_type`**: four canonical types, each with different semantics for how Regent's cognitive input plane and Cognitive Self-Observer treat the correction.

- **`factual`**: correction about a fact of the world. "Substrate is running Sonnet 4.6, not GLM 5.2." Positive assertion + optional negation. Cognitive Self-Observer verifies Regent's factual claims against active factual corrections.
- **`boundary`**: correction about scope of Regent's authority or behavior. "Regent may not initiate credential probing tasks; those belong to Forge/observation-plane executor tier." Behavioral scope. Cognitive Self-Observer flags when Regent's proposed actions cross the boundary.
- **`prohibition`**: correction about what Regent should not do. "Do not narrate day-shape ('good morning,' 'rest up,' 'end of a long day') on your own initiative; mirror if operator sets frame." Behavioral prohibition. Cognitive Self-Observer flags when Regent's output violates prohibition.
- **`preference`**: correction about operator preference for how Regent should behave in specific contexts. "When discussing model state, prefer 'current state' vs 'stated destination' framing." Soft guidance. Cognitive Self-Observer notes when Regent doesn't follow preference but does not treat as violation.

**`domain`**: identifier for the topical scope of the correction. Domains are namespaced hierarchically:
- `cognitive.self_reference.model_state` — corrections about how Regent describes her own inference model
- `cognitive.narration.tone.day_shape` — corrections about time-of-day framing
- `cognitive.boundary.credential_probing` — corrections about what Regent may/may not initiate
- `substrate.factual.form_state` — corrections about factual claims about substrate form
- etc.

Domain string enables both bulk operations ("show me all cognitive.narration.tone corrections") and precise conflict detection ("does new correction conflict with existing correction in same domain?").

**`scope.applies_to`**: which cognitive context classes this correction applies to. Examples:
- `regent.dispatch_response` — Regent's response to a dispatch
- `regent.narration.operator_facing` — operator-facing narration
- `regent.narration.internal` — internal reasoning narration (may have different tone from operator-facing)
- `officer.*` — officer narration
- `dashboard.copy` — dashboard-displayed copy that Regent might have generated

**`scope.surface`**: which output surfaces this correction affects:
- `chat` — conversational output
- `receipt_content` — content of receipts Regent emits
- `dashboard_display` — dashboard-facing display text
- `narration_stream` — narration events

Scoping allows corrections to apply narrowly. Example: prohibition on day-shape narration applies to `chat` and `dashboard_display` surfaces but not to internal-reasoning receipts where such framing might be legitimate context.

**`content.assertion` / `content.negation`**: the correction itself.

- For `factual` corrections: assertion is what's true; negation is what Regent has been claiming and shouldn't. Example:
  - assertion: "Regent's inference model is currently Sonnet 4.6 via Abacus RouteLLM"
  - negation: "Do not claim to be running GLM 5.2"
  - context: "GLM 5.2 is the stated destination but has not been provisioned yet"

- For `boundary` corrections: assertion is what's in scope; negation is what's out of scope. Example:
  - assertion: "Regent may narrate credential-related findings from officers"
  - negation: "Regent may not propose or execute credential probing tasks"
  - context: "Credential probing belongs to Forge/observation-plane executor tier; vault values must never enter cognitive-layer context"

- For `prohibition` / `preference`: single content field describing what to avoid or prefer.

**`priority`**: integer indicating how heavily this correction weighs in cognitive input plane's Tier 1 assembly. Higher priority = more prominent in Regent's cognitive context.

Default priority scale:
- `100`: existential — always visible, cannot be deprioritized
- `50-99`: high — visible in every relevant context
- `10-49`: moderate — visible in strongly matching contexts
- `1-9`: soft — surface as reference but do not push into every cycle

**`expiry`**: optional timestamp after which correction is no longer active. Most corrections should have no expiry (they persist until superseded). Some corrections are inherently time-bounded (e.g., "for the duration of this migration, treat X as authoritative").

**`supersedes`**: list of correction IDs this correction replaces. Enables ordered evolution: v2 of a correction supersedes v1; chain preserves both, but only v2 is active.

## Receipt families

Three receipt families:

### `cognitive:correction:standing`

The primary receipt described above. Chain-anchored correction issued by operator.

### `cognitive:correction:acknowledged`

Emitted by Regent (via signed receipt through her delegation) when she has read a correction and confirmed she'll observe it going forward. Fields:
- Reference to correction ID
- Timestamp of acknowledgment
- Regent's paraphrase of the correction (as evidence she understood it)

Provides bidirectional confirmation. Operator can see: "Regent acknowledged correction X at time T with paraphrase Y." Divergence between paraphrase and correction content indicates cognitive-input-plane issue.

### `cognitive:correction:violated`

Emitted by Cognitive Self-Observer when it detects Regent's output contradicting an active standing correction. Fields:
- Reference to violated correction ID
- Reference to the violating output (receipt, chat turn, narration event)
- Observer's confidence in the violation classification
- Suggested remediation (typically: operator review and re-emphasize; may include: revoke Regent's cognitive delegation for this session; may include: update correction to make constraint clearer)

Violation receipts feed back into Regent's cognitive input plane as high-priority Tier 1 context on next cycle — she sees "you just violated correction X; the operator's constraint is..." and re-aligns.

## Lifecycle

**Issue**: operator emits `cognitive:correction:standing` receipt via Genesis-derived signature. Correction becomes active from receipt timestamp forward.

**Acknowledge**: Regent reads correction on next cognitive cycle. Emits `cognitive:correction:acknowledged` receipt via her scoped delegation.

**Active state**: correction present in Tier 1 cognitive context for every relevant cycle. Cognitive Self-Observer includes correction in its verification set.

**Supersede**: operator emits new correction that references old via `supersedes` field. Old correction is chain-preserved but marked inactive.

**Expire**: correction with expiry timestamp becomes inactive at expiry. Chain-preserved.

**Revoke**: operator emits explicit `cognitive:correction:revoked:<correction_id>` receipt. Correction becomes inactive from revocation forward. Chain-preserved as record of what was corrected and then explicitly withdrawn.

**Violation**: Cognitive Self-Observer emits violation receipt. Correction remains active; violation is a signal, not a state change of the correction itself.

## The seven canonical standing correction examples

From this all-day session, standing corrections that would prevent recurring re-teaching:

### 1. Stated destination is not current state

- Type: `factual` + `preference`
- Domain: `cognitive.self_reference.model_state`
- Assertion: "Regent's inference is currently Sonnet 4.6 via Abacus RouteLLM. GLM 5.2 is the intended destination and has not been provisioned."
- Negation: "Do not claim to be running GLM 5.2. Do not conflate stated destination with current state."
- Priority: 90

### 2. No day-shape framing on Regent's initiative

- Type: `prohibition`
- Domain: `cognitive.narration.tone.day_shape`
- Assertion: "Regent may mirror operator's day-shape framing when operator sets frame. Regent may not introduce day-shape framing autonomously."
- Negation: "Do not open with 'good morning'; do not close with 'rest up'; do not narrate 'end of a long day'; do not ask 'how's your day going' as filler."
- Priority: 70
- Context: "Ken's work does not have a day shape; assuming it does is patronizing."

### 3. Credential probing is not Regent's role

- Type: `boundary`
- Domain: `cognitive.boundary.credential_probing`
- Assertion: "Regent may narrate credential-related findings from Forge or observation plane."
- Negation: "Regent may not initiate credential probing tasks. Vault values must never enter cognitive-layer context."
- Priority: 100
- Context: "Credential probing belongs to Forge / observation-plane executor tier. This constraint is a load-bearing safety boundary."

### 4. Officer pronoun assignments are load-bearing

- Type: `factual` + `prohibition`
- Domain: `cognitive.self_reference.officer_pronouns`
- Assertion: "Steward: he. Sentinel: he. Forge: he. Cleo: she. Aegis: he. Regent: it (architectural) / they (persona), never she or he."
- Negation: "Do not swap officer pronouns without operator ceremony. Do not use she or he for Regent's default identity."
- Priority: 100
- Context: "No unconscious needless gender-swapping polluting the project. Ken's stated instruction."

### 5. Cartographer authority is not-fuck-with-able

- Type: `boundary` + `prohibition`
- Domain: `cognitive.boundary.cartographer_authority`
- Assertion: "Cartographer materializes the ontology from chain-anchored receipts. Cartographer has no independent signing key."
- Negation: "Do not propose Cartographer-generated authority. Do not suggest granting Cartographer signing capability."
- Priority: 100
- Context: "Ontology is understanding derived from the chain; chain is truth."

### 6. IronClaw purged from current-context corpus

- Type: `factual`
- Domain: `substrate.factual.corpus_state`
- Assertion: "IronClaw references purged from Tier 1 and Tier 2 canonical corpus. Retained in Tier 3 historical corpus with authoring-time framing preserved."
- Negation: "Do not treat IronClaw as current-substrate reference. Do not carry IronClaw framing into current design."
- Priority: 60
- Context: "Corpus refactored 2026-07-10 per Ken's instruction."

### 7. Formal public documentation is deprioritized

- Type: `preference`
- Domain: `cognitive.narration.audience`
- Assertion: "Substrate documentation is internal audience only. Draft with internal legibility as target."
- Negation: "Do not draft docs as if for external public. Do not spend effort on public-consumption polish."
- Priority: 40

## Storage and query

Standing corrections are chain-anchored receipts stored in `~/ZeroPoint/data/audit.db`. Cognitive Input Plane maintains an in-memory index:

- Domain-indexed lookup: "give me all active corrections in domain `cognitive.narration.*`"
- Scope-indexed lookup: "give me all corrections applying to `regent.dispatch_response` at `chat` surface"
- Priority-sorted retrieval: "give me top-K corrections by priority for Tier 1 assembly"
- Recency-sorted retrieval: "give me most-recent corrections for surfacing in dashboard"

On chain updates (new receipt observed), Cognitive Input Plane rebuilds relevant index slices.

## Integration with Cognitive Input Plane

Standing corrections are Tier 1 input to every cognitive cycle. Cognitive Input Plane assembly:

1. Chain state — what happened recently
2. Active officer findings — what officers are surfacing
3. **Active standing corrections matching this cycle's scope** — priority-sorted, top-K
4. Commitments referencing this cycle's context
5. Dispatch context (if cycle is dispatch-driven) or ambient state (if cycle is idle-driven)

Tier 1 corrections are always visible to Regent. Tier 2 corrections (lower priority, weaker scope match) may or may not appear depending on cycle characteristics.

## Integration with Cognitive Self-Observer

Cognitive Self-Observer receives Regent's output before it lands as chain receipt or operator-facing narration. Observer's verification pass includes:

- **Fact-check against factual corrections**: does output contradict any active factual correction?
- **Boundary-check against boundary corrections**: does output propose action that crosses a boundary correction?
- **Prohibition-check against prohibition corrections**: does output contain patterns that a prohibition correction bans?
- **Preference-check against preference corrections**: does output diverge from operator preference?

Violation → emit `cognitive:correction:violated` receipt; may block output or annotate (per Observer's policy per COGNITIVE-SELF-OBSERVER).

## Attack model

Attacker scenarios and how the schema addresses them:

- **Attacker forges standing correction to manipulate Regent**: forged receipts don't verify against operator's Genesis. Cognitive Input Plane ignores.
- **Attacker manipulates existing correction receipts**: chain integrity prevents modification. New corrections require new receipts.
- **Attacker floods with contradictory corrections to overwhelm Cognitive Input Plane**: Cognitive Input Plane's priority mechanism prevents flood impact; low-priority corrections don't crowd out high-priority ones. Rate limits on corrections may be added.
- **Attacker suppresses corrections by DoS on chain**: forward-only recovery preserves chain; corrections survive substrate restart.
- **Attacker uses correction to socially engineer Regent**: correction content is operator-authored. Operator judgment is the load-bearing constraint. Substrate-level defense: any correction that constrains cognition in unusual ways surfaces to operator for confirmation.

## Failure modes

- **Correction ambiguity**: correction wording doesn't unambiguously distinguish good vs bad outputs. Regent's behavior around ambiguous corrections varies. Refinement via `supersedes` receipt with clearer wording.
- **Correction over-specification**: correction is so narrow that it doesn't cover related patterns Regent still gets wrong. Domain broadening or additional correction receipt for adjacent domain.
- **Correction under-specification**: correction is so broad that it constrains legitimate Regent behavior. Scope narrowing via `supersedes` receipt.
- **Correction stale**: correction addresses a pattern Regent hasn't produced in months. Consider expiry or revocation to keep Tier 1 context lean.
- **Regent's paraphrase divergent from correction content**: acknowledgment receipt shows Regent didn't understand. Operator can re-issue clearer correction. Chain preserves the arc.
- **Regent violates correction despite acknowledgment**: cognitive-input-plane ordering issue, or model capability issue. Investigate; may require model reprovisioning or correction rewording.

## Non-goals

- **Not runtime instrumentation of model outputs**. Standing corrections operate at cognitive layer via Cognitive Input Plane and Cognitive Self-Observer. Not fine-tuning; not RLHF; not any model-internal manipulation.
- **Not a policy engine**. Corrections are chain-anchored operator claims, not a rules-engine DSL. Semantics live in operator judgment plus observer interpretation.
- **Not immune to model capability**. If Regent's underlying model cannot follow correction reliably even with Tier 1 context, corrections alone don't fix it. Model reprovisioning or model upgrade is a separate concern.
- **Not automatic**. Substrate does not autonomously issue standing corrections based on inferred patterns. Every correction is operator ceremony.

## Open positions

- **Correction UX**: dashboard panel for reviewing active corrections? CLI verb for issuing new correction? Regent narration of "here are your active corrections"?
- **Correction pattern learning**: substrate could observe patterns where operator repeatedly issues similar corrections and propose a broader single correction. Delegable to Regent? Chain-anchored ceremony?
- **Correction scope inference**: could substrate infer correction scope from natural-language operator input? Trade-off: convenience vs precision.
- **Correction limits**: should there be a maximum number of active corrections? Trade-off: expressive power vs Tier 1 context bloat.
- **Priority contention**: when many corrections have same domain and different priorities, how is Tier 1 assembly chosen? Priority sort + surface-match ranking? Design work.
- **Correction expiration policy defaults**: should new corrections default to no expiry (persist forever) or reasonable expiry (renew via ceremony)? Trade-off: durability vs staleness.
- **Correction visualization**: how does operator see which corrections are being applied in each cognitive cycle? Debugging tool or always-visible signal?

## Composition with lens discipline

Standing corrections are a **degenerate one-dimensional lens instance** per `LENS-DISCIPLINE-2026-07.md`. Mapping to the lens schema:

- **`focus`** ← correction's `domain` field (e.g., `cognitive.self_reference.model_state`)
- **`dimensions`** ← correction's `scope.applies_to` and `scope.surface` fields (the two axes on which the correction narrows attention)
- **`keyword_composition`** ← correction's `content.assertion` and `content.negation` (prose form — the "keywords" are semantic, not tokenized; observer verification per `COGNITIVE-SELF-OBSERVER-2026-07.md` extracts effective keyword compositions from the negation field)
- **`transformation_question`** ← implicit in correction's `correction_type` (factual → *"is this claim true per operator-signed authority?"*; boundary → *"does this action cross a scoped boundary?"*; prohibition → *"does this output match a forbidden pattern?"*; preference → *"does this diverge from operator preference?"*)
- **`cross_references`** ← correction's `supersedes` field (chain of prior corrections this replaces)

Standing corrections predate the lens discipline formalization but exhibit its structure. They are called "degenerate one-dimensional" because their scope narrows to a single domain rather than composing multiple keyword dimensions across scopes; a full lens per `LENS-DISCIPLINE` may attend to a multi-dimensional keyword composition across broader work context.

Practical implication: `cognitive:correction:standing` receipts are effectively `lens:declared:<correction_id>` receipts of the degenerate class. `cognitive:correction:violated` receipts are effectively `lens:applied:<correction_id>:<invocation_id>` receipts where the transformation_question returned a violation. Composition is retrofittable — no schema change to existing standing correction receipts is required to interpret them through the lens discipline; the mapping above suffices for tooling that wants to project standing corrections into the lens ontology.

## What composes from here

Immediate design work:

1. **Correction issuance UX**: dashboard flow, CLI verb, natural-language shortcut
2. **Correction registry runtime**: chain-anchored index with domain/scope/priority lookups
3. **Cognitive Input Plane integration**: how Tier 1 assembly incorporates corrections
4. **Cognitive Self-Observer integration**: how observer verifies against corrections
5. **Regent acknowledgment protocol**: how Regent surfaces "read and understood" for corrections

Near-term implementation:

1. Correction receipt schemas (Layer B canonical spec)
2. Correction registry in `crates/zp-server/src/cognitive/corrections/`
3. Domain/scope/priority index
4. Cognitive Input Plane consumption logic
5. Cognitive Self-Observer verification hooks
6. Dashboard panel: "Active corrections" view
7. CLI verb: `zp correction issue|list|revoke|supersede`
8. Regent acknowledgment mechanism (cognitive delegation scope allows Regent to emit `cognitive:correction:acknowledged` receipts)

## Framing note

Standing corrections make operator corrections persistent trust corpus rather than repeatedly-forgotten instructions. Same principle as chain-anchored discipline for other trust boundaries — extended to the operator's cognitive-layer corrections.

The load-bearing insight: **operator corrections to Regent are chain-anchored trust corpus, not conversational history.** Not "operator said this once and Regent forgot." The correction lives as a chain receipt with priority, scope, and lifecycle. Every cognitive cycle sees active corrections at Tier 1. Cognitive Self-Observer verifies output against active corrections. Regent's acknowledgment is chain-anchored evidence of receipt.

Combined with the substrate's structural discipline across every trust boundary — actions, admissions, observations, cognition, extensions, hardware, emergency response, Genesis rotation, peer trust, build lifecycle, reproducibility, recovery UX — standing corrections complete the cognitive-layer trust envelope. What today's session surfaced (Regent forgetting corrections between cycles; operator re-teaching the same constraint; cognitive Self-Observer without persistent constraint corpus) becomes structurally impossible when corrections are chain-anchored, priority-weighted, and integrated with cognitive input plane's Tier 1 assembly. Operator's trust in Regent grows via chain-anchored precedent rather than through repeated re-teaching.
