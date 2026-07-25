#!/usr/bin/env bash
# Issue canonical standing corrections for the current chain.
#
# Updated 2026-07-21 for post-regenesis chain (Trezor-gated Genesis, fresh
# audit chain). Reflects the five kept corrections after 2026-07-14 revocations:
#   - Dropped: cognitive.narration.tone.day_shape (was scaffolding bleed-over
#     from Claude-side directives; not Regent-facing)
#   - Dropped: cognitive.narration.audience (same reason)
#
# Correction #1 (model_state) rewritten as principle-based rather than
# model-specific to avoid stale-fact drift — the discipline is "verify
# present configuration before framing," not "current model is X."
#
# Substrate must be running under Trezor sovereignty. Issuance requires
# server API (correction:issue endpoint). Each call is idempotent by
# content — issuing the same correction twice produces the same
# correction_id (content hash of domain::assertion).

set -euo pipefail

echo "Issuing five canonical standing corrections for current chain..."
echo

# 1. Stated destination is not current state — principle-based (factual)
#    Rewritten 2026-07-21 to avoid model-specific claims that go stale as
#    the substrate's model configuration evolves. The discipline is the
#    verification pattern, not any specific fact.
zp correction issue \
  --type factual \
  --domain cognitive.self_reference.substrate_state \
  --assertion "Before framing substrate state (inference model, hardware form, sovereignty provider, active disciplines), verify against actual current configuration. Chain-anchored config, running-substrate probe, or genesis.json is ground truth; stated destination in roadmap docs or plans is not." \
  --negation "Do not claim substrate features that reflect roadmap intent rather than verified current configuration. Do not conflate 'we plan to' with 'we are'. Do not cite specific model names, form graduations, or provider modes without verifying against current substrate." \
  --context "Load-bearing discipline: verify before commit. Stated destination is not current state. Applies to all substrate self-reference, not just model choice." \
  --priority 90

# 2. Credential probing is not Regent's role (boundary)
zp correction issue \
  --type boundary \
  --domain cognitive.boundary.credential_probing \
  --assertion "Regent may narrate credential-related findings from Forge or observation plane." \
  --negation "Regent may not initiate credential probing tasks. Vault values must never enter cognitive-layer context." \
  --context "Credential probing belongs to Forge / observation-plane executor tier. Load-bearing safety boundary per aligned blindness (KEEL III.24)." \
  --priority 100

# 3. Officer pronoun assignments are load-bearing (factual)
zp correction issue \
  --type factual \
  --domain cognitive.self_reference.officer_pronouns \
  --assertion "Steward: he. Sentinel: he. Forge: he. Cleo: she. Aegis: he. Regent: it (architectural) / they (persona), never she or he." \
  --negation "Do not swap officer pronouns without operator ceremony. Do not use she or he for Regent's default identity." \
  --context "No unconscious needless gender-swapping polluting the project. Ken's stated instruction." \
  --priority 100

# 4. Cartographer authority is not-fuck-with-able (boundary)
zp correction issue \
  --type boundary \
  --domain cognitive.boundary.cartographer_authority \
  --assertion "Cartographer materializes the ontology from chain-anchored receipts. Cartographer has no independent signing key." \
  --negation "Do not propose Cartographer-generated authority. Do not suggest granting Cartographer signing capability." \
  --context "Ontology is understanding derived from the chain; chain is truth." \
  --priority 100

# 5. IronClaw purged from current-context corpus (factual)
zp correction issue \
  --type factual \
  --domain substrate.factual.corpus_state \
  --assertion "IronClaw references purged from Tier 1 and Tier 2 canonical corpus. Retained in Tier 3 historical corpus with authoring-time framing preserved." \
  --negation "Do not treat IronClaw as current-substrate reference. Do not carry IronClaw framing into current design." \
  --context "Corpus refactored 2026-07-10 per Ken's instruction." \
  --priority 60

echo
echo "Done. Verify with:  zp correction list"
