// ============================================================================
// DRAFT — proposed additions to RESERVED_RECEIPT_PREFIXES
// crates/zp-server/src/substrate_validate.rs, appended to the existing array.
//
// Source: connection-map run at commit eccc2a6 — 421 corpus_to_chain edges
// classified `aspirational` (documented receipt, no emitter found in
// crates/**/*.rs). These entries cover 9 of the 10 documents proposed for
// reservation; the 10th is argued against at the bottom of this file.
//
// SAFETY CHECK PERFORMED. Every prefix below was tested against the current
// KNOWN_RECEIPT_PREFIXES (80 entries), RESERVED_RECEIPT_PREFIXES (30 entries),
// and the live emitted set (102 receipt names scanned from crates/). None
// shadows a known prefix, a reserved prefix, or an emitted receipt. The
// prefixes are deliberately narrow — multi-segment where the top-level
// namespace is already live — so that reserving a deferred family cannot
// silence a real defect in a built one. Specifically:
//   - `regent:` was NOT reserved; `regent:naming:`, `regent:named`,
//     `regent:renamed:`, `regent:name_retracted:` were.
//   - `officer:` was NOT reserved; `officer:shutdown:` was.
//   - `chain:`, `vault:`, `inference:`, `observer:` were NOT reserved; the
//     specific health receipts naming them were.
//
// Re-run `python3 tools/connection-map/connection_map.py` after applying;
// expected effect is ~114 edges moving defect -> tied_off. Verify the delta
// rather than the absolute figure.
// ============================================================================

    // Operator death and legacy — declared in
    // OPERATOR-DEATH-AND-LEGACY-2026-07. Executor ceremony, legacy access
    // scopes, and memorial preferences. No succession, death-declaration or
    // beneficiary machinery exists in crates/ today; the whole subject is
    // forward work. Reserved so the eventual implementation uses these names.
    "legacy:",
    "sovereign:death_declared",

    // Hardware observer — declared in HARDWARE-OBSERVER-2026-07 and KEEL
    // §II.13 P6. Companion to the existing `observation:hardware:`
    // reservation above, which covers the TPM-attestation half; these are the
    // coprocessor's own fault, thermal, rail, clock and radio findings.
    // Requires physical MCU hardware that is not in any current build.
    "hw:",
    "observe:hardware:",

    // Kinship coordination scopes — declared in
    // SOVEREIGN-KINSHIP-PRIMITIVES-2026-07 and constrained by KEEL §III.23
    // (coordination, not oversight). Twelve narrow cross-sovereign scopes.
    // No kinship code ships; scope vocabulary reserved so the coordination
    // shape is fixed before any implementation can widen it.
    "kinship:scope:",

    // Dependent guardianship scopes — declared in
    // DEPENDENT-SOVEREIGNTY-2026-07. Ten scopes covering care, medical,
    // education and transition advocacy for dependent sovereigns. Unbuilt.
    // These names are load-bearing for a class of operator the substrate
    // does not yet serve; reserved rather than left aspirational because
    // the scope boundaries are the design, not an implementation detail.
    "guardian:scope:",

    // Household composition scopes — declared in
    // HOUSEHOLD-COMPOSITION-2026-07. Multi-sovereign shared-dwelling
    // coordination. Unbuilt; composes with kinship scopes above.
    "household:scope:",

    // Embodiment state — declared in EMBODIMENT-STATE-PROTOCOL-2026-07
    // (pre-personalization aniconic default through committed embodiment).
    // No avatar, renderer or signature-action pipeline exists in crates/.
    // `cycle:emitted` and `policy:committed` are the doc's unqualified
    // spellings of `embodiment:cycle:emitted` and
    // `embodiment:policy:committed`; both are reserved here, and the
    // duplication is itself a corpus defect worth fixing in the doc.
    "embodiment:",
    "cycle:emitted",
    "policy:committed",
    // Face-tracking observation sources — same doc. Note these sit under
    // `observation:`, which is a live namespace in zp-observation, but that
    // crate implements chain-reflection claims rather than any operator
    // sensing tier. Narrow prefixes used so the reservation cannot reach
    // the built family.
    "observation:operator:face:",
    "observation:source:",

    // Regent naming ceremony — declared in
    // REGENT-NAMING-CEREMONY-2026-07. Identity commitment (name, pronouns,
    // voice, avatar) as a chain-anchored operator ceremony, plus renaming
    // and retraction to pre-named. The `regent:` namespace is heavily built,
    // so only the four naming-specific segments are reserved.
    "regent:naming:",
    "regent:named",
    "regent:renamed:",
    "regent:name_retracted:",
    "identity:pre_named",

    // Build and runtime lifecycle receipts — declared in
    // BUILD-PROCESS-DESIGN-2026-07. The build/restart lifecycle currently
    // runs through zp-dev.sh entirely out-of-chain, which that document
    // names as its own open gap. Each entry below is a single receipt, not
    // a family: `chain:`, `vault:`, `inference:`, `observer:` and
    // `officer:` are all live namespaces and are NOT reserved.
    "build:",
    "guard_state:",
    "hygiene:",
    "port_registry:",
    "restart:preshutdown",
    "officer:shutdown:",
    "vault:healthy",
    "chain:database_healthy",
    "inference:healthy",
    "inference:unhealthy",
    "observer:healthy",
    "boot:startup",

    // Community coordination — declared in
    // COMMUNITY-COORDINATION-ON-ZEROPOINT-2026-07. Proposal, governance and
    // advisory vocabulary for the federation surface. The mesh and
    // reputation substrate it composes with is built; this coordination
    // layer is not. `foundation_relay:` is a live family and is untouched —
    // only the three `foundation:` sub-namespaces this doc declares are
    // reserved.
    "community:",
    "foundation:proposal:",
    "foundation:documentation:",
    "foundation:security:",

// ============================================================================
// NOT PROPOSED — REGENT-SELF-BUILDOUT-TRAJECTORY-2026-07 (8 edges)
//
// This document was in the original ten. It should not be reserved, and the
// reason is the document's own text: it declares itself a design declaration
// that is not chain-anchored, and states that no trajectory receipt is
// emitted from its landing because that receipt belongs to the Cartographer.
// Rule 2 for this array requires an entry to name "the phase or condition
// under which implementation lands." This document supplies none, because it
// is not claiming one.
//
// Its eight names are also the wrong shape for reservation. Several are
// wildcards over live namespaces (`lens:composition:missing:*`,
// `operator:build:signed:*`, `regent:build:executed:*`), and reserving a
// wildcard under a built namespace is exactly the over-reach the rest of
// this patch avoids. Two others — `cognitive:fidelity:measured` and
// `corpus:coherence:verified` — name measurements that TRIAGE-FOR-COHERENCE
// and METACOGNITIVE-FIDELITY-HARNESS already compute by other means, so
// they may be duplicate vocabulary rather than deferred vocabulary.
//
// Recommended disposition: retract or requalify the receipt names in the
// document, rather than reserve them. Reserving would convert eight
// aspirational edges to tied_off while asserting a roadmap commitment the
// corpus has not made — the reservation mechanism's own failure mode.
// ============================================================================
