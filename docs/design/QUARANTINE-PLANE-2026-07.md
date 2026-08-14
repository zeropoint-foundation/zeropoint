# Quarantine Plane

**Tier 2 canonical elaboration.** Elaborates `KEEL-2026-07.md` §II (adds Layer A admission tier), §III (adds Layer B canonical claims about default-deny at trust boundaries), and Part V (Composition Contract, admission of external composed artifacts). Introduces a new proposed Layer A invariant (§II.15 or wherever it lands after canonicalization ceremony). Canonical claims live in KEEL; this doc provides implementation-level detail and design rationale.

Draft — 2026-07-10 — internal audience only. Composes with `SUBSTRATE-FORM-2026-07.md` (Form-scoped verification depth), `OBSERVATION-PLANE-2026-07.md` (parallel Layer A plane at a different substrate boundary), and the emerging Cognitive Input Plane and Circuit Breaker specs.

## Framing

Every substrate that trusts the world eventually gets compromised through an artifact that entered its trust boundary without adequate scrutiny. Every mainstream sandboxing model fails because its safety mechanism is either rigid (accept vendor rules or bypass entirely) or leaky (accept unsigned by default with a warning that gets clicked past). The failure mode is always the same: the safety mechanism and the operator's authority end up structurally in tension, and the operator loses either productivity (living with the rigidity) or safety (bypassing to get work done).

The quarantine plane is the substrate's structural discipline against this failure mode. Any artifact entering the substrate's trust boundary from outside its own signing scope is placed in quarantine — an isolated storage tier that is visible to the substrate but has no admitted trust — until verification completes and the operator signs an admission delegation. Default posture is deny. The safety property is structural, not policy. But because admission is via Genesis-derived operator delegation rather than vendor gate, safety and sovereignty compose — the operator uses the substrate's own admission ceremony to admit artifacts, keeping the quarantine discipline intact for everything else.

Three properties frame the plane:

1. **Default-deny at the boundary.** No artifact enters trust without passing through quarantine. Nothing bypasses. Same discipline as the gate for actions.
2. **Verification is a discrete step, not a hoped-for outcome.** Signature check, content-hash check, capability audit, and operator delegation are explicit chain-anchored operations. Not "we assume it's safe because it looks fine."
3. **Delegable admission preserves sovereignty.** The operator can admit any artifact via signed delegation ceremony. Not a bypass — the mechanism by which admission operates. Safety and operator authority compose because the operator IS the admission authority.

## The six admission surfaces

Every incoming artifact maps to one of six surfaces. Each has native intake primitives (Layer A), a verification schema (Layer B), and a corresponding delegation class.

### Executable artifacts

WASM modules — extensions, officer extensions, verb extensions, protocol adapters, tenant frameworks. Anything that runs inside the substrate's execution boundary.

- **Layer A primitives**: intake via `zp extension install`, `zp extension update`, or automated fetch from delegated sources. Placement in `$ZP_DATA/quarantine/executable/`.
- **Verification schema**: signature verification against operator-trusted signers (Genesis-derivable), content-hash match to declared manifest, WASM parse validation, imported host interface audit vs declared capabilities, semantic sanity (no obvious anti-patterns).
- **Delegation class**: `delegation:admit:executable:<content_hash>` with declared capability scope and expiry.

### Canonical spec artifacts

Layer B data records — canonical claims, prompts, model dossiers, ontology definitions, policy modules that arrive as artifacts rather than being edited in-substrate.

- **Layer A primitives**: intake via canonicalization ceremony (KEEL Part VI) or from delegated spec sources.
- **Verification schema**: signature verification, content-hash match, schema conformance to declared trait interface, cross-reference validation against existing canonical corpus.
- **Delegation class**: `delegation:admit:canonical:<content_hash>` — typically bundled into canonicalization ceremony receipt.

### Chain artifacts

Receipts from peers, chain segments received during peer sync, external anchor receipts (blockchain anchoring, etc.).

- **Layer A primitives**: Peer-Verification Contract intake (KEEL Part VII), external anchor bridge.
- **Verification schema**: chain integrity per Part VII, signature chain traversal to a trusted peer's Genesis, timestamp sanity, no rowid/hash collisions with existing chain.
- **Delegation class**: `delegation:admit:peer_chain:<peer_id>` — typically granted once per peer relationship, scoped to peer's genesis identity.

### Data artifacts

Files referenced by chain receipts (media, documents, embeddings), downloaded content, artifacts fetched via delegated tool actions.

- **Layer A primitives**: content-addressed store, blob intake with mandatory hash-check.
- **Verification schema**: hash-check against declared reference, size sanity, MIME-type sanity, malformation checks.
- **Delegation class**: `delegation:admit:data:<content_hash>` — typically automatic if the reference receipt is trusted and the content hash matches.

### Credential artifacts

Keys, tokens, secrets that enter the vault from external sources (initial provisioning, rotation via external key ceremony, imported credentials).

- **Layer A primitives**: vault intake with mandatory tier assignment, provenance receipt required.
- **Verification schema**: format sanity, no obvious plaintext-in-key-name anti-patterns, provenance trace to operator ceremony.
- **Delegation class**: `delegation:admit:credential:<vault_path>` — always operator-signed, never automated.

### Configuration artifacts

Changes to substrate configuration applied outside the running substrate (edits to `config.toml`, imported policy bundles, external canonicalization ceremonies).

- **Layer A primitives**: config file monitoring (detects external edits), import verbs (`zp config import`).
- **Verification schema**: diff against last-signed configuration, semantic sanity, schema conformance, operator confirmation.
- **Delegation class**: `delegation:admit:config:<config_hash>` — always operator-signed, includes diff for operator review.

## Layer A / Layer B split

The plane spans both layers per SUBSTRATE-EXECUTION-ARCHITECTURE-2026-07.md.

**Layer A (compiled Rust host)**:
- Intake primitives per surface (WASM parsers, peer-chain receivers, blob stores, config watchers)
- Isolated quarantine storage (`$ZP_DATA/quarantine/<surface>/`) with no admitted-trust visibility to normal substrate operations
- Verification runtime — signature-check, hash-check, capability-audit dispatcher
- Signing infrastructure — Genesis-derived per-class quarantine keys, admission-receipt shaping
- Refusal-at-boundary discipline: if a code path attempts to reference a quarantined artifact without an admission receipt, the reference errors structurally

**Layer B (WASM modules + canonical data)**:
- Verification schemas per surface (what "signature check" means for each artifact class)
- Capability declaration language (how executable artifacts declare their intended host interface)
- Verification policy modules (what makes an admission acceptable)
- Trust anchor records (which peer Genesis-derivations are trusted for which surfaces)

Layer A is structurally defended. Layer B evolves via canonicalization ceremony. Adding a new admission surface, changing verification criteria, adding a new trusted peer — all Layer B, all ceremony-amendable.

## The admission ceremony

Every admission is a chain-anchored ceremony with a specific structural sequence.

### Step 1: intake

Artifact arrives at the quarantine plane. Layer A intake primitive places it in `$ZP_DATA/quarantine/<surface>/<hash>/`. Emits `quarantine:entered:<surface>:<hash>` receipt with:
- Artifact hash
- Surface class
- Intake source (peer id, url, cli command, etc.)
- Declared manifest (for executable artifacts: capabilities requested; for others: reference metadata)
- Timestamp

At this point the artifact exists but has no admitted trust. Substrate can inspect it but cannot execute, load, or reference it in active operations.

### Step 2: verification

Layer A verification runtime runs the surface-specific checks:
- Signature verification — is the artifact signed by a signer derivable from Genesis or from a trusted peer's Genesis?
- Content-hash check — does the artifact's actual hash match declared?
- Capability audit — for executable artifacts, do the imported host functions match declared capabilities?
- Semantic sanity — no obvious malformation, no anti-patterns

Emits `quarantine:verified:<surface>:<hash>` receipt on pass with:
- What was verified
- Trust-chain path from Genesis to artifact
- Capabilities declared and confirmed

Emits `quarantine:verification_failed:<surface>:<hash>` receipt on fail with:
- What failed
- Details for operator diagnosis

**Third signature state (added 2026-08-14; `AI-LANDSCAPE-SIGNAL-2026-07.md` §"Signal 5", E9a).** Signature verification above is binary — Genesis-derivable or not — and an artifact signed verifiably by a party the operator has no trust path to falls to *not*. As vendor-signed capability artifacts become the industry norm, that discards evidence rather than defending against it. Verification therefore records a third outcome: **verifiable, non-Genesis-derivable**, emitted as `quarantine:attestation:<surface>:<hash>` with the attesting party, the verification result, the attestation's own claims, and an explicit `authority: none` marker. It does not satisfy the signature check, does not advance the ceremony, and is never read by the gate — it is evidence placed in front of the operator at Step 3 and retained on chain so that a later compromise of the attesting party is traceable to everything it vouched for. Specified in `EXTENSION-SURFACE-2026-07` §"Delegation semantics".


### Step 3: operator delegation ceremony

For admission to complete, the operator must sign a delegation receipt granting the artifact's runtime scope. Operator reviews:
- Quarantine entry receipt (what came in and from where)
- Verification receipt (what passed)
- Declared capabilities (what the artifact says it needs)
- Any `quarantine:attestation:*` receipts — third-party attestations, named and marked `authority: none`
- Optional: operator can narrow the granted scope below the declared

Operator signs `delegation:admit:<surface>:<hash>` receipt with:
- Granted capabilities (may be narrower than declared)
- Expiry (optional; ceremony-configurable)
- Revocation-priority (how quickly circuit breaker or manual revocation should propagate)
- Justification (free text; part of the audit trail)

### Step 4: admission

Layer A observes the delegation receipt and moves the artifact out of quarantine into its operational location (`$ZP_DATA/extensions/<hash>/` for executable, vault entry for credentials, etc.). Emits `quarantine:cleared:<surface>:<hash>` receipt marking the transition.

Artifact is now admitted. Substrate can execute, load, reference it — but only within the granted delegation scope. Every subsequent operation involving the artifact cites the admission delegation, so the audit trail traces from action back to admission back to intake back to source.

### Step 5: revocation (asymmetric to admission)

Operator can revoke admission at any time via `delegation:revoked:admit:<surface>:<hash>` receipt. Layer A observes revocation, purges the artifact from operational location, and emits `quarantine:re_quarantined:<surface>:<hash>` (returns to quarantine) or `quarantine:destroyed:<surface>:<hash>` per revocation scope. Revocation is faster than admission — no verification required, just operator signature.

Circuit breaker can trip a broader revocation — see CIRCUIT-BREAKER-2026-07.md (in progress).

## Provenance — quarantine plane signing keys

Per KEEL §II.5 (Decision A): all keys derive from Genesis. The quarantine plane needs its own signing keys so its receipts are attributable.

Shape: one signing key per admission surface, HKDF-derived from Genesis with the surface class as info material.

```
quarantine_key[surface] = HKDF(genesis_root, salt=chain_head_at_derivation, info=f"quarantine:{surface}")
```

Six admission surfaces = six quarantine keys. Each surface's key signs the entered/verified/cleared/rejected receipts for its class. Compromise of one surface's key does not compromise the others.

Officer findings can cite specific quarantine receipts by hash, closing the provenance loop back to Genesis. Same discipline as observation plane's per-class keys.

## Composition with Substrate Form

Verification depth varies by Substrate Form.

### Sovereign Form

Full verification stack. Native primitives for every admission surface. Complete audit trail from intake to admission stored in operator-controlled storage. Measured-boot receipts from the substrate's own boot chain can be part of trust anchors for peer verification.

### Appliance Form

Full verification on the appliance itself. Daily driver client can request admission on behalf of operator, but the admission ceremony happens on the appliance where the operator's Genesis lives. Delegation receipt is signed on the appliance.

### Companion Form

Verification bounded by vendor primitives. Signature check, hash check, and capability audit all work. But the surrounding process isolation for quarantine is vendor-permitted subset. Form Disclosure names the reduction honestly: "Quarantine on Companion Form runs within the vendor's process isolation guarantees, not the substrate's own."

## Composition with the observation plane

Observation plane observes the quarantine plane's operations. `quarantine:entered`, `quarantine:verified`, `quarantine:cleared` are all observation-plane visible events.

Officers query the observation ontology and can propose findings on quarantine patterns:
- **Sentinel**: unusual intake sources, suspicious signature patterns, capability-declaration anomalies
- **Steward**: verification failure rates, quarantine backlog, integrity of the quarantine store itself
- **Forge**: quarantine storage growth, admission ceremony completion rates, revocation cadence
- **Cleo**: narrates the admission history for the operator ("today you admitted 3 extensions, 12 data blobs, 1 credential; here's the summary")

## Composition with the cognitive input plane

Quarantine receipts are matrix inputs to Regent's cognitive input plane (see COGNITIVE-INPUT-PLANE-2026-07.md, in progress). When Regent's cycle begins, top-tier priority inputs include:
- Active admission delegations (what artifacts are currently trusted at what scope)
- Recent admission ceremonies (what the operator has recently admitted, for precedent)
- Recent verification failures (what the substrate has recently rejected, for anti-pattern awareness)

So Regent perceives the substrate's admission history as part of her operating context, and her reasoning about capability delegation naturally composes with the quarantine discipline.

## Composition with the circuit breaker

The circuit breaker (see CIRCUIT-BREAKER-2026-07.md, in progress) operates on admitted artifacts as well as active operations. When a breaker trips at surface X:
- Active admissions at scope X are immediately arrested (delegations flip to unavailable pending reset)
- Artifacts move back to quarantine visually — from admitted operational storage back to quarantine store, with `quarantine:emergency_re_quarantined:<hash>` receipt
- New intake at scope X is refused entirely (breaker-tripped surfaces stop accepting)
- Reset via operator ceremony re-admits the arrested artifacts (with possibly modified scope)

Circuit breaker + quarantine plane together give a full spectrum: normal ceremony for planned admission, emergency arrest for suspected compromise, chain-anchored evidence at every step.

## Composition with the Extension Surface

The extension surface (see EXTENSION-SURFACE-2026-07.md, in progress) is a specific application of the quarantine plane at the executable-artifact admission surface. Extensions ARE the primary use case for executable-artifact admission. The extension surface defines:
- The trait interfaces extensions implement
- The capability declaration syntax extensions use
- The delegation ceremony specifics for extension admission
- The lifecycle beyond admission (update, revoke, uninstall)

Quarantine plane provides the general admission mechanism; extension surface specializes it for third-party executable code. Extensions cannot bypass the quarantine plane — every extension passes through it.

## Attack model

Real threats and how the plane addresses them:

- **Malicious signed artifact from trusted signer**: verification passes (signature valid), operator delegation ceremony is the last line — operator reviews declared capabilities. Circuit breaker catches post-admission anomalies. Precedent-based auto-admission (Regent adopting patterns) requires prior operator ceremony, so first-time-from-signer is always human review.
- **Unsigned artifact claiming to be signed**: signature check fails, `quarantine:verification_failed`, artifact stays quarantined.
- **Signature theft**: attacker signs with stolen key. First admission requires operator ceremony; operator sees the attempt in dashboard, can refuse. If operator admits accidentally, blast radius is scoped to the artifact's delegation. Circuit breaker on detection of anomaly. Genesis-level rotation ceremony as ultimate fallback.
- **Content mutation post-signature**: hash check catches this. Artifact rejected.
- **Capability lying**: declared capabilities audited against actually-imported host functions. Anomalies caught structurally.
- **Chain-artifact poisoning from peer**: peer verification contract catches signature-chain gaps. Peer-source anomalies emit findings; operator can revoke peer trust.
- **Quarantine store tampering**: the quarantine store itself is signed by the quarantine plane's key. Tampering breaks signature, detected by verification. On Sovereign Form the store lives on encrypted volume with measured-boot integrity.
- **Bypass attempt via race condition**: intake-verification-admission is atomic per artifact (single-threaded per artifact within the plane). No race window between "not admitted" and "admitted."

## Non-goals

- **Not a virus scanner.** The plane verifies signature, provenance, and structural conformance. It does not attempt to detect malicious behavior via signature-of-known-badness. That's a different discipline that could run alongside as an extension.
- **Not automatic admission ever.** No policy that admits artifacts without operator ceremony, even for "trusted" signers. Precedent-based auto-admission (Regent applying patterns) always requires prior explicit ceremony.
- **Not a policy engine.** The plane enforces default-deny and delegation-based admission. Operator policies about *what to trust* live in Layer B canonical spec. Plane implements the mechanism; operator declares the policy via canonicalization ceremony.
- **Not the sole security layer.** Composes with circuit breaker (emergency response), observation plane (behavior monitoring), officer cadre (finding-based detection). Quarantine is admission; these others handle post-admission concerns.

## Open positions

- **Admission delegation UX.** How does the operator review a pending admission? Dashboard panel with capability summary, source, verification result, and one-tap sign? Regent-narrated summary with confirmation? Both? Design work.
- **Admission of instruction-shaped artifacts carrying authority (2026-08-14).** The canonical-spec surface covers prompts and policy modules arriving as artifacts, and verifies them by schema conformance and corpus cross-reference — checks that suit a Layer B data record and say nothing about what an authority-carrying instruction bundle asks the cognition layer to do. The industry's capability unit at the extension layer has become exactly that (signed, catalogued `SKILL.md`-shaped instruction sets with machine-readable trust records), so the surface now has a class of artifact its verification schema does not reach. Wants a design pass; see `EXTENSION-SURFACE-2026-07` §Open positions and `AI-LANDSCAPE-SIGNAL-2026-07.md` §"Signal 5" (E9c).
- **Precedent must be built from operator signatures (2026-08-14).** Constraint on the position above rather than a separate question: a `quarantine:attestation:*` receipt must never contribute to precedent. Precedent built from a third party's signatures is that party's trust root wearing the operator's clothes.
- **Precedent-based auto-admission scope.** Once operator has admitted an extension from signer X, can Regent autonomously admit future extensions from X within the same capability class? Under what precedent depth? Composes with the act-on-precedent-escalate-on-novelty heuristic.
- **Peer chain admission threshold.** How many peer receipts must be verifiable before a peer's chain segment is admitted vs quarantined for further review? Depends on peer relationship strength (composes with the reputation discipline).
- **Storage tier for quarantine.** Sovereign Form: encrypted volume under sealed FDE. Appliance Form: same. Companion Form: whatever the OS provides. How do we honestly disclose the difference?
- **Verification cost bounds.** Some verification (WASM parse + capability audit) is fast. Others (semantic analysis) can be expensive. How do we bound verification cost per intake to prevent DoS via floods of malformed artifacts?
- **Retention of rejected artifacts.** Do we keep `quarantine:verification_failed` artifacts for post-hoc forensics, or destroy them immediately? Trade-off: forensic evidence vs storage cost vs holding potentially-malicious content.
- **Composition with WASI evolving standards.** The capability declaration language for executable artifacts depends on WASI's evolution. How do we handle capability declarations for WASM modules using experimental WASI features?

## What composes from here

Immediate design work:

1. **Surface schemas** — Layer B canonical records for each of six admission surfaces. Verification criteria, receipt shapes, capability declaration languages.
2. **Admission ceremony flow** — concrete UX for the operator delegation review. Dashboard panel, Regent narration, tap-to-sign.
3. **Extension Surface companion** — how the executable-artifact quarantine specializes for third-party extensions (Task #46).
4. **Circuit Breaker composition** — how emergency revocation propagates through admissions (Task #49).
5. **Cognitive Input Plane matrix inputs** — quarantine receipts as top-tier priority context inputs for Regent (Task #45).

Near-term implementation:

1. Quarantine store scaffolding — `$ZP_DATA/quarantine/<surface>/` directories with strict access control.
2. Intake primitives per surface — WASM parser + capability audit; peer chain receiver; blob store; config watcher; credential intake; canonical spec intake.
3. Verification runtime with dispatch per surface.
4. Chain-receipt emitters for all quarantine events.
5. Genesis-derived key derivation for quarantine plane per-surface keys.
6. Operator delegation ceremony UI (dashboard panel first, then Regent-narrated).

## Framing note

The quarantine plane is the substrate's structural discipline against the most common failure mode of trust systems: safety mechanisms getting bypassed because they can't be safely delegated. By making admission delegation the mechanism by which safety operates (not the exception to it), the plane keeps default-deny structural while giving the operator full sovereign authority to admit what they choose. Safety and sovereignty compose. Every admission is chain-anchored evidence. Nothing enters the substrate's trust boundary silently.

Combined with the observation plane (chain-anchored evidence of what the substrate is seeing) and the cognitive input plane (chain-anchored evidence of what Regent is perceiving), the substrate now has three symmetric Layer A tiers — each a boundary discipline, each default-restrictive, each Genesis-derived. Same architectural family; three different substrate concerns.
