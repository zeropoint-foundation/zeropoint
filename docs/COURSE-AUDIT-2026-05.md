# Course Content Audit (May 2026)

Survey of `zeropoint.global/course.html` (Track 3 — Protocol Internals)
and `zeropoint.global/course-sdk.html` (Track 2 — SDK & Integration)
against the current state of the ZeroPoint workspace after the May 2026
structural-hardening work.

Status legend:

- **Current** — code patterns match the workspace; no fix needed.
- **Partially Stale** — works as taught but bypasses a new carrier or
  misses a new architectural concept. Lab compiles but mis-educates.
- **Stale** — taught code/concept is wrong or no longer compiles.
- **Incomplete** — content is accurate but a major new concept is
  missing from a module that should cover it.

## Track 3 — Protocol Internals (`course.html`)

| # | Title | Status | What's wrong / missing |
|---|---|---|---|
| 0 | Environment Setup | Current | Setup steps still accurate. Optional add: `cargo test --workspace` to introduce `zp-discipline` early. |
| 1 | Your First Key | Current | `Certificate.verify_signature()` API unchanged. Internally now routes through `zp_core::verify_signature` (Seam 5) — could mention this in a sidebar. |
| 2 | Trust Hierarchy and Signing | Partially Stale | Teaches `Signer::verify(pk, msg, sig)`. API unchanged but doesn't introduce the canonical primitive `zp_core::verify_signature`. Lab should cover both: `Signer::verify` for typed Signers, `zp_core::verify_signature` for raw-bytes call sites. |
| 3 | Capability Grants | Current | `CapabilityGrant` builder + constraints unchanged. Could mention that grants are now `Signable` (Seam 20). |
| 4 | Delegation Chains | Current | Eight invariants unchanged. `DelegationChain::verify` API unchanged. |
| 5 | The Policy Engine | Current | `PolicyEngine` and `GovernanceGate::evaluate` unchanged. |
| 6 | The Governance Gate | Partially Stale | Three-stage Guard → Policy → Audit pipeline still accurate. Missing: (a) Guard parser was rewritten (Seam 2 — structural shell tokenizer, rules-first per statement); (b) audit entries now carry `signatures: Vec<SignatureBlock>` (was `signature: Option<String>`); (c) `audit_chain_head()` still returns a hex string but the underlying entries are signed when the gate is wired with an `AuditSigner`. |
| 7 | Receipts and Receipt Chains | Partially Stale | Receipt + ReceiptChain APIs unchanged. Missing: Receipts now `impl Signable`. Lab should show `receipt.canonical_hash()` and `verify_signed(&receipt, pk, sig)` — that's the practical use of Seam 20. |
| 8 | The Audit Trail | **Stale** | Lab calls `AuditStore::open("./lab-audit.db")` — **this method no longer exists** in production code paths. Constructors are now `open_signed(path, signer)`, `open_readonly(path)`, and `open_unsigned(path)` (test-feature-gated). Lab will not compile against current crate. Must rewrite to teach `AuditSigner::from_seed`, `derive_audit_signer_seed(&genesis)`, and `open_signed`. Also missing entirely: `SignatureBlock` shape, the SQLite v=3 append-only triggers (BEFORE UPDATE / BEFORE DELETE), and the convention→invariant lesson this module is the perfect home for. |
| 9 | Discovery | Partially Stale | Concept: "MeshRuntime's event loop parses inbound announces, verifies the Ed25519 signature, extracts the combined public key and capabilities, and auto-registers the peer." After Seam 8 the runtime path now parses a `SignedAnnounce` envelope (capabilities + announced_at + nonce), not bare `AgentCapabilities`. Lab code unchanged at the `register_peer` API level but the implicit wire format is wrong. |
| 10 | The Presence Plane | **Stale** | Concept text and lab strings describe the old wire format `[combined_key(64)] + [capabilities_json] + [ed25519_signature(64)]`. New format is `[combined_key(64)] + [signed_envelope_canonical_bytes] + [ed25519_signature(64)]` where the envelope is `SignedAnnounce { capabilities, announced_at, nonce }`. Lab prints `Capabilities JSON: {} bytes` — should be `SignedAnnounce envelope: {} bytes`. Checkpoint asserts "(1) `build_announce_payload` produces bytes of length 64 + JSON + 64" — needs to reference the envelope structure. |
| 11 | Adversarial Model | **Incomplete** | Reciprocity, grace period, structural amnesia, ConnectionBehavior all still accurate. Missing: replay protection (Seam 8) — `REPLAY_WINDOW`, per-`(peer, source)` nonce cache, `AnnounceTimestampSkewed` / `AnnounceReplayDetected` errors. This is exactly what the adversarial module is for; its absence is conspicuous. |
| 12 | Reputation and Trust Tiers | Current | API unchanged. |
| 13 | Consensus | Current | API unchanged. Could mention that the consensus receipt-hash is now a canonical hash (Seam 17). |
| 14 | Epoch Compaction | Current | API unchanged. The Merkle leaf-hashing now uses `canonical_hash` under the hood — could add a sidebar: "Every node computes the same epoch root because every node serializes receipts identically. That property comes from Seam 17 — the canonical-bytes carrier." |
| 15 | WASM Policy Modules | Current | `PolicyModuleRegistry` API unchanged. |
| 16 | Capstone — Portable Trust | **Stale** | 17-step integration list. Steps that need updating: (7) "Persists audit trail to SQLite" → must use `open_signed`; (8) "Verifies audit chain integrity" → should mention `SignatureBlock` verification per-entry; (11) "Node A announces, Node B auto-discovers" → uses old wire format implicitly; (14) "Spins up a WebRelayServer and tests reciprocity enforcement" → could also test replay protection. Final fleet summary unchanged in structure but the mention of "Receipts: 20 (chain verified ✓)" should say "Receipts: 20 (chain signed + verified ✓)". |

## Track 2 — SDK & Integration (`course-sdk.html`)

I spot-checked the headers and Module 0; haven't read every module's lab
text in full. The headers and lab snippets I saw show the same general
staleness pattern.

| # | Title | Status | What's wrong / missing |
|---|---|---|---|
| 0 | Bootstrap | **Stale** | Path is wrong throughout. Lab teaches `~/.zeropoint/` (dotfile) — actual runtime home is `~/ZeroPoint/` (visible directory). Per `crates/zp-core/src/paths.rs`: "ZeroPoint v3 uses `~/ZeroPoint/` exclusively. There is no backward-compatibility layer for `~/.zeropoint`." Three references to the old path in this module alone. ZP_HOME chain description correct in spirit but under the wrong default. |
| 1 | Agent Keys | Likely partially stale | (sampled header only) |
| 2-5 | (rest of track) | Likely partially stale | Audit pass needed module-by-module. Same staleness vectors as Track 3 likely apply: audit `open` API, announce wire format, missing `verify_signature` carrier, missing `paths::home` carrier discussion. |

Track 2 needs its own focused pass. The path-default error in Module 0
is the most visible, and likely cascades into every later module that
mentions the runtime home.

## Missing Modules / Concepts Entirely

The course was written before the architectural concepts that emerged
from the May 2026 structural-hardening work. These are missing across
both tracks:

1. **The convention-vs-invariant thesis and `zp-discipline`.** The most
   important architectural concept in current ZeroPoint has zero
   coverage. Track 3 ("Internals") should have a dedicated module:
   what a discipline pin is, how it converts a documentation-bound
   convention into a build-bound invariant, the six existing pins and
   what each protects.

2. **Seam 5 — single verify primitive.** `zp_core::verify_signature`
   and `verify_signed<T: Signable>` deserve a dedicated explanation.
   Currently they're invisible.

3. **Seam 17 — canonical bytes.** The "ZP-canonical-v1" form is the
   silent foundation of every signed thing in the workspace. The
   course never explains why deterministic serialization matters or
   what the discipline pin (`no_serde_preserve_order`) protects.

4. **Seam 19 — path resolution.** `zp_core::paths::home` (ZP data root)
   vs `paths::user_home` (user's actual home). Module 0 in both tracks
   should mention these.

5. **Seam 20 — Signable trait.** The composition between canonical
   preimages and signature verification. Pairs naturally with Module 7
   (Receipts) since Receipts are the most visible Signable.

6. **The structural audit doc as a teaching artifact.**
   `docs/STRUCTURAL-AUDIT-2026-05.md` maps 20 seams. The map itself is
   a teachable concept. Could be a sidebar in any module that touches
   a seam, or a dedicated capstone-adjacent module.

## Cross-cutting issues

**A. Player rendering bugs** (independent of content staleness):

- Off-by-one between sidebar selection (`currentModule === mod.id` at
  course.html:1128) and content rendering (`courseData.modules
  [currentModule - 1]` at course.html:1159). Sidebar highlights "02"
  while content shows "Module 1" content.
- "Mark as Complete" button looks dead because the `completed` prop
  uses `currentModule` while `onComplete` adds `module.id` to the
  set; the indices never match.

Both are three-line fixes in `course.html`. They affect the friend
who reported the bug regardless of content updates.

**B. Hash conventions referenced inconsistently.** The course mixes
"BLAKE3 hash", "content hash", and "canonical hash" without naming
the carrier. After Seam 17 there is one canonical hash function;
naming it consistently would help.

**C. The course tagline says "16 modules" in some places and "17
modules" in others.** With Environment Setup as id=0 and Capstone as
id=16, the count is 17 modules total but the original framing was
"16 modules + capstone." Pick one and apply consistently.

## Recommended action plan, prioritized

**Phase A — Stop the bleeding (1-2 hours of editing):**

1. Fix the off-by-one player bugs in `course.html` (three lines).
   Friend who reported the bug stops seeing it.
2. Rewrite Module 8 (The Audit Trail) lab to use `open_signed` with
   an `AuditSigner` derived from a Genesis seed. Without this, the
   lab does not compile against current crate APIs.
3. Update Module 10 (Presence Plane) wire-format text, lab strings,
   and checkpoint to reference the `SignedAnnounce` envelope.
4. Fix Track 2 Module 0 path references: `~/.zeropoint/` →
   `~/ZeroPoint/` (three occurrences in that module).

**Phase B — Add what's missing (2-4 hours):**

5. Extend Module 11 (Adversarial Model) with a Replay Protection
   subsection covering `REPLAY_WINDOW`, the per-`(peer, source)`
   nonce cache, and the new error variants. Lab demonstrating
   accept-on-multi-source / reject-on-same-source-replay.
6. Add a new Module 17 (or rename Capstone to 18) — "Convention vs
   Invariant: The Discipline Framework." Walks through `zp-discipline`,
   the six existing pins, the convention-vs-invariant thesis. Doubles
   as the architectural narrative the course is currently missing.
7. Update Module 16 (Capstone) steps 7, 8, 11, 14 to reference
   current APIs (signed audit chain, replay-protected announces).

**Phase C — Polish and unify (1-2 hours):**

8. Audit Track 2 module-by-module the way Track 3 was audited here.
   Produce a similar table.
9. Add Seam-aware sidebars to Modules 2, 7, 14: name the carrier the
   module is using and link to the relevant `STRUCTURAL-AUDIT-2026-05`
   entry.
10. Pick a module-count framing ("16 modules + capstone" or "17
    modules") and apply consistently across the two tracks plus
    `learn.html`.

**Phase D — Optional architectural narrative:**

11. Write a "May 2026 Hardening" case-study appendix that walks
    through a real seam (Seam 5 or Seam 8) end-to-end — discovery,
    audit, structural map, sweep, discipline pin, lessons doc.
    Aimed at advanced students; doubles as a recruiting/narrative
    artifact.

## What this audit didn't cover

- **Track 2 modules 1-5** — only spot-checked. Need a focused pass to
  produce the same module-by-module table as Track 3.
- **`learn.html` track descriptions** — describe the courses, may
  reference module counts or topics that have drifted.
- **`course.html` and `course-sdk.html` non-module content** — intro
  pages, philosophy text, prerequisites blurbs. Spot-checked the
  intro page; main risk there is the "16 modules" framing.
- **Lab code compilability** — none of the lab code samples in either
  course was actually compiled against the current workspace as part
  of this audit. The compilable lab examples are in
  `crates/course-examples/` (mostly clean per the earlier grep), but
  the inline lab samples in the HTML files have no build-time
  verification. A future discipline could be: extract every lab
  sample into a compile-tested fixture and pin the inline HTML to the
  fixture.
