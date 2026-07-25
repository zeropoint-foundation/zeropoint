# Chain-Participating Build & Restart

**Tier 2 canonical elaboration.** Elaborates `KEEL-2026-07.md` §II.5 (Genesis-derived signing), §II.15 (substrate boundary planes), III.20 (forward-only recovery), and III.22 (verify before commit). Specifies the discipline for how substrate builds, restarts, and hot-reloads participate in the chain rather than bypassing it. Canonical claims live in KEEL.

Draft — 2026-07-11 — internal audience only. Composes with `SUBSTRATE-FORM-2026-07.md` (Form-specific build ceremony), `CIRCUIT-BREAKER-2026-07.md` (restart as recovery pathway from graduated escalation), `BLAST-RADIUS-AND-RECOVERY-2026-07.md` (forward-only recovery via restart), `HARDWARE-OBSERVER-2026-07.md` (observer restart / firmware update flow), and today's incident (11Hz hot loop; port registry unconditional persist; stale `.guard-paused`; log noise).

## Framing

Today's diagnostic session surfaced a structural gap: substrate builds and restarts operate as *out-of-chain* operations. `./zp-dev.sh` deletes override assets, runs `cargo build`, spawns `zp serve`. None of this touches the chain. The operator sees a running substrate; the substrate has no record of what was built, what was restarted, or why. When post-restart the substrate emits `boot:startup` receipts, the receipt says the substrate booted — it does not say *what* booted.

The consequences accumulated across the day: stale `.guard-paused` files persisted across restarts with no chain evidence of who paused what; empty `tool-ports.json` after restart with no chain evidence of registry state loss; log-noise hygiene (11Hz hot loop) that only became visible after the fact through operator inspection; a claimed reasoning-model destination (GLM 5.2) that diverged from actual running config (Sonnet 4.6) with no build-time chain check to catch the mismatch. Each incident was individually small; the pattern was that the substrate's own build/restart lifecycle was invisible to the substrate itself.

The Chain-Participating Build & Restart discipline is the substrate's structural response. Every build, every restart, every hot-reload emits chain receipts documenting what happened. Verify-before-commit runs pre-flight structural checks. Forward-only recovery treats restart as a chain event, not a substrate reset. The lsof-test principle (substrate mature when own footprint is legible) extended to the build lifecycle itself.

Three properties frame the discipline:

1. **Every build event is a chain event.** `build:artifact_produced:<hash>`, `build:reproducibility_verified:<hash>`, `restart:initiated:<reason>`, `restart:completed:<generation>` — the chain records the substrate's own build/restart lifecycle.
2. **Restart preserves chain; recomputes derived state.** Per III.20 (forward-only recovery), the chain is truth. Derived state — port registry, guard-paused flags, ephemeral caches — is recomputed on restart from chain state. Stale files that don't have chain evidence are treated as suspect.
3. **Build reproducibility is verifiable.** Same source + same build environment produces byte-identical artifact hash. Reproducibility is chain-anchored via `build:reproducibility_verified` receipts. Peers can verify the operator's substrate is running what its source claims.

## The current gap

The build/restart lifecycle today (as of 2026-07-11):

1. Operator runs `./zp-dev.sh` (or `./zp-dev.sh release`)
2. Script kills existing `zp serve` process (unconditional `pkill`)
3. Script deletes override assets from `~/ZeroPoint/assets/`
4. Script runs `cargo build` (or `cargo build --release`)
5. Script copies static/HTML assets to override dir
6. Script backgrounds `zp serve`
7. `zp serve` boots, initializes runtime, emits `boot:startup` receipt

Gaps:

- **No pre-flight verification**. Nothing checks that the current source will produce a build that composes with current chain state. Bad build lands, substrate crashes at startup, operator investigates from silence.
- **No build-artifact chain evidence**. The binary hash is not recorded. Operator has no chain-anchored answer to "what am I actually running?"
- **No restart intent receipt**. The chain jumps from pre-restart `receipt N` to post-restart `receipt N+1: boot:startup` with no evidence of why the transition happened.
- **Derived state loss is silent**. If `tool-ports.json` is empty after restart, no chain event says so. Operator finds it via inspection.
- **Stale-file hygiene is manual**. `.guard-paused`, orphan PIDs, empty state files persist unless operator notices.
- **Reproducibility is untested**. Substrate does not verify that its running binary matches its source. Peers cannot verify either.
- **Hot-reload is invisible**. `./zp-dev.sh html` (if it existed) would swap assets with no chain evidence.

## The target lifecycle

The chain-participating build/restart lifecycle:

### Phase 1 — Build intent

Operator invokes build:

```
zp build [--release] [--reason "<reason>"]
```

Substrate emits `build:initiated:<build_id>` receipt:
- Build ID (content-addressed from git rev + build flags + timestamp)
- Source rev (git HEAD commit)
- Build flags (release / debug, features enabled)
- Optional operator-provided reason
- Signed by operator's Genesis-derived key

### Phase 2 — Pre-flight verification (verify before commit)

Before invoking `cargo build`, run structural checks:

- **Source integrity**: git working tree is clean or diff is chain-declared. Uncommitted changes must be surfaced.
- **Config coherence**: current `config.toml` fields all reference features that will be present in the built binary. Stale config fields (features no longer built) are flagged.
- **Discipline pins**: any repo-level lints, discipline pins, or invariant checks pass.
- **Test suite (release only)**: relevant test suite passes.

Failures emit `build:preflight_failed:<build_id>:<check>` receipts and abort the build. Operator sees why. Chain records the attempt.

### Phase 3 — Build execution

Invoke `cargo build [--release]`. Capture:
- Build stdout/stderr (chain-linked as artifact for retrospection; not chain-embedded)
- Wall time
- Exit status

On success:
- Compute binary hash (BLAKE3)
- Compute reproducibility hash (source tree hash + build flags → expected binary hash)
- Emit `build:artifact_produced:<build_id>:<binary_hash>` receipt

On failure:
- Emit `build:failed:<build_id>:<exit_code>` receipt
- Abort restart

### Phase 4 — Reproducibility check (optional, ideally always)

Verify build reproducibility:
- Re-derive source tree hash
- Look up prior build receipts with same source rev + build flags
- If prior build receipt exists with matching binary hash → emit `build:reproducibility_verified:<binary_hash>`
- If prior build receipt exists with different binary hash → emit `build:reproducibility_diverged:<binary_hash>:<prior_hash>` and flag for investigation
- If no prior build receipt → this build sets the reproducibility baseline

Per REPRODUCIBILITY-CEREMONY (future spec), formal reproducibility ceremony involves peer independent rebuild.

### Phase 5 — Restart intent

Before killing the running process:

- Emit `restart:initiated:<restart_id>` receipt from the currently-running process:
  - Restart reason (`build_updated`, `config_updated`, `operator_requested`, `emergency_recovery`, `escalation_response`)
  - Target build artifact hash
  - Current generation number
  - Any known state that will be lost or preserved
- Signed by the currently-running substrate's Genesis-derived key

### Phase 6 — Graceful shutdown

Currently-running substrate performs graceful shutdown:

- Complete in-flight tool dispatches (with reasonable timeout)
- Flush chain state to disk (SQLite checkpoint)
- Emit final receipts:
  - `officer:shutdown:*` for each officer
  - `port_registry:snapshot:<state_hash>` recording current port bindings for post-restart reload
  - `guard_state:snapshot:<state_hash>` recording currently-active guard pauses
  - Any other derived state that needs continuity: snapshotted as chain receipts
- Emit `restart:preshutdown_complete:<restart_id>` receipt
- Terminate with clean exit

Zp-dev.sh's `kill` step is replaced by SIGTERM to the running process, giving it a chance to complete graceful shutdown. Only escalate to SIGKILL after grace period expires.

### Phase 7 — Restart execution

Launch new substrate process from the new binary. New process:

- Reads chain from last-known-good position
- Emits `boot:startup:<restart_id>:<generation+1>` receipt including:
  - Reference to `restart:initiated:<restart_id>` receipt
  - Binary hash of the running process (verified against `build:artifact_produced` receipt)
  - Substrate Form (Sovereign / Appliance / Companion)
  - Environment fingerprint (host OS, arch, key libraries)
- Reconstitutes derived state from chain snapshots:
  - Port registry loaded from `port_registry:snapshot` receipt (not from stale `tool-ports.json`)
  - Guard pause states loaded from `guard_state:snapshot` receipts (not from stale `.guard-paused` files)
  - Any other derived state: recomputed from chain

If a legacy state file exists on disk with no matching chain snapshot: treat as suspect. Emit `hygiene:stale_state_file_detected:<path>` observation receipt. Do not load. Quarantine.

### Phase 8 — Post-restart verification

New substrate verifies its own health:

- Officer cadre boots and emits `officer:heartbeat:<name>` receipts
- Chain integrity check runs (verify tail is coherent with pre-restart state)
- Configured components come online:
  - Inference backend reachable? → `inference:healthy` or `inference:unhealthy`
  - Chain database opened cleanly? → `chain:database_healthy`
  - Vault decryptable? → `vault:healthy`
  - Hardware self-observer heartbeat received (if hardware observer configured)? → `observer:healthy`
- Emit `restart:completed:<restart_id>` receipt with health summary

If any component fails: emit `restart:degraded:<restart_id>:<component>` receipt. Operator sees status via dashboard. Circuit breaker may escalate if health degradation is severe.

## Hot-reload (asset-only refresh)

For asset-only refreshes (HTML, CSS, JS changes without binary rebuild):

- Operator invokes `zp assets reload`
- Substrate emits `assets:reload_initiated:<reload_id>` receipt with:
  - Source paths being reloaded
  - Content hashes before / after
- Copies new assets to override dir
- Emits `assets:reload_completed:<reload_id>` receipt

The substrate's `resolve_html_asset()` reads from override dir on next request. No process restart needed. Chain has full record of what changed and when.

## Restart categories

Five restart reason categories, each with slightly different ceremony:

### `build_updated`

Normal build cycle. New binary hash. Full ceremony as above.

### `config_updated`

Configuration change requiring restart. No binary change. Skip build phase; jump to restart intent with `config_updated` reason and pointer to config change receipt.

### `operator_requested`

Operator manually requested restart (no build change, no config change). Direct restart with reason recorded.

### `emergency_recovery`

Restart triggered by circuit breaker at Level 5 (per CIRCUIT-BREAKER) or by operator emergency intervention. Ceremony includes:
- Reference to escalation events that triggered restart
- Broader diagnostic snapshot pre-shutdown
- Post-restart, substrate enters degraded-recovery mode: reduced-authority operation until operator explicitly clears

### `escalation_response`

Restart proposed as remediation for a chain-detected problem (e.g., substrate self-observer flagged runaway resource use). Requires operator ceremony to authorize the restart; substrate does not self-restart without operator sign-off.

## Stale-state hygiene

The forward-only recovery discipline (III.20) means: chain is truth, derived state is recomputed. On restart, any on-disk state file that isn't matched by a chain snapshot receipt is suspect.

**On-disk state file categories**:

- **Chain-managed** (canonical): `~/ZeroPoint/data/audit.db` — this IS the chain, never disturbed by restart hygiene
- **Chain-snapshotted** (derived): `tool-ports.json`, `.guard-paused` files, session tokens — should have matching `*_snapshot` chain receipts on graceful shutdown; recomputed on restart from snapshots
- **Configuration** (operator-managed): `config.toml`, `vault.json`, `genesis.json` — persistent across restarts, operator responsibility
- **Ephemeral** (runtime): `zp-serve.log`, temporary caches, PID files — recreated on restart, cleared as needed
- **Unknown** (suspect): anything not in the above categories

Hygiene sweep at restart:

1. Enumerate all files under substrate runtime directories
2. Classify each per the categories above
3. For chain-snapshotted files without matching snapshot receipt: emit `hygiene:orphaned_state_file` receipt; quarantine
4. For unknown files: emit `hygiene:unknown_file` receipt; flag for operator review
5. For ephemeral files: safe to clean

## Peer verification of build

Under Peer-Verification Contract (KEEL Part VII) and peer trust anchor (per PEER-TRUST-ANCHOR-2026-07.md), peers can request build evidence:

- **`build:artifact_produced` receipts** are shareable — peer sees "this operator's substrate ran binary hash X built from source rev Y at time Z"
- **Reproducibility verification receipts** allow peer to independently verify: peer pulls source rev Y, builds locally, computes their own binary hash, compares to shared build receipt
- **Divergence** triggers investigation: could be reproducibility bug in the build system, could be substrate running unexpected code

This is the substrate answer to "how do I know you're running what you say you're running?" — verifiable via chain evidence and independent rebuild, not via trust.

## Attack model

Attacker scenarios and how the discipline addresses them:

- **Attacker swaps binary between build and run**: operator's `build:artifact_produced` receipt records binary hash at build time. On startup, substrate hashes its own binary and cross-references. Divergence → emergency response.
- **Attacker manipulates on-disk state files across restart**: hygiene sweep detects orphaned or unknown state files without matching chain snapshots. Loading is refused. Operator investigation follows.
- **Attacker triggers rogue restart to reset substrate state**: restart intent must be signed by currently-running substrate's Genesis-derived key. Attacker without that key cannot initiate restart. External `kill -9` bypasses graceful shutdown but new-process boot still verifies chain state and detects the abrupt termination.
- **Attacker injects malicious source**: pre-flight verification checks source integrity. Discipline pins and test suite catch known bad patterns. Peer reproducibility verification catches source-hash mismatches at the corpus level.
- **Attacker manipulates zp-dev.sh to skip verification**: zp-dev.sh is source-controlled. Modifications to build script are themselves source changes visible in source rev, and the substrate's built-in verification (not the shell script) runs at process startup regardless of how the process was launched.

## Failure modes

- **Pre-flight verification incorrectly blocks legitimate build**: false positive. Operator can override with signed `build:preflight_override:<reason>` receipt. Override is chain-visible.
- **Reproducibility divergence with no attacker**: reproducibility bugs in build system (nondeterministic compiler behavior, embedded timestamps). Diagnose via `SOURCE-DETERMINISM` audit — usually resolves with build system fixes.
- **Graceful shutdown times out**: in-flight tool dispatches don't complete within grace period. SIGKILL applied. `restart:preshutdown_incomplete` receipt emitted. Post-restart, substrate looks for in-flight state that didn't complete cleanly and handles per its recovery policy.
- **Chain snapshot missing on planned restart**: substrate's own shutdown failed to snapshot before dying. Post-restart, derived state is empty (safe default). Operator investigates why snapshot wasn't emitted.
- **Post-restart component health check fails**: substrate enters degraded-recovery mode. Reduced authority until component healthy or operator intervention.
- **Legitimate on-disk state file has no chain evidence**: legacy files from before chain-participating restart was implemented. Migration path: operator ceremony to grandfather the file with `hygiene:legacy_file_accepted:<path>` receipt.

## Non-goals

- **Not a substitute for CI/CD**. Substrate's build discipline is about chain-anchoring the local operator's build/restart lifecycle. Team CI/CD systems remain a separate concern.
- **Not a formal build system replacement**. `cargo` remains the build tool. Discipline layers on top.
- **Not automatic upgrade delivery**. Substrate does not fetch new source and rebuild without operator ceremony. Every build is operator-initiated.
- **Not immune to compiler bugs**. If the compiler is compromised, reproducibility across many independent operators can catch it, but no single operator has structural defense against a compromised compiler. That's a corpus-level concern.
- **Not perfect uptime**. Restart is a chain event; the substrate is not designed to never restart. Restart is a first-class primitive, not a failure mode.

## Open positions

- **`zp build` verb design**. Currently `./zp-dev.sh` is the build entry point. Should there be a `zp build` verb that wraps cargo with the chain-participating discipline? Trade-off: shell script simplicity vs verb-uniformity.
- **Pre-flight failure severity**. Some pre-flight failures are hard blocks; others are advisories. Which is which? Configurable per operator?
- **Reproducibility check cadence**. Every build? Every release build only? Weekly ceremony? Trade-off: cost vs assurance.
- **Snapshot receipt schema**. Each derived-state family (port registry, guard pauses, etc.) needs its own snapshot receipt schema. Design work.
- **Restart-in-progress dashboard**. Should the dashboard show restart-in-progress state? Or is that a CLI-only concern? Operator UX design.
- **Restart authorization ceremony for escalation_response category**. Should operator ceremony be required for every restart, or only for escalation-triggered restarts? Trade-off: friction vs governance.
- **In-flight state preservation**. If operator restarts substrate while dispatch is in-flight, what state gets preserved beyond snapshot receipts? Currently: nothing beyond snapshots. Should there be dispatch resumption?

## What composes from here

Immediate design work:

1. **Snapshot receipt schemas** — one for each derived-state family
2. **`zp build` verb spec** — CLI entry point with chain-participating discipline
3. **Pre-flight check registry** — canonical set of pre-flight checks, extensible via extension surface
4. **Hygiene sweep policy** — file classification rules
5. **Reproducibility ceremony** — spec in `REPRODUCIBILITY-CEREMONY-2026-07.md` (task next in sequence)

Near-term implementation:

1. Restart intent / graceful shutdown pipeline in `crates/zp-server/src/lifecycle/`
2. Snapshot receipt emitters for each derived-state family
3. Boot-time state reconstitution logic (chain snapshot → in-memory state)
4. Pre-flight verification framework
5. Binary hash computation and cross-reference at startup
6. Hygiene sweep at startup with unknown-file detection
7. Dashboard restart-lifecycle panel
8. `zp build` CLI verb (or refactor `zp-dev.sh` to call chain-participating primitives)

## Framing note

Chain-participating build & restart applies the substrate's structural discipline to its own lifecycle. Same principle as delegation for actions, admission for artifacts, observation for host state, cognition for reasoning — extended to build events, restart events, and derived-state hygiene.

The load-bearing insight: **the substrate's own lifecycle is chain-anchored.** Not implicit. Not shell-script-visible only. Not "restart is just a process event." Build produces artifacts with recorded hashes; restart is intent → shutdown → boot with chain evidence at each step; derived state is snapshotted before restart and reconstituted from chain after; unknown state files are quarantined pending operator review.

Combined with the substrate's structural discipline across every trust boundary — actions, admissions, observations, cognition, extensions, hardware, emergency response, Genesis rotation, peer trust — chain-participating build & restart completes the visibility envelope for the substrate itself. The lsof test extended to the substrate's own footprint: every file, every process, every restart, every build accounted for on the chain. What today's incident surfaced (stale files, log noise, config divergence, invisible restarts) becomes structurally impossible when the lifecycle itself participates in the chain.
