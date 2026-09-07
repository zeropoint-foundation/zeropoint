# `zp restart` redux — the escape hatch is the verb

**Status:** proposed 2026-08-09 · no code changed yet
**Decides:** what `zp restart` means, and which of four process-identity
mechanisms is authoritative
**Type:** Tier 2 elaboration. Records a decision and the evidence for it.
Figures are regenerable with `tools/cli_surface.py` and the queries named
inline; do not edit them by hand.
**Follows:** `CHANNEL-BOUNDARY-2026-08.md` (which channel carries what),
SEAM-007 (the operator surface leaves no trace), PIN-006.

## The decision

`zp restart`, with no flag, restarts the substrate. `--self` becomes an alias
kept for muscle memory, not a mode.

The kill path is **deleted rather than fixed**. `zp serve` already reaps its
predecessor from `pids/zp-server.pid` before it binds. `zp restart` becomes:
spawn `zp serve`, and let the process that owns the pidfile do the reaping it
already does. Four mechanisms collapse toward one.

`--name` and `--all` are **classified, not repaired**. They are the CLI's
wired-but-never-fired: correct code over a registry that has never held a
binding. Under the SEAM-007 rule that is `reserved` — with a stated `because`
and a `review_after` — or `retired`. What they may not remain is *looking
built*, because "No tools registered in port registry" and "this flag is
broken" are the same output to the operator who typed it.

And restarting the substrate is an **authority act**, so it goes on the receipt
channel with the operator as actor, per the boundary already decided.

## Second decision — the registry is an attestation surface, and the chain is where it lives

Taken 2026-08-09, after measuring what the registry's absence actually costs.
Recorded here because it shares the expired premise; it can be split into its
own document once it has an implementation.

The `PortRegistry` does not retire with the fleet verbs. Its **purpose**
changes: from *the processes ZeroPoint launches and owns* to **the processes
the operator has vouched for**.

What retires is the launching — `zp configure exec`, stored
`StoredLaunchCommand`s, `zp restart --name`, `zp restart --all`,
`zp update --name`. What stays is attribution: `PortRegistry`, `ToolBinding`,
`sync_known_bindings`, the sensor layer's `KnownBinding` feed, and governance
posture. All of it already built, all of it currently starved.

And the source of truth moves. An operator vouching for a process is a signed
claim about trust that must survive a restart and be checkable by someone
without this process's memory — the boundary test from
`CHANNEL-BOUNDARY-2026-08.md`, clause for clause. `tool-ports.json` fails every
one. So attestations live on the **receipt channel**, and the JSON file becomes
a materialisation of chain state, the relationship the Cartographer already has.

### Why not retire the registry with the verbs

Because it is not inert. It is a **finding generator**, and its emptiness is
what generates.

`officers.rs:904` (`sync_known_bindings`) maps registry bindings into
`zp_sensors::KnownBinding`; `officers.rs:706` builds the governance-posture
snapshot from `registered_tools`; `officers.rs:1233` re-syncs on a
`tool-ports.json` change. Zero bindings means zero known bindings, which means
every listening process on the machine is unattributed.

Measured over the most recent 20,000 chain entries:

| finding | officer | findings | distinct binaries |
|---|---|---|---|
| `unregistered_listener` | Forge (operations) | 268 | **21** |
| `unregistered_known_app` | Sentinel (security) | 195 | **12** |
| `unauthorized_listener` | Sentinel (security) | 73 | **9** |

12 + 9 = 21. Forge flags everything absent from the registry; Sentinel splits
that same set into *recognised but unvouched* and *unrecognised*. The officers
already do the triage, and the queue is 21 decisions, not 200.

The single largest entry is `/Applications/Ollama.app/Contents/Resources/llama-server`
at 118 findings, plus 23 for `ollama` and 4 for `Ollama` — the inference backend
`config.toml` points the Regent at on 11434. **The substrate flags the process it
thinks with as an unattributed listener, on every sweep, with no mechanism to say
otherwise.** That is the case for attestation existing at all.

It also closes a loop. The fleet premise expired → nothing registers → the
registry is permanently empty → three findings fire on every sweep and can never
clear → the finding set never changes → the Regent's novelty gate never opens.
At least three of SEAM-006's standing findings now have a named cause, and
DECIDED-002 was right for a reason not yet visible when it was taken.

### What an attestation must carry

If it binds path and port only, replacing the binary at that path silently
inherits the vouch, and the attestation certifies a filename. It carries the
**binary hash at attestation time**, and a hash change raises a finding.

That inverts the current situation productively: today the standing findings are
permanent and therefore ignorable; under attestation the *violation* is the
event, it is genuinely novel by the DECIDED-002 fingerprint, and it reaches the
Regent through the gate already built. An attestation that cannot be violated is
not evidence.

### Falsify before building

One binding, one finding. Attest `llama-server`; `unregistered_known_app` should
fall from 12 distinct binaries to 11. If it does not, the causal chain above is
wrong and everything in this section needs revisiting before any of it is built.
This is the whole of step one.

## Why this is not drift

`zp restart` was a unit variant until 2026-05-18:

```
-    /// Restart the running ZeroPoint server (kill → re-launch)
-    Restart,
+    /// Restart tools or the ZeroPoint server.
+    Restart { name: Option<String>, all: bool, self_: bool },
```

`8fb021d` — *"feat(ports): rewire zp restart to tool-targeted; add zp port
list; add discipline pin"*. Its own commit body says `--self` "preserves old
lsof→kill→re-exec behavior as a documented escape hatch (for recovery when the
chain can't be queried)."

That was a coherent decision under the premise of the time: ZeroPoint as a
universal agent-framework adapter, managing a fleet of tools whose ports and
PIDs it owned. The verb's centre of gravity moved to the fleet, and the
substrate — the thing an operator actually restarts — was left in the position
labelled *escape hatch*.

The premise expired. The fleet never materialised. Nothing announced this,
because nothing was watching for it: the code stayed internally consistent the
whole time, and consistency is what our instruments measure.

## The evidence

Measured 2026-08-09 against the live chain (295,560 entries) and the running
substrate.

**The fleet never existed.** `--name` and `--all` read
`{data_dir}/tool-ports.json` (`tool_ports.rs:264`). That file is not in
`~/ZeroPoint/data/`. No chain event begins `port:`, `tool:`, `configure:` or
`update:`. No `port_registry` actor appears among the 16 distinct actors on the
chain. `PortRegistry` skips persisting when empty (`tool_ports.rs:~375`), so an
unused registry leaves no file — the absence is self-concealing. `--all`
therefore prints "No tools registered in port registry." and exits 0, which is
the reported symptom and is also correct behaviour. PIN-002.

**`zp serve` already reaps.** `crates/zp-server/src/lib.rs:1956–1998`: read
`pids/zp-server.pid`, `kill -0`, TERM, 500ms, KILL, 200ms, then write our own
PID — all before the listener binds. This runs regardless of who launched the
process, so **the pidfile is the one mechanism that always holds.** It is also
the one no CLI verb consults.

**Four mechanisms claim to know which process is the substrate.**

| | how it identifies | how it kills | reads pidfile |
|---|---|---|---|
| `zp serve` boot (`lib.rs:1956`) | `pids/zp-server.pid` | `-0` → TERM → 500ms → KILL | writes it |
| `zp restart --self` (`main.rs:1934`) | `lsof -ti :PORT` | TERM → 500ms → *(no check)* | no |
| `zp-dev.sh kill_server` (`:58–90`) | `lsof -ti :PORT -sTCP:LISTEN` + `pkill -f "zp serve"` | TERM → poll → KILL | no |
| `restart --name` (`main.rs:~1987`) | `PortRegistry` binding PID | TERM → poll 5s via `is_pid_alive` → KILL | n/a |

**`--self` is the least careful path, and it is the only one an operator runs.**

1. It is the sole kill site in the tree calling `lsof -ti :PORT` **without**
   `-sTCP:LISTEN`. `zp-dev.sh` uses the filter in all five of its calls. Without
   it, the match includes processes holding a *connection* to the port, not just
   the listener — so the command can kill clients of the substrate along with it.
2. It sends a plain TERM, sleeps 500ms, and never verifies death.
3. It spawns `zp serve` **unconditionally**, including down the branch that has
   just printed "⚠ No server found on port {}". A command that reports finding
   nothing to restart then performs a full boot ceremony — which is how a
   hardware-sovereignty prompt appears after an apparent no-op.
4. It spawns bare `zp serve`, and `open_dashboard` defaults to `true`
   (`zp-config/src/schema.rs:123`), so a restart also opens a browser tab.

**The correct primitive exists and the substrate path does not call it.**
`is_pid_alive` (`tool_ports.rs:1209`) with TERM → poll 5s → KILL escalation is
used by `--name`, for the fleet that has never had a binding. The substrate gets
`sleep(500ms)`. This is the `AuditStore::live_entry_count` shape exactly:
correct, documented, and wired to the wrong caller.

**The careless path is rescued by the careful one it does not know about.** When
`--self`'s TERM does not take within 500ms, the `zp serve` it spawns reaps the
survivor properly during its own boot. `--self` appears to work because of a
mechanism it never references. Remove the reap and `--self` starts failing
intermittently, with the failure attributed to the wrong file.

**Flag precedence is undeclared.** The three flags carry no `conflicts_with`,
and the handler tests them in order: `--self` short-circuits with
`std::process::exit(0)` before `--name` is read, and `--name` before `--all`.
`zp restart --all --self` silently does `--self`. `zp restart --name x --all`
silently does `--name`. Neither combination is rejected, and no output says
which flag won.

**The boot is recorded; the decision to boot is not.** `emit_lifecycle_receipt`
(`lib.rs:~1990`) writes `system:startup version= pid= port=`. There are 85 such
entries on the chain, most recently `pid=98509` at 2026-08-09T20:32:13Z, which
matches the current pidfile. **All 85 carry actor `{"System":"server"}`.** The
substrate records that it booted. Nothing records that an operator asked.
`restart` is one of 43 top-level verbs with no operator-attributed entry; three
of 46 have one (SEAM-007).

## Consequences

**One mechanism, not four.** `zp restart` spawns `zp serve` and stops there.
`--self`'s lsof path is removed rather than given the `-sTCP:LISTEN` filter,
because fixing it preserves the second mechanism. If a pre-kill is still wanted
for a stale pidfile, it reads the pidfile and escalates via `is_pid_alive` — the
primitive `--name` already uses.

**`zp-dev.sh` stays, and is not the same thing.** It rebuilds, installs the
symlink, tails logs, and waits on the listener. It should delegate its kill to
the same path rather than keep its own `pkill -f`, but it is a development
harness and does not need to become a verb.

**Precedence gets declared.** `conflicts_with` on all three, so a contradictory
invocation is rejected by clap rather than resolved by statement order. This is
the same class as the flag audit in `cli_surface.py` measure 2, which came back
clean because it can only see whether a field is *destructured* — not whether
one silently shadows another.

**`restart` becomes the first verb of the SEAM-007 tranche.** One receipt at the
point of asking, operator as actor, distinct from the `system:startup` the
server emits about itself. Restart is the smallest honest instance of the
problem: unambiguous authority, one call site, no data model to design. If a
receipt cannot be attached here it cannot be attached to `keys`, `delegate`,
`revoke`, `gate`, `operator`, or `configure` either.

**Retiring `--name`/`--all` does not retire the sediment.** The fleet premise
left consumers throughout the tree that outlive the verbs: `AuditAction`
declares `ToolInvoked` and `ToolCompleted` with no producer outside test
fixtures, `narration.rs` dispatches on all 12 variants with ten arms that cannot
fire, and `zp-regent/src/context.rs:1651` builds the Regent's context from tool
actions that have never been written. The verb is the surface. That is the
stratum.

## Corrections to this document

Recorded rather than edited away, per the practice in
`CHANNEL-BOUNDARY-2026-08.md`.

- **"`zp restart --self` writes nothing anywhere" — withdrawn.** Stated
  2026-08-09 in the SEAM-007 discussion. It writes nothing *itself*, but the
  `zp serve` it spawns emits `system:startup`, and 85 of those are on the chain.
  The defect is attribution, not absence — a materially different claim, and the
  weaker one was reached by reading the `restart` handler without following what
  it spawned.
- **"The pidfile has no writer" — nearly asserted, false.** An initial grep for
  `zp-server.pid` restricted to `--include=*.rs` under `crates/` returned only
  `binding.pid` field accesses, and `zp-dev.sh` uses a shell `$!` it never
  persists. The writer is `lib.rs:1998`, found by searching for the path
  construction rather than the filename. Had this been published it would have
  removed the one authoritative mechanism from the map and argued for building a
  fifth.
- **"`zp restart` is stale" — true, but not by drift.** It was rewired
  deliberately in a single commit with a stated rationale. "Stale" here means the
  premise expired, not that the code decayed. The distinction matters for the
  review method: no consistency check can find this, because nothing became
  inconsistent.
- **"The allowlist is leaking and should be fixed first" — withdrawn before it
  reached this document, stated aloud first.** `known_system_category`
  *classifies* rather than suppresses, which is why "known app" and
  "unauthorized" are separate finding types. The 12 + 9 = 21 arithmetic shows
  the split working as designed. The instinct came from seeing `ollama` in both
  the allowlist and the findings and concluding the table had failed, without
  checking what the table is for. The separate allowlist defect is real, smaller,
  and differently shaped — SEAM-008.
- **"An empty registry causes these findings" — supported, not proven.** The
  consumption path (`officers.rs:706`, `:904`, `:1233`), the remediation
  (`SetPortBinding`), and the 12 + 9 = 21 split all point one way. No binding has
  been added and no finding has been watched to clear. Until that is done this is
  the best available reading of the evidence, not a demonstrated cause — which is
  why "Falsify before building" is step one and not a formality.

## Open

The four questions this document opened were answered in discussion on
2026-08-09; the answers are recorded here and the remaining work is below them.

1. **`--name` / `--all`: neither reserved nor retired — reclassified.**
   The verbs retire; the registry they addressed becomes an attestation surface
   (second decision, above). Same disposition for `zp configure exec` and
   `zp update --name`. `zp port` survives and grows an `attest` verb. `zp tool`,
   `zp ps --tools` and `zp run` are unreviewed and belong to the cluster sweep.
2. **The restart receipt is not a restart receipt.** There is no lifecycle or
   session type among the 40 declared; the nearest are `ConfigurationClaim`,
   `ObservationClaim`, and the fleet premise's own inert `PortAllocated` /
   `PortReleased`. Stretching one is wrong — an operator restarting the
   substrate is not a configuration change, and `ObservationClaim` is the system
   observing itself, which already happens 295,481 times. What is missing is a
   *category*: operator-initiated lifecycle acts. One type serving all seven
   verbs of the SEAM-007 tranche. If it cannot carry all seven it is the wrong
   type, and adding a 41st while 26 are inert needs that justification.
3. **`zp restart` does not refuse mid-cycle.** Refusing yields a substrate you
   cannot restart precisely when it is wedged, and "we will add a way around it"
   is how `--self` came to exist. Restarts already announce themselves: under
   DECIDED-002 the first cycle after a restart is novel by definition and always
   deliberates. Record the interruption, do not prevent it. Unchecked: whether
   an in-flight cycle loses unpersisted state on kill. If it does, the answer
   becomes "do not refuse, but drain."
4. **The binary is identified by the receipt.** `env!("ZP_GIT_HASH")` is already
   bound in the restart handler and used for one `println!`. Meanwhile all 85
   `system:startup` entries carry `version=0.1.0` — `CARGO_PKG_VERSION`,
   identical across every build ever made — so the chain cannot distinguish two
   binaries. One field, no new plumbing, and the value is already in scope at
   the moment of emission. Same shape as the `CapabilityGrant` bound to
   `_grant`.

Remaining:

5. **Prove the causal chain before building anything** — attest `llama-server`,
   watch `unregistered_known_app` fall from 12 distinct binaries to 11.
6. **What retires alongside the launching path.** `StoredLaunchCommand`,
   `ReleaseReason::OperatorKill`, and the `zp configure exec` re-invocation in
   `restart --name` have no meaning under attestation. They are code, not
   surface, and deleting them is not urgent — but they should be classified so
   the next reader does not reconstruct the fleet premise from them.
7. **Whether `zp-dev.sh` delegates its kill.** It keeps its own
   `lsof -sTCP:LISTEN` + `pkill -f` path. It is a development harness and need
   not become a verb, but it should not be a fourth opinion about which process
   is the substrate.
8. **`zp port attest` is an operator-signed verb, which makes it the first one
   outside the session-token trio.** Whether it uses that path or the sovereign
   root is undecided, and `is_session_token_only` is the wrong place to decide
   it — see SEAM-007 on collapsing the third dispatcher.
