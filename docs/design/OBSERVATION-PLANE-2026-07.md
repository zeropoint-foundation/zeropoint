# Observation Plane

**Tier 2 canonical elaboration.** Elaborates `KEEL-2026-07.md` §II (adds Layer A observation tier) and Part IV (adds host-body ontology objects). Canonical claims live in KEEL; this doc provides the implementation-level detail and design rationale. Supersedes the strategic reservation in the historical `ARCHITECTURE-2026-04.md` Part VIII.

Draft — 2026-07-10 — internal audience only. Composes with `SUBSTRATE-FORM-2026-07.md` — reachable observation surface varies by Substrate Form.

## Framing

The officer-blindness question surfaced a structural gap: the officers observe the chain, but nothing writes host-body facts to the chain, so nothing to observe. A 399MB runaway log, a 1.35GB audit database that isn't checkpointing, a `.guard-paused` file two months stale, `tool-ports.json` empty despite tools running — none of these produced findings from any officer, because the substrate has no proprioception. It cannot feel its own body.

The observation plane closes this gap. It is the Layer A tier that gathers signals from the substrate's host environment and emits signed observation receipts to the chain. It does not interpret, decide, or act. Officers query the ontology the Cartographer builds from those receipts; Regent perceives host-body state through the same path. The observation plane is the sensor tier of the substrate — chain-anchored, delegation-scoped, Form-appropriate.

Three load-bearing properties frame everything below:

1. **Observation is universal; control is delegated.** The plane sees what its delegation scopes permit; acts on nothing. Any action taken in response is a downstream officer or operator decision, gated normally.
2. **Scope is chain-signed.** The plane cannot observe outside its baseline scope without an operator-signed delegation. Privacy is structural, not policy — it's a cryptographic property of the chain.
3. **Reach varies by Form.** On Sovereign Form the plane can observe the full host; on Companion Form only what the vendor permits. Form Disclosure covers the honest limitations.

## The seven observation surfaces

Every observable phenomenon on the host maps to exactly one of six surfaces. Each surface has native sensor primitives (Layer A), an ontology object type (Layer B), a default sampling cadence, and a delegation class.

### Processes

Every process on the host with cmdline, parent, opened files, socket table, memory footprint, CPU time.

- **Layer A primitives (Sovereign / Appliance)**: `procfs`, `sysctl kern.proc`, eBPF `process_exec` / `process_exit` tracepoints, `getgrouplist`, `libproc` for socket-to-PID resolution.
- **Layer A primitives (Companion)**: `libproc` on macOS bounded by vendor permissions; NT `Process32Next` on Windows; whatever the OS permits.
- **Ontology object**: `Process` — pid, ppid, name, cmdline, uid, gid, start time, socket descriptors, memory RSS, CPU seconds. Materialized by the Cartographer from `observation:process:*` receipts.
- **Cadence**: enumeration every 60s; event-driven receipts on exec/exit if the primitive supports it.
- **Delegation class**: `observe:processes:host` — default is only ZP's own process tree.

What this would have caught: `.guard-paused` idle for months (no receipt from guard for that duration), stale foreign PIDs after tile restarts (per the 2026-06-28 heuristic), the auth-polling client (identified by process not just by log line).

### Network

Every listener, every outbound connection, every DNS query.

- **Layer A primitives (Sovereign / Appliance)**: `ss` / `netstat`-equivalent via netlink, eBPF `sock_ops` tracepoints, `iproute2` for interface state, DNS via systemd-resolved query log or eBPF DNS trace.
- **Layer A primitives (Companion)**: `lsof -i` bounded by vendor permissions on macOS; PowerShell / Netsh on Windows; degraded but useful.
- **Ontology object**: `Listener`, `Connection`, `DnsQuery`. Materialized from `observation:network:*` receipts.
- **Cadence**: listeners every 30s; connection deltas event-driven where possible, 30s snapshot otherwise; DNS event-driven.
- **Delegation class**: `observe:network:host`.

What this would have caught: the 8-endpoint 401-polling client identified as a specific connection triple (source PID, dest port, cadence), unfamiliar outbound connections from ZP-launched tools, DNS queries revealing exfiltration attempts.

### Filesystem posture

Disk usage per volume, growth rate on key directories, mtimes on structural files, filesystem type, encryption state.

- **Layer A primitives (Sovereign / Appliance)**: `statfs`, `du`-equivalent via directory walk, inotify on watched paths, LUKS state via `cryptsetup status`, ZFS/btrfs state via native tools.
- **Layer A primitives (Companion)**: `statfs`, macOS `du` bounded by TCC, Windows `Get-Volume`.
- **Ontology object**: `Volume`, `Directory`, `TrackedFile`. Materialized from `observation:filesystem:*` receipts.
- **Cadence**: volume stats every 5 min; tracked-directory growth every 60s; mtime deltas on chain-anchored important files (audit.db, tool-ports.json, vault.json) every 30s.
- **Delegation class**: `observe:filesystem:home` for `~`, `observe:filesystem:full` for full disk.

What this would have caught: audit.db at 1.35GB, WAL at 1.13GB, zp-serve.log at 399MB and still growing, tool-ports.json empty despite tools running.

### Persistent surfaces

Launchd jobs (macOS), systemd units (Linux), scheduled tasks (Windows), cron/at, Docker containers, brew services, snap packages, background app registrations.

- **Layer A primitives (Sovereign / Appliance)**: `systemctl list-units`, `crontab -l`, `docker ps` if Docker present, container runtime introspection.
- **Layer A primitives (Companion)**: `launchctl list` on macOS, `Get-ScheduledTask` on Windows.
- **Ontology object**: `PersistentSurface` — a running-or-configured-to-run job with restart policy, invocation command, ownership, next-fire time.
- **Cadence**: enumeration every 5 min; event-driven on install/uninstall via inotify-equivalent on config dirs.
- **Delegation class**: `observe:persistent:host`.

What this would have caught: silent addition of a launchd job (post-compromise persistence pattern), Docker container running that no receipt attests to, cron job expiring or firing at unexpected times.

### Credentials

Keychain items (macOS), Credential Manager items (Windows), Secret Service items (Linux), SSH keys, GPG keys, VPN state, browser cookie metadata (via extension or accessibility bridge).

- **Layer A primitives (Sovereign / Appliance)**: Secret Service D-Bus interface, `ssh-add -L`, `gpg --list-keys`, WireGuard/OpenVPN state files, browser extension bridge for cookie enumeration.
- **Layer A primitives (Companion)**: macOS Security framework `SecItemCopyMatching` for metadata only (not contents), Windows Credential Manager APIs.
- **Ontology object**: `CredentialRef` — service, account, kind (password / token / key / cert), creation time, last-modified time, storage backend. **Never** the credential value.
- **Cadence**: enumeration every 10 min; event-driven on add/remove if the primitive supports.
- **Delegation class**: `observe:credentials:keychain_metadata`, `observe:credentials:ssh`, `observe:credentials:vpn`, `observe:credentials:browser_cookies_metadata`.

What this would have caught: an unauthorized keychain entry added by a rogue installer, an SSH key present that no operator ceremony provisioned, a VPN silently reconfigured.

**Content is out of scope for the observation plane by policy and by architecture.** Reading credential *contents* is a separate, delegation-gated operation with different provenance requirements. The observation plane emits metadata only.

### Application state

Running applications and their coarse-grained state — foreground/background, workspace/window count, MCP servers connected, IDE workspaces open, browser tabs (via extension).

- **Layer A primitives (Sovereign / Appliance)**: X11/Wayland compositor introspection, accessibility APIs, MCP client for connected servers, IDE process detection.
- **Layer A primitives (Companion)**: macOS accessibility API bounded by TCC, Windows UI Automation.
- **Ontology object**: `RunningApp` — app name, running instances, foreground state, workspace count, external integrations.
- **Cadence**: foreground/focus event-driven; enumeration every 60s.
- **Delegation class**: `observe:apps:running`, `observe:browser:tabs`.

What this would have caught: an MCP server silently connected without an authorizing receipt, a background AI companion running unnoticed, a browser tab holding a session that outlived its intended scope.

### Inference telemetry

Substrate-internal signal from the inference path — for now, drafter acceptance rate under speculative-decoding acceleration. When a MODEL-DOSSIER-2026-07 drafter is active for a target model, the decoder produces per-token evidence of whether the drafter's guess matched the target's verification. That signal is a live measurement of drafter-target fit, and by MODEL-DOSSIER's characterization equivalence it is a live measurement of dossier freshness.

- **Layer A primitives (all Forms)**: hook in the substrate's inference server (vLLM, SGLang, MLX runtime); reads drafter's per-token confidence and acceptance outcomes; aggregates over rolling windows.
- **Ontology object**: `DrafterAcceptanceWindow` — target_model_id, drafter_id, window_start, window_end, mean_acceptance_rate, position_wise_acceptance_curve, workload_class_breakdown. Materialized by the Cartographer from `observation:inference:drafter_acceptance` receipts.
- **Cadence**: emitted per rolling window (default: every 1000 tokens). Additional emission on any per-window acceptance-rate drop crossing the dossier-declared threshold.
- **Delegation class**: `observe:inference:acceptance` — separate from `observe:apps:running` because inference telemetry sees content-shape signal, not just process state; operator opts in per model.

What this catches: silent provider version drift (a hosted model swapped behind a stable name; drafter trained against previous behavior shows acceptance-rate collapse within a small number of tokens); drafter staleness after base-model minor version bump; workload-class mismatch (drafter fits math well, chat poorly — visible in `workload_class_breakdown` before it shows up in dispatch failures). Consumed by MODEL-DOSSIER §"Continuous drift signal" to emit `substrate:characterization:drift_suspected` receipts against affected dossiers; consumed by CIRCUIT-BREAKER as a trigger class; consumed by SHADOW-EVALUATION-PRIMITIVE Context 1 as the *when* signal for running candidate-vs-control comparisons.

## Layer A / Layer B split

The observation plane spans both layers per the SUBSTRATE-EXECUTION-ARCHITECTURE-2026-07 split.

**Layer A (compiled Rust host)**:
- Native sensor primitives per Form (kqueue, inotify, procfs, sysctl, eBPF, native security framework calls)
- Sampler task runners and event-driven listeners
- Signing infrastructure — Genesis-derived per-class observation keys, receipt shaping, chain append
- Delegation-scope enforcement — the plane refuses to sample surfaces outside currently-delegated scopes
- Form-appropriate primitive selection at compile time or first-boot

**Layer B (WASM modules + canonical data)**:
- Receipt schemas per observation class
- Ontology object definitions (Process, Listener, Volume, PersistentSurface, CredentialRef, RunningApp, DrafterAcceptanceWindow)
- Interpretation rules — what constitutes drift, what thresholds mean "warning" vs "info"
- Officer-consumable finding shapes derived from observation streams

Layer A is structurally defended. Layer B evolves per the canonicalization ceremony (KEEL §VI). New observation classes, new thresholds, new object schemas — all Layer B, all amendable through ceremony.

## Observation-scope delegation as a new gate class

The gate today governs *action* delegation — what the substrate is allowed to *do*. The observation plane introduces *observation* delegation — what the substrate is allowed to *see*.

Structurally the same shape: chain-anchored, operator-signed, scoped, expirable, revocable. But a new gate check inside Layer A: before the observation plane calls a sensor primitive, it verifies the current chain contains a valid, unexpired `delegation:observe:{class}` receipt covering the scope needed. No delegation → primitive not called → no receipt emitted → no data collected. The plane cannot "leak" data it wasn't authorized to observe because it never collected it.

**Baseline scope (no delegation required):**
- ZP's own process tree
- ZP's own log files
- ZP's own vault
- ZP's own listening ports
- The audit chain database

Everything else requires explicit delegation.

**Standard delegation classes:**
- `delegation:observe:processes:host` — all host processes
- `delegation:observe:network:host` — all host listeners and connections
- `delegation:observe:filesystem:home` — mtimes and posture across `~`
- `delegation:observe:filesystem:full` — full disk posture
- `delegation:observe:persistent:host` — launchd / systemd / cron / Docker / etc.
- `delegation:observe:credentials:keychain_metadata` — keychain item names, never contents
- `delegation:observe:credentials:ssh` — SSH agent state
- `delegation:observe:credentials:vpn` — VPN state
- `delegation:observe:credentials:browser_cookies_metadata` — browser cookie names, never values
- `delegation:observe:apps:running` — running applications
- `delegation:observe:browser:tabs` — browser tab URLs and titles

Each delegation carries: scope class, allowed operations (read, watch, poll cadence bounds), expiry, revocation-priority. The operator can revoke any delegation via signed receipt; the observation plane transitions to baseline scope for that class within one sampling cycle.

**Observation receipts cite their delegation:**
Every `observation:*` receipt includes the delegation ID that authorized its scope. The chain records not just *what was observed* but *why the substrate was allowed to see it*. Cleo can narrate: "You granted the substrate permission to see all listening ports at time T. Since then, 47 network listener receipts have been emitted. Here's what they show."

## Provenance — observation-plane signing keys

Per KEEL §II.5 (Decision A): all keys derive from Genesis. The observation plane needs its own signing keys so its receipts are attributable.

Shape: one signing key per observation *class*, HKDF-derived from Genesis with the class name as info material. Cryptographically:

```
observation_key[class] = HKDF(genesis_root, salt=chain_head_at_derivation, info=f"observation:{class}")
```

This gives fine-grained provenance:

- Compromise of the `observe:processes:host` key does not compromise `observe:credentials:*`
- Each class's key rotates on its own cadence
- Receipts carry `signed_by: observation:processes:host` — the chain shows *which observation authority* attested to each fact
- Officer findings can cite specific observation receipts by hash, closing the provenance loop back to Genesis

Genesis-certification happens once per class at first delegation grant. The delegation receipt provisions the class's key alongside the scope grant.

## Composition with Substrate Form

The observation plane's reachable set varies by Form. Same architecture, Form-specific Layer A primitives, Form-specific reach.

### Sovereign Form

Full native primitives. All six surfaces reachable at native Layer A depth. eBPF for kernel-level events, direct procfs access, direct secret-service D-Bus, direct netlink. The observation plane is the substrate's sensory system for a host it fully owns.

### Appliance Form

Same as Sovereign for the appliance itself. On the daily driver (Companion-tier client), observation is limited to what the client's OS permits. The delegated-client observation plane on the daily driver reports up to the appliance, where the reasoning happens. This means the appliance sees the operator's daily-driver state *as reported by the client* — trust is bounded by client integrity.

Fleet-composed observation: if the sovereign has multiple appliances (per SUBSTRATE-FORM-2026-07.md fleet compositions), each observation plane emits to its local chain replica; chain sync per Peer-Verification Contract (KEEL §VII) propagates. Officers reason over the union.

### Companion Form

Best-effort within vendor permissions. Reachable set for each surface:

- Processes: coarse via `libproc` / `ps` — no cmdline for other users' processes, no eBPF
- Network: `lsof -i` output, restricted per TCC — cannot see all sockets on macOS
- Filesystem posture: only paths TCC grants access to
- Persistent surfaces: `launchctl list` (macOS), scheduled tasks (Windows)
- Credentials: keychain via Security framework — metadata only, and only for items the operator's session has access to
- Application state: accessibility API — requires user grant of Accessibility permission

Form Disclosure covers the gaps honestly. Companion Form's observation plane is *degraded*; the substrate is honest about what it cannot see.

## Composition with the officer cadre

Each officer's sweep queries the ontology; adding host-body ontology objects extends every officer's reach.

- **Steward (integrity)** — verifies chain integrity as before, plus verifies observation-plane provenance (every observation receipt cites a valid delegation, signing keys derive correctly from Genesis, sampling cadence matches declared).
- **Sentinel (security)** — reads Process, Listener, Connection, PersistentSurface, CredentialRef ontology objects. Findings: unfamiliar processes, unexpected listeners, silent persistence additions, credential-store changes without operator ceremony, VPN reconfigured.
- **Forge (operations)** — reads Volume, Directory, TrackedFile, RunningApp objects. Findings: log growth exceeding threshold, disk pressure, tracked-file drift, hot-loop signatures (churn rate on specific PID), tool-registry drift.
- **Cleo (governance narration)** — narrates delegation grants (including observation delegations) and the observation traffic that resulted. Answers "what has the substrate been watching, and what has it seen?"
- **Aegis (trajectory monitoring)** — cross-surface trajectory detection. A pattern of processes-plus-network-plus-persistent-surfaces changes over time reveals trajectories (e.g. onboarding a new development environment) or drift (e.g. gradual scope creep in some app's persistence footprint).

**The officer-blindness examples from the current substrate diagnosis, now findable:**

- 399MB log growth → Forge finding on `TrackedFile:zp-serve.log` growth-rate exceeding threshold
- 1.35GB audit.db with 1.13GB WAL → Forge finding on `Volume:audit_db_volume` growth + `TrackedFile:audit.db-wal` size ratio anomaly
- `.guard-paused` idle 2.5 months → Steward finding on `Process:guard` absence, cross-referenced against chain absence of `guard:resumed` receipt
- 401-polling storm → Sentinel finding on `Connection` pattern (persistent client hitting eight endpoints per second, all unauthenticated)
- Empty `tool-ports.json` despite a governed tool running → Forge finding on `PersistentSurface:{tool}` present, `Process:{tool}` present, but `tool-ports.json` empty — structural inconsistency

All emerge from the same architecture: observation receipts populate the ontology, officers query the ontology, findings emit as chain receipts, the chain teaches everyone downstream.

## Composition with the Cartographer

The Cartographer materializes host-body ontology from observation receipts, same as it materializes governance ontology from governance receipts. Same infrastructure, additional object types.

New ontology objects: `Process`, `Listener`, `Connection`, `DnsQuery`, `Volume`, `Directory`, `TrackedFile`, `PersistentSurface`, `CredentialRef`, `RunningApp`.

New relationships to existing ontology:

- `Process` observed → linked to `Trajectory` if operator activity correlates
- `PersistentSurface` observed → linked to `Artifact` if provisioned by a chain-anchored artifact
- `CredentialRef` observed → linked to `Delegation` if the credential authorizes some capability
- Any observation drift → potential `Friction` if pattern recurs

Cartographer state is local, rebuildable, disposable per KEEL §II.7. Deleting host-body ontology entries and rebuilding from chain receipts must produce identical output — same architecture as governance ontology.

## Composition with Regent

Regent's cognitive context expands to include host-body state as first-class perception.

- She perceives current process footprint, memory pressure, disk pressure, loaded models
- She perceives active persistent surfaces and background tasks
- She perceives delegation-observation scopes currently in force (so she knows what she can reason about)
- She perceives her own runtime cost — inference latency, spend rate, thermal state where available

This is the substrate side of what the *new capabilities must be harmonized with the flow of the system* heuristic requires. Regent's harmony calculus — decisions about when to spawn background work, when to defer to operator input, when to cancel a sweep — depends on this perception. Without it, Regent is making harmony decisions blind.

The observation plane also protects Regent: if her inference-sourcing decision (local vs rally vs cloud) needs to weigh privacy scope of the query against provider trust, she needs to see what surfaces the query would expose. Observation-scope perception feeds inference-source choice.

## Privacy as structural property

The delegation-signature-per-scope architecture makes privacy a cryptographic property, not a policy that could be violated. Concretely:

- The observation plane *cannot* produce receipts about credential metadata unless a signed `delegation:observe:credentials:*` exists on the chain. Same shape as any capability gate. Attempts to sample outside delegated scope fail structurally.
- Every observation receipt cites its authorizing delegation. Operator can audit at any time: "show me every receipt observation-plane emitted about my browser, and which delegation authorized each."
- Revoking a delegation is a chain-signed receipt. Once emitted, the observation plane observes that revocation before its next sampling cycle for that class, and transitions to baseline scope. No leak window past revocation-plus-cycle.
- Contents vs metadata is structurally enforced. Credential *values* live in a separate gate class; the observation plane is metadata-only by architecture, not by policy.

Cleo can narrate the observation surface honestly. The chain doesn't lie about what the substrate has been seeing.

## Non-goals

- **Not a replacement for osquery / Datadog / Falco.** Those observe for humans reading dashboards. The observation plane observes for agents reasoning about the chain. Same data domain, different consumer. osquery may be an *implementation detail* (called under the hood, output translated into observation receipts) but the chain-anchored receipt is the substrate's contract, not osquery's output format.
- **Not root by default.** The plane operates at whatever privilege the substrate has. Elevated observation (e.g. `lsof -i` requiring root to see all sockets) is negotiated per-invocation via OS-native permission grants, chain-anchored as elevation receipts. No persistent root.
- **Not silent expansion.** New observation classes and delegation scopes are added through canonicalization ceremony (Tier 2), not by shipping new binaries. The operator sees each new class arrive on the chain and has to sign a delegation to authorize it.
- **Not the credentials-reading path.** Reading credential *contents* is a separate delegation class with different provenance requirements. The observation plane is metadata-only.

## Open positions

- **Cadence tuning per surface.** Defaults above are estimates. The empirical program will map load impact and information gain per cadence per Form.
- **Aggregation vs raw receipts.** A busy host has many processes — 200+ on a typical Mac. Should each process observation be its own receipt, or one aggregated `observation:processes:snapshot` receipt per sampling cycle? Trade-off: chain volume vs officer query granularity. Recommendation: aggregate snapshots for enumeration, individual receipts for events (exec, exit, socket bind, socket close). Empirically validate.
- **eBPF vs polling on Sovereign Form.** eBPF is beautiful but limits which kernels the substrate runs on. Polling is universal but heavier. Recommendation: eBPF where kernel supports; polling fallback with declared observation-fidelity degradation.
- **Cross-appliance observation.** A sovereign with multiple appliances — should each observation plane emit locally and rely on chain sync, or should there be a designated "primary observation source" per surface? Related to fleet composition per SUBSTRATE-FORM. Recommendation: emit locally, chain sync propagates, no primary designation needed if chain sync semantics are sound.
- **What triggers a delegation review.** Automatically prompting the operator to review long-lived observation delegations (e.g. "you granted `observe:network:host` 90 days ago; still want it?") is good hygiene but easy to make annoying. Cleo probably owns the narration; cadence and threshold TBD.
- **Retention policy.** Observation receipts add up fast. The chain grows. Epoch-seal compaction (KEEL §II.2) handles the bulk case, but per-class retention (keep enumeration snapshots for 7 days, event receipts for 90 days) is worth designing. Related to audit.db bloat problem the current substrate is exhibiting.
- **First-boot ceremony for observation delegations.** How does an operator granting fresh delegations at first boot know what to grant? Sensible defaults (e.g. `observe:processes:host` and `observe:filesystem:home` are usually wanted) with visible dashboards showing what each delegation surfaces. Design work.

## What composes from here

Immediate design work:

1. **Six observation-class schemas** (Layer B canonical records). One per surface. Includes receipt shape, ontology object shape, drift thresholds.
2. **Observation-plane runtime scaffold** (Layer A). Task runners, primitive dispatchers, delegation-scope enforcement, signing key derivation, chain-append pipeline.
3. **Minimum-viable proprioception subset** — before full plane lands, ship processes + filesystem posture + audit.db size + log size on a 60s cadence. This alone unlocks Forge findings on the current substrate hygiene issues (the very ones that surfaced this whole architecture).
4. **Observation delegation UI copy**. Not just chain receipts — the operator needs a legible surface explaining what each scope grants and why. Related to *the chain configures the cockpit* heuristic.
5. **Empirical program entries** — observation-plane load impact per Form, delegation-scope UX, host-body ontology stability under drift, keychain-metadata observation privacy verification.

Near-term implementation:

1. Add proprioception subset to Regent stand-up sequence, before first inference call. Regent should perceive her own runtime cost from her first cycle.
2. Downgrade current INFO logs that would be replaced by observation receipts (KEEL Layer A cleanup).
3. Wire the officer findings for the four host-body issues currently unfound (log growth, DB bloat, guard state, port registry drift).
4. Companion Form disclosure of degraded observation surface — the operator running Companion should see explicitly which surfaces are limited.

## Framing note

The observation plane is what makes the substrate legible to itself. Without it, the KEEL's proposals — *the substrate proposes, operators sign*, *the chain configures the cockpit*, *harmonize new capabilities with the flow of the system* — depend on perception the substrate does not have. With it, the substrate can finally observe, reason about, and act on its own condition through the same architecture it uses for everything else: signed receipts, chain-anchored ontology, delegation-scoped authority.

The officer-blindness we found in the current runtime is not a bug in the officers. It is the observation plane not yet existing. Building it closes the gap that made the substrate quietly incapable of noticing its own runaway log.
