# Observation Plane

**Tier 2 canonical elaboration.** Elaborates `KEEL-2026-07.md` §II (adds Layer A observation tier) and Part IV (adds host-body ontology objects). Canonical claims live in KEEL; this doc provides the implementation-level detail and design rationale. Supersedes the strategic reservation in the historical `ARCHITECTURE-2026-04.md` Part VIII.

Draft — 2026-07-10, amended 2026-07-24 (operator-facing surfaces added — see §Display topology, §Operator face signals, §Composition with EMBODIMENT-STATE-PROTOCOL, §Composition with presence-driven policy responders) — internal audience only. Composes with `SUBSTRATE-FORM-2026-07.md` — reachable observation surface varies by Substrate Form. Composes with `EMBODIMENT-STATE-PROTOCOL-2026-07.md` — operator-facing observations flow through cognition into Regent's embodiment envelope. Composes with `LENS-DISCIPLINE-2026-07.md` — lenses filter and interpret observation-plane emissions across their scoped attention surfaces.

## Framing

The officer-blindness question surfaced a structural gap: the officers observe the chain, but nothing writes host-body facts to the chain, so nothing to observe. A 399MB runaway log, a 1.35GB audit database that isn't checkpointing, a `.guard-paused` file two months stale, `tool-ports.json` empty despite tools running — none of these produced findings from any officer, because the substrate has no proprioception. It cannot feel its own body.

The observation plane closes this gap. It is the Layer A tier that gathers signals from the substrate's host environment — and, when the operator enables it, from the operator's own presence at the terminal — and emits signed observation receipts to the chain. It does not interpret, decide, or act. Officers query the ontology the Cartographer builds from those receipts; Regent perceives host-body state and (when delegated) operator-facing state through the same path. The observation plane is the sensor tier of the substrate — chain-anchored, delegation-scoped, Form-appropriate.

Three load-bearing properties frame everything below:

1. **Observation is universal; control is delegated.** The plane sees what its delegation scopes permit; acts on nothing. Any action taken in response is a downstream officer or operator decision, gated normally.
2. **Scope is chain-signed.** The plane cannot observe outside its baseline scope without an operator-signed delegation. Privacy is structural, not policy — it's a cryptographic property of the chain.
3. **Reach varies by Form.** On Sovereign Form the plane can observe the full host; on Companion Form only what the vendor permits. Form Disclosure covers the honest limitations.

## The eight observation surfaces

Every observable phenomenon the plane emits about maps to exactly one of eight surfaces. Six are host-body surfaces (proprioception). Two are operator-facing surfaces (the operator's own environment and, opt-in, the operator's face). Each surface has native sensor primitives (Layer A), an ontology object type (Layer B), a default sampling cadence, and a delegation class.

### Host-body surfaces

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

### Operator-facing surfaces

The two surfaces below observe the operator's environment, not the substrate's host. They are the sensory substrate for `EMBODIMENT-STATE-PROTOCOL-2026-07.md` — the Regent uses them to reason about where the operator is looking and how she should stage herself in response. Display topology is baseline (enumerating attached monitors is not sensitive); face signals are strictly opt-in, per-signal.

### Display topology

Every display attached to the operator's device, plus arrangement (relative positions), scale factor, resolution, primary flag, connection state.

- **Layer A primitives (Sovereign / Appliance)**: OS display enumeration APIs — Wayland / X11 (`xrandr`, `wlr-randr`, protocol-native), macOS `CGDirectDisplay` / `NSScreen`, Windows `EnumDisplayMonitors`.
- **Layer A primitives (Companion)**: same as Sovereign — display enumeration is not gated by TCC or vendor restrictions in practice.
- **Ontology object**: `Display` (id, resolution, position, scale, primary, connected), `DisplayTopology` (set of Displays + geometric arrangement). Materialized from `observation:display:*` receipts.
- **Cadence**: enumeration every 60s; event-driven on display connect/disconnect via OS notifications.
- **Delegation class**: `observe:displays:topology` — baseline. Enumerating attached displays does not observe operator data. Standard operator ceremony includes this at first boot.

Purpose: the embodiment plane resolves the Regent's semantic placement intent (`surface: operator_display, display_id: left, region: {0.72, 0.42}`) to concrete pixels against the operator's actual monitor configuration. Without display topology, the Regent cannot know which monitors exist, at what resolution, or in what arrangement — placement decisions degrade to a single-monitor fallback. See `EMBODIMENT-STATE-PROTOCOL-2026-07.md` §Staging across the operator's displays.

What this catches: an operator adding a new monitor mid-session (the Regent notices and can restage), a monitor being disconnected while the Regent was staged on it (she rehomes), scale-factor changes that affect her presence-size.

### Operator face signals

Derived signals from an operator-enabled face-tracking module — operator affect, attention direction, presence, turn-taking intent, display focus, gaze locus, proximity. **Derived signals only — never raw video, never landmark coordinates, never biometric identifiers.**

- **Layer A primitives**: face-tracking module running client-side on the operator's device — VTube Studio's tracker, a substrate-provided equivalent, or any tracker conforming to the derived-signal emission contract. The substrate does not process webcam frames itself; the tracker is a delegated component running on the operator's device with an operator-Genesis-derived signing key.
- **Ontology object**: `OperatorFaceObservation` — per-signal fields (`affect: {valence, arousal}`, `attention: {target, intensity}`, `presence: {present, engaged}`, `turn_intent: {speaking, yielding, listening, preparing_to_speak}`, `display_focus: {display_id, confidence}`, `gaze_locus: {display_id, region}`, `proximity: {distance_band}`) with timestamp and confidence. Materialized from `observation:operator:face:*` receipts.
- **Cadence**: streaming per tracker cycle; rate-limited to Layer B threshold (default: no more than one receipt per 500ms per derived signal, to avoid chain bloat and jitter noise).
- **Delegation class**: `observe:operator:face:{signal}` — **per-signal opt-in**. Distinct delegation classes:
  - `observe:operator:face:affect`
  - `observe:operator:face:attention`
  - `observe:operator:face:presence`
  - `observe:operator:face:turn_intent`
  - `observe:operator:face:display_focus`
  - `observe:operator:face:gaze_locus`
  - `observe:operator:face:proximity`

The operator enables signals à la carte — presence and turn_intent (useful for conversational rhythm) may be enabled without affect (personal enough to prefer withheld). Each signal is a separate delegation; revoking one does not revoke others.

The face-tracking module signs each observation with a subordinate key derived from the operator's Genesis under the signal-specific delegation. Revoking a delegation invalidates the corresponding key immediately; no orphan observations continue past the operator's next chain-visibility cycle.

**Tracker conformance requirements:**

Any face-tracking module the substrate accepts as an authorized observation source must:

1. **Emit derived signals only.** Never emit raw video, landmark coordinates, or biometric identifiers. The Layer B receipt schema rejects disallowed fields structurally.
2. **Sign observations with the operator-derived signal-specific key.** Unsigned or wrong-key observations are rejected structurally.
3. **Honor per-signal opt-in.** If a delegation is not present, the tracker must not emit that signal — even locally. The tracker holds signing keys only for currently-delegated signals; missing delegation ≡ missing key.
4. **Rate-limit per Layer B threshold specification.** Emission bursts exceeding thresholds are rejected as suspected malfunction.
5. **Announce identity at authorization.** Emit `observation:source:announced:face_tracking` receipt at delegation, carrying the tracker's own hash so the substrate knows *which* tracker is active.

What this catches: an unauthorized third-party tracker attempting to emit; a legitimate tracker attempting to emit a signal not delegated; over-frequent emission from a legitimate tracker; a compromised tracker signing with a rotated-out key.

**What operator-face signals *enable* beyond cognitive input** (see §Composition with presence-driven policy responders below):
- Screen dimming, muting, or locking on prolonged operator absence
- Wake-on-presence for display groups
- Auto-yield of the Regent's active speech when operator attention departs
- Cockpit rearrangement responsive to which display holds operator focus

These are downstream consumers of face observations — substrate policy responders that read presence and act on operator-signed policy without waiting for Regent's deliberative loop.

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
- Ontology object definitions (Process, Listener, Volume, PersistentSurface, CredentialRef, RunningApp)
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
- Display topology — count, resolution, arrangement of attached monitors (no operator content observed)

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
- `delegation:observe:operator:face:affect` — operator affect (valence, arousal) from a conformant face tracker
- `delegation:observe:operator:face:attention` — operator attention target and intensity
- `delegation:observe:operator:face:presence` — operator presence and engagement
- `delegation:observe:operator:face:turn_intent` — operator turn-taking intent
- `delegation:observe:operator:face:display_focus` — which monitor holds operator attention
- `delegation:observe:operator:face:gaze_locus` — operator gaze locus (region-resolution) within focused display
- `delegation:observe:operator:face:proximity` — coarse operator distance band from the display

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
- **Aegis (trajectory monitoring)** — cross-surface trajectory detection. A pattern of processes-plus-network-plus-persistent-surfaces changes over time reveals trajectories (e.g. onboarding a new development environment) or drift (e.g. gradual scope creep in some app's persistence footprint). With the operator-facing surfaces active, Aegis can also observe operator-attention trajectories — sustained withdrawal of engagement, gradual proximity drift — as signal, though translating those into findings is delicate and belongs to Cleo's narration rather than Sentinel-style enforcement.
- **Sentinel (security), extended** — on operator-facing surfaces, Sentinel watches for tracker anomalies: unauthorized tracker attempting to sign, legitimate tracker emitting outside its delegated signal set, emission bursts exceeding rate-limits, tracker binary hash changing without an authorization ceremony.

**The officer-blindness examples from the current substrate diagnosis, now findable:**

- 399MB log growth → Forge finding on `TrackedFile:zp-serve.log` growth-rate exceeding threshold
- 1.35GB audit.db with 1.13GB WAL → Forge finding on `Volume:audit_db_volume` growth + `TrackedFile:audit.db-wal` size ratio anomaly
- `.guard-paused` idle 2.5 months → Steward finding on `Process:guard` absence, cross-referenced against chain absence of `guard:resumed` receipt
- 401-polling storm → Sentinel finding on `Connection` pattern (persistent client hitting eight endpoints per second, all unauthenticated)
- Empty `tool-ports.json` despite a governed tool running → Forge finding on `PersistentSurface:{tool}` present, `Process:{tool}` present, but `tool-ports.json` empty — structural inconsistency

All emerge from the same architecture: observation receipts populate the ontology, officers query the ontology, findings emit as chain receipts, the chain teaches everyone downstream.

## Composition with the Cartographer

The Cartographer materializes host-body ontology from observation receipts, same as it materializes governance ontology from governance receipts. Same infrastructure, additional object types.

New ontology objects: `Process`, `Listener`, `Connection`, `DnsQuery`, `Volume`, `Directory`, `TrackedFile`, `PersistentSurface`, `CredentialRef`, `RunningApp`, `Display`, `DisplayTopology`, `OperatorFaceObservation`.

New relationships to existing ontology:

- `Process` observed → linked to `Trajectory` if operator activity correlates
- `PersistentSurface` observed → linked to `Artifact` if provisioned by a chain-anchored artifact
- `CredentialRef` observed → linked to `Delegation` if the credential authorizes some capability
- Any observation drift → potential `Friction` if pattern recurs

Cartographer state is local, rebuildable, disposable per KEEL §II.7. Deleting host-body ontology entries and rebuilding from chain receipts must produce identical output — same architecture as governance ontology.

## Composition with EMBODIMENT-STATE-PROTOCOL

The two operator-facing surfaces are the sensory substrate for the operator-informed embodiment behavior described in `EMBODIMENT-STATE-PROTOCOL-2026-07.md`. The composition is clean and one-directional: observations flow into cognition; cognition produces embodiment envelopes; envelopes reference (but do not directly consume) the observations that shaped them.

### Composition path

1. Tracker emits derived-signal observations per its authorized delegations; display topology emitter emits per its baseline delegation. Both flow through Layer A signing and land on the chain as `observation:operator:face:*` and `observation:display:*` receipts.
2. Cartographer materializes them into `OperatorFaceObservation` and `DisplayTopology` ontology objects.
3. Cognitive input plane's Class 7 substrate state snapshot (per `COGNITIVE-INPUT-PLANE-2026-07.md`) surfaces recent operator observations and current display topology into Regent's cycle input.
4. Regent's cognition reasons over them alongside conversation semantics — "the operator is looking at the right display; I'll appear at ambient depth on the left so I don't cover their work" — and populates the embodiment envelope's `attention`, `placement`, and other fields accordingly.
5. The embodiment plane signs and emits the envelope; the behavior controller resolves semantic placement against the display topology; the renderer draws.

### Per-signal opt-in ceremony ↔ delegation grant

What `EMBODIMENT-STATE-PROTOCOL-2026-07.md` calls the "operator-enablement ceremony" for face tracking IS an observation-plane delegation grant. The two docs describe the same primitive from opposite sides:

- **Operator invokes** `zp observation face-tracking enable --signals attention,presence,turn_intent` (or the cockpit equivalent).
- **Substrate constructs** a compound delegation record listing the requested signals, scope (session id or persistent), expiry, operator signature.
- **Operator signs** with Genesis-derived key.
- **Substrate emits** `delegation:observe:operator:face:{signal}` receipts (one per authorized signal) plus the tracker's `observation:source:announced:face_tracking` receipt naming and hashing the tracker binary that will emit.
- **Tracker begins** emitting authorized signals. Non-authorized signals: the tracker literally lacks the signing key.

Disablement is symmetric: `zp observation face-tracking disable --signals affect` emits `delegation:observe:operator:face:affect:revoked`; the affect-signal key is invalidated; the tracker stops emitting that signal on its next cycle.

### Placement composition

The Regent's envelope carries a `placement` field (semantic staging intent). The behavior controller resolves it to concrete pixels against the current `DisplayTopology` ontology object. When face-tracking display-focus is enabled, cognition's placement decisions compose with the operator's current attention target — the Regent chooses whether to appear on the operator's focused display (assertive), the peripheral display (deferential), or ambient (background presence).

Absent face tracking, placement resolves against display topology only, using policy defaults for display selection (typically the operator's declared primary monitor).

### Scope disclosure at the embodiment surface

When face-tracking observations are active, the enablement receipts are visible in Regent's chain-anchored input. Cognition therefore *knows it is being informed by operator observation* and may express appropriate acknowledgment — a subtle shift in her mode, an explicit "I notice you're focused elsewhere," or per operator preference nothing at all. The substrate does not hide the fact of observation from either the observer or the observed.

## Composition with presence-driven policy responders

The operator-face-signals surface enables a class of substrate consumers that are **not** Regent-cognition-mediated: fast reactive policy responders that read presence signals and apply operator-signed policy directly. These are the "screen mute if the operator has been absent for 30 seconds" pattern generalized.

### Why the distinction matters

Regent's cognitive cycle is deliberative — she reasons over her cognitive input plane, composes an embodiment envelope, and emits a response. That loop takes seconds and involves inference. It is the right latency profile for conversational and interpretive work; it is the wrong latency profile for privacy responses like *"the operator just walked away — dim the screens before someone else can read what's on them."*

Presence-driven policy responders sit between the observation plane and substrate action, with these properties:

- **Fast.** Sub-second response to observation-plane presence transitions. No inference in the loop.
- **Policy-declared, not deliberated.** The operator has signed a policy declaring "on presence=absent for 30s → dim non-primary displays; for 5min → lock." The responder applies the policy mechanically; it does not reason about whether to apply it.
- **Chain-anchored on both ends.** The policy is a signed record (operator-Genesis-derived key); the response emits its own action receipts (`policy:response:screen_mute:applied`, etc.) so the chain records what happened, why, and against which signed policy.
- **Delegation-gated.** Just as observation-plane sampling requires delegation, policy responders require delegation to *act* on the screens/audio/OS surfaces they affect. Same gate primitive; different scope.
- **Operator-declared bounds.** Grace periods, exempt scenarios ("do not lock during presentations"), reversibility windows all live in the signed policy.

### Composition path (concrete case: screen mute on absence)

1. Operator signs `delegation:observe:operator:face:presence` (per §Operator face signals) and separately signs `delegation:policy:respond:screen:{dim,mute,lock}` naming permitted surfaces (which displays, which audio outputs).
2. Operator signs a policy record: `policy:presence_responder:v1` — declares thresholds (e.g., 30s absence → dim, 5min → lock), exempt scenarios, grace periods.
3. Face tracker emits `observation:operator:face:presence: {present: false}` at time T.
4. Presence-responder subsystem observes the receipt (via chain subscription), starts an absence timer.
5. At T+30s, if no `presence: true` observation has landed, responder applies dim policy, emits `policy:response:screen_mute:applied` receipt naming the policy hash, the observation that triggered it, and the surfaces affected.
6. On next `presence: true` observation, responder restores prior state and emits `policy:response:screen_mute:restored`.

### Boundary discipline

- **Responders do not extend the observation plane.** They are consumers of it. The observation plane emits; responders read.
- **Responders are their own delegation-gated tier.** Actions the responder can take (dim, mute, lock, restore) are separate delegation classes from the observation classes that feed them.
- **Regent may observe responder actions but does not mediate them.** Responder receipts land on chain and are visible in the cognitive input plane's substrate state snapshot; Regent perceives that the screens were locked and by which policy, but the responder ran without her cycle. She can amend the policy through operator-mediated ceremony, but she does not veto individual responses in flight.
- **Cleo narrates.** Responder actions are governance-relevant events. Cleo surfaces "your screens were locked at 14:32 per policy X; you resumed at 14:47" as chain-anchored narration.

### Why this isn't its own elaboration yet

Presence-driven screen mute is the first concrete case of an observation-plane consumer that responds to observations autonomously via signed policy. When a second concrete case emerges (e.g., idle-process suspension responding to process-observation quiescence; network-anomaly quiet-hours response), the pattern probably deserves its own Tier-2 elaboration (`POLICY-RESPONDER-DISCIPLINE-2026-07.md` or similar). Until then, this section is the substrate's acknowledgment that the composition exists and preserves its shape.

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
- **Not a webcam frame processor.** The substrate never sees raw webcam video. Face signals are derived by a tracker running on the operator's device and emitted as typed observations only. Any receipt carrying frame data or landmark coordinates is rejected structurally at the Layer B schema level.
- **Not a face-tracking puppet channel for the Regent's expression.** Operator face signals inform Regent's cognition; they do not drive her facial parameters. Puppetry would collapse the cognition-authors-expression invariant established in EMBODIMENT-STATE-PROTOCOL-2026-07.md.

## Open positions

- **Cadence tuning per surface.** Defaults above are estimates. The empirical program will map load impact and information gain per cadence per Form.
- **Aggregation vs raw receipts.** A busy host has many processes — 200+ on a typical Mac. Should each process observation be its own receipt, or one aggregated `observation:processes:snapshot` receipt per sampling cycle? Trade-off: chain volume vs officer query granularity. Recommendation: aggregate snapshots for enumeration, individual receipts for events (exec, exit, socket bind, socket close). Empirically validate.
- **eBPF vs polling on Sovereign Form.** eBPF is beautiful but limits which kernels the substrate runs on. Polling is universal but heavier. Recommendation: eBPF where kernel supports; polling fallback with declared observation-fidelity degradation.
- **Cross-appliance observation.** A sovereign with multiple appliances — should each observation plane emit locally and rely on chain sync, or should there be a designated "primary observation source" per surface? Related to fleet composition per SUBSTRATE-FORM. Recommendation: emit locally, chain sync propagates, no primary designation needed if chain sync semantics are sound.
- **What triggers a delegation review.** Automatically prompting the operator to review long-lived observation delegations (e.g. "you granted `observe:network:host` 90 days ago; still want it?") is good hygiene but easy to make annoying. Cleo probably owns the narration; cadence and threshold TBD.
- **Retention policy.** Observation receipts add up fast. The chain grows. Epoch-seal compaction (KEEL §II.2) handles the bulk case, but per-class retention (keep enumeration snapshots for 7 days, event receipts for 90 days) is worth designing. Related to audit.db bloat problem the current substrate is exhibiting.
- **First-boot ceremony for observation delegations.** How does an operator granting fresh delegations at first boot know what to grant? Sensible defaults (e.g. `observe:processes:host` and `observe:filesystem:home` are usually wanted) with visible dashboards showing what each delegation surfaces. Design work.
- **Per-signal face-tracking UX.** Seven per-signal delegations is granular; the UX must let the operator toggle them without ceremony fatigue. Bundled presets (e.g. "conversational rhythm" = attention + presence + turn_intent; "full staging" adds display_focus + gaze_locus + proximity; "affect" is separate) with an "explain what each unlocks for the Regent" surface. Design work.
- **Tracker conformance certification.** Which trackers qualify as authorized observation sources? The substrate could ship a first-party tracker plus accept community trackers that pass a conformance suite (schema compliance, rate-limit behavior, no landmark/frame emission). Certification receipt shape TBD.
- **Cross-device face tracking.** If the operator uses ZP across desktop and mobile, face tracking may run on either or both. Which observation stream is authoritative when both are emitting? Probably per-session single-source with explicit handoff receipts. Design work.
- **Presence-responder discipline as its own elaboration.** When a second concrete presence-driven policy responder emerges beyond screen mute (per §Composition with presence-driven policy responders), the pattern should probably get its own Tier-2 elaboration codifying the general shape (observation subscription → policy record → action delegation → action receipt). Filed until a second case exists.
- **Face-observation timestamp jitter as peer-verification determinism source.** Face-signal receipts land at streaming cadence with per-signal rate limits — two peers running the same tracker cycle may observe near-but-not-identical timestamps due to local clock skew. Observer-windows Phase 4 pre-registration should acknowledge this as a new nondeterminism-source class to trace if peer hashes diverge on face-derived summaries.

## What composes from here

Immediate design work:

1. **Eight observation-class schemas** (Layer B canonical records). One per surface — six host-body plus two operator-facing (display topology, operator face signals). Each includes receipt shape, ontology object shape, drift thresholds. Operator-facing schemas additionally include the tracker-conformance rules and per-signal signing-key derivation.
2. **Observation-plane runtime scaffold** (Layer A). Task runners, primitive dispatchers, delegation-scope enforcement, signing key derivation, chain-append pipeline.
3. **Minimum-viable proprioception subset** — before full plane lands, ship processes + filesystem posture + audit.db size + log size on a 60s cadence. This alone unlocks Forge findings on the current substrate hygiene issues (the very ones that surfaced this whole architecture).
4. **Observation delegation UI copy**. Not just chain receipts — the operator needs a legible surface explaining what each scope grants and why. Related to *the chain configures the cockpit* heuristic.
5. **Empirical program entries** — observation-plane load impact per Form, delegation-scope UX, host-body ontology stability under drift, keychain-metadata observation privacy verification.

Near-term implementation:

1. Add proprioception subset to Regent stand-up sequence, before first inference call. Regent should perceive her own runtime cost from her first cycle.
2. Downgrade current INFO logs that would be replaced by observation receipts (KEEL Layer A cleanup).
3. Wire the officer findings for the four host-body issues currently unfound (log growth, DB bloat, guard state, port registry drift).
4. Companion Form disclosure of degraded observation surface — the operator running Companion should see explicitly which surfaces are limited.
5. Face-tracking delegation-grant ceremony wired end-to-end — CLI + cockpit, one signal at a time or bundled preset, revocation likewise.
6. First-party face-tracking module (or VTube Studio adapter that satisfies conformance) as reference implementation. Empirical verification that no landmark/frame data leaks past the tracker boundary.
7. Display-topology emitter — baseline, no delegation ceremony required, live from first boot on any Form that supports display enumeration.

## Framing note

The observation plane is what makes the substrate legible to itself. Without it, the KEEL's proposals — *the substrate proposes, operators sign*, *the chain configures the cockpit*, *harmonize new capabilities with the flow of the system* — depend on perception the substrate does not have. With it, the substrate can finally observe, reason about, and act on its own condition through the same architecture it uses for everything else: signed receipts, chain-anchored ontology, delegation-scoped authority.

The officer-blindness we found in the current runtime is not a bug in the officers. It is the observation plane not yet existing. Building it closes the gap that made the substrate quietly incapable of noticing its own runaway log.
