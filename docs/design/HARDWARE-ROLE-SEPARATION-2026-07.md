# Hardware Role Separation: Sentinel and Regent — 2026-07

**Document type:** Tier 2 elaboration. Canonical statement of the two-role sovereign node topology, and the reference hardware that serves each role.

## Thesis

The sovereign node has two distinct roles that earlier corpus framing conflated: a **Sentinel role** (network-adjacent, watches traffic, coordinates with the router) and a **Regent role** (inference host, holds Companion state, runs adapters, does the cognitive work). Different hardware serves each role optimally. When separated onto their own physical devices they compose more strongly than they do when merged onto a single board.

Under the prior framing, a Raspberry Pi 5 8GB was implicitly named as *the* reference sovereign node — the single-board target for TPM-attested boot, chain-anchored governance, and local LLM inference. That framing forced one piece of constrained hardware to do three jobs — attest, observe, and infer — and the third of those (inference) is the one Pi 5 does least well. The pivot this doc canonicalises separates those jobs across two devices:

- **Pi 5 8GB** — Sentinel-role reference hardware. Isolated SoC, allowlist evaluation, flow-level destination monitoring, network-side attestation. **Placement is load-bearing** — either on the router or as the LAN's DNS server and gateway; adjacency alone observes nothing (see `SENTINEL-V1-MVP-2026-07.md` §2). The Pi 5's strengths — cheap sustained pattern matching, NEON-accelerated hashing and regex, low-power always-on operation — are exactly what the Sentinel role needs.
- **M4 Pro Mac Mini (64GB unified memory), designated APOLLO** — Regent-role reference hardware. LLM inference host, LoRA and X-LoRA adapter workload, in-process output observer, Secure Enclave attestation. The Mac Mini's strengths — Metal-accelerated inference, generous unified memory, comfortable multi-model residence — are exactly what the Regent role needs.

Both nodes hold their own Genesis root. Both are chain-attestable. Both are sovereign in their scope. The substrate treats them as distinct roles that compose, not as a single node distributed across two boards.

## The two roles, defined

### Sentinel role

The Sentinel is the network-boundary observer for the sovereign node. Its responsibilities are: name-resolution monitoring, device admission, flow-level destination monitoring (5-tuple, direction, byte and packet counters, taken from the kernel's conntrack event stream), allowlist evaluation, coordination with the router-level security stack (ASUS AiProtection or equivalent) for enforcement actions, and chain-anchored attestation of every anomaly it flags.

**Corrected 2026-08-12.** This paragraph previously said the Sentinel "sits adjacent to the router (typically over Ethernet, in mirror mode or on a VLAN-tagged tap)" and "sees all traffic to and from the Regent." Neither was true. No packet capture exists anywhere in the tree, and none is achievable on this hardware: gigabit Ethernet at small frames is on the order of 1.5 Mpps, userspace capture on a quad Cortex-A76 is not, and a Pi 5 has one NIC so it cannot sit inline at all. **The observation is flow-level metadata, never payload**, and the binding constraint is placement rather than throughput — the Sentinel observes only traffic that passes through the host it runs on. A Pi merely *adjacent* to the router observes nothing, because dnsmasq and the flow table both live on the router. Either the Sentinel runs on the router, or the Pi is made the LAN's DNS server and gateway. See `SENTINEL-V1-MVP-2026-07.md` §2 for the three topologies and what each can honestly attest; a Sentinel not in the path must emit no egress findings, because a missing finding would read as an absent egress.

The existing `tools/sentinel/zp_sentinel/` Python package (v0.3 as of March 2026) already implements the Sentinel role across four platform profiles: ASUS Merlin (runs inside router firmware), OpenWrt, Linux-systemd, and Docker. The pivot promotes the Linux-systemd profile — running on a dedicated Pi 5 adjacent to the router — to first-class reference status, alongside (not replacing) the Merlin-inside-router topology. The Sentinel is already a first-class mesh peer with Ed25519 identity, Blake3 hash-chained SQLite ledger, `AgentAnnounce` capability declaration, and 30-second heartbeats to Core. It is also already an officer role in the Rust codebase at `crates/zp-officers/src/sentinel.rs`. The pivot changes deployment topology and reference-hardware framing; it does not change the substrate primitives.

The Sentinel does not host the Regent's LLM inference. It does not need a GPU. It does not need more than a few hundred MB of RAM for its pattern rules, allowlist, and chain writer. A Pi 5 8GB is generously overprovisioned for the role, which is exactly what makes it a stable, long-uptime device that never runs hot on the workload it's meant to do.

### Regent role

The Regent is the cognitive substrate for the sovereign node. It hosts LLM inference (via llama.cpp with GGUF quantized models, or via MLX for Metal-accelerated Apple Silicon), holds the Companion-form persistent state, loads and hot-swaps LoRA adapters, runs the in-process output observer that watches inference at the IPC level, and signs its chain events via Secure Enclave (the Apple-Silicon equivalent of TPM 2.0 for attestation).

Reference hardware is the M4 Pro Mac Mini (64GB unified memory), designated APOLLO. This is not the Pi 5. The Pi 5's inference ceiling — Phi-3-mini or Qwen 2.5 3B at Q4_K_M, roughly 8 tokens per second, with tight RAM budgets that leave little room for adapter concurrency or long-context KV cache — is too constrained to serve as the primary Regent for meaningful workloads. The Mac Mini can run 7B–13B models at interactive speeds, host multiple adapters concurrently via S-LoRA-style batching, experiment with X-LoRA-style token-level blending (research-grade but hardware-capable), and support on-device shadow-evaluation of candidate adapters — none of which are viable on Pi 5.

The Regent hosts the in-process observer (see next § for taxonomy). This observer runs in a separate address space from the inference process, watches llama.cpp or MLX output at IPC level, and is the first line of defense against drift and policy violation. Its trip conditions are rule-based rather than ML-classifier-based, keeping its compute footprint negligible relative to inference.

## Observer taxonomy

The pivot creates three distinct observer classes, each with its own attack-surface visibility. They are complementary rather than redundant.

**Hardware coprocessor observer.** A dedicated MCU on the sovereign node's carrier board, watching physical state — power rails, thermals, RF emissions, tamper switches. Framed in full at `docs/design/HARDWARE-OBSERVER-2026-07.md`. This observer is a Tier 1+ subsystem present only on custom carrier boards; neither the Tier 0 Pi 5 nor the M4 Pro Mac Mini has this observer, and the pivot does not change its architectural role.

**In-process inference-output observer.** A rule-based watcher inside the Regent, running in its own address space, reading llama.cpp or MLX output via IPC (unix socket or shared ring buffer). Watches for banned-phrase matches, output-length blowups, high-entropy token sequences, refusal-cadence anomalies. Sleeps when no output is streaming. Compute budget under 5% of one core; no ML inference on-device. Any richer drift-detection classifier runs off-device on a signed schedule, returning signed profiles that inform future trip-condition thresholds. This observer is the first line of defense against drift and misuse; it sees model outputs before they get wrapped in TLS.

**Network sentinel observer.** The Pi 5 Sentinel described above, sitting adjacent to the router. Sees all network traffic to and from the Regent. Cannot be subverted by anything running on the Regent, because it lives on a physically separate SoC with its own TPM measurement, its own boot chain, and its own chain of TPM-signed events. Its visibility is limited to connection metadata (destinations, timing, sizes, protocol families) rather than TLS content — which is precisely the complementary surface to the in-process observer's content-level visibility. The two observers together see everything: content before encryption via the in-process observer, connection behavior after encryption via the network sentinel.

Defensive triggers gain confidence when observers agree. A trip condition raised by either observer alone is a signal; a trip condition raised by both is a stronger signal that warrants a chain-anchored defensive-swap ceremony without further deliberation.

## Composition with the officer cadre

Sentinel is already an officer role in the Rust substrate at `crates/zp-officers/src/sentinel.rs`. The pivot embodies that officer at a distinct hardware boundary — a physically separate SoC — rather than as a process on the Regent. This makes the officer's isolation guarantees hardware-level rather than process-level, which the substrate's constitutional discipline rewards.

The Cartographer role weaves the two nodes' chains into a composite substrate view. Genesis roots on Pi 5 and Mac Mini are distinct; their chains are byte-compatible (see next §) and cross-referenceable via shared event IDs when officers coordinate. The Cartographer is agnostic to which hardware holds which role — it maps the chains it is given.

Officer coordination between Sentinel and Regent flows via the existing mesh protocol: Ed25519 identity per node, `AgentAnnounce` at boot, 30-second heartbeats, WebSocket topology update. No new protocol primitives are needed. The Sentinel node registers with Core (running on the Regent or elsewhere) exactly as it does today under the v0.3 mesh design.

## Composition with substrate forms

Under the substrate-forms taxonomy — Sovereign, Appliance, Companion — the two nodes take distinct forms that reflect their operational postures.

The Pi 5 Sentinel is an **Appliance-form sovereign**: bounded task, no shifting behavior over time, no persistent relationship accumulation. It runs a stable pattern-matcher and allowlist enforcer. Its Regent field is nonexistent; its cognition is rule-based, not model-based.

The M4 Pro Mac Mini in Regent role is (typically) a **Companion-form sovereign**: persistent relationship with the operator, accumulates LoRA adapters over time as material trace of co-creation, holds long-context conversational state, allows adapter portfolio evolution via signed ceremonies. It can also be operated in Sovereign form (higher discipline, more restrictive delegation) or Appliance form (bounded to a specific task with no LoRA accumulation), depending on the operator's chosen posture.

Both nodes are chain-attestable in their own scope, and either can rally to or from the other depending on the coordination pattern. Neither is "the" canonical sovereign node; both are role-specialized sovereigns that compose.

## Composition with the tier ladder

The `docs/design/SOVEREIGN-HARDWARE-2026-07.md` tier ladder currently frames Pi 5 8GB as Tier 0 "Commodity Sovereign Form," implicitly serving as the reference sovereign against which higher tiers are compared. Under the pivot, the tier ladder framing survives, but Tier 0 is more precisely characterized as **Sentinel-role Tier 0** — the entry point for the network-boundary observer role, not the entry point for the entire sovereign node.

The M4 Pro Mac Mini needs a home in the tier ladder that it currently lacks. Recommended framing: introduce a **Regent-role tier axis** parallel to the existing Sovereign-form tier ladder, with the Mac Mini as the entry-point Regent-role hardware, and future Regent hardware (dedicated inference boxes with discrete GPUs, sovereign compute clusters, custom silicon) as higher tiers on that axis. The two axes intersect at the substrate: a sovereign node is a Sentinel-tier hardware plus a Regent-tier hardware, coordinated via chain-anchored discipline.

Detailed edits to `SOVEREIGN-HARDWARE-2026-07.md` to reflect this two-axis framing are companion work to this doc.

## Cross-tier chain invariance

Whatever the hardware differences between Sentinel and Regent, the chain each produces must be byte-compatible and replayable across the other's tools. Concretely: `LoRAAdapter` artifact schemas identical, ceremony schemas identical, adapter-load event format identical, defensive-swap event format identical, signature envelope identical (the underlying key material comes from TPM 2.0 on Pi 5 and from Secure Enclave on Mac Mini — the chain does not care which, as long as the signature verifies against the attested public key registered at boot).

This invariance is what makes the two-node design a coherent substrate rather than two parallel builds that happen to look similar. Any deviation breaks the substrate discipline; any addition to one node's chain vocabulary must be reflected in the other's before it becomes canonical.

## Deployment topologies

Three deployment topologies are now first-class, in decreasing order of role separation:

**Two-node reference (recommended for new deployments).** Pi 5 8GB as Sentinel, adjacent to the ASUS router over Ethernet. M4 Pro Mac Mini (APOLLO) as Regent. Router provides simple pattern matching (AiProtection); Pi 5 provides more sophisticated allowlist enforcement and destination monitoring; Mac Mini provides inference and the in-process observer. Three attestation surfaces (router, Pi 5 TPM, Mac Mini Secure Enclave) with three chain segments cross-referenced by shared event IDs.

**Sentinel-inside-router (existing Merlin deployments).** ASUS router running Merlin firmware, with `zp_sentinel` installed via Entware. Regent runs on a Mac Mini or equivalent. This is the topology of the March 2026 release — still valid, still supported, still documented. The pivot does not deprecate it; it introduces a preferred alternative for new nodes where hardware isolation between Sentinel and router is desired.

**Single-node collapsed (deprecated for new work).** Pi 5 running both Sentinel and Regent as processes on the same board. This was the implicit topology in the prior sovereign-node standup checklist. The pivot deprecates this for new deployments because process-level isolation is weaker than hardware-level isolation, and because Pi 5 inference performance is a poor fit for meaningful Regent workloads. Existing single-node deployments continue to work; the guidance for their next iteration is to split roles.

## Cross-references

- `docs/design/SOVEREIGN-HARDWARE-2026-07.md` — tier ladder; forthcoming edits add the Regent-role tier axis and Mac Mini reference hardware
- `docs/design/HARDWARE-OBSERVER-2026-07.md` — hardware coprocessor observer (Tier 1+ custom carrier boards); untouched by the pivot, cross-references this doc for the sibling observer classes
- `docs/design/LOCAL-MODEL-SELECTION-2026-07.md` — model shortlist per hardware role; forthcoming edit closes the topology question at line 20 in favor of "APOLLO as primary Regent, Pi 5 as Sentinel"
- `docs/design/TESTBED-AND-PHASING-2026-07.md` — phasing framework; forthcoming edit adds a Phase-4 gate exercising the Sentinel↔Regent split
- `docs/handoffs/pi5-sovereign-standup-checklist-2026-07-17.md` — forthcoming refactor: retain the ceremony spine (TPM, LUKS, measured boot, NixOS, Trezor Genesis), reframe as Sentinel-role stand-up rather than canonical sovereign
- `docs/handoffs/mac-mini-regent-standup-checklist-2026-07-27.md` — forthcoming companion handoff for Regent-role stand-up, referencing Secure Enclave in place of TPM 2.0
- `tools/sentinel/zp_sentinel/` — existing Sentinel implementation (v0.3, four platform profiles)
- `crates/zp-officers/src/sentinel.rs` — Sentinel officer in the Rust substrate

## Deferred

The following are deliberately not decided in this doc, to keep it focused on the role-separation canonical:

- Specific v1 MVP scope for the Sentinel Pi 5 deployment (allowlist rules, router integration mode, chain event vocabulary). Belongs in a Sentinel v1 MVP handoff.
- Specific LoRA and X-LoRA workflow on APOLLO (adapter artifact schema, training ceremony, hot-swap discipline). Belongs in a Regent adapter design doc.
- Router-specific integration bindings (ASUS SSH, AiProtection API, Merlin scripts). Belongs in a router integration handoff.
- Two-node Genesis coordination ceremony (how Pi 5 and Mac Mini establish cross-attestation on first boot). Belongs in a two-node genesis ceremony handoff.

These are all in scope for follow-on work but not this doc.

---

*Authored 2026-07-27. Canonical statement supersedes implicit prior framings that treated Pi 5 8GB as the single reference sovereign node.*
