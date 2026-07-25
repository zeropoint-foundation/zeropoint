# Substrate Form

**Tier 2 canonical elaboration.** Elaborates `KEEL-2026-07.md` §II.14 (Canonical substrate form) and Part XIV (Substrate Realization). Canonical claims live in KEEL; this doc provides the implementation-level detail and design rationale.

Draft — 2026-07-10 — internal audience only.

## Framing

The substrate's thesis is portable trust infrastructure for the operator, rooted in the operator's sovereignty. That thesis has a load-bearing assumption we did not surface until now: *where the trust root actually lives*.

On any current mainstream operating system — macOS, Windows, Chromebook, iPad — the trust root is the vendor. The vendor controls the boot chain, what code can run, the credential substrate, the certificate trust store, the observation surface the substrate is permitted, and the cadence at which any of those change. The operator holds authority the vendor permits, until the vendor stops permitting it. Every recent version of these operating systems has narrowed operator authority.

A substrate that runs *as an install* on such an OS is a tenant. It can defend operator authority within the vendor's permissions, but not against the vendor. The sovereignty thesis has a silent footnote: *personal sovereignty, above the trust boundary you neither own nor control*.

The pivot: the substrate's canonical form is not an install. It is a reproducibly-built OS with operator-controlled hardware trust chain. Everything else is a bridge or a compatibility mode, honestly labeled.

This document specifies the three Forms — Sovereign, Appliance, Companion — their technical shapes, their composition with the rest of the substrate, and the graduation path between them.

## Two axes: sovereignty and compute capacity

Substrate Form describes *where the trust chain is rooted* — firmware → boot chain → substrate. Sovereignty is a property of the trust chain, not of the hardware's compute capacity. Independent of Form, a sovereign device has some amount of local inference capacity, and that capacity may or may not be sufficient for the cognitive work its Regent needs to do.

These two axes are independent, and it is a first-order design error to conflate them.

- A Sovereign-Form Raspberry Pi 5 with 8GB RAM is *fully sovereign* — firmware, boot chain, and substrate all operator-controlled — even if its local inference capacity is insufficient to run a useful Regent.
- A Companion-Form Mac Studio with 128GB unified memory has *high compute capacity* — capable of running large local models — even though its trust root remains Apple's.

Sovereignty is decided by Form; cognitive capacity is sourced separately.

The substrate handles this via three *inference sources* the active Regent orchestrates:

- **Local**: on the device the Regent is presently active on. Fastest, cheapest per call, requires sufficient local compute.
- **Rallied**: on another authorized device in the sovereign's fleet, per Decision C. A cheap edge device holding Regent presence can rally to a workstation-class device in the same fleet for heavy inference. Rally protocol is Genesis-authenticated end-to-end; results return signed. Rally makes Sovereign Form accessible at hardware price points that could not run local inference alone.
- **Cloud**: on external provider under signed CloudMandate with hard token and cost caps. Currently our nearest-term path — GLM 5.2 via Abacus is a live example. Never at the cost of sovereignty (mandate is Genesis-signed, caps are structural), always with disclosed provider.

The practical floor for local inference is empirically unknown as of 2026-07. We do not yet know: what is the smallest device that can run a useful Regent locally at each model tier? What are the latency floors at various parameter counts and quantizations? Where does rally beat local for total operator experience even on capable hardware (thermal, battery, ambient noise)? These are empirical program work per Phase 5 of EXECUTION-AUTHORITY-MODEL-2026-07.

The immediate architectural consequence: no Form is gated by inference capacity. A sovereign can adopt any Form on any capable-enough hardware and source cognition wherever they can afford or reach. This democratizes sovereignty in a way vendor-tied stacks structurally cannot.

## The three Forms

### Sovereign Form (canonical)

The substrate is the operating system. NixOS-based, reproducibly built, measured boot with operator-enrolled keys, sealed full-disk encryption bound to boot state, Genesis held on hardware token. The operator boots into their own sovereignty from silicon up.

- **Trust chain reach**: firmware → boot ROM → bootloader → kernel → userland → substrate. Every stage measured, every measurement chain-anchored. Operator controls the signing keys used at every verifiable stage.
- **Observation surface**: full. The substrate IS the OS; every process, network socket, file, persistent daemon, credential surface, and application state is reachable.
- **Operator commitment**: dedicated hardware or dedicated VM. Existing daily-driver workflows either migrate here or stay on Companion Form and interoperate.
- **What is compromised**: nothing structural. Firmware-level attestation is still hardware-vendor mediated (Intel ME, AMD PSP, GPU firmware, TPM implementation). The trust boundary moves down but does not vanish.

### Appliance Form (bridge)

The same substrate stack as Sovereign Form, running on dedicated hardware alongside the operator's daily driver. The operator's laptop stays on whatever OS they use; the appliance sits on the local network and holds the sovereign compute. Genesis-signed handshake authenticates the daily driver as a delegated surface into the sovereign substrate.

- **Trust chain reach**: full within the appliance boundary. The appliance is Sovereign Form. The daily driver has whatever trust chain its vendor gives it.
- **Observation surface**: full within the appliance. On the daily driver, only what the client can observe within its OS's permissions — same as Companion Form, but the reasoning agent lives on the appliance where it has real authority.
- **Operator commitment**: one piece of hardware, network reachable, unattended runtime. No workflow migration required on the daily driver.
- **What is compromised**: the daily driver's local state is not sovereign. Chain-anchored work happens on the appliance; local drafts, browser tabs, and ephemeral state remain in the daily driver's vendor-permitted scope until synced.

### Companion Form (compatibility)

The substrate installs on the operator's existing OS. Runs within vendor permissions. This is the current shape.

- **Trust chain reach**: bounded at the operating system boundary. The vendor's boot chain, code-signing enforcement, credential substrate, and certificate trust store all sit above the substrate.
- **Observation surface**: whatever the vendor permits. On macOS this excludes system-wide process introspection past coarse `ps` output, TCC-gated file access, keychain contents by policy, and much else. Best-effort proprioception of the substrate's own footprint; blind to most of the host.
- **Operator commitment**: minimal. Install a package, run.
- **What is compromised**: the sovereignty root. The vendor holds the trust chain. Mandatory *Form Disclosure* (below) makes this explicit to the operator so no one is confused about what they have.

## Form Disclosure (invariant)

Every operator surface on Companion Form must display Form Disclosure prominently. Not buried in docs. Not hedged. Direct language:

> You are running Companion Form. Your operating system vendor controls the trust root of this device. The substrate defends your authority within the constraints your vendor permits, but cannot defend it against your vendor. To reach full sovereignty, graduate to Appliance or Sovereign Form.

Appliance Form disclosure is lighter but present:

> You are running Appliance Form. Sovereign compute runs on the appliance. Local state on this device remains in your vendor's permitted scope until synced to the appliance.

Sovereign Form disclosure is silence — the canonical form does not need to explain itself.

Form Disclosure is a Layer A invariant. Compatibility mode without honest disclosure is not a compatibility mode; it is a lie about what the substrate is.

## Sovereign Form — technical spec

### Base: NixOS

NixOS is chosen because it uniquely satisfies four load-bearing properties:

1. **Reproducible builds.** The entire OS state — kernel, packages, services, configurations — is declaratively specified in a Nix expression that builds bit-identically. Which means the OS state is a chain-anchorable artifact. A signed receipt can pin "the substrate runs on system hash X." Verification recomputes the hash from the expression.
2. **Atomic rollback.** Bad updates roll back cleanly. This matches the *store-and-forward is primary* principle at OS level: state is durable and reversible.
3. **Immutable base + overlay.** Layer A of the substrate corresponds naturally to NixOS's immutable read-only system generation. Layer B corresponds to the mutable overlay. Same architecture at OS level as at KEEL level.
4. **Configuration as code.** The whole OS state is a signable artifact. The `configuration.nix` expression can be chain-anchored; a subsequent `nixos-rebuild switch` from the same expression produces bit-identical state.

Alternatives considered: Guix (stricter free-software policy, smaller community), Alpine (smaller footprint, weaker reproducibility guarantees), Debian minimal (very stable, less reproducible), Fedora Silverblue (immutable but Red Hat governed). NixOS is the pragmatic sweet spot; Guix is the acceptable alternative if the free-software constraint hardens.

### Trust chain: measured boot with operator-enrolled keys

The full trust chain from firmware to substrate:

1. **Firmware / UEFI.** Operator sets a firmware password. Operator enrolls their own Secure Boot keys (Platform Key, Key Exchange Key, Signature Database) — either by clearing the vendor's default keys entirely, or by adding operator-controlled keys alongside. This lets the operator sign the bootloader; the vendor cannot.
2. **Bootloader.** `systemd-boot` with UKI (Unified Kernel Image) signed by the operator's Secure Boot key. Bootloader verifies its own signature via UEFI Secure Boot.
3. **Kernel + initramfs.** Bundled in the UKI, verified as one artifact. Kernel command line is part of the signed artifact — no runtime injection.
4. **Root filesystem.** LUKS2 full-disk encryption, decryption key sealed to TPM 2.0 with PCR policy covering PCRs 0, 2, 4, 7 (firmware, extended firmware, bootloader, Secure Boot state). If any earlier stage is tampered with, the disk does not decrypt.
5. **NixOS userland.** Boots from the verified root FS. System generation identifier and Nix expression hash written to the chain as a `boot:generation` receipt signed by the substrate's boot key.
6. **Substrate services.** Officer cadre, Cartographer, observation plane, Regent — all start from the verified userland, aware of their measured-boot lineage via the boot receipt.

### Hardware Genesis

The operator's Genesis lives on a hardware token — YubiKey 5, Nitrokey 3, or Trezor. Touch to sign. The token is the physical form of the singular sovereign root. Losing the token is losing sovereignty; recovery is via M-of-N quorum of pre-registered recovery tokens per Decision A and the future quorum-sovereignty design.

The substrate never holds the operator's raw Genesis material. Signature requests are dispatched to the token via WebAuthn / U2F / OpenPGP smartcard interface. Every operator action that requires sovereign authority — mandate issuance, delegation grant, artifact signing, Form graduation ceremonies — triggers a physical touch on the token.

### Reproducible artifact chain

Every deployed substrate runtime traces to a signed artifact. Concretely:

1. **Source pin.** A specific Nix flake commit hash. Signed by the substrate release key (itself Genesis-certified).
2. **Build product.** The `nixos-rebuild build` output. Bit-identical from the source pin, verifiable by anyone with the source.
3. **Boot receipt.** On boot, the running system emits `boot:generation` citing (source pin, build hash, PCR values). Chain-anchored.
4. **Configuration receipt.** Any operator configuration change emits `config:apply` with the diff and the resulting new expression hash. Chain-anchored.

This closes the loop: what is running is provable; how it got there is provable; who authorized each transition is provable. The KEEL's canonicalization principle now covers the OS itself.

## Appliance Form — technical spec

### Same substrate stack

Appliance Form is Sovereign Form deployed on dedicated hardware. Same NixOS base, same measured boot, same sealed FDE, same hardware Genesis. What differs is only how the operator consumes it.

### Handshake: daily driver ↔ appliance

The operator's daily driver runs a thin ZP client — one binary, minimal state, no independent authority. First-run pairs the client to the appliance via Genesis-signed pairing ceremony:

1. Operator triggers pairing on the appliance via local UI (touch on physical device, or web UI over authenticated LAN).
2. Appliance emits `pairing:offer` to the client, containing the appliance's public identity and a nonce.
3. Client presents to operator: "Pair with appliance ID X? Fingerprint Y." Operator confirms with Genesis touch.
4. Client emits `pairing:accepted` signed by operator Genesis. Appliance verifies signature, records the client as a delegated surface, emits `client:delegated`.
5. Ongoing: client authenticates each request via short-lived tokens derived from the pairing chain.

The client itself is stateless with respect to trust — every trust decision routes to the appliance. Local state on the daily driver is scratch; canonical state lives on the appliance.

### Reference hardware

Not a locked SKU. A spec any operator can meet:

- x86_64 or aarch64, minimum 4 cores, minimum 8GB RAM, minimum 128GB storage
- TPM 2.0 (dedicated chip or firmware TPM acceptable if operator trusts the firmware)
- Ethernet (Wi-Fi acceptable but discouraged for canonical appliance role)
- No vendor telemetry hardware modules where possible

Reference recommendations (as of drafting; will drift):

- **Framework mainboard** in a small enclosure — highest operator-repairability, best long-term sustainability, higher price. Local inference tier: mid to high depending on CPU choice.
- **Beelink / Minisforum mini-PC** (Intel N100 or Ryzen tier) — cheap, capable, wide availability. Local inference tier: low to mid; small models locally, rally for larger. Good candidate for many-appliance-per-household deployments.
- **Raspberry Pi 5 + external SSD** — cheapest (~$75), arm64 only, limited TPM story (external TPM module required for full measured boot; boot chain gap otherwise disclosed). Local inference tier: minimal — primarily a Regent-presence host that rallies or uses cloud mandate. Democratizes sovereignty at a price point most vendor-tied stacks cannot match.
- **Framework Laptop 13 without display** — if operator wants portability but full x86 capability. Local inference tier: mid.
- **Workstation-class** (Threadripper / Xeon / Apple Silicon Studio on future Asahi Linux tier) — local inference tier: high. Suitable as rally target for lighter appliances in the same fleet.

The substrate is defined by its Nix expression, not by a specific piece of hardware. Any host meeting the base spec is a valid Appliance. Local inference capacity varies; inference sourcing (local vs rallied vs cloud) is the axis Regent orchestrates over, independent of Form.

### Fleet compositions

Real operators often want multiple devices. A few compositions worth naming:

- **Single-appliance**: one Appliance-Form mini-PC handles everything. Operator's daily driver pairs to it. Simplest.
- **Presence + workstation**: cheap Pi holds Regent presence in a mobile / always-with-you role, rallies to a workstation-Appliance at home for heavy inference. Regent presence is portable; compute is delegated.
- **Home + travel**: home Appliance handles daily work; travel Appliance (small mini-PC or Framework laptop) takes presence when the operator leaves. Handoff per Part VII (Peer-Verification Contract).
- **Redundant sovereignty**: two Sovereign-Form devices, both able to hold presence, chain replicates. Loss of one device doesn't lose sovereignty. Consumer-tier disaster recovery.

Each composition uses the same substrate stack; the fleet-level shape is operator choice.

## Companion Form — technical spec

### What we have now

The install path we have been building. Rust binaries, macOS/Windows/Linux targets, `~/ZeroPoint/` runtime directory, `zp` CLI. Works within vendor permissions.

### Structural limitations (to be documented in Form Disclosure)

- **Trust root is the vendor.** Apple / Microsoft / Google holds the boot chain, code signing, certificate store.
- **Observation surface is vendor-permitted.** Cannot see the full compute surface (Compute Surface Awareness arc is degraded here).
- **Keychain access is API-mediated.** Vendor decides who reads what.
- **Update surface is vendor-controlled.** Vendor OS updates can change trust boundaries without operator consent.
- **No hardware Genesis on iOS/iPadOS/managed devices.** On desktop macOS, hardware Genesis via YubiKey works. On managed Windows, MDM may interfere.

Companion Form is not deprecated. It is honestly labeled. Its role is on-ramp and hybrid workflow — an operator using Companion Form for their daily driver plus Appliance Form for their sovereign compute is a real and valid graduation stage.

## Form graduation

Graduation moves the operator between Forms without losing their identity or their chain. The operator's Genesis is portable; their chain replicates across Forms per Peer-Verification Contract (KEEL Part VII).

### Companion → Appliance

1. Operator provisions appliance hardware, boots Sovereign Form image, completes first-boot ceremony (Genesis token registration, disk sealing).
2. Operator's daily driver Companion install pairs with the appliance per the handshake ceremony above.
3. Chain state replicates from Companion to Appliance via signed sync. Appliance becomes canonical; Companion becomes a delegated client.
4. Optional: Companion install continues running as a client, or is uninstalled — operator choice.

### Appliance → Sovereign

1. Operator repurposes existing hardware (or acquires new) for full Sovereign Form.
2. Reproducible artifact chain lets the operator's exact NixOS configuration migrate — same Nix expression, different hardware.
3. Chain state replicates from Appliance to Sovereign device.
4. Operator's daily driver becomes the Sovereign device. Appliance either retires or continues as second sovereign node for redundancy per Decision C (Regent-follows-the-operator, rally for compute).

### Companion → Sovereign (direct)

Legal but higher-friction. Operator commits to reformatting their daily driver hardware. Same shape as Appliance → Sovereign but without the intermediate appliance stage.

## Composition with other substrate pieces

### Officers

Each Form determines what the officers can see and act on.

- **Sovereign Form.** Officers query the ontology including full host-body coverage — Compute Surface Awareness fully wired. Forge notices audit.db bloat before it becomes 1.35GB. Sentinel notices auth-polling storms. Steward notices `.guard-paused` idle for months. Aegis notices trajectory drift in operator activity across the whole compute surface.
- **Appliance Form.** Officers see the appliance in full. Officers see the daily driver only within what the client reports (which is bounded by daily driver's OS permissions).
- **Companion Form.** Officers see only what vendor permissions expose. Compute Surface Awareness is degraded, honestly disclosed.

### Observation plane

The observation plane specified in `OBSERVATION-PLANE-2026-07.md` (companion doc) composes with Form as follows:

- **Sovereign Form.** All six observation surfaces (processes, network, filesystem posture, persistent surfaces, credentials, application state) are natively reachable. Delegation scopes are operator-facing choice.
- **Appliance Form.** Same six surfaces on the appliance. Daily driver client provides best-effort reporting within vendor permissions.
- **Companion Form.** Observation surfaces are vendor-permitted subsets. Delegation scopes are still meaningful, but the reachable set is smaller and disclosed.

The observation plane's Layer A primitives (kqueue, inotify, sysctl, procfs, eBPF, native security framework calls) are Form-appropriate — Sovereign / Appliance get Linux primitives; Companion gets whatever the host OS exposes.

### Empirical program

`EMPIRICAL-PROGRAM-2026-07.md` gets Form-scoped investigation entries added:

- Form graduation UX and correctness
- Chain replication across Forms under adversarial conditions
- Measured-boot receipt verifiability across firmware / TPM implementations
- Hardware Genesis loss and recovery (M-of-N quorum flow)
- Reproducible-build determinism across build hosts
- Observation surface reach per Form, empirically measured
- **Practical floor for local inference** — smallest device that can run a useful Regent at each model tier (1.7B, 7B, 13B, 27B, 70B at various quantizations); latency and thermal characteristics on each tier; where rally beats local even on capable hardware
- **Rally protocol under real network conditions** — latency, throughput, resilience to partition; fleet composition patterns (single-appliance vs presence-plus-workstation vs home-plus-travel vs redundant)
- **Cloud mandate economics** — cost per operator-day at each model tier under real usage patterns; the point at which local or rallied inference beats cloud on TCO for the sovereign

### Regent

Regent's cognitive context includes the current Form and the current inference sourcing strategy as first-class properties. Harmony decisions vary by both — for example, on Companion Form, Regent cannot spawn background evaluation sweeps that require kernel-level introspection; on Sovereign Form, she can. When local inference capacity is insufficient, Regent rallies or invokes CloudMandate rather than degrading her reasoning; the choice of source becomes part of her harmony calculus (latency budget, cost budget, thermal budget, privacy scope of the query).

Regent's tool set is Form-aware: some tools are gated to Sovereign or Appliance because their execution requires authority Companion cannot grant. Regent's inference behavior is capacity-aware: heavy queries route to rally targets or cloud when local is not sufficient, all under the same Genesis-signed authority.

Regent's persona is Form-invariant and capacity-invariant. Her *what* is the same everywhere; her *where* and *what she can reach* differs by Form; her *how she gets thinking done* differs by inference sourcing.

## Open positions

The following are deliberately unresolved and will close as the empirical program iterates.

- **Practical floor for local inference.** Unknown as of 2026-07. Empirical program will map this out per hardware tier and model tier. The floor is not fixed — quantization improvements, smaller-better model releases, and rally protocol maturity all move it over time. Design assumption: the floor is *low enough that a $75 Pi 5 is a viable Regent-presence host*, sourcing heavy inference via rally or cloud mandate. Confirm empirically.
- **Firmware attestation strategy.** Coreboot, Heads, or vendor UEFI with operator-enrolled keys. Coreboot gives deeper attestation but limited hardware support; Heads is more mature for supported ThinkPads; vendor UEFI is broadest but shallower. Likely: support all three, canonical form recommends Heads on supported hardware, coreboot on hardware where it works, vendor UEFI as fallback with reduced attestation reach.
- **GPU / accelerator inclusion.** Local inference on Sovereign Form wants GPU. NVIDIA firmware is proprietary; AMD is more open; Intel Arc is emerging. Impacts inference-cost story and Regent's local-vs-cloud decisions.
- **Wireless story.** Wi-Fi firmware is proprietary on almost all chipsets. Sovereign Form on wireless-only hardware has a firmware-trust gap. Options: canonical form recommends Ethernet where possible; acknowledge the wireless firmware gap in Form Disclosure at Sovereign level; investigate specific chipsets with open firmware.
- **Companion-Form deprecation timeline.** Do we retire Companion Form when Appliance Form reaches maturity, or keep it indefinitely as on-ramp? Recommend: keep indefinitely, treat it as on-ramp not target.
- **Chain replication under partition.** Peer-Verification Contract handles the general case, but Form graduation involves specific replication sequences (Companion → Appliance handoff, in particular) that need protocol specification.
- **Existing-app integration on Sovereign Form.** How does an operator use the equivalents of Photos, iMessage, Notes on Linux? Recommend: substrate does not solve this directly. Substrate is compute sovereignty; personal-data application choice is a separate question. Compose with operator's chosen Linux applications; provide chain-anchored bridges where useful (backup, provenance, cross-device sync).

## What composes from here

Immediate design work:

1. `OBSERVATION-PLANE-2026-07.md` — six observation surfaces, delegation scopes, composition with Forms (drafted next).
2. KEEL Part XV — this doc's declarations elevated to invariant status.
3. `HARDWARE-GENESIS-2026-07.md` — YubiKey / Nitrokey / Trezor selection, WebAuthn / OpenPGP interface, ceremony flow, recovery quorum.
4. `FORM-GRADUATION-2026-07.md` — ceremony protocol for each graduation path, chain replication details, rollback semantics.

Near-term implementation work:

1. Reference Nix flake for Sovereign Form — minimum viable NixOS configuration that boots the substrate on a spec-compliant host.
2. Measured boot integration — UKI signing, TPM PCR policy, sealed LUKS key.
3. Hardware Genesis dev-loop — YubiKey enrollment ceremony, signature dispatch, recovery ceremony.
4. Companion Form Disclosure — UI copy, prominence rules, presence in every operator surface.

Regent stand-up work continues in Companion Form for now — the substrate we have works, and iteration on Regent's cognition doesn't gate on graduating Forms. But everything Regent learns to do on Companion Form has a shadow future on Sovereign Form, where her authority scope is genuinely larger. Design Regent's tool interface with that in mind.

## Framing note

Substrate Form was a silent assumption in every prior architectural document. Naming it — and declaring canonical form to be OS-level with hardware trust chain — closes a gap that made the sovereignty thesis quietly inconsistent with what we were building. This is a KEEL amendment, not a distraction; the amendment restores coherence between what we claim and what we ship.

Public thesis framing (deferred per no-external-audience directive) will need parallel work when we return to public documentation. For now, this doc + the KEEL amendment are enough for us to reason from.
