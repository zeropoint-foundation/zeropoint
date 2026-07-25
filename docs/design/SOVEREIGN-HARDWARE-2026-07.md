# Sovereign Hardware

**Tier 2 canonical elaboration.** Elaborates `KEEL-2026-07.md` §II.14 (canonical substrate form) and Part XIV (Substrate Realization) at the hardware-design layer. Where `SUBSTRATE-FORM-2026-07.md` declares the three Forms and their trust-chain reach, this doc specifies the physical hardware architecture that realizes Sovereign Form on operator-controlled boards. Canonical claims live in KEEL.

Draft — 2026-07-10 — internal audience only. Composes with `SUBSTRATE-FORM-2026-07.md` (Form definitions), `OBSERVATION-PLANE-2026-07.md` (adds physical observation layer via hardware self-observer), `HARDWARE-OBSERVER-2026-07.md` (companion — subsystem detail), `QUARANTINE-PLANE-2026-07.md` (firmware and boot artifacts are quarantine-relevant), `CIRCUIT-BREAKER-2026-07.md` (hardware anomalies can trigger circuit breaker escalation).

## Framing

The substrate's canonical Form is Sovereign — a reproducibly-built OS with operator-controlled hardware trust chain. Commodity Sovereign Form (Raspberry Pi 5 with LetsTrust TPM) works today at $200 all-in and validates the thesis. But commodity hardware carries residual vendor-controlled surfaces (Broadcom boot ROM, closed WiFi firmware, TPM firmware trust) that the operator cannot inspect or replace.

The sovereign hardware arc is the substrate's answer to *what deeper hardware sovereignty looks like when the operator is willing to invest*. It's not "necessary for Sovereign Form" — Pi 5 is Sovereign Form. It's "how far can we extend operator control of the physical stack." Three graduation tiers, each with substantive trust-chain improvements, each achievable by ordinary independent development.

The load-bearing architectural claim: **PCB design and manufacturing are NOT gatekept.** PCBway, JLCPCB, Seeed Studio, OSHPark — the fab industry is a commodity service. Anyone can upload Gerbers and receive PCBs in 3-7 days. The gate is at specific components (modern high-performance SoCs from vendors requiring NDA + volume) and advanced foundry nodes (billion-dollar partnerships). Everything else — SoMs, discrete TPMs, secure elements, hardware kill switches, tamper detection, custom board layout — is buildable today by small independent teams.

This doc specifies:
1. The hardware tiers and what each achieves
2. Canonical board architecture principles that apply across tiers
3. Hardware self-observer as first-class subsystem in the canonical design
4. Firmware discipline (measured boot with operator-controlled keys)
5. Trust chain reach at each tier, honestly disclosed
6. Bill of materials and realistic cost expectations
7. Reproducibility discipline
8. Form Disclosure per hardware tier
9. Attack model and residual limits

## Hardware tiers

Four graduated tiers of hardware sovereignty. Each tier is real Sovereign Form; each extends operator control incrementally.

### Tier 0 — Commodity Sovereign Form (Pi 5 + LetsTrust TPM)

The entry point. Raspberry Pi 5 (8GB), Argon ONE V3 M.2 NVMe case, Kingston NV2 250GB SSD, official 27W PSU, LetsTrust TPM 2.0 module. Total: ~$200.

- **Realized**: reproducibly-built OS (NixOS), measured boot with TPM PCR values, sealed FDE, chain-anchored `boot:generation` receipts, all Sovereign Form userland capabilities per SUBSTRATE-FORM-2026-07.md.
- **Residual vendor surface**: Broadcom SoC boot ROM (closed), Broadcom WiFi firmware (closed), Cypress Bluetooth firmware (closed), Infineon TPM firmware (closed but well-audited, standardized).
- **Form Disclosure**: "Sovereign Form userland with Broadcom-controlled SoC firmware and Infineon-implemented TPM."

Available today. Democratizes sovereignty at accessible price point. Sufficient for substrate development, for smaller sovereigns, and as the reference against which higher tiers are compared.

### Tier 1 — Custom carrier board around Pi CM5

The first graduation. Carrier PCB designed and manufactured by operator (or by community). Uses Raspberry Pi Compute Module 5 (Pi 5 in SoM form factor with edge connectors instead of on-board peripherals). Custom PCB provides the peripherals and defines the operator's specific hardware capabilities.

- **What custom carrier gets us**:
  - **Hardware kill switches for every radio and sensor** — physical toggles wired into signals the substrate can observe. Kill switch reports must match observed radio state.
  - **Discrete TPM soldered on** — Infineon SLB9670 on the board, not a plug-in module. No accidental removal, no plug-connector risk.
  - **Secure element for operator Genesis** — dedicated slot for hardware token (YubiKey/Nitrokey via USB-C, or ATECC608 soldered on).
  - **Tamper-detect switches** — case-open, board-flex sensors wired to TPM for PCR extension. Physical intrusion breaks disk-decryption seal.
  - **Hardware self-observer coprocessor** — RP2040 or STM32F4-class MCU on the board with its own crystal and power rail. Observes physical state independently of the main SoC. Detail in HARDWARE-OBSERVER-2026-07.md.
  - **PCIe M.2 NVMe slot** — direct on-board, no USB adapter, faster and more reliable.
  - **All schematics published** as part of KEEL Tier 2 canonical spec.
- **Residual vendor surface**: Broadcom SoC firmware (still closed — CM5 is same silicon as Pi 5), but the board is yours. What's on the board is operator choice.
- **Form Disclosure**: "Sovereign Form userland with Broadcom-controlled SoC firmware, operator-designed and operator-verifiable carrier board with hardware self-observer."
- **BOM (~$300-500 assembled)**: Pi CM5 (~$80) + custom PCB (~$50) + discrete TPM (~$5) + observer MCU + sensors (~$15-25) + M.2 SSD (~$30) + PSU (~$15) + case/enclosure (~$50) + kill switches, tamper switches, connectors (~$25) + secure element ATECC608 or slot for external HW token (~$5-25).
- **Design cost**: 2-6 weeks for someone with mixed-signal PCB experience; 2-3 spins typical before ready to ship.

This tier proves the "operator-designed hardware is buildable" thesis. It closes the "board is yours" gap; SoC firmware remains vendor-controlled.

### Tier 2 — Custom carrier board around RISC-V SoM

The sovereignty-story shift. Same custom carrier discipline as Tier 1, but around a RISC-V SoM (StarFive VisionFive derivative, Milk-V Pioneer SoM, or Radxa RISC-V module).

- **What RISC-V gets us**:
  - **Open ISA** — no proprietary microcode discipline like Intel/AMD; instruction set is fully documented
  - **Increasingly open SoC firmware** — RISC-V boot ROMs in newer chips are documented; some are open-source
  - **No Intel ME / AMD PSP equivalent** — RISC-V SoCs don't have vendor management engines with the same runtime capability
  - **Software ecosystem maturing** — NixOS-RISCV, Debian-riscv64, Ubuntu-riscv64 all real and usable
- **Residual**: still some closed firmware components (memory controller training firmware, PMIC firmware), but the boundary has moved substantially inward.
- **Trade-off**: performance lags Intel/AMD/ARM by 3-5x at similar power envelope. For substrate work (chain integrity, officers, Regent presence, rally target) that's fine. For heavy local inference, rally to a higher-capacity node.
- **Form Disclosure**: "Sovereign Form userland on RISC-V ISA with operator-designed carrier board, hardware self-observer, and open-ISA/mostly-open-firmware SoC."
- **BOM (~$400-700 assembled)**: RISC-V SoM (~$100-200) + custom PCB (~$50) + rest similar to Tier 1.

This tier is where the sovereignty story genuinely improves at the SoC level. Software ecosystem is the current constraint; hardware is available.

### Tier 3 — Custom SoC on open PDK

The full sovereignty story. Design and tape out a custom SoC on an open Process Design Kit (Google/eFabless OpenMPW at SkyWater 130nm, or emerging efforts at 90nm and 65nm).

- **What custom silicon gets us**:
  - **Operator-designed silicon** — the SoC itself is operator-authored (or community-authored, or foundation-shipped through canonicalization ceremony)
  - **Full reproducibility** — Verilog/nMigen source, synthesized to GDS, taped out; anyone can verify the silicon matches the design
  - **No closed boot ROM** — boot code is operator-written and inspectable
  - **Fully open trust chain** — every component from silicon up is operator-controlled
- **Trade-offs**:
  - **Not a competitive CPU** — 130nm can't run at GHz speeds; workloads must fit slower silicon
  - **Long timeline** — 12+ months from design to first working silicon
  - **Small production runs** — MPW shuttles produce 10-100 chips per run; not thousand-piece quantities
- **Realistic scope**: probably not a full application processor. More likely a **security coprocessor** — operator-designed silicon for Genesis root operations, boot attestation, TPM-equivalent functions, hardware self-observer. Combined with a Tier 1 or Tier 2 carrier board, this closes the last major trust-chain gap for the security-critical operations while keeping the main SoC as a commodity (or RISC-V) part.
- **Form Disclosure**: "Sovereign Form with operator-designed security coprocessor and operator-verifiable primary SoC (commodity or RISC-V)."
- **Cost**: Google MPW is free for open designs; commercial multi-project wafers are $10k-100k depending on node.

This tier is aspirational for most operators today. Worth spec'ing so the architecture is prepared when it becomes accessible.

## Canonical board architecture

Design principles applying to all custom-board tiers (Tier 1+).

### Principle 1 — Hardware kill switches for every radio and sensor

Every radio (WiFi, Bluetooth, cellular if present) has a physical toggle wired into a hardware line the substrate can observe. Kill switch positions are observed by the hardware self-observer independently of the main SoC.

Signals: kill switch state → observer MCU GPIO → chain-anchored observation receipt. Substrate emits `hw:radio:wifi:disabled` receipt when observer confirms both switch position AND absent RF emission (via RF detector frontend). If switch says "off" but RF detector says "active," observer emits `hw:radio:wifi:integrity_violated` — the switch is compromised or the radio firmware is disobeying.

Same principle for camera, microphone (if present), tamper-detect, etc.

### Principle 2 — Discrete TPM soldered on

Not a plug-in module (plug-in connectors are physical risk — accidental removal, tampering). TPM chip soldered to board, connected via SPI to main SoC and observer MCU (separate SPI channels — observer verifies TPM state independently).

Recommended: Infineon SLB9670 (well-audited, open documentation, standardized).

### Principle 3 — Operator Genesis via hardware token

Two options, operator picks:
- **External hardware token via USB-C** — YubiKey 5C, Nitrokey 3C, Trezor Model T. Standard interface, works across all boards. Recommended default.
- **On-board secure element** — ATECC608 or equivalent. Tighter integration, harder to lose, harder to replace. Requires operator delegation to reset.

Either way, Genesis material never leaves the token/element. Substrate never holds raw Genesis. Every ceremony requiring Genesis signature triggers physical interaction (touch on token, or defined ceremony on secure element).

### Principle 4 — Tamper detection with TPM integration

Case-open switch and board-flex sensor wired to observer MCU. Observer signals TPM to extend a specific PCR on tamper event. PCR extension breaks sealed FDE (per KEEL §XIV.4 measured boot chain). Physical intrusion → disk stops decrypting until operator investigates.

Chain-anchored `hw:tamper:detected` receipt emitted by observer. Operator sees tamper event immediately; substrate refuses to boot into full operational state until operator confirms and re-seals.

### Principle 5 — Hardware self-observer as first-class subsystem

Dedicated MCU on the board with its own crystal, power rail, signed firmware, and Genesis-derived signing key. Observes physical state (power rails via INA260, thermals via TMP117, RF via peak detect, kill switch positions, tamper switches, boot timing) and emits chain-anchored `observation:hardware:*` receipts.

Observer cannot control the main SoC — it observes and reports only. Inverts the vendor-coprocessor model (Intel ME watches for Intel; this observer watches for operator).

Full subsystem detail in HARDWARE-OBSERVER-2026-07.md (companion doc).

### Principle 6 — Every port and connector physically discoverable

USB, Ethernet, HDMI, GPIO headers, SD card slot — every physical interface documented and enumerable. Substrate observes what's plugged into what. Unauthorized plug event → observer receipt.

### Principle 7 — Boot mode selector switch

Physical switch selecting between operational-canonical boot, recovery-mode boot, and diagnostic boot. Boot mode affects what firmware runs and what receipts get emitted. Recovery mode allows re-flashing of firmware from operator-authored source without needing to boot into potentially-compromised operational firmware.

### Principle 8 — Published schematics as canonical spec

Every custom board's schematic is chain-anchored as canonical spec. Layer B receipt of type `hw:board:schematic:<version>` points at the KiCad or similar source. Operator can verify the physical board matches the schematic; community can review and audit the design.

Reproducibility discipline: BOM is content-addressed; every component is specified by manufacturer part number; assembly instructions are chain-anchored.

## Firmware discipline

Every custom board runs operator-controlled firmware where possible.

### Bootloader

Operator-signed UKI (Unified Kernel Image) bundling kernel, initramfs, and command line. Signed by operator's Secure Boot key. Bootloader verifies UKI signature against operator's enrolled key before executing.

On Tier 1 (Pi CM5): bootloader is the Pi Foundation's bootloader binary; UKI verification happens at kernel-load stage. Boot ROM remains Broadcom's. Trust chain reach: Broadcom → Pi bootloader → operator's UKI → measured boot from there forward.

On Tier 2 (RISC-V): U-Boot is common; can be operator-built from source. UKI verification at U-Boot stage. Boot ROM depends on SoC; some SoCs (SiFive, StarFive) have documented boot ROMs.

On Tier 3 (custom SoC): boot ROM is operator-authored.

### Measured boot

Each stage measures the next. TPM PCRs accumulate:
- PCR 0: firmware/boot ROM
- PCR 2: extended firmware
- PCR 4: bootloader
- PCR 7: Secure Boot state
- PCR 11: UKI (operator's kernel + initramfs)

Sealed FDE ties disk decryption to expected PCR values. Any tamper or unexpected firmware change breaks seal.

### Boot receipt

On successful boot, substrate emits `boot:generation` receipt with:
- Board schematic version hash
- Firmware component hashes and versions
- PCR values
- NixOS system generation hash (source pin)
- Timestamp

Chain-anchored evidence of exactly what booted. Operator (or peer) can verify: given the schematic, given the firmware manifest, given the NixOS expression, recompute expected PCRs and confirm they match.

### Firmware update ceremony

Firmware updates are chain-anchored operations per QUARANTINE-PLANE (firmware artifacts pass through quarantine). Update signed by operator Genesis (or by delegated firmware-update authority under strict scope). Old firmware retained for rollback per BLAST-RADIUS-AND-RECOVERY forward-only discipline.

## Trust chain reach per tier

| Tier | SoC firmware | Bootloader | Kernel | Userland | Observer |
|---|---|---|---|---|---|
| 0 (Pi 5 + LetsTrust) | Broadcom | Pi Foundation → op UKI | Op | Op | Plug-in TPM, no observer |
| 1 (custom carrier + Pi CM5) | Broadcom | Pi Foundation → op UKI | Op | Op | Op-designed on-board observer |
| 2 (custom carrier + RISC-V SoM) | Partially open | Op-built U-Boot → op UKI | Op | Op | Op-designed on-board observer |
| 3 (op-designed security coprocessor + commodity/RISC-V main SoC) | Op-designed silicon for security coprocessor | Op | Op | Op | Op-designed on-board observer, plus operator-designed coprocessor for security ops |

Each tier's Form Disclosure honestly names the boundary. No pretense of sovereignty deeper than the operator actually controls.

## Bill of materials (Tier 1 reference)

Realistic BOM for a custom carrier board around Pi CM5 with all canonical principles:

| Category | Component | Cost |
|---|---|---|
| SoM | Raspberry Pi Compute Module 5, 8GB, no eMMC | $80 |
| PCB | Custom 4-layer board, 100x100mm, PCBway | $50 (small batch) |
| TPM | Infineon SLB9670 SPI TPM 2.0 chip | $5 |
| Observer MCU | RP2040 or STM32F411 | $2 |
| Observer sensors | 4x INA260 (rail voltage/current), 3x TMP117 (thermals), passives for RF detect frontends | $20 |
| Secure element | ATECC608B (on-board) OR YubiKey 5C USB-C (external) | $5-25 |
| NVMe | Kingston NV2 250GB M.2 2280 | $30 |
| PSU | 5V/5A USB-C PSU or 12V barrel with on-board buck converter | $15 |
| Case/enclosure | Custom 3D-printed or laser-cut aluminum, with tamper switches integrated | $50 |
| Kill switches | Sealed SPDT switches × N (radios if any, camera, mic) | $10 |
| Connectors | USB-C, HDMI, Ethernet, GPIO header, boot-mode selector | $15 |
| Passives | R/C/L bulk order | $10 |
| Misc | Standoffs, screws, cables, assembly | $20 |
| **Total** | **~$310-330** |

Small-batch fab is more expensive per unit. Larger batches drop cost significantly. Community-shared designs amortize the design cost.

Reference build cost per unit at batch of 100: probably $200-250. At batch of 10: $300-350. At batch of 1 (single prototype): $400-500 including one-off PCB fab.

## Design and manufacturing timeline

Realistic sequence for a new operator or small team building Tier 1:

- **Weeks 1-2**: Schematic design in KiCad. Reference existing open designs (Pine64, Radxa, community boards).
- **Weeks 3-4**: PCB layout. Component placement, routing, DRC.
- **Week 5**: First PCB submission to fab (JLCPCB or PCBway). Component sourcing (Digi-Key, Mouser, LCSC).
- **Week 6-7**: Boards arrive. Manual population or SMT assembly service.
- **Weeks 8-9**: Bring-up. Firmware to blink LEDs, verify power rails, verify each peripheral. Almost always reveals wiring or footprint errors.
- **Week 10**: Second PCB spin fixing bring-up issues.
- **Weeks 11-13**: Full firmware bring-up including observer MCU, TPM integration, boot mode selector logic.
- **Weeks 14-15**: NixOS on target hardware. Kernel driver work for any non-standard peripherals.
- **Week 16**: Third spin (if needed) with observations from full-stack testing.
- **Weeks 17-20**: Substrate deployment, chain integrity testing, operator ceremony flow.

Realistic total: 4-5 months for first operator-designed sovereign board. Second and third boards in same family: 1-2 months.

## Reproducibility discipline

Every board is a chain-anchored artifact per KEEL §XIV.6 canonicalization principle.

**Source pin**: KiCad project files at specific git commit, published open-source. Chain receipt `hw:board:source:<hash>` points at content-addressed source archive.

**BOM manifest**: canonical BOM with manufacturer part numbers, DigiKey/Mouser part numbers, quantities. Chain receipt `hw:board:bom:<hash>`.

**Assembly manifest**: instructions for building the board from BOM + PCB. Documentation, not code, but content-addressed.

**Test manifest**: firmware for testing each board post-assembly, expected results per test. Content-addressed.

Given these four manifests, anyone can:
1. Order the PCB from the source manifest
2. Order components per BOM
3. Assemble per assembly manifest
4. Verify per test manifest
5. Reproduce the exact hardware

Same content-addressability discipline as WASM extensions or NixOS system generations. Hardware is canonical spec at the physical layer.

## Composition with Substrate Form

Custom hardware doesn't change Substrate Form definitions — Sovereign Form is the same behavior regardless of hardware tier. What changes is:
- **Trust chain reach** — Tier 1+ improves reach vs Tier 0
- **Observation surface** — hardware observer adds physical proprioception unavailable on commodity Pi 5
- **Form Disclosure text** — honestly names the boundary at each tier

Substrate Form is a *behavioral* declaration; hardware tiers refine *what physical realizations of that behavior look like*.

## Composition with the observation plane

Hardware self-observer adds a seventh observation surface (in addition to the six declared in OBSERVATION-PLANE-2026-07.md):

- **Surface**: physical hardware state — rail voltages, currents, thermals, clock frequencies, RF detection, tamper state, boot timing, kill switch positions
- **Layer A primitives**: observer MCU on custom board; not available on Tier 0
- **Ontology object**: `HardwareObservation` with rail state, thermal state, radio state, tamper state, etc.
- **Cadence**: continuous sampling with declared bounds
- **Delegation class**: `observe:hardware:*` — baseline scope is board-inherent (observer's own state); broader scopes optional

Observer's operation and receipts detailed in HARDWARE-OBSERVER-2026-07.md.

## Composition with quarantine plane

Firmware components are quarantine-relevant artifacts:

- **Bootloader binaries**: quarantined until operator-signed
- **UKI (kernel + initramfs bundles)**: quarantined until operator-signed
- **Observer MCU firmware**: quarantined until operator-signed
- **TPM firmware updates** (rare, but happen): quarantined; TPM vendor's signature verified; operator delegation required for admission

Firmware admission ceremony parallels executable-artifact admission. Bootstrap: initial firmware is provisioned at manufacturing time; operator can subsequently rotate to their own signed builds via secure-boot key enrollment ceremony.

## Composition with circuit breaker

Hardware anomalies feed circuit breaker triggers per BLAST-RADIUS-AND-RECOVERY §"Escalation Ladder":

- **Physical anomaly at L1**: rail voltage brief spike, thermal transient — elevated attention, increased sampling
- **Sustained physical anomaly at L2-L3**: consistent power draw inconsistent with claimed workload — rate limit workload attribution, soft arrest of affected scopes
- **Integrity violation at L4**: tamper detected, kill switch state disagrees with observed RF, boot timing wildly off — hard trip on affected scopes
- **Boot chain integrity at L5**: PCR values don't match expected → substrate refuses to boot into operational state

Hardware observer is a first-class trigger source for circuit breaker. Physical evidence has same weight as officer evidence for escalation.

## Attack model

- **Attacker replaces main SoC firmware**: measured boot detects; PCR values change; sealed FDE breaks; disk refuses to decrypt. Operator sees failure clearly.
- **Attacker modifies observer MCU firmware**: observer firmware is signed by operator; observer refuses to run unsigned firmware; unsigned observer emits no receipts; substrate detects observer silence → circuit breaker trip.
- **Attacker physically opens case**: tamper switch triggers TPM PCR extension; sealed FDE breaks; substrate refuses to boot into operational state.
- **Attacker probes hardware for side-channel leakage**: substrate operates within known-side-channel-resistant algorithms (constant-time crypto). Genesis operations happen inside hardware token where possible; secure element side-channel resistance is manufacturer-declared.
- **Attacker replaces or swaps board**: board is content-addressed. Substrate emits `boot:generation` receipt including board hash. Different board = different receipt = detectable.
- **Attacker manipulates power rails to induce fault**: observer detects power anomaly; circuit breaker trip; substrate enters safe state.
- **Attacker activates radios via firmware exploitation despite kill switch position**: observer's RF detector catches the emission mismatch; `hw:radio:integrity_violated` receipt; circuit breaker escalation.
- **Attacker attempts to remove observer MCU or discrete TPM**: soldered components; removal requires case-opening which trips tamper detection.
- **Attacker with physical access disables observer power rail**: observer heartbeat monitoring detects absence; substrate treats observer silence as circuit breaker trigger.
- **Attacker performs cold-boot RAM extraction**: mitigation via memory encryption where available, tamper-triggered wipe on detection, and operator-configurable RAM-clearing at shutdown.

## Non-goals

- **Not a general-purpose PC**. Custom sovereign hardware is optimized for substrate operations, not for arbitrary desktop workloads. It's fine for browsing and editing text, but heavy compute (video editing, 3D rendering, gaming) is not the target.
- **Not for mass consumer market**. This is operator-designed hardware for operators willing to invest. Not intended to compete on price/performance with commodity computing hardware.
- **Not a certification program**. No "ZP Approved Hardware" gatekeeper. Operators build (or purchase from independent builders) hardware meeting the canonical principles. No central authority approves designs.
- **Not fully immune to hardware supply-chain attacks**. Component provenance is best-effort. Discussed further in HARDWARE-OBSERVER-2026-07.md attack model.

## Open positions

- **Reference open-hardware design releases**. Foundation may (or may not) publish reference designs for Tier 1 and Tier 2. Trade-off: canonical reference simplifies adoption vs foundation-privilege concerns.
- **Community fabrication pooling**. Operators individually ordering small PCB batches is expensive per-unit. Community pooling to hit price breaks makes sense; needs coordination infrastructure.
- **RISC-V SoM availability**. Depends on external supply. StarFive VisionFive, Milk-V Pioneer, Radxa RISC-V — availability fluctuates. Foundation may bulk-purchase and redistribute as substrate consumers request.
- **Custom SoC path readiness**. Tier 3 aspirational for now; when does it become accessible? Depends on open PDK maturity, community collaboration around shared designs, foundation coordination.
- **Cross-tier compatibility**. Should observer firmware be identical across tiers, or tier-specific? Prefer identical with tier-specific sensor configuration; watch for cases requiring split.
- **Firmware audit expectations**. Even operator-controlled firmware benefits from third-party review. How does the ecosystem coordinate audits without creating audit-authority-as-gatekeeper problems?
- **Second-source component strategy**. Every canonical component should have documented second-source alternatives (equivalent parts from different manufacturers) to avoid single-vendor supply chain dependency.

## What composes from here

Immediate design work:

1. **HARDWARE-OBSERVER-2026-07.md** — companion doc detailing the observer subsystem (Task #30)
2. **Reference Tier 1 schematic** — actual KiCad design implementing canonical principles; publishable as canonical spec
3. **Bootloader chain integration** — how UKI signing, measured boot, and `boot:generation` receipts wire together
4. **Firmware update ceremony** — operator UX for reviewing and signing firmware updates
5. **Component audit database** — canonical list of validated components per canonical principle, with alternatives per second-source strategy
6. **Community fabrication coordination** — mechanism for pooling PCB orders to hit price breaks

Near-term implementation:

1. Actual Tier 1 board design published as reference
2. Firmware for observer MCU (from HARDWARE-OBSERVER-2026-07.md)
3. NixOS module for measured-boot chain and `boot:generation` emission
4. Substrate integration of hardware observation surface (chain reception, ontology materialization)
5. Dashboard panel showing hardware state and board provenance
6. Documentation and tutorials for operators pursuing custom-hardware graduation

## Framing note

Sovereign hardware is the physical realization of what SUBSTRATE-FORM-2026-07.md declares behaviorally. Pi 5 is Sovereign Form; custom carrier boards are Sovereign Form with expanded operator control of the physical stack; RISC-V is Sovereign Form with ISA-level sovereignty; custom silicon is Sovereign Form with silicon-level sovereignty. Each tier is real; each is honestly disclosed; each extends the trust chain further.

The load-bearing insight: **hardware is not gatekept.** PCB fab is a commodity service. Component sourcing is a commodity service. Anyone with the design skills — or the community pooling to share designs — can build sovereign hardware today. Barriers are attention and effort, not vendor gates. The substrate's architectural family, extended physically: what officers, extensions, observations, and cognitive input have declared at the software layer, custom hardware realizes at the physical layer.

Combined with the substrate's structural discipline for actions, admissions, observations, cognition, and emergencies, custom sovereign hardware is the physical foundation that makes the entire trust story genuinely operator-controlled from silicon to Regent. Substrate coherence, all the way down.
