# Hardware Self-Observer

**Tier 2 canonical elaboration.** Companion to `SOVEREIGN-HARDWARE-2026-07.md`. Details the hardware self-observer subsystem — a first-class component of canonical sovereign hardware. Elaborates `KEEL-2026-07.md` §II (adds physical observation tier) and Part XIV (Substrate Realization at hardware level). Canonical claims live in KEEL.

Draft — 2026-07-10 — internal audience only. Composes with `SOVEREIGN-HARDWARE-2026-07.md` (hardware architecture), `OBSERVATION-PLANE-2026-07.md` (adds physical observation as seventh surface), `CIRCUIT-BREAKER-2026-07.md` (observer findings feed trigger sources), `BLAST-RADIUS-AND-RECOVERY-2026-07.md`.

## Framing

The main SoC on any computer — Broadcom on Pi, Intel on desktop, Apple Silicon on Mac — has its own view of what's happening. It reports temperature via its thermal sensors, current via its power management IC, activity via its performance counters. The operator, and any observer running on the SoC, sees what the SoC chooses to report.

That's a trust problem. If the SoC is compromised — via firmware exploit, via microcode manipulation, via undocumented management engine functionality — its self-reports become unreliable. The compromised SoC could report "idle" while running full-tilt compute; report "WiFi off" while emitting RF; report "TPM secure" while leaking keys. Every mainstream computing platform has this vulnerability by architecture.

The hardware self-observer is the substrate's structural discipline against this failure mode. It's a small, independent microcontroller on the board — separate crystal, separate power rail, separate signing key, signed firmware — whose sole job is *observing physical properties independently of the main SoC and reporting via signed chain-anchored receipts*. It cannot execute commands from the main SoC. It cannot be silenced by software. It has physical measurement paths to power rails, thermals, clock outputs, RF frontends, tamper switches, and boot-timing signals that the main SoC cannot lie about.

Three properties frame the observer:

1. **Physically independent of the main SoC** — separate silicon, separate power domain, separate firmware. Compromise of the main SoC does not compromise the observer.
2. **Observation-only, no control** — the observer sees and reports; it does not modify substrate behavior or the main SoC state. Inverts the vendor-coprocessor model (Intel ME watches for Intel and can control the main CPU; this observer watches for the operator and cannot).
3. **Genesis-derived signing authority** — the observer's key derives from the operator's Genesis via HKDF at provisioning. Every observer receipt is chain-verifiable back to Genesis.

## The observer chip

Small, cheap, well-documented microcontroller with sufficient I/O for the sensor array and sufficient RAM for cryptographic operations.

### Chip selection

Two viable options:

**RP2040** (Raspberry Pi Foundation's own chip):
- Dual-core ARM Cortex-M0+ at 133MHz
- 264KB SRAM
- 30 GPIO pins
- I2C, SPI, UART, PIO (programmable I/O)
- Fully documented, open-source SDK
- ~$1 in single quantities
- Well-supported by community

**STM32F411** (ST Microelectronics):
- Cortex-M4 at 100MHz with FPU
- 512KB flash, 128KB SRAM
- More GPIO than RP2040
- Better hardware crypto acceleration
- ~$3 in single quantities
- Long history of use in security-critical embedded

Either works. RP2040 preferred for foundation-shipped reference designs (aligns with Pi Foundation partnership; simpler supply chain). STM32F411 preferred for operators wanting hardware crypto acceleration and larger flash for more elaborate firmware.

### Independent power

Observer runs from its own linear regulator (LDO) tapped from board input voltage. Not from main SoC's rail. Rationale: if main SoC compromised or in fault, observer still runs and reports.

Voltage: 3.3V typical. Current: ~50mA maximum. Runs continuously.

Backup capacitor (100µF) provides brief power-fail continuation so observer can emit a `hw:power:fault` receipt before losing power itself. Alternative: coin cell backup for hours-long autonomous operation (chain of custody: observer reports even after board is unplugged, until battery drains).

### Independent crystal

Observer runs from its own crystal oscillator, not from a clock derived from the main SoC. Frequency accuracy independent of main SoC state. Rationale: observer's timing measurements are trustworthy.

12MHz crystal (standard, cheap) sufficient for RP2040. Higher frequency options for STM32 if needed for precise measurements.

## Sensor array

The observer's physical measurement paths. Each sensor connects via I2C or GPIO; observer polls at declared cadence.

### Rail voltage and current (INA260)

Multiple INA260 modules on I2C bus, one per major power rail:
- Main SoC core rail (typically 0.8-1.2V)
- Main SoC IO rail (typically 1.8V or 3.3V)
- RAM rail (typically 1.1-1.5V depending on memory)
- Storage rail (5V or 3.3V depending on NVMe)
- USB port rails (5V)
- Radio module rails (if radios present)

Each INA260 provides bus voltage, current, and computed power. Cadence: 100Hz sampling per rail. Storage: circular buffer, sampled data emitted as aggregate observation at 1Hz.

Anomaly detection at observer:
- Rail voltage outside declared bounds → `hw:rail:voltage_anomaly` receipt
- Rail current above declared idle bound when workload should be idle → `hw:rail:current_inconsistent_with_workload` receipt
- Sudden power spike on GPU-related rail while OS reports idle → `hw:covert_compute_suspected` receipt

The `hw:covert_compute_suspected` receipt is the observer's answer to "is the SoC secretly computing without OS knowledge?" — the physical evidence is power draw. Compromised SoC cannot hide from power measurement.

### Thermal (TMP117)

Multiple TMP117 modules at strategic points:
- Main SoC package top
- RAM chips
- Storage controller
- Board center (ambient reference)

Cadence: 1Hz sampling. Includes derivative (rate of change) computation.

Anomaly detection:
- Absolute temperature above declared threshold → `hw:thermal:overtemp` receipt
- Thermal derivative anomaly (rate of change inconsistent with claimed workload) → `hw:thermal:derivative_anomaly` receipt

Thermals are the second physical evidence of covert compute — sustained thermal signature at rest indicates ongoing computation.

### Clock frequency (frequency counter on GPIO)

Independent frequency counter watching the main SoC's clock output. Compares against expected clock frequency for reported CPU governor state.

Cadence: 10Hz measurement. Anomaly detection:
- Clock frequency higher than reported governor state → `hw:clock:overspeed_suspected` (SoC running faster than it claims)
- Clock frequency lower than reported → `hw:clock:underspeed` (thermal throttle? firmware issue?)

Detects some microcode-level manipulation where SoC lies about its own clock speed.

### RF detection (per radio)

Small RF frontend per radio (WiFi, Bluetooth, cellular if present):
- Antenna coupling → RF attenuator → RF detector (peak detect diode) → op-amp → observer ADC

Cadence: 100Hz sampling. Detects presence of RF emission at the radio's operational frequency bands.

Anomaly detection:
- Kill switch says "off" but RF detector says "emission present" → `hw:radio:integrity_violated:<radio>` receipt (compromised radio firmware ignoring kill switch)
- Kill switch says "on" but no emission when OS claims network activity → potentially benign or `hw:radio:emission_absent_unexpected`

RF detection is the answer to "is the radio actually off when the operator says it's off?" — cryptographic evidence, not just switch position.

### Tamper switches

Physical switches wired to observer GPIO:
- Case-open detect (magnetic reed switch, or mechanical switch triggered by case removal)
- Board-flex sensor (piezo element, detects PCB flexing)
- Optional: light sensor (case interior should be dark when closed)

Cadence: interrupt-driven (immediate on state change).

On tamper event: observer emits `hw:tamper:detected:<sensor>` receipt AND signals TPM via SPI to extend PCR (breaks sealed FDE on next boot). Immediate response; not deferred.

### Boot timing signals

Observer receives signals at boot stages (via GPIO from bootloader and kernel):
- Power-on
- Firmware start
- Bootloader start
- Kernel handoff
- Userspace start
- Substrate services start
- First operator interaction

Cadence: event-driven. Each signal captured with observer's own timestamp (from its independent crystal).

Anomaly detection:
- Boot stage timing outside declared envelope → `hw:boot:timing_anomaly`
- Missing expected boot signal → `hw:boot:stage_missing`
- Extra unexpected signal → `hw:boot:unexpected_signal`

Detects some classes of boot compromise — attacker's added code that runs between stages adds detectable time.

### Kill switch positions

Direct GPIO connections to physical kill switches:
- WiFi kill switch
- Bluetooth kill switch (if separate from WiFi)
- Camera kill switch (if camera present)
- Microphone kill switch (if microphone present)
- USB power kill switch (deny power to USB ports)

Cadence: interrupt-driven. Emit `hw:kill_switch:<name>:<state>` receipt on state change.

Kill switch state + RF detection state together are the load-bearing evidence for "the radio is actually off."

### Optional: EM shielding sensor

For paranoid deployments, an EM sensor detecting EM emissions from within the case that shouldn't be there (indicates unauthorized transmitter or unusual electrical activity).

## Firmware

Observer runs signed firmware. Firmware is small (target: <30KB), fully auditable, and updateable only via operator ceremony.

### Firmware discipline

- **Signed by operator Genesis** (via secure element or hardware token during provisioning)
- **Verified at every boot** by observer's own signature-check code (bootloader stage of observer firmware)
- **Refuses to run unsigned firmware** — observer just halts if signature check fails, emits no receipts, substrate sees observer silence → circuit breaker escalation
- **Update ceremony chain-anchored** — new firmware passes through QUARANTINE-PLANE per firmware artifact class, operator delegation ceremony admits, observer bootloader accepts on next boot

### Firmware architecture

**Startup (~1KB)**:
- Verify main firmware signature against operator's public key
- If valid, jump to main
- If invalid, halt, blink error LED, emit no receipts

**Main (~20-25KB)**:
- Initialize sensors (I2C setup, GPIO configuration)
- Genesis-key derivation (from provisioning-time material)
- Main observation loop:
  - Sample sensors per cadence
  - Detect anomalies against declared thresholds
  - Compose observation receipts
  - Sign receipts with observer key
  - Emit to main SoC via UART or SPI (structured protocol)
- Interrupt handlers for tamper, kill switch state changes, boot signals

**Diagnostic (~5KB)**:
- Available in recovery boot mode only
- Detailed sensor readouts for operator investigation
- No chain emission (recovery mode; may not have chain access)

Total: ~30KB. Fully audited by reading the firmware source (published as canonical spec).

### Firmware development stack

- **Language**: Rust (via `embassy-rs` or `rtic-rs`) or C (bare metal)
- **Toolchain**: cargo/rustc for Rust, GCC/clang for C, both open-source
- **Build reproducibility**: pinned toolchain version, deterministic build flags, `hw:observer:firmware:<hash>` receipt

## Signing and chain integration

Observer emits observation receipts signed with its Genesis-derived key.

### Key derivation

At provisioning time:
1. Operator connects to observer via UART (physical connection, not network)
2. Observer generates ephemeral keypair
3. Observer sends public key to substrate via UART
4. Substrate emits `hw:observer:provisioning:<board_hash>` receipt including observer's public key
5. Operator signs `delegation:granted:observer:<board_hash>` receipt with Genesis, delegating "observation of this board" capability to this specific observer public key
6. Observer stores private key in its own flash (non-exportable — no path to read it out of the chip)

Provisioning is one-time per observer. Compromised observer requires new observer chip (soldered — physically new hardware) and re-provisioning.

### Receipt emission

Observer composes observation receipts as protobuf or CBOR structures containing:
- Board hash (which board is this?)
- Observer public key (which observer?)
- Timestamp (from observer's independent crystal)
- Observation class (`rail_voltage`, `thermal`, `rf`, `tamper`, `boot_timing`, etc.)
- Observation data (measurement values)
- Signature (Ed25519 over serialized structure)

Observer sends receipts to main SoC via UART. Substrate reader on main SoC verifies signature, verifies against provisioning receipt, then appends to chain.

Trusted path: observer's receipts are signed on the observer; substrate cannot forge them. Main SoC can drop them (denial-of-service) but cannot fabricate them. If receipts stop arriving, substrate treats as `hw:observer:silence` → circuit breaker trigger.

### Anti-replay

Observer includes monotonic counter in each receipt. Substrate rejects receipts with counter values not strictly increasing. Prevents replay of old observations to hide current state.

## Composition with observation plane

The hardware observer adds a seventh observation surface to the six declared in OBSERVATION-PLANE-2026-07.md:

- **Surface class**: `hardware`
- **Layer A primitive**: observer MCU on board (only present on custom carrier board tiers, not Pi 5 commodity)
- **Ontology object**: `HardwareObservation` with sub-classes per sensor
- **Delegation class**: `observe:hardware:*` — baseline scope grants observer's own state observation; broader scopes optional

Officers can subscribe to `HardwareObservation` ontology objects and reason about physical state alongside other observation classes.

## Composition with circuit breaker

Hardware observer findings are trigger sources for circuit breaker escalation:

- **L1 elevated attention**: single anomaly detected (brief power spike, thermal transient) → increase observer sampling, subscribe cognitive observer
- **L2 rate limit**: repeated anomaly at same subsystem → rate-limit workloads at scope
- **L3 soft arrest**: sustained anomaly at critical class (rail current inconsistent with workload sustained > N samples) → block new operations at scope
- **L4 hard trip**: integrity violation (kill switch state disagrees with RF, tamper detected) → arrest all operations at scope, cascade per dependency graph
- **L5 substrate-wide graduated response**: multi-subsystem physical anomalies concurrent → maximum-safety mode; only identity operations, chain reads for operator diagnosis

Hardware evidence has same weight as officer evidence for escalation decisions.

## Composition with cognitive input plane

Hardware observation state is a Class 5 (filtered officer findings / substrate state) input to Regent's cycle context. Regent perceives:
- Current thermal state
- Current radio state (with kill switch positions)
- Recent tamper events (if any)
- Physical anomaly history

Enables Regent to reason about substrate health with full physical awareness. Composes with the *new capabilities must be harmonized with the flow of the system* heuristic — she can perceive her substrate's physical condition, not just software condition.

## Attack model

- **Attacker replaces observer chip**: chip is soldered on the board; removal requires case-opening which trips tamper detection. Even if attacker gets past tamper, replacement observer isn't provisioned; substrate rejects its receipts.
- **Attacker replaces observer firmware**: firmware signature check at observer boot; unsigned/wrong-signed firmware causes observer to halt. Substrate sees observer silence → circuit breaker trigger.
- **Attacker suppresses observer receipts (blocks UART line)**: substrate detects receipt stream stop; treats as circuit breaker trigger; refuses to enter operational state until observer restored.
- **Attacker feeds fake receipts on UART line**: fake receipts fail signature check; substrate rejects; may treat sustained invalid-receipt injection as circuit breaker trigger.
- **Attacker replays old observer receipts**: monotonic counter check rejects; substrate detects and treats as `hw:observer:replay_detected` — bigger emergency requiring investigation.
- **Attacker manipulates observer's own power rail**: observer detects its own low-voltage condition via internal power monitor; emits `hw:observer:power_fault` before browning out. Backup capacitor allows brief report.
- **Attacker probes observer chip for side-channel leakage**: Ed25519 constant-time implementation; observer avoids side-channel-prone operations. Advanced side-channel attacks require physical probing which requires case opening → tamper detection.
- **Attacker uses laser or focused-EM to fault observer**: mitigation is expensive-attacker discipline; not primary threat model. Observer redundancy (two observers cross-checking) available at Tier 1+ for operators willing to pay.
- **Attacker compromises operator's Genesis to sign malicious observer firmware**: Genesis compromise is the underlying emergency; Genesis rotation ceremony is the response.
- **Attacker manipulates sensors themselves (INA260 replacement with fake reporting values)**: sensors are soldered; replacement requires case opening → tamper. Fake sensor values would need physical replacement of the sensor chip.

## Attack model residual limits

Being honest about what the observer cannot address:

- **Compromised silicon supply chain**: if attacker manipulates the chip during manufacturing (e.g., inserts backdoor in the Broadcom SoC or the observer's own MCU), the observer's guarantees are broken. Mitigation is best-effort supply chain diligence, second-source component strategy, and community audit of specific batches.
- **Advanced nation-state hardware attacks**: focused-ion-beam probing, chip decap and analysis, IC-level attacks — beyond observer's mitigation. Not primary threat model.
- **Compromise of operator's Genesis**: observer's trust chain roots at Genesis; Genesis compromise cascades. Response is Genesis rotation ceremony, not observer improvement.

## Reproducibility

Observer firmware is a canonical spec artifact per KEEL §XIV.6:
- Source code published, git commit pinned
- Toolchain version pinned
- Build script content-addressed
- Compiled firmware hash chain-anchored

Operator can reproduce: given source, given toolchain, run build script, verify hash matches chain-anchored expected.

Sensor selection and layout published as part of `SOVEREIGN-HARDWARE-2026-07.md` §"Bill of Materials." Community can build boards that match canonical observer configuration, ensuring cross-board interoperability of the observer discipline.

## Non-goals

- **Not a general-purpose coprocessor**. Observer only observes and reports. Not a compute unit for offloaded work. Not accessible to the main SoC as a peripheral for other purposes.
- **Not for real-time control**. Observer's output is chain-anchored evidence, not real-time control signals. Circuit breaker uses observer evidence but operates via its own runtime.
- **Not a HSM**. Observer signs its own receipts but is not a general-purpose hardware security module. Operator Genesis operations live in the hardware token or secure element, not the observer.
- **Not present on Pi 5 commodity Tier 0**. Observer is a first-class subsystem on custom carrier boards (Tier 1+). Tier 0 lacks physical observation surface; Form Disclosure names the reduction.

## Open positions

- **Sensor cadence tuning**. Currently declared as reasonable defaults; empirical calibration against real workloads improves signal/noise trade-off.
- **Two-observer cross-check**. For paranoid deployments, two independent observer chips cross-verifying each other's receipts. Adds cost (~$3 in chip + support components) but eliminates single-observer-compromise attack surface. Worth spec'ing as opt-in.
- **Battery-backed observer**. Coin cell keeps observer running after main power cut. Enables continued reporting during power-off events, useful for forensic timeline reconstruction. Adds cost and space; opt-in.
- **Observer-observer mesh**. Multi-board deployments where each board's observer can see peer boards' observer heartbeats. Peer-detected observer silence adds signal beyond single-board self-report. Aspirational; requires network-connected observer path.
- **Sensor selection alternatives**. INA260 is one option for rail sensing; MAX44009 for light; TMP117 for temperature. Second-source strategy per SOVEREIGN-HARDWARE §"Open Positions" needs canonical alternatives documented.
- **Radio frontend tuning**. RF detector frontend design depends on frequency band. WiFi 2.4/5GHz, Bluetooth 2.4GHz, cellular various bands — each needs its own frontend design. Community reference designs per band useful.

## What composes from here

Immediate design work:

1. **Receipt schemas per observation class** — Layer B canonical spec for rail_voltage, thermal, rf, tamper, boot_timing, kill_switch state receipts
2. **Provisioning ceremony** — operator UX for first-time observer setup
3. **Firmware source code** — reference implementation in Rust (via embassy-rs), targeting RP2040 initially
4. **Board integration guide** — how to wire observer into carrier board designs; sensor placement, trace routing, EMC considerations
5. **Attack-model formalization** — threat modeling per attack class, with mitigation effectiveness rating

Near-term implementation:

1. Observer firmware reference implementation
2. Substrate reader on main SoC (chain integration of observer receipts)
3. Dashboard panel showing hardware state, observer heartbeat, anomaly history
4. Circuit breaker integration — observer findings as trigger sources
5. Cognitive input plane integration — hardware state as Regent's context input
6. Provisioning tooling (`zp observer provision` CLI verb + ceremony flow)

## Framing note

The hardware self-observer inverts the vendor-coprocessor model. Intel ME and AMD PSP are coprocessors that observe the CPU for the vendor's benefit — capabilities include remote management, DRM enforcement, and (per various disclosures) undocumented capabilities users cannot audit. The ZeroPoint observer is architecturally identical (small coprocessor with its own OS and communication channels) but inverted in trust: it observes for the operator, signs with operator-derived keys, cannot control the main SoC, is fully open-source, and is bounded by physical measurement paths that the main SoC cannot lie about.

Combined with the substrate's structural discipline for actions, admissions, cognition, and emergencies — all chain-anchored, Genesis-derived, structurally enforced — the hardware observer completes the physical foundation. Silicon-to-cognition trust chain, operator-controlled at every layer where operator control is achievable, honestly disclosed where residuals remain. The substrate's coherence extends into the physical world.

The load-bearing philosophical claim, from framing note in COGNITIVE-SELF-OBSERVER-2026-07 extended to hardware: *physical trust is not a property of the hardware; it's a property of the substrate.* Commodity hardware confabulates about itself just like models confabulate about reality. A substrate with independent physical observation converts confabulation into detectable, correctable, chain-anchored evidence. Physical fidelity is engineered, not hoped for. Same discipline; different layer; one canonical trust model, silicon to Regent.
