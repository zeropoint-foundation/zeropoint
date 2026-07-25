# Reproducibility Ceremony

**Tier 2 canonical elaboration.** Elaborates `KEEL-2026-07.md` §II.5 (Genesis-derived signing), Part VII (Peer-Verification Contract), and III.22 (verify before commit). Specifies how the substrate's source-to-binary correspondence is chain-anchored and verifiable by peers independently rebuilding from source. Canonical claims live in KEEL.

Draft — 2026-07-11 — internal audience only. Composes with `BUILD-PROCESS-DESIGN-2026-07.md` (chain-participating build produces the artifacts this ceremony verifies), `PEER-TRUST-ANCHOR-2026-07.md` (peer verification requires trust anchor for reproducibility-input surface), `SUBSTRATE-FORM-2026-07.md` (reproducibility semantics vary by Form).

## Framing

The substrate's trust model depends on the operator being able to answer: "What is my substrate actually running?" Chain evidence documents what the substrate emits, but chain evidence alone cannot answer whether the running binary matches the source that operator believes to have built it. A malicious build system, a compromised compiler, an attacker-swapped binary — all could produce a substrate that emits chain evidence while running fundamentally different code from what the source claims.

Reproducibility ceremony is the substrate's structural response to this gap. Same source + same build environment → byte-identical binary. If independent parties rebuild from identical source and get identical binary hash, the source-to-binary correspondence is verifiable rather than trusted. Chain-anchored via `build:reproducibility_verified` receipts. Peer-verifiable via independent rebuild + hash comparison + peer attestation receipt.

Three properties frame the ceremony:

1. **Reproducibility is a source-code property**, not a build-artifact property. The substrate is reproducible if the source tree, build config, and toolchain versions together deterministically produce a binary hash. Non-determinism in build (embedded timestamps, absolute paths, thread scheduling) breaks reproducibility even when source is intact.
2. **Independent verification is the ceremony**. Operator's own build receipt is evidence of *this operator's build*, not of source-to-binary correspondence. Peer's independent rebuild producing the same hash is what verifies correspondence. Ceremony is the ritual of exchanging rebuild attestations.
3. **Reproducibility complements, not replaces, other trust mechanisms**. Genesis-derived signing, delegation ceremony, chain-anchored discipline — these establish authority. Reproducibility establishes that the authority is exercised by the code the source declares.

## The reproducibility guarantee

The substrate targets bit-identical reproducibility across:

- Same source tree hash (git rev, tree state)
- Same Cargo.lock (exact dependency versions)
- Same declared toolchain (Rust version, target architecture)
- Same declared build flags (release / debug, features enabled)

Given all four inputs, `cargo build [--release]` must produce byte-identical binaries. Non-determinism at build time — from any source — is a substrate hygiene bug to be resolved.

Sources of non-determinism to eliminate:

- **Embedded timestamps**: `env!("CARGO_PKG_VERSION")` is deterministic; `chrono::Utc::now()` at build time is not. Use `SOURCE_DATE_EPOCH` convention.
- **Absolute paths in debug info**: build system must remap paths (`--remap-path-prefix`).
- **Thread-scheduling nondeterminism**: parallel compilation should still produce identical output; single-threaded fallback catches remaining issues.
- **Locale-dependent sort orders**: any build script that reads directory listings must sort deterministically.
- **Random seeds in codegen**: no PRNG-based codegen without deterministic seeds.
- **Compiler version drift**: pinned Rust toolchain per Cargo.toml `rust-version` and `rust-toolchain.toml`.

## The ceremony flow

Reproducibility ceremony is a chain-anchored protocol between operator (the source-of-truth builder) and one or more peers (independent verifiers).

### Step 1 — Operator publishes build attestation

Operator's substrate emits `build:artifact_produced:<build_id>` receipt (per BUILD-PROCESS-DESIGN Phase 3) with:
- Source rev
- Cargo.lock hash
- Toolchain version
- Build flags
- Binary hash
- Build environment fingerprint (host OS, arch)

This receipt is shareable to peers via peer distribution mesh.

### Step 2 — Peer receives build attestation

Peer with trust anchor for reproducibility-input surface (per PEER-TRUST-ANCHOR) receives operator's `build:artifact_produced` receipt. Peer decides to participate in ceremony.

Peer emits `reproducibility:verification_initiated:<build_id>:<peer_id>` receipt on their own chain.

### Step 3 — Peer independent rebuild

Peer pulls source at operator's declared source rev. Peer runs their own build with identical parameters (Cargo.lock, toolchain, flags). Peer's build produces a binary; peer hashes it.

### Step 4 — Peer attestation

Peer emits verification receipt:

**Match case** — `reproducibility:verified:<build_id>:<peer_id>` receipt:
- Reference to operator's `build:artifact_produced` receipt
- Peer's rebuilt binary hash
- Peer's build environment fingerprint
- Confirmation that hashes match
- Signed by peer's Genesis

**Mismatch case** — `reproducibility:diverged:<build_id>:<peer_id>` receipt:
- Reference to operator's `build:artifact_produced` receipt
- Peer's rebuilt binary hash
- Operator's stated binary hash
- Peer's build environment fingerprint
- Signed by peer's Genesis

**Verification failure case** — `reproducibility:verification_failed:<build_id>:<peer_id>` receipt:
- Reference to operator's `build:artifact_produced` receipt
- What failed (source unavailable, toolchain unavailable, build error, etc.)
- Signed by peer's Genesis

Peer distributes verification receipt back to operator (and to other peers who may care).

### Step 5 — Operator receives peer attestation

Operator's substrate observes peer's verification receipt via mesh distribution. Substrate emits `reproducibility:peer_verification_received:<build_id>:<peer_id>:<result>` receipt on operator's chain, chain-linking peer's attestation.

Reputation composes: peer's positive verification adds trust signal; peer's mismatch or failed verification adds concern signal.

### Step 6 — Ceremony completion

After operator has received verifications from N peers (where N is operator-configured threshold, typically 3 for daily builds, higher for release builds), operator can emit `reproducibility:ceremony_completed:<build_id>` receipt attesting that the build is peer-reproducibility-verified.

Peers who trust this operator can then treat `build:artifact_produced` receipts from this operator as trustworthy without needing to independently rebuild each one.

## Ceremony scope

Not every build requires ceremony. Substrate distinguishes:

### Continuous reproducibility

Every `build:artifact_produced` receipt is candidate for peer verification. Peers in reproducibility federation independently verify at their own cadence. Divergences trigger investigation.

Trade-off: verification cost (peer CPU, storage) vs coverage.

### Release ceremony

Explicit ceremony on release builds. Operator publishes release; multiple peers verify; ceremony completion receipt anchors release as peer-verified.

Trade-off: ceremony delay vs release confidence.

### Milestone ceremony

Ceremony triggered on specific events: post-Genesis-rotation build, post-major-refactor build, post-toolchain-upgrade build. Chain-anchored ceremony receipt.

Trade-off: ceremony overhead vs assurance for specific high-risk events.

## Peer selection

Which peers verify?

**All peers with trust anchor for reproducibility-input surface** may participate. Peer participation is voluntary; peer's own trust anchor for the operator determines whether they'll perform verification for this operator.

**Ceremony completion threshold** (N peers required for completion receipt) is operator-configured based on desired assurance level. Higher N = more confidence but longer ceremony delay.

**Peer diversity** matters: peers running different OS, different hardware, different environments provide broader coverage. Ceremony can require diversity constraints (e.g., "at least one peer on macOS, one on Linux, one on ARM").

**Peer independence** matters: ceremony receipts from peers who share build infrastructure (e.g., all pulling from same CI cache) provide weaker verification than peers with fully independent build environments.

## The federation view

A reproducibility federation is a group of substrates who mutually verify each other's builds. Federation is emergent from trust anchors, not centrally organized.

Reciprocity: peer A verifying peer B's builds gives peer A some assurance that peer B's substrate matches source. Peer B verifying peer A's builds gives peer B corresponding assurance. Mutual verification is stronger than one-way verification.

Federation reputation: a federation's collective reputation for careful verification (deep investigation of divergences, cross-checking builds across environments) becomes shared reputation across the federation. Federation members co-signal trustworthiness by association.

The commons (per DISTRIBUTED-KNOWLEDGE-COMMONS) can host reputation signals about federations: "this federation caught three source-to-binary divergences and investigated correctly; that federation missed a known divergence." Federations that consistently perform well accrue reputation; federations that don't are less trusted as verifiers.

## Non-reproducibility handling

Sometimes builds are legitimately non-reproducible for structural reasons (e.g., a build step requires network access that isn't cache-controlled). Substrate acknowledges and manages this:

**Declared non-reproducibility**: operator declares specific build artifacts as non-reproducible via `build:reproducibility_scope_excluded:<artifact_path>` receipt. Peer ceremony still verifies the reproducible portion; excluded artifacts are excluded from ceremony.

**Reproducibility failure investigation**: divergence between peers triggers investigation. Common causes:
- Non-determinism in build (embedded timestamp, absolute path) — bug in build; substrate patches
- Compiler version mismatch — peer's declared toolchain differs; investigate
- Genuine compromise — attacker manipulated source or binary somewhere; emergency response

Emit `reproducibility:investigation_initiated:<divergence_id>` receipt when investigation starts. Emit `reproducibility:investigation_resolved:<divergence_id>:<root_cause>` when concluded. Chain records the arc.

## Attack model

Attacker scenarios and how the ceremony addresses them:

- **Attacker swaps operator's binary post-build**: operator's build receipt records intended binary hash; substrate hashes running binary at startup. Mismatch caught locally. Peer ceremony catches at broader level.
- **Attacker compromises operator's build system**: operator's binary hash is different from what independent peer rebuild produces. Divergence detected in ceremony; investigation ensues.
- **Attacker compromises single peer verifier**: single peer's false verification would attest to a binary hash that doesn't match reality. Other peers in ceremony contradict. False-attesting peer flagged; reputation impact.
- **Attacker compromises multiple peers**: if attacker controls M-of-N ceremony peers, they could conspire to attest a false hash. Federation reputation, peer trust anchor scope, and cross-federation verification provide resilience. Absolute ceiling: if attacker controls all trusted peers, ceremony provides no protection — trust anchor management is the concern at that point.
- **Attacker manipulates source before commit**: source integrity depends on git integrity and commit signing. Post-commit reproducibility ceremony verifies source→binary, not source integrity itself. Signed commits and code review are the mechanisms for source integrity.
- **Attacker exploits build system nondeterminism**: attacker introduces subtle nondeterminism that some peers see and some don't. Divergence detected in ceremony; substrate hygiene bug or attacker exploitation; investigation distinguishes.
- **Attacker delays ceremony completion via peer DoS**: attacker prevents peers from responding. Ceremony completion delays. Operator can wait or lower N threshold (with acknowledged reduced assurance).

## Failure modes

- **Genuine reproducibility bug in substrate**: substrate has some nondeterminism operator hasn't fixed yet. Ceremony catches; substrate patches; operator ceremony restarts with patched substrate.
- **Peer's build environment differs from operator's**: peer runs different OS/arch; different builds produce different binaries. Ceremony reveals divergence. Cross-arch reproducibility is a further target; single-arch reproducibility is the minimum.
- **Peers offline; ceremony never completes**: reproducibility federation is unavailable. Operator has no peer-verification for this build. Substrate operates on operator-local trust only. Reduced federation trust footprint until federation online.
- **Ceremony completion falsely positive**: N peers verified but there's an unknown attacker with M peer keys. Extended over time, additional peer verifications and cross-federation reputation reveal manipulation.
- **Operator's own trust anchor for peers is compromised**: operator trusts a peer they shouldn't. Broader trust anchor management concern; peer verification quality is downstream.

## Non-goals

- **Not a substitute for source review**. Reproducibility verifies source-to-binary correspondence. Source itself must still be reviewed for correctness. Reproducibility does not tell you the source is safe; it tells you the binary matches the source.
- **Not universal cross-platform verification**. Different OS/arch produce different binaries. Ceremony verifies within a target family; cross-family verification requires different comparison logic.
- **Not automated remediation**. Divergence detection triggers investigation, not automatic revert. Substrate does not roll back binaries automatically based on peer divergence; operator ceremony authorizes response.
- **Not a substitute for signed commits**. Ceremony verifies binary matches declared source rev. Commit signing verifies source rev matches operator intent. Both are needed for full source-to-authority-chain trust.
- **Not a defense against compromised compiler**. If the Rust compiler itself is compromised (see "Reflections on Trusting Trust"), reproducibility still catches the compromise if independent peer compilers are uncompromised. Universal compiler compromise is beyond substrate scope.

## Open positions

- **Reproducibility federation bootstrap**. How do operators find peers to verify with? Foundation-published reference federation? Community discovery? Referral from existing peer relationships?
- **Ceremony delay tolerance**. What's acceptable delay from build to peer verification completion? Immediate (minutes) for daily builds? Extended (days) for milestone ceremonies? Trade-off: assurance vs release velocity.
- **Ceremony threshold defaults**. What N for daily verification? Release verification? Milestone ceremony? Operator judgment or reasonable defaults?
- **Peer selection algorithm**. Do peers auto-select each other for ceremony participation? Round-robin? Random? Reputation-weighted? Operator preference?
- **Non-reproducibility scope declarations**. What's the schema for declaring specific build steps as reproducibility-excluded? How is exclusion audited?
- **Cross-arch verification protocol**. Different OS/arch binaries differ; but source→behavior correspondence can still be verified via behavioral verification (running specific test cases). Design work.
- **Toolchain reproducibility**. If Rust compiler binaries differ across peers, ceremony verifies source→binary but not toolchain→binary. Bootstrapping trust chain to compiler itself is a further problem.
- **Compiler explorer verification**. Could peers with different compilers verify same source produces functionally-equivalent binaries even if bit-differing? Beyond current substrate scope.

## What composes from here

Immediate design work:

1. **Reproducibility receipt schemas** — Layer B canonical spec for the ceremony receipts
2. **Ceremony coordinator runtime** — protocol for operator↔peer verification exchange
3. **Non-reproducibility scope declaration schema** — what's excluded, how it's chain-declared
4. **Cross-federation reputation signals** — how federation reputation flows through DISTRIBUTED-KNOWLEDGE-COMMONS
5. **Ceremony UX** — operator dashboard panels for initiating ceremony, tracking peer verification progress, reviewing divergences

Near-term implementation:

1. Ceremony coordination runtime in `crates/zp-server/src/reproducibility/`
2. Binary hash computation utility (BLAKE3 over binary)
3. Source tree hash utility (deterministic tree hash)
4. Ceremony receipt emitters
5. Peer verification exchange protocol (over mesh)
6. Dashboard reproducibility ceremony panel
7. CLI verb: `zp reproducibility ceremony <build_id>` for initiating explicit ceremony

## Framing note

Reproducibility ceremony completes the trust chain from source to binary to running substrate. Same principle as chain-anchored discipline for other trust boundaries — extended to the source→binary correspondence.

The load-bearing insight: **source-to-binary correspondence is verifiable via independent rebuild, not trusted via authority.** Not "the vendor built this; trust them." Not "the operator's build system said so; trust it." Independent peers rebuild from source and get the same binary hash; ceremony receipts chain-anchor the verification. Federation of verifiers strengthens the assurance; reputation flows via commons; peer trust anchors gate participation.

Combined with the substrate's structural discipline across every trust boundary — actions, admissions, observations, cognition, extensions, hardware, emergency response, Genesis rotation, peer trust, build lifecycle — reproducibility ceremony completes the source-to-binary trust surface. What today's stated-destination confabulation surfaced (Regent thinking she was running one model when she was running another) becomes structurally impossible when the running binary is peer-verifiable against declared source, and the declared model is chain-anchored config that matches the running binary's expectations.
