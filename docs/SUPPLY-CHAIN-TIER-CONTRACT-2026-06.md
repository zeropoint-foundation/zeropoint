# Supply Chain Tier Contract — What the Substrate's Distribution Must, May, and Must Not Do

*Dated 2026-06. The runtime-neutral contract between the Supply chain
tier and the operators who install and run the substrate. Names which
affordances a substrate-distribution implementation MUST have, which it
MAY have, and which it MUST NOT have, so that affordance gaps are
classifiable without re-deriving from structural first principles each
time.*

*Updates to this doc are architectural acts and should be treated as such.*

---

## 1. What this doc is

This is the Supply chain tier contract — the operational complement to the
substrate's two existing supply-chain documents:
`docs/SUPPLY-CHAIN-MANIFEST.md` (the public-asset Subresource Integrity
manifest for browser-loaded scripts and stylesheets, the partial spoke this
contract generalizes from) and the substrate-binary supply chain commitments
currently implicit in `Cargo.lock` and the open-source repository. This
document makes both slices explicit in the contract's Required / Optional /
Forbidden form and names the conformance target for affordances not yet
implemented.

The structural motivation: an attacker who can substitute a malicious binary
for the substrate's release artifact undermines every downstream claim. The
chain that malicious binary produces may pass internal integrity verification
while encoding adversary-controlled state. Supply chain integrity is the
precondition for every other tier's guarantees — before the substrate is
even running, the operator must be able to verify that what they installed
is what was specified. The Supply chain tier is what makes "the substrate
that produced this chain is the substrate that was specified" a structurally
checkable assertion rather than a trust assumption.

Several Required affordances are currently aspirational in the
implementation: release signing (Required #3), reproducible-build attestation
(Required #4), install-time verification (Required #5), and transparency log
entries (Required #7). The contract names the conformance target; substrate-
readiness work brings the implementation up to the contract. This is the
same pattern as the External anchor tier's `NoOpAnchor` framing: the
structural commitment is what the contract specifies; the current posture
is the explicit starting point, not the destination.

This document is the spoke for Tier 11 in
`docs/SUBSTRATE-CONFORMANCE-CONTRACT-2026-06.md` — the final spoke in the
tier taxonomy. It covers both slices as one coherent contract: the public-
asset Subresource Integrity slice for browser-loaded resources and the
substrate-binary slice for Rust binaries and release artifacts. Most Required
and Forbidden affordances apply equally to both slices; most Optional
affordances extend the binary slice specifically.

---

## 2. The category statement

The Supply chain tier covers implementation-integrity semantics — what makes a
substrate's distribution conformant for downstream operators to verify what
they are installing and running. Every other tier assumes the substrate is
behaving as specified; this tier is what makes that assumption checkable. The
four substrate claims, the eight principles, the gate, the chain — none of
these structural commitments survive a compromised distribution pipeline. An
operator who installs a binary they cannot independently verify has placed
their trust in the distribution pipeline itself, which is exactly the class
of trust assumption the substrate is designed to make structural rather than
disciplinary.

The tier operates in two coordinated slices. The public-asset slice covers
browser-loaded resources: every external script and stylesheet the substrate
ships in HTML must carry a Subresource Integrity hash that the browser
enforces before execution. The substrate-binary slice covers the Rust
binaries and installer artifacts that operators download, install, and run:
each release must be signed with a Genesis-derived identity key, recorded
in a publicly verifiable append-only transparency log, and accompanied by a
reproducible-build attestation that allows independent reconstruction. Both
slices share the same structural commitments: verification before trust,
explicit posture declaration, no silent substitution path.

---

## 3. Required affordances

An implementation lacking any of these cannot serve as a conformant substrate
distribution. The fallback when this tier's commitments are absent is a
distribution whose integrity rests on trust in the pipeline rather than
structural verification — which is not conformant for a substrate whose
entire value proposition is structural trust.

**1. Pinned dependency manifest with content hashes.** Every direct and
transitive dependency the substrate's build consumes must be pinned to a
specific version and content hash in a committed manifest. For the Rust
workspace, this is `Cargo.lock` at the repository root, with every crate
pinned by version and checksum. For any other language ecosystems the
substrate's distribution includes — JavaScript (public-asset slice),
Python components, native libraries — the equivalent manifest must be
present: `package-lock.json` with package integrity hashes, `pip` with
`--require-hashes`, or equivalent. No implicit "latest" version resolution
at build time or install time. A build that can resolve differently on
different days is not reproducible and cannot be attested. **P1, P4.**

**2. Public-asset Subresource Integrity for all browser-loaded external
resources.** Every external `<script>` and `<link rel="stylesheet">` in
HTML the substrate ships must carry an `integrity=` attribute containing the
SHA-384 hash of the bytes the browser is expected to execute, plus the
corresponding `crossorigin=` attribute. The `docs/SUPPLY-CHAIN-MANIFEST.md`
tracks the pinned URLs and SHA-384 hashes; the
`no_external_script_without_integrity` discipline pin in
`crates/zp-discipline/tests/` enforces at build time that no HTML file
carries an external resource reference without a matching integrity attribute.
The browser refuses to execute bytes that don't match the pin. SRI converts
the assertion "please send us the right bytes" into an enforced invariant:
trust is structural, not requested. **P1, P4.**

**3. Signed release binaries via the Genesis-derived identity key.**
Each released binary — Rust artifact, installer, library — must carry a
detached signature from the substrate's Genesis-derived identity key. This
is the `singular_sovereign_root` principle applied to the release-signing
boundary (`docs/SINGULAR-SOVEREIGN-ROOT-2026-05.md`): there is no separate
"release key" with its own credential-store entry and its own lifecycle,
derived or maintained independently of the operator's Genesis root. The
same cryptographic identity that signs canonical chain receipts signs the
release binaries. A downstream operator who holds the substrate's public
key can verify both the chain's receipts and the release binary in one
verification pass against one identity. A separate release key would
require the downstream operator to establish the release key's relationship
to the operator's identity separately — an unnecessary trust dependency that
P2 and the singular-sovereign-root principle both prohibit. **P1, P2.**
*(Aspirational: not yet implemented in the current release process.)*

**4. Reproducible-build attestation with documented residual non-determinism.**
The substrate's release process must produce a signed attestation naming a
specific source commit, `Cargo.lock`, and build flags, and asserting that
those inputs produce a specific binary hash. Verifiers who can replicate the
build environment and reproduce the named inputs should obtain the same
binary hash. Sources of non-determinism that the build process controls —
embedded build timestamps, randomized symbol ordering, build-host path
strings embedded in the binary — must be eliminated or excluded from the
hash domain. Residual non-determinism that affects only artifacts outside the
running binary's behavior (debug symbols, embedded metadata that the binary
does not read at runtime) is acceptable if explicitly documented in the
attestation. A substrate that does not attempt reproducibility is
non-conformant; a substrate that attempts reproducibility and documents the
residual sources of non-determinism is conformant. **P1.**
*(Aspirational: not yet implemented in the current release process.)*

**5. Install-time integrity verification with explicit posture attestation.**
Before the substrate binary executes, the install process must either verify
the binary's hash against the signed release attestation and confirm success,
or explicitly attest that verification was not performed and why (operator
choice at first install, constrained environment, etc.). The operator may
choose to install without verification — contact does not commit (P7) applies
to first install as much as anywhere else — but the substrate must not hide
which mode was selected. A silent install that performs neither verification
nor explicit posture declaration is forbidden. The verification-or-attest
requirement is what makes the install posture auditable: an operator's chain
can record which mode was used and with what result. **P1, P7.**
*(Aspirational: not yet implemented in the current install tooling.)*

**6. Source-code transparency at the pinned commit.** The source code
corresponding to every released binary must be publicly accessible at the
exact commit hash named in the release attestation. Any party who obtains the
source at that commit and follows the named build flags should be able to
reproduce the binary (subject to Required #4's reproducibility commitment).
The ZeroPoint repository at `github.com/zeropoint-foundation/zeropoint` is
the current canonical source; it provides public access, commit immutability
backed by Git's content-addressing, and audit logs. GitHub is the current
operational platform; it is not itself a trust anchor — the substrate's
authority derives from the Genesis-derived signing key and the content-addressed
source commit, not from GitHub's URL or platform availability. Adopters who
require stronger source-availability guarantees (geographic diversity,
resistance to platform-level access restriction) may mirror the repository to
IPFS-pinned archives, Radicle, or other content-addressed systems; that is a
stronger posture, not a Required one. Binaries with no traceable source commit
are not conformant. **P3.**

**7. Transparency log entry per release with structural commitments met.**
Each release must be recorded in a publicly verifiable, append-only,
queryable log before the release is distributed. The structural commitments
are: publicly verifiable (any third party can query the log and confirm the
entry exists), append-only (entries cannot be deleted or modified, by design
rather than by policy convention), and queryable (the log supports lookup
by release identifier and time range). Sigstore/Rekor is the reference
implementation — its append-only Merkle tree provides inclusion proofs that
any party can verify independently of the log operator. GitHub Releases
provides append-only semantics by platform convention rather than by structural
cryptographic commitment; it satisfies this affordance as a weaker fallback
(see §7 portability sketches) but Sigstore/Rekor or equivalent cryptographic
log is the conformance target. **P1, P3.**
*(Aspirational: not yet implemented in the current release process.)*

**8. No undeclared runtime dependencies.** The substrate's running process
must not load executable code, scripts, plugins, or data from sources not
declared in the pinned manifest. Every component loaded at runtime traces to
a pinned dependency entry, a chain-anchored artifact, or an explicit operator
action that the chain records. Implicit loading paths — auto-discovered plugin
directories, ambient configuration scripts, network-fetched code invoked
during startup, auto-update mechanisms that replace components without user
confirmation — are not conformant. Runtime dependency loading that the
manifest cannot enumerate produces a substrate whose actual behavior diverges
from what the manifest attests. **P4.**

---

## 4. Optional affordances

Each optional affordance improves the distribution's integrity assurance or
operational convenience without changing what conformant supply-chain
commitment means.

**Specific signing tool and format.** Cosign with Sigstore (the reference),
GPG detached signatures, plain Ed25519 signatures with a custom verification
tool, or any other signing system that satisfies the structural commitments
in Required #3 (signed by the Genesis-derived identity key, publicly
verifiable) is conformant. The tool is operator choice; the structural
commitment is not.

**Specific reproducible-build framework.** Nix derivations, Bazel hermetic
builds, `cargo build --frozen --locked` with a controlled build environment,
`cargo vendor` with a vendored dependency tree, or any other framework that
achieves the reproducibility commitment with documented residuals is
conformant. Each carries different operational trade-offs; the contract is
framework-neutral.

**Specific transparency log.** Sigstore/Rekor (the cryptographic reference),
custom Merkle-tree logs, Certificate Transparency adaptations, GitHub
Releases (weaker posture, append-only by policy), or other publicly verifiable
append-only systems are conformant if they meet the structural commitments
in Required #7. The specific log is operator choice within those constraints.

**SBOM generation.** Software Bill of Materials in SPDX or CycloneDX format
published alongside releases. Useful for downstream auditing, vulnerability
triage, license compliance checks, and regulatory reporting. Not a substrate-
correctness requirement; an operational hygiene enrichment.

**Vulnerability scanning of dependencies.** Periodic checks of the pinned
manifest against advisory databases (RustSec, npm audit, CVE feeds) with
results published as part of release attestation. The manifest pins what was
known-good at release time; scanning detects vulnerabilities disclosed after
the pin. Orthogonal to the integrity proof.

**Multi-party release signatures (M-of-N quorum).** Quorum-signed releases
as a higher-assurance posture, composing with the quorum-sovereignty
architecture in `docs/design/quorum-sovereignty.md`. Single-signer is
conformant; M-of-N quorum is optional enrichment for deployments where
single-key compromise risk is unacceptable. The infrastructure for quorum
signing at the release boundary must be structurally possible without
redesigning the signing path (see Forbidden #7).

**in-toto / SLSA provenance attestations.** Structured build provenance
beyond the basic reproducible-build attestation — naming the build
environment, the builder identity, each pipeline stage's inputs and outputs.
SLSA (Supply-chain Levels for Software Artifacts) provides a graduated
conformance framework; the substrate targets the structural commitments in
Required #4 as the minimum. Higher SLSA levels are optional enrichment for
operators with regulatory or contractual requirements.

**CI-enforced reproducible-build verification.** Building the substrate twice
in different CI environments and comparing hashes before release; rejecting
the release if hashes diverge. This operationalizes Required #4 with a
structural check rather than a manual attestation and is recommended for
production release processes. Without this affordance, reproducibility is
attested by process discipline; with it, it is enforced by the release
pipeline.

**Release announcement on chain.** Each release also produces a chain entry
on the substrate's operator chain attesting "we released binary X with
signature Y at transparency-log entry Z at time T." This makes release
history queryable from the chain itself, not only from the transparency log
or the repository's release page. Composes with the Operator substrate's
Receipt sub-layer and optionally with the External anchor tier (Optional #9
in that contract) for cross-anchored release attestations.

---

## 5. Forbidden affordances

The Forbidden category at the Supply chain tier is calibrated against one
structural failure mode: silent substitution. A distribution pipeline that
allows the bytes an operator installs to differ from the bytes the distributor
published — without the operator knowing — is the failure class this tier
exists to prevent. The substrate uses dependency managers, package registries,
signing infrastructure, and build tooling extensively; the Forbidden entries
below name specific distribution practices that produce the silent substitution
failure mode at this tier, regardless of whether the practices are common in
the broader software ecosystem.

**1. Unsigned binary distribution.** Releasing binaries without a verifiable
signature from the Genesis-derived identity key — including releases
distributed through channels that are individually trusted (the GitHub
releases page, an official website download link, a package manager registry)
— is forbidden. The channel is not the signature; the channel's authority
is a separate trust model that doesn't derive from the substrate's own
Genesis key. An operator who verifies the signature can confirm the release's
provenance independently of the distribution channel's trustworthiness.
**P1.**

**2. Silent install without explicit verification posture declaration.**
Install processes that neither verify the binary hash against the signed
attestation nor explicitly attest that verification was not performed are
forbidden. The operator may choose to install without verification — P7
(contact does not commit) applies here; a first install is contact, not
commitment — but the substrate must surface the choice explicitly. "I
verified and confirmed" and "I installed without verifying" are both
conformant postures; "I installed and produced no record of whether I
verified" is not, because it prevents the operator from auditing their
own install posture after the fact. **P1, P7.**

**3. Opaque dependencies in the substrate's critical path.** Dependencies
whose source, version, or content hash cannot be independently verified —
binary-only packages, closed-source SDKs that participate in signing,
chain-handling, or receipt-production logic — are forbidden. If a dependency
in the critical path cannot be reconstructed from source at the pinned
version and hash, the reproducible-build attestation cannot be confirmed and
the manifest cannot enable the operator to independently verify what they
installed. **P3, P4.**

**4. Build pipelines that produce non-identical binaries for identical
inputs.** Non-determinism in the build process that originates from sources
the build controls — embedded build timestamps read from the system clock,
randomized symbol ordering, build-host filesystem paths compiled into the
binary — is forbidden. These are not constraints the build environment
imposes; they are choices the build process makes. Eliminating them or
excluding them from the hash domain is tractable. A build pipeline that
introduces these sources and makes the reproducible-build attestation
structurally impossible to confirm is non-conformant. **P1.**

**5. Source-binary divergence.** A released binary built from a source
commit different from the one named in the release attestation, or with
build flags different from those named, is forbidden. The source commit
named in the attestation must produce the released binary when rebuilt with
the named flags. A release where the attestation names commit `abc123` but
the binary was built from commit `def456` is a false attestation — not
merely an operational oversight but a structural break in the verification
path that any verifier who attempts to reproduce the build will detect.
**P1.**

**6. Mutable release artifacts after publication.** Replacing a published
binary with different bytes under the same release identifier — "hotfix
overwrites," silent corrections, emergency patches applied without a new
log entry — is forbidden. Each new binary hash is a new release with its
own log entry, its own signature, and its own transparency log record.
The transparency log's append-only property is what makes historical release
verification possible; mutating the artifact while preserving the old log
entry produces a log entry that no longer matches the distributed binary.
**P1, M3.**

**7. Signing infrastructure that structurally precludes multi-party release
signing.** A substrate distribution whose release-signing process structurally
precludes M-of-N quorum signing — because the key derivation, key storage, or
signing protocol assumes exactly one signer at every step — is not conformant
for high-assurance deployments. Single-signer is conformant and is the default;
quorum must be structurally possible without redesigning the signing
infrastructure. This is the supply-chain expression of the one-canonical-path
principle: the signing path must accommodate both single-signer and quorum
postures without the posture choice requiring an architectural rework. **P3.**

**8. Direct dependency on closed-source signing service whose internals are
unknown.** Using an HSM whose firmware is not publicly auditable but whose
signing API and output are inspectable and verifiable is conformant — the
verification path is transparent even if the hardware implementation is not.
Using a signing service whose internal behavior, key storage, or signing logic
are opaque and unverifiable, and whose output cannot be independently confirmed
against any public standard, is not conformant. The signing path is load-
bearing for the entire distribution's integrity claim; an opaque step in that
path is a center of uncheckable trust. **P3.**

**9. External script loading without SRI hash verification.** Already enforced
structurally by the `no_external_script_without_integrity` discipline pin in
`crates/zp-discipline/tests/`; this entry is the contract-level naming of the
same commitment. Any `<script src="">` or `<link rel="stylesheet">` in HTML
the substrate ships that references an external URL without a matching
`integrity=` attribute (SHA-384 or stronger) and `crossorigin=` attribute is
forbidden. The sole current exemption — Google Fonts CSS, whose bytes vary by
User-Agent — is documented in `docs/SUPPLY-CHAIN-MANIFEST.md` and its scope
is intentionally narrow. **P1, P4.**

**10. Time-of-check-to-time-of-use vulnerability in install verification.**
Verifying the binary's hash at one point and executing a different binary
loaded at a different point — with a window between verification and execution
during which substitution is possible — is forbidden. The check and the load
must be atomic, or the binary must be integrity-checked again at execution
time, or the window must be structurally closed by the install environment.
A TOCTOU gap in install verification produces a conformant-looking install
log while allowing the actual executing binary to be substituted. **P1.**

---

## 6. Composition with principles

The Supply chain tier is the tier where more principles carry simultaneous
load-bearing weight than any other. Six of the eight principles do substantive
structural work here, because the distribution pipeline is the first point
at which any of the substrate's other guarantees can be undermined.

**P1 (signing is gravity) is the foundational principle for the entire tier.**
Signed release binaries (Required #3), signed reproducible-build attestations
(Required #4), signed transparency log entries (Required #7) — every
verification path the operator can take begins with a signature. Forbidden
#1, #4, #5, #6, and #10 all protect P1 at this tier: unsigned releases, non-
reproducible builds, false attestations, mutable artifacts, and TOCTOU gaps
all produce situations where a signature existed but failed to bind what the
operator actually installed. Signing is not gravity if the signed artifact
can be replaced by the time it is executed.

**P2 (identity is a key, not a location) is the structural basis for Required
#3.** The release signer is the substrate's Genesis-derived identity — not a
release-specific key tied to a specific infrastructure deployment, not a
delegated key whose relationship to the operator's Genesis must be separately
established. An operator who verifies the release signature against the
operator's public key has confirmed that the same Genesis-rooted identity
that will sign the chain's receipts also signed the binary. If a separate
release key existed, it would be a second identity — and the distribution
channel (GitHub, a CDN, a package registry) would be the de facto authority
that binds the release key to the operator, which is exactly the kind of
location-based identity P2 prohibits.

**P3 (there is no center) is the structural basis for Required #6, Required
#7, and Forbidden #3, #7, and #8.** Source-code transparency ensures the
verification path doesn't require trusting any single platform's claim about
the source. Transparency logs with structural append-only properties ensure
the verification path doesn't require trusting any single log operator's
claim about immutability. No opaque critical-path dependencies, no
structurally-precluded quorum signing, no closed-source signing services:
each of these forbids a center forming in the distribution pipeline that
would make the verification path dependent on a single party's honesty.

**P4 (every bit counts) is the structural basis for Required #1, Required
#2, Required #8, and Forbidden #3 and #9.** Every dependency pinned with
a content hash, every browser-loaded script carrying an SRI attribute, no
implicit runtime components — these are P4 applied to the distribution rather
than to the chain. Every component in the distribution that cannot be
independently verified is a bit that earns its place through trust rather
than through cryptographic necessity. The SRI hash, the `Cargo.lock`
checksum, the absence of implicit loading paths — all of these make the
distribution's component set verifiable by construction rather than by
assertion.

**P7 (contact does not commit) appears at this tier in its first-install
form.** The operator's first encounter with the substrate is contact; it must
not silently commit to trusting the binary. Required #5 and Forbidden #2
operationalize this: the install process must surface the verification posture
explicitly, and the operator's choice — verify or attest the no-verification
decision — must be recorded. An install that produces no record of whether
verification was performed has made the install itself a silent commitment
rather than a transparent choice. P7 at the distribution tier is the reason
a `NoOpAnchor`-style posture (explicit declaration of no verification) is
conformant, while silent installation without declaration is not.

**P8 (one canonical path) justifies Required #3's singular-sovereign-root
grounding and Forbidden #7's prohibition on structurally-precluded quorum.**
There is one canonical signing path for the substrate's distribution: the
Genesis-derived identity key, via the singular sovereign root, accessible
either as a single-signer or as a quorum. Multiple independent signing keys
for releases — one for CI, one for the maintainer, one for releases from a
specific build environment — are a multi-path distribution whose paths can
diverge. P8 is why the singular-sovereign-root principle applies to the
release boundary as it does to the chain-signing boundary.

**The Supply chain tier makes the substrate itself verifiable.** The four
substrate claims, the eight principles, and every adjacent tier's conformance
guarantee all presuppose that the substrate behaving as specified is a
meaningful claim. This tier is what makes it checkable: an operator who
verifies the release signature, confirms the transparency log entry, and
reproduces the build has structural evidence that what they installed is what
was specified. Without this tier's commitments, the entire downstream
architecture rests on trust in the distribution pipeline, which is not a
structural guarantee.

---

## 7. Portability sketches

The contract is tool-neutral and framework-neutral. These six sketches name
the current state and the conformance target along with trade-offs.

**Current state — Rust + Cargo + GitHub (partially conformant).** `Cargo.lock`
pins all Rust dependencies with version and checksum (Required #1 satisfied).
Public-asset SRI via `SUPPLY-CHAIN-MANIFEST.md` and the
`no_external_script_without_integrity` discipline pin (Required #2 satisfied).
Source at `github.com/zeropoint-foundation/zeropoint` (Required #6 satisfied
operationally via GitHub). Release signing (Required #3), reproducible-build
attestation (Required #4), install-time verification (Required #5), and
transparency log entries (Required #7) are aspirational. The current state
is the named starting point; the contract names the conformance target.

**Cosign + Sigstore + Rekor (reference target for binary slice).** `cosign sign`
signs the release binary's digest with the Genesis-derived Ed25519 key; the
signature is published to the Rekor append-only Merkle tree. Any party can
run `cosign verify` against the Rekor entry to confirm the signature and the
binary's digest. Satisfies Required #3 (signed), Required #7 (cryptographic
transparency log, publicly verifiable, append-only, queryable). Pairs
naturally with Optional #7 (SLSA provenance) and Optional #8 (CI-enforced
reproducible-build verification).

**Nix-based reproducible build.** Nix derivations specify inputs deterministically
and produce byte-identical outputs across build environments, eliminating the
primary sources of non-determinism (timestamps, path-based non-determinism,
ambient system state). A Nix build provides Required #4 by construction
rather than by process discipline. Operational trade-off: Nix toolchain is
heavier to maintain than `cargo build`; the reproducibility guarantee is
stronger. Pairs with Cosign for signing and Rekor for transparency to cover
all Required affordances in the binary slice.

**GitHub Releases as transparency log (weaker posture).** GitHub Releases
provides an append-only surface by platform convention: releases are versioned,
each artifact is hosted at a stable URL, and the release page maintains a
changelog. This satisfies the "publicly verifiable" and "queryable" structural
commitments for Required #7 but satisfies "append-only" by policy rather than
by cryptographic commitment. A GitHub admin can delete or replace a release
artifact; Rekor's Merkle tree cannot be modified after the entry is included.
GitHub Releases is conformant as a fallback when cryptographic transparency
infrastructure is unavailable, with the understanding that the transparency
guarantee is weaker. Operators who require stronger guarantees should use
Rekor or equivalent.

**GPG-signed releases + RFC 9162 Certificate Transparency log.** GPG detached
signatures satisfy Required #3 if the signing key derives from the Genesis
root per the singular-sovereign-root requirement. RFC 9162 Certificate
Transparency (the standard underlying web PKI's CT logs) provides a
cryptographic append-only log satisfying Required #7's structural commitments.
This stack is mature and well-understood; operational trade-off is the GPG
key management complexity and the CT log infrastructure overhead relative to
Sigstore's OIDC-based key handling.

**Self-built from source with `cargo build --frozen --locked`.** An operator
who builds the substrate themselves from the verified source commit at the
pinned `Cargo.lock` state is exercising the strongest trust posture. The
`--frozen` flag prevents `Cargo.lock` from being updated; `--locked` requires
all dependencies to match the lockfile exactly. The reproducible-build
attestation is what enables this path: the operator's locally-produced hash
should match the signed release hash, giving them structural confirmation that
their build matches the distributed release. Self-built from source is the
gold standard for operators who cannot accept any trust in the distribution
pipeline.

---

## 8. Autoregressive update triggers

1. **A new release-signing tool is adopted.** If the substrate switches from
   GPG to Cosign, or from Cosign to a different signing infrastructure, this
   document's Required #3 portability implications and §7 portability sketches
   should be updated to name the new tool and confirm the structural
   commitments hold.

2. **A new transparency log is adopted.** If the substrate adds Rekor alongside
   GitHub Releases, or adopts a different append-only log, this document should
   be updated to name the new log in Required #7 and add a portability sketch.
   Each new log also changes the current-state conformance assessment in §7.

3. **A new dependency ecosystem is added to the substrate.** If the substrate
   gains a Python component, a native library, or any other ecosystem requiring
   its own manifest format, Required #1 should be updated to name the manifest
   format and pinning mechanism for that ecosystem.

4. **A Required affordance proves hard to implement portably.** If reproducible-
   build attestation (Required #4) proves structurally infeasible for a target
   platform or architecture — perhaps because the platform's toolchain introduces
   non-determinism that cannot be controlled — the question is whether to
   document the residual as an accepted exception or to accept that the target
   platform's distribution is partially conformant.

5. **A Forbidden affordance is proposed for relaxation.** If someone proposes
   "allow unsigned debug builds distributed through internal channels," this
   document is what the proposal must justify against. Debug builds that are
   not distributed externally and never run in production contexts may warrant
   a conformance note rather than a Forbidden entry; builds that reach any
   operator's production environment must meet Required #3.

6. **A supply-chain attack pattern surfaces that reveals an unnamed failure
   mode.** The SolarWinds pattern (compromised build pipeline producing
   conformant-looking but adversary-controlled binaries), the xz-utils pattern
   (compromised maintainer key producing a legitimate-looking signed release),
   and similar attacks each reveal a supply-chain failure mode not captured
   in the Forbidden category at the time they occurred. If a new attack pattern
   surfaces that the current Forbidden category does not cover, the category
   should be updated.

7. **A new principle is added to Architecture Part V½.** Each new principle
   may add new Forbidden entries or make existing Optional affordances Required.

---

## 9. Refs

- `docs/handoffs/supply-chain-tier-affordance-pass-2026-06.md` — the
  architectural-decisions source; the Required / Optional / Forbidden partition
  this contract synthesizes
- `docs/SUPPLY-CHAIN-MANIFEST.md` — the existing partial spoke for the public-
  asset SRI slice; the current implementation of Required #2
- `docs/SUBSTRATE-CONFORMANCE-CONTRACT-2026-06.md` — the hub contract;
  §4 Tier 11 entry ("Supply chain tier"); §5 contract template
- `docs/SINGULAR-SOVEREIGN-ROOT-2026-05.md` — the identity-binding commitment
  Required #3 derives from; release signing uses the same Genesis-derived
  key as chain-receipt signing
- `docs/design/quorum-sovereignty.md` — M-of-N quorum signing composing with
  Optional #6
- `docs/EXTERNAL-ANCHOR-TIER-CONTRACT-2026-06.md` — release announcements may
  be externally anchored (Optional #9 composition)
- `docs/EDGE-TIER-CONTRACT-2026-06.md` — the contract template exemplar
- `docs/STORAGE-TIER-CONTRACT-2026-06.md`, `docs/VERIFIER-TIER-CONTRACT-2026-06.md`,
  `docs/EXTERNAL-ANCHOR-TIER-CONTRACT-2026-06.md` — flat-list contract
  structure exemplars
- `docs/handoffs/discipline-pin-audit-2026-06.md` — the structural enforcement
  inventory; the `no_external_script_without_integrity` pin is in the existing
  set and enforces Required #2
- `crates/zp-discipline/tests/no_external_script_without_integrity.rs` —
  current structural enforcement of Required #2 (public-asset SRI)
- `Cargo.lock` (workspace root) — current implementation of Required #1
  (pinned Rust dependency manifest with content hashes)
