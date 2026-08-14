# Security Policy

Thank you for helping keep ZeroPoint secure. If you believe you've found a security vulnerability, please report it responsibly.

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

Instead, email: **ken@thinkstreamlabs.ai**

Include in your report:
- **Subject line**: "ZeroPoint Security: [Brief description]"
- **Description**: What you found and why it's a security concern
- **Steps to reproduce**: How to verify the vulnerability
- **Impact**: What an attacker could accomplish if this were exploited
- **Your contact information**: Preferred way to reach you

## What Qualifies as a Security Issue

We take the following seriously:

### Cryptographic Vulnerabilities
- Weaknesses in elliptic curve cryptography, hashing, or key derivation
- Nonce reuse, bias, or predictability in random number generation
- Side-channel attacks (timing, power analysis, cache)
- Incorrect cryptographic primitive usage

### Policy Engine Bypasses
- Methods to circumvent HarmPrincipleRule or SovereigntyRule evaluation
- Ways to inject malicious policies that pass validation
- Logic flaws in policy composition or precedence

### Chain Integrity Weaknesses
- Attacks on ledger immutability or consistency
- Consensus mechanism bypasses
- Merkle proof or commitment validation failures

### WASM Policy Module Escapes
- Escapes from the WebAssembly sandbox that hosts **policy modules**
- Memory safety violations in module execution
- Fuel-exhaustion or trap behaviour that changes a policy outcome

Note the scope: wasmtime sandboxes *policy modules*, not agent code. Agent-directed
code runs as an OS subprocess (`crates/execution-engine/`), whose isolation is
`unshare --net --pid --fork` on Linux and, by default, none on macOS. Weaknesses
there are execution-sandbox issues, not WASM issues, and §6 of the threat model
already records that filesystem confinement is unimplemented.

### Constitutional Constraint Violations
- Bypasses of the HarmPrincipleRule
- Bypasses of the SovereigntyRule
- Methods to weaken policy enforcement

## What We Won't Consider Security Issues

The following are **not** security issues:

- **Deployment misconfigurations**: Insecure setup by operators (e.g., weak TLS, exposed keys)
- **Issues in forks**: Problems in unofficial branches or modifications
- **Social engineering**: Attacks that target people, not systems
- **Denial of service through resource exhaustion**: Unless there's a specific protocol flaw
- **Documentation or process problems**: Report these as regular issues

## Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 7 days
- **Proposed fix or mitigation**: Within 30 days (or timeline negotiated with reporter)
- **Public disclosure**: Coordinated with you

## Responsible Disclosure

We commit to:
1. Treating your report confidentially
2. Working with you to understand the issue
3. Developing a fix in a private branch
4. Coordinating disclosure timing with you
5. Crediting you publicly (unless you prefer anonymity)

We ask that you:
1. Don't publicly disclose until we've had time to fix it
2. Provide reasonable time for us to respond and patch
3. Don't exploit the vulnerability beyond verification
4. Work with us in good faith

A typical timeline is 90 days from initial report to public disclosure, but we'll negotiate based on the severity and complexity of the issue.

## Threat Model

**Read this first: [`docs/design/THREAT-MODEL-2026-08.md`](./docs/design/THREAT-MODEL-2026-08.md).**

It states the single invariant ZeroPoint claims, enumerates adversary classes by cost to mount, lists the trusted computing base component by component, and — most relevant to a reporter — publishes both what we do not defend against (§5) and where the invariant currently fails (§6).

The invariant, in short:

> Every action crossing the ZeroPoint host boundary produces a signed, hash-chained receipt verifiable by a party that trusts neither the agent nor the harness that produced it.

An issue is in scope if it breaks that sentence. Please check §5 and §6 before reporting — §6 in particular is a published list of known gaps, and a report that rediscovers one of them is welcome but will be closed as known rather than treated as a new finding.

## What We Already Know Is Broken

Publishing known gaps is deliberate. A trust layer that hides them has a category problem, not a marketing problem. The current list lives in [`THREAT-MODEL-2026-08.md`](./docs/design/THREAT-MODEL-2026-08.md) §6 and includes, as of August 2026: in-process advisory enforcement, chain append as a companion rather than a precondition of the effect, WASM policy module errors failing open, `Warn`/`Review` decisions auto-approving, self-asserted trust tiers, no external anchor backend, and no filesystem confinement in the execution sandbox.

Remediation is sequenced in [`HOST-BROKER-2026-08.md`](./docs/design/HOST-BROKER-2026-08.md) §10.

## Constitutional Context

ZeroPoint is designed to prevent harm. If you discover a way that the system could be misused to:
- Enable surveillance
- Violate autonomy or self-determination
- Undermine integrity guarantees
- Weaken transparency mechanisms

...please report it as a security issue. These are fundamental to our design.

## Public Acknowledgment

Once a fix is deployed, we will:
- Publish a security advisory
- Credit you publicly (unless you request anonymity)
- Update the security changelog

## Questions?

If you're unsure whether something qualifies as a security issue, email us. It's better to report and have us clarify than to hold back.

---

**Security contact**: ken@thinkstreamlabs.ai
**Last updated**: August 2026
