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

### WASM Sandbox Escapes
- Escapes from the WebAssembly sandbox environment
- Unauthorized access to host resources
- Memory safety violations in module execution

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

ZeroPoint's threat model and security assumptions are detailed in the [ZeroPoint Whitepaper](./v2/docs/whitepaper.md), Section 6: Threat Model and Guarantees.

Refer to this before reporting to ensure the issue is within our scope of protection.

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
**Last updated**: February 2026
