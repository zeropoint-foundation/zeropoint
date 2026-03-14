# Contributing to ZeroPoint

Welcome. ZeroPoint is a trust infrastructure project, and that means something important: contributions to this codebase carry responsibility. The code you write here will form the foundation of systems that respect constitutional boundaries, protect autonomy, and enforce the principle that harm should never be instrumentalized. We take that seriously, and we hope you do too.

## Getting Started

Clone the repository and get up to speed quickly:

```bash
git clone https://github.com/zeropoint-foundation/zeropoint.git
cd zeropoint
cargo test --workspace
cargo clippy
```

If all tests pass and clippy is quiet, your environment is set up correctly.

## Where to Contribute

ZeroPoint is organized into focused crates:

- **zp-core**: The foundational types, cryptographic primitives, and the Four Tenets model
- **zp-audit**: Comprehensive audit logging and forensics
- **zp-policy**: The policy engine that evaluates rules against constitutional constraints
- **zp-trust**: Trust scoring and reputation mechanisms
- **zp-pipeline**: GovernanceGate: Guard → Policy → Execute → Audit sequence
- **zp-server**: Axum HTTP API server
- **zp-llm**: LLM integration layer
- **zp-skills**: Skill/capability registry and management
- **zp-learning**: Adaptive learning and feedback mechanisms
- **zp-mesh**: Mesh networking primitives and distributed communication
- **zp-receipt**: Receipt building, signing, hashing, and verification
- **execution-engine**: Sandboxed command execution environment
- **zp-cli**: Command-line interface and user-facing tools
- **zp-keys**: Key hierarchy, signing, and cryptographic identity
- **zp-introduction**: Cross-node trust establishment protocols
- **trust-triangle**: Reference implementation of the Trust Triangle pattern
- **default-gate**: Tier 0 default policy module (permissive baseline)

Each crate has clear boundaries and responsibilities. When you're considering a contribution, understand which crate owns the concern you're addressing.

## Code Standards

We maintain high quality standards:

- **Rust version**: Stable channel only. No nightly features.
- **Formatting**: All code must pass `cargo fmt --workspace`
- **Linting**: All code must pass `cargo clippy --workspace -- -D warnings` (no warnings)
- **Tests**: All tests must pass with `cargo test --workspace`
- **Documentation**: Public APIs must be documented. Examples help.

Zero warnings is non-negotiable. If you see a warning in CI, the PR won't merge.

## Pull Request Process

1. **Fork** the repository and create a branch from `main`
2. **Name your branch** descriptively: `feature/policy-rule-for-x` or `fix/chain-integrity-check`
3. **Write your code** following the standards above
4. **Push to your fork** and open a PR against `main`
5. **Describe what and why** in your PR description, not just what. Link related issues.
6. **Address feedback** in conversation. We may ask questions or request changes.
7. **Sign-off**: All commits must include sign-off (`git commit -s`)

PRs that are incomplete, failing CI, or don't explain their purpose will not be merged.

## What We're Looking For

Contributions that strengthen ZeroPoint are welcome:

- **Transport integrations**: New transport backends that maintain the abstraction layer
- **Policy rule implementations**: Additional HarmPrincipleRule, SovereigntyRule, or DataIntegrityRule specializations
- **Testing and fuzzing**: Property-based tests, fuzzing harnesses, edge case coverage
- **Documentation**: Architecture guides, tutorials, threat model analysis, security considerations
- **Security review**: Careful audits of cryptographic assumptions, sandbox boundaries, policy evaluation logic

## What We Won't Accept

Some contributions, no matter how well-written, cannot be merged:

- **Surveillance tooling**: Capabilities designed to enable monitoring of people without consent
- **Bypass mechanisms**: Code that weakens, circumvents, or bypasses the HarmPrincipleRule or SovereigntyRule
- **Constitutional violations**: Changes that contradict the Four Tenets or reduce their enforceability
- **Weaponization features**: Functionality designed to enable harm at scale

If you're uncertain whether a contribution fits this category, open an issue to discuss it before investing time.

## The Four Tenets as Community Standards

ZeroPoint is built on four foundational commitments:

1. **Do No Harm**: The system must never serve surveillance, coercion, or violation. Neither should our community.
2. **Respect Sovereignty**: Autonomy and self-determination are sacred. We respect different viewpoints and approaches.
3. **Integrity First**: Everything is auditable and verifiable. Our discussions should be honest and evidence-based.
4. **Transparency**: The mechanisms and reasoning should be understandable. We explain our decisions clearly.

These principles apply to how we build together. Refer to the [ZeroPoint Whitepaper](https://zeropoint.global/whitepaper) for the complete vision.

## Security Issues

If you discover a security vulnerability, **do not open a public issue**. See [SECURITY.md](./SECURITY.md) for responsible disclosure procedures.

## Code of Conduct

This project adheres to a code of conduct grounded in the Four Tenets. See [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md) for expectations and how we handle violations.

## License

ZeroPoint is dual-licensed under MIT and Apache 2.0. By contributing, you agree that your contributions will be made available under these licenses.

## Questions?

Reach out to **ken@thinkstreamlabs.ai** with questions about contribution process, architectural decisions, or the project's direction. We're here to help you succeed.

---

Thank you for considering ZeroPoint. Building trustworthy systems requires trustworthy people. We're glad you're here.
