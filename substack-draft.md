# Trust is Infrastructure: ZeroPoint's Developer Course is Live

We talk about AI safety a lot. Alignment, values, red-teaming, constitutional AI. But we often miss something fundamental: the infrastructure layer.

Most agent governance today is bolted on after the fact. A framework ships with a capability list. A layer of monitoring sits on top. You wire in some rules. It feels like safety, but the system wasn't born with governance—it's a feature you add, patch, and hope works correctly.

I started ZeroPoint because I think that's backwards.

Agents need cryptographic governance built into their identity from day one. Not as an afterthought. Not as a plugin. As infrastructure.

Today, I'm announcing that ZeroPoint's developer course is live. And with it comes everything you need to ship agents that are verifiable, auditable, and genuinely trustworthy.

## What shipped

**The SDK Developer Course** is a 4-hour, self-paced journey through ZeroPoint from the CLI up. No Rust required. It covers:

- Bootstrapping an agent identity with `zp init`
- Issuing scoped capability keys—because agents don't need all permissions all the time
- The 5-layer constitutional gate stack: who can act, what can they do, what guardrails apply, how do we log it, and how do we verify that log
- Writing custom WASM governance gates if the built-ins aren't enough
- Generating and verifying tamper-evident audit chains
- Integrating with the HTTP API

Six modules, hands-on. You'll leave understanding not just how to use ZeroPoint, but why each layer exists.

**The Internals Course** is for the people who want to go deeper. 20 hours, 14 modules. Rust level. It covers key hierarchies, capability grants, delegation chains, the policy engine, the adversarial model, reputation systems, consensus, epoch compaction, and how the whole thing fits together. If you're building governance infrastructure or auditing systems that claim to be secure, this is for you.

Both are live now at [zeropoint.global/course-sdk.html](https://zeropoint.global/course-sdk.html) and [zeropoint.global/course.html](https://zeropoint.global/course.html).

**The CLI now has real governance.** `zp gate eval`, `zp audit log`, `zp audit verify`—they all use the real GovernanceGate and AuditStore. SQLite-backed. Hash-chained for tamper evidence. The chain-head-sync bug is fixed, so audit chains stay valid across CLI invocations. What you see is what actually happened.

**WASM policy modules.** `zp policy load`, `zp policy list`, `zp policy verify`, `zp policy remove`. Full lifecycle management for custom governance gates. You can author policies in Rust, compile them to WASM, load them into an agent, and verify that the agent is actually enforcing what you wrote.

**Sovereign distribution via NomadNet.** ZeroPoint runs on the Reticulum mesh network. The binary is hosted on a ZeroPoint node at `89.167.86.60:4243`. BLAKE3 verification hash included. No DNS lookups. No CDN. No certificate authority. If you want to deploy agents in environments where the internet infrastructure is contested—or just want to opt out of it—you can.

## Why this matters

Agents are eating software. Not as a metaphor. Right now. The tools we build today will shape what's possible tomorrow.

But agency without governance is just drift. You can't trust what you can't verify. And you can't verify what wasn't designed to be verified from the start.

ZeroPoint's bet is simple: governance isn't a policy layer you bolt on. It's infrastructure. It's built into cryptographic identity. It's checked at every gate. It's logged immutably. And it can be audited by anyone, anytime.

The design philosophy is this: **Trust is Infrastructure.**

That means:
- **Cryptographic identity.** Ed25519 key hierarchies. Agents have provable identities.
- **Governance gates.** Constitutional, operational, and custom WASM gates. You decide what an agent can do and under what conditions.
- **Tamper-evident audit trails.** Hash-chained receipts. If someone claims "this never happened," you can prove them wrong.
- **Mesh networking.** Dual-backend Presence Plane. Agents can discover and communicate with each other over Reticulum without relying on centralized infrastructure.

It works with any framework. Anthropic's SDK, OpenAI's API, open source models, custom systems. ZeroPoint is governance for the agent, not a framework itself.

## Getting started

If you want to try it:

1. **Start the course.** [zeropoint.global/course-sdk.html](https://zeropoint.global/course-sdk.html). 4 hours, hands-on. You'll ship a governed agent by the end.

2. **Clone the repo.** [github.com/zeropoint-foundation/zeropoint](https://github.com/zeropoint-foundation/zeropoint). `cargo install --path crates/zp-cli` to get the CLI.

3. **Try the CLI.** Bootstrap an agent, issue some keys, evaluate a gate:
   ```
   zp init
   zp keys issue --name my-agent --capabilities "tool:read"
   zp gate eval "tool:filesystem:read" --resource "/data/test.csv"
   ```
   You'll see what real governance looks like.

4. **Check the audit trail.** `zp audit log` and `zp audit verify`. See that every decision was logged, signed, and chained.

5. **Join the mesh.** NomadNet is growing. Connect to the ZeroPoint node and talk to other governed systems.

The repo is open source. MIT license. The community is small but sharp—people who care about actually building trustworthy systems, not just talking about it.

## The bet

Here's what I think happens next:

Agents become ubiquitous. They run infrastructure. They manage money. They coordinate networks. And at some point, the question stops being "can we build agents?" and becomes "can we trust them?"

That's when governance becomes the constraint that unlocks possibility. Right now, it feels like overhead. Soon, it'll be the thing that lets you deploy with confidence.

ZeroPoint is the infrastructure for that moment.

Star the repo. Take the course. Deploy a governed agent. Or just follow along as we build this.

The code is yours. The philosophy is open. Trust shouldn't require a middleman.

—Ken

P.S. If you're at a company thinking about agent governance, you should talk to us. We're building the primitives that every serious agent system will eventually need. Reach out.
