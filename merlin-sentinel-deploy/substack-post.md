# Dogfooding ZeroPoint: My Router Now Governs Itself

I built ZeroPoint to bring cryptographic governance to autonomous systems. Today I'm going to tell you about the first place I deployed it: my home router.

Not a cloud cluster. Not a Kubernetes pod. An ASUS RT-AX58U running Merlin firmware in my barn, connected to an AT&T gateway that barely cooperates. If ZeroPoint's governance model can work here — on a 32-bit ARM processor with 256MB of RAM, running Python on a USB stick — it can work anywhere.

## The problem nobody talks about

Every device on your home network is making decisions without you. Your smart plugs phone home to Chinese cloud servers. Your IoT devices resolve domains you've never heard of. New devices appear on your network and you have no idea what they are or what they're doing.

Most people either don't know this is happening, or know and feel powerless to stop it. The tools that exist — Pi-hole, AdGuard Home — are good at blocking ads. But they're not *governing* your network. They don't create tamper-evident records of every decision. They don't evaluate threats through a policy pipeline. They don't push to your phone when something suspicious happens at 2am.

## What the Sentinel does

The ZeroPoint Network Sentinel is a Python service that runs on Merlin routers via Entware. Every DNS query, every device connection, every anomaly flows through a governance pipeline:

**Guard** checks blocklists and rate limits. **Policy Engine** evaluates rules and assigns trust tiers. **Audit Store** records every decision in a hash-chained SQLite database — each entry contains the SHA-256 hash of the previous entry, creating a tamper-evident chain you can verify at any time. **Notifier** dispatches alerts to syslog, a log file, and optionally pushes to your phone via Ntfy.

The key insight: the act of *notifying* you is itself an auditable, hash-chained event. There's a governed record not just that a threat occurred, but that you were told about it.

## What I learned from dogfooding

The first version was a silent guardian. It logged everything but told me nothing. I realized this is an anti-pattern — if a security tool doesn't come to you, it doesn't exist. Most people install monitoring software, feel good about it, and never check the logs.

So I made "observable by default" the design principle. Out of the box, the Sentinel writes to syslog and an alert file. Add one URL to the config and it pushes to your phone. Silent mode is an explicit opt-in for headless deployments — not the default.

The notification tiers map directly to the governance gate's risk levels. A routine ad-domain block? Log it, don't bother anyone. A DGA-looking domain burst from an IoT device? Push immediately. A persistent threat that hasn't been acknowledged? Repeat every five minutes until someone pays attention.

## Why this matters for ZeroPoint

ZeroPoint is a set of cryptographic governance primitives designed for autonomous agent systems. The core concepts — policy evaluation, trust tiers, hash-chained audit trails, governed decision pipelines — are abstract until you see them running on something real.

The Merlin Sentinel is the first *onramp*. You install it because you want network visibility and control. ZeroPoint's governance model comes with it. Every module in the Sentinel maps directly to ZeroPoint's Rust primitives: `GovernanceGate`, `Guard`, `PolicyEngine`, `AuditStore`, `PolicyDecision`. If you understand how the Sentinel governs your router, you understand how ZeroPoint governs autonomous agents.

This is the strategy: build tools that solve problems people already have, and let the governance model prove itself through use. The router sentinel is the first. A LangChain plugin for agent governance is next. Then more — wherever autonomous systems make decisions that affect people.

## Try it

The Sentinel is open source and installs in one command on any Merlin router with Entware:

```
curl -fsSL https://raw.githubusercontent.com/zeropoint-foundation/zeropoint/main/tools/merlin-sentinel/install.sh | sh
```

You'll need an ASUS router running Merlin firmware and a USB drive for Entware. The README walks through everything, including push notifications via Ntfy.

GitHub: [zeropoint-foundation/zeropoint](https://github.com/zeropoint-foundation/zeropoint)

If the idea of governed infrastructure resonates — whether for your home network, your agent pipelines, or your organization's autonomous systems — I'd love to hear from you. ZeroPoint is building the trust layer for the Agentic Age, and every onramp we build makes that layer more real.

---

*Ken Romero is the founder of ThinkStream Labs and creator of ZeroPoint. He writes about cryptographic governance, autonomous systems, and building trust infrastructure from the ground up.*
