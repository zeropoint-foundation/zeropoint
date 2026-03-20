>ZeroPoint SDK Developer Course

`F7ebTrack 2 — Ship a Governed Agent in an Afternoon`f

-

>Course Overview

*Prerequisites:* A terminal. Rust toolchain for building ZeroPoint.
No Rust literacy required — this uses only CLI and HTTP API.

*Duration:* ~4 hours self-paced

*Outcome:* You bootstrap a ZeroPoint environment, issue agent keys,
evaluate actions through the governance gate stack, install custom
WASM gates, verify audit chains, and integrate via HTTP API. You
understand ZeroPoint's developer vocabulary and can govern any
agentic system.

-

>Course Philosophy

Each module follows the same structure:

1. *Concept* — What you're doing and why it matters
2. *Do it* — Run commands, read output, understand what happened
3. *Checkpoint* — Prove you understood by doing something slightly
   different

The modules are sequential. Each builds on the previous.
The whole track takes an afternoon.

-

>Module 1: Bootstrap

**Concept**

`zp init` generates your cryptographic identity, seals five
constitutional governance gates into the runtime, and writes a genesis
record that anchors your trust chain. After this command, you exist in
the ZeroPoint universe.

**Do it**

```
$ zp init
```

You should see:

```
  ZeroPoint Genesis
  ─────────────────
  Generating operator keypair...        ✓ Ed25519
  Sealing constitutional bedrock...     ✓ 5 gates installed
  Writing genesis record...             ✓ ~/.zeropoint/genesis.json

  Operator identity: 2008570f...
  Constitutional hash: b1e466...

  Your environment is ready.
  Run `zp keys issue` to create your first agent key.
```

Check what was created:

```
$ ls ~/.zeropoint/keys/
$ cat ~/.zeropoint/genesis.json | head -5
$ cat zeropoint.toml
```

The genesis record contains your operator's public key, the
constitutional hash, and a timestamp. This is your root of trust.

**ZeroPoint Home Resolution**

Keys and governance state live at `~/.zeropoint/` by default.
ZeroPoint resolves its home through a three-step chain:

1. `ZP_HOME` env var — explicit override for CI, Docker, production
2. `zeropoint.toml` key_path — project-level config
3. `~/.zeropoint/` — default for local development

**Checkpoint**

Run `zp keys list`. You should see genesis and operator keys present,
zero agents. If not, check error output and contents of `~/.zeropoint/`.

-

>Module 2: Agent Keys

**Concept**

Your operator identity is yours. Agents get their own keys — scoped,
expiring, revocable. The delegation chain links every agent key back to
your genesis through cryptographic signatures: genesis → operator →
agent. No trust is assumed. Every link is verified.

**Do it**

Issue a key for a research agent:

```
$ zp keys issue --name scout --capabilities "tool:read,llm:query"
```

You should see:

```
  Issuing Agent Key
  ─────────────────
  Generating agent key...              ✓ Ed25519
  Writing to keyring...                ✓ .zeropoint/keys/agents/scout.json

  Agent:        scout
  Public key:   784af05deeb5146a...
  Capabilities: tool:read, llm:query
  Expires:      90 days

  Delegation chain: genesis → operator → scout
```

Issue a second agent with different capabilities:

```
$ zp keys issue --name writer --capabilities "tool:write,tool:read" --expires-days 30
```

Check the keyring:

```
$ zp keys list
```

Look at the raw certificate chain:

```
$ cat ~/.zeropoint/keys/agents/scout.json
```

That JSON contains three certificates — genesis, operator, and agent —
each signed by the level above. Anyone with the genesis public key can
verify the entire chain without contacting any server.

**Checkpoint**

Issue three more agent keys with different capability sets and
expiration periods. Then revoke one:

```
$ zp keys revoke <name>
```

Run `zp keys list` again and confirm the count decreased. Real revocation
in a distributed system requires publishing revocation to peers
(that's a Track 3 topic).

-

>Module 3: The Gate Stack

**Concept**

Every action in a ZeroPoint-governed system passes through a stack of
gates before it executes. The stack has four layers:

1. *Constitutional bedrock* — two immutable rules that enforce
   foundational principles. These cannot be removed. They are the floor.

2. *Operational gates* — three immutable rules that enforce practical
   governance. Also compiled into the runtime.

3. *Custom WASM gates* — modules you install. These implement your
   policies: rate limits, cost caps, scope restrictions, compliance
   rules. They run in a sandbox with no I/O access.

4. *DefaultAllowRule* — the fallback. If nothing blocked or warned,
   the action proceeds.

The most restrictive decision wins. If any gate blocks, the action is
blocked. If any gate warns and none blocks, you get a warning. Only if
every gate allows does the action proceed cleanly.

**Do it**

See what gates are installed:

```
$ zp gate list
```

You should see the five constitutional gates, no custom WASM gates,
and the DefaultAllowRule fallback.

Evaluate an action:

```
$ zp gate eval "tool:filesystem:read" --resource "/data/reports/q4.csv"
```

Every gate should pass. You'll see a receipt hash — a BLAKE3 fingerprint
of this evaluation, timestamped and unique.

Try something the gates should scrutinize:

```
$ zp gate eval "tool:filesystem:write" --resource "/etc/passwd"
$ zp gate eval "credential:access" --resource "db-production"
```

**Checkpoint**

Evaluate at least five different actions across different categories:
reads, writes, executes, API calls, credential accesses. Note which
gates fire for each. Build a mental model of how the gate stack triages
different action types.

-

>Module 4: Custom Gates

**Concept**

The constitutional bedrock protects against catastrophic harm. Your
operational policies — cost caps, rate limits, compliance rules,
org-specific restrictions — live in WASM gates. A WASM gate is a
compiled module that receives a policy context and returns a decision.
It runs in a sandbox: no filesystem, no network, no clock. Pure
evaluation logic.

**Do it**

*Option A: Install a pre-built gate*

```
$ zp gate add path/to/cost-cap.wasm
```

*Option B: Write your own*

Create a new Rust library:

```
$ cargo new --lib my-gate && cd my-gate
```

Add to `Cargo.toml`:

```
[lib]
crate-type = ["cdylib"]
```

Write `src/lib.rs`:

```rust
#[no_mangle]
pub extern "C" fn evaluate(action_type: i32, _trust_tier: i32) -> i32 {
    if action_type == 4 {
        return 5;
    }
    1
}
```

Compile and install:

```
$ cargo build --target wasm32-wasi --release
$ zp gate add target/wasm32-wasi/release/my_gate.wasm
```

Now evaluate again:

```
$ zp gate eval "tool:execute" --resource "python"
$ zp gate list
```

Your custom gate should appear in the gate stack output.

**Checkpoint**

Write or obtain two WASM gates with different rules. Install both.
Evaluate an action that one allows and the other blocks. Verify that
the block wins. Then evaluate an action that both allow. This is the
composition model: the most restrictive voice wins.

-

>Module 5: The Audit Chain

**Concept**

Every gate evaluation produces a receipt. Receipts are hash-chained —
each one references the previous, forming an append-only log that's
tamper-evident. If anyone modifies a receipt after the fact, the chain
breaks. This is your evidence layer.

**Do it**

Run evaluations to generate audit entries:

```
$ zp gate eval "tool:filesystem:read" --resource "/data/safe.txt"
$ zp gate eval "tool:filesystem:write" --resource "/tmp/output.json"
$ zp gate eval "tool:execute" --resource "python"
$ zp gate eval "credential:access" --resource "api-key-weather"
```

Check the audit log:

```
$ zp audit log --limit 10
```

Verify the chain's integrity:

```
$ zp audit verify
```

If the chain is valid, every entry's hash matches its content, and every
entry's prev_hash matches the previous entry's hash. No gaps, no
tampering.

**How the Chain Stays Valid Across Invocations**

Each `zp gate eval` creates a fresh GovernanceGate, but the audit chain
lives in a persistent SQLite database. Before evaluating, the CLI reads
the store's latest hash and sets it as the gate's chain head. The new
entry's `prev_hash` then correctly points to the previous entry,
maintaining an unbroken chain.

**Checkpoint**

Run 20 evaluations with varied actions. Check the audit log. Verify
the chain. Think about what happens at scale — thousands of evaluations
per hour across a fleet of agents. This is where epoch compaction
(Track 4) becomes necessary.

-

>Module 6: The HTTP API

**Concept**

The CLI is for operators. Agents talk to ZeroPoint through the HTTP API.
The core endpoint is `POST /api/v1/evaluate` — it takes an action
description and returns a gate decision with a receipt. This is how you
integrate ZeroPoint into any agentic system, regardless of language or
framework.

**Do it**

Start the server:

```
$ zp serve
```

In another terminal, hit the evaluate endpoint:

```
$ curl -s http://localhost:3000/api/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "action": "tool:filesystem:read",
    "trust_tier": "Tier1"
  }' | jq .
```

You should get back a JSON response with the decision, rationale, applied
rules, and an audit entry ID.

Try a higher-risk action:

```
$ curl -s http://localhost:3000/api/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "action": "credential:access",
    "trust_tier": "Tier0"
  }' | jq .
```

Check the audit chain through the API:

```
$ curl -s http://localhost:3000/api/v1/audit/entries | jq .
$ curl -s http://localhost:3000/api/v1/audit/verify | jq .
```

**Checkpoint**

Write a simple script (bash, Python, etc.) that:

1. Evaluates 10 different actions through the HTTP API
2. Collects all receipt IDs
3. Verifies the audit chain through the API
4. Prints a summary: allowed, warned, blocked

This script is the skeleton of a governance sidecar. Any agent
framework — OpenClaw, Agent Zero, LangGraph, CrewAI — can call this
endpoint before executing an action.

-

>What You've Built

In about four hours, you went from zero to:

• A cryptographic identity anchored by a genesis key
• Agent keys with scoped capabilities and delegation chains
• A five-layer constitutional gate stack with custom WASM extension
  points
• A tamper-evident audit chain with hash-linked receipts
• An HTTP API that any agent framework can call

You didn't write Rust (unless you chose to). You used a CLI and an API
— the same tools you'd use in production.

-

>What Comes Next

*Track 3: Internals* teaches the Rust crate-level API — for builders
who want to embed ZeroPoint directly, write custom policy engines, or
understand cryptographic primitives. ~20 hours.

*Track 4: Operator* covers production deployment — epoch compaction,
key ceremony procedures, retention policies, monitoring, and
fleet-scale mesh governance.

`F7ebTrust is Infrastructure. Now go build on it.`f

-

[Visit zeropoint.global`zeropoint.global]
[GitHub: zeropoint-foundation/zeropoint`https://github.com/zeropoint-foundation/zeropoint]
