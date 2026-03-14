# Track 2: SDK Developer

## ZeroPoint Developer Course — Ship a Governed Agent in an Afternoon

**Prerequisites:** A terminal. Rust toolchain (for building ZeroPoint). No Rust literacy required — this track uses only the CLI and HTTP API.
**Duration:** ~4 hours self-paced
**Outcome:** You bootstrap a ZeroPoint environment, issue agent keys with scoped capabilities, evaluate actions through the governance gate stack, install a custom WASM gate, verify your audit chain, and integrate via the HTTP API. You understand ZeroPoint's developer vocabulary and can govern any agentic system.

---

## Course Philosophy

This track teaches ZeroPoint the way you'll actually use it: from the command line and the HTTP API. You won't write Rust unless you choose to. Every module follows the same structure:

1. **Concept** — What you're doing and why it matters (one paragraph, not three)
2. **Do it** — Run the commands. Read the output. Understand what happened.
3. **Checkpoint** — Prove you understood by doing something slightly different

The modules are sequential. Each builds on the previous. The whole track takes an afternoon.

---

## Module 1: Bootstrap

### Concept

`zp init` generates your cryptographic identity, seals five constitutional governance gates into the runtime, and writes a genesis record that anchors your trust chain. After this command, you exist in the ZeroPoint universe.

### Do it

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

Now look at what was created:

```
$ ls ~/.zeropoint/keys/
agents/          genesis.json     genesis.secret   operator.json    operator.secret

$ cat ~/.zeropoint/genesis.json | head -5
```

The genesis record contains your operator's public key, the constitutional hash (a BLAKE3 fingerprint of the five immutable gates), and a timestamp. This is your root of trust.

Check your project directory too:

```
$ cat zeropoint.toml
```

This is your project-level configuration. The `key_path` tells ZeroPoint where to find the keyring.

### Where does ZeroPoint live?

By default, keys and governance state live at `~/.zeropoint/` — one identity per machine, shared across projects. But ZeroPoint resolves its home through a three-step chain, first match wins:

1. **`ZP_HOME` env var** — explicit override. Use in CI, Docker, or production.
2. **`zeropoint.toml` key_path** — project-level config. ZeroPoint walks up from your working directory looking for this file.
3. **`~/.zeropoint/`** — the default for local development.

```
# Local dev — uses ~/.zeropoint/ automatically
$ zp keys list

# CI pipeline — keys come from a mounted secret
$ ZP_HOME=/run/secrets/zeropoint zp keys list

# Per-project isolation — set key_path in that project's zeropoint.toml
```

You don't have to think about this until you need it.

### Checkpoint

Run `zp keys list`. You should see genesis and operator keys present, zero agents. If you don't, something went wrong with init — check the error output and the contents of `~/.zeropoint/`.

---

## Module 2: Agent Keys

### Concept

Your operator identity is yours. Agents get their own keys — scoped, expiring, revocable. The delegation chain links every agent key back to your genesis through cryptographic signatures: genesis → operator → agent. No trust is assumed. Every link is verified.

### Do it

Issue a key for a research agent that can read data and query LLMs:

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

Now issue a second agent with different capabilities and a shorter lifespan:

```
$ zp keys issue --name writer --capabilities "tool:write,tool:read" --expires-days 30
```

Check the keyring:

```
$ zp keys list
```

You should see genesis, operator, and two agents.

Look at the raw certificate chain:

```
$ cat ~/.zeropoint/keys/agents/scout.json
```

That JSON contains three certificates — genesis, operator, and agent — each signed by the level above. Anyone with the genesis public key can verify the entire chain without contacting any server.

### Checkpoint

Issue three more agent keys with different capability sets and expiration periods. Then revoke one:

```
$ zp keys revoke <name>
```

Run `zp keys list` again and confirm the count decreased. Think about what "revoke" means here — the key material is deleted from your keyring. Any copy of the certificate chain that exists elsewhere is still cryptographically valid, but won't appear in your keyring. Real revocation in a distributed system requires publishing the revocation to peers (that's a Track 3 topic).

---

## Module 3: The Gate Stack

### Concept

Every action in a ZeroPoint-governed system passes through a stack of gates before it executes. The stack has four layers:

1. **Constitutional bedrock** — two immutable rules that enforce foundational principles (HarmPrincipleRule, SovereigntyRule). These cannot be removed or overridden. They are the floor.
2. **Operational gates** — three immutable rules that enforce practical governance (CatastrophicActionRule, BulkOperationRule, ReputationGateRule). Also compiled into the runtime.
3. **Custom WASM gates** — modules you install. These implement your policies: rate limits, cost caps, scope restrictions, compliance rules. They run in a sandbox with no I/O access.
4. **DefaultAllowRule** — the fallback. If nothing blocked or warned, the action proceeds.

Together, the constitutional bedrock and operational gates form five native gates that are always present. The most restrictive decision wins. If any gate blocks, the action is blocked. If any gate warns (and none blocks), the action gets a warning. Only if every gate allows does the action proceed cleanly.

### Do it

First, see what gates are installed:

```
$ zp gate list
```

You should see the five constitutional gates, no custom WASM gates, and the DefaultAllowRule fallback.

Now evaluate an action:

```
$ zp gate eval "tool:filesystem:read" --resource "/data/reports/q4.csv"
```

Every gate should pass. You'll see a receipt hash — that's a BLAKE3 fingerprint of this evaluation, timestamped and unique.

Now try something the gates should scrutinize more carefully:

```
$ zp gate eval "tool:filesystem:write" --resource "/etc/passwd"
```

And something that involves credentials:

```
$ zp gate eval "credential:access" --resource "db-production"
```

### Checkpoint

Evaluate at least five different actions across different categories: reads, writes, executes, API calls, credential accesses. Note which gates fire for each. The constitutional gates always run, but their decisions may differ based on what you're asking to do. Build a mental model of how the gate stack triages different action types.

---

## Module 4: Custom Gates

### Concept

The constitutional bedrock protects against catastrophic harm. Your operational policies — cost caps, rate limits, compliance rules, org-specific restrictions — live in WASM gates. A WASM gate is a compiled module that receives a policy context and returns a decision. It runs in a sandbox: no filesystem, no network, no clock. Pure evaluation logic.

### Do it

If you have the Rust toolchain and the `wasm32-wasi` target installed, you can write a gate from scratch. If not, you can install a pre-built one.

**Option A: Install a pre-built gate**

```
$ zp gate add path/to/cost-cap.wasm
```

**Option B: Write your own**

Create a new Rust library:

```
$ cargo new --lib my-gate && cd my-gate
```

Add to `Cargo.toml`:

```toml
[lib]
crate-type = ["cdylib"]
```

Write `src/lib.rs`:

```rust
/// Gate that blocks any action on sensitive paths.
/// Returns: 1 = Allow, 3 = Warn, 5 = Block
#[no_mangle]
pub extern "C" fn evaluate(action_type: i32, _trust_tier: i32) -> i32 {
    // Block all execute actions (action_type 4)
    if action_type == 4 {
        return 5; // Block
    }
    1 // Allow
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
```

Your custom gate should now appear in the gate stack output, and its decision participates in the most-restrictive-wins composition.

```
$ zp gate list
```

You should see your gate listed under "Custom WASM Gates."

### Checkpoint

Write (or obtain) two WASM gates with different rules. Install both. Evaluate an action that one gate allows and the other blocks. Verify that the block wins. Then evaluate an action that both allow. This is the composition model: the stack is additive, and the most restrictive voice wins.

---

## Module 5: The Audit Chain

### Concept

Every gate evaluation produces a receipt. Receipts are hash-chained — each one references the previous, forming an append-only log that's tamper-evident. If anyone modifies a receipt after the fact, the chain breaks. This is your evidence layer.

### Do it

Run a few evaluations to generate audit entries:

```
$ zp gate eval "tool:filesystem:read" --resource "/data/safe.txt"
$ zp gate eval "tool:filesystem:write" --resource "/tmp/output.json"
$ zp gate eval "tool:execute" --resource "python"
$ zp gate eval "credential:access" --resource "api-key-weather"
```

Now check the audit log:

```
$ zp audit log --limit 10
```

And verify the chain's integrity:

```
$ zp audit verify
```

If the chain is valid, every entry's hash matches its content, and every entry's prev_hash matches the previous entry's hash. No gaps, no tampering.

### How the chain stays valid across invocations

Each `zp gate eval` invocation creates a fresh GovernanceGate, but the audit chain lives in a persistent SQLite database. Before evaluating, the CLI reads the store's latest hash and sets it as the gate's chain head. The new entry's `prev_hash` then correctly points to the previous entry, maintaining an unbroken chain.

If you're reading the Rust internals later (Track 3) and you see `GovernanceGate::new()` used without calling `set_audit_chain_head()`, that's intentional — course labs and tests run in-memory with no persistence, so chain continuity doesn't apply. In production code that persists to an AuditStore, the chain head must always be synced first.

### Checkpoint

Run 20 evaluations with varied actions. Check the audit log. Verify the chain. Then think about what happens at scale — thousands of evaluations per hour across a fleet of agents. This is where epoch compaction (Track 4) becomes necessary: rolling up old entries into a single Merkle proof so the chain doesn't grow without bound.

---

## Module 6: The HTTP API

### Concept

The CLI is for operators. Agents talk to ZeroPoint through the HTTP API. The core endpoint is `POST /api/v1/evaluate` — it takes an action description and returns a gate decision with a receipt. This is how you integrate ZeroPoint into any agentic system, regardless of language or framework.

### Do it

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

You should get back a JSON response with the decision, rationale, applied rules, and an audit entry ID.

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

### Checkpoint

Write a simple script (bash, Python, whatever you prefer) that:

1. Evaluates 10 different actions through the HTTP API
2. Collects all the receipt IDs
3. Verifies the audit chain through the API
4. Prints a summary: how many allowed, warned, blocked

This script is the skeleton of a governance sidecar. Any agent framework — OpenClaw, Agent Zero, LangGraph, CrewAI — can call this endpoint before executing an action. ZeroPoint doesn't care what framework you use. It evaluates the action and returns a decision. The agent respects it or doesn't. The receipt exists either way.

---

## What You've Built

In about four hours, you went from zero to:

- A cryptographic identity anchored by a genesis key
- Agent keys with scoped capabilities and delegation chains
- A five-layer constitutional gate stack with custom WASM extension points
- A tamper-evident audit chain with hash-linked receipts
- An HTTP API that any agent framework can call

You didn't write Rust (unless you chose to in Module 4). You didn't learn a framework. You used a CLI and an API — the same tools you'd use in production.

---

## What Comes Next

**Track 3: Internals** teaches the Rust crate-level API — for builders who want to embed ZeroPoint directly, write custom policy engines, or understand the cryptographic primitives. It covers key hierarchy construction, signing and verification, the credential vault, capability grants, delegation chain invariants, the full governance gate pipeline, receipt chains, audit persistence, and mesh peer communication. 16 modules, ~20 hours.

**Track 4: Operator** covers production deployment — epoch compaction, key ceremony procedures, retention policies, monitoring, and fleet-scale mesh governance.

Trust is Infrastructure. Now go build on it.
