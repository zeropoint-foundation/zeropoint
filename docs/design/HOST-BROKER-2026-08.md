# Host Broker — moving the enforcement point out of the agent's address space

**Document type:** Design note. Elaborates no KEEL section directly — it specifies the enforcement-point relocation that `THREAT-MODEL-2026-08.md` §3.3 names as target state, and is subordinate to that document's §1 invariant.

**Status:** Proposed 2026-08-14, for review. No code written. Phase 0 landed the same day as a discipline pin; Phases 1–5 unbuilt.

**Date:** 2026-08-14.

**Precedent:** `docs/design/WHONIX-LESSONS.md` §3.1–3.2, §4
**Prior art in-tree**: `docs/STRUCTURAL-AUDIT-2026-05.md` (convention vs. invariant), `crates/zp-discipline/` (the test-layer carrier for the same idea)

---

## 1. The invariant this exists to hold

> **A process running agent-directed code cannot cause a host effect — process spawn, file write, network request — except by asking a process it does not control, which records the request in the chain before the effect occurs and refuses if the chain cannot record it.**

Stated in Whonix's fail-closed grammar, so it's testable rather than aspirational:

- **Fails closed** = the effect does not happen and the denial is recorded.
- **Fails open** = the effect happens and no verifiable record of it exists.

Everything below is enforcement of that one sentence. Note what it does *not* claim: it says nothing about the agent's reasoning being correct, nothing about the model resisting injection, and nothing about effects reachable without crossing the boundary. Those are non-goals, listed in §8.

## 2. Why the current shape can't hold it

`zp-host` is well designed and its doc comment is accurate within its scope: no `Command::new` is reachable through its public API. But the boundary is a crate API inside one address space, and the audit shows what that means in practice.

**109 `Command::new` call sites across 27 files in 7 crates. One of them is in `zp-host`.**

Most are benign — fixed-literal capability probes (`ioreg`, `lsusb`, `sysctl`, `which`, `lsof`, `kill`). The governance-relevant subset is the sites where the program name is a **variable**:

| Site | Expression | What it is |
|---|---|---|
| `zp-server/src/lib.rs:6416` | `Command::new(&lc.command)` | tool launch |
| `zp-server/src/auth.rs:1140` | `Command::new(&self.program)` | tool launch |
| `zp-server/src/onboard/preflight.rs:1650` | `Command::new(program)` | preflight launch |
| `zp-server/src/regent.rs:858` | `Command::new("browser-harness")` | Regent spawning a browser agent |
| `zp-regent/src/inference.rs:719,733` | `Command::new("ollama")`, `Command::new("open")` | Regent spawning a model server and opening URLs |
| `zp-cli/src/main.rs:2785` | `Command::new(&command[0])` | arbitrary command from a vector |

These are the governed surface, and none of them crosses `zp-host`. `zp-server/src/regent.rs:858` and `zp-regent/src/inference.rs:719` are the sharpest cases: the apex cognitive agent spawns processes directly, with no gate evaluation and no chain entry.

There is already a discipline pin forbidding `Command::new("sh").arg("-c")` (`no_sh_c_in_tool_launch`), and it works — `tool_launch.rs` exists precisely because that pin forced the fix. But its scope is `restrict_to_paths(&["crates/zp-server/src/"])` and it forbids only *shell* invocation. Removing the shell removed string re-parsing. It did not remove ambient spawn authority.

## 3. Topology

```
┌────────────────────────────────────────────┐
│ AGENT PROCESS  (zp-server, harness, Regent)│   uid: zp-agent
│                                            │
│  model calls · tool dispatch · web UI      │   NO chain write handle
│  policy *hints* (advisory, for UX only)    │   NO signing key
│                                            │   NO credential vault
│  zp_host::Client ──── AF_UNIX SOCK_SEQPACKET
└────────────────────────┬───────────────────┘   NO CAP_* / no spawn
                         │
                    /run/zeropoint/host.sock
                    mode 0600, owner zp-broker
                         │
┌────────────────────────▼───────────────────┐
│ BROKER PROCESS  (zp-hostd)                 │   uid: zp-broker
│                                            │
│  GovernanceGate  ·  AuditStore (writer)    │   the ONLY chain writer
│  CredentialVault ·  Ed25519 signing key    │   the ONLY key holder
│  PolicyRegistry  ·  sandbox construction   │
│                                            │
│  4 methods. No general RPC. No eval.       │
└────────────────────────────────────────────┘
```

Three properties do the work, and each maps to a Whonix mechanism:

1. **The agent process holds no chain write handle.** It cannot forge, skip, or truncate an entry, because it has no path to the file. (Whonix: the Workstation cannot edit the Gateway's nftables.)
2. **The socket is the only channel, and it speaks four verbs.** Not a general RPC surface — four typed messages. (Whonix: onion-grater exposes a whitelist of Tor control commands, not the control port.)
3. **The agent process runs as a uid that cannot spawn what it wants anyway.** Belt and braces: even a broker bypass lands in a uid with no write access to anything that matters. (Whonix: the Workstation has no NIC — bypassing the firewall gains nothing.)

Property 3 is what makes this different from "the same code with an extra hop." Without it, an attacker who gets code execution in the agent process just calls `Command::new` and ignores the broker. With it, the call succeeds and accomplishes nothing.

## 4. Wire protocol

`HostContext` already has exactly the right shape — four methods, typed arguments, no string parsing. That is a smaller and better-specified surface than onion-grater's whitelist, and it is why this is a few weeks of work rather than a rewrite. The trait becomes the wire.

```rust
// zp-host-proto — shared by client and broker, no logic
#[derive(Serialize, Deserialize)]
pub enum HostRequest {
    Spawn      { program: String, args: Vec<String>, cwd: PathBuf,
                 env: BTreeMap<String, String>, sandbox: SandboxConfig,
                 tool_name: String },
    WriteFile  { path: PathBuf, contents: Vec<u8>, mode: Option<u32> },
    HttpRequest{ method: Method, url: Url, headers: HeaderMap,
                 body: Option<Vec<u8>>, credential_ref: Option<CredentialRef> },
    HttpStream { /* as above; response streams back over the socket */ },
}

#[derive(Serialize, Deserialize)]
pub struct HostEnvelope {
    pub request:   HostRequest,
    pub grant:     SignedGrant,      // §5 — replaces the self-asserted tier
    pub conv_id:   ConversationId,   // §6 — correlation, currently lost
    pub nonce:     [u8; 16],
}

#[derive(Serialize, Deserialize)]
pub enum HostResponse {
    Completed { gate_receipt_hash: Hash, result: EffectResult },
    Denied    { gate_receipt_hash: Hash, reason: String },
    Unavailable { reason: UnavailableReason },   // §7 — never means "proceed"
}
```

Three deliberate choices:

- **`SOCK_SEQPACKET`, not a stream.** Message boundaries come from the kernel. No length-prefix framing, so no framing parser, so no framing bug. Whonix caps control commands at 128 bytes for the same reason — the parser is attack surface, so don't have one.
- **`credential_ref`, not a credential.** The agent process names a credential; the broker injects the secret. This is what `ARCHITECTURE.md:731-777` describes as `CredentialInjector` and what `CatastrophicActionRule` currently substitutes for by hard-blocking all `ActionType::CredentialAccess` with the message *"credentials must be injected by the host boundary only."* The broker is that boundary. The rule's message becomes true.
- **`gate_receipt_hash` on every response, including denials.** Non-optional. A response without one is a protocol violation, not a degraded success. Today it is `Option<Hash>` and `None` on audit failure — see §7.

## 5. Grants replace self-asserted tiers

`PolicyContext.trust_tier` is currently a field the caller sets, and `zp-host` hardcodes `TrustTier::Tier1` at all four call sites (`system.rs:59,125,191,242`). Since `TrustTierEnforcementRule` requires ≤ Tier1 for writes and API calls, the boundary self-asserts exactly the tier its own check requires. The check cannot fail.

Across the socket this is no longer expressible. The broker derives the tier from `SignedGrant`:

```rust
// broker side — the agent has no say in this
let grant = self.verify_grant(&env.grant)?;     // zp-keys: Genesis → Operator → Agent
let tier  = grant.effective_tier();             // derived, not asserted
let ctx   = PolicyContext { trust_tier: tier, /* ... */ };
```

The machinery exists — `zp-keys` implements the Genesis → Operator → Agent Ed25519 certificate chain, and `zp-core/src/capability_grant.rs` is the largest file in the repo. The gap is only that the gate reads a struct field instead of a verified grant. Across a process boundary there is no struct field to read, which is the point: **the boundary makes the honest implementation the only implementable one.**

Two cleanups this forces, both currently divergent:

- Document `Tier0..Tier5`. README and `ARCHITECTURE.md` both say 0/1/2; the code has six, and Tiers 3–5 are gated by no rule anywhere in `zp-policy`. `Tier5::is_ceremony()` with non-delegatable enforcement in `CapabilityGrant::delegate()` is a genuine structural invariant and is undocumented.
- Reconcile Sentinel. `tools/sentinel/zp_sentinel/gate.py:21-33` uses `{TRUSTED, UNTRUSTED, UNKNOWN, SUSPICIOUS, BLOCKED}` despite a docstring claiming it maps to the Rust enum. It doesn't, and Sentinel evaluates first-match-wins where Rust uses most-restrictive-wins. Sentinel is already an out-of-process enforcement point — the topology you want exists in the fleet, pointed at DNS instead of at agent actions.

## 6. Ordering: the chain entry is a precondition, not a companion

Current `zp-host` sequence (`system.rs:69-95`, verified):

```
1. gate.evaluate(...)
2. audit_store.append(...)  →  on Err or poisoned lock: warn!(), hash = None
3. if blocked { return GateDenied }
4. spawn                     ←  reached even when step 2 failed
```

Step 4 is reachable when step 2 failed. The effect happens; no record of it exists. `ARCHITECTURE.md:250` claims *"it's structurally impossible to act without a trace"* — this path is the counterexample.

Broker sequence:

```
1. verify_grant                → on failure: Denied, no effect
2. gate.evaluate
3. chain.append(sealed)        → on failure: Unavailable, NO EFFECT, no retry-as-success
4. if blocked { return Denied(hash) }
5. perform effect
6. chain.append(outcome)       → best-effort; the pre-entry already exists
```

The inversion at step 3 is the whole change: **append-failure becomes a refusal instead of a warning.** Step 6 may fail without violating the invariant, because step 3's entry already records that the effect was authorized and attempted — which is the property "no receipt, no proof" was always meant to express.

Also fixed here: every `zp-host` method currently constructs a fresh `ConversationId::new()`, so entries from the host boundary cannot be correlated to the request that caused them. The envelope carries the real one.

## 7. Degradation — the contentious part

Whonix defines fail-closed against a *named* invariant: failing open would mean "connect using the user's real external IP instead." Ours: failing open means the effect happens with no verifiable record.

So: **broker down ⇒ no host effects.** Not degraded-permissive, not queue-and-replay, not "log a warning and continue." `Unavailable` is terminal for that request.

This will be argued about, so the honest accounting:

| Broker state | Agent process behavior |
|---|---|
| Running, gate allows | effect proceeds, two chain entries |
| Running, gate blocks | `Denied` + receipt hash; agent surfaces the denial |
| Running, chain unwritable (disk full, lock poisoned) | `Unavailable`; **no effect**; loud operator alarm |
| Not running / socket absent | `Unavailable`; **no effect**; `zp-server` starts and serves read-only |
| Socket present, broker unresponsive > timeout | `Unavailable`; **no effect** |

That last row matters and it's stolen directly from `zp-trace`'s own analysis, which is already correct in-tree: Goose's hook manager treats spawn error, timeout, and any exit code ≠ 2 as Allow, so *"an attacker who can make the gate slow can make it absent."* A timeout must be a denial. `zp-trace` sets `FailureMode::Closed` as its default for exactly this reason — the crate reached the right conclusion and then couldn't act on it, because a trait installed in the harness's address space can be disabled by the harness. Across a socket, an unresponsive broker is indistinguishable from a hostile one, and both resolve to "no effect."

The staged-open precedent is worth copying too. Whonix's `timesync-fail-closed` restricts the Gateway to a single SOCKS port until time sync succeeds, then transitions automatically — with an explicit carve-out permitting port 9108 so the mode cannot deadlock itself. Broker equivalent: until the chain head verifies and the policy registry loads, permit only `WriteFile` under `$ZP_HOME/data/`, then open to the full four. The carve-out is the same shape and needed for the same reason.

And note what Whonix does with this mode: **ships it off by default and says so.** *"This is not yet enabled by default."* `ZP_BROKER_REQUIRED=0` should ship first, log every request that *would* have been refused, and flip to `1` only once the logs are quiet. Fail-closed you can't turn on is worse than fail-closed you shipped gradually.

## 8. Non-goals

Whonix's most valuable habit is publishing what it doesn't do. This design does not defend against:

- **A compromised broker.** It holds the key, the vault, and the chain. This design relocates trust into a small auditable component; it does not eliminate trust. (Whonix: the Gateway is in the TCB, and *"in the case of onion services, the Whonix-Gateway is ALSO part of the TCB."*)
- **A compromised host or kernel.** Same posture as Whonix's host-trust row: total and unmitigated.
- **A malicious workspace crate in the broker.** `zp-hostd` must be small. Whonix's own note applies: *"Embrace simplicity. Complexity is security's primary adversary."* `zp-server/src/lib.rs` is 312 KB today — the broker must not become that. If it exceeds a few thousand lines, this design has failed.
- **Effects not routed through the four methods.** A tool that opens a raw socket via a linked C library is out of scope for the broker and in scope for the sandbox (§9).
- **Bad agent reasoning.** The broker records and gates; it does not evaluate whether the action was wise.
- **Anything before `ZP_BROKER_REQUIRED=1`.** While it's advisory, it's telemetry.

## 9. The sandbox is a separate, parallel problem

The broker governs *whether* an effect is authorized. The sandbox governs *what the effect can reach once running*. Both are needed; neither substitutes.

`crates/execution-engine/src/sandbox.rs:39-53` is honest in its own doc table: `memory_limit_bytes`, `max_cpu_ms`, `readonly_mounts` are all "Planned." Two concrete defects worth fixing regardless of the broker:

- The Linux wrapper comment says `--mount: new mount namespace (isolated filesystem view)` but the emitted argv is `unshare --net --pid --fork` — **no `--mount`** (`sandbox.rs:180-205`). The child sees the full host filesystem with the invoking user's permissions, while `src/lib.rs:44` claims "Filesystem: tmpdir only, no host access."
- macOS defaults to `use_os_isolation: false`, reducing the wrapper to `perl -e 'alarm N; exec @ARGV'` — a timer, not isolation.

`SandboxCapability` (`ReadSandbox`, `NetConnect`, `SpawnProcess`…) is declared and never translated into OS enforcement; `build_sandbox_wrapper` ignores the capability set entirely. Once the broker constructs sandboxes, that translation has one owner and one place to be correct.

## 10. Migration

Ordered so each phase is independently valuable and independently revertable.

**Phase 0 — ratchet (days).** Land `no_raw_spawn_outside_zp_host` as a discipline pin (§2's variable-program patterns only, current sites allowlisted with named deferrals). Green on day one; new violations fail the build. This is the project's own idiom applied to ambient authority — the mechanism already exists and is mature.

**Phase 1 — close the fail-opens in place (1–2 weeks).** No new processes. Purely in `zp-host` and `zp-pipeline`:
- Chain append becomes a precondition of the effect (§6).
- WASM module error → `Block`, not "no opinion" (`wasm_runtime.rs:328-342`, currently *"We never let a broken WASM module block the pipeline"*).
- Stop auto-approving `Warn`/`Review` (`pipeline.rs:629-631`), or delete the variants until wired.
- Carry the real `ConversationId`.
- Add `--mount`; fix or document the macOS default.

Phase 1 alone makes `ARCHITECTURE.md:250` true. It is the highest value-per-hour work in this document.

**Phase 2 — extract the broker (2–4 weeks).** `zp-host-proto` + `zp-hostd`. `zp_host::Client` implements the existing `HostContext` trait over the socket, so the five dependent crates (`execution-engine`, `zp-cli`, `zp-pipeline`, `zp-server`, `zp-host`) change one constructor call and nothing else. Ship with `ZP_BROKER_REQUIRED=0`.

**Phase 3 — migrate the variable-program sites (2–4 weeks).** The six sites in §2 route through the client. Widen the pin from variable-program to all non-probe spawn. `zp-regent` and `regent.rs:858` first — the apex agent should be the most governed component, not the least.

**Phase 4 — make the bypass pointless (1 week).** Separate uid, socket mode 0600, agent process without write access to `$ZP_HOME/data/`. Flip `ZP_BROKER_REQUIRED=1`. Only now is the §1 invariant actually held.

**Phase 5 — bypass tests.** `zp-discipline` pins are static; these are dynamic:
- Kill the broker mid-run; assert no effect completes.
- Load a policy module that always traps; assert `Block`.
- Fill the chain volume; assert `Unavailable`, not silent success.
- Sandboxed script reads `/etc/passwd` and writes outside the sandbox dir; assert both fail.
- Delay the broker past timeout; assert denial, not allow.

Land them red where they fail, with a README saying what each red test means. Whonix's leak tests were valuable before they passed — the suite *is* the specification, and a red test is a non-arguable statement of where the claim exceeds the code.

## 11. What this earns

After Phase 4, the README claim can be stated in Whonix's form — narrow, testable, and true:

> Every action crossing the ZeroPoint host boundary produces a signed, hash-chained receipt verifiable by a party that trusts neither the agent nor the harness. An agent process cannot produce a host effect without a receipt, because the process holding the effect capability is not the process running agent-directed code. ZeroPoint does not prevent effects reachable without crossing that boundary, and does not claim the agent's reasoning is correct.

Weaker-sounding than *"you can't bypass it because it's structural"* (`ARCHITECTURE.md:721`). Considerably more likely to survive an adversarial reading — which, for a trust layer, is the only kind of reading that counts.
