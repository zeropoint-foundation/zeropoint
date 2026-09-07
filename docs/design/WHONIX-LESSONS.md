# Whonix as a Design Precedent for ZeroPoint

**Document type:** Outside-in precedent study. Elaborates no KEEL section — it is the reasoning trail behind `THREAT-MODEL-2026-08.md` and `HOST-BROKER-2026-08.md` rather than a claim about the substrate in its own right. Nothing canonical should depend on it.

**Status:** Reference, 2026-08-14. Frozen at authoring frame; Whonix is an external project and its documentation will drift.

**Date:** 2026-08-14.

**Subject:** architectural patterns worth stealing from Whonix, and the specific places ZeroPoint's current code diverges from them.

**Scope:** architecture only — isolation model, trust boundaries, failure modes, and the documentation practice that keeps them honest. Distribution, governance, and funding are deliberately out of scope.

---

## 0. Why Whonix is the right thing to study

Whonix and ZeroPoint are solving formally similar problems in different domains.

Whonix's problem: *an application inside my system will be fully compromised, and when it is, it must still be unable to reveal the user's IP.*

ZeroPoint's problem: *an agent inside my system will be prompt-injected or subverted, and when it is, it must still be unable to take an ungoverned action.*

Both are **containment under assumed compromise**. Neither is trying to prevent the compromise — Whonix explicitly does not harden the Workstation, and ZeroPoint explicitly does not try to align the model. Both bet everything on the boundary holding after the inside falls.

Whonix has been running that bet in production since 2012 with, by their own careful phrasing, no discovered leak. It is worth understanding exactly *why* — because the reason is narrower and more mechanical than the reputation suggests, and the mechanism transfers directly.

The one asymmetry to keep in mind: Whonix's invariant is about **information not escaping**, and information containment can be made topological. ZeroPoint's invariant is about **actions not happening**, which is harder — an action's effects are the point, so you can't just cut the wire. That difference matters in §5, but it changes less than it first appears.

---

## 1. The single load-bearing idea

Whonix's guarantee does not come from its firewall. This is the most commonly misunderstood thing about the design, and Whonix says so in their own docs, in bold:

> "**Even without Whonix-Gateway Firewall and without Whonix-Workstation firewall, no leaks are possible.** Traffic from Whonix-Workstation can either reach Tor which is running on Whonix-Gateway or no destination at all."
> — [Dev/Technical_Introduction](https://www.whonix.org/wiki/Dev/Technical_Introduction)

Remove every nftables rule from both machines and the invariant survives. What holds it up is the **virtual hardware**: the Workstation VM's only NIC is attached to a VirtualBox Internal Network, a switch fabric with no host-side interface and no uplink. There is no NAT engine, no bridge, no TAP device. The Workstation isn't blocked from the internet — it is *not wired to it*.

The firewall provides transparent proxying and stream isolation. Those are features. The topology provides the guarantee. Delete the features and you lose convenience; you don't lose the invariant.

**The pattern, stated generally: remove the capability, don't police it.** A policy check is a decision made by code that the adversary may also control. A missing wire is not a decision at all.

This is the lens for everything below.

---

## 2. Where ZeroPoint currently sits

I read the tree at `~/projects/zeropoint` against this lens. The finding is unambiguous and worth stating plainly, because the rest of the document depends on it.

**ZeroPoint's enforcement is in-process and advisory.** All three enforcement paths are ordinary synchronous Rust method calls on structs the caller owns:

| Path | Location | Shape |
|---|---|---|
| `Pipeline::handle` | `crates/zp-pipeline/src/pipeline.rs:563` | `self.policy_engine.evaluate(&ctx)` → branch on result |
| `GovernanceGate::evaluate` | `crates/zp-policy/src/gate.rs:306` | returns a `GateResult` **value**; caller must honor it |
| `SystemHostContext::{spawn_process, write_file, http_request}` | `crates/zp-host/src/system.rs` | gate → audit → execute |

`zp-host` is the best of the three and the crate doc is proud of it:

> "The type system makes ambient authority unrepresentable in production call paths: There is no `Command::new` accessible to callers of this crate's public API."
> — `crates/zp-host/src/lib.rs:8-15`

That claim is true and much narrower than it reads. `zp-host` exposes no raw spawn. But **any other crate in the 44-member workspace can `use std::process::Command` directly**, and nothing stops it — no seccomp filter, no namespace, no separate uid, no separate process. The invariant is a coding convention enforced by one crate's API surface.

Compare the two shapes directly:

```
Whonix:     [ Workstation VM ]  ─── no route exists ───X   clearnet
                                     (hypervisor)

ZeroPoint:  [ agent code ] ──calls──> [ gate ] ──> effect
                  │
                  └──── std::process::Command ────> effect     ← same address space
```

`ARCHITECTURE.md:721` makes the strong claim: *"You can't bypass it because it's structural."* Against the code as it stands, that isn't supported. It's one `use` statement.

This is not a criticism of the project's value. ZeroPoint's real, working, genuinely novel contribution is the **evidentiary layer** — Blake3-chained, Ed25519-signed, portable receipts and capability grants with delegation chains. Nothing in Whonix does that; Whonix has no notion of a portable proof of what happened. The problem is that the README and ARCHITECTURE.md currently sell an *enforcement* story that the code delivers as an *observation* story, and Whonix's chief architectural virtue is refusing to do exactly that (§7).

---

## 3. Five patterns, mapped

Whonix's design reduces to five reusable moves. Each is scored against ZeroPoint below.

### 3.1 Remove the capability, don't police it

**Whonix**: Workstation has no external NIC. IP forwarding disabled on the Gateway. Notably — "there is no dependency on routing table modifications," an explicit contrast with VPN kill-switches, whose safety depends on mutable state an attacker with root can mutate.

**ZeroPoint today**: the capability is fully present. `execution-engine`'s sandbox is honest in its own doc comment about what's enforced (`crates/execution-engine/src/sandbox.rs:39-53`): `timeout_ms`, `env_vars`, `use_os_isolation` — enforced. `memory_limit_bytes`, `max_cpu_ms`, `readonly_mounts` — "Planned." The `SandboxCapability` enum (`ReadSandbox`, `NetConnect`, `SpawnProcess`…) is declared and **never translated into OS enforcement** — `build_sandbox_wrapper` ignores the capability set entirely.

Worth flagging one specific gap I verified directly: the Linux wrapper's comment says `--mount: new mount namespace (isolated filesystem view)`, but the emitted argv is `unshare --net --pid --fork` — **no `--mount`** (`sandbox.rs:180-205`). The child gets a full view of the host filesystem with the invoking user's permissions, while `src/lib.rs:44` claims "Filesystem: tmpdir only, no host access." On macOS the default is `use_os_isolation: false`, which reduces the wrapper to `perl -e 'alarm N; exec @ARGV'` — a timer, not isolation.

**The move**: `zp-host`'s `HostContext` trait has exactly four methods — `spawn_process`, `write_file`, `http_request`, `http_request_streaming`. That is a remarkably small surface, and it maps cleanly onto an RPC interface. Making it one — a broker process that holds the gate, the chain, and the credentials, with the agent process holding none of them — converts the boundary from a convention into a topology. The agent process then *has no capability to spawn*, in the same sense the Workstation has no capability to route: not "is denied," but "cannot express the request except by asking the broker."

Add `--mount` (or better, a mount namespace with an explicit bind set) and the sandbox starts matching its own README.

### 3.2 Put the enforcement point where the enforced party can't reach it

**Whonix**: from their attack matrix — RCE with local privilege escalation to root on the Workstation is rated **Safe**, with the reason given as: *"the firewall runs on another (virtual) machine."* Tails fails this same row because root and the firewall share a kernel.

**ZeroPoint today**: the gate, the pipeline, the audit store, the execution engine, and the LLM proxy all run in one `zp-server` binary. Root on that process is root on the enforcer. There is no row 4 to pass.

**The move**: this is the same as §3.1 but stated as a placement rule rather than a capability rule, and it has a cheaper intermediate form than full process split. Sentinel is already an out-of-process enforcement point — it just enforces the wrong thing (network events, not agent actions) with an incompatible vocabulary (see §6). The topology you want already exists in the fleet; it isn't pointed at agent actions yet.

Whonix's own note is relevant to the cost objection: *"Embrace simplicity. Complexity is security's primary adversary. Whonix-Gateway could operate on straightforward hardware like the Raspberry Pi."* The enforcer should be the small, boring, auditable component. Right now `zp-server/src/lib.rs` is 312 KB — larger than the 8000-line `main.rs` that ARCHITECTURE.md §6 criticizes v1 for having.

### 3.3 Squat the resource so misuse can't bind

This is Whonix's cleverest move and the most directly transferable to a single-process codebase.

**Whonix**: to prevent Tor-over-Tor, the `anon-ws-disable-stacked-tor` package dpkg-diverts `/usr/bin/tor` and `/usr/sbin/tor` to no-op dummies, declares `Provides: tor` so apt won't install a real one, and runs `systemd-socket-proxyd` **occupying** `127.0.0.1:9050/9051/9150/9151`. If a user installs Tor anyway, it fails to bind and exits. A misconfiguration becomes a loud startup failure instead of a silent security regression.

**ZeroPoint move — cheap, do this first**: you cannot remove `std::process::Command` from the language, but you can make its use fail the build. A `clippy.toml` with `disallowed-methods` / `disallowed-types` covering `std::process::Command`, `std::fs::write`, `std::fs::File::create`, and direct `reqwest::Client` construction, denied in CI for every crate except `zp-host`, turns "please route through the gate" from a convention into a compile-time gate. Pair it with `#![forbid(...)]`-style crate-level lints and an explicit `#[allow]` with a written justification at each of the handful of legitimate exception sites.

This does not stop a malicious workspace member, and it isn't a security boundary — but it is exactly the right *category* of fix for the current architecture, it costs a day, and it stops the bypass from happening by accident, which is how it will actually happen.

### 3.4 Displace the binary, don't document the flag

**Whonix**: `uwt` uses `config-package-dev`'s `displace` to physically replace `/usr/bin/apt-get`, `curl`, `git`, `gpg`, `ssh`, `wget` and others with wrappers that route through per-application Tor SocksPorts. The real binary is moved to a suffixed path. Underneath, `torsocks.conf` sets `IsolatePID 1` so each process gets its own isolation credentials. Stream isolation therefore applies to a naive `apt-get update` typed by an uninformed user — not only to a correctly configured one.

The contrast Whonix draws is precise. Per-app proxy settings in Tor Browser or Thunderbird are *configured* — a compromised app can change them. `uwt` is *enforced* — the app never sees the unwrapped binary.

**ZeroPoint**: this is the answer to "how do we govern a harness we don't control." The current answer in the README is `@zeropoint/trace` and `@zeropoint/guard` as hook-based integrations. Two problems:

1. Neither package exists. `git grep` finds five hits, all prose — the README diagram plus two design docs that describe them as *"the smallest thing that makes the README true."* The Rust prototype `crates/zp-trace` is thoughtful but is **not a workspace member** and **does not compile** (it references `ReceiptType::ToolCall`, `Status::Observed`, `Status::Allowed`, `Status::Completed`, `Status::Degraded`, `Action::tool_result` — six symbols that don't exist in `zp-receipt`).
2. More importantly, `zp-trace`'s own doc comment already identifies the architectural problem: *"trait integration gives visibility, the process boundary gives enforcement"* — and then chooses trait integration. It also notes, correctly, that Goose disables its hook manager entirely for subagents, and that Goose's hook manager treats spawn error / timeout / any-exit-code-≠-2 as Allow, so *"an attacker who can make the gate slow can make it absent."*

That's the `uwt` insight arrived at independently and then not acted on. **The uwt-shaped move for ZeroPoint is to wrap the harness's tool binaries and MCP server endpoints, not to hook its event lifecycle.** An MCP server that a harness is configured to talk to is a process boundary you already own — the harness cannot un-configure it mid-run the way it can skip a hook. That is also, notably, what `zp-mcp-server` was supposed to be; it doesn't exist in the repo either (`README.md:58`).

Adopting this framing has a pleasant consequence: the trace/guard two-layer story stays true, but "guard" stops meaning "a callback the harness may or may not invoke" and starts meaning "the only endpoint through which the tool is reachable."

### 3.5 Normalize every observable

**Whonix**: hostname `host`, username `user`, timezone UTC, 24-bit color, 1920×1080@60, shared `/etc/machine-id`, identical font list, identical internal LAN IP. All instances look the same, so fingerprint entropy across the population approaches zero. The explicit design choice is a **shared personality** over a per-user virtual one, borrowed from Tor's *anonymity loves company*. They also name the cost honestly: hardening is itself a fingerprint, and *"Whonix prioritizes security hardening whenever these goals conflict."*

**ZeroPoint**: the direct analogue is weak — you're not defending anonymity. But the *inverse* is strong and you're already doing it: receipts are only comparable across harnesses if their shape is canonical. `zp-receipt`'s canonical/signable serialization is the same move pointed the other way — normalize the observable so that instances are *comparable*, rather than so that they're *indistinguishable*. Worth naming explicitly in the docs as a design principle, since it's the thing that makes "portable trust" mean anything.

Where the pattern does transfer literally: the sandbox environment. `executor.rs:220-221` already points `HOME` and `TMPDIR` at the sandbox dir and sets a minimal `PATH`. Normalizing the rest of the execution environment — locale, TZ, hostname, umask — makes sandboxed runs reproducible and makes receipt comparison across nodes meaningful. Cheap, and it's on the way to `--mount` anyway.

---

## 4. Fail-closed: Whonix's definition, and ZeroPoint's actual failure modes

Whonix's definition is worth adopting verbatim because it's precise about what "closed" means:

> "Fails 'closed' means, connection failing without any leak. Nothing goes out to the internet. **Failing 'open' in this context would mean it would fail to connect using Tor and connect using the user's real external IP address instead.**"

Note the structure: fail-closed is defined against a *named specific invariant*, not as a general disposition. You can't evaluate "does it fail closed?" without first fixing what must not happen.

ZeroPoint's failure behavior today is mixed, and the mix is not intentional. Verified paths:

| Path | On failure | Verdict |
|---|---|---|
| `SystemHostContext` on `Block` | returns `HostError::GateDenied`, no spawn | **Fails closed** ✓ |
| `zp-trace`'s `FailureMode` default | `Closed` | **Fails closed** ✓ (but crate doesn't build) |
| WASM policy module error / trap / fuel exhaustion | `None` → "no opinion" → `DefaultAllowRule` permits (`wasm_runtime.rs:328-342`) | **Fails open** — comment reads *"We never let a broken WASM module block the pipeline"* |
| `Warn` / `Review` decisions in the pipeline | auto-approved (`pipeline.rs:629-631`, *"auto-approving in Phase 1"*) | **Fails open** — the graduated model exists in types only |
| Audit append failure or poisoned lock in `zp-host` | `warn!`, `gate_receipt_hash: None`, **spawn proceeds** (`system.rs:69-95`) | **Fails open** |
| Audit append failure in the pipeline | `warn!`, continue (`pipeline.rs:1055-1072`) | **Fails open** |

That third row deserves attention: a WASM policy module that crashes reliably is a module that has been silently disabled. Whonix's inverse is `firewall-common`'s `trap "error_handler" ERR`, which aborts rather than leaving a half-built ruleset.

The last two rows contradict ARCHITECTURE.md's strongest structural claim — *"it's structurally impossible to act without a trace"* (`ARCHITECTURE.md:250`). Today, tracing is best-effort; the side effect happens whether or not the receipt lands. Making the audit append a precondition rather than a companion is a small code change with a large claim attached to it, and it's the single highest-leverage fix in this document relative to effort.

There's also a useful Whonix precedent for *staged* fail-closed. `timesync-fail-closed` restricts the Gateway to only the sdwdate SOCKS port until time sync succeeds, then transitions to full mode automatically — with an explicit carve-out permitting port 9108 so the mode can't deadlock itself. That's a good model for ZeroPoint boot: restrict to a minimal capability set until the policy registry and chain head are verified, then open up. Note also that Whonix ships this mode **off by default** and says so plainly: *"This is not yet enabled by default."* They don't claim the stricter mode as the shipped posture.

---

## 5. Structural identity vs. self-asserted identity

In Whonix, **which machine you are is a fact about the topology.** The Workstation is `10.152.152.11` on an internal network with no uplink. It cannot assert that it is the Gateway; there is nowhere for that assertion to be believed.

In ZeroPoint, `PolicyContext.trust_tier` is a plain field on a struct the caller constructs. It is not verified against a certificate, a grant, or a key. And the values in practice are constants:

- `TrustTier::Tier0` in the pipeline config
- `TrustTier::Tier1` hardcoded at all four `zp-host` call sites (`system.rs:59, 125, 191, 242`)

That second one has an unfortunate interaction. `TrustTierEnforcementRule` (`rules.rs:531-605`) requires ≤ Tier1 for writes and API calls. The host boundary therefore **self-asserts exactly the tier needed to pass its own tier check**, on every call. The check cannot fail.

You already have the machinery to fix this — `zp-keys` implements a Genesis → Operator → Agent Ed25519 certificate chain, and `zp-core::capability_grant` is the largest file in the repo. The gap is that the gate reads the tier from the caller's struct instead of deriving it from a presented, verified grant. Derive it and the tier becomes an attested fact rather than a claim.

Two smaller related notes:

- The code has `Tier0..Tier5`; README and ARCHITECTURE.md both document 0/1/2. Tiers 3–5 are gated by no rule anywhere in `zp-policy`. `Tier5::is_ceremony()` with non-delegatable enforcement in `CapabilityGrant::delegate()` is a genuinely nice structural invariant — the kind of thing this document is about — and it's undocumented.
- Sentinel's `TrustTier` is `{TRUSTED, UNTRUSTED, UNKNOWN, SUSPICIOUS, BLOCKED}` (`tools/sentinel/zp_sentinel/gate.py:21-33`), despite a docstring claiming it "maps to the ZeroPoint Rust trust_tier enum." It doesn't. A Sentinel classification cannot currently be compared against a Core grant. Sentinel also uses first-match-wins rule evaluation where Rust uses most-restrictive-wins — two different semantics for the same named concept.

---

## 6. Scope discipline — the thing to copy first

Whonix's most valuable and least imitated property is that **it claims exactly one thing**:

> "Whonix is designed to prevent direct detection of the IP (**not more!**) even if an adversary has unrestricted access to the Whonix-Workstation."

Everything else in the system is either enforcement of that invariant or fingerprint normalization layered on top. And the disclaimers are equally sharp: *"Whonix does not claim to protect from very powerful adversaries, to be a perfectly secure system, to provide strong anonymity."* They self-describe as *"currently alpha quality software"* — in 2026, fourteen years in.

They publish a **table of things they don't do**: no global-adversary protection, no full-system AppArmor, no user data encryption, no cold-boot/evil-maid defense, no RAM wipe on shutdown, no automatic updates, no stylometry defense, no deterministic builds, and — my favorite entry — no protection for *"User Behavior: Protect those who fail to read the Documentation."*

The payoff is that every claim they *do* make is testable, and fourteen years of scrutiny has found no counterexample to the one invariant.

**The recommendation**: pick ZeroPoint's one invariant and write it in the README in the same form. A candidate that is true of the code today:

> *Every action that crosses the ZeroPoint host boundary produces a signed, hash-chained receipt that can be verified by a party that trusts neither the agent nor the harness. ZeroPoint does not prevent an action taken outside that boundary; it makes the boundary the only path through which a governed tool is reachable.*

That is a real, defensible, differentiated claim, and it's the one the receipt layer actually delivers. It is also much weaker-sounding than *"you can't bypass it because it's structural"* — and much more likely to survive an adversarial reading, which is the whole point.

Then write the non-goals table. Current honest entries: no protection against a compromised host; no protection against a malicious workspace crate; no memory or CPU limits on sandboxed execution; no filesystem confinement; no signature verification on WASM policy modules; no protection against a harness that declines to route through the MCP endpoint.

---

## 7. Documentation as architecture

Three Whonix practices are cheap and disproportionately valuable.

**7.1 A threat model in RFC 2119 language.** [Dev/Threat_Model](https://www.whonix.org/wiki/Dev/Threat_Model) opens by binding MUST/SHOULD/MAY, then reasons about *attacker economics* — legal and physical attacks are "prohibitively expensive for more than a small target group"; software attacks are "economical, can be automated for a broad target set." Then it enumerates the TCB component by component.

ZeroPoint has no threat model section anywhere. `ARCHITECTURE.md`'s 14 sections contain no threat-model, security-boundary, sandboxing, or deployment-topology section; `SECURITY.md:88-92` forwards to a whitepaper section. The nearest thing is §10's local-model argument, which is good reasoning about *why* the deterministic core is the boundary — it just never says what the boundary defends against.

Note also Whonix's reason for a wiki over a PDF: *"we prefer an editable, frequently updated, and revised website over a static paper."* Given that ARCHITECTURE.md is dated February and the code has drifted substantially since (skills removed, tiers doubled, 44 crates vs. the documented 11), this is a live concern.

**7.2 Leak tests as a repeatable practice.** This is the one I'd steal today. Whonix ships `anon-gw-leaktest` / `anon-ws-leaktest` as packages exposing `sudo leaktest`, plus `systemcheck --leak-tests`, plus a documented manual suite:

- Shut down the Gateway, boot the Workstation, confirm zero external traffic.
- Disable DNS on the *host*; Workstation `nslookup` must still work (if it breaks, DNS was leaking through the host).
- The FIN/ACK test: open a socket in the Workstation, stop Tor on the Gateway, close the socket, watch the host interface with `tcpdump` for teardown packets escaping.
- `dig AAAA check.torproject.org` must return `NOTIMP` from `10.152.152.10#53`.

They also document which tests are *unsuitable* and why, and they use [corridor](https://github.com/rustybird/corridor) — an independent third-party gateway — as an external oracle.

**ZeroPoint's equivalent is a `bypass-test` suite**, and you already have `zp-hardening-tests` as a home for it. Candidate tests, all writable this week:

- Kill the audit store mid-run; assert no side effect completes. (Fails today.)
- Load a WASM policy module that always traps; assert the pipeline blocks rather than allowing. (Fails today.)
- Grep the workspace for `std::process::Command` / `std::fs::write` outside `zp-host`; assert the set is empty or matches an explicit allowlist with justifications. (Fails today; this is the `clippy.toml` from §3.3 as a test.)
- Assert every `PolicyContext.trust_tier` traces to a verified grant, not a literal. (Fails today.)
- Run a sandboxed script that reads `/etc/passwd` and writes outside the sandbox dir; assert both fail. (Fails today on both platforms.)

The value isn't that they pass. Whonix's leak tests were valuable *before* they passed — the suite is the specification of the invariant in executable form, and each red test is a precise, non-arguable statement of where the claim currently exceeds the code.

**7.3 Publish the criticism.** Whonix maintains a [Security Reviews and Feedback](https://www.whonix.org/wiki/Security_Reviews_and_Feedback) page linking *negative* reviews alongside positive ones, including the debian-derivatives thread where someone said "if VirtualBox is exploited, it is game over" and Whonix's response was: *"This is true and already mentioned in the attack matrix."*

Their stated posture: *"At first glance this site may create the impression that Whonix is completely insecure and everything is a lost cause. We are upfront with things we could do better."* For an open-source trust project, this is not modesty — it's the product. A trust layer that overstates its guarantees has a category problem, not a marketing problem.

---

## 8. What not to copy

- **The two-VM tax.** Whonix costs the user two VMs plus a host to patch, four OSes in the hybrid physical-isolation variant, no automatic updates, and a support window that can expire one month after a Debian release. ZeroPoint's Tier 0 "install and run, zero ceremony" posture is right and worth protecting. A broker process is not a VM; don't let the isolation argument escalate into a virtualization requirement.
- **Anonymity-style fingerprint normalization.** Not your threat model. The receipt-canonicalization inversion (§3.5) is the useful half.
- **The self-deprecation as literal copy.** "Alpha quality software" after fourteen years is calibrated for a threat model where users can be imprisoned. Match the *precision* of Whonix's claims, not their pessimism.
- **Whonix's own inconsistencies**, which are instructive as failure modes: their wiki still says "IPv6 is disabled" while the shipped firewall carries full IPv6 ULA rules; it says "iptables" throughout while the code is nftables; the physical-isolation variants table rates bare-metal isolation "equivalent to the standard download" while their own attack matrix rates it strictly better on two rows. Documentation drift is universal — the defense is executable specification (§7.2), not discipline.

---

## 9. Sequenced recommendations

Ordered by (value ÷ effort), highest first.

**Week 1 — say the true thing**
1. Rewrite the README's enforcement claim to the receipt/boundary invariant in §6. Delete or explicitly mark as roadmap: `@zeropoint/trace`, `@zeropoint/guard`, `zp-mcp-server`, and the Hedera anchoring box in the diagram (`zp-anchor` is a trait with no backend; `zp-hedera` doesn't exist).
2. Add a non-goals table to `SECURITY.md`.
3. `clippy.toml` with `disallowed-methods` for ambient authority, denied in CI outside `zp-host` (§3.3).

**Weeks 2–3 — close the fail-open paths**
4. Make the audit append a precondition of the side effect in `zp-host` and the pipeline. This is what makes `ARCHITECTURE.md:250` true.
5. Flip WASM module error from "no opinion" to `Block` (`wasm_runtime.rs:328-342`).
6. Stop auto-approving `Warn`/`Review` (`pipeline.rs:629-631`), or remove those variants until they're wired.
7. Add `--mount` to the `unshare` argv and a real bind set; fix the macOS default or document that macOS sandboxed execution is unenforced.

**Month 2 — executable specification**
8. `zp-hardening-tests/bypass/` with the five tests in §7.2. Land them red, with a README explaining what each red test means.
9. Publish the threat model: TCB enumeration, attacker economics, RFC 2119 language.

**Quarter — the structural change**
10. Derive `trust_tier` from a verified `zp-keys` certificate chain / capability grant instead of a caller-set literal (§5).
11. Split `HostContext`'s four methods across a process boundary — broker holds gate, chain, and credentials; agent process holds none. This is the change that makes the Whonix comparison flattering rather than instructive.
12. Reconcile Sentinel's trust vocabulary and rule semantics with Core, so the out-of-process enforcement point you already have can govern agent actions and not just DNS.

---

## Appendix: the pattern table

| Pattern | Whonix instance | ZeroPoint status | Move |
|---|---|---|---|
| Remove the capability | Workstation has no external NIC; no IP forwarding; no routing-table dependency | Absent — capability fully present in-process | Broker process behind `HostContext`'s four methods |
| Enforcer out of reach | Firewall + Tor on a separate VM; root on Workstation can't edit them | Absent — gate, chain, engine, LLM in one binary | Same; Sentinel already proves the topology |
| Squat the resource | `systemd-socket-proxyd` occupies 9050/9051/9150/9151; `tor` dpkg-diverted to no-op | Absent | `clippy.toml` disallowed-methods, CI-denied |
| Displace the binary | `uwt` replaces `apt-get`/`curl`/`git`/`ssh`; `IsolatePID 1` | Hook-based design, not built | Wrap the MCP endpoint, not the event lifecycle |
| Normalize the observable | hostname `host`, user `user`, TZ UTC, shared `machine-id` | Present, inverted — canonical receipt serialization | Name it as a principle; normalize the sandbox env too |
| Fail-closed, defined | "fails to connect via Tor **and connects via real IP instead**" | Mixed; four verified fail-open paths | §4 table |
| Structural identity | Which VM you are is a topology fact | Self-asserted struct field, hardcoded `Tier1` | Derive from `zp-keys` grant |
| Narrow published claim | "prevent direct detection of the IP (not more!)" | Claim exceeds code | §6 invariant |
| Executable specification | `sudo leaktest`, FIN/ACK test, corridor as external oracle | Absent | `zp-hardening-tests/bypass/` |

And Whonix's own closing caveat, which applies equally here: every one of these patterns collapses at the layer below. Hypervisor escape, a Tor process exploit, a compromised host — Whonix rates all of them **Fail** and says so in a public table. The two-VM split converts a large class of application-layer failures into structural impossibilities. It converts nothing below the hypervisor. The discipline worth copying is not the containment; it's knowing precisely where the containment stops and writing that down where users will read it.

---

## Sources

**Whonix (primary)**
- [Dev/Technical_Introduction](https://www.whonix.org/wiki/Dev/Technical_Introduction) — two-VM split, fail-closed definition, security layers
- [Dev/Threat_Model](https://www.whonix.org/wiki/Dev/Threat_Model) — RFC 2119 threat model, TCB enumeration, attacker economics, no-auto-updates rationale
- [Comparison with Others](https://www.whonix.org/wiki/Comparison_with_Others#Attacks) — the 13-row attack matrix
- [Warning](https://www.whonix.org/wiki/Warning) — non-goals table, missing features, unsubstantiated conclusions
- [Dev/Leak Tests](https://www.whonix.org/wiki/Dev/Leak_Tests) — the verification suite
- [Stream Isolation](https://www.whonix.org/wiki/Stream_Isolation) — SocksPort map, uwt, enforcement vs. configuration
- [Protocol-Leak-Protection and Fingerprinting-Protection](https://www.whonix.org/wiki/Protocol-Leak-Protection_and_Fingerprinting-Protection) — shared-personality design goal, normalized values
- [Connections between Gateway and Workstation](https://www.whonix.org/wiki/Connections_between_Gateway_and_Workstation) — unauthenticated LAN, trust asymmetry
- [Dev/onion-grater](https://www.whonix.org/wiki/Dev/onion-grater) — control-port whitelist proxy
- [Dev/TimeSync](https://www.whonix.org/wiki/Dev/TimeSync) · [Time Attacks](https://www.whonix.org/wiki/Time_Attacks) — sdwdate, `timesync-fail-closed`
- [whonix-gateway-firewall source](https://raw.githubusercontent.com/Whonix/whonix-firewall/master/usr/bin/whonix-gateway-firewall) · [firewall-common](https://raw.githubusercontent.com/Whonix/whonix-firewall/master/usr/libexec/whonix-firewall/firewall-common) — nftables default-deny, port map, `trap ERR`
- [anon-ws-disable-stacked-tor](https://github.com/Whonix/anon-ws-disable-stacked-tor) — socket squatting
- [Dev/Installation_from_Repository](https://www.whonix.org/wiki/Dev/Installation_from_Repository) — meta-packages, distro-morphing, why the packages can't carry the guarantee
- [Security Reviews and Feedback](https://www.whonix.org/wiki/Security_Reviews_and_Feedback) — published criticism
- [Project Zero, *An EPYC Escape*](https://googleprojectzero.blogspot.com/2021/06/an-epyc-escape-case-study-of-kvm.html) — hypervisor escape, quoted on the Warning page

**ZeroPoint (repo, read directly)**
`Cargo.toml` · `README.md` · `ARCHITECTURE.md` · `SECURITY.md` · `crates/zp-host/src/{lib,system}.rs` · `crates/zp-pipeline/src/pipeline.rs` · `crates/zp-policy/src/{gate,rules,engine,wasm_runtime,policy_registry}.rs` · `crates/execution-engine/src/{sandbox,executor,engine,lib}.rs` · `crates/zp-core/src/policy.rs` · `crates/zp-trace/src/lib.rs` · `crates/zp-receipt/src/types.rs` · `crates/zp-anchor/` · `tools/sentinel/zp_sentinel/gate.py` · `docs/design/{HARNESS-SURVEY,REGENT-MODES,GOOSE-INTEGRATION}-2026-08.md`
