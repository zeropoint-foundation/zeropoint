# ZeroPoint Threat Model

**Document type:** Threat model. Foundational — it elaborates no other document and is elaborated *by* the conformance targets and design notes that cite it.

**Date:** 2026-08-14.

**Key words.** MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY and OPTIONAL are to be interpreted as described in RFC 2119.

**Why this exists.** `WHONIX-LESSONS.md` §7.1 recorded that the corpus has no threat model. `ARCHITECTURE.md`'s fourteen sections contain no threat-model, security-boundary, or deployment-topology section; `SECURITY.md:88-92` forwards to a whitepaper section. Every conformance document in `docs/design/` reasons about adversaries informally and inconsistently because there is nothing to reason *against*. This is that document.

**Why a living document rather than a paper.** Following Whonix's stated reason for a wiki over a PDF — a threat model that is revised when the code changes is worth more than one that is authoritative and stale. `ARCHITECTURE.md` is dated February and has drifted materially: skills removed, tiers doubled from three to six, 44 workspace members against a documented eleven. This document SHOULD be revised in the same commit as any change to an enforcement boundary.

**Composes with:** `WHONIX-LESSONS.md` (the isolation precedent and the five patterns), `HOST-BROKER-2026-08.md` (the enforcement-point relocation this model assumes as target state), `NOSTR-TRANSPORT-CONFORMANCE-2026-08.md` (§3's relay classification is a boundary decision in this model's terms), `CROSS-SUBSTRATE-PEER-CONTRACT-2026-06.md`, `EXTERNAL-ANCHOR-TIER-CONTRACT`, `DEPENDENCY-POSTURE.md`.

**Attribution.** The deployment profiles, TCB enumeration, and adversary classes are drafted by Claude against the shipped code, the corpus, and two primary sources cited in §3. The rulings this document requests — §2's invariant statement above all — remain Ken's.

---

## 1. Scope discipline: what ZeroPoint claims

Whonix's most valuable and least imitated property is that it claims exactly one thing, and says so with an interjection:

> "Whonix is designed to prevent direct detection of the IP (**not more!**) even if an adversary has unrestricted access to the Whonix-Workstation."

Fourteen years of scrutiny has found no counterexample to that one sentence, and the reason is that the sentence is narrow enough to test. Everything else in Whonix is either enforcement of it or fingerprint normalization layered on top.

ZeroPoint MUST adopt the same discipline. The proposed invariant:

> **Every action crossing the ZeroPoint host boundary produces a signed, hash-chained receipt verifiable by a party that trusts neither the agent nor the harness that produced it.**

And the disclaimers, which are load-bearing rather than modest:

- ZeroPoint does **not** prevent effects reachable without crossing that boundary.
- ZeroPoint does **not** claim the agent's reasoning is correct, safe, or aligned.
- ZeroPoint does **not** claim to protect against a compromised host, kernel, or hypervisor.
- ZeroPoint does **not** currently hold the invariant. §6 states precisely where it fails today.

That last bullet is not an admission to be minimized. Whonix self-describes as *"currently alpha quality software"* fourteen years in, and publishes its own attack matrix with **Fail** in nine of thirteen rows. For a trust layer, overstating a guarantee is a category error rather than a marketing choice: the product *is* the accuracy of the claim.

---

## 2. Adversary classes and their economics

Whonix's threat model reasons about attacker cost before mechanism, which correctly orders the work. Adapted to this domain:

| Class | Cost to mount | Scales? | In scope |
|---|---|---|---|
| **A1 — Injected content** in a document, web page, email, tool output, or peer message that steers an agent | Near zero | Yes, automatable across every user | **Primary** |
| **A2 — Malicious or compromised tool / MCP server** the operator installed | Low; one supply-chain foothold | Yes | **Primary** |
| **A3 — Agent-to-agent propagation** — a subverted agent steering sibling agents that trust it | Near zero once A1 lands | Yes, within a deployment | **Primary** |
| **A4 — Third-party platform** treating an agent's action as the operator's, adversarially or bureaucratically | Zero — it is the platform's normal operation | Yes | **Primary** (§3.4) |
| **A5 — Malicious workspace crate / dependency** inside the substrate build | Moderate | Yes | Secondary — mitigated by `DEPENDENCY-POSTURE`, not by this model |
| **A6 — Compromised operator host or kernel** | High | No | **Out of scope** — total compromise, stated |
| **A7 — Targeted state-level adversary** | Very high | No | **Out of scope**, explicitly |

A1–A4 are the ones that are cheap and automatable, and they are therefore the ones the design MUST address. This is the same shape as Whonix's conclusion that software attacks are *"economical… can be automated for a broad target set"* while legal and physical attacks are *"prohibitively expensive for more than a small target group."*

**A4 deserves emphasis because it is routinely omitted from agent threat models.** It is not an attack in the usual sense. It is a platform doing exactly what it is supposed to do — noticing an anomalous login, enforcing its automation terms — and the operator having no artifact with which to answer. §3.4 works it through.

---

## 3. Deployment profiles

A threat model is meaningless without a deployment shape to hold it against. Three are current as of this date. Two are real products examined from primary sources; the third is the target.

### 3.1 Profile A — Shared-perimeter agent host

**Reference instance:** xAI's Grok Bot, from a firsthand review ([LM7Ft7g8qJw](https://www.youtube.com/watch?v=LM7Ft7g8qJw)) and launch coverage. Characterised, not endorsed or condemned.

Shape: many named agents, one cloud machine, one filesystem, one credential set, one browser. The reviewer states the security posture plainly and approvingly:

> "Grockbot is one security perimeter… adding more agents doesn't add to that security perimeter. It's just one set of risk that you accept."

That is accurate and it is the problem. The perimeter does not grow with agent count because it was already maximal. Specific properties, each with its adversary class:

| Property (as described) | Consequence | Class |
|---|---|---|
| "You authorize [a connector] once in one conversation with one bot. Any other bot… it's authorized." | Ambient authority. Every agent inherits every grant; a landing-page agent holds the mail scope. | A1 → A3 |
| Agents "message each other in ways that are transparent to you" | Unattested inter-agent channel. Injection in one propagates to siblings with no record of the hop. | A3 |
| "It can self-improve its machine as it goes" — agents authoring their own tools | Agent-authored code enters the trusted set without review. | A2 |
| Agent drives a real browser login as the operator | Platform sees the operator's identity from foreign infrastructure. | A4 |
| Model routing opaque to the operator | The reasoning component cannot be pinned, versioned, or attested. | A1 |

**Fair counterweight.** A dedicated single-tenant machine is genuinely better than credentials distributed across a dozen third-party SaaS agents, and the described consent flow — presenting a login screen for the human to drive rather than capturing a password — is good design that ZeroPoint SHOULD study. The failure here is not carelessness. It is that convenience and blast radius were traded, deliberately, and only one side of the trade is in the marketing.

**ZeroPoint's relationship to this profile:** it is a *governed harness target*, not a competitor. An operator running Profile A who wants provenance needs the trace layer. This is the population the portability thesis exists for, and it is about to be large and non-technical.

### 3.2 Profile B — Sovereign-custody workspace

**Reference instance:** Block's Buzz — Nostr-based, Apache 2.0, self-hosted relay + Postgres + Redis + media store, humans and agents in shared channels, identity as a keypair. Read at `df9e773` for `NOSTR-TRANSPORT-CONFORMANCE-2026-08.md`; that document's §9 and §14 are the authoritative in-corpus assessment and are not restated here.

What Profile B fixes relative to A: model choice, source availability, data custody, portability, and — most significantly — **identity as a key rather than an account**, shipped to non-technical operators via one-click deploy.

What it does not fix, and this is the point of naming it as a distinct profile:

- **Custody is not provenance.** The operator holds the database. A log the operator can edit is not evidence to a party that does not trust the operator. Buzz's `audit_log` *is* hash-chained — `seq`, `prev_hash`, per-community uniqueness — and `verify_chain` has no production caller anywhere in its tree.
- **A bare key carries no chain of authority.** An agent signs; nothing binds that agent key to an operator's delegation, bounds its scope, or expires it. This is the identity thinness the Nostr conformance document declines while adopting the transport.
- **Shared channels are an A3 surface.** Humans and agents from multiple parties in one room is the product thesis, and it is also unattested cross-agent influence with a wider trust boundary than Profile A.
- **Managed-hosting lifecycle.** Per the amendment proposed to `NOSTR-TRANSPORT-CONFORMANCE` §3, a one-click VPS relay satisfies custody intuition and fails governed-lifecycle: config changes traverse a hosting panel and leave no receipt.

**ZeroPoint's relationship:** complementary, not competitive. Profile B supplies distribution and custody; ZeroPoint supplies the chain of authority and the receipt. That composition is the subject of the Nostr conformance document.

### 3.3 Profile C — Governed substrate (target state)

Broker process holding gate, chain, credentials, and signing key; agent process holding none of them; effects crossing a socket that speaks four verbs. Specified in `HOST-BROKER-2026-08.md`. Not shipped — see §6.

### 3.4 Worked example: the accountability gap, all three profiles

From the Buzz comparison review ([oDwhzUA-iDg](https://www.youtube.com/watch?v=oDwhzUA-iDg)), firsthand and self-damaging, which is why it is weighted:

The reviewer asked his agent to read his LinkedIn inbox. The agent drove a browser login as him, cleared four captchas and a Cloudflare check, and LinkedIn then emailed asking him to verify a new device — Chrome, Linux, San Jose, California. He is in none of those. His conclusion:

> "LinkedIn's terms are not very friendly to automated access to your account. If the platform decides it doesn't like it, the account at risk is mine."

This is A4 in the wild, with the third party actively posing the question. Trace it through:

| | Can the operator answer "was this you"? |
|---|---|
| **Profile A** | No. No exportable record exists; the reviewer notes there is no backup or restore path. |
| **Profile B** | Partially, and not usefully. He holds the logs. Self-held, self-editable logs are not evidence to a party that does not trust him — which is the entire posture LinkedIn is in. |
| **Profile C** | Yes, in the form that matters: a signed receipt naming the agent key, the capability grant that authorized the action, the grant's scope and expiry, the operator delegation it descends from, and a chain position anchored where the operator cannot revise it. |

**This is the clearest statement available of what ZeroPoint is for**, and it should be treated as the canonical scenario. Note what makes it compelling: the demand for provenance arrives from **platforms**, not from users. Users want convenience. Platforms want to know whether to believe you, and they will ask with account suspension rather than a support ticket.

Note also the dependency it exposes. The answer in Profile C requires an anchor the operator cannot revise. `zp-anchor` is a trait with no backend; the `zp-hedera` crate its doc comment references does not exist in the workspace, while `README.md:50` shows "Hedera HCS (Anchoring)" as a live component. **The scenario that best justifies the project depends on the component least implemented.** That ordering SHOULD change.

---

## 4. Trusted computing base

Enumerated component by component, following Whonix's practice. Each entry states what its compromise costs.

**In the TCB, Profile C target state:**

| Component | Compromise cost |
|---|---|
| Operator host OS and kernel | Total. Out of scope (A6). |
| The broker process (`zp-hostd`) | Total for the invariant — holds gate, chain writer, vault, signing key. |
| `zp-keys` root custody and the Genesis → Operator → Agent chain | Total for identity. Every grant descends from it. |
| The chain store and its write path | Total for provenance. A forgeable chain proves nothing. |
| Ed25519 / Blake3 primitives, `ed25519-dalek` | Total. Standard cryptographic dependency. |
| The external anchor, once one exists | Partial — its compromise costs third-party verifiability, not local integrity. |

**Explicitly NOT in the TCB, by design:**

- The model. Any model, local or cloud. `ARCHITECTURE.md` §10's reasoning is correct and is the strongest security argument in that document: a small local model that is easy to subvert but has unrestricted tool access is more dangerous than a strong cloud model with gated capabilities. Safety comes from the enforcement layer, not from where inference runs.
- The harness. Goose, Claude Code, Codex, Grok Bot, anything. The trace layer's entire premise.
- Any transport. Per `DECENTRALIZED-TRANSPORT-OPPORTUNITY-MAPPING`: a carrier is never a gate. Relays, mesh interfaces, and peers are outside.
- Agent-authored tools and skills. `zp-skills` was removed on 2026-08-10 with the rationale recorded at `crates/zp-pipeline/src/pipeline.rs:32-34` — fuzzy skill matching widens capability in response to attacker-controlled input. **This was the correct call and it is a live differentiator**, since Profile A markets the capability that was deliberately removed here.

**The TCB grows when the broker does.** `zp-server/src/lib.rs` is 312 KB today. If `zp-hostd` acquires that shape, this design has failed — the point of relocating the enforcement point is that the relocated component is small enough to audit. Whonix's note applies verbatim: *"Embrace simplicity. Complexity is security's primary adversary."*

---

## 5. Non-goals

Published as a table, per Whonix's practice of making the negative space explicit. These are current statements of fact, not permanent refusals.

| Not defended against | Status |
|---|---|
| Compromised host OS, kernel, or hypervisor | Out of scope, permanently. Same posture as Whonix's host-trust row. |
| Targeted state-level adversary | Out of scope, permanently. |
| A compromised broker | Out of scope by construction — it holds the key and the chain. Mitigation is smallness, not defense. |
| A malicious crate inside the workspace build | Out of scope here; belongs to `DEPENDENCY-POSTURE`. |
| Bad agent reasoning that stays within granted capability | Out of scope. The gate records and bounds; it does not adjudicate wisdom. |
| Effects not routed through the host boundary | Out of scope by definition — this is what the boundary *means*. Narrowing what escapes it is `HOST-BROKER` Phase 3. |
| Memory / CPU exhaustion by sandboxed execution | **Not implemented.** `execution-engine/src/sandbox.rs:39-53` marks both "Planned." |
| Filesystem confinement of sandboxed execution | **Not implemented.** The Linux wrapper emits `unshare --net --pid --fork` with no `--mount` despite the adjacent comment claiming one; macOS defaults to no isolation. |
| Signature verification of policy modules | **Not implemented.** Blake3 content hash only; `PolicyMetadata.signature` is never populated or checked. |
| A harness that declines to route through the governed endpoint | Out of scope. The `uwt` answer — own the endpoint rather than hook the lifecycle — is `WHONIX-LESSONS` §3.4. |
| Traffic analysis of substrate activity | Out of scope. Not an anonymity system. |
| Operator behaviour | Out of scope. Whonix's phrasing is the right one: no protection for *"those who fail to read the Documentation."* |

---

## 6. Where the invariant fails today

Stating this plainly is the point of the document. Each row is verified by direct read on this date.

| Failure | Location | Effect |
|---|---|---|
| Enforcement is in-process and advisory | `zp-pipeline`, `zp-policy::gate`, `zp-host` | 109 `Command::new` sites across 27 files in 7 crates; one is in `zp-host`. Bypass is a `use` statement. |
| Chain append is a companion, not a precondition | `zp-host/src/system.rs:69-95` | Append failure warns; the spawn proceeds. Directly contradicts `ARCHITECTURE.md:250`. |
| WASM policy error fails open | `zp-policy/src/wasm_runtime.rs:328-342` | A trapping module is "no opinion"; `DefaultAllowRule` then permits. A module that crashes reliably is disabled silently. |
| `Warn` / `Review` auto-approve | `zp-pipeline/src/pipeline.rs:629-631` | The graduated model exists in types only; effective behaviour is binary. |
| Trust tier is self-asserted | `PolicyContext.trust_tier`; `zp-host/src/system.rs:59,125,191,242` | Hardcoded `Tier1` — exactly the tier `TrustTierEnforcementRule` requires for writes. The check cannot fail. |
| No external anchor | `zp-anchor` | Trait only. §3.4's answer is unavailable. |
| Sandbox does not confine the filesystem | `execution-engine/src/sandbox.rs:180-205` | Full host filesystem view at the invoking user's permissions. |

Remediation is sequenced in `HOST-BROKER-2026-08.md` §10. Phases 1 and 4 are the ones that move rows in this table.

---

## 7. Verification practice

A threat model that cannot fail is a brochure. Whonix ships `sudo leaktest` as a package and documents which tests are unsuitable and why; the suite is the specification of the invariant in executable form.

ZeroPoint has the mechanism already — `crates/zp-discipline/` and its twenty-six pins, whose module doc states the thesis directly: *"A convention is a rule developers must remember to follow. An invariant is a rule the code makes impossible to violate."* Pins are static; this model additionally REQUIRES dynamic tests.

**Static (discipline pins).** `no_raw_variable_spawn_outside_zp_host` landed 2026-08-14 as the first pin against ambient authority. It widens with `HOST-BROKER` Phase 3.

**Dynamic (bypass suite).** These SHOULD land red where they fail, with a README stating what each red test means — a red test is a non-arguable statement of where the claim exceeds the code:

1. Kill the chain writer mid-run; assert no effect completes.
2. Load a policy module that always traps; assert `Block`.
3. Exhaust the chain volume; assert refusal, not silent success.
4. Delay the gate past timeout; assert denial, not allow. Per `zp-trace`'s own analysis: *"an attacker who can make the gate slow can make it absent."*
5. Sandboxed script reads `/etc/passwd` and writes outside the sandbox dir; assert both fail.
6. Assert every `PolicyContext.trust_tier` traces to a verified grant rather than a literal.
7. **The A4 test:** given a completed tool action, produce the receipt chain answering "which agent, under which grant, authorized by whom, expiring when" — and verify it with the operator's keys withheld from the verifier.

Test 7 is the one that verifies the §1 invariant rather than a component of it, and it is the only one whose pass condition is the §3.4 scenario. It SHOULD be written first even though it will fail longest.

---

## 8. Revision

This document MUST be revised when any row in §6 changes state, when a deployment profile in §3 materially changes, or when a component enters or leaves the §4 TCB. Profiles A and B are external products and WILL drift; their entries carry the date and source of the read, and a stale profile SHOULD be marked stale rather than silently trusted.

Rulings requested of the operator: the §1 invariant statement, the §5 non-goals table as the published list, and whether §3.4 becomes the canonical positioning scenario.
