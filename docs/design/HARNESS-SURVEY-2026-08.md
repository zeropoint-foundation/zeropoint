# CODING HARNESS SURVEY — Selecting a Reference Integration Target

**Draft for discussion** · 2026-08-13 · Companion to `REGENT-MODES-2026-08.md`

> **Finding:** The field splits on a criterion most harness comparisons never mention — whether a third party can *deny* a tool call, and what happens when that gate fails. Eight of nine candidates now have some blocking hook; only three have defensible failure semantics. Ranked against ZeroPoint's actual requirements, the answer is **Goose**, and not for its hook — for the fact that it is Rust, foundation-governed, and can be integrated the way IronClaw is, below the hook layer entirely.

---

## 1. Why the usual criteria don't apply

ZeroPoint does not need the best coding agent. It needs a harness that can be *governed* and *driven*, which is close to orthogonal to coding quality. Seven criteria, derived from the architecture rather than from the market:

| # | Criterion | Why it comes from our architecture | Weight |
|---|---|---|---|
| 1 | **Blocking pre-tool hook** | Trace is easy; Guard needs deny power. Without it the second layer of the README is unimplementable. | 25% |
| 2 | **Drivability** | Regent coding mode drives the harness as a subordinate. Needs headless + structured event stream. | 20% |
| 3 | **Governance of the harness** | Our pitch is that the chain survives switching harnesses. Anchoring the reference integration to a vendor-controlled harness undercuts it. | 20% |
| 4 | **Implementation language** | Rust means trait injection with no bridge — GAR §3.1's stated preference. Anything else is the wrapper model. | 15% |
| 5 | **Local inference posture** | Must run `officer-inference.toml`'s models inside a 128k budget. | 10% |
| 6 | **Process shape** | Daemon with stable identity beats CLI-that-exits — GAR's second reason for IronClaw. | 5% |
| 7 | **MCP client** | Near-free trace coverage once `zp-mcp-server` exists. | 5% |

The weights are the argument. Disagree with them and the ranking moves — criterion 3 in particular is weighted far above where a normal engineering evaluation would put it, and deliberately so.

---

## 2. The criterion nobody publishes: what happens when the gate fails

A deny hook that fails open is not a security boundary. This turned out to be the sharpest discriminator in the field, and it is documented in exactly three places:

- **Goose** — *fails open, explicitly.* Spawn errors, 30s timeouts, and all non-zero exits other than 2 are logged and treated as `Allow`. The source comment is unambiguous: *"a misbehaving hook MUST NOT block."*
- **Cline** — *configurable, with the right default available.* Hook policies carry `failureMode: "fail_open" | "fail_closed"`, and the docs say to use `fail_closed` "for policy-enforcement hooks where bypassing the hook is unsafe." The only candidate that names our use case.
- **pi** — *fails safe.* "`tool_call` errors block the tool." No configuration needed; the correct default is the only behaviour.

Everyone else leaves it undocumented. For Crush and Codex, exit codes other than the blocking one are treated as non-blocking errors and the tool proceeds — fail-open by construction.

A second, related discriminator: **OpenCode's `tool.execute.before` does not intercept tool calls made by subagents spawned via the `task` tool** (issue #5894, open and unresolved). Any policy built on it is escapable by delegation. Kilo Code's CLI is a fork of OpenCode and inherits the same plugin API, so it likely inherits the bypass — unverified, but it should be assumed until tested.

That single bug disqualifies both from being a governance reference, regardless of how good they otherwise are. A gate with a known delegation bypass is worse than no gate, because it produces receipts that assert coverage it does not have.

---

## 3. Scored

Scores are 0–5 against the criterion, weighted per §1.

| Harness | 1 Hook | 2 Drive | 3 Gov | 4 Lang | 5 Local | 6 Proc | 7 MCP | **Total** |
|---|---|---|---|---|---|---|---|---|
| **Goose** | 3 | 5 | **5** | **5** | **5** | 5 | 4 | **4.35** |
| **Codex CLI** | **5** | **5** | 2 | **5** | 4 | **5** | **5** | **4.20** |
| **Cline** | **5** | 5 | 3 | 2 | 3 | 4 | 4 | 3.85 |
| **pi** | 4 | 4 | 3 | 2 | **5** | 1 | **0** | 3.10 |
| **oh-my-pi** | 4 | **5** | 2 | 3 | **5** | 2 | 4 | 3.55 |
| **Claude Code** | **5** | 5 | **1** | 1 | **0** | 3 | 4 | 2.95 |
| **Kilo Code** | 2* | 4 | 2 | 2 | 3 | 4 | 4 | 2.75 |
| **OpenCode** | 1* | **5** | 3 | 2 | 4 | **5** | 4 | 3.05 |
| **Crush** | 3 | 2 | 2 | 4 | 4 | 4 | 4 | 3.00 |
| **Aider** | **0** | 2 | 2 | 1 | 4 | 1 | **0** | 1.45 |

\* Scored down for the subagent bypass, not for hook design.

---

## 4. The recommendation: Goose, integrated below the hook

Goose wins on a combination that no other candidate has:

- **Rust.** GAR §3.1 chose IronClaw as first tenant partly because shared language allows ZP to participate as a library dependency implementing the tenant's own traits, with no serialization boundary and no bridge process. Goose is the only *coding* harness where that model is available at all. Codex is also Rust but is a closed development process — you can fork it, you cannot compose with it.
- **Foundation governance.** Block donated Goose to the **Agentic AI Foundation at the Linux Foundation** — the same foundation that now holds MCP and AGENTS.md. Repo moved to `aaif-goose/goose`. For a project whose entire claim is that trust survives switching vendors, a reference integration anchored to a Linux Foundation project is thesis-consistent in a way that Codex (OpenAI), Claude Code (Anthropic), Kilo (Anaconda), OpenCode (VC-funded Anomaly), Cline (Cline Bot Inc.), and pi (Earendil Works) all are not. It is also the only candidate that got *less* vendor-controlled over the past year while everything else got more.
- **Local inference, in-process.** `goose-local-inference` embeds llama.cpp directly with a HuggingFace model manager. Not "points at Ollama" — actually hosts the model. That fits the sovereignty argument better than any subprocess arrangement.
- **Both process shapes.** `goose run --output-format stream-json` for one-shot; `goose serve` (HTTP + WebSocket, default 127.0.0.1:3284) and `goose acp` (stdio) for stable identity. Sessions have durable IDs.
- **MCP both directions.** Client over stdio and Streamable HTTP; `goose mcp <server>` exposes its own extensions as MCP servers. `zp-mcp-server` tenancy works out of the box.

**The catch, stated plainly:** Goose's `PreToolUse` hook is the *weakest* enforcement surface of the serious candidates. Allow/deny only, no argument mutation, and it fails open on timeout or crash. As a Guard layer it is not fit for purpose.

**Which is the point.** We should not use it. The Rust integration path means ZeroPoint can sit inside the tool dispatch path as a library rather than beside it as a hook — the same distinction GAR draws between *visibility* (trait integration) and *enforcement* (process boundary), except here we can have both in one process. The hook becomes the fallback for non-Rust deployments and the fail-open behaviour becomes acceptable, because it is no longer the only thing standing between the model and the tool.

Contributing a `fail_closed` option upstream is also a reasonable first move into an AAIF project, and a cheaper way to establish standing than any amount of README positioning.

### Second target: Codex CLI

Build the second adapter here, and weight the vendor risk consciously rather than avoiding it.

Codex has the best *enforcement* story in the field, and it is not the hook. `codex app-server` is a long-lived daemon over stdio, WebSocket, or a Unix socket at `$CODEX_HOME/app-server-control/app-server-control.sock`, and it issues **server→client approval requests** — `execCommandApproval` and `applyPatchApproval` — that the driving parent answers. That is a native protocol-level gate for an embedding harness, structurally better than a hook because it is the harness asking permission rather than a third party intercepting. Plus `PreToolUse` with `updatedInput`, `codex mcp-server`, Apache-2.0, and `--oss` for Ollama/LM Studio.

Two Rust harnesses, two integration models — library-level for Goose, protocol-level for Codex — is a far stronger demonstration of portable trust than two adapters of the same shape.

---

## 5. Correcting the earlier pi recommendation

pi looked good on a narrow read and looks weaker on a full one. Three things surfaced that change the assessment:

1. **pi has no MCP at all, by design.** Verified absent from the shipped bundle — zero `*mcp*` files, no SDK dependency. The README is explicit: *"No MCP. Build CLI tools with READMEs, or build an extension that adds MCP support."* This kills the `zp-mcp-server`-gives-free-trace story for pi specifically, which was a meaningful part of why it seemed cheap.
2. **pi was acquired in April 2026.** Mario Zechner joined Earendil Works (co-founded by Armin Ronacher); repo moved to `earendil-works/pi`, npm scope moved with it. Core stays MIT, but the company plans Fair Source and proprietary enterprise/cloud tiers on top, and the roadmap is company-controlled. The unshipped remote-session server — the client ships, the server does not — is plausibly the first instance of that periphery. This is the same risk class as the April 4 subscription change, arriving four days later from a different direction.
3. **No process identity whatsoever.** Zero listeners in the shipped bundle. Every run is a fresh subprocess.

What pi still has, and it is genuinely the best in the field: **`tool_call` errors block the tool.** Fail-safe as the only behaviour, not a configuration option. If we build our own harness or fork one, that is the semantic to copy.

---

## 6. Excluded, with reasons

- **Aider** — no interception surface at all (edit-loop shaped, not tool-loop shaped; the only choke point is a human `confirm_ask` that doesn't even cover edits to files already in chat), no MCP, no JSON output. Additionally **dormant**: last commit 2026-05-22, ~0 commits/month, maintainer absent with an open "Where is Paul?" issue and community forks emerging. Would be excluded on either ground alone.
- **Claude Code** — proprietary, and its legal terms explicitly prohibit third-party products routing through claude.ai login, with demonstrated enforcement (consumer OAuth blocked in third-party tools ~Feb 2026; OpenAI's API access revoked Aug 2025). It also cannot be pointed at non-Claude models: Anthropic states it "doesn't support routing Claude Code to non-Claude models through any gateway." Best-in-class hooks — `deny`/`ask`/`allow`/`defer`, `http` and `prompt` handler types, in-process SDK callbacks, documented precedence — but structurally unavailable as a governed local-inference tenant. Fine as a *dev* tool; wrong as the reference integration.
- **OpenCode / Kilo Code** — subagent bypass (§2). Revisit if #5894 closes.
- **Crush** — FSL-1.1-MIT is source-available with a non-compete, not OSI open source until it converts after two years. Also no JSON output from `run`; the structured event stream exists only over an undocumented HTTP API with no published spec or SDK.
- **oh-my-pi** — the strongest drivability in the field (rpc, rpc-ui, ACP, json) and schema-revalidated argument rewriting, which is safer than pi's unvalidated in-place mutation. But: single-individual control, a vouch-to-contribute system currently on trial suspension and explicitly liable to return, and **583 npm releases in eight months**. That churn rate is disqualifying for a receipt schema we need to hold stable across versions.

---

## 7. Suggested sequence

1. **`@zeropoint/trace` against Goose, library-level.** Rust-to-Rust, no bridge. Proves the package exists and gives the receipt schema its first producer. Smallest thing that makes the README true.
2. **Guard below the hook layer**, in the dispatch path. Compare against the `PreToolUse` hook path as a fallback and document the difference in enforcement strength — that comparison is itself a good piece of writing for the corpus.
3. **Contribute `fail_closed` upstream to AAIF Goose.** Small patch, real standing, directly relevant to our thesis.
4. **Second adapter against `codex app-server`**, protocol-level, answering `execCommandApproval` / `applyPatchApproval` as the driving parent.
5. **Update the README diagram** to name what actually exists. Today it leads with pi, which has no adapter, no MCP, and no process identity.

---

## Sources

Primary sources, verified at source level where noted.

**pi / oh-my-pi:** [earendil-works/pi](https://github.com/earendil-works/pi) · [docs/extensions.md](https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/extensions.md) · [docs/rpc.md](https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/rpc.md) · [docs/compaction.md](https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/compaction.md) · ["I've sold out" — Zechner, 2026-04-08](https://mariozechner.at/posts/2026-04-08-ive-sold-out/) · [can1357/oh-my-pi](https://github.com/can1357/oh-my-pi) · [omp.sh/docs/sdk](https://omp.sh/docs/sdk)

**Goose:** [aaif-goose/goose](https://github.com/aaif-goose/goose) · [Goose moves to AAIF](https://goose-docs.ai/blog/2026/04/07/goose-moves-to-aaif/) · [aaif.io](https://aaif.io/) · [Open Plugins hooks spec](https://open-plugins.com/agent-builders/components/hooks)

**Codex:** [openai/codex](https://github.com/openai/codex) · [app-server README](https://github.com/openai/codex/blob/main/codex-rs/app-server/README.md) · [MCP interface](https://github.com/openai/codex/blob/main/codex-rs/docs/codex_mcp_interface.md) · [hooks](https://learn.chatgpt.com/docs/hooks) · [non-interactive mode](https://learn.chatgpt.com/docs/non-interactive-mode.md)

**Claude Code:** [hooks reference](https://code.claude.com/docs/en/hooks) · [Agent SDK permissions](https://code.claude.com/docs/en/agent-sdk/permissions) · [legal and compliance](https://code.claude.com/docs/en/legal-and-compliance) · [LLM gateways](https://code.claude.com/docs/en/llm-gateway) · [Agent SDK with your Claude plan](https://support.claude.com/en/articles/15036540-use-the-claude-agent-sdk-with-your-claude-plan)

**OpenCode / Kilo / Crush / Cline / Aider:** [opencode.ai/docs/plugins](https://opencode.ai/docs/plugins/) · [opencode issue #5894](https://github.com/anomalyco/opencode/issues/5894) · [Kilo-Org/kilocode](https://github.com/Kilo-Org/kilocode) · [Anaconda acquires Kilo Code](https://blog.kilo.ai/p/anaconda-acquires-kilo-code) · [charmbracelet/crush](https://github.com/charmbracelet/crush) · [crush docs/hooks](https://raw.githubusercontent.com/charmbracelet/crush/main/docs/hooks/README.md) · [cline/cline](https://github.com/cline/cline) · [Cline SDK plugins](https://raw.githubusercontent.com/cline/cline/main/docs/sdk/plugins.mdx) · [Aider-AI/aider](https://github.com/Aider-AI/aider) · [aider issue #4613](https://github.com/Aider-AI/aider/issues/4613)
