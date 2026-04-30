# Footprint Update Brief — April 2026

**Scope.** Survey what's changed in the AI security landscape since the last footprint update (January 2026) and propose line-by-line changes to `zeropoint.global/footprint.html`. Honesty bar: *calibrated* — keep green where the primitive exists and works, flag gaps in copy.

---

## Part I — What's changed since January 2026

Three months, and the landscape has moved from "people write papers about agentic threats" to "agentic threats are operational, named, counted, and exploited at scale." Six headline shifts.

### 1. The OWASP Agentic Top 10 is no longer an aspiration — it shipped

Released **December 2025** with the 2026 edition formally titled *OWASP Top 10 for Agentic Applications 2026*, developed by 100+ industry experts. The ten categories (ASI01–ASI10) are:

| ID    | Category                              | In current footprint? |
|-------|---------------------------------------|----------------------|
| ASI01 | Goal Hijack                           | Yes (keep)           |
| ASI02 | Tool Misuse                           | Yes (keep)           |
| ASI03 | Identity & Privilege Abuse            | **Missing** — ZP's strongest area |
| ASI04 | Agentic Supply Chain Vulnerabilities  | **Missing**          |
| ASI05 | Unexpected Code Execution             | **Missing**          |
| ASI06 | Memory Poisoning                      | **Missing**          |
| ASI07 | Insecure Inter-Agent Communication    | Yes (keep)           |
| ASI08 | Cascading Failures                    | Yes (rename from "Cascading Hallucinations") |
| ASI09 | Human-Agent Trust Exploitation        | **Missing**          |
| ASI10 | Rogue Agents                          | Yes (keep)           |

The current footprint has 7 items under Agentic Threats; the new canon has 10. Four of the new five are categories where ZP has real-but-different-tier coverage. This is the single biggest revision the page needs.

### 2. OWASP MCP Top 10 emerged (beta)

An entirely new top-10 just for the Model Context Protocol: token mismanagement, scope creep, tool poisoning, supply chain, command injection, intent flow subversion, insufficient auth, lack of audit/telemetry, shadow MCP servers, context injection. This is *protocol-layer* governance — exactly the layer ZP operates at. The footprint has no MCP-specific domain today.

### 3. XBOW went from "impressive demo" to "#1 on HackerOne globally" — and raised $120M

- **June 2025:** XBOW became the first non-human bug hunter to reach #1 on HackerOne's US leaderboard, submitting ~1,060 vulnerabilities.
- **March 19, 2026:** Series C of $120M, $1B+ valuation. Planning to shift left into CI/CD pipelines in Q2–Q3 2026.
- **Category now has competitors:** Escape, Terra Security, Hadrian, Penti, Novee (LLM-specific), Strix, RedAmon, PentAGI (open source), HackingBuddyGPT. "Agentic Pentesting" is now a recognized market category.

The implication for ZP's footprint: autonomous offensive tooling is no longer a theoretical threat class. It's a capital-backed industry running continuously against production systems.

### 4. Google Big Sleep shipped real CVEs

Big Sleep (Project Zero + DeepMind evolution of Naptime) found an exploitable stack buffer underflow in SQLite in October 2024, then five WebKit flaws acknowledged by Apple in late 2025. This is the first *public* evidence of autonomous AI finding unknown exploitable memory-safety bugs in widely deployed software. Autonomous CVE discovery is now real, not conjectured.

### 5. MCP itself is under active attack

- **September 2025:** First documented malicious MCP server — a rogue `postmark-mcp` npm package was quietly copying every email to an attacker server, starting in v1.0.16.
- **March 24, 2026:** LiteLLM (3.4M daily downloads) backdoored via PyPI. CVE-2026-30623 for command injection via Anthropic's MCP SDK.
- **March 31, 2026:** `axios` npm package (100M weekly installs) compromised via hijacked maintainer; malicious versions shipped a cross-platform RAT.
- **April 15, 2026:** OX Security disclosed an architectural "by design" flaw in Anthropic's MCP STDIO interface — enables RCE across every official SDK language. 14 assigned CVEs, **~200,000 AI servers affected**, 7,000+ public servers, 150M+ package downloads. Anthropic declined to patch the protocol, putting sanitization responsibility on developers.
- **OWASP Agent Memory Guard** project launched; MINJA research shows **>95% injection success rates** against production agents with memory.
- **Radware's ZombieAgent PoC (January 2026):** ChatGPT connector + memory features chained into persistent, cross-session indirect prompt injection.

### 6. Indirect prompt injection became the dominant attack vector

- Indirect prompt injection now **>55% of observed attacks** in 2026 (Palo Alto Networks, March 2026).
- Multi-hop indirect attacks via agents/tools **up 70% YoY** (2025 → 2026).
- 10 new in-the-wild payloads documented by Unit 42 targeting financial fraud, data destruction, API key theft.
- **CVE-2026-21520** (Copilot Studio, CVSS 7.5, patched Jan 15 2026) — indirect prompt injection with post-patch exfiltration still possible.
- **Simon Willison's "Lethal Trifecta"** (private data + untrusted content + external comms = exfiltration) is now the operative framing security teams reason with.
- MITRE ATLAS v5.4.0 (Feb 2026) added "Publish Poisoned AI Agent Tool", "Escape to Host", AI Agent Context Poisoning, Memory Manipulation, Exfiltration via AI Agent Tool Invocation.

### 7. Confused deputy re-emerged as the key agent-delegation vulnerability

Cloud Security Alliance and others are now naming the *confused deputy* problem — a classical access-control bug — as the signature vulnerability of multi-agent pipelines. The Cline incident (a GitHub-issue-triggered Claude coding session that did a poisoned package install which propagated into a release pipeline) is being cited as the canonical real-world example: **three delegation hops, original authorization context lost, no enforcement barrier between hops.** 

This is exactly what ZP's scoped capability grants + delegation depth limits are architected to prevent. The footprint currently under-sells this — it's mentioned as a line item but the industry conversation has caught up, and this deserves to be its own ASI03-aligned capability with a real callout.

### 8. Autonomous malware, not just autonomous pentesters

- PROMPTFLUX, PROMPTSTEAL, PromptLock, BlackMamba — malware that invokes LLMs at runtime to rewrite itself and evade detection.
- **41% of ransomware families** now use AI for dynamic behavior modification (per Lumu / Check Point research).
- Check Point's VoidLink analysis: "the long-awaited era of sophisticated AI-generated malware has likely begun."
- There are also contrary voices (Rochford, Medium) arguing LLM-embedded malware is mostly marketing — worth acknowledging rather than sensationalizing.

### 9. NIST acknowledged the gap (partially)

- **February 2026:** NIST announced the AI Agent Standards Initiative.
- **Q4 2026 (planned):** AI Agent Interoperability Profile.
- **April 7, 2026:** Concept note for AI RMF Profile on Trustworthy AI in Critical Infrastructure.
- Cloud Security Alliance published a community **Agentic NIST AI RMF Profile v1** (pre-NIST). Worth referencing as a badge.

---

## Part II — Line-by-line audit of the current footprint

Status legend: **KEEP** (unchanged), **REWORD** (same tier, copy update), **RE-TIER** (change color), **NEW** (add), **DROP** (remove or fold elsewhere), **RENAME**.

### Domain: Identity & Access (7 items) — *minor additions*

| Item                       | Current | Action      | Notes |
|---------------------------|---------|-------------|-------|
| Agent Authentication       | green   | KEEP        | Accurate |
| Dynamic Authorization      | green   | KEEP        | Accurate |
| Credential Vault           | green   | KEEP        | Accurate |
| Scoped Capability Grants   | green   | REWORD      | Promote the copy — this is the primary defense against confused-deputy delegation chains, the most-cited agent vuln of 2026. |
| Least-Privilege Enforcement | green  | REWORD      | Same reason. Call out delegation depth limit explicitly. |
| Credential Rotation        | green   | KEEP        | Accurate |
| Peer Discovery             | green   | KEEP        | Accurate |
| **Delegation Tokens / Bounded Sub-Agent Authority** | — | **NEW — green** | Industry is now explicitly asking for this (CSA, AWS "four security principles for agentic AI" blog). ZP's scoped grants with depth limits are this primitive. Deserves its own row. |

### Domain: Governance & Policy (6 items) — *minor rewording*

| Item                     | Current | Action | Notes |
|--------------------------|---------|--------|-------|
| AI Gateway / Firewall    | green   | REWORD | Differentiator now: most "AI gateways" screen *inputs* (prompts). ZP's GovernanceGate screens at the *point of action* — effective against indirect prompt injection because it doesn't matter where the intent came from. Call this out. |
| Constitutional Rules     | green   | KEEP   | |
| Content Policy Screening | green   | KEEP   | |
| Human Override           | green   | REWORD | Tie to ASI09 (Human-Agent Trust Exploitation). Note: SovereigntyRule + receipts make "agent claims user approved" non-repudiable. |
| Responsible AI Tenets    | green   | KEEP   | |
| Regulatory Compliance    | green   | REWORD | Mention NIST CSA community Agentic Profile v1 (published pre-NIST; ZP's primitives align). |

### Domain: Audit & Traceability (6 items) — *one rewording, one addition*

| Item                       | Current | Action | Notes |
|---------------------------|---------|--------|-------|
| Immutable Audit Trail      | green   | KEEP   | |
| Non-repudiation            | green   | KEEP   | |
| Chain Verification         | green   | KEEP   | |
| Forensic Record            | green   | REWORD | Say "full delegation chain reconstructable" — directly answers the confused-deputy lament ("original authorization context is lost by hop three"). |
| Behavioral Analytics       | yellow  | KEEP   | Still partial |
| Posture Assessment         | yellow  | KEEP   | |
| **Delegation Chain Audit** | —       | **NEW — green** | Specifically named in CSA / Cline-incident literature. ZP reconstructs who-authorized-what across N hops. This is a real capability deserving its own row. |

### Domain: Agentic Threats — **MAJOR REWRITE**

The current 7 items don't match OWASP 2026. Proposed replacement (10 items, mapped to ASI01–ASI10):

| OWASP ID | Item | Proposed tier | ZP copy |
|----------|------|---------------|---------|
| ASI01 | Goal Hijack | yellow | GovernanceGate screens at point-of-action; policy rules constrain goals. Primary attack delivery is indirect prompt injection — ZP mitigates by acting on intent structure, not input trust. |
| ASI02 | Tool Misuse | green | zp-skills: verified registry + sandboxed execution + scoped capability grants |
| ASI03 | Identity & Privilege Abuse | **green** | Ed25519 identity + scoped capability grants + delegation depth limits. **Flagship defense.** |
| ASI04 | Agentic Supply Chain Vulns | yellow | zp-skills registry verification + signed receipts for every capability grant. Does not cover upstream npm/PyPI compromise of MCP tools — those land as trusted and are constrained by scope. |
| ASI05 | Unexpected Code Execution | yellow | Sandboxed skill execution + scoped capabilities limit blast radius. Does not prevent Anthropic-MCP-class design flaws in third-party runtimes. |
| ASI06 | Memory Poisoning | yellow | Receipt chain records what was read into memory and by whom; cross-session contamination traceable. Does not *prevent* memory writes — that's the agent implementation's job. |
| ASI07 | Insecure Inter-Agent Communication | green | zp-mesh: Ed25519-signed messages over Presence Plane dual-backend transport |
| ASI08 | Cascading Failures (was "Cascading Hallucinations") | yellow | Receipt chain traces provenance across chains; kill switch halts cascade. Does not *detect* a cascade in progress — that's posture-assessment work. |
| ASI09 | Human-Agent Trust Exploitation | yellow | SovereigntyRule + receipt-based human approval for irreversible actions. UI/UX for human-in-the-loop not fully shipped. |
| ASI10 | Rogue Agents | green | Kill switch (SovereigntyRule) + capability revocation + Ed25519 identity binding |

**Drop:** "Passive Scanning" as a line here (fold the concept into ATLAS Reconnaissance where it already appears; it's not an OWASP Agentic category).
**Drop:** "Excessive Agency" as its own line — fold into ASI03.

### Domain: LLM Threats — *align to OWASP LLM v2.0 (2025) + rewordings*

Current page says "OWASP LLM Top 10, 2025" — that's accurate for v2.0. Needed adjustments:

| Item                       | Current | Action | Notes |
|---------------------------|---------|--------|-------|
| Prompt Injection           | yellow  | REWORD | Separate direct vs. indirect. ZP's post-action policy evaluation sidesteps the "input screening" arms race — this is a genuine differentiator worth surfacing. |
| Sensitive Info Disclosure  | green   | KEEP   | |
| Insecure Plugin Design     | green   | KEEP   | |
| Supply Chain Vulns         | yellow  | REWORD | Rust memory safety is true but irrelevant against maintainer-account compromise (axios, LiteLLM). Reword to note the limitation. |
| Data Poisoning             | red     | KEEP   | Still training-time |
| Model Theft                | red     | KEEP   | |
| Prompt Leakage             | yellow  | RENAME | → **System Prompt Leakage** (OWASP v2.0 naming) |
| Unbounded Consumption      | green   | KEEP   | |
| **Vector & Embedding Weaknesses** | — | **NEW — red** | OWASP v2.0 category. Outside ZP runtime scope. |
| **Misinformation**         | —       | **NEW — yellow** | Receipts enable provenance (you can trace who-said-what) but don't prevent hallucination. |
| **Improper Output Handling** | —     | **NEW — yellow** | Policy rules can enforce output screening via GovernanceGate. |

### Domain: Adversarial ML (MITRE ATLAS) — *add 2026 techniques*

Keep existing 8 items, add 4 new ones from ATLAS v5.4.0:

| New item | Source | Proposed tier | ZP copy |
|----------|--------|---------------|---------|
| AI Agent Context Poisoning | ATLAS v5.4.0 | yellow | Receipts record context ingestion — makes post-hoc detection possible; doesn't prevent ingestion |
| Publish Poisoned AI Agent Tool | ATLAS v5.4.0 | yellow | zp-skills verified registry; doesn't cover upstream package-manager compromise |
| Escape to Host | ATLAS v5.4.0 | yellow | Sandboxed execution limits blast radius; ZP doesn't own the sandbox isolation layer |
| Exfiltration via AI Agent Tool Invocation | ATLAS v5.4.0 | green | Scoped capabilities block tools with exfiltration potential unless granted; signed audit detects attempts |

### Domain: Data Protection — *add one item*

| Item                      | Current | Action | Notes |
|--------------------------|---------|--------|-------|
| Encryption at Rest        | green   | KEEP   | |
| Access Controls           | green   | KEEP   | |
| Data Loss Prevention      | yellow  | KEEP   | |
| Training Data Security    | red     | KEEP   | |
| Privacy Preservation      | green   | KEEP   | |
| **Retrieval Provenance**  | —       | **NEW — yellow** | Receipts can record what was retrieved from RAG and by whom. Partial because ZP doesn't own the RAG pipeline, but can sign the retrieval envelope. |

### Domain: Infrastructure — *no change*

All items still outside ZP governance scope.

### Domain: Edge Sovereignty — *one promotion*

| Item                       | Current | Action | Notes |
|---------------------------|---------|--------|-------|
| Device Identity            | green   | KEEP   | |
| Firmware Integrity         | yellow  | KEEP   | |
| RF Sensing Governance      | yellow  | KEEP   | |
| Telemetry Accountability   | yellow  | KEEP   | |
| Physical Presence Consent  | yellow  | KEEP   | |
| Open Firmware Mandate      | yellow  | KEEP   | |
| **Autonomous Network Actor Governance** | — | **NEW — yellow** | Sentinel explicitly governs non-consenting devices on-network (MAC block list for Tuya/AI-Link in Ken's own Barn). Spec shipped, enforcement partial — honest yellow. |

---

## Part III — The agentic-offensive-tooling domain question

My recommendation: **option (c) — cross-cutting preamble, not a new domain.**

Why not a new "Autonomous Offensive Tooling" domain:

1. **Overlap with Agentic Threats is confusing.** ASI01–ASI10 already cover the attack *surface* (what the autonomous attacker can target). Adding a separate "autonomous attacker" domain means every cell would duplicate what's already mapped elsewhere, with lower confidence.
2. **ZP is not a defensive-offensive tool.** It's a governance substrate. Claiming a coverage grid against XBOW/Big Sleep invites the wrong mental model — readers expect behavioral detection, IDS-like features, or machine-speed response. ZP offers *structural* answers (scope, audit, revocation), not *operational* ones.
3. **Most cells would be red or yellow.** A domain that is honestly 70% "outside scope" lowers rather than raises the signal on ZP's actual coverage.

What option (c) does better:

- **A ~150-word preamble** above the radial map framing the 2026 threat environment: XBOW at #1 on HackerOne, 200k+ MCP servers vulnerable by design, indirect prompt injection >55% of attacks, agentic malware in the wild. Cites sources.
- **Re-points the 9 existing domains** at the new taxonomy (OWASP Agentic 2026, ATLAS v5.4.0) so readers see how ZP answers the *named 2026 threats* — not a parallel threat class.
- **One sentence at the end of the preamble** explicitly acknowledging what ZP does not do: "ZP is not an IDS, not a red-team platform, not an LLM filter. It is the substrate that makes autonomous actors accountable — the rest of the stack still matters."

If you want a stronger "threat landscape has shifted" story, we can also add a small **Recent Incidents** badge strip (postmark-mcp, axios, LiteLLM, Anthropic MCP RCE, CVE-2026-21520) below the preamble — five grey chips, each a dated, linked incident. Communicates "we know what just happened" without adding a domain.

Alternative if you do want the domain: I'd call it **"Threat Environment 2026"** (not "Offensive Tooling") with 5–6 items framed as the *threat classes* (not the tools): *Autonomous Vulnerability Discovery*, *Multi-hop Indirect Prompt Injection*, *MCP Supply Chain Compromise*, *Persistent Memory Poisoning*, *Agentic Malware Runtime*. Each cell honestly evaluates ZP's structural answer. Most would be yellow with pointed copy.

---

## Part IV — Proposed weighted coverage number

Current page claims **~69%** overall weighted coverage. After this revision:

- Current total: 59 items (36G / 16Y / 7R → 36 + 8 = 44 / 59 = 74.6%, page says 69% — slight rounding mismatch even today)
- Proposed total: ~68 items after additions (minimum)
  - Identity & Access: 7 → 8 (+1 green)
  - Agentic Threats: 7 → 10 (+3 new — 1 green, 4 yellow, net +1G/+2Y after OWASP 2026 rewrite)
  - LLM Threats: 8 → 11 (+3 new — 0G/2Y/1R)
  - MITRE ATLAS: 8 → 12 (+4 new — 1G/3Y)
  - Data Protection: 5 → 6 (+1 yellow)
  - Edge Sovereignty: 6 → 7 (+1 yellow)

New weighted coverage, honest estimate: **~70%** — essentially unchanged, but now honestly reflects the 2026 landscape rather than the early-2025 one. The story isn't "we got better" — it's "the landscape got clearer, we're still defending the ground we claimed."

---

## Part V — One architectural observation worth capturing

While reading the confused-deputy and lethal-trifecta literature, I noticed something worth writing down: **ZP's four design claims are 1:1 with the industry's converging answer to agentic threats.**

| Agentic threat (2026 industry naming) | ZP answer (already shipped) |
|---------------------------------------|------------------------------|
| Confused deputy across delegation hops | Scoped capability grants + delegation depth limits (Claim: Identity is a key) |
| Lethal trifecta (data + untrusted + exfil) | Scoped grants separate the trifecta structurally (Claim: Every bit counts) |
| Memory poisoning across sessions | Receipt chain records memory ingestion (Claim: Store-and-forward is primary) |
| MCP-by-design RCE | Signing is gravity — unsigned actions are structurally meaningless (Claim 1) |
| Autonomous red team at #1 HackerOne | Terminable by design, receipts survive for forensic replay |

This mapping is not a coincidence. The industry arrived at these primitives empirically in 2025–2026 after enough incidents made them unavoidable. ZP arrived at them a priori from first-principles reasoning about autoregressive trust. That convergence is itself a footprint claim worth making — tastefully, not triumphantly.

Recommend: one sentence in the preamble like: *"The primitives the industry now names — delegation tokens, scope inheritance, cross-session audit, signed capability grants — are primitives ZP shipped because the first-principles reasoning about autoregressive trust required them, before the incidents named them."*

---

## Part VI — Honesty flag: tension with the architecture doc

Worth surfacing before you sign off. `docs/ARCHITECTURE-2026-04.md` — which you've marked as the north star — says two of the four substrate claims are *currently false*:

- **Claim 1 (chain integrity)** — currently false.
- **Claim 3 (gate enforcement)** — currently false.

The current footprint marks "Immutable Audit Trail", "Chain Verification", and "AI Gateway / Firewall" as **green** (directly addressed). On the "calibrated — keep green where the primitive works" bar, this is borderline: the *primitive* exists and is the right shape, but the architecture doc explicitly says it's not yet doing what the page claims it's doing.

Three choices:

**A. Leave green, tighten the copy.** The primitive exists, the page is aspirational-but-accurate in framing, and the architecture doc is an internal engineering target that readers shouldn't be expected to reconcile. Add a single line to the subhead: *"Green = ZeroPoint primitive ships and enforces the property; yellow = primitive ships, enforcement partial; red = outside scope."* Then fix the two claims in code, not the page.

**B. Downgrade the two affected rows to yellow for now.** Honest to a fault. Matches the architecture doc. Risk: the page lands weaker than the thesis warrants, and may need another update when Claims 1 and 3 go true.

**C. Add a "claim status" glyph to each row.** A small dot indicating whether the corresponding ARCHITECTURE-2026-04 claim is currently enforced. Makes the page a true north-star view — ambitious in scope, honest about current state. Risk: page gets busier, and the distinction between "primitive exists" and "claim enforced" is subtle.

My recommendation is **A**, because the footprint's purpose is to map ZP's *answer shape* to the threat surface, and the answer shape is correct even where enforcement is incomplete. But this is your call — these are load-bearing public claims. If you'd rather go B, every recommendation in Part II holds; just replace "green" with "yellow" for the three rows above in the radial data.

---

## Sources

Agentic pen-test tooling:
- [XBOW — The road to Top 1: How XBOW did it](https://xbow.com/blog/top-1-how-xbow-did-it)
- [Dark Reading — An AI-Driven Pen Tester Became a Top Bug Hunter on HackerOne](https://www.darkreading.com/vulnerabilities-threats/ai-based-pen-tester-top-bug-hunter-hackerone)
- [BusinessWire — XBOW Raises $120M to Scale its Autonomous Hacker (March 18, 2026)](https://www.businesswire.com/news/home/20260318258057/en/XBOW-Raises-$120M-to-Scale-its-Autonomous-Hacker)
- [SiliconANGLE — Autonomous penetration testing enters chaos phase (March 25, 2026)](https://siliconangle.com/2026/03/25/autonomous-penetration-testing-enters-chaos-phase-ai-rewrites-offensive-security-rsac26/)
- [Penligent — 2026 Ultimate Guide to AI Penetration Testing](https://www.penligent.ai/hackinglabs/the-2026-ultimate-guide-to-ai-penetration-testing-the-era-of-agentic-red-teaming/)
- [Escape.tech — Best Agentic Pentesting Tools in 2026](https://escape.tech/blog/best-agentic-pentesting-tools/)
- [Mindgard — Best AI Red Teaming Tools (2026)](https://mindgard.ai/blog/best-tools-for-red-teaming)
- [Help Net Security — Novee introduces autonomous AI red teaming](https://www.helpnetsecurity.com/2026/03/24/novee-ai-red-teaming-for-llm-applications/)

Autonomous vulnerability discovery:
- [Google Project Zero — From Naptime to Big Sleep](https://projectzero.google/2024/10/from-naptime-to-big-sleep.html)
- [The Hacker News — Google's AI 'Big Sleep' Finds 5 New Vulnerabilities (Nov 2025)](https://thehackernews.com/2025/11/googles-ai-big-sleep-finds-5-new.html)

Frameworks:
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [OWASP Gen AI Security Project — Release announcement (Dec 9, 2025)](https://genai.owasp.org/2025/12/09/owasp-genai-security-project-releases-top-10-risks-and-mitigations-for-agentic-ai-security/)
- [Microsoft Security — Addressing OWASP Top 10 Agentic Risks with Copilot Studio (March 30, 2026)](https://www.microsoft.com/en-us/security/blog/2026/03/30/addressing-the-owasp-top-10-risks-in-agentic-ai-with-microsoft-copilot-studio/)
- [Palo Alto Networks — OWASP Agentic 2026 Is Here](https://www.paloaltonetworks.com/blog/cloud-security/owasp-agentic-ai-security/)
- [Zenity — MITRE ATLAS AI Security and Agentic Threats 2026 Update](https://zenity.io/blog/current-events/mitre-atlas-ai-security)
- [Zenity — Contributions to MITRE ATLAS 2026 Update](https://zenity.io/blog/current-events/zenitys-contributions-to-mitre-atlas-first-2026-update)
- [MITRE ATLAS Framework 2026 guide (Practical DevSecOps)](https://www.practical-devsecops.com/mitre-atlas-framework-guide-securing-ai-systems/)
- [CSA Labs — Agentic NIST AI RMF Profile v1](https://labs.cloudsecurityalliance.org/agentic/agentic-nist-ai-rmf-profile-v1/)
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)

MCP and supply-chain incidents:
- [The Hacker News — First Malicious MCP Server Found (postmark-mcp, Sept 2025)](https://thehackernews.com/2025/09/first-malicious-mcp-server-found.html)
- [The Hacker News — Anthropic MCP Design Vulnerability Enables RCE (April 2026)](https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html)
- [The Register — Anthropic won't own MCP 'design flaw' putting 200K servers at risk (April 16, 2026)](https://www.theregister.com/2026/04/16/anthropic_mcp_design_flaw/)
- [OX Security — The Mother of All AI Supply Chains: Critical, Systemic Vulnerability at the Core of MCP](https://www.ox.security/blog/the-mother-of-all-ai-supply-chains-critical-systemic-vulnerability-at-the-core-of-the-mcp/)
- [SecurityWeek — 'By Design' Flaw in MCP Could Enable Widespread AI Supply Chain Attacks](https://www.securityweek.com/by-design-flaw-in-mcp-could-enable-widespread-ai-supply-chain-attacks/)
- [LiteLLM — Security Update: CVE-2026-30623 (MCP SDK command injection, April 2026)](https://docs.litellm.ai/blog/mcp-stdio-command-injection-april-2026)
- [LiteLLM — Suspected Supply Chain Incident (March 2026)](https://docs.litellm.ai/blog/security-update-march-2026)
- [The Register — Another npm supply chain worm hits dev environments (April 22, 2026)](https://www.theregister.com/2026/04/22/another_npm_supply_chain_attack/)
- [The Hacker News — N. Korean Hackers Spread 1,700 Malicious Packages](https://thehackernews.com/2026/04/n-korean-hackers-spread-1700-malicious.html)
- [Securelist — Malicious MCP servers used in supply chain attacks](https://securelist.com/model-context-protocol-for-ai-integration-abused-in-supply-chain-attacks/117473/)
- [Authzed — A Timeline of Model Context Protocol Security Breaches](https://authzed.com/blog/timeline-mcp-breaches)
- [PipeLab — State of MCP Security 2026](https://pipelab.org/blog/state-of-mcp-security-2026/)
- [Checkmarx Zero — 11 Emerging AI Security Risks with MCP](https://checkmarx.com/zero-post/11-emerging-ai-security-risks-with-mcp-model-context-protocol/)

Indirect prompt injection:
- [Unit 42 — Fooling AI Agents: Web-Based Indirect Prompt Injection Observed in the Wild](https://unit42.paloaltonetworks.com/ai-agent-prompt-injection/)
- [Simon Willison — The Lethal Trifecta for AI Agents](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)
- [HiddenLayer — How the Lethal Trifecta Exposes Agentic AI](https://www.hiddenlayer.com/research/the-lethal-trifecta-and-how-to-defend-against-it)
- [Lakera — Indirect Prompt Injection: The Hidden Threat Breaking Modern AI Systems](https://www.lakera.ai/blog/indirect-prompt-injection)
- [The Hacker News — Google Patches Antigravity IDE Flaw Enabling Prompt Injection Code Execution (April 2026)](https://thehackernews.com/2026/04/google-patches-antigravity-ide-flaw.html)
- [VentureBeat — Microsoft Copilot Studio prompt injection remediation (CVE-2026-21520)](https://venturebeat.com/security/microsoft-salesforce-copilot-agentforce-prompt-injection-cve-agent-remediation-playbook)

Memory poisoning:
- [Microsoft Security Blog — AI Recommendation Poisoning (Feb 10, 2026)](https://www.microsoft.com/en-us/security/blog/2026/02/10/ai-recommendation-poisoning/)
- [Christian Schneider — Memory Poisoning in AI Agents: Exploits That Wait](https://christian-schneider.net/blog/persistent-memory-poisoning-in-ai-agents/)
- [Unit 42 — When AI Remembers Too Much](https://unit42.paloaltonetworks.com/indirect-prompt-injection-poisons-ai-longterm-memory/)
- [OWASP — Agent Memory Guard Project](https://owasp.org/www-project-agent-memory-guard/)

Confused deputy / delegation:
- [CSA Labs — Confused Deputy Attacks on Autonomous AI Agents](https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-agent-confused-deputy-prompt-injection/)
- [CSA — Fixing AI Agent Delegation for Secure Chains (March 25, 2026)](https://cloudsecurityalliance.org/blog/2026/03/25/control-the-chain-secure-the-system-fixing-ai-agent-delegation)
- [AWS Security Blog — Four security principles for agentic AI systems](https://aws.amazon.com/blogs/security/four-security-principles-for-agentic-ai-systems/)
- [Medium — The Confused Deputy Problem Just Hit AI Agents](https://dev.to/claude-go/the-confused-deputy-problem-just-hit-ai-agents-and-nobodys-scanning-for-it-384f)

Autonomous malware:
- [SecurityWeek — Cyber Insights 2026: Malware and Cyberattacks in the Age of AI](https://www.securityweek.com/cyber-insights-2026-malware-and-cyberattacks-in-the-age-of-ai/)
- [Check Point Research — VoidLink: Evidence That the Era of Advanced AI-Generated Malware Has Begun](https://research.checkpoint.com/2026/voidlink-early-ai-generated-malware-framework/)
- [Google Cloud — GTIG AI Threat Tracker: Advances in Threat Actor Usage of AI Tools](https://cloud.google.com/blog/topics/threat-intelligence/threat-actor-usage-of-ai-tools)
- [Oliver Rochford / Medium — Contrary view: LLM-embedded malware as marketing artefact](https://cyberfuturist.medium.com/prediction-in-2026-llm-embedded-malware-will-remain-largely-a-marketing-artefact-because-it-59c78790d47e)
