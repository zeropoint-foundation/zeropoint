# Chinese AI Standardization ↔ ZeroPoint — Comparative Analysis

**Author:** Cowork sweep agent, at operator request 2026-08-20.
**Status:** Research artifact. Not canonical, not indexed under `CANONICAL-CORPUS-INDEX-2026-07.md`. Comparative reading of the emerging Chinese apparatus against ZP's `KEEL-2026-07.md` and the Tier-2 elaborations indexed alongside it.
**Prerequisite reading:** `tc260-corpus-survey-2026-08.md` (this session's earlier survey of the TC260 corpus).
**Companion:** `ai-landscape-log.md` (running observation of the same territory over time).

**Verification posture per KEEL III.22 (verify before commit):**
- ZP claims are grounded in `KEEL-2026-07.md` §II (invariants), §III (axioms), §IV (ontology definitions), and §XIV (substrate realization), read at primary in this session.
- Chinese-apparatus claims are grounded in **thirteen load-bearing primaries** touched this session, ordered by depth of read:
  - **Full text:** CAC 《智能体规范应用与创新发展实施意见》 (`cac.gov.cn` 2026-05-08); CAC 《人工智能生成合成内容标识办法》 (`cac.gov.cn` 2025-03-14, all 14 articles); CAC 《生成式人工智能服务管理暂行办法》 (`cac.gov.cn` 2023-07-13, 7-agency Order No. 15, all 24 articles across 5 chapters — the *parent regulation* grounding much of the downstream corpus); CAC 《互联网信息服务深度合成管理规定》 (`cac.gov.cn` 2022-12-11, 3-agency Order No. 12, in force 2023-01-10 — the middle tier of the content-marking statutory chain); CAC 《互联网信息服务算法推荐管理规定》 (`cac.gov.cn` 2022-01-04, 4-agency Order No. 9, in force 2022-03-01 — the **root regulation** defining the 备案 mechanism that all downstream algorithm-related regulations point at).
  - **Full structure + key clauses:** TC260-TR-005-2026 《智能体安全标准化研究》 (92pp v1.0-202603, operator-supplied via RAR unpack); TC260-TR-004-2026 《工业具身智能安全标准化研究》 (31pp v1.0-202603, same bundle); GB/T 45654-2025 《生成式人工智能服务 安全基本要求》 (§4-§6 + Apps A/B via SAMR-cleared mirror at `content.mlex.com`); MIIT 《工业和信息化领域人工智能安全治理标准体系建设指南 (2025)》 (seven-dimension framework + 智能体 five-subdimension via CAICT-hosted OSS mirror).
  - **Clause-level reconstruction:** GB 45438-2025 (Apps E metadata schema + F single-instance rule + explicit-marking dimensions + Article 6 four-step verification, via PwC HK compliance-guide quotation).
  - **Landing / metadata:** 网安秘字〔2026〕34号 5-TR release notice; 网安秘字〔2026〕44号 second-batch needs notice; news.cn primary on GB/Z 185 series (2026-06-26); TC260 GB/T 45654 landing page.
- Audit trail preserved in Appendices A.1–A.4, one delta note per primary-read pass, with confidence upgrades (▲), corrections (✗→✓), refinements (◇), and roadmap-bearing findings (◆) keyed against specific body-section claims.
- **Rule 6 from the sweep discipline** — *distrust convergence in your own favour* — is in force throughout §5 and §11 (where convergence is asserted, the mechanism producing the apparent match is named explicitly, so a future reviewer can independently check whether the shapes are actually the same or only appear to be).

---

## 1. What is being compared

Two apparatus that arrive at agent-era substrate design from different starting posture, on different timetables, with different institutional theories of how safety is produced.

**ZeroPoint** — sovereign-operator-rooted substrate. KEEL 2026-07 the canonical spec; nine design principles (§II.13) the invariants; three Substrate Forms (§XIV.1) the realization tier; the Regent + officer cadre + Cartographer the cognitive architecture. Layer A/B two-layer artifact model. Chain-anchored per-sovereign, per-substrate discipline. Foundation is a peer among sovereigns, not an authority over them.

**Chinese apparatus** — institutional-issuance-rooted standardization program. TC260 the primary standards body, WG9 the AI-specific working group; MIIT / CAICT parallel track; CAC the regulator; SAMR / State Council driving the numeric agenda ("100 AI national standards"). Multi-tier instrument classes (GB mandatory / GB/T recommended / GB/Z guidance / TC260-nnn operational / TR research). Standard-first, then operationalization; regulator-anchored trust chain; certified-evaluator observation reach.

Both are load-bearing. Both are internally coherent. Where they arrive at similar shapes, that is worth naming carefully; where they diverge, the divergence usually traces to their institutional-theory differences and is not a bug in either apparatus.

---

## 2. Comparative axes

Nine axes on which the two apparatus can be read against each other. Each subsequent section applies one axis; §5 and §6 collect the composite reading.

1. **Trust root** — where authority terminates.
2. **Identity primitive** — what "agent identity" *is*, structurally.
3. **Delegation model** — how authority passes and narrows.
4. **Chain / ledger discipline** — what is anchored, where, by whom.
5. **Observation reach** — who gets to see the substrate's state.
6. **Cognitive layer** — how the reasoning surface is treated.
7. **Content provenance** — how artifacts carry their history.
8. **Emergency response** — what "revoke" and "recover" mean.
9. **Bindingness layering** — how instruments compose.

---

## 3. Object-level correspondences

Matched pairs, with the concrete instrument on each side named. Absence of a pair — either side blank — is itself a finding and is called out.

| Territory | ZeroPoint side | Chinese apparatus side |
|-----------|---------------|-----------------------|
| Trust root | KEEL II.5 Genesis-as-single-root (Decision A); III.1 sovereign operator is fundamental unit | 身份码 (identity code) issuance under GB/Z 185 series; institutional filing regime under GB/T 45654 |
| Agent identity | KEEL IV.2 Genesis-derived / Genesis-certified keys; PHONE-AND-IDENTITY-2026-07.md | GB/Z 185.2-2026 身份码 + GB/Z 185.3-2026 身份管理 |
| Agent description / capability declaration | AGENT-TOOL-CONTRACT-2026-06.md; CAPABILITY-VERIFICATION-RECEIPTS.md | GB/Z 185.4-2026 智能体描述; GB/Z 185.7-2026 智能体工具调用 |
| Agent discovery | PEER-DISCOVERY-AS-OUTREACH-2026-07.md; KEEL IV.7 Peer discovery | GB/Z 185.5-2026 智能体发现 |
| Agent-to-agent interaction | KEEL Part VII Peer-Verification Contract; CROSS-SUBSTRATE-PEER-CONTRACT-2026-06.md | GB/Z 185.6-2026 智能体交互; AIP (智能体互联协议) |
| Delegation | KEEL II.4 delegation narrowing; III.16 precedent grows autonomous scope; IV.5 Delegation / Mandate | CAC 《实施意见》 clause 6 (决策权限 tiering); TC260 solicited standard 智能体应用安全基本要求 |
| Cascade risk / multi-agent safety | KEEL III.25 (octopus-shaped, autonomic operation); CIRCUIT-BREAKER-2026-07.md | TR-005 AIA06 (多智能体级联幻觉扩散、冲突死锁和资源超载); TR-005 §3.2.2 群体效应凸显; MIIT F 多智能体协作安全 |
| Behavior verifiability | KEEL III.19 detectability over invulnerability; chain-anchored discipline throughout | CAC 《实施意见》 clause 7 (blockchain-anchored verifiable/traceable agent behavior in important scenarios) |
| Substrate blindness / observation bounds | KEEL III.24 aligned blindness; OBSERVATION-PLANE-2026-07.md (delegation-scoped) | CAC 内生安全 framing (clause 8); regulator-inspection reach (clause 11 分级治理) |
| Provenance / content marking | MEDIA-PROVENANCE-2026-07.md; MEDIA-PROVENANCE-INTEROP-2026-07.md; C2PA composition | GB 45438-2025 mandatory 生成合成内容标识方法 |
| Sovereign fleet / multi-device | KEEL III.15 sovereign fleet as one coordinated substrate | CAC 《实施意见》 clause 4 智能互联网; 智能体注册平台 (proposed) |
| Cross-org / peer verification | KEEL Part VII; PEER-TRUST-ANCHOR-2026-07.md | AIP + GB/Z 185 series taken as a system |
| Cognitive plane / metacognition | KEEL III.12 metacognition as load-bearing; COGNITIVE-INPUT-PLANE / COGNITIVE-SELF-OBSERVER / COGNITIVE-ACT-ACCOUNTING (all 2026-07) | **Partial pair, scope-limited.** For general software agents: TR-005 §3.5 gestures at 决策过程透明可解释 but stops there; TR-005 §3.6 explicitly classifies AIA05 hallucination / AIA01 prompt injection / AIA10 memory hallucination as beyond standards' scope. For **embodied AI**: TR-004 §一.(四) names 认知安全 as first-class with concrete substrate requirements (输入输出监测, 模型版本审计, 抗对抗攻击). MIIT §A 治理能力 lists 透明性 / 可解释性 as substrate primitives. |
| Coordination-not-oversight | KEEL III.23 coordination, not oversight; SOVEREIGN-KINSHIP-PRIMITIVES-2026-07 | **No direct pair.** Chinese framing is oversight-by-design (备案 / 检测 / 召回) for sensitive domains. |
| Substrate Forms axis | KEEL III.8 bounded operator sovereignty; XIV.1 Three Forms (Sovereign / Appliance / Companion) | **No direct pair.** No Chinese instrument names trust-chain-reach as an explicit design axis. |
| Application traction / vertical playbooks | **No direct pair on ZP side.** ZP corpus is substrate-first; vertical application playbooks are downstream. | CAC 《实施意见》 sections 4–5 (science / industry / consumption / welfare / social governance — 34 clauses of vertical application direction); MIIT construction guide F 应用安全 (工业应用, 行业应用, 智能产品, 智能服务) |
| Agent-security sub-decomposition | KEEL substrate-integrity + boundary-plane + P9 + III.16/III.25 + Part VII (Peer-Verification Contract) — one for each of MIIT's five | MIIT F 智能体安全: 内生安全 / 数据接口安全 / 人机协作安全 / 自主操作安全 / 多智能体协作安全 (five-for-five parity with KEEL discipline areas — the strongest single-instrument alignment recorded) |
| Standards-framework partitioning | Two-layer architecture (Layer A invariants + Layer B canonical claims); Tier-2 elaborations under `docs/design/` | Two Chinese partitionings of the same territory: TC260 5-part (基础共性 / 安全管理 / 关键技术 / 测试评估 / 产品与应用); MIIT 7-part (治理能力 / 基础设施 / 网络 / 数据 / 算法模型 / 应用 / 赋能) |
| Regulation-side authority chain | KEEL §II invariants (Layer A) → §III axioms (Layer B canonical claims) → Tier-2 elaborations under `docs/design/` | Six-tier statutory chain for generative-AI content marking: Order No. 9 (2022, algorithm-推荐 root, 4-agency) → Order No. 15 (2023, gen AI, 7-agency) → Order No. 12 (2023, deep synthesis, 3-agency) → 《标识办法》 (2025, 4-agency) → GB 45438-2025 (mandatory standard) → TC260 A-B-C-D-E framework implementations. CAC + MIIT + 公安部 stable three-agency core across all four regulations; sectoral additions vary. |
| Substrate-vs-operator role distinction | Substrate (Genesis-anchored, Layer A discipline) vs Operator (Regent + officer cadre execution) | Order No. 12 Article 23 four-role decomposition: 深度合成技术 / 深度合成服务提供者 / 深度合成服务**技术支持者** / 深度合成服务使用者. Technical-supporter carries substrate-provisioning obligations (Article 19 备案 by reference; Article 15 face/voice security assessment); service provider carries user-facing obligations (authentication, moderation, marking). Same two-layer architectural distinction as ZP, differently anchored. |
| User rights (algorithmic-decision transparency and control) | Sovereign operator decides — no external rights layer; delegation-scoped observation and P9 operator-retains-choice discipline place rights at operator altitude | Order No. 9 Article 17: (1) non-personalization opt-out; (2) user-tag deletion; (3) liability explanation for significant algorithmic impact on user rights. Chinese apparatus's GDPR-Article-22-shape user rights at regulation altitude. Order No. 9 Chapter 3 (Articles 16-22) covers transparency, minors, elderly, labor, consumers (explicit 大数据杀熟 prohibition), complaints. |

The last two rows on each side are the load-bearing asymmetries: ZP has structural axes the Chinese corpus has not surfaced; the Chinese corpus has vertical-application ground the ZP corpus has not covered.

---

## 4. Point-by-point analysis

### 4.1 Trust root — where authority terminates

**ZP.** Genesis is the singular sovereign root (KEEL II.5, III.1). Every subsequent key traces to Genesis via chain-anchored derivation or provisioning. The operator holds Genesis on hardware (Hardware Genesis per glossary); the substrate never holds raw Genesis material. Recovery via M-of-N pre-registered quorum tokens. There is no institutional overlay: no CA, no registrar, no certification body sits above Genesis. The Foundation retains trademark and defends the integrity clause but is a peer, not an authority (KEEL IV.1 Foundation definition).

**Chinese apparatus.** Identity is *issued* — the GB/Z 185.2 身份码 is granted by an issuing body under the standard's regime, and CAC's proposed 智能体注册平台 (Registration Platform) in the 《实施意见》 clause 4 is an *upstream* directory: "提供智能体数字身份管理、检索发现、能力声明等服务" (provides agent digital-identity management, retrieval and discovery, capability declaration services). **The statutory clause where this trust root actually terminates is 《暂行办法》 Article 17** — services with "opinion-forming or social mobilization capacity" must undergo security assessments and complete algorithm 备案 registration per 《互联网信息服务算法推荐管理规定》. The trust root is *institutional* — regulator + certified issuer + certified evaluator, with the service provider filing to the regime — and Article 17 is the mechanism that ties the filing to legal enforceability. Article 22 defines "service provider" broadly to include *individuals providing services via programmable APIs*, which brings API-exposed Sovereign-Form deployments into scope even without hosted-service infrastructure.

**The load-bearing contrast.** In the Chinese frame, an agent has identity because a body issued it identity; in ZP, an agent has identity because Genesis certified it. This is not a translation difference — it is a difference in *what happens if the top-level anchor is compromised or captured*. In an institutional-root regime, that pressure is applied to the issuing body; in a sovereign-root regime, that pressure is applied to the operator's Genesis holding, which they physically control. The two regimes are answering different threat models: capture of the issuing body (Chinese answer: multiple issuing bodies, oversight regime, filing requirements) vs capture of any body above the operator (ZP answer: no body sits above the operator).

**Composition question.** Can a ZP-Sovereign-Form operator obtain a GB/Z 185 身份码 for their agent without collapsing the trust chain to institutional-root? Structurally: the 身份码 could be a *downstream* attestation over the operator's Genesis-derived agent identity — a signed record by the issuing body that says "I recognize this key." This is architecturally analogous to how a Sovereign-Form deployment can compose with a downstream institutional layer without moving the trust root. **Whether that composition satisfies the standard's filing-regime intent is a separate question and is a compliance-analysis matter, not a substrate-design matter.**

### 4.2 Identity primitive — what "agent identity" *is*, structurally

**ZP.** A cryptographic key with a chain-anchored derivation or provisioning path to Genesis (KEEL IV.2). Identity is *a key, not a location* (principle 2). Portable across devices via the sovereign fleet primitive (III.15). Not a name in a registry; not a certificate under a hierarchy.

**Chinese apparatus.** 身份码 (identity code) — from the news.cn primary on GB/Z 185: "统一身份认证、全程追溯机制" (unified identity authentication + full-process traceability). The code is a *registry-issued token*, presumably cryptographically underpinned but definitionally a *reference* to a directory entry rather than the key itself.

**Coherence surface.** Both apparatus require agent identity to be *distinguishable*, *addressable*, and *interactable*. Both couple identity to capability declaration. Both anticipate discovery mechanisms. The five-stage GB/Z 185 pipeline (身份标识 → 能力描述 → 供需发现 → 协同交互 → 工具调用) matches the ZP flow (Genesis-derived key → capability-declaration receipt → peer discovery → peer-verification contract → tool contract) on shape, differing on where the anchor sits.

### 4.3 Delegation model — how authority passes and narrows

**ZP.** KEEL II.4 (delegation narrowing) states: capability delegation composes monotonically — a delegated capability is always a subset of the granting capability. Verified against the eight invariants at every hop. Chain-anchored via `delegation:granted:*` receipts. Withdrawn via signed revocation. Autonomous scope grows through precedent (III.16): operator-signed autonomous action becomes precedent for future similar actions; the corpus is chain-anchored.

**Chinese apparatus.** CAC 《实施意见》 clause 6 (明确决策权限, Clarify Decision Authority) — **three-tier authority framing that is structurally the same shape as KEEL III.16 and P9**:

> "厘清仅限用户本人决策、需由用户授权决策和智能体自主决策等各种决策方式的合理边界及所需权限。确保用户对智能体自主决策享有知情权和最终决策权，智能体执行操作不得超出用户授权范围。"
>
> *"Clarify the reasonable boundaries and required authorities of each decision mode: user-only decisions, user-authorized-delegated decisions, and agent-autonomous decisions. Ensure users hold the right to know and final decision authority over agent-autonomous decisions; agent execution must not exceed the user's authorized scope."*

This is a state-level regulatory document arriving at a three-tier authority decomposition that reads as a natural-language rendering of P9 ("the system acts; the operator signs"), with the further specification that agent-autonomous decisions require operator right-to-know and final decision authority even in the autonomous mode. **Rule 6 (distrust convergence in your own favour) is in force here** — the vocabulary is uncomfortably close. Two things worth noticing so the convergence is calibrated rather than assumed:

- The mechanism is left to the standards apparatus. Clause 7 immediately below proposes "rule-inlaying, behavior fencing, and blockchain-anchored verifiable/traceable records for important scenarios" as the compliance mechanism. ZP's delegation-receipt discipline is *one* such mechanism; the CAC text does not require it and does not name it.
- The three-tier framing is common industry vocabulary (Google's AP2, Anthropic's Claude Skills operator-approval flow, and the OWASP Agentic Skills Top 10 all reach for similar three-tier decompositions). The apparent convergence with ZP is partly a convergence with the whole industry rather than a specifically-ZP-shaped convergence.

That said, the CAC document is the strongest public state-level articulation of an operator-authority-preserving delegation model this sweep has surfaced.

### 4.4 Chain / ledger discipline — what is anchored, where, by whom

**ZP.** Every sovereign has one chain: append-only, hash-linked, per-sovereign, per-substrate (KEEL IV.1 Chain). "Signing is gravity" — unsigned receipts are structurally meaningless (principle 1). "Store-and-forward is primary" — the chain survives outages (principle 5). "Chain is truth; ontology is understanding" (III.13) — derived state can be recomputed, chain cannot be rewritten.

**Chinese apparatus.** CAC 《实施意见》 clause 7:

> "探索利用区块链等技术，建立重要应用场景智能体行为可验证、可追溯机制，防范智能体不当行为引发重大风险。"
>
> *"Explore the use of blockchain and similar technologies to establish verifiable, traceable agent behavior mechanisms in important application scenarios, preventing significant risks from improper agent behavior."*

**The most consequential convergence in the current sweep.** A state-level regulatory document naming *blockchain-anchored verifiable and traceable agent behavior records* as the compliance mechanism for "important scenarios." Not the same substrate ZP is building, but the same architectural pattern for the same problem. Two contrasts worth naming so the convergence is not overstated:

- The Chinese framing is *"blockchain and similar technologies"* — technology-neutral, potentially satisfied by any ledger. ZP's chain is per-sovereign and per-substrate, not a shared external chain. A "blockchain" implementation of clause 7 could be a shared industry ledger where all agents write; ZP's chain is not that. The compositional question is whether a per-sovereign chain satisfies a mechanism spec written for shared ledgers.
- The Chinese framing is *"important application scenarios"* only. ZP's chain is universal — every consequential action, every operator, every substrate. The Chinese scoping is narrower by design.

### 4.5 Observation reach — who gets to see the substrate's state

**ZP.** OBSERVATION-PLANE-2026-07 spec: six observation surfaces (processes, network, filesystem, persistent surfaces, credentials, application state). Baseline observation is the substrate's own footprint; broader observation is *delegation-scoped* — requires operator-signed `delegation:observe:*` receipts. KEEL III.24 (aligned blindness) makes this a moral property: some data classes the substrate has no business observing regardless of who would authorize it.

**Chinese apparatus.** CAC 《实施意见》 clause 8 ("内生安全", intrinsic security) covers "data safety, personal information protection, cryptographic protection, attack detection, permission management, behavior control" — inward-facing. Clause 11 (分类分级治理, classification-tiered governance) makes *outward* observation regime-defined:

> "对于敏感领域及重点行业，由网信部门联合行业主管部门确定开放场景，根据相关法律法规、监管要求和安全防护标准，实行备案、检测、问题产品召回等管理措施。"
>
> *"For sensitive domains and key industries, the 网信 [CAC] department jointly with industry regulators determines open scenarios, and implements filing, testing, and defective-product recall management measures per relevant laws, regulations, oversight requirements and security protection standards."*

**The contrast is architectural, and the statutory clause is 《暂行办法》 Article 19.** Article 19 states explicitly: *"providers must cooperate and disclose training data sources, scale, type, annotation rules, algorithm mechanisms"* upon inspection. This is the operational clause that makes regulator-inspection reach concrete — the substrate is not merely inspectable *in principle*, it is required to *disclose* its internal state on demand. ZP structurally bounds observation; the Chinese regime structurally *unbounds* observation for sensitive/key domains via this Article 19 disclosure duty, and structurally bounds it (via industry self-testing and platform-mediated management) for lower-risk domains. This is where the aligned-blindness invariant (III.24) is furthest from the Chinese posture: III.24 says the substrate has no business observing some classes even under authorization, and Article 19's disclosure duty cannot accept "the substrate has no observation surface here" as a compliance answer.

**Composition question.** A ZP-Sovereign-Form deployment cannot satisfy sensitive-domain 备案 filing under the Chinese regime — the regime assumes the regulator can inspect, and Sovereign Form denies that reach. Companion Form (per KEEL XIV) — where the operator's daily driver stays in the vendor's scope — could theoretically satisfy inspection reach but at the cost of moving the trust root off the operator. This is the strongest example of KEEL Layer A invariants being incompatible with a specific external regime, and is important to name explicitly rather than paper over.

### 4.6 Cognitive layer — how the reasoning surface is treated

**ZP.** Extensive first-class treatment. KEEL III.12 makes metacognition load-bearing; IV.3 defines Regent, officer cadre, Cartographer, ontology, metacognition, reflexivity, introspection, self-awareness, confabulation gap. Tier-2 elaborations: COGNITIVE-INPUT-PLANE (context is priority-weighted, not a bucket), COGNITIVE-SELF-OBSERVER (post-emission verification), COGNITIVE-ACT-ACCOUNTING (witnessed-vs-asserted epistemic boundary), COGNITIVE-MODE-AND-AGENCY, METACOGNITIVE-FIDELITY-HARNESS, plus the mapping docs (COGNITIVE-PRIMITIVES-OPPORTUNITY-MAPPING, COGNITIVE-TOOLS-OPPORTUNITY-MAPPING).

**Chinese apparatus, general-agent scope.** For general software agents, the published Chinese instruments treat agents as *goal-executing systems* with security properties; the cognitive substrate itself is not surfaced at KEEL depth. TR-005 §3.5 mentions *"决策过程透明可解释"* as one AIA05 response measure but stops at "make the decision process explainable" — no witnessed-vs-asserted, no post-emission verification, no act-accounting. TR-005 §3.6 further classifies AIA05 (hallucination), AIA01 (prompt injection), and AIA10 (memory hallucination) into risk-treatment class 3: *"需标准提供基础支撑,风险根植于模型本质...其解决超越标准范围"* — TC260 explicitly naming these as beyond standards' reach.

**Chinese apparatus, embodied-agent scope — partial convergence.** For embodied AI, TR-004 §一.(四) makes **认知安全 (Cognitive Trustworthiness)** one of four first-class safety properties, with concrete substrate requirements: *"算法行为可解释、输入输出监测、模型版本审计与抗对抗攻击能力"* (algorithm behavior explainability, input/output monitoring, model version audit, adversarial resistance). This is direct pattern-level parallel to COGNITIVE-SELF-OBSERVER-2026-07 (post-emission verification) + METACOGNITIVE-FIDELITY-HARNESS-2026-08 (model-version-tagged fidelity measurement). The MIIT construction guide §A 治理能力 dimension lists 透明性 / 可解释性 / 可追溯性 as substrate primitives at governance-capability altitude.

**Amended asymmetry.** The claim that "metacognitive substrate has no TC260 equivalents" holds for general software agents (TR-005 scope). For embodied AI (TR-004 scope) and at governance-capability altitude (MIIT §A), the territory is surfaced with concrete substrate requirements — pattern-level convergence, though depth-of-treatment still favours the ZP corpus (witnessed-vs-asserted, act accounting, mode-and-agency have no Chinese counterpart). The depth gap is itself downstream of the root-authority delta per §11: regulator-drafted standards work at the interface level (make outputs verifiable); sovereign-root substrate can instrument the reasoning surface itself.

### 4.7 Content provenance — how artifacts carry their history

**ZP.** MEDIA-PROVENANCE-2026-07 + MEDIA-PROVENANCE-INTEROP-2026-07 spell out chain-anchored action-side receipts + C2PA content-side manifest composition. The 2026-08-20 sweep entry on the C2PA implementation guide named the five machine-readable assertions (`digitalSourceType`, `c2pa.ai-disclosure`, Regions of Interest, `inputTo`, Actions) that any C2PA-composing deployment now needs to handle.

**Chinese apparatus.** GB 45438-2025 — the *mandatory* content-marking standard, implementation instrument for the CAC 《生成合成内容标识办法》. Not the same technology as C2PA (search-level; not read at primary). Marks the *content* with a service-provider-attested signature; the identity-holder in the mark is the service, not the creator.

**Six-layer composition, not three-way.** Primary reading of GB 45438 Appendix E (5-element metadata schema) + CAC 《标识办法》 all 14 articles surfaced this territory at article-and-field precision. The composition is not "add three marking types"; it is six specific emission layers arranged across generator, distribution platform, and upstream substrate:

- **Layer 1 (generator, 《标识办法》 Article 4 explicit):** substrate emits visible text/audio marking. Precise dimensions per GB 45438: video/virtual scenes text height ≥ 5% of shortest edge for ≥ 2 seconds; images ≥ 5% shortest edge; audio "短长短短" rhythm at normal speed; all must include "AI" + "生成/合成". *Not natively covered by C2PA.*
- **Layer 2 (generator, 《标识办法》 Article 5 implicit + GB 45438 Appendix E fields 1-3):** substrate emits metadata containing (1) 生成合成属性 attribute, (2) 服务提供者身份标识, (3) 内容生产编号. Plausibly discharged by C2PA content credentials with these three fields mapped.
- **Layer 3 (generator, safe-harbor encouragement):** digital watermark (数字水印 — 鼓励 not 应, per Article 5). Plausibly discharged by C2PA `soft_binding` durable content binding.
- **Layer 4 (distribution platform, GB 45438 Appendix E fields 4-5):** platform-side enrichment adding (4) 传播服务提供者身份标识, (5) 传播内容编号.
- **Layer 5 (distribution platform, 《标识办法》 Article 6):** four-step verification chain — metadata check → user declaration acceptance → trace-detection protocol → self-report function.
- **Layer 6 (upstream, KEEL action-side):** chain-anchored receipt for operator provenance. Coexists with all above; not visible to downstream consumers but load-bearing for cross-substrate audit.

**Substrate-work implication for MEDIA-PROVENANCE-INTEROP-2026-07.** The field mapping between the five GB 45438 metadata elements and C2PA assertion fields is the specific compositional design item. Generator emits Layer 1 (visible marking) + Layer 2 (three fields in metadata) + Layer 3 (optional watermark) + Layer 6 (chain-anchored receipt). Distribution downstream adds Layers 4-5. **Simplification finding:** if the C2PA implementation includes `soft_binding` durable watermarking, Layers 2+3 collapse into one emission. The compositional load is bounded and specifiable.

### 4.8 Emergency response — what "revoke" and "recover" mean

**ZP.** CIRCUIT-BREAKER-2026-07: broad revocation, asymmetric reset — fast to trigger, slow to release. KEEL III.20 (forward-only recovery): chain is preserved; derived state recomputes from a chain-anchored checkpoint. Emergency and its resolution are permanent audit trail. Every escalation emits signed chain receipts.

**Chinese apparatus.** CAC 《实施意见》 clause 10 (化解应用衍生风险): "常态化风险识别、预警及干预机制，强化人机协同审核、拦截阻断等风险处置能力" (routine risk identification, warning, and intervention mechanisms; strengthen human-machine collaborative review, interception and blocking risk-handling capabilities). Clause 11: 备案 / 检测 / 召回 for sensitive domains. This is a *product-lifecycle* recall model — a defective product gets recalled from market; the operator/service-provider stops distribution or modifies the product. It is not the substrate-runtime revocation model Circuit Breaker specifies.

**The contrast.** ZP's revocation is *cryptographic and chain-anchored* — a signed revocation receipt renders the revoked capability non-verifiable at every future check. The Chinese regime's revocation is *market-mediated* — a recall notice removes the product from lawful distribution, with continued operation of already-deployed instances a separate compliance problem. These are complementary rather than competing but they target different tiers of the same system.

### 4.9 Bindingness layering — how instruments compose

**ZP.** Layer A (compiled binary, invariants, not amendable via canonicalization) + Layer B (chain-anchored operator-signed spec, WASM modules and canonical data records, amendable via canonicalization ceremony). KEEL II.9 makes the two-layer architecture an invariant. KEEL III.6 makes the amendment process a two-layer discipline: Layer B evolves via ceremony; Layer A changes require a new substrate binary through the release chain.

**Chinese apparatus.** Five-tier instrument layering: GB (mandatory) / GB/T (recommended) / GB/Z (guidance) / TC260-nnn (committee-operational) / TC260-TR (research). Bindingness decreases across the tiers; drafting-effort decreases roughly the other way. New instruments frequently start as TR, promote to TC260-nnn, and eventually to GB/T; the graduation of TC260-003 to GB/T 45654-2025 is the paradigm case.

**Coherent shape, different mechanism.** Both apparatus separate binding invariants from operational elaboration from working-vocabulary research. Both make bindingness a first-class property of an instrument. The mechanism for moving between tiers differs — ZP's canonicalization ceremony is chain-anchored operator-signed; Chinese standard promotion is committee-review + SAC approval — but the shape of "here is what is settled, here is what is elaborating, here is what is being researched" is common. **A ZP-authored technical document could be positioned against Chinese standard tiering without translation friction:** a ZP Tier-1 (KEEL) claim maps to a GB/T; a Tier-2 elaboration maps to a TC260-nnn; a research doc in `docs/research/` maps to a TC260-TR.

---

## 5. Where convergence is real vs illusory (rule 6 applied)

**Real convergence:**
- **Three-tier decision authority.** Both apparatus decompose agent authority into user-only / user-authorized / autonomous, with user retaining right-to-know and final decision authority. The vocabulary is close because the underlying problem is the same, and multiple independent apparatus (Google AP2, OWASP Agentic Top 10, Anthropic delegation semantics, ISO/IEC JTC 1/SC 42 discussions) are converging on the same three-tier decomposition. ZP arrived earlier and by structural derivation from P9; the CAC document arrives via natural-language regulatory drafting. **The shape is genuinely the same; the mechanism to make it real is where the apparatus differ.**
- **Chain-anchored verifiability as a compliance mechanism.** CAC 《实施意见》 clause 7 explicitly names blockchain-anchored verifiability. This is real convergence at the mechanism level, not merely at the outcome level. The specific chain shape differs (per-sovereign vs shared) but the pattern is confirmed as a viable regulatory answer to agent-behavior accountability.
- **Five-stage agent interaction lifecycle.** GB/Z 185's identity → capability declaration → discovery → interaction → tool invocation matches ZP's Genesis-derived key → capability-verification receipt → peer discovery → peer-verification contract → tool contract. This is real convergence — both apparatus have reasoned their way to the same functional decomposition of agent interconnection. Vocabulary is different; shape is the same.
- **Cascade risk as substrate-level concern.** TR-005 AIA06 (多智能体级联幻觉扩散、冲突死锁和资源超载) and §3.2.2 群体效应凸显 name the same phenomenon KEEL III.25 (distributed cognition + escalation for novelty) and the Circuit Breaker spec are designed to address. MIIT F 多智能体协作安全 confirms the same substrate-level treatment at the industrial/informatization altitude. Both apparatus treat multi-agent cascade as a first-class safety property, not as an emergent implementation detail.
- **Two-role execution-vs-verification discipline.** GB/T 45654 §4.3 mandates *"标注执行与审核角色分离"* — annotation execution role separate from review role. This is the same architectural intuition KEEL uses for observation-signed-vs-act-signed distinction and for delegation-receipt role separation. Not identical primitives, but the same substrate-role-discipline pattern (execution ≠ verification) recorded on both sides.
- **Six-month consent-log retention as chain-anchored discipline at regulatory altitude.** CAC 《标识办法》 Article 9 requires unmarked-content-request logs with user consent retained ≥ 6 months. This is state-level mandate for chain-anchored consent-log preservation — direct pattern-level parallel to CAPABILITY-VERIFICATION-RECEIPTS discipline and KEEL delegation-record permanence. Convergence at the regulatory-mechanism level.
- **Agent-security five-subdimension parity (MIIT).** MIIT §F 智能体安全 sub-dimensions — 内生安全 / 数据接口安全 / 人机协作安全 / 自主操作安全 / 多智能体协作安全 — map five-for-five to KEEL discipline areas (substrate integrity + boundary planes + P9 + III.16/III.25 + Part VII). Not partial match; not lossy translation; five distinct primitives, five distinct KEEL parallels, one-to-one. Both apparatus reasoned their way to the same substrate decomposition from their respective authority roots.
- **Chain-anchored discipline traces to a specific parent regulation.** CAC 《暂行办法》 Order No. 15 Article 19 explicitly requires providers to *"cooperate and disclose training data sources, scale, type, annotation rules, algorithm mechanisms"* upon inspection — the operational clause that makes regulator-inspection reach concrete. Order No. 9 Article 28 is the parent clause requiring log-preservation and inspection cooperation. This is chain-anchored-record discipline at regulation altitude, matching KEEL P1 (signing is gravity) and P5 (store-and-forward is primary) at the pattern level. Delta reduces to authority root per §11.
- **Substrate-vs-operator role distinction is architectural on both sides.** Order No. 12 Article 23 introduces 深度合成服务技术支持者 (technical supporter) as an explicit substrate-provisioning role distinct from service provider. This maps directly to KEEL's substrate (Genesis-anchored) vs operator (Regent + officer cadre execution) architectural distinction. Same two-layer separation; different anchor per §11.
- **Algorithmic-decision user-rights convergence.** Order No. 9 Article 17 grants three user rights: non-personalization opt-out, user-tag deletion, liability explanation for significant algorithmic impact. Chinese apparatus's GDPR-Article-22-shape rights at regulation altitude, matching KEEL's operator-retains-meaningful-choice (P9-shape) + delegation-scoped observation (tag-management parallel) + accountability-chain-flows-from-chain-anchored-records at the outcome level. Mechanism differs (Chinese: opt-out setting + tag-management UI; ZP: sovereign-root discipline structurally denies the accumulation).
- **The 分级分类 五-criterion rubric is the shared risk-tiering shape.** Order No. 9 Article 23 defines five criteria for tiered governance: (1) opinion-forming/mobilization capacity, (2) content categories, (3) user scale, (4) data importance, (5) degree of user-behavior intervention. CAC 《实施意见》 clause 11, TR-005 §3.6 risk-treatment classes, GB/T 45654 edge-deployment tiers all trace back to this rubric. Direct pattern-level parallel to KEEL's context-sensitive discipline (different rigor for different-consequence actions per III.16 precedent + III.25 novelty-triggers-deliberate). Both apparatus reason about risk tiers with essentially the same five-dimensional decomposition.

**Illusory or partial convergence:**
- **"Identity" is not one thing.** GB/Z 185.2 身份码 and KEEL IV.2 Genesis-derived keys are both called "agent identity" in their respective corpora. They are not the same primitive. The 身份码 is a registry-issued reference; the ZP key is a Genesis-derived cryptographic primitive. Treating these as identical because they occupy the same territory would be the confabulation shape the sweep discipline names as "reading to the confirming sentence."
- **"Trusted interconnection" is not one thing either.** CAC 《实施意见》 clause 4 uses the phrase "可信互联" (trusted interconnection). KEEL Part VII specifies peer-verification. Both apparatus use trust-vocabulary. The CAC framing routes trust through the 智能体注册平台 (Registration Platform); the KEEL framing routes trust through the Peer-Verification Contract. Same word, different anchor. Rule 6 in force.
- **"内生安全" is not aligned blindness.** 内生安全 (intrinsic security) is a Chinese security-engineering term of art meaning "security properties designed in rather than bolted on." KEEL III.24 (aligned blindness) is the *structural refusal to observe certain classes*. Both are inward-facing; both are principled. They point in different directions: 内生安全 asserts the substrate has strong internal defenses; aligned blindness asserts the substrate refuses certain internal capabilities. Treating them as synonymous would misread both.

---

## 6. Where each apparatus extends beyond the other

**ZP has, and TC260 has not (yet) surfaced:**
- **Trust chain reach as an explicit design axis** (KEEL XIV.1 Three Forms). The Chinese apparatus assumes institutional trust chain by default; a Sovereign-Form-equivalent "how far does the operator's root reach into the trust stack" question is not currently posed.
- **Delegation ceremony as chain-anchored append-only record.** GB/Z 185 covers identity, description, discovery, interaction, and tool-invocation, but the authorization audit trail as an *own primitive* is not standardized. Chinese work here is likely to grow — CAC clause 7 hints at it — but no current instrument specifies the delegation-receipt shape.
- **Metacognitive substrate as first-class primitive (scope-limited claim).** For general software agents, TC260 has not surfaced witnessed-vs-asserted, act-accounting, mode-and-agency, or metacognitive-fidelity-harness territory. For embodied AI (TR-004 §一.(四) 认知安全) and at governance-capability altitude (MIIT §A 治理能力), TC260 has surfaced the territory at concrete-substrate-requirement level — 输入输出监测, 模型版本审计, 抗对抗攻击 — but does not reach KEEL's depth-of-treatment. The remaining depth gap is downstream of the root-authority delta per §11: regulator-drafted work stops at the interface-verifiability level; sovereign-root substrate can instrument the reasoning surface itself.
- **Coordination-not-oversight as first-class principle** (KEEL III.23). The Chinese regime is oversight-by-design; the "some primitives shouldn't exist as substrate capabilities even under mutual authorization" claim has no analog.
- **Aligned blindness** (KEEL III.24). Definitionally at odds with the regulator-inspection frame.
- **Peer-verification without a shared anchor** (KEEL Part VII). Chinese peer interaction routes through the proposed 智能体注册平台; ZP peer interaction is anchor-free.
- **The Substrate Form graduation ceremony** (KEEL XIV.8). The idea that an operator's substrate can move between deployment tiers with the trust chain reach adjusting accordingly is not a shape any Chinese instrument covers.
- **Autonomic-vs-deliberate cognitive engagement discipline** (KEEL III.25). The framing that substrate matures when routine flow is invisible to the operator is not a standardization concern in current Chinese work.

**TC260 / CAC has, and ZP has not (yet) surfaced:**
- **Vertical application playbooks.** CAC 《实施意见》 sections 4–5 contain 34 clauses of vertical direction: scientific research, R&D assistance, smart manufacturing, energy resources, transportation, agriculture, financial services, terminal applications, culture and tourism, commercial services, education, medical health, human resources, information services, government affairs, judicial services, public safety, urban governance, bidding, open-source communities, industrial collaboration platforms, application promotion channels, focal-scenario opening, global ecosystem cultivation. This is ground the ZP corpus does not touch — deliberately, because ZP is substrate-first — but a mature agent-era standards apparatus needs both, and the Chinese corpus has been building the vertical side in parallel.
- **State-mediated inspection regime for sensitive domains.** Not a shape ZP wants to build, but a shape ZP will encounter when its substrate is deployed into markets where inspection-regime satisfaction is a compliance requirement.
- **Mandatory content-marking regime with a specific implementation standard** (GB 45438). ZP has action-side provenance; C2PA has content-side assertions; GB 45438 has service-provider-mandatory marking. The three-way composition is a demand ZP's MEDIA-PROVENANCE spec probably needs to think about explicitly.
- **Numeric-target-driven agenda** ("100 AI national standards"). Whatever else can be said about state-agency-driven standardization, the effect is a *dense, dated, sequenced* production schedule that the substrate ecosystem then has to keep pace with. ZP's corpus grows by need; the Chinese corpus grows by declared numeric target. Both produce corpus; the second produces it faster in specific declared directions.

---

## 7. Composition scenarios

Three concrete scenarios where the two apparatus meet in a real deployment, with the compositional shape each requires:

**Scenario A — ZP-Sovereign-Form operator publishing media into Chinese and EU markets.**
- KEEL action-side chain receipts document the artifact's operator provenance (already discharged).
- C2PA content-side manifest with the five 2026-08-20 assertions (`c2pa.ai-disclosure` etc.) discharges the EU AI Act Article 50 machine-readable marking obligation via the Commission's Code of Practice.
- GB 45438 service-provider-signed marking discharges the PRC 生成合成内容标识办法 obligation. The service provider here is the party fielding the content into the Chinese market; if the operator is publishing themselves, they *are* the service provider.
- Composition demand: MEDIA-PROVENANCE-INTEROP-2026-07 needs to know about all three shapes and either emit all three at publication time or clearly document which markets a given emission pattern can reach.

**Scenario B — ZP substrate operating in a Chinese sensitive-domain regulated market.**
- Sovereign Form is not admissible: the regulator-inspection reach cannot be denied.
- Companion Form composes with regulator-inspection because the daily driver's OS vendor is inspectable through existing regime. Substrate operates within the vendor scope; Form Disclosure (KEEL XIV.3) names the sovereignty limitations honestly.
- Delegation ceremony still per-sovereign chain-anchored, but composes with an upstream 智能体注册平台 registration for the specific agent that will operate in the regulated scenario.
- Composition demand: the operator's Genesis authority is *not* handed to the regulator, but the specific in-scope agent's operating certificate *is* file-able through the regime. This is architecturally analogous to how a Sovereign-Form operator can carry a driver's license without collapsing their identity into it.

**Scenario C — ZP operator running a cross-org agent workflow with a counterparty subject to GB/Z 185.**
- Peer-Verification Contract (KEEL Part VII) discharges the peer-to-peer trust check.
- 智能体交互 (GB/Z 185.6) shape is the counterparty's expected interface. The ZP agent implements the standard's interaction surface as one of several transports its Peer-Verification-Contract-compatible identity can present.
- Composition demand: not on KEEL — Layer A stays intact — but on a Layer B agent-adapter WASM module that speaks GB/Z 185 to the counterparty and KEEL to the operator's chain. This is exactly the composition pattern the two-layer architecture is built for.

---

## 8. Load-bearing findings, ranked

Ordered by how much a future ZP roadmap decision might turn on them:

1. **CAC clause 7 is the strongest external convergence yet on ZP's chain-anchored discipline, and per §11 its significance is stronger than "convergence."** A state-level regulatory document naming blockchain-anchored verifiability as the compliance mechanism for important scenarios. The delta that remains — per-sovereign chain vs shared/regulator-visible chain — is precisely the root-authority delta exposed at the mechanism level. Not merely convergence; state-level acknowledgment that chain-anchored is the correct answer to agent-behavior accountability *regardless* of which root authority owns the chain. Rule 6 in force; convergence is at the mechanism-pattern level, and the residual difference reduces to authority root per §11.
2. **CAC clause 6's three-tier decision authority is the P9 shape at regulator-drafted altitude.** Industry-wide convergence, ZP arrived earlier by structural derivation, but the vocabulary is now shared enough that a ZP-CAC alignment can be phrased in terms the regulator's own text carries.
3. **GB/Z 185's five-stage agent-interconnection decomposition is the same shape as KEEL Part VII + agent-tool-contract.** Composition rather than contradiction. A Layer B WASM adapter module is the natural composition point.
4. **The inspection-reach contrast is architectural, not surface.** Sovereign Form is not admissible under sensitive-domain 备案. This is a Layer A invariant colliding with a specific external regime. Naming it precisely (rather than papering over it) is what allows Companion Form composition to be honest per XIV.3.
5. **The Chinese apparatus is producing corpus faster than ZP is, in the specific directions the numeric-target agenda names.** Not a shape ZP should copy — the substrate-first posture is deliberate — but a signal that vertical-application playbooks will exist in the Chinese ecosystem well before they exist as ZP elaborations, and that composition work may need to route through them.
6. **Metacognitive substrate is a ZP contribution the Chinese corpus has not yet reached.** Value if it stays that way; watch the in-progress 《人工智能模型开发安全指南》 for whether it grows in that direction.
7. **Content provenance is three-way, not two-way.** MEDIA-PROVENANCE-INTEROP-2026-07 probably needs to add GB 45438 to its composition matrix.
8. **The 智能体注册平台 (Registration Platform) proposal is architecturally significant.** CAC 《实施意见》 clause 4 proposes an upstream directory for digital-identity management, discovery, capability declaration. Whether it ships as a mandatory-participation regime or a voluntary-participation service will substantially change the composition problem. Standing follow-up.

---

## 9. Reading and monitoring recommendations

**Priority reading (operator to supply PDFs where marked, per the CACR retrieval caveat):**
1. **TC260-TR-005-2026** 《智能体安全标准化研究》 — 92 pages, 11 core risks + 5-dimension framework. **PDF at `tc260.org.cn` direct download; not readable via `web_fetch`; operator supply.**
2. **GB/Z 185.1 through 185.7-2026** — the 7-part agent-interconnection series. Sold through SAMR / SAC channels; not always free.
3. **TC260-TR-004-2026** 《工业具身智能安全标准化研究》 — embodied AI security; closest to Substrate-Form-on-embedded-hardware territory.
4. **GB 45438-2025** 《网络安全技术 人工智能生成合成内容标识方法》 — mandatory content-marking; feeds into the MEDIA-PROVENANCE-INTEROP question.
5. **GB/T 45654-2025** 《网络安全技术 生成式人工智能服务 安全基本要求》 — the graduated `TC260-003`. What Chinese-market generative-AI compliance measures against.
6. **CAC 《生成合成内容标识办法》** (2025-03, in force 2025-09) — the regulation GB 45438 implements.
7. **2026年度第二批网络安全国家标准需求清单** (附件1 of 网安秘字〔2026〕44号) — the working needs list. **PDF operator supply.**
8. **《工业和信息化领域人工智能安全治理标准体系建设指南（2025）》** — MIIT parallel-track construction guide, seven-part framework.

**Ongoing monitoring (weather-report surfaces):**
- `tc260.org.cn/portal/project/plan` — the operator-named dashboard, now in `ai-landscape-sources.md` Candidate sources.
- `tc260.org.cn/portal/suggestion` — draft standards in comment period; pre-issuance signal.
- `tc260.org.cn/portal/cms/work/10/2` — 通知公告 notices; where release events land first.
- `cac.gov.cn` policy pages and 专家解读 / 答记者问 companion documents.
- `caict.ac.cn` for MIIT-side parallel-track releases.
- `cacrnet.org.cn` for the cryptographic-architecture parallel track (per 2026-08-18 sweep entry).
- News.cn / people.cn for state-media primary coverage of instrument releases.

**Standing follow-ups (unread work referenced above):**
- The TR-005 92-page PDF has not been read at primary in this session — all its content characterization rests on Chinese-language commentary.
- The second-batch needs list PDF has not been read at primary — the in-progress standards list is search-level only.
- GB/T 45654-2025 has not been read at primary — the SAMR-cleared release copy is at `content.mlex.com`, per an earlier sweep entry.
- GB 45438-2025 has not been read at primary — the exact marking format specified by the mandatory standard is a specific compositional demand on MEDIA-PROVENANCE-INTEROP-2026-07.
- MEDIA-PROVENANCE-INTEROP-2026-07 has not been re-read in this session against the three-way composition demand named in §4.7 and §8.7 — this is a *research finding for that spec's next revision*, not a substrate-work item this task should execute per its scope rule.

---

## 10. What this analysis is not

- **Not a compliance opinion.** The composition scenarios in §7 are structural — they identify architectural shapes that could satisfy the regime, not certified compliance paths. Actual PRC-market compliance requires legal counsel.
- **Not a translation.** All quoted Chinese passages carry the original Chinese so a future reader can chase the primary; English renderings are annotative.
- **Not a decision.** §5–§8 identify structural relationships and rank findings by how much a future roadmap decision might turn on them; they do not recommend which relationships ZP should act on. That is Ken's call, on which this analysis provides the map.
- **Not a substrate-work item.** Per the sweep task's scope rule, findings that imply ZP should change something are flagged in Bearing statements and stop there. The three MEDIA-PROVENANCE-INTEROP composition demands (§4.7, §7 Scenario A, §8.7) are surfaced but not investigated further; whether they earn a dedicated session is Ken's decision.
- **Not comprehensive on the TC260 corpus.** This analysis covers what was reachable via search and primary-fetch in one session. Standing follow-ups above name the specific unread items; TR-005 and the second-batch needs list are the two most consequential gaps.

---

## 11. The single-axis reduction: root authority is the delta

The nine-axis structure of §2–§9 was the analytical instrument. The finding, after seven primary-read passes recorded in Appendices A.1–A.7 covering thirteen load-bearing Chinese-side primaries, is that **eight of the nine axes reduce to symptoms of the ninth.** The load-bearing delta between the two apparatus is at the *root authority model* — where authority terminates, upstream of everything else. Sovereign-operator-Genesis on one side, institutional-multi-agency-composite on the other. Every other apparent divergence traces back to that root.

**The Chinese institutional root has four altitudes of authority-terminating machinery** (traced across all seven primary passes):

- **Regulatory-root altitude:** 《互联网信息服务算法推荐管理规定》 (Order No. 9, 2022-03-01) — the mechanism-defining regulation that all downstream algorithm-related regulations reference for 备案. Articles 23-26 define 分级分类 rubric + 备案 lifecycle; Article 27 defines 安全评估; Article 28 defines inspection cooperation; Chapter 3 defines user rights.
- **Agency-composite altitude:** **CAC + MIIT + 公安部** stable three-agency core across all content-related CAC regulations. Sectoral additions per regulation — SAMR joins for consumer protection (Order No. 9), NDRC + 教育部 + 科技部 + 广电总局 join for generative-AI cross-sectoral coverage (Order No. 15). Composite membership itself is authority-derived.
- **Mechanism altitude:** 备案 as the operational anchor (Articles 24-26 of Order No. 9, reprised as Article 17 of Order No. 15 and Article 19 of Order No. 12). Both 服务提供者 and 技术支持者 file — the substrate-vs-operator role distinction is regulated at both altitudes.
- **Enforcement altitude:** Articles 31-33 (administrative penalties: warning → correction → suspension → fines) escalating through public-security law and criminal law.

**Downstream from Order No. 9's mechanism altitude runs a six-tier statutory chain for generative content marking:**

Order No. 9 (root) → Order No. 15 (2023, gen AI) → Order No. 12 (2023, deep synthesis) → 《标识办法》 (2025-09) → GB 45438-2025 (mandatory) → TC260 A-B-C-D-E framework implementations. The chain is fully traced; no deeper regulation altitude exists that hasn't been touched.

The reduction has been stress-tested at three scales without a counterexample surfacing:
- **Intra-Chinese scale:** CAC/TC260 track vs MIIT track (§Appendix A.4) — same country, different ministries; corpus-coverage delta between them lands at exactly the authority-chain-scope point.
- **Intra-regulation scale:** Order No. 9 → Order No. 12 → Order No. 15 (§Appendices A.5-A.7) — all three regulations point at the same 备案 mechanism and the same three-agency core.
- **Intra-branch scale:** Order No. 9 contains five algorithm-type branches (生成合成类 + 个性化推送 + 排序精选 + 检索过滤 + 调度决策); this session traced only the generative branch. The other four branches remain as stress-test targets — if §11 holds there too, the reduction is genuinely general.

The reduction is now supported by clause-level PRC statutory grounding at all four altitudes, not just pattern-level inference from downstream instruments.

Rule 6 (distrust convergence in your own favour) applies here in a specific way: this reduction is not a claim that ZP and the Chinese apparatus are "actually the same." They are architecturally different. The claim is that the difference is *one axis, not nine*. That is a stronger and cleaner comparative statement than the nine-axis expansion suggested.

Walk of the eight downstream axes as symptoms:

- **Identity primitive (§4.2).** Both are cryptographic identity — distinguishable, addressable, capability-coupled. The delta is *who certifies the key*: Genesis-derived by the operator vs 身份码 issued by 认证机构. Downstream of root authority.
- **Delegation model (§4.3).** Both converge on the three-tier decomposition (user-only / user-authorized / autonomous). CAC 《实施意见》 clause 6 is a natural-language rendering of KEEL P9. The mechanism differs only in what anchors the ceremony — chain-anchored operator receipts vs regulatory-boundary specification + service-provider filing. Downstream of root authority.
- **Chain / ledger discipline (§4.4).** Both anchor to cryptographic verifiability with signatures. CAC clause 7 blockchain-anchored records + TR-005 §3.5 数字签名 for non-repudiation + 日志加密签名 audit logs are the *same pattern* as ZP's chain discipline. The delta is where the chain terminates — per-sovereign vs shared/regulator-visible. Downstream of root authority.
- **Observation reach (§4.5).** Aligned blindness (KEEL III.24) is enforceable only when the authority stack terminates at the sovereign. Under regulator-inspection authority the substrate cannot structurally refuse observation because the regulator can compel disclosure. So the observation delta is *derivative* of the root: sovereign root allows the substrate to have primitives that refuse; institutional root cannot enforce that refusal against compelled inspection. Downstream of root authority via enforceability.
- **Cognitive layer (§4.6).** TR-004 §一.(四) surfaces 认知安全 as first-class for embodied AI with concrete substrate requirements (输入输出监测, 模型版本审计); TR-005 §3.5 gestures at 决策过程透明可解释 for general agents. Both apparatus surface the territory. The depth gap — ZP goes to witnessed-vs-asserted, act accounting, mode-and-agency — traces to whether the substrate must instrument its own cognition (sovereign latitude) or merely make outputs verifiable at the regulator interface. Downstream of root authority.
- **Content provenance (§4.7).** GB 45438 Appendix E's five-field metadata schema has 服务提供者身份标识 as a required element. What populates that field differs by root authority: sovereign fills it with operator-Genesis-derived identity; institutional fills it with the filed service-provider registration. Same field, different anchor. Downstream of root authority.
- **Emergency response (§4.8).** Both revoke via cryptographic mechanism + enforcement chain. ZP: chain-anchored operator revocation, instantly effective at every future verification. Chinese: 备案 / 检测 / 召回 enforced through legal-regulatory chain. The enforcement chain terminates where the authority terminates. Downstream of root authority.
- **Bindingness layering (§4.9).** Both are five-tier bindingness structures with pattern-level parity (Layer A ↔ GB mandatory, Layer B canonical claims ↔ GB/T recommended, Tier-2 elaborations ↔ GB/Z guidance, operational specs ↔ TC260-nnn, research ↔ TR). Amendment authority terminates at operator-Genesis (chain-anchored canonicalization ceremony) vs institutional consensus (committee review + SAC approval). Downstream of root authority.

The vertical-playbook asymmetry (§6) is also authority-derived: regulator-drafted corpus grows by declared numeric target ("100 AI national standards"); sovereign-rooted corpus grows by operator need. Corpus composition rate and direction traces to which authority drives production.

### Consequences of accepting the reduction

**One.** The three delta notes in Appendices A.1–A.3 are not independent findings. They are cumulative evidence for the same reduction. Every confirmation upgrade (▲), every scope correction, every new-primary refinement (◇) points at the same conclusion: the substrate architecture is the same territory both apparatus are covering; the mechanism-and-anchor difference reduces to where authority terminates.

**Two.** The load-bearing findings in §8 need one reordering. Item 1 (CAC clause 7 as strongest external convergence on chain-anchored discipline) is confirmed. But its significance is *stronger* than §8 originally stated: it is not merely a convergence, it is state-level acknowledgment that the chain-anchored pattern is the correct answer to agent-behavior accountability *regardless* of which root authority owns the chain. The delta that remains — per-sovereign chain vs shared chain — is precisely the root-authority delta, exposed at the mechanism level.

**Three.** The composition scenarios in §7 are not invalidated by the reduction. They are *specific instances* of the reduction in action: Scenario A (Sovereign-Form publishing into PRC+EU) is the operator carrying a sovereign root while composing with institutional-root instruments for market-side compliance. Scenario B (Sovereign Form inadmissible under sensitive-domain 备案) is the operator refusing to route root authority through the regulator. Scenario C (cross-org GB/Z 185 counterparty) is a Layer B adapter translating between root-authority regimes at the interface layer. All three are architectural expressions of *how the two root-authority models compose or refuse to compose*.

### What the reduction does not collapse

**Substrate-architecture pattern parity is genuine.** Both apparatus have reasoned their way to: cryptographic identity, three-tier delegation, chain-anchored records, cascade-risk bounding, five-tier bindingness, content-provenance marking, backdoor detection, execution-vs-review role separation. This convergence is real and worth preserving in the analysis — it means a Layer B adapter can carry Chinese-market compositional obligations without the operator's Genesis authority being renegotiated.

**Vocabulary specificity remains useful.** The clause-level detail in Appendices A.1–A.3 (11 AIA risks, 5-element metadata schema, ISO/IEC 22989 lifecycle, GB/T 45654 31-risk taxonomy, four-step Article 6 verification) is what a substrate compositional design draws from. The reduction says *the delta reduces to one axis*; it does not say the vocabulary reduces to one term.

**KEEL Layer A invariants and the Chinese sensitive-domain 备案 regime remain incompatible at the interface where root authority is asserted.** The reduction explains the incompatibility (both regimes claim upstream authority the other's root cannot yield); it does not resolve it. Scenario B in §7 correctly names Sovereign Form as inadmissible for sensitive-domain 备案. That is the direct consequence of the root-authority delta manifesting at a market interface.

### One-sentence statement of the finding

*Between ZeroPoint and the emerging Chinese agent-standardization apparatus, the substrate architecture is the same shape; the difference is where the authority chain terminates, and every other apparent difference is downstream of that root.*

---

## Appendix A — Instrument enumeration referenced

For traceability. Instrument-side references only; ZP-side references are inline against `docs/KEEL-2026-07.md` and the Tier-2 elaborations in `docs/design/`.

**On the appendix's structure.** The instrument-enumeration table below is followed by seven delta notes (A.1–A.7), one per primary-read pass performed in this session. **Two consolidation passes have occurred:**

- **First consolidation (after A.4):** promoted A.1–A.4 findings into the body — §3 correspondence-table rows (cascade-risk vocabulary, cognitive-plane scope, MIIT rows, agent-security sub-decomposition, standards-framework partitioning), §4.6 (cognitive-layer scope amendment), §4.7 (six-layer composition — refined further in second consolidation), §5 (four real-convergence items), §6 (metacognitive-substrate scope correction), §8 (item-1 significance), and §11 (four-pass framing at that point).
- **Second consolidation (after A.7):** promoted A.5–A.7 findings — added correspondence-table rows for the regulation-side authority chain, substrate-vs-operator role distinction, and user-rights layer; added four new real-convergence items to §5 (chain-anchored parent-regulation grounding, substrate-vs-operator role distinction, algorithmic-decision user-rights convergence, 分级分类 shared risk-tiering rubric); rewrote §11 opening to name the four altitudes of institutional-root machinery and the six-tier statutory chain.

**The delta notes are preserved as audit trail** — the reasoning chain from primary reading to body finding, keyed against specific claims — but are no longer the primary carrier of the analytical findings. A future minor revision may collapse them to a compressed single-note; this session preserves them for transparency of the confidence-upgrade chain.

| Instrument | Kind | Date | Primary read? |
|-----------|------|------|---------------|
| GB/T 45654-2025 网络安全技术 生成式人工智能服务 安全基本要求 | GB/T | 2025-04-25 issued, 2025-11-01 in force | **Yes** — full-structure read at primary 2026-08-20 from SAMR-cleared mirror at `content.mlex.com/Attachments/2025-05-23_CZT297CHX8R49J68/SAMR_NSA_Basic_Security_Requirements_GenAI_service.pdf`. Confirmed: §4 training data safety (§4.1 source / §4.2 content / §4.3 annotation), §5 model safety (§5.1 training / §5.2 output / §5.3–5.5 monitoring, versioning, isolation), §6 security measures (§6.1–6.7 documentation, transparency, opt-out, complaint, input monitoring, stability, edge deployment), Appendix A 31-risk-category taxonomy, Appendix B assessment methods. See §Appendix A.3. |
| GB/T 45288.1-2025 人工智能 大模型 第1部分：通用要求 | GB/T | 2025 | No (search-level) |
| GB 45438-2025 网络安全技术 人工智能生成合成内容标识方法 | GB (mandatory) | 2025-02-28 issued, 2025-09-01 in force | Clause-level requirements reconstructed 2026-08-20 from the PwC HK compliance guide (`pwccn.com/zh/tmt/method-identifying-synthetic-content-generated-ai-sep2025.pdf`, professional analysis quoting clauses); metadata from SAMR openstd portal. Appendix E (5-element metadata schema) and Appendix F (single-instance rule) reconstructed at clause precision; full clause text of body sections still not read at primary — SAMR sells clause text separately. See §Appendix A.3. |
| GB/Z 185.1 through 185.7-2026 人工智能 智能体互联 | GB/Z (7 parts) | 2026-06-26 | Partially — `news.cn` primary read in full; individual parts not read |
| TC260-TR-001-2026 智能驾驶网络和数据安全标准化研究 | TR | 2026-04-03 (issued 2026-03-26) | No |
| TC260-TR-002-2026 6G网络内生及边界安全技术与标准化研究 | TR | 2026-04-03 (issued 2026-03-26) | No |
| TC260-TR-003-2026 卫星通信网络安全标准化研究 | TR | 2026-04-03 (issued 2026-03-26) | No |
| TC260-TR-004-2026 工业具身智能安全标准化研究 | TR | 2026-04-03 (issued 2026-03-26) | **Yes** — 31-pp v1.0-202603 read at primary 2026-08-20 from same 网安秘字〔2026〕34号 RAR bundle; local copy at `docs/research/tc260-primaries/`. See §Appendix A.2. |
| TC260-TR-005-2026 智能体安全标准化研究 | TR | 2026-04-03 (issued 2026-03-26) | **Yes** — 92-pp v1.0-202603 read at primary 2026-08-20 (operator supplied via RAR unpack from 网安秘字〔2026〕34号 bundle at `tc260.org.cn/sysFile/downloadFile/65a2ac0e14a140f68bb382b7a6e00b0c`); local copy at `docs/research/tc260-primaries/`. See §Appendix A.1 delta note below. |
| 网安秘字〔2026〕34号 关于发布5项网络安全标准化技术研究报告的通知 | TC260 notice | 2026-04-03 | Yes (primary read) |
| 网安秘字〔2026〕44号 关于发布2026年度第二批网络安全国家标准需求的通知 | TC260 notice | 2026-04-16 | Yes (primary read; attachments not read) |
| CAC 《智能体规范应用与创新发展实施意见》 | Regulatory implementation opinion | 2026-05-08 | Yes (primary read in full) |
| CAC 《人工智能生成合成内容标识办法》 (国信办通字〔2025〕2号) | Regulation | 2025-03-07 issued, 2025-09-01 in force | **Yes** — all 14 articles read at primary 2026-08-20 via `cac.gov.cn/2025-03/14/c_1743654684782215.htm`. Four issuing bodies: 中央网信办, 工信部, 公安部, 广电总局. See §Appendix A.2. |
| CAC 《生成式人工智能服务管理暂行办法》 (Order No. 15) | Regulation (parent) | 2023-07-10 issued, 2023-08-15 in force | **Yes** — all 24 articles across 5 chapters read at primary 2026-08-20 via `cac.gov.cn/2023-07/13/c_1690898327029107.htm`. Seven issuing bodies: 国家互联网信息办公室 + 发改委 + 教育部 + 科技部 + 工信部 + 公安部 + 广电总局. This is the parent regulation grounding much of the downstream CAC/TC260 corpus (Article 12 → 《深度合成管理规定》 → 《标识办法》; Article 17 → 备案 regime; Article 19 → inspection authority). See §Appendix A.5. |
| CAC 《互联网信息服务深度合成管理规定》 (Order No. 12) | Regulation (mid-tier) | 2022-11-25 issued, 2023-01-10 in force | **Yes** — all articles read at primary 2026-08-20 via `cac.gov.cn/2022-12/11/c_1672221949354811.htm`. Three issuing bodies: 国家互联网信息办公室 + 工信部 + 公安部. Middle tier of the content-marking statutory chain. Introduces the four-role decomposition (深度合成服务提供者 / 技术支持者 / 使用者 + 深度合成技术), Article 17 five-category prominent-marking trigger, Article 19 备案 mechanism paralleling 《暂行办法》 Article 17. See §Appendix A.6. |
| CAC 《互联网信息服务算法推荐管理规定》 (Order No. 9) | Regulation (root of 备案 mechanism) | 2021-12-31 issued, 2022-03-01 in force | **Yes** — all 35 articles across 6 chapters read at primary 2026-08-20 via `cac.gov.cn/2022-01/04/c_1642894606364259.htm`. Four issuing bodies: 国家互联网信息办公室 + 工信部 + 公安部 + 市场监管总局. Article 2 defines five algorithm types (生成合成类, 个性化推送类, 排序精选类, 检索过滤类, 调度决策类). Articles 23-25 define the 分级分类 + 备案 mechanism definitively — the deepest authority-anchoring altitude the CAC apparatus has produced. Article 17 defines user rights (non-personalization opt-out, tag deletion, liability explanation). See §Appendix A.7. |
| MIIT 《工业和信息化领域人工智能安全治理标准体系建设指南 (2025)》 | Ministry construction guide | 2025 | **Yes** — full-structure primary read 2026-08-20 via CAICT-hosted OSS mirror at `caict-llm-portal-storage.oss-cn-beijing.aliyuncs.com/6153dd34-d7fc-4d24-97b5-d40fc48105c5`. Seven-dimension framework (A 治理能力 / B 基础设施 / C 网络 / D 数据 / E 算法模型 / F 应用 / G 赋能), 智能体 five-subdimension decomposition under F, 70 planned standards in three urgency tiers per attachment 2. See §Appendix A.4. |
| CACR 《生成式人工智能系统密码应用指引》 v1.0 | Cryptographic architecture spec | 2026-08 | Read (operator-supplied per 2026-08-18 sweep entry) |
| 20263116-Q-252 mandatory agent-security standard plan | Standard plan | 2026-08 | No (per 2026-08-15 sweep entry) |

## Appendix A.1 — Delta note (2026-08-20 post-primary read of TC260-TR-005)

**Origin.** Operator supplied the 5-TR bundled RAR from 网安秘字〔2026〕34号 direct-download; local unpack + extraction of TC260-TR-005-2026 《智能体安全标准化研究》 v1.0-202603, 92 pages, WPS 文字 as creator, produced by 全国网络安全标准化技术委员会秘书处 and 新技术安全标准特别工作组 (SWG-ETS). Local copy at `docs/research/tc260-primaries/`. Read in full for §3 (安全风险与应对措施), §4.1–§4.2 (标准体系需求 + 框架), spot-check of §1 (定义) and §2 (政策). Contributor list includes 中国移动研究院, CESI (中国电子技术标准化研究院), 工信部电子五所, 中关村实验室, 上海人工智能实验室, 阿里云, 华为终端, 浙大, 北大武汉AI研究院, 快手, 百度, 抖音, 小米 — the drafting coalition is state-media + platform-vendor + academy composite.

Confidence upgrades (▲), corrections (✗→✓), and refinements (◇) below, keyed against comparative-doc claims.

### Confirmed against primary

- ▲ **§4.6 core claim confirmed and sharpened.** The comparative doc read that TR-005 "treats hallucination as a risk to bound rather than a cognitive property to instrument." TR-005 §3.6 explicitly classifies AIA05 (幻觉和策略性拒绝), AIA01 (提示词注入与越狱), and AIA10 (记忆幻觉和操纵) into risk-treatment class 3: *"需标准提供基础支撑,风险根植于模型本质...其解决超越标准范围,主要依靠技术进步与法律监管"* (requires standards to provide foundational support; risk is rooted in model essence; resolution exceeds standards' scope; mainly relies on technological progress and legal oversight). This is TC260 explicitly saying these three risks are beyond standardization's reach — putting them exactly in the territory KEEL III.12 (metacognition as load-bearing) and the cognitive-substrate tier-2s attempt to instrument. **Convergence upgrade.** The comparative doc's §6 claim ("metacognitive substrate as first-class primitive has no TC260 equivalents") stands and is *strengthened* — TC260 explicitly names the gap it does not fill.
- ▲ **§4.4 chain-anchored convergence has a second, granular instance in TR-005.** The comparative doc treated CAC 《实施意见》 clause 7 as the strongest state-level convergence. TR-005 §3.5 adds a second convergence at the TC260 committee level: AIA07 (协议风险) response measure explicitly names *"数字签名"* (digital signatures) for non-repudiation, and AIA09 (人工监管与可追溯性失效) response measure names *"全生命周期日志记录、监控和审计"* + *"日志加密签名"* (full-lifecycle log recording + encrypted-signed logs). This is directly parallel to KEEL P1 (signing is gravity), P5 (store-and-forward is primary), and the chain-anchored delegation-receipt discipline. Not a shared external chain (per the §4.4 caveat) but the *same pattern* at a lower altitude than the CAC clause 7 framing. Rule 6 still in force: the mechanism is named at the standard's level; ZP's per-sovereign chain remains a specific composition.
- ▲ **§5 real-convergence #4 (multi-agent cascade) confirmed.** TR-005 §3.2.2 has "群体效应凸显" as a subsection heading with three specific concerns: 协同风险, 目标冲突升级, 系统级失效. §3.2.3 AIA06 name is "多智能体级联幻觉扩散、冲突死锁和资源超载." §3.5 response to AIA06 includes *"对关键决策过程实施多智能体共识验证"* (implement multi-agent consensus verification for key decision processes) — this is a substrate-level bounding mechanism, not a per-agent one. Convergence with KEEL III.25 (distributed cognition with central intent) and Circuit Breaker's broad revocation/asymmetric reset is real at the pattern level.
- ▲ **§4.5 observation-reach architectural contrast confirmed at higher resolution.** TR-005 §3.5 memory-security response measures include *"记忆内容验证 / 会话隔离 / 异常检测系统 / 定期记忆清理 / 记忆快照取证"* (memory content verification / session isolation / anomaly detection / periodic memory cleanup / memory snapshot forensics). This is aggressive substrate-observation posture — the substrate is expected to internally observe agent memory for regulatory forensics. KEEL III.24 (aligned blindness) posture is definitionally at odds with the "memory snapshot forensics" primitive. The §4.5 composition-question call-out (Sovereign Form not admissible under sensitive-domain 备案) is *strengthened* by this primary reading.

### Corrections

- ✗→✓ **§3 correspondence-table vocabulary was one step imprecise.** The row *"Cascade risk / multi-agent safety"* named TR-005's phenomenon as *"多智能体级联故障; 群体效应放大"*. Neither is TR-005's actual vocabulary. Primary text uses *"多智能体级联幻觉扩散"* (multi-agent cascade hallucination diffusion — narrower and more specific than "cascade failure") and *"群体效应凸显"* (group-effect emergence — as a subsection heading). Amend the row to: *"TR-005 AIA06 (多智能体级联幻觉扩散、冲突死锁和资源超载); §3.2.2 群体效应凸显"*. Substantive convergence is unchanged; the vocabulary should be exact.
- ✗→✓ **§5 confabulation-shape guard-rail vindicated at a specific point.** The comparative doc warned in §5 that treating GB/Z 185.2 身份码 and KEEL Genesis-derived keys as "the same primitive" would be the confabulation shape "reading to the confirming sentence." TR-005 §3.5 AIA04 (身份仿冒和越权访问) response measures include *"双向身份认证"* (bidirectional identity authentication) and *"基于行为的身份伪造识别"* (behavior-based identity forgery recognition) — but the *anchor* is still the institutional issuance regime (身份令牌, 服务账户 language), not a derivation from a sovereign root. Confabulation guard held. No claim to correct; the guard-rail was well-placed.

### Refinements (new material the primary carries that the comparative doc did not surface)

- ◇ **Four-party responsibility decomposition (Table 7, p47) is a shape the comparative doc did not name.** TR-005 assigns risk ownership to four roles: *模型算法研发者 / 智能体开发平台提供者 / 智能体服务提供者 / 智能体用户* (model-algorithm R&D / agent-development-platform provider / agent-service provider / agent user). This is a *supply-chain accountability decomposition* orthogonal to the CAC 《实施意见》 clause 6 authority-tier decomposition the comparative doc's §4.3 focused on. Both apparatus need both cuts; TR-005 provides the supply-chain cut with explicit stage-by-stage mapping (启动 / 设计与开发 / 验证与确认 / 部署 / 运行与监视 / 重新评价 / 退役). ZP-side analog: SUPPLY-CHAIN-TIER-CONTRACT-2026-06 covers the same territory but from the substrate-inbound perspective; the outbound-accountability shape TR-005 uses (who is *answerable* for each risk at each stage) is not currently formalized in the ZP corpus. Not a gap to fill urgently — ZP's chain-anchored discipline gives every action an operator anchor and thus terminates accountability at Genesis — but a shape worth naming when the composition question forces the answer.
- ◇ **TR-005 §3.1 self-diagnosis of the TC260 framework.** *"全国网络安全标准化技术委员会现有框架聚焦静态AI模型（如数据安全、算法偏见），但智能体运行过程中,感知、规划、记忆和行为等技术层面所涉及的工具调用、记忆状态维护、目标拆解和多代理协作中产生新风险维度,缺乏安全标准化规范"* — TC260 explicitly acknowledges the existing framework is model-static and does not cover agent-runtime concerns (tool invocation, memory state, goal decomposition, multi-agent collaboration). This is a *self-declared gap statement* that positions TR-005 as the first-step response. Bearing on the comparative doc's §6 asymmetry table: the ZP-runtime-substrate lead is not merely observed from outside; TC260 itself declares it.
- ◇ **ISO/IEC 22989 lifecycle adopted verbatim.** TR-005 §3.4 uses the 7-stage ISO/IEC 22989 lifecycle (启动 / 设计与开发 / 验证与确认 / 部署 / 运行与监视 / 重新评价 / 退役) as the risk-flow spine. This confirms TR-005's international-standards-composition intent, and — combined with §4.1 references to ISO/IEC 22989:2022 and ITU-T F.748.46 — indicates TC260 is drafting toward ISO-alignable output, not PRC-only.
- ◇ **5-dimension standards-framework verification.** Comparative doc §Prerequisite and elsewhere cited the "5-dimension framework." TR-005 §4.2 Figure 4 confirms: **基础共性 / 安全管理 / 关键技术 / 测试评估 / 产品与应用**, with subdimensions as follows. Basis (基础共性): 术语定义, 通用安全要求. Management (安全管理): 模型算法安全, 数据安全, 供应链安全, 隐私保护, 风险管理与治理. Key tech (关键技术): 检索增强安全, 多模态安全, 生成技术安全, 交互安全, 工具调用安全, 协议安全, 多智能体协同安全. Testing (测试评估): 安全评估, 系统安全测试. Products (产品与应用): 应用分类分级, 典型行业应用安全. **The comparative doc did not name the subdimensions.** Each subdimension is a specific standardization landing site; monitoring at that resolution will surface upcoming standard-plan entries earlier than the top-level dashboard.
- ◇ **§3.5 planning-security response measure explicitly names decision-process explainability.** AIA05 (幻觉和策略性拒绝) response measures include *"决策过程透明可解释"* (decision-process transparency and explainability). This is a partial acknowledgment of the cognitive-instrumentation concern KEEL III.12 and the COGNITIVE-SELF-OBSERVER 2026-07 tier-2 address. TR-005 stops at "make the decision process explainable" — no witnessed-vs-asserted primitive, no post-emission verification, no act-accounting. But the gesture is present and worth naming: TC260 is aware of the space; it has not moved into it structurally.

### Updated confidence tags on Appendix A row

- **TR-005:** primary read; confidence upgrade from "search-level via Sohu commentary" to "primary in this repo." Vocabulary corrections in §3 above should be reflected in a future minor revision of the comparative doc.
- **Sohu / secrss commentary:** the pre-primary characterizations of TR-005 that informed the earlier comparative-doc draft were substantively accurate on the framework (5 dimensions, 11 risks, ISO/IEC lifecycle) but imprecise on specific vocabulary (as noted). Rule 6 held: the Chinese-language commentary did not overstate convergence, and the sweep discipline's insistence on primary-read-before-committing to specific vocabulary is validated by this pass.

### What did *not* change

- §4.1 (trust root architectural contrast), §4.3 (delegation model — CAC-clause-6 three-tier convergence), §4.5 (observation-reach contrast + Sovereign-Form-inadmissible finding), §4.8 (revocation model contrast), §4.9 (bindingness layering shape), §7 (three composition scenarios), and §8 (load-bearing findings ranking) are unaffected by the primary read.
- The strongest single finding (CAC 《实施意见》 clause 7 as state-level chain-anchored convergence) remains the strongest single finding; TR-005 §3.5 adds a committee-level second instance, does not displace it.
- The §6 asymmetry claims — ZP-has-and-TC260-hasn't (metacognitive substrate, coordination-not-oversight, aligned blindness, Substrate Form axis) — all *strengthened* by the primary read. TC260 explicitly declares the runtime/cognitive-substrate gap in §3.1; TC260's §4.5 observation posture is definitionally at odds with aligned blindness; no TC260 instrument yet posed a trust-chain-reach axis.

### Standing follow-ups now cleared vs still open

- **Cleared:** TR-005 primary read; the handoff `docs/handoffs/tc260-comparative-analysis-2026-08-20.md`'s "Unread primaries the analysis needs" line item on TR-005 can be crossed off.
- **Still open:** 2026年度第二批网络安全国家标准需求清单 (attachment 1 of 网安秘字〔2026〕44号) — the working needs list — remains unread. Same PDF-retrieval wall; operator supply pattern still applies. GB 45438-2025, GB/T 45654-2025, and CAC 《生成合成内容标识办法》 remain unread at primary.
- **Newly opened:** TR-004 《工业具身智能安全标准化研究》 (31pp, on disk via same operator supply) is now readable and would inform the §4.1 hardware-genesis / embodied-substrate territory. Deferred to a future session per scope rule.

---

## Appendix A.2 — Delta note (2026-08-20 second pass, post-primary reads of TR-004 + CAC 《标识办法》; landing-page reads of GB 45438 and GB/T 45654)

**Origin.** Same session as Appendix A.1. Operator prompt: "let's hit the next docs." Reads performed in parallel:
- TR-004 《工业具身智能安全标准化研究》 v1.0-202603, 31pp — read in full from the same 网安秘字〔2026〕34号 bundle unpacked for Appendix A.1.
- CAC 《人工智能生成合成内容标识办法》 (国信办通字〔2025〕2号) — all 14 articles fetched from `cac.gov.cn/2025-03/14/c_1743654684782215.htm`.
- GB 45438-2025 — SAMR openstd portal metadata fetched; SAMR carries structured metadata only, no clause preview.
- GB/T 45654-2025 — TC260 landing page (`tc260.org.cn/portal/article/1/20250630122232`) fetched; page is an index with a PDF download link, not full text. SAMR-cleared mirror URL located at `content.mlex.com`.

Confidence upgrades (▲), refinements (◇), and roadmap-bearing findings (◆) below.

### From TR-004 (embodied AI security)

- ▲ **§4.6 cognitive-layer asymmetry needs a nuanced amendment.** The Appendix A.1 delta already noted that TR-005 gestures toward cognitive instrumentation via *"决策过程透明可解释"* but stops short of KEEL-level treatment. TR-004 goes further: §一.(四) names **认知安全 (Cognitive Trustworthiness)** as one of four first-class safety properties — alongside 本体安全 (Physical Safety), 网络安全 (Cyber Security), 控制安全 (Control Robustness) — and lists concrete substrate requirements: *"算法行为可解释、输入输出监测、模型版本审计与抗对抗攻击能力"* (algorithm behavior explainability, input/output monitoring, model version audit, adversarial resistance). This is direct pattern-level parallel to COGNITIVE-SELF-OBSERVER-2026-07 (post-emission verification) + METACOGNITIVE-FIDELITY-HARNESS-2026-08 (model-version-tagged fidelity measurement). **Amendment:** the §6 asymmetry claim that "metacognitive substrate as first-class primitive has no TC260 equivalents" is *narrower than the primary supports.* For **embodied AI specifically**, TC260 has surfaced cognitive-trustworthiness as a first-class dimension with concrete substrate requirements. For **software/general agents** (TR-005 territory), the gap persists. The comparative doc's asymmetry claim should be scoped to the general-agent case; embodied-agent territory has partial convergence.
- ▲ **§4.4 chain-anchored discipline gains an ISO-referenced third instance.** TR-004 §3(二)(a) names *"力觉传感器数据需在边缘节点完成同态加密处理,并同步符合 ISO 10218-1/2 的机械精度指标"* and cites IEEE P7007-2021 requiring *"安全操作数字护照"* recording fault events and ethics audit results. The convergence with KEEL P1 (signing is gravity) is at the international-standards level, not the PRC-only level. Rule 6 remains in force — the specific substrate is not ZP's per-sovereign chain — but the *pattern* of tamper-evident, cryptographically-signed operational records as the compliance mechanism is now surfaced at ISO/IEEE altitude, not just at CAC and TC260 altitude.
- ◇ **The A-B-C-D-E TC260 standards structure is the actual framework.** TR-004 §3(二)(d) shows the 人工智能安全标准体系 V1.0 framework diagram with five top-level parts: **A 基础共性 / B 安全管理 / C 关键技术 / D 测试评估 / E 产品与应用**. Under C 关键技术, 智能体安全 (agent security) and 具身智能安全 (embodied AI security) are *parallel sibling nodes* alongside 生成式人工智能安全, 多模态安全, 生成合成安全, 安全对齐, 安全围栏. **This is a more precise reading than TR-005's 5-dimension framework** (which named the same 5 top-level parts but not the parallel sibling nodes under C). The comparative doc §Prerequisite reading and correspondence table treat "agent security" as a monolithic TC260 workstream; TR-004 confirms it is *one branch alongside embodied-AI and generative-AI*, all three under 关键技术. Composition implication: a ZP Substrate-Form-on-embedded-hardware deployment maps to **both** 智能体安全 AND 具身智能安全 branches simultaneously — a shape the comparative doc §7 scenarios did not name.
- ◇ **Currently-published Chinese AI-safety standards, enumerated (TR-004 §3(二)(d), pp20-22).** Definitive list as of TR-004's drafting: **GB 45438-2025** (mandatory content-marking), **GB/T 41871-2022** (automotive data safety), **GB/T 42888-2023** (ML algorithm security assessment), **GB/T 45654-2025** (generative AI service basic safety), **GB/T 45674-2025** (generative AI data labeling), **GB/T 45652-2025** (generative AI pretraining/fine-tuning data safety), **GB/T 45958-2025** (AI compute platform safety framework), **TC260-003** (generative AI service basic safety, technical doc → graduated to GB/T 45654), **TC260-PG-20233A** (generative AI service content-marking practice guide), **TC260-PG-20211A** (AI ethics-safety risk prevention guide), **T/CESA 1193-2022** (AI risk-management capability assessment, industry-association standard). The comparative doc previously enumerated only GB/T 45654, GB 45438, and GB/T 45288.1. **Seven additional in-force GB/T standards are load-bearing composition surfaces the comparative doc did not name.** Notably GB/T 45652 (training-data safety) and GB/T 45674 (data-labeling safety) are the compliance floor any generative-AI-adjacent ZP deployment into China must clear.
- ◇ **Standards under drafting, per TR-004:** 《网络安全技术 互联网信息服务深度合成安全规范》 and 《网络安全技术 人工智能代码生成服务安全要求》. Both are recommendation-tier and both target service-provider obligations rather than agent-substrate obligations.
- ◇ **Robot-safety standards enumerated (TR-004 §3(二)(e), p23).** GB/T 20867.1-2024 (industrial robot safety base standard), GB/T 45509-2025 (industrial robot dynamic stability testing), GB/T 45501-2025 (industrial robot 3D vision guidance), GB/T 45502-2025 (service robot information-security general requirements), GB/T 39404-2020 under revision (industrial robot control-unit information security). Any ZP Substrate-Form-on-embodied-hardware deployment eventually composes with this stack.
- ◆ **TR-004 §4 standards-need recommendations name six workstreams** for embodied-AI safety: (1) 工业具身智能网络安全防护基本要求, (2) 工业具身智能数据分类分级方法 + 数据安全管理要求, (3) 工业具身智能算法安全要求 + 模型安全要求, (4) 工业具身智能交互安全要求, (5) 安全性能指标与度量体系, (6) 工业具身智能可信评估指标 + 算法安全评估规范. These are the concrete titles TC260 will draft against next; each is a monitoring target for the `ai_landscape` lens.

### From CAC 《人工智能生成合成内容标识办法》 (14 articles)

- ▲ **§4.7 content provenance three-way composition is now specifiable at article-level.** The comparative doc's §4.7 named the three-way tension (KEEL action-side + C2PA content-side + GB 45438 service-side) but treated GB 45438 abstractly. CAC 《标识办法》 is the *regulation* GB 45438 implements. The article-level demands are:
  - **Article 4 (explicit marking, 显式标识):** user-perceivable text/audio/visual marking in the content itself. **C2PA does not natively address this.** A ZP-deployed pipeline into the PRC market must add a visible-watermark layer (audio, video overlay, text disclaimer) separately from C2PA.
  - **Article 5 (implicit marking, 隐式标识):** metadata-embedded marking, with digital watermarks encouraged. **C2PA content credentials plausibly satisfy this article** — the manifest is metadata-embedded, cryptographically signed, and content-file-attached. The composition question narrows to: does a C2PA-only marking discharge Article 5 implicit-marking obligation? Structurally yes; whether the regulator recognizes it is a separate compliance question.
  - **Article 6 (platform verification):** content-distribution platforms must verify the metadata, accept user declarations, and run detection protocols. **This composes with the C2PA verification chain naturally** — the platform-side verification of Content Credentials is exactly the shape Article 6 assumes.
  - **Article 9 (unmarked-content requests):** users can request unmarked content but the service provider must log the request with user consent, retention ≥6 months. This is a *chain-anchored data-retention requirement* directly analogous to how KEEL treats operator-approval receipts as chain-anchored records. Convergence at the compliance mechanism level.
  - **Article 12 (algorithm registration):** the service provider must complete 深度合成算法备案 (deep-synthesis algorithm filing) and submit implementation materials. This is *the* institutional overlay the comparative doc §4.1 identified as characteristic of the Chinese trust root. Article 12 makes it operational for content-marking specifically.
- ◆ **The MEDIA-PROVENANCE-INTEROP-2026-07 composition demand is more specific than §4.7 originally named.** The comparative doc treated GB 45438 as one axis. Correctly stated, the composition is: **(a) KEEL action-side chain receipts for operator provenance**, **(b) C2PA content-side manifest satisfying 《标识办法》 Article 5 implicit-marking**, **(c) a separate explicit-marking layer satisfying Article 4**, **(d) platform-verification chain hooks satisfying Article 6**, **(e) algorithm-filing preparedness under Article 12 if the operator is themselves a service provider**. This is a five-axis composition, not three-way. Bearing on that spec's next revision.
- ◆ **CAC 《标识办法》 Article 5 encouragement of digital watermarks is the strongest EU-Article-50-plus-C2PA alignment vector.** The Article explicitly encourages *"数字水印"* — digital watermarking — as an implicit-marking approach. C2PA's `soft_binding` (durable content binding via watermarking) covers exactly this territory. A single-pipeline C2PA-Content-Credentials + durable-watermark emission plausibly satisfies both EU AI Act Article 50 (via the Code of Practice) and 《标识办法》 Article 5 simultaneously. The three-way scenario in §7 Scenario A can collapse to a two-way scenario (KEEL + C2PA-with-watermark) if the C2PA implementation includes durable-binding. Practically, this is a substantive simplification of MEDIA-PROVENANCE-INTEROP's compositional load.

### From landing-page reads (metadata only)

- GB 45438-2025 metadata confirmed from SAMR openstd portal: standard number, CCS L80, ICS 35.030, in force 2025-09-01 (synchronized with CAC 《标识办法》 in-force date — the pair is a coordinated regulation + implementing-standard rollout, not two independent instruments). Supervising body: 中央网信办. Full-text clauses still not read at primary — SAMR openstd is metadata-only for GB standards. This is a **known retrieval wall**: SAMR sells GB clause text through separate channels.
- GB/T 45654-2025 TC260 landing page fetched: title, secretariat, PDF download link confirmed. **The PDF at the linked download URL is the next primary-read target.** SAMR-cleared mirror at `content.mlex.com` may be reachable via a subsequent WebFetch attempt.

### Bearings on §5 real vs illusory convergence

- The comparative doc's §5 named four real-convergence items. Post this pass:
  - **CAC 《实施意见》 clause 7 blockchain-anchored discipline** — remains the strongest single state-level convergence. Not displaced.
  - **CAC clause 6 three-tier decision authority** — remains. No new evidence.
  - **GB/Z 185 five-stage lifecycle** — not re-tested this pass.
  - **Multi-agent cascade as substrate-level concern** — reinforced by TR-004's cyber-physical framing.
- **New convergence to add:** TR-004 §一.(四) 认知安全 with four concrete substrate-requirements is a **fifth real-convergence item** at the embodied-AI scope. Add to §5 in a future minor revision, with the scope-limit note (embodied only; general-agent case unchanged).
- **New convergence to add:** CAC 《标识办法》 Article 9 6-month retention requirement is a *state-level* mandate for chain-anchored consent-log preservation — direct analog to KEEL's operator-approval receipt discipline and the CAPABILITY-VERIFICATION-RECEIPTS tier-2. Add to §5 as a sixth real-convergence, at the regulatory-mechanism level.

### Bearings on §6 (what each apparatus extends beyond the other)

- **ZP-has-and-TC260-hasn't (metacognitive substrate)** — *scope-corrected*: TC260 has surfaced it for embodied AI (TR-004). For general software agents (TR-005), the gap persists.
- **ZP-has-and-TC260-hasn't (coordination-not-oversight)** — unchanged.
- **ZP-has-and-TC260-hasn't (aligned blindness)** — unchanged and strengthened; TR-004's cyber-physical observation posture is even further from aligned blindness than TR-005's.
- **ZP-has-and-TC260-hasn't (Substrate Form axis)** — unchanged.
- **TC260-has-and-ZP-hasn't (vertical application playbooks)** — TR-004 provides 石化、冶金、钢铁、电力 vertical mentions; the vertical-playbook gap widens further.
- **TC260-has-and-ZP-hasn't (mandatory content-marking regime with implementing standard)** — GB 45438 + 《标识办法》 pair confirmed as a two-instrument coordinated regime. This is the specific regulatory instrument shape the ZP corpus has no analog for (deliberately: ZP is substrate-first, not regulatory-first).

### Updated confidence tags on Appendix A rows

- **TR-004:** primary read; confidence upgrade from "No" to "Yes — 31-pp in-repo primary."
- **CAC 《标识办法》:** primary read; confidence upgrade from "search-level" to "primary read of all 14 articles from cac.gov.cn."
- **GB 45438-2025:** metadata read; confidence upgrade from "search-level" to "metadata-primary + clause-text-still-unread." Standard number, CCS/ICS classifications, and effective-date coordination with CAC 《标识办法》 confirmed at primary.
- **GB/T 45654-2025:** landing-page read; confidence upgrade from "search-level" to "landing-page-primary + PDF-still-unread." Next retrieval attempt: the TC260-linked PDF.

### Cleared, still open, newly opened

- **Cleared:** TR-004 primary; CAC 《标识办法》 primary at article-level; GB 45438 metadata at SAMR; GB/T 45654 landing page + PDF URL located.
- **Still open:** GB/T 45654-2025 full-text PDF (URL known, retrieval not yet attempted); GB 45438-2025 full clause text (retrieval wall at SAMR portal); 2026年度第二批网络安全国家标准需求清单 (unchanged from Appendix A.1).
- **Newly opened:** GB/T 45652-2025 (generative AI pretraining/fine-tuning data safety), GB/T 45674-2025 (generative AI data-labeling safety), GB/T 45958-2025 (AI compute platform safety framework) — TR-004 enumeration surfaced these as in-force standards not previously named in the comparative doc. Composition-relevance depends on the specific ZP deployment surface; monitoring targets, not read-priority.

---

## Appendix A.3 — Delta note (2026-08-20 third pass, post-primary read of GB/T 45654 + clause-level reconstruction of GB 45438)

**Origin.** Same session, operator prompt "continue with the next." Reads performed:
- **GB/T 45654-2025** — full-structure primary read from the SAMR-cleared PDF mirror at `content.mlex.com/Attachments/2025-05-23_CZT297CHX8R49J68/SAMR_NSA_Basic_Security_Requirements_GenAI_service.pdf`. Section headings, key sub-clauses, both appendices confirmed. This clears the largest remaining reading gap in the comparative doc's regulatory baseline.
- **GB 45438-2025** — clause-level requirements *reconstructed* from PwC HK's compliance guide (`pwccn.com/zh/tmt/method-identifying-synthetic-content-generated-ai-sep2025.pdf`) which quotes the standard directly. Appendix E (5-element metadata schema) and Appendix F (single-instance rule) recovered at clause precision. Body-section clause text still gated at SAMR openstd.

Two things drop out that reshape §4.7 and §7 Scenario A:

### From GB/T 45654-2025 (full-structure primary)

- ▲ **Scope note that changes §7 Scenario A analysis.** GB/T 45654-2025's *Scope* clause: applies to *service providers* (服务提供者) and *regulatory / assessment bodies* (监管评估机构). **NOT applied to end-user self-hosted deployments.** Consequence: a ZP-Sovereign-Form operator running local inference for their own use is **not** a service provider under GB/T 45654 — compliance obligation flows upstream to the model provider, not to the operator. GB/T 45654 does apply when the operator publishes generative content (through Article 4/5 of 《标识办法》 + GB 45438), but it does not apply to their local inference activity. **This is a substantive simplification of §7 Scenario B (regulated sensitive-domain deployment) — the Sovereign Form operator's compliance surface is smaller than the comparative doc implied.**
- ▲ **§4.3 two-role annotation discipline is a real convergence with KEEL role-separation instincts.** GB/T 45654 §4.3 mandates *"标注执行与审核角色分离"* (execution role must be separate from review role) for annotation staff. This is the pattern KEEL uses for the observation-signed-vs-act-signed distinction and for the way delegation receipts require distinct roles. Not the same primitive (annotation ≠ delegation), but the same architectural intuition (execution ≠ verification) at the substrate level.
- ▲ **§5.1 explicit numeric compliance metric.** *"生成内容安全性作为评价生成结果优劣的主要考虑指标之一"* — content safety is a primary evaluation metric during training. §5.2 sets a **90% minimum compliance rate for generated content** against Appendix A's 31-category risk taxonomy. This is a *testable numeric bar*, not a general safety principle. Bearing on ZP: substrate-work does not attempt to solve this; it flows through model-provider selection. But it is the hard number Chinese-market compliance measures against, and any ZP deployment scenario that reaches PRC generative-AI service scope must clear it.
- ▲ **Backdoor detection as substrate-level obligation (§5.1).** GB/T 45654 §5.1 mandates *"框架和代码定期安全审计"* and specific *"后门检测与消除流程"* (backdoor detection and remediation procedures). This is TR-005 AIA02 (数据泄露、篡改和投毒) operationalized at a compliance-testing level. Convergence with ZP's supply-chain tier + Quarantine Plane at the pattern level; the specific procedures differ.
- ◇ **§6.6 stability + §6.7 edge deployment.** §6.7 covers edge-device deployment obligations — the specific edge-tier requirements are the closest thing in GB/T 45654 to TR-004 embodied-substrate concerns. Full clauses of §6.7 not fully extracted; would inform §4.5 observation-reach analysis if read in detail. Standing follow-up for a targeted re-read.
- ◇ **Appendix A 31-risk category taxonomy is the compliance-testing shape.** Categories cover: violations of core values, discrimination, commercial violations, rights infringements, service-type inadequacy. This is a content-moderation shape, not a substrate-design shape — but any ZP operator running generative pipelines into PRC markets tests against this list.
- ◇ **Date correction.** The prior Appendix A entry read "2025-05." Primary confirms **2025-04-25 issued, 2025-11-01 in force.** Updated in the Appendix A table above.

### From GB 45438-2025 (clause-level reconstruction via PwC quotations)

- ◆ **The 5-element implicit-marking metadata schema — this is the compositional target.** GB 45438 Appendix E specifies five metadata fields any 隐式标识 (implicit marking) implementation must carry:
  1. **生成合成属性** (generation/synthesis attribute) — the "this is AI-produced" flag
  2. **服务提供者身份标识** (service provider identifier — name or code)
  3. **内容生产编号** (content production number — unique ID from the generator)
  4. **传播服务提供者身份标识** (distribution provider identifier — added by the platform)
  5. **传播内容编号** (distribution content number — added by the platform)
  
  Appendix F rules: **only one metadata instance per file**. This is the article-level, field-level specification the MEDIA-PROVENANCE-INTEROP composition question needed. **A C2PA implementation that carries all five in its assertion set plausibly satisfies GB 45438 Appendix E — but note fields 4 and 5 are ADDED downstream by the distribution platform, not at generation time.** The generator emits fields 1-3; the platform enriches to 4-5 during distribution. This split matters for §7 Scenario A composition planning.

- ◆ **Explicit-marking technical requirements — precise dimensions.** Not a mere "add a visible watermark" instruction. GB 45438 mandates:
  - **Video / virtual scenes:** text height ≥ **5% of the shortest edge**, displayed for ≥ **2 seconds**
  - **Images:** text height ≥ **5% of the shortest edge**
  - **Audio:** *"正常语速，音频节奏'短长短短'清晰可辨"* — a specific rhythm pattern ("short-long-short-short") at normal speech tempo
  - **All content:** must include *"AI"* + *"生成"* or *"合成"* elements, distinguishable
  
  This is a specific enough technical spec that a substrate implementation must have the marking-emission logic wired in per output format. **The C2PA content-credential does not natively cover this** — C2PA's `soft_binding` is durable watermarking (implicit), not explicit user-perceivable text-on-frame. Explicit marking is a *distinct* emission layer.
  
- ◆ **Digital watermarks are encouraged, not mandatory.** *"鼓励引入数字水印等技术手段"* — the vocabulary is 鼓励 (encourage), not 应 (shall). This is a **safe harbor pattern** rather than a hard requirement. A C2PA `soft_binding` implementation is one way to answer the encouragement; not the only way. Bearing on §4.7 three-way (five-way per §Appendix A.2) composition: the watermarking axis is optional-with-benefit, not mandatory. Simplification finding relative to §Appendix A.2.

- ◆ **Article 6 four-step platform verification chain, precise.** PwC quotes 《标识办法》 Article 6 as a four-step: (1) metadata check, (2) user declaration acceptance, (3) trace-detection protocol, (4) self-report function. This is the *distribution-platform* obligation shape. For ZP composition: a Sovereign-Form operator publishing content is themselves the platform for their own emission channel (they carry both Article 4/5 generator obligations AND Article 6 platform obligations if they distribute). **A Companion-Form deployment (per KEEL XIV) with a hosted-vendor platform naturally offloads Article 6 to the vendor.**

### Bearings on §4.7 (content provenance) — final refactor

The comparative doc's original §4.7 gave a three-way distinction: KEEL action-side / C2PA content-side / GB 45438 service-side. Appendix A.2 refactored this to five-way. **Appendix A.3 delivers the article-and-field-precise specification the compositional design can now be drafted against:**

- **Layer 1 (generator, Article 4 explicit):** substrate emits visible text/audio marking meeting the 5%-height and 2-second-duration bars.
- **Layer 2 (generator, Article 5 implicit + GB 45438 Appendix E fields 1-3):** substrate emits metadata containing generation attribute + service-provider ID + content production number. Plausibly discharged by C2PA content credentials with these three fields mapped.
- **Layer 3 (generator, encouraged safe-harbor):** digital watermark, plausibly discharged by C2PA `soft_binding`.
- **Layer 4 (distribution platform, GB 45438 Appendix E fields 4-5):** platform-side enrichment adding distribution-provider ID + distribution content number to the metadata.
- **Layer 5 (distribution platform, Article 6):** four-step verification chain — metadata check → user declaration → trace detection → self-report.
- **Layer 6 (upstream, action-side):** KEEL chain-anchored receipt for operator provenance — coexists with all above.

**Composition demand on MEDIA-PROVENANCE-INTEROP-2026-07:** the field mapping between the 5 GB 45438 metadata elements and C2PA assertion fields needs to be worked out. Generator emits Layer 1 (visible marking) + Layer 2 (three fields in metadata) + Layer 3 (optional watermark) + Layer 6 (chain-anchored receipt). Distribution downstream adds Layer 4-5. This is a substrate-work item, not a research finding — the six-layer decomposition is what MEDIA-PROVENANCE-INTEROP would build against.

### Bearings on §5 real vs illusory convergence

- **Add to §5 (real convergence):** GB/T 45654 §4.3 execution-vs-review role separation as the seventh real convergence item, at the substrate-role-discipline level. Not identical to KEEL but the same architectural intuition.
- **Add to §5 (real convergence):** GB 45438 Appendix E metadata schema is the *specific* substrate-emission spec that KEEL action-side receipts + C2PA content-side assertions compose against. Not a convergence in the "same idea" sense but a convergence in the "same interoperability surface" sense.

### Updated confidence tags on Appendix A rows

- **GB/T 45654-2025:** primary-structure read; confidence upgrade from "landing-page primary" to "primary-structure read of all §4-§6 body clauses and both appendices via SAMR-cleared mirror."
- **GB 45438-2025:** clause-level reconstruction; confidence upgrade from "metadata primary" to "clause-level via professional analysis." Appendix E and F recovered at exact-field precision. Body-section clause text (§4-§6) still gated at SAMR openstd; PwC guide covered the compositionally-relevant technical requirements but not every clause verbatim.

### Cleared vs still open

- **Cleared this pass:** GB/T 45654 §4-§6 structure + both appendices; GB 45438 Appendix E metadata schema + Appendix F single-instance rule + explicit-marking technical dimensions + Article 6 four-step verification.
- **Still open:** GB 45438 §4-§6 exact clause text (SAMR portal wall; may need operator supply of the standard document); **2026年度第二批网络安全国家标准需求清单** (attachment 1 of 网安秘字〔2026〕44号 — unchanged since Appendix A.1); GB/T 45652 / 45674 / 45958 for the extended generative-AI compliance floor named in Appendix A.2.
- **Not attempted this pass:** MIIT 《工业和信息化领域人工智能安全治理标准体系建设指南 (2025)》 — the parallel-track construction guide. Standing follow-up.

### Session summary across the three delta notes

Three primaries newly read at full-or-structure precision in this session — TC260-TR-005 (§Appendix A.1), TC260-TR-004 + CAC 《标识办法》 all 14 articles (§Appendix A.2), GB/T 45654-2025 full structure + GB 45438-2025 clause-level via PwC (§Appendix A.3). This clears the four largest reading gaps identified by the original handoff's standing-follow-ups line. The core comparative doc body (§1–§10) remains structurally unchanged; the three delta notes carry all confidence upgrades, scope corrections, and new composition specificities. A future minor revision to the body should:

- **Promote to §5 body:** the seventh real-convergence item (GB/T 45654 §4.3 role separation) and the sixth (CAC 《标识办法》 Article 9 6-month retention).
- **Scope-correct §6:** the metacognitive-substrate asymmetry claim to "for general software agents; embodied-AI case has partial convergence via TR-004 认知安全."
- **Refactor §4.7:** to the six-layer composition surfaced in this delta note.
- **Fix §3 correspondence-table cascade-risk row vocabulary** per §Appendix A.1.
- **Update Prerequisite / Verification-Posture** to reflect the seven primaries now read at full or structure precision (KEEL §II/III/IV/XIV + CAC 《实施意见》 + 网安秘字〔2026〕34号 + 网安秘字〔2026〕44号 + news.cn GB/Z 185 primary + TC260-TR-005 + TC260-TR-004 + CAC 《标识办法》 + GB/T 45654).

---

## Appendix A.4 — Delta note (2026-08-20 fourth pass, post-primary read of MIIT construction guide + §11 reduction stress-test)

**Origin.** Operator prompt: "next doc then." Target: MIIT 《工业和信息化领域人工智能安全治理标准体系建设指南（2025）》 — the parallel-track construction guide, and the last of the standing-follow-ups from the original handoff that had not yet been touched. First-attempt URL at `aihub.caict.ac.cn/f/d/e1de60a31fac8c0bba447d8e9dd38916` refused by robots.txt. Second attempt at the CAICT LLM portal OSS mirror (`caict-llm-portal-storage.oss-cn-beijing.aliyuncs.com/6153dd34-d7fc-4d24-97b5-d40fc48105c5`) succeeded — this is the finalized guide (not the earlier 征求意见稿 draft).

**Purpose of the read.** This pass has a dual purpose: (1) close the last unread primary from the original handoff's standing follow-ups; (2) **stress-test the §11 root-authority reduction against a genuinely parallel Chinese regulatory track.** The CAC/TC260 corpus has been the doc's focus; MIIT operates from a different authority chain (工业和信息化部 rather than 中央网信办) and if the §11 reduction is real, MIIT-drafted framework work should show the same substrate patterns anchored at a *different* institutional root.

### MIIT seven-dimension framework (A–G)

Unlike TC260's A-B-C-D-E five-dimension structure (surfaced in §Appendix A.2), MIIT partitions differently:

- **A 治理能力** (governance capability) — 支撑能力, 管理能力
- **B 基础设施安全** (infrastructure security) — 硬件平台, 软件平台, 智算中心
- **C 网络安全** (cybersecurity) — 防护, 监测, 管理, 供应链, 风险评估
- **D 数据安全** (data security) — 基础数据服务, 训练数据, 业务数据
- **E 算法模型安全** (algorithm/model security) — 算法安全, 模型安全
- **F 应用安全** (application security) — 工业应用, 行业应用, 智能产品, 智能服务 (**includes 智能体安全**)
- **G 赋能安全** (enablement security) — 网络, 数据, 信息, 业务 enabled-by-AI

Two different Chinese framework decompositions of the same substrate territory: TC260's 5-part (basis / management / key-tech / testing / products) and MIIT's 7-part (governance / infra / network / data / algorithm / application / enablement). This is not a contradiction — it is two ways of slicing the same set of substrate concerns. Both cover the concerns; they package them differently. This is itself evidence for §11: the *substrate concerns* are stable across both frameworks; the *packaging* differs by which authority is doing the drafting.

### MIIT §A 治理能力 dimension is directly parallel to KEEL substrate-primitive vocabulary

The primary lists 治理能力 as containing:

**Support technologies (支撑技术):** 验证 (verification), 监测 (monitoring), 防护 (protection), 追溯 (traceability), 证真 (truth verification), 鉴伪 (forgery detection).

**Governance-support properties (治理支撑):** 透明性 (transparency), 可解释性 (explainability), 鲁棒性 (robustness), 公平性 (fairness), 可追溯性 (traceability), 隐私保护 (privacy protection).

The full twelve-item substrate-concern list maps to KEEL Layer A/B and Tier-2 primitives with substantial parity: 验证 ↔ verify-before-commit (III.22); 追溯 / 可追溯性 ↔ chain-anchored discipline (P1, IV.1 Chain); 证真 ↔ CAPABILITY-VERIFICATION-RECEIPTS; 鉴伪 ↔ MEDIA-PROVENANCE + Circuit Breaker anti-spoof; 透明性 / 可解释性 ↔ COGNITIVE-SELF-OBSERVER + confabulation-gap discipline; 鲁棒性 ↔ metacognitive-fidelity harness; 隐私保护 ↔ aligned blindness (III.24) — same territory named differently.

### MIIT §F 智能体安全 sub-decomposition — direct pattern-level parity with KEEL

MIIT explicitly enumerates the following five sub-dimensions of 智能体安全 under Application Security F:

| MIIT sub-dimension | Direct KEEL / Tier-2 parallel |
|--------------------|------------------------------|
| 内生安全 (intrinsic security) | Substrate integrity, Genesis-derived key discipline, Layer A invariants |
| 数据接口安全 (data interface security) | KEEL II.15 substrate boundary planes, EDGE-TIER-CONTRACT + STORAGE-TIER-CONTRACT |
| 人机协作安全 (human-machine collaboration security) | P9 (system acts; operator signs), KEEL III.16 precedent grows autonomous scope |
| 自主操作安全 (autonomous operation security) | KEEL III.25 octopus-shaped substrate, autonomic-when-routine discipline |
| 多智能体协作安全 (multi-agent collaboration security) | KEEL Part VII Peer-Verification Contract, PEER-TRUST-ANCHOR, CROSS-SUBSTRATE-PEER-CONTRACT |

**Five for five substrate-pattern parity.** MIIT's five-part 智能体安全 decomposition maps to five distinct KEEL discipline areas, one-to-one. This is strong evidence at MIIT altitude for §11: the substrate concerns are the same shape; the delta reduces to which authority root anchors the standards work.

### Two authority-chain visibility gaps in MIIT

- **具身智能 (embodied AI) is not specifically named.** Whereas TC260 TR-004 makes 具身智能 a first-class parallel-sibling under C 关键技术, MIIT's framework is silent on the term. F 工业应用 covers industrial deployment (which encompasses embodied-AI application scenarios), but the specific 具身智能 vocabulary is absent. This is a *scope difference* — MIIT's authority attaches to industry and informatization sectors; the embodied-AI theoretical framing sits with TC260's key-technologies research track. Not a §11 counterexample; both apparatus cover the territory, they name it via their own institutional angle.
- **算法备案 (algorithm registration/filing) is not covered.** This is a **direct §11 corroboration.** Algorithm 备案 is a CAC-track authority mechanism (from 《生成式人工智能服务管理暂行办法》 and 《深度合成管理规定》). MIIT's construction guide does not touch it because MIIT's authority chain does not include the CAC registration regime. The two Chinese ministries have overlapping-but-distinct authority chains; where they don't overlap, the corpus doesn't cover. **This is the reduction observable at the intra-Chinese level:** even *within* the Chinese apparatus, different root authorities produce different corpus coverage in the same substrate territory, differing at exactly the authority-chain point.

### 70-standard forward pipeline (Attachment 2)

MIIT's guide names **70 planned standards** in three urgency tiers:

- **1-year tier (急用先行):** short-horizon standards for rapid-breakthrough scenarios.
- **2-year tier:** medium-horizon.
- **3-year tier:** long-horizon full-coverage.

Two-horizon rollout structure explicitly stated: short-term (1-2 years, 急用先行 / 快速突破) and long-term (3-5 years, 全面保障 / 产业落地). The specific 70-standard list is in Attachment 2 which the search-level fetch did not fully surface; deferred as a standing follow-up for a targeted second retrieval.

### Bearings on §11 root-authority reduction

The MIIT read **strengthens** the §11 reduction rather than complicating it. Three specific corroborations:

1. **The substrate concerns are the same across TC260 and MIIT.** Both apparatus cover verification, traceability, transparency, explainability, robustness, privacy protection, cascade-risk, multi-agent coordination, tool-invocation safety. Different packaging (5-dim vs 7-dim), same territory.
2. **The 智能体安全 5-subdimension one-to-one KEEL parity is the strongest single-instrument alignment recorded in this session.** MIIT partitioned agent security into five sub-dimensions that map without residue to five KEEL discipline areas. That is not the outcome of one apparatus copying the other; it is the outcome of both apparatus reasoning their way to the same substrate decomposition from their respective authority roots.
3. **The 算法备案 gap in MIIT is the reduction visible in a single frame.** Same country, same standards-body ecosystem, two different ministries. One touches algorithm 备案; the other doesn't. The difference is exactly at the authority-chain point. If a scale change (ministry-to-ministry within one country) produces this kind of scoped-coverage delta, then the ZP-to-Chinese scale (sovereign root vs institutional root) producing an eight-axis symptom cascade is the same reduction operating at a larger scale.

### Bearings on the comparative doc body

- **§3 correspondence table** should add a row for MIIT construction guide: seven-dimension framework as parallel-track partition; substrate-concern coverage matches TC260's 5-dim + ZP's KEEL decomposition. Deferred to a future minor revision.
- **§4.3 delegation model.** MIIT's 人机协作安全 sub-dimension operationalizes the P9 shape at industrial-application altitude. Not a new axis — same P9-shape convergence at a third altitude (already have CAC clause 6 and TC260 TR-005 §3.5).
- **§6 what each extends beyond the other.** MIIT adds industrial-application-verticals coverage the ZP corpus does not touch. Consistent with the existing §6 asymmetry finding — Chinese apparatus has verticals, ZP does not.
- **§11 reduction stands.** Explicitly stress-tested against MIIT (different regulator lineage than CAC/TC260); no reduction failure detected; two direct corroborations recorded.

### Updated confidence tags

- **MIIT construction guide:** primary structure read; confidence upgrade from "No (search-level)" to "Yes — full seven-dimension framework + 智能体安全 sub-decomposition."

### What's cleared, what's still open

- **Cleared this pass:** MIIT construction guide primary structure; the last major unread standing-follow-up primary from the original handoff.
- **Still open:** 2026 second-batch needs list (attachment 1 of 网安秘字〔2026〕44号 — unchanged since Appendix A.1, still walled); GB 45438 body clause text (unchanged since A.3); MIIT Attachment 2 70-standard specific enumeration (newly opened this pass — attachment content not fully extracted by the OSS-mirror fetch).
- **Not attempted this session:** 20263116-Q-252 mandatory agent-security standard plan (comparative doc Appendix A row 15). Would be a natural next target if the sweep continues.

### Session tally after this pass

- **Primaries read at full text:** CAC 《实施意见》 (all clauses), CAC 《标识办法》 (all 14 articles).
- **Primaries read at full structure + key clauses:** TC260-TR-005 (92pp), TC260-TR-004 (31pp), GB/T 45654-2025 (§4-§6 + Apps A/B), MIIT construction guide (7-dim framework + agent 5-subdim).
- **Primaries read at clause-level reconstruction:** GB 45438-2025 (Apps E and F, explicit-marking specs, Article 6 verification chain via PwC quotation).
- **Primaries read as landing page / metadata:** 网安秘字〔2026〕34号 notice, 网安秘字〔2026〕44号 notice, news.cn GB/Z 185 series, TC260 GB/T 45654 landing.
- **Total load-bearing primaries touched this session:** 10.

---

## Appendix A.5 — Delta note (2026-08-20 fifth pass, post-primary read of CAC 《生成式人工智能服务管理暂行办法》 — the parent regulation)

**Origin.** Operator prompt: "continue." Target: the single most authority-terminating primary the sweep had not yet touched — CAC 《生成式人工智能服务管理暂行办法》 (Interim Measures for the Management of Generative AI Services), Order No. 15, 2023-07-13 issued, 2023-08-15 in force. This is the *parent regulation* grounding much of the downstream corpus. Reading it lets §11 name the specific PRC statutory clauses where the Chinese apparatus's authority chain terminates on the regulation side, analogous to how the ZP side terminates at KEEL §II invariants. Full 24 articles across 5 chapters read at primary via `cac.gov.cn/2023-07/13/c_1690898327029107.htm`.

### The seven-agency issuance is itself load-bearing

Order No. 15 is issued by **seven agencies acting in concert**: 国家互联网信息办公室 (CAC) + 国家发展和改革委员会 (NDRC) + 教育部 + 科技部 + 工业和信息化部 (MIIT) + 公安部 + 国家广播电视总局. This is the *actual authority-chain-terminating structure* — not "CAC alone" but a coordinated multi-ministry composite root. Consequence for §11: the "institutional root" characterization is more accurately "multi-ministry composite institutional root," and the intra-Chinese stress-test from §Appendix A.4 (MIIT track vs CAC/TC260 track) shows what happens *within* that composite when specific ministries' scopes diverge.

### Article-level statutory anchor for §11

Each of the §11 authority-derived deltas now has a specific 《暂行办法》 clause anchoring it:

| §11 axis | 《暂行办法》 statutory anchor |
|----------|--------------------------|
| Trust root | Article 17 备案 registration for opinion-forming / social-mobilization services; Article 22 service-provider definition (including API-provision) |
| Identity primitive | Article 9 "network information producer responsibility" + Article 22 service-provider identity |
| Delegation model | Article 9 mandatory service agreement between provider and user; Article 22 provider-vs-user role distinction |
| Chain / ledger discipline | Article 11 user input/usage record protection + non-necessary-collection prohibition; Article 19 record-keeping-and-disclosure obligation |
| Observation reach | Article 19 inspection duty ("providers must cooperate and disclose training data sources, scale, type, annotation rules, algorithm mechanisms") |
| Cognitive layer | Article 4 prohibited-content list + Article 7 training data truthfulness/accuracy/objectivity/diversity — cognitive concern at the interface/output level, not at substrate level |
| Content provenance | Article 12 → 《深度合成管理规定》 → 《标识办法》 → GB 45438 (four-tier statutory-to-standard chain) |
| Emergency response | Article 14 cease-halt-delete for violation content + Article 21 penalty ladder (warning → correction → suspension → criminal) + Article 20 cross-border technical disposition |
| Bindingness layering | Article 16 multi-agency enforcement; Order No. 15 as regulatory-level bindingness (higher than GB, subordinate to laws) |

The §11 reduction is now supported by clause-level PRC statutory grounding, not just by pattern-level inference from downstream instruments. Every axis's authority-derivation traces to a specific numbered clause.

### The four-tier statutory-to-standard chain for content marking

《暂行办法》 Article 12 anchors the content-marking chain, and the primary makes explicit which subordinate instrument implements the next tier:

- **Tier 1 (regulation, parent):** 《暂行办法》 Article 12 — marking generated images/videos required per 《深度合成管理规定》.
- **Tier 2 (regulation, specific):** 《互联网信息服务深度合成管理规定》 (2022-12-11 issued, 2023-01-10 in force).
- **Tier 3 (regulation, implementing):** 《人工智能生成合成内容标识办法》 (2025-03, in force 2025-09-01).
- **Tier 4 (standard, mandatory):** GB 45438-2025 (2025-02-28 issued, 2025-09-01 in force — synchronized effective date with Tier 3).

**Bearing on §4.7 six-layer composition specification (from A.3).** The regulation-chain-to-standard-chain vertical is now specifiable: the marking obligation runs Article 12 → 深度合成规定 → 标识办法 → GB 45438. The six emission layers in §4.7 are the technical implementation of this vertical.

### The Article 22 API-provision definition — refinement to A.3 scope note

Appendix A.3 recorded that GB/T 45654-2025 excludes end-user self-hosted deployments from its "service provider" scope. **《暂行办法》 Article 22 narrows this exemption.** The parent regulation defines *"Service Providers: Organizations/individuals delivering such services (including via programmable APIs)."* An individual providing generative AI via API is a service provider under Article 22. Consequence: a Sovereign-Form-for-own-use ZP deployment is outside GB/T 45654 scope only if it exposes no API — the moment the operator opens an API endpoint (even a private one to a small circle), Article 22 pulls them into service-provider scope, and GB/T 45654 obligations plus 备案 registration under Article 17 become applicable. **The self-hosted exemption is narrower than A.3 originally stated.**

### The territorial reach — Article 2 + Article 20

Article 2 scope: services *"providing text, images, audio, video content generation to PRC domestic audiences."* This is the authority-reach declaration — the standard reaches all providers targeting PRC domestic audiences, regardless of provider location. Article 20 states that non-compliant foreign services can be *"disposed via technical measures upon CNNIC notification."* Combined: **extraterritorial by targeting rule** — a foreign-hosted Sovereign-Form operator publishing generative content to PRC domestic audiences is within Article 2 scope, and Article 20 authorizes CNNIC to invoke technical measures (typically DNS/BGP-level blocking) to enforce compliance. Consequence for §7 Scenario A (Sovereign-Form publishing into PRC + EU): the PRC-side compliance obligation attaches by the *audience* the operator is publishing to, not by where the operator is located. Layer B compositional discipline still specifiable; the compliance-trigger boundary is more expansive than territorial residence.

### Article 5 carve-outs

Article 5 states scope carve-outs: *"news, film, artistic creation per separate regulations."* Bearing on §7 Scenario A: specific media categories may exempt from 《暂行办法》 by falling under separate news/film/artistic-creation regulation regimes. This is a compositional shape that a substrate-work analysis of §7 Scenario A would need to account for — not every generative-media publication routes through the 《暂行办法》 filing regime.

### The Article 4 prohibited-content list grounds GB/T 45654 Appendix A

Article 4 lists prohibited content: state overthrow, national security/image, splitting nation, terrorism/extremism, ethnic hatred, violence, obscenity, false harmful information + discrimination + IP/trade secrets. **This is the substrate of GB/T 45654-2025 Appendix A's 31-category risk taxonomy** — the parent regulation names the base categories that the recommended-tier standard elaborates. The 31-item Appendix A is not an independent list; it is an operationalization of Article 4. Bearing on the §4.6 cognitive layer analysis: the "risk to bound" characterization is at the interface/output level, and Article 4 is what defines what "bounded" means — a regulation-side statutory floor.

### Bearings on §11 reduction

**The reduction is corroborated at the strongest possible altitude for the Chinese apparatus: parent regulation Order No. 15 itself.** All eleven primaries now touched, including the parent regulation. Every axis of §11 has a specific Article 4-through-22 clause anchoring it. The MIIT stress-test from A.4 corroborated the reduction at intra-Chinese scale; the Article-17-and-19 grounding in A.5 corroborates it at intra-corpus scale (parent regulation to downstream standards).

Two additional §11 corroborations from A.5:

- **The 4-tier statutory chain (Article 12 → 深度合成规定 → 标识办法 → GB 45438) is the visible authority-cascade.** Each tier terminates at the tier above, and the entire cascade terminates at Order No. 15 which itself terminates at the multi-agency composite root. This is what §11 identified abstractly as "institutional root"; A.5 shows the exact statutory ladder.
- **Article 22 API-provision-as-service-provision is the reduction visible at operational altitude.** The regulation does not care whether an entity is a "hosted service" or a "sovereign operator running local inference" — it cares whether the entity provides generative AI via API to PRC-directed audiences. That framing is precisely the authority-root-anchored classification the §11 reduction identifies as the delta with ZP's sovereign root.

### Updated confidence tags

- **《暂行办法》:** primary read (full text of all 24 articles across 5 chapters). This closes the last major regulation-side gap the sweep had.

### What's cleared, what's still open

- **Cleared this pass:** 《暂行办法》 full text — the parent-regulation authority-terminating primary. No further high-value primary reads on the CAC/regulation side remain open at time of this session.
- **Still open (unchanged):** 2026 second-batch needs list (attachment 1 of 网安秘字〔2026〕44号); GB 45438 §4-§6 exact clause text; MIIT Attachment 2 70-standard specific enumeration; 《人工智能安全治理框架 2.0》 (2025-09-15, TR-005 §3.2.1 reference); 20263116-Q-252 mandatory agent-security standard draft.
- **Newly opened:** 《互联网信息服务深度合成管理规定》 (2022-12, in force 2023-01-10) — the middle tier of the four-tier content-marking statutory chain, referenced by 《暂行办法》 Article 12. Not previously named in the sweep; adds one specific unread regulation to the standing-follow-ups.

### Session tally after five passes

- **Primaries read at full text (3):** CAC 《实施意见》, CAC 《标识办法》 (14 articles), CAC 《暂行办法》 (24 articles).
- **Primaries read at full structure + key clauses (4):** TR-005 (92pp), TR-004 (31pp), GB/T 45654-2025, MIIT construction guide.
- **Primaries read at clause-level reconstruction (1):** GB 45438-2025 (Apps E+F + explicit-marking specs + Article 6 chain).
- **Primaries read as landing / metadata (3):** 网安秘字〔2026〕34号, 网安秘字〔2026〕44号, news.cn GB/Z 185.
- **Total load-bearing primaries touched:** 11.

---

## Appendix A.6 — Delta note (2026-08-20 sixth pass, post-primary read of 《互联网信息服务深度合成管理规定》 — the middle tier of the content-marking chain)

**Origin.** Operator prompt: "continue." Target named as newly opened at end of §Appendix A.5. Full-text primary read of CAC 《互联网信息服务深度合成管理规定》 (三部门令第12号), 2022-11-25 issued, 2023-01-10 in force, via `cac.gov.cn/2022-12/11/c_1672221949354811.htm`.

### The three-agency issuance is narrower than 《暂行办法》's seven-agency

Three issuing bodies: 国家互联网信息办公室 + 工信部 + 公安部. Compared to Order No. 15's seven-agency composite (adding NDRC + 教育部 + 科技部 + 广电总局), Order No. 12 is the content-security-agency-only composite. **Bearing on §11 institutional-root characterization:** the Chinese "institutional root" is not a single monolithic authority; it is a *composite that varies by regulation*, with the specific ministries included reflecting which sectoral concerns the regulation attaches to. For deep-synthesis content security: three agencies. For generative-AI service management: seven. The composite membership itself is authority-derived.

### Article 23 introduces a four-role decomposition — a shape the sweep had not surfaced

Article 23 defines four distinct roles:

- **深度合成技术** (deep-synthesis technology) — the technology itself
- **深度合成服务提供者** (service provider) — organizations/individuals providing the service
- **深度合成服务技术支持者** (**technical supporter**) — organizations/individuals providing *technical support* to the service
- **深度合成服务使用者** (service user) — organizations/individuals using the service to create/copy/publish/distribute

**The technical-supporter role is the load-bearing addition.** Neither the ZP-side nor the earlier CAC/TC260 primaries the sweep had touched drew this distinction as explicitly. TR-005 §3.5 named four *risk-solution parties* (模型算法研发者 / 智能体开发平台提供者 / 智能体服务提供者 / 智能体用户); Order No. 12 §23 names four *service-relationship roles*. Different decompositions, both are supply-chain accountability cuts, but Order No. 12's version separates *the technical layer under the service* as an explicit party with its own obligations.

**Bearing on §11.** The technical-supporter role maps to KEEL's substrate layer (Genesis-anchored substrate providing capability to the operator), while service-provider maps to the operator (Regent + officer cadre execution). **Both apparatus recognize the same two-layer distinction — substrate vs operator-of-substrate — with the delta at where each layer's authority terminates.** The Chinese apparatus terminates both layers at the institutional root (备案-filed entity, Article 19 disclosure duty applies to both layers per Article 19's "参照履行" language); the ZP apparatus terminates both at operator-Genesis. Same architectural distinction, different anchor. Downstream of root authority per §11.

### Article 17 five-category prominent-marking trigger — the *when* to §Appendix A.3's *how*

Article 17 mandates *显著标识* (prominent marking) for **five specific high-risk categories**:

1. **智能对话、智能写作** (intelligent dialogue / writing)
2. **合成人声、仿声** (synthetic voice / voice imitation)
3. **人脸生成、人脸替换、人脸操控** (face generation / face swapping / face manipulation)
4. **沉浸式拟真场景** (immersive realistic scenes)
5. **其他具有生成或显著改变信息内容功能的服务** (other services with significant generation/alteration capability)

For services not in the five categories, the obligation is *"提供显著标识功能，并提示使用者可以进行显著标识"* — provide the marking function, prompt users to invoke it.

**Bearing on §Appendix A.3 six-layer composition.** A.3 gave the *how* of marking (5% edge height, 2s duration, "短长短短" audio rhythm, 5-element metadata schema). Article 17 gives the *when* — which content categories trigger the prominent-marking obligation vs which only require the marking-function-provision. **This is the categorical trigger anchor for the six-layer composition.** Face-generation content: prominent marking required. Intelligent-writing content: prominent marking required. Non-face-non-voice-non-dialogue content: marking function must be available, invocation is discretionary. Bearing on §7 Scenario A: a Sovereign-Form operator publishing face-swap or voice-clone content into PRC audiences hits Article 17 category 3 or 2 automatically; a text-generation-only pipeline hits category 1 (intelligent-writing) if the text is presented as human-authored.

### Article 16 implicit marking — the parent clause for 《标识办法》 Article 5

Article 16: *"应当采取技术措施添加不影响用户使用的标识，并依照法律、行政法规和国家有关规定保存日志"* — implicit marking via technical measures + log preservation per legal/regulatory requirements. **This is the parent clause for CAC 《标识办法》 Article 5** (metadata-embedded marking, digital watermark encouraged). Confirms the four-tier statutory chain the A.5 delta note identified.

### Article 19 备案 — the parallel-mechanism confirmation, points at a deeper root

Article 19: services with *"舆论属性或者社会动员能力"* (opinion-forming or social-mobilization capacity) must complete 备案 per 《互联网信息服务算法推荐管理规定》. **Same clause structure as 《暂行办法》 Article 17.** Same trigger, same reference. Additionally: technical supporters *"参照履行"* (shall file by reference) — extending 备案 to the substrate layer.

**Critical bearing on §Appendix A.5's four-tier statutory chain.** The chain is really a **five-tier chain**: (Tier 0) 《互联网信息服务算法推荐管理规定》 (2021-12-31 issued, 2022-03-01 in force, four-agency Order No. 9) → (Tier 1) 《暂行办法》 Order No. 15 → (Tier 2) 《深度合成规定》 Order No. 12 → (Tier 3) 《标识办法》 → (Tier 4) GB 45438. Both Order No. 15 Article 17 and Order No. 12 Article 19 point at 《算法推荐规定》 as the *actual* mechanism-defining regulation for 备案. **The Chinese apparatus's institutional root actually terminates at 《算法推荐规定》, not at Order No. 15 as A.5 had it.** Order No. 15 is a very-high-level anchor; 《算法推荐规定》 is the operational-mechanism-defining anchor for the specific 备案 mechanism that §11 identified as the load-bearing authority-terminating mechanism. Newly opened primary; would be the natural next surgical read.

### Article 15 + Article 20 security-assessment requirements

- **Article 15:** face/voice editing tools + national-security-related scene tools require 安全评估 (self or third-party) before deployment.
- **Article 20:** new products/applications/features with 舆论属性 or 社会动员能力 require 安全评估.

**Bearing on §Appendix A.5 statutory anchor table.** Add rows: face/voice tools → Article 15 pre-deployment assessment; new-feature launches → Article 20 pre-deployment assessment. The 安全评估 (security assessment) is the *ex-ante* compliance mechanism that composes with 备案 (registration) as the *ongoing* compliance mechanism. Together they form the two-part pre-deployment + ongoing-oversight enforcement structure.

### Service Provider vs Technical Supporter obligation-allocation table

From primary text:

| Dimension | 服务提供者 | 技术支持者 |
|-----------|-----------|-----------|
| Real-name authentication of users (Art 9) | Required | Not specified |
| Content moderation of inputs and outputs (Art 10) | Required | Not specified |
| Implicit marking + log preservation (Art 16) | Required | Not specified |
| Prominent marking for five categories (Art 17) | Required | Not specified |
| 备案 for opinion/mobilization services (Art 19) | Required | Required (参照履行) |
| 安全评估 (new features) (Art 20) | Required | Not specified |
| 安全评估 (face/voice tools) (Art 15) | Not specified | Required |

**Two-layer role separation is asymmetric, not symmetric.** Service providers carry the user-facing compliance load (authentication, moderation, marking); technical supporters carry the substrate-provisioning compliance load (备案 by reference, security assessment for face/voice tools). This asymmetry maps directly to KEEL's substrate-vs-operator distinction, though ZP places substrate authority at operator-Genesis rather than at a filed technical-supporter regime.

### Bearings on §11 reduction

**A.6 corroborates §11 at operational-mechanism altitude.** Order No. 12 provides:

- The three-agency-vs-seven-agency issuance-composite variation (composite membership is authority-derived per §11).
- The four-role decomposition with technical-supporter as an explicit layer (matches KEEL two-layer substrate architecture, differs only at where each layer's authority terminates — §11 reduction visible in role structure).
- Article 17 five-category marking-trigger and Article 19 parallel 备案 mechanism (both authority-derived per §11).
- A pointer to 《算法推荐规定》 as the actual mechanism-defining root — confirming that "institutional root" in §11 is really "algorithm-recommendation regulation" at the mechanism altitude, with Order Nos. 12 and 15 as adjacent regulations pointing at the same root.

**No §11 counterexample surfaced.** The reduction survives this primary read.

### Bearings on §7 composition scenarios

- **Scenario A (Sovereign-Form publishing).** Article 17 five-category trigger means: face-swap or voice-clone content → prominent marking required immediately. Text-generation content presented as human-authored → category 1 (intelligent-writing) trigger. Non-triggered categories: marking function must be *available*. This is a substantive refinement of Scenario A's compliance path.
- **Scenario B (sensitive-domain deployment).** Article 15 face/voice tool 安全评估 obligation attaches to the substrate layer (technical supporter), not just the service provider. A ZP substrate providing face/voice editing capabilities to an operator would carry Article 15 assessment obligation if it operates within PRC scope. Consistent with the A.5 finding that Sovereign-Form-with-API is in-scope.
- **Scenario C (cross-org GB/Z 185 counterparty).** Article 23 role distinction extends the counterparty analysis: is the counterparty a service provider, a technical supporter, or both? Layer B adapter design should account for the possibility that role classification determines which Order No. 12 clauses apply.

### Updated confidence tags

- **《深度合成管理规定》 (Order No. 12):** primary read (full text). Closes the middle-tier gap in the content-marking statutory chain.

### What's cleared, what's still open

- **Cleared this pass:** Order No. 12 full text — the middle tier of the four-tier (now five-tier) content-marking statutory chain.
- **Still open (unchanged):** 2026 second-batch needs list; GB 45438 §4-§6 exact clause text; MIIT Attachment 2 70-standard specific enumeration; 《人工智能安全治理框架 2.0》; 20263116-Q-252 mandatory agent-security standard draft.
- **Newly opened this pass:** **《互联网信息服务算法推荐管理规定》 (2021-12-31 issued, 2022-03-01 in force, four-agency Order No. 9)** — the actual mechanism-defining root of the 备案 chain. Both Order No. 15 Article 17 and Order No. 12 Article 19 point at this as the 备案 mechanism reference. Reading it would ground §11 at the deepest authority-anchoring altitude the CAC apparatus has produced. Highest-value next primary target if the sweep continues.

### Session tally after six passes

- **Primaries read at full text (4):** CAC 《实施意见》, CAC 《标识办法》 (14 articles), CAC 《暂行办法》 (24 articles), CAC 《深度合成规定》.
- **Primaries read at full structure + key clauses (4):** TR-005 (92pp), TR-004 (31pp), GB/T 45654-2025, MIIT construction guide.
- **Primaries read at clause-level reconstruction (1):** GB 45438-2025.
- **Primaries read as landing / metadata (3):** 网安秘字〔2026〕34号, 网安秘字〔2026〕44号, news.cn GB/Z 185.
- **Total load-bearing primaries touched:** 12.

---

## Appendix A.7 — Delta note (2026-08-20 seventh pass, post-primary read of 《互联网信息服务算法推荐管理规定》 — the root of the 备案 mechanism)

**Origin.** Operator prompt: "Continue." Target: **the deepest authority-anchoring altitude the CAC apparatus has produced.** Both Order No. 15 Article 17 and Order No. 12 Article 19 point at 《互联网信息服务算法推荐管理规定》 as the reference regulation for the 备案 mechanism. Reading this closes the mechanism-defining root gap. Full text of all 35 articles across 6 chapters read at primary via `cac.gov.cn/2022-01/04/c_1642894606364259.htm`.

### The four-agency issuance completes the composite-membership pattern

Four issuing bodies: **国家互联网信息办公室 + 工信部 + 公安部 + 市场监管总局**. Compared to Orders No. 12 (three-agency, no SAMR) and No. 15 (seven-agency, adds four sectoral bodies), Order No. 9 sits in the middle with SAMR joining the core CAC+MIIT+公安 three. **The composite-membership pattern is now visible across four regulations:**

| Regulation | Agencies | Sectoral additions vs core |
|-----------|----------|---------------------------|
| Order No. 9 (algorithm-recommendation root) | 4 | + SAMR (consumer protection) |
| Order No. 12 (deep synthesis) | 3 | — (core only) |
| Order No. 15 (generative AI services) | 7 | + NDRC + 教育部 + 科技部 + 广电总局 (development + education + S&T + broadcast) |
| 《标识办法》 | 4 | + 广电总局 |

**The core CAC+MIIT+公安部 three-agency is stable across all content-related CAC regulations.** Additions are sectoral, added when the regulation touches consumer protection (SAMR), development coordination (NDRC), education/S&T policy, or broadcast content oversight. **This is the actual §11 "institutional root" characterization:** the Chinese authority anchor is a *stable three-agency core with sectoral extensions per regulation.* Not "CAC alone" and not "seven agencies always" — a three-agency substrate with sectoral cosigners.

### Article 2 defines FIVE algorithm-type branches

Article 2: *"应用算法推荐技术，是指利用生成合成类、个性化推送类、排序精选类、检索过滤类、调度决策类等算法技术向用户提供信息."*

The five branches:
1. **生成合成类** (generative synthesis) — the branch Order Nos. 12 and 15 elaborate
2. **个性化推送类** (personalized push)
3. **排序精选类** (ranking selection)
4. **检索过滤类** (retrieval filtering)
5. **调度决策类** (scheduling decision)

**Bearing on the four-tier chain from §Appendix A.6.** The chain is really a **five-tier chain rooted at Order No. 9**, and Orders No. 12 and 15 are specific branch-elaborations for the *生成合成类* branch. The other four branches (personalization, ranking, filtering, scheduling) route through 备案 without going through Orders 12/15. **The Chinese apparatus's actual structural anatomy for algorithm regulation is:**

- **Root:** Order No. 9 (五-branch algorithm framework + 备案 + 分级分类 mechanisms)
  - 生成合成类 branch:
    - Order No. 12 (deep synthesis) — 2022
    - Order No. 15 (generative AI services) — 2023
      - 《标识办法》 — 2025
        - GB 45438-2025

**§Appendix A.6 called this a "five-tier chain"; the accurate characterization is "six-tier chain when tracing generative-content marking, rooted at Order No. 9."** The other four algorithm branches route through Order No. 9 → 备案 without the generative-marking downstream tier.

### Articles 23-25: the definitive 备案 mechanism

- **Article 23 分级分类 rubric definitively established.** Grading criteria: (1) opinion-forming/mobilization capacity, (2) content categories, (3) user scale, (4) data importance, (5) degree of user-behavior intervention. **This is the SPECIFIC RUBRIC that CAC 《实施意见》 clause 11 (分级分类治理) elaborates and that TR-005 §3.6 risk-treatment classification is a downstream operationalization of.** Every downstream 分类分级 mention in the CAC/TC260 corpus references this five-criterion rubric.
- **Article 24 备案 trigger + timeline.** Trigger: services with 舆论属性 or 社会动员能力 (opinion-forming or social-mobilization capacity). Timeline: file within 10 working days of service commencement. Content: name + service form + application domain + algorithm type + algorithm self-assessment report + proposed publicity content. Changes: 10 working days. Cancellation: 20 working days after termination.
- **Article 25 authority response.** Authority responds within 30 working days: complete filing → 备案 number issued + public notice; incomplete filing → rejection with reasons.
- **Article 26.** 备案-completed providers must display the 备案 number prominently on their website/application and provide a link to the public notice.

**Bearing on §11 root-authority reduction.** The mechanism-defining altitude is Articles 23-26 of Order No. 9. This is where the Chinese apparatus's institutional root actually terminates on the operational-mechanism side. §11's statutory-anchor table (from §Appendix A.5) should be re-anchored here for the specific 备案 clauses: the authoritative reference is Order No. 9 Articles 23-26, not Order No. 15 Article 17 or Order No. 12 Article 19 (both of which point at Order No. 9).

### Article 17 — Chinese-apparatus user rights (GDPR-Article-22-shape)

Article 17 grants three user rights that read as the Chinese-apparatus version of algorithmic-decision transparency and control:

1. **Non-personalization option or convenient opt-out.** Providers must offer users the choice to not have algorithmic personalization applied to them, or a convenient way to disable it.
2. **User-tag deletion.** Users can select or delete the user tags used for personalization about them.
3. **Liability explanation for significant impact.** When algorithms cause significant impact on user rights, providers must lawfully explain and bear responsibility.

**Bearing on §5 real convergence.** This is a real convergence with KEEL discipline at the user-rights level: (1) maps to KEEL's operator-retains-meaningful-choice / P9-shape; (2) maps to observation-scope discipline (delegation-scoped observation, aligned blindness's cousin at the tag-management level); (3) maps to the accountability chain that flows from chain-anchored records. Adds an eighth real-convergence item at the user-rights level. Rule 6 still in force: the mechanisms differ (Chinese: opt-out setting + tag-management UI; ZP: sovereign-root discipline structurally denies the accumulation), but the outcome for the user is comparable.

### Article 28 — the inspection-and-log-preservation duty, at deepest altitude

Article 28: *"提供者应依法留存网络日志，配合开展安全评估和监督检查，提供必要的技术、数据支持和协助"* — providers shall lawfully preserve network logs, cooperate in security assessments and inspections, provide necessary technical and data support and assistance.

**This is the parent clause for 《暂行办法》 Article 19** (the inspection-authority clause §Appendix A.5 identified as the mechanism realization of §11's observation-reach axis). The log-preservation duty is anchored at Order No. 9 altitude, three tiers deep in the hierarchy. **§4.5 body-section reference to Article 19 should now note the Order No. 9 Article 28 origin.**

### Chapter 3 — user-rights body deeper than the sweep had captured

Order No. 9 Chapter 3 (Articles 16-22) has seven articles of user-rights protection:
- **Article 16:** service disclosure + algorithm transparency (basic principle, purpose intent, main operational mechanism)
- **Article 17:** user rights (non-personalization opt-out, tag deletion, liability explanation) — covered above
- **Article 18:** minors' network protection duty + prohibitions against unsafe-behavior modeling and addiction-inducing recommendations
- **Article 19:** elderly service adaptation (transportation, medical, consumption, government-affairs needs + anti-fraud monitoring)
- **Article 20:** labor-rights protection for workers receiving algorithmic dispatch (compensation, working hours, rest days, order allocation)
- **Article 21:** consumer protection — **explicit prohibition on algorithmic 大数据杀熟 (dynamic discriminatory pricing based on user preferences and transaction habits)**
- **Article 22:** complaint and reporting mechanisms with defined processing timelines

**Bearing on §6 (what each apparatus extends beyond the other).** Chapter 3 is territory the ZP corpus does not touch — deliberately, because ZP is substrate-first — but a mature agent-era compliance regime is expected to have these rights defined somewhere. The Chinese apparatus places them at the regulation altitude; ZP places them at the sovereign-operator level (the operator decides). Downstream of root authority per §11.

### Article 14 — prohibition catalog against algorithm-abuse patterns

Article 14 prohibits: fake-account creation, illegal account trading, account manipulation, fake likes/comments/shares, information blocking, over-recommendation, ranking manipulation, hot-search control, evasion of oversight. This is the *Chinese apparatus's substrate-integrity floor* — the specific behaviors that platform-scale algorithm services are forbidden from engaging in.

**Bearing on §5 real convergence.** Direct pattern-level parallel to KEEL III.24 (aligned blindness — the substrate has no business observing certain classes) at the *market-behavior* level: some substrate capabilities shouldn't be used to manipulate at scale. Different mechanism (Chinese: regulatory prohibition; ZP: structural design refusal), same intuition. Rule 6: worth noting but not counted as a distinct real-convergence item — the mechanism divergence is substantial enough that this reads as parallel evolution to the same intuition rather than shape-level convergence.

### Article 33 — falsification-of-备案 penalties define the enforcement teeth

- Cancellation of 备案 for hidden information or false materials
- Warning + public criticism
- Serious violations: service-update suspension + fines 10,000-100,000 CNY
- Penalty for failure to cancel filing when required, or for entities whose websites/licenses/business permits are revoked: 备案 canceled by authority

**Bearing on §4.8 emergency response.** The enforcement chain is now specifiable at clause precision: 警告 → 通报批评 → 责令限期改正 → 责令暂停信息更新 → 罚款 → 治安管理 or 刑事 responsibility. The chain terminates in criminal liability per 《刑法》 or public-security law per 《治安管理处罚法》. Same enforcement-terminates-through-state-power pattern §11 identified.

### Bearings on §11 root-authority reduction

**A.7 corroborates §11 at the deepest possible statutory altitude for the CAC apparatus.** Every downstream regulation (Orders No. 12, 15, 《标识办法》, GB 45438) that references 备案 as its authority-anchoring mechanism points at Order No. 9. Reading Order No. 9 shows:

- The 备案 mechanism definitively terminates at Articles 23-26 (the 分级分类 rubric + 备案 lifecycle).
- The inspection-and-log-preservation duty definitively terminates at Article 28.
- The user-rights layer definitively terminates at Articles 16-22 (Chapter 3).
- The prohibition-catalog for algorithm abuse patterns definitively terminates at Article 14.
- The composite-membership pattern (CAC+MIIT+公安部 core, sectoral additions) is now visible as a stable structural feature across four regulations.

**No §11 counterexample surfaced.** The reduction survives this deepest primary read.

**§11 sharpening on institutional-root characterization.** The Chinese "institutional root" is really:
- **Regulatory-root altitude:** Order No. 9 for algorithm-recommendation services (of which generative-AI is one branch); other regulation families exist for other AI concerns.
- **Agency-composite altitude:** CAC + MIIT + 公安部 three-agency core with sectoral additions.
- **Mechanism altitude:** Articles 23-26 (备案) + Article 27 (安全评估) + Article 28 (inspection cooperation) + Chapter 3 (user rights).
- **Enforcement altitude:** Articles 31-33 (administrative penalties) + escalation to public-security-law and criminal-law regimes.

Four altitudes of authority-terminating machinery, all downstream of the CAC+MIIT+公安部 three-agency core with SAMR joining specifically for algorithm-recommendation coverage. Sharper than "institutional root" as abstractly named in §11.

### Bearings on §7 composition scenarios

- **Scenario A (Sovereign-Form publishing).** Article 17 non-personalization opt-out attaches if the operator's substrate uses any personalization. A ZP substrate that doesn't personalize (e.g., stateless generation) has *no* Article 17 obligation; a ZP substrate that maintains user-tag state must expose opt-out. Article 14 prohibitions attach categorically — a Sovereign-Form operator cannot use algorithm-abuse patterns even for their own use in a service context.
- **Scenario B (sensitive-domain deployment).** Article 23 分级分类 rubric applies: opinion-forming/mobilization + user scale + data importance + degree of intervention. A Sovereign-Form operator in a sensitive-domain deployment likely hits multiple 分级分类 criteria — the compliance surface is broader than just 备案.
- **Scenario C (cross-org GB/Z 185 counterparty).** Article 28 log-preservation applies to the ZP side if operating as an algorithmic-recommendation service provider within PRC scope. Layer B adapter design should account for log-preservation obligations.

### Updated confidence tags

- **《算法推荐管理规定》 (Order No. 9):** primary read (full text of all 35 articles across 6 chapters). This is the mechanism-defining root for the entire CAC content-regulation apparatus. No deeper regulation altitude exists that hasn't been touched.

### What's cleared, what's still open

- **Cleared this pass:** Order No. 9 full text. The mechanism-defining root of the CAC content-regulation apparatus. The 备案 chain is fully traced from root (Order No. 9) through generative-AI branch (Order No. 15) to marking implementation (《标识办法》 + GB 45438).
- **Still open (unchanged):** 2026 second-batch needs list; GB 45438 §4-§6 exact clause text; MIIT Attachment 2 70-standard specific enumeration; 《人工智能安全治理框架 2.0》; 20263116-Q-252 mandatory agent-security standard draft.
- **Not this pass, but standing:** the "other four algorithm-type branches" (个性化推送 / 排序精选 / 检索过滤 / 调度决策) each have their own downstream regulation stacks not touched by the sweep. Reading them would test whether §11 holds across the *other* Order No. 9 branches beyond just 生成合成类; would be a natural next stress-test target.

### Session tally after seven passes

- **Primaries read at full text (5):** CAC 《实施意见》, CAC 《标识办法》 (14 articles), CAC 《暂行办法》 Order No. 15 (24 articles), CAC 《深度合成规定》 Order No. 12, CAC 《算法推荐规定》 Order No. 9 (35 articles).
- **Primaries read at full structure + key clauses (4):** TR-005 (92pp), TR-004 (31pp), GB/T 45654-2025, MIIT construction guide.
- **Primaries read at clause-level reconstruction (1):** GB 45438-2025.
- **Primaries read as landing / metadata (3):** 网安秘字〔2026〕34号, 网安秘字〔2026〕44号, news.cn GB/Z 185.
- **Total load-bearing primaries touched:** 13.

**The CAC regulation stack is now traced to the mechanism-defining root.** No deeper regulation altitude exists that hasn't been touched.

---

## Appendix B — ZP-side references cited

For traceability. Reachable at `docs/KEEL-2026-07.md` and `docs/design/` in this repo.

- KEEL 2026-07 — canonical spec. §II invariants (Layer A), §III axioms (Layer B canonical claims), §IV ontology definitions, §XIV substrate realization.
  - §II.4 delegation narrowing, §II.5 Genesis-as-single-root, §II.9 two-layer architecture, §II.13 nine design principles, §II.14 canonical substrate form, §II.15 substrate boundary planes.
  - §III.1 sovereign operator as fundamental unit, §III.6 two-layer amendment, §III.8 bounded operator sovereignty, §III.12 metacognition as load-bearing, §III.13 chain is truth / ontology is understanding, §III.15 sovereign fleet as one coordinated substrate, §III.16 precedent grows autonomous scope, §III.18 delegable safety, §III.19 detectability over invulnerability, §III.20 forward-only recovery, §III.22 verify before commit, §III.23 coordination not oversight, §III.24 aligned blindness, §III.25 distributed cognition with central intent.
  - §XIV.1 three Forms, §XIV.3 Form Disclosure, §XIV.4 Sovereign Form trust chain, §XIV.5 Hardware Genesis, §XIV.8 Form graduation.
- Tier-2 elaborations referenced:
  - OBSERVATION-PLANE-2026-07
  - CIRCUIT-BREAKER-2026-07
  - PEER-TRUST-ANCHOR-2026-07, CROSS-SUBSTRATE-PEER-CONTRACT-2026-06
  - COGNITIVE-INPUT-PLANE-2026-07, COGNITIVE-SELF-OBSERVER-2026-07, COGNITIVE-ACT-ACCOUNTING-2026-07, COGNITIVE-MODE-AND-AGENCY-2026-07, METACOGNITIVE-FIDELITY-HARNESS-2026-08
  - COGNITIVE-PRIMITIVES-OPPORTUNITY-MAPPING-2026-07, COGNITIVE-TOOLS-OPPORTUNITY-MAPPING-2026-07
  - MEDIA-PROVENANCE-2026-07, MEDIA-PROVENANCE-INTEROP-2026-07
  - QUARANTINE-PLANE-2026-07
  - SOVEREIGN-KINSHIP-PRIMITIVES-2026-07
  - AGENT-TOOL-CONTRACT-2026-06, CAPABILITY-VERIFICATION-RECEIPTS
  - PEER-DISCOVERY-AS-OUTREACH-2026-07
