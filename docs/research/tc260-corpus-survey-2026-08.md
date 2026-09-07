# TC260 corpus survey — 2026-08

**Author:** Cowork sweep agent, at operator request 2026-08-20.
**Status:** Research artifact. Not canonical, not indexed under `CANONICAL-CORPUS-INDEX-2026-07.md`. Survey of an external tradition to inform roadmap orientation per the `ai_landscape` lens.
**Verification posture:** Every enumerated instrument was named at either a TC260 primary (`tc260.org.cn`) or a state-media primary (`news.cn`, `secrss.com`, `caict.ac.cn`). Instrument *contents* rest on Chinese-language summaries unless explicitly noted as read at primary. PDFs from `tc260.org.cn/sysFile/downloadFile/...` are direct binary attachments and returned as `application/x-msdownload` under `web_fetch`, unreadable in this session — flagged where they matter.

The `ai-landscape-log.md` sources file records `tc260.org.cn/portal/project/plan` as the operator-named **"weather report" dashboard** — the working project list that precedes any published instrument. This survey collates what has *already* landed downstream of that dashboard, so the roadmap has a fixed reference against which future plan-list entries can be read.

---

## 1. What TC260 is, and what its outputs are called

**TC260** — 全国网络安全标准化技术委员会 (National Cybersecurity Standardization Technical Committee), Chinese national mirror of ISO/IEC JTC 1/SC 27. Secretariat at the 中国电子技术标准化研究院 (China Electronics Standardization Institute, CESI) in Beijing. Sub-organized into working groups; **WG9 (人工智能安全标准工作组, Artificial Intelligence Security Standards Working Group)** was formally constituted at the 2026 first Director's Office meeting and owns the AI-specific track.

Four output classes, in decreasing bindingness:

- **GB / GB/T** — 国家标准 (national standard) / 国家推荐性标准 (recommended national standard). GB is mandatory; GB/T is recommended but frequently referenced in regulation as the operative test.
- **GB/Z** — 国家标准化指导性技术文件 (guidance-track technical document). Weaker legal status than GB/T; used where the technology is moving faster than the ceremony a mandatory standard requires. The `智能体互联` series is on this track.
- **TC260-nnn** — Committee-published operational documents (e.g. `TC260-003` = 生成式人工智能服务安全基本要求, later graduated to `GB/T 45654-2025`). Faster than a GB/T; often the pre-cursor.
- **TC260-TR-nnn-YYYY** — Technical Research Reports. Explicitly *research*, not standards, and titled as such — "for reference in standards research and drafting work." The mechanism by which the standards apparatus establishes shared vocabulary before an instrument is drafted.

Adjacent bodies that produce parallel work in the same space, worth naming so this survey is not mistaken for the whole picture:

- **工信部 (MIIT) AI Standardization Technical Committee** — sister apparatus, publishes the *工业和信息化领域人工智能安全治理标准体系建设指南*. Released July 2025 (final) with a seven-part framework: governance capability, infrastructure security, network security, data security, algorithm model security, application security, and application enablement security. Not TC260's committee; overlapping subject matter.
- **CAC** (中央网络安全和信息化委员会办公室 / Cyberspace Administration of China) — regulatory body, issues instruments like 《生成式人工智能服务管理暂行办法》 and 《生成合成内容标识办法》. The regulatory forcing function that TC260 standards are drafted to *operationalize*.
- **CAICT** (中国信息通信研究院 / China Academy of Information and Communications Technology) — MIIT-affiliated research institute; drafts most of the CAICT-hosted PDFs referenced in TC260 documents.
- **CACR** (中国密码学会 / Chinese Association for Cryptologic Research) — 密评联委会 published 《生成式人工智能系统密码应用指引》 v1.0 in August 2026 (already in the sweep log). Cryptographic architecture parallel track.

The corpus below is TC260's; the adjacent bodies are named so the reader knows which shoulder the standard is riding on.

---

## 2. Published standards — the flagship instruments already binding

### 2.1 生成式AI (Generative AI)

- **GB/T 45654-2025 网络安全技术 生成式人工智能服务 安全基本要求**
  *(Cybersecurity Technology — Basic Security Requirements for Generative AI Services)*
  - The graduated form of `TC260-003`. Registered under SAC/TC260; ICS 35.030 / CCSL 80.
  - Published 2025-05-23 (per the SAMR-cleared release copy at `content.mlex.com`), effective 2025-11.
  - The operative test for CAC's 《生成式人工智能服务管理暂行办法》 filing regime. Any generative-AI service delivered into the PRC market is measured against this instrument.
  - Contents at search-level only in this session. Full text should be read at the SAMR release copy.

### 2.2 AI 大模型 (Large Models)

- **GB/T 45288.1-2025 人工智能 大模型 第1部分：通用要求**
  *(AI — Large Models — Part 1: General Requirements)*
  - "Part 1" implies a multi-part instrument. Additional parts likely in the pipeline; not enumerated at primary in this session.
  - Published 2025 (specific date not confirmed at primary).

### 2.3 AI-generated content marking

- **GB 45438-2025 网络安全技术 人工智能生成合成内容标识方法**
  *(Cybersecurity Technology — Methods for Identifying AI-Generated Synthetic Content)*
  - **GB, not GB/T** — mandatory national standard. Rare in this space.
  - Implementation instrument for the CAC 《生成合成内容标识办法》 (regulation adopted 2025-03, effective 2025-09; already in the sweep log). Where the regulation says "content must be marked," this standard specifies *how*.
  - Not fetched at primary this session; content coverage rests on Chinese-language commentary.

### 2.4 智能体互联 (Agent Interconnection) — the flagship agent-era series

- **GB/Z 185.1-2026 through GB/Z 185.7-2026 人工智能 智能体互联** — seven-part guidance series covering, per the 2026-08-15 sweep entry and confirmed at `news.cn`: Overall Architecture / Identity Codes / Identity Management / Agent Description / Agent Discovery / Agent Interaction / (seventh part not disambiguated in searches this session).
  - Published 2026-06-26. Guidance track (GB/Z), not mandatory.
  - Already in log; enumerated here for corpus completeness.
  - The 08-18 correction (7 parts, not 8; the 8th row in 公告 2026 no. 22 was an unrelated musical-instruments standard) applies.
  - **This is the closest structural analog to ZP's own agent-identity work in the entire Chinese corpus.**

---

## 3. Technical Research Reports — where next vocabulary is set

Release event: **网安秘字〔2026〕34号**, 2026-04-03, one bundled RAR at `tc260.org.cn/sysFile/downloadFile/65a2ac0e14a140f68bb382b7a6e00b0c`. Five reports, three of which are directly on-lens:

- **TC260-TR-001-2026 《智能驾驶网络和数据安全标准化研究》** *(Autonomous Driving Network and Data Security Standardization Research)*
  - Adjacent-lens: autonomous driving = intense edge/embedded AI security posture, closest existing analog in the corpus to Sovereign-Form-on-embedded-hardware trust chain reasoning.

- **TC260-TR-002-2026 《6G网络内生及边界安全技术与标准化研究》** *(6G Network Intrinsic and Boundary Security Technology and Standardization Research)*
  - Off-lens for ZP directly, but worth naming for corpus completeness — the term "内生安全" (intrinsic security) is load-bearing across the Chinese apparatus and appears frequently in agent-security drafts.

- **TC260-TR-003-2026 《卫星通信网络安全标准化研究》** *(Satellite Communication Network Security Standardization Research)*
  - Off-lens for ZP.

- **TC260-TR-004-2026 《工业具身智能安全标准化研究》** *(Industrial Embodied Intelligent Agent Security Standardization Research)*
  - **On-lens.** Embodied AI safety — physical actuation, hardware trust boundaries, delegation to autonomous systems in industrial contexts. The nearest Chinese-apparatus companion to ZP's Substrate Form axis (Sovereign / Appliance / Companion) and the Observation Plane spec, at least in territory covered.
  - PDF v1.0-202603 mirrored at `pdf.dfcfw.com` (aggregator, not primary). Not read in full this session.

- **TC260-TR-005-2026 《智能体安全标准化研究》** *(Intelligent Agent Security Standardization Research)*
  - **The load-bearing item.** 92 pages. Systematically organizes agent definitions, classifications, application scenarios, security policies, risk taxonomy, and standard framework — "top-level guidance for China's intelligent agent security governance and standard development."
  - Five-dimension framework: 基础共性 (foundational commonality) / 安全管理 (security management) / 关键技术 (key technologies) / 测试评估 (testing evaluation) / 产品与应用 (products and applications).
  - **Eleven core security risks** enumerated in the report, per Sohu summary of the primary: agent hijacking (智能体挟持), data leakage and poisoning (数据泄露投毒), supply-chain poisoning (供应链投毒), identity spoofing (身份仿冒), hallucination diffusion (幻觉错误), multi-agent cascade failure (多智能体级联故障), plus five more not fully enumerated in current-session searches.
  - Risks characterized as showing "cross-module transmission, group-level amplification, and full-lifecycle circulation" (跨模块传导、全生命周期流转、群体效应放大).
  - Contents rest on Chinese-language commentary (Sohu, secrss). PDF not read at primary this session.

---

## 4. In-progress — where the wind is blowing next

Release event: **网安秘字〔2026〕44号**, 2026-04-16, "关于发布2026年度第二批网络安全国家标准需求的通知" *(Notice on the 2026 Second Batch of Cybersecurity National Standard Needs)*. The needs list is a PDF (附件1) at `tc260.org.cn/sysFile/downloadFile/ce31ca70f5d54633a94d53014466235a` — direct binary, not readable via `web_fetch` in this session. **Standing follow-up: this document has not been read at primary; the entries below rest on Chinese-language commentary and are search-level only.**

Purpose: to operationalize the four-agency 《加快推动人工智能百项国家标准建设专项行动计划》 (Accelerated Promotion of 100 AI National Standards Construction Special Action Plan) issued jointly by SAMR (市场监管总局) / CAC / MIIT (工信部) / National Data Administration (国家数据局). The **100-standard** framing is the load-bearing number — TC260 is executing against a numeric target from four state agencies acting in concert.

Standards under member solicitation, per search-level summaries:

- 《网络安全技术 人工智能模型开发安全指南》 *(AI Model Development Security Guide)*
- 《网络安全技术 人工智能训练及推理框架安全要求》 *(AI Training and Inference Framework Security Requirements)*
- 《网络安全技术 智算云服务安全评估方法》 *(Intelligent Compute Cloud Service Security Assessment Methods)*
- **《网络安全技术 端侧大模型网络安全指南》** *(On-Device Large Model Cybersecurity Guide)* — **directly on-lens for Sovereign Form**
- 《智能体应用安全基本要求》 *(Intelligent Agent Application Security Basic Requirements)* — the flagship agent-application standard, one tier down from the interconnection series
- Additional in-progress *智能体互联* series entries (Overall Architecture / Identity Codes / Identity Management / Agent Description / Agent Discovery / Agent Interaction) — these appear to be the standard-track continuation of what shipped as the GB/Z 185 guidance series

Application window closed 2026-05-06 17:00. Standards accepted into the batch will be drafted through 2026 with committee-review cadence.

Separately: **20263116-Q-252** — the mandatory (Q = 强制, mandatory-track) agent-security standard plan already covered in the 2026-08-15 sweep entry. Tracked here for corpus completeness.

---

## 5. Commonality with ZeroPoint — where the vocabulary aligns

Reading the TC260 corpus against KEEL 2026-07 and the elaborations indexed in `CANONICAL-CORPUS-INDEX-2026-07.md`:

**Agent identity and delegation as a primary primitive.** The GB/Z 185 series *Identity Codes* + *Identity Management* + *Agent Description* + *Agent Discovery* + *Agent Interaction* is a five-part breakdown that occupies the same territory as ZP's Genesis-rooted agent identity + delegation ceremony. Both apparatus arrive at the observation that agent identity must be *distinguishable*, *addressable*, and *interactable* — and both root the mechanism in cryptographic identifiers rather than deployment coordinates.

**Cascade risk as a first-class concern.** TR-005's "multi-agent cascade failure" (多智能体级联故障) and "group-level amplification" (群体效应放大) name the same phenomenon KEEL's coordination discipline (III.25, "octopus-shaped substrate") and the Circuit Breaker spec (broad revocation / asymmetric reset) are designed to bound. Both traditions treat cascade as a substrate-level risk rather than a per-agent one.

**Content-provenance marking as a substrate obligation.** GB 45438-2025 (mandatory) + CAC 《生成合成内容标识办法》 give China's marking-obligation regime the same load-bearing shape as EU AI Act Article 50 — machine-readable identification of AI-generated content, with the substrate responsible for producing it. The Chinese instrument is *mandatory* where the EU is *technology-neutral*; both push in the same direction. Substrate-level compliance work maps to both.

**Supply chain and hardware trust root.** TR-005's "supply-chain poisoning" (供应链投毒) is the same phenomenon that motivates the Quarantine Plane spec (delegable safety through admission ceremony) and Hardware Genesis. Chinese standard-track work here is dense; the parallel is direct.

**Testing and evaluation as a mandatory tier.** The five-dimension framework's 测试评估 (testing evaluation) dimension is the same structural position as ZP's empirical program discipline (EMPIRICAL-PROGRAM-2026-07) — verification of behavior against declared invariants, not as an afterthought but as a first-class layer.

---

## 6. Coherence — where the shape is compatible

**Layered instrument classes.** GB / GB/T / GB/Z / TC260-nnn / TR corresponds structurally to KEEL Layer A / Layer B / operational elaboration / research corpus (canonical index Tier 1 / Tier 2 / Tier 3). Both apparatus separate binding invariants from operational elaboration from working-vocabulary research, with declared bindingness for each tier. A ZP-authored instrument could be *positioned* against the TC260 layering without translation friction.

**Standard-first, then operationalization.** TC260's flow — regulation names an outcome → TC260 issues the operational standard → industry maps compliance to the standard — is the same shape as EU AI Act Article 50 → Commission Code of Practice → C2PA vocabulary. ZP operates one layer deeper (substrate-level primitives that any of these operational standards could be implemented against), but the layering is compatible.

**Working-group organization aligned with attack surface.** WG9 (AI Security Standards Working Group) constituted as an explicit AI-specific track, parallel to the existing cybersecurity WGs, mirrors the ZP officer-cadre design where distinct domains have distinct signing officers (Steward / Sentinel / Forge / Cleo / Aegis). Both apparatus recognize AI as requiring domain-specific expertise inside an existing security-standards frame, rather than as an extension of general cybersecurity.

**Bilateral posture on cross-organizational delegation.** GB/Z 185's *Agent Interconnection* framing acknowledges that agents will act across organizational boundaries and specifies the identity / description / discovery / interaction primitives required to make those actions verifiable. This is coherent with the WIMSE cross-org delegation direction the sweep log has been tracking (Reece / Rampalli / EMILIA / DRP / DAAP / AAT cluster), and coherent with ZP's peer-verification contract discipline. The three traditions (TC260 GB/Z 185, IETF WIMSE cross-org, ZP peer-verification) are working on the same problem and are reaching structurally compatible answers.

---

## 7. Contrast — where the shapes differ meaningfully

**Institutional trust root, not sovereign trust root.** TC260 assumes the *institutional* — regulator, licensed service provider, certified evaluator — is the ultimate anchor. GB 45438's marking obligation is filed *by the service provider* under the CAC filing regime; identity binding in GB/Z 185 is rooted in institutionally-issued identifiers (身份码). ZP's Genesis-rooted design puts the trust root at the *operator* — the individual sovereign — with institutional participation as delegated authority rather than as the anchor. This is the load-bearing contrast. **Any composition of ZP into a TC260-legible deployment would need to name explicitly whether the operator's Genesis root is exposed to the regulator's evaluator regime, or whether the regime terminates at an institutional layer sitting *above* the operator's substrate.**

**Compliance as first-class product feature, not sovereignty as first-class product feature.** TC260's mandatory-track (GB) instruments are compliance targets — an implementer's task is to satisfy the instrument. ZP's Layer A invariants are sovereignty targets — an implementer's task is to preserve the operator's authority against all pressures, including regulatory pressures. Both traditions produce structural discipline, but they optimize different objectives. Neither is wrong; they solve for different values.

**Observation surface bounded by delegation, not by regulation.** TC260's testing/evaluation framework assumes an *evaluator* can inspect the deployed system. ZP's observation plane bounds observation to delegation-authorized scope, with baseline scope being the substrate's own footprint. A TC260-certified deployment implies regulator-inspection reach; a ZP-Sovereign-Form deployment structurally denies it (per Substrate Form's trust-chain reach). The contrast is not academic — it determines what "compliant" can mean when both regimes touch the same system.

**Content-provenance shape.** GB 45438 marks the *content* with a service-provider-attested signature — the standard's identity-holder is the *service*, not the *creator*. C2PA's `c2pa.ai-disclosure` (per 2026-08-20 log entry) is *content-side* with model-provenance attestation. ZP's provenance model is *action-side* — signed receipts documenting the operator's action that produced the artifact. All three coexist in principle; a substrate that produces media for cross-jurisdiction distribution may need to emit all three. The shape contrast means "chain-anchored provenance" doesn't discharge either the C2PA or the GB 45438 obligation — it composes with them, but does not substitute.

**Cascade risk, differently bounded.** TR-005 treats cascade risk as a testing/evaluation target — measure it, bound it, certify. ZP's coordination discipline (III.25) and Circuit Breaker treat cascade risk as a *runtime* property to be prevented structurally, with chain-anchored evidence of every escalation. TC260 answers "how do we know cascade risk is bounded"; ZP answers "how does the substrate structurally prevent cascade in the first place." Different tiers of the same stack.

**Where "agent identity" lives.** GB/Z 185 identity is an *institutional issuance* — the 身份码 is granted by an issuing body under the standard's regime. ZP's agent identity is *derived from the operator's Genesis root* — the sovereign is the issuer, and any external body's role is downstream verification, not upstream grant. This is the same shape as the general institutional-root vs sovereign-root contrast, applied specifically to agent identity.

---

## 8. What TC260 has *not* named that ZP has

Worth surfacing so the ZP roadmap can position its distinct contributions cleanly:

- **Trust chain reach as an explicit design axis.** No TC260 instrument names the equivalent of Substrate Form's "how far does the operator's sovereign root reach into the trust stack" question. Chinese standards assume institutional trust chain by default.
- **Delegation ceremony as a chain-anchored append-only record.** GB/Z 185 covers identity + description + discovery + interaction, but the *authorization audit trail* is not itself specified as a substrate primitive. ZP's delegation-receipt discipline (P9, "the system acts; the operator signs") has no direct TC260 analog.
- **Cognitive / metacognitive plane.** TC260's five-dimension framework covers technology, testing, applications, management, and commonality — but the Regent's metacognitive substrate (Cognitive Input Plane, Cognitive Self-Observer, confabulation gap detection) has no analog in Chinese standard-track work as of 2026-08.
- **Coordination-not-oversight as first-class principle.** KEEL III.23 (coordination primitives that resist mutual-surveillance drift) has no TC260 equivalent; the Chinese apparatus assumes evaluator observation reach as a compliance property, which is a load-bearing contrast.
- **Aligned blindness.** KEEL III.24 (substrate structurally refuses certain observation classes) is definitionally at odds with a regulator-inspection frame. This is where the two traditions are furthest apart in principle.

---

## 9. Reading priority for the ZP roadmap

Ordered by lens-alignment and effort:

1. **TC260-TR-005-2026 《智能体安全标准化研究》** — full read at primary. Highest-value single document; the risk taxonomy alone will inform any ZP substrate-defense direction.
2. **GB/Z 185.1-2026 through GB/Z 185.7-2026** — the seven guidance parts, read as a set. Direct structural comparison against ZP's agent-identity primitives.
3. **GB/T 45654-2025** — the graduated `TC260-003`. What Chinese-market generative-AI compliance measures against.
4. **TC260-TR-004-2026 《工业具身智能安全标准化研究》** — embodied AI security; closest analog to Substrate Form embedded-hardware trust chain reasoning.
5. **2026年度第二批网络安全国家标准需求清单** (附件1 of 网安秘字〔2026〕44号) — the working needs list. **Requires operator supply of the PDF, per the CACR retrieval caveat pattern.** Once read, tells us what will be drafted through 2026 and thus what to align commentary vocabulary against.
6. **GB 45438-2025** — the mandatory AI-content marking standard. Compose with C2PA implementation guide (2026-08-20 log) for the full picture of marking obligations across jurisdictions.
7. **《工业和信息化领域人工智能安全治理标准体系建设指南（2025）》** — MIIT sister-track construction guide. Frames the seven-part governance system TC260 outputs will slot into.
8. **CAC 《智能体规范应用与创新发展实施意见》** (May 2026) — the regulatory forcing function under which the standards were drafted. Read to understand *why* each standard exists.

Standing follow-ups the sweep discipline should track:

- **`tc260.org.cn/portal/project/plan`** — the operator-named weather-report dashboard, added to `ai-landscape-sources.md` Candidate sources this cycle.
- **`tc260.org.cn/portal/suggestion`** — the standards-under-solicitation page (comment periods on draft instruments). The pre-issuance window; catches shape before publication.
- **`tc260.org.cn/portal/cms/work/10/2`** — the "通知公告" (notices/announcements) page — where release events like the two enumerated above land first.
- **Direct-download URLs at `tc260.org.cn/sysFile/downloadFile/...`** — binary attachments unreadable via `web_fetch` in this session. Same pattern as the CACR retrieval caveat: **ask operator to supply the file rather than burn a run retrying.**

---

## 10. What this survey is not

- **Not a compliance analysis.** The purpose is roadmap orientation, not preparation for a Chinese-market certification pass. Any actual compliance work needs a full read of the primary instruments and probably Chinese-language legal counsel.
- **Not a translation.** All quoted Chinese terms are transliterated / rendered with the source Chinese in parallel so future readers can chase the primaries. Where an English gloss is offered, it is annotative, not authoritative.
- **Not comprehensive.** The corpus is large and moving. This survey covers what was reachable via search and (where fetchable) primary in one Cowork session on 2026-08-20. Standing follow-ups above name the specific unread items; TR-005 and the second-batch needs list are the two most consequential gaps.
- **Not a decision.** Where the survey names commonality / coherence / contrast, it identifies structural relationships; it does not recommend which TC260 instruments ZP should compose with, decline to compose with, or position against. That is Ken's call, on which this survey provides the reading list.
