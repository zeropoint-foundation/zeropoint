# ZeroPoint v2: Launch and Go-to-Market Strategy

*Prepared February 2026 for ThinkStream Labs*

---

## Executive Summary

ZeroPoint v2 is a Rust framework providing cryptographic governance primitives for any system where actions have consequences — with autonomous AI agents as the most urgent application. The project is technically complete (623 tests, 11 crates, 6 phases delivered) and ready for public release. This document outlines a launch strategy that accounts for the current AI governance landscape, the Reticulum community's transition period, competitive positioning, and the political risks of operating in the AI safety space.

The core recommendation is a phased launch: seed the Reticulum community first (where the technical foundation creates natural credibility), then expand into the AI governance space (where the timing is favorable), and build toward commercial sustainability through consulting and enterprise features.

---

## Part I: The Landscape — What You're Walking Into

### 1.1 The AI Governance Space Is Hot and Crowded

The agentic AI governance space exploded in late 2025 and early 2026. Singapore launched the world's first Model AI Governance Framework for Agentic AI at Davos in January 2026. The Cloud Security Alliance published an Agentic Trust Framework. OWASP has an active Gen AI Security Project. Enterprise players (Palo Alto Networks, Cisco, various GRC vendors) are all publishing frameworks and tools.

Most of this is top-down: compliance checklists, risk management frameworks, enterprise dashboards. Very little of it is protocol-level. Almost none of it is open source infrastructure that developers actually build with.

**ZeroPoint's differentiation**: It's not a governance framework you comply with — it's a governance protocol you build on. The distinction matters. NIST AI RMF tells you what to do. ZeroPoint gives you the cryptographic primitives to do it.

### 1.2 The Reticulum Community Is in Transition

Mark Qvist stepped back from public engagement with Reticulum in December 2025, after releasing RNS 1.0.0 in Fall 2025. At FOSDEM 2026, the community held sessions titled "Reticulum: What's Next? Building the Future After the Founder Steps Back" — with live interoperability testing between the Python reference implementation, a Rust rnsd daemon, RetiNet (an AGPL fork), and other implementations.

The community is actively figuring out coordination without upstream. They're discussing protocol specification, documentation gaps, embedded device support, and governance of the project itself.

**What this means for you**: The Reticulum community needs contributors, especially ones bringing Rust implementations and new use cases. ZeroPoint is both — a Rust-native mesh transport layer and a novel application (AI agent governance) that extends Reticulum's reach. The timing is unusually good for making contact.

**What to be careful about**: The community is protective of Mark's vision. ZeroPoint must be presented as building *on* Reticulum, not *replacing* or *forking* it. The philosophical alignment (Harm Principle, sovereignty, no central authority) is genuine and should be emphasized.

### 1.3 The "Palantir for Everyone" Problem Is Real

As the WorldView project demonstrates, single developers can now build intelligence-grade data fusion tools in days using AI coding agents. This capability is spreading faster than any governance framework can respond. Governments are aware of this — the Atlantic Council's 2026 AI geopolitics report explicitly discusses the diffusion of AI capabilities beyond state control.

**ZeroPoint's position**: You are not trying to prevent this. You are building the accountability infrastructure that makes it auditable. This is a critical framing distinction. "We stop bad things" is a losing pitch in the open-source world. "We make actions provable" is an engineering proposition that developers can respect.

### 1.4 Licensing and IP Considerations

ZeroPoint is currently dual-licensed MIT/Apache-2.0, which is the Rust ecosystem standard. This is the right choice for maximum adoption. It means anyone can use ZeroPoint in proprietary products without contributing back.

If you want a commercial path, the standard approach is open-core: the protocol and core crates remain MIT/Apache-2.0, while enterprise features (hosted mesh infrastructure, management dashboards, compliance reporting, SLA-backed support) are proprietary under ThinkStream Labs.

**Do not change the license later.** Relicensing after building community trust is one of the most damaging things an open-source project can do. Decide your licensing strategy before launch and commit to it publicly.

---

## Part II: Strategic Risks — What Can Hurt You

### 2.1 Co-option by Surveillance Interests

The biggest political risk: ZeroPoint's architecture — cryptographic identity, audit trails, capability tracking — is exactly what surveillance states want. The same protocol that proves "this agent acted with authorization" can prove "this person authorized this action." Immutable audit trails are accountability tools for the governed and surveillance tools for the governors.

**Mitigation**: The Tenets are your defense. Tenet I (Do No Harm) and the HarmPrincipleRule being constitutionally non-removable isn't just philosophy — it's a technical safeguard that's embedded in the protocol. Emphasize this in all public communications. The fact that constitutional rules cannot be overridden by any operator, policy, or consensus vote is what distinguishes ZeroPoint from a generic audit framework.

**Practical step**: Consider adding a "Use Restrictions" section to the license or a separate ETHICS.md that, while not legally binding under MIT/Apache-2.0, makes the project's values explicit. Some projects (e.g., the Hippocratic License) have explored this. You don't need to adopt a restrictive license, but you should have a public, signed statement of intent.

### 2.2 Being Dismissed as "Security Theater"

The AI safety community has a faction that views open-source governance tools as performative — "checkbox safety" that creates an illusion of control without actually constraining powerful systems. If ZeroPoint is perceived as a rubber stamp that lets developers claim "we have governance" without meaningfully limiting agent behavior, it loses credibility fast.

**Mitigation**: Publish concrete threat models. Show what ZeroPoint prevents and, critically, what it doesn't prevent. The honest conversation we had about WorldView — that ZeroPoint doesn't solve the "Palantir for everyone" problem, it changes the terms — is the right tone. Honesty about limitations builds more credibility than overclaiming.

### 2.3 Reticulum Community Rejection

If the Reticulum community perceives ZeroPoint as appropriating their work, branding their protocol, or dragging their mesh network into AI hype, the backlash would be severe and difficult to recover from.

**Mitigation**: First contact matters enormously. Before any public launch, reach out to key Reticulum community members privately. Show them the code. Show them the interoperability tests. Show them the governance.md acknowledgments. Ask for feedback, not permission — but genuinely incorporate it. Do not announce ZeroPoint publicly without having had this conversation first.

### 2.4 Premature Enterprise Interest

Large companies may express interest in ZeroPoint for compliance purposes before the project has community credibility. Taking enterprise money too early — especially from defense or surveillance-adjacent companies — can permanently brand the project and alienate the developer community you need.

**Mitigation**: Be selective about early partnerships. The first few adopters define the project's identity. Prioritize use cases that align with the Tenets: humanitarian tech, journalism, privacy-preserving AI, decentralized infrastructure. You can pursue enterprise later from a position of community strength.

### 2.5 Regulatory Capture

Governments are actively seeking AI governance standards. If ZeroPoint gains traction, there will be pressure to align with specific regulatory frameworks (EU AI Act, Singapore MGF, NIST AI RMF). Each alignment is a political act — it positions ZeroPoint within a specific jurisdiction's power structure.

**Mitigation**: Stay protocol-level, not compliance-level. ZeroPoint provides the cryptographic primitives; compliance frameworks are built on top by others. If someone wants to build "ZeroPoint for EU AI Act compliance," that's a product built on the protocol, not a change to the protocol itself.

---

## Part III: Launch Sequence

### Phase 1: Reticulum Community (Weeks 1-4)

**Objective**: Establish ZeroPoint as a legitimate member of the Reticulum ecosystem before any public announcement.

**Actions:**

1. **Reach out to the Reticulum community privately.** The FOSDEM 2026 organizers (Liam and others leading the community transition) are the right first contacts. Share the GitHub repo (private or unlisted), emphasize the wire compatibility, and ask for feedback on the transport layer implementation. Frame it as: "We built a Rust-native mesh transport for AI agent governance that's wire-compatible with Reticulum. We'd like your feedback before we release it publicly."

2. **Contribute upstream.** If there are documentation gaps, interoperability issues, or protocol specification work the Reticulum community needs, contribute to those first. Becoming a known contributor before announcing your own project builds trust that no amount of marketing can replicate.

3. **Run interoperability tests.** You have NomadNet and MeshChat installed. Run actual packet exchanges between ZeroPoint's TCP interface and Reticulum's TCP transport. Document the results. If there are compatibility issues, fix them and contribute the fixes. If it works cleanly, that's your proof of legitimacy.

4. **Prepare the GitHub repository.** Before going public: clean up commit history if needed, ensure all READMEs are accurate (done), add CONTRIBUTING.md, CODE_OF_CONDUCT.md, and a SECURITY.md for vulnerability reporting. Add GitHub issue templates (bug report, feature request, question).

### Phase 2: Quiet Public Release (Weeks 4-8)

**Objective**: Make ZeroPoint publicly available without fanfare. Let the code speak first.

**Actions:**

1. **Make the repository public.** No press release, no blog post, no Twitter thread. Just flip the visibility. The Reticulum community members you've already contacted will be the first to see it.

2. **Write one technical blog post.** Not a manifesto — a technical walkthrough. "Building a governed AI agent mesh in Rust" or similar. Show code, show the architecture, show the test results. Post it to your personal blog or ThinkStream Labs site. Share it in Reticulum community channels and on Hacker News.

3. **Publish on crates.io.** Make each crate installable via `cargo add`. This is the Rust ecosystem's trust signal — if your crates compile cleanly, have good docs, and pass CI, Rust developers will take you seriously.

4. **Set up CI/CD.** GitHub Actions for `cargo test --workspace`, `cargo clippy`, `cargo fmt --check`, and ideally `cargo doc`. A green badge on the README is worth more than any marketing copy.

### Phase 3: Community Building (Weeks 8-16)

**Objective**: Build the first ring of contributors and users beyond the Reticulum community.

**Actions:**

1. **Engage with the AI agent governance conversation.** The Singapore MGF, the CSA Agentic Trust Framework, and OWASP Gen AI Security Project are all active communities. ZeroPoint's protocol-level approach is distinct from their framework-level approach — position it as complementary infrastructure, not competition.

2. **Submit to relevant conferences.** FOSDEM 2027 CFP (especially the Decentralized Internet devroom), RustConf, AI safety workshops, and privacy/security conferences. The talk should be technical, not promotional. Show the architecture, the Reticulum compatibility, and the threat model.

3. **Create example applications.** A minimal "two agents exchanging governed receipts over TCP" example. A "policy-gated data pipeline" example. A "multi-agent delegation chain" example. Developers adopt through examples, not documentation.

4. **Discord or Matrix server.** One communication channel, not many. Matrix aligns better with the decentralization ethos and the Reticulum community's values.

### Phase 4: Partnerships and Sustainability (Months 4-12)

**Objective**: Establish revenue paths without compromising the open-source core.

**Actions:**

1. **Consulting.** ThinkStream Labs offers integration consulting for organizations that want to add ZeroPoint governance to their AI agent systems. This is the fastest path to revenue and doesn't require any proprietary code.

2. **Hosted mesh infrastructure.** Run Reticulum transport nodes and ZeroPoint mesh infrastructure as a service. Organizations that want governed agent communication without running their own mesh can subscribe. This is analogous to how companies pay for hosted Kubernetes even though Kubernetes is open source.

3. **Enterprise features (open-core).** Compliance reporting dashboards, managed policy module distribution, SLA-backed support, and advanced monitoring. These are proprietary products built on the open protocol.

4. **Grants.** The Rust Foundation, NLnet Foundation, Open Technology Fund, and similar organizations fund open-source infrastructure projects. ZeroPoint's alignment with privacy, decentralization, and AI safety makes it a strong candidate.

---

## Part IV: Messaging — How to Talk About ZeroPoint

### What to say

- "Cryptographic accountability for systems that matter" — this is the broadest one-line pitch
- "Cryptographic accountability for agents, humans, and everything in between" — the participant-agnostic pitch
- "Every action produces a verifiable receipt. Every receipt joins an immutable chain. The chain is the truth."
- "The protocol doesn't care who holds the keypair — human, agent, service, or device. The cryptographic guarantees are the same."
- "Agents are the most urgent application. But the primitives serve everyone."
- "ZeroPoint doesn't prevent misuse — it makes actions provable and participants refusable."
- "Built on Reticulum. Wire-compatible. Sovereign by design."

### What not to say

- Don't claim ZeroPoint "solves" AI safety. It doesn't. It provides infrastructure for accountability.
- Don't compare to Palantir, even as aspiration. The association is toxic for the communities you need.
- Don't pitch governance as a feature. Pitch it as infrastructure that enables trust between participants — agents, humans, and services — from different operators.
- Don't frame it as agent-only. The primitives are participant-agnostic by design. Narrowing the pitch to agents alone leaves half the value on the table.
- Don't use the word "compliance" in early messaging. It attracts enterprise buyers but repels developer communities.
- Don't claim Reticulum endorsement unless it's explicitly given. Say "built on" and "compatible with."

### Tone

The governance.md you've already written has exactly the right tone: technically precise, philosophically grounded, honest about limitations, and unapologetically principled. Your public communications should match it. Let the Tenets speak. Let the code speak. Resist the urge to hype.

---

## Part V: Key Relationships to Build

### Tier 1: Build these first

- **Reticulum community leadership.** Whoever is coordinating post-Mark-Qvist. Essential for legitimacy.
- **Rust ecosystem maintainers.** Visibility on crates.io, presence in Rust community spaces.
- **Privacy/decentralization communities.** EFF, Tor Project, Matrix.org, Signal adjacent developers. Natural philosophical allies.

### Tier 2: Build these next

- **AI safety researchers.** Academic groups working on agent alignment, multi-agent safety, and AI governance (not the policy/think-tank layer — the technical layer).
- **Humanitarian technology organizations.** Groups using technology for crisis response, journalism, human rights monitoring. These are the use cases that prove the Tenets aren't just words.
- **Open-source AI projects.** Projects like Ollama, LangChain, CrewAI that are building multi-agent systems and need governance infrastructure.

### Tier 3: Approach carefully

- **Enterprise/defense.** Not inherently bad partners, but each one defines your brand. Choose carefully and ensure alignment with the Tenets before engaging.
- **Government bodies.** Regulatory alignment is valuable but comes with political entanglement. Contribute to standards processes; don't become captured by them.
- **VC/investors.** Funding enables scale but investors have expectations about growth and control. If you raise, raise from aligned sources (climate tech, privacy, decentralization-focused funds).

---

## Part VI: Timeline Summary

| Timeframe | Milestone |
|-----------|-----------|
| **Week 1-2** | Private outreach to Reticulum community; interop testing |
| **Week 2-4** | Contribute upstream; prepare GitHub repo (CONTRIBUTING.md, CI, issue templates) |
| **Week 4** | Make repository public (quiet release) |
| **Week 5-6** | Publish crates to crates.io; one technical blog post |
| **Week 6-8** | Share in Reticulum, Rust, and AI safety channels; Hacker News |
| **Month 3-4** | Conference submissions; example applications; Matrix/Discord server |
| **Month 4-6** | First external contributors; consulting engagements; grant applications |
| **Month 6-12** | Partnership development; hosted infrastructure; enterprise features scoped |

---

## Part VII: What Could Go Wrong

Honest assessment of failure modes, ordered by likelihood:

1. **Nobody cares.** The most common outcome for any open-source project. Mitigated by community-first launch (Reticulum) rather than broadcast launch.

2. **Reticulum community pushback.** If first contact goes badly. Mitigated by genuine contribution, not just self-promotion.

3. **Co-option by bad actors.** MIT/Apache-2.0 means you can't prevent this legally. Mitigated by strong community norms, ETHICS.md, and the constitutional rules in the protocol itself.

4. **Competitor with more resources.** A well-funded startup or big company launches a similar framework. Mitigated by protocol-level design (harder to replicate than an application) and Reticulum compatibility (unique positioning).

5. **Burnout.** Solo maintainer risk. Mitigated by building community contributors early and keeping scope focused on the core protocol.

---

## Closing

The hardest part of launching ZeroPoint isn't technical — the code is solid, the tests pass, and the architecture is sound. The hard part is navigating a political landscape where AI governance is contested territory, open-source communities are protective of their values, and the line between accountability infrastructure and surveillance infrastructure is determined by intent, not architecture.

Your advantage is that ZeroPoint's values are genuine — they're embedded in the protocol, not bolted on as marketing. The Tenets aren't aspirational; they're enforced by constitutional rules in the code. That's rare in this space and it's your strongest credential.

Lead with the code. Lead with the community. Lead with honesty about what ZeroPoint does and doesn't do. The rest follows.
