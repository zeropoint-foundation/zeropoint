# ZeroPoint Content Strategy — Building in Public

**Author:** Ken Romero, with synthesis assistance from Claude.
**Date:** 2026-04-21 (updated 2026-04-29).
**Status:** v2. Living document. Revise after 30 days based on what's working.

---

## The Thesis in One Paragraph

AI agents are making real decisions across trust boundaries, and every agent harness tracks what happened differently — but none of them can prove it. ZeroPoint is the open trust substrate beneath all of them: signed receipts, tamper-evident chains, cryptographic identity, capability delegation — the same governance primitives regardless of which harness produced the action. Ken Romero is building this largely alone, in real time, with full transparency about the thinking, the breakthroughs, and the evolution. The story is not "here is a product." The story is "here is a mind working on a problem that matters, and the problem is shaping the mind as much as the mind is shaping the solution." That recursive quality — the builder being changed by the build — is the narrative engine.

## The Positioning (see also: docs/POSITIONING.md)

**One-liner:** Open-source trust infrastructure for the agentic age.

**Tagline:** Trust shouldn't be a feature. It should be the substrate.

**The structural analogy:** JetBrains provides code intelligence as the substrate beneath any AI model. ZeroPoint provides trust infrastructure as the substrate beneath any agent harness.

**The anti-pattern:** We don't compete with agent harnesses. We don't lock anyone in. We don't ask you to bet your governance story on one vendor. We make every harness trustworthy — and when you switch (you will switch), the audit chain is continuous.

---

## Why Now

The agent governance space is about to get noisy. Every major lab and a dozen startups will announce "guardrails for agents" in 2026. Most of them will be policy layers, compliance dashboards, or contractual wrappers that depend on the agent cooperating. ZeroPoint is structurally different — governance enforced by the kernel, not by the agent's good behavior. The window to establish that distinction in people's minds is measured in months, not years.

The work is already deep enough to be compelling. 22 Rust crates, 700+ tests, a pentest that revealed real structural findings, a grammar formalism that makes trust decidable, a governed agent runtime spec that treats autoregression as a first-class computational principle. This is not vaporware looking for attention. This is running code looking for witnesses.

---

## The Voice

Technical depth with philosophical reach. The register sits somewhere between a senior architect's design doc and a builder's journal. It doesn't talk down. It doesn't hype. It shows the actual thinking — including the parts where the thinking changed direction.

**The JetBrains model.** In 2024, JetBrains tried to be your sole AI provider — their models, their subscription, their backend. It didn't work. The AI space moved too fast. Their recovery: reposition the IDE as an open platform, reject vendor lock-in, and be transparent about the misstep. The positioning landed because it didn't feel like selling. It felt like an engineer being honest. That's our tone.

Five qualities to maintain:

- **Precision over polish.** Say what you mean. Use the real vocabulary (autorecursive, constitutional invariant, grammar reframe). The audience worth having will rise to meet the language. The audience that needs buzzwords is not the audience that builds category-defining projects.

- **Honesty about uncertainty.** The calibrated-uncertainty section of the architecture doc is the model. "I'd take this bet at 4:1" is more compelling than "we are confident." Show the error bars. Show what would change your mind.

- **Honesty about what's built vs. what's roadmap.** Lead with what's working (fleet heartbeat, lease renewal, signed receipts, audit chain). Be clear about what's next (harness integrations, Hedera anchoring). Never oversell. The running code speaks first.

- **The personal stake.** You're not a corporation. You're a person who sees something others don't yet, building it because no one else will. That's not weakness — it's the thing that makes the story worth following.

- **The JetBrains-direct close.** End with an invitation, not a pitch. "Here's what we believe. Tell us if we're wrong." This is not a rhetorical move — it's a genuine request. If the primitives are wrong, we'd rather know now.

---

## The Intellectual Constellation

ZeroPoint did not emerge from a single discipline. It is the convergence of threads that span cryptography, linguistics, philosophy of mind, distributed systems, martial arts, and decades of building software. This section maps the influences — not as name-dropping, but because a project's intellectual lineage is part of its credibility and part of its story.

### The Foundation: US Navy Crypto-Linguist

The deepest influence is professional, not academic. Ken served as a cryptographic linguist in the US Navy — a discipline that trains you to find structure in signals, parse grammar under adversarial conditions, and understand that language is simultaneously a communication medium and an operational security surface. The difference between signal and noise is a formal property, not a judgment call. Trust in a communication system is either structural or it is nothing.

This is the origin of the grammar reframe. Trust-as-grammar, verification as re-derivation, failure as a parse error — these are not metaphors borrowed from computer science. They are the native frame of a crypto-linguist, applied to a new domain. The conviction that governance must be enforced by the kernel, not by the agent's cooperation, comes from the same source: you don't trust the channel, you trust the math.

### The Design and Development Career

The decades of work as a designer, developer, and programmer gave the builder's instinct — the ability to construct the thing, not just theorize it. The crypto-linguist background gave ZeroPoint its shape. The engineering career gave it substance. 22 Rust crates and 700+ tests do not emerge from a thesis alone.

### The Constellation

**Mark Qvist / Reticulum** — Sovereignty at the network layer. No DNS, no CA, no ISP dependency. The conviction that infrastructure should not require permission. Reticulum proved that you can build a serious communication system on cryptographic addressing alone, without any institutional trust anchor. ZeroPoint's mesh sovereignty plane (zp-mesh, zp-introduction) is a direct descendant. Qvist demonstrated that the "you need institutions" argument is an engineering failure, not a law of nature.

**Elan Barenholtz** — His theories on AI and the nature of language itself — the relationship between perception, cognition, and linguistic structure. This connects directly to the autoregression-as-universal-computational-principle thesis: the idea that autoregressive unfolding is not merely a language modeling technique but a fundamental mode of cognition. Language models did not invent autoregression; they stumbled into something that was already there. Barenholtz's work helped clarify why governing the reasoning chain matters — because the chain is the computation, not a record of it.

**Federico Faggin** — The inventor of the first commercial microprocessor, but more importantly his later philosophical work on consciousness: the thesis that subjective experience is fundamental rather than emergent, that computation has an interior that cannot be reduced to its inputs and outputs. This feeds the conviction that governing an agent's reasoning chain is not an engineering convenience but a philosophical necessity. If there is something it is like to be an autoregressive process, then the process itself — not just its side effects — falls within the scope of governance.

**Dr. Leemon Baird / Hedera** — The hashgraph consensus mechanism and, more specifically, Hedera's governance layer. Baird understood what most distributed systems projects do not: that a trustworthy system needs both a formally verifiable mechanism (the math) and a governance structure that constrains how the mechanism evolves over time (the council). The separation of consensus from governance, with neither subordinate to the other, is a pattern ZeroPoint inherits. The gossip-about-gossip protocol — metadata about information propagation as proof of consensus — has a structural echo in ZeroPoint's receipt chain, where the chain is the state, not a record of the state.

**Todd Blume** — A mentor, an old-school programmer from Santa Cruz whose father moved in circles that included Buckminster Fuller. Todd taught the apprenticeship way — not through papers or courses, but through working together extensively in Hawaii, showing what it looks like to think structurally about problems. Fuller's ghost is in ZeroPoint whether or not it is named: doing more with less, strength through the geometry of connections rather than material brute force, the idea that structure itself can be the solution. Tensegrity as an architectural principle. A trust substrate that derives its strength from the pattern of its construction — hash-linked, grammar-parsed, autorecursive — rather than from the authority of any institution.

**Nate B. Jones** — A programmer, commentator, and observer of the technology landscape (YouTube, Substack) whose daily observations and prognostications have been consistently accurate. Not a single breakthrough idea but a calibration source — someone whose read on the industry has proven reliable enough to trust as signal. In a field flooded with hype and narrative manipulation, a consistently accurate observer is a rare and valuable influence.

**Bruce Lee / Jeet Kune Do** — "Absorb what is useful, discard what is useless, add what is specifically your own." The system that refuses to be a system. No fixed form — only principles that survive contact with reality. The substrate that is never finished. ZeroPoint's Section 4a ("the substrate is never finished — and that is the design") is Jeet Kune Do applied to trust infrastructure. A finished grammar is a dead language. A finished martial art is a dead tradition. The project's autoregressive structure at the meta layer — architectural decisions conditioned on prior architectural decisions, conditioned on what running the prior decisions taught you — is the same principle Lee articulated: the style of no style, the form that absorbs what reality reveals about it.

### How the Threads Converge

The constellation is not random. Every influence contributes to one of three pillars:

**Trust must be structural, not institutional.** (Qvist, Baird, the Navy) — You cannot depend on cooperation. You cannot depend on institutions. You can depend on math, on grammar, on kernel-enforced boundaries.

**Computation has an interior that governance must reach.** (Faggin, Barenholtz, the autoregression thesis) — Governing side effects without governing the computation that produces them is like controlling file I/O without understanding process memory. The reasoning chain is the primary substrate.

**The system must absorb what reality reveals about it.** (Lee, Fuller via Blume, the grammar reframe) — No fixed form. No completion state. The loop closes repeatedly; it does not terminate. Structure is strength. Rigidity is death.

ZeroPoint sits at the intersection of all three.

---

## The Origin Story Post

The constellation above becomes a standalone piece — working title: **"The Shoulders I Stand On"** or **"Where This Comes From."** It maps the full intellectual lineage, tells the story of how the threads converged, and becomes a permanent reference point that other posts can link back to. Inserted into the publication sequence as Post 2 or 3, after the manifesto ("Trust Is Infrastructure") has established what ZeroPoint is.

---

## Channel Strategy

### Primary: Written Long-Form (Blog / Substack / Personal Site)

This is the anchor. Everything else derives from it.

**Why:** You think in prose. Your natural mode is the 1500-3000 word piece that takes one idea and follows it to its conclusion. The architecture doc, the whitepaper, the GAR spec — these are already essays. The blog is where they become public.

**Cadence:** One substantive post every 1-2 weeks. Not daily. Not forced. Each post should be something you'd want to read yourself.

**Platform options:**
- **Substack** — built-in audience discovery, email delivery, easy to start. Good for building a subscriber base from zero. Recommended starting point.
- **Personal site (thinkstreamlabs.ai/blog or kenromero.dev)** — full control, SEO ownership, professional presence. Build this in parallel but don't let it block publishing.
- **GitHub Pages / docs site** — lowest friction if you want to keep everything in the repo ecosystem.

Start with Substack. Migrate to owned infrastructure once the habit is established and the audience is growing.

### Secondary: Short-Form (X/Twitter + LinkedIn)

**Purpose:** Distribution and discovery. The long-form posts are the product; short-form is the storefront.

**X/Twitter:**
- Thread format: 5-8 tweets that distill one idea from a longer piece
- Build-in-public updates: screenshots of the dashboard, terminal output from a successful test, architecture diagrams
- Engage with the AI governance / AI safety / Rust / agent framework communities
- Cadence: 3-5 posts per week (including quote tweets, replies, short observations)

**LinkedIn:**
- Repurpose the professional/strategic angle of each blog post
- Target: enterprise security, compliance, CISO community
- Cadence: 1-2 posts per week

### Co-Primary: YouTube

YouTube is now a launch-alongside channel, not a Phase 2 afterthought. The format fits Ken's strengths: technical depth, honest narration, showing the actual system running. The JetBrains strategy video that influenced our positioning is proof of the format — honest, engineer-to-engineer, no hype, and it landed.

**Content tiers:**

- **Deep-dives (15-25 min):** Architecture decisions, the substrate thesis, live fleet demos, harness integration walkthroughs. "Why trust shouldn't be a feature." "How we govern agents without modifying the harness." These are evergreen discovery content — they compound.
- **Build-in-public updates (5-10 min):** What shipped this week, what broke, what changed. Screen recordings of the real system. Terminal output. Dashboard. The unpolished version — that's the point.
- **Short-form clips (60-90 sec):** Pull the sharpest insight from each long video. Distribute on YouTube Shorts, X, LinkedIn. The storefront for the deep-dives.

**First five videos (aligned with the release):**

1. "Trust Shouldn't Be a Feature" — the substrate thesis in 15 minutes. Adapted from the blog post (R7). The manifesto video.
2. "The Fleet Is Live" — screen recording of Sentinel heartbeat, lease renewal, cockpit dashboard. Show the running system. No slides — just the terminal and the dashboard.
3. "How ZeroPoint Works with Claude Code" — trace layer walkthrough. Install the MCP server, run a task, show the receipts. Concrete, hands-on.
4. "Building Alone: What It's Actually Like" — the personal piece. Food poisoning while deploying fleet delegation. Selling your car to keep going. The honest version.
5. "Why I Left the Walled Garden" — the JetBrains-inspired piece. Why open substrate beats vendor lock-in. Why agents kill the walled garden model. Why ZeroPoint bets on protocols, not platforms.

**Revenue potential:** YouTube Partner Program (1,000 subscribers + 4,000 watch hours), sponsorships from dev tool companies, GitHub Sponsors integration. Not the primary revenue path, but every dollar helps while grants and partnerships materialize.

**Cadence:** 1 deep-dive every 2 weeks, 1 build update weekly, short-form clips cut from both. Start with the release push — the first two videos can ship alongside the release.

### Tertiary: Podcast + Community

- **Podcast guest appearances:** AI governance, Rust, indie hacker, startup podcasts. You have a unique story. Podcast hosts love guests who've actually built the thing. Pursue actively once the first 3-5 YouTube videos establish the talking points.
- **Discord or GitHub Discussions:** A place for people who find the content and want to go deeper. Don't launch this until there are at least 50-100 engaged viewers/readers. A ghost town is worse than no community.
- **Office hours:** Monthly open call where anyone can ask about ZeroPoint, agent governance, or the architecture. Low effort, high signal. Start after the YouTube channel has traction.

---

## The First Eleven Posts

These are ordered to build the narrative arc: start with the thesis, establish the lineage, show the work, reveal the journey, then point forward. Each title is a working draft.

### 1. "Trust Shouldn't Be a Feature"
The manifesto. Why trust infrastructure can't be owned by one harness vendor. Why the receipt chain survives switching agents. Why "developer accountability" needs cryptographic backing. Not a product announcement — a statement of belief. Draw the line between proprietary observability and cryptographic provenance: LangSmith tells you what happened, ZeroPoint proves what happened. End with the JetBrains-direct close: here's what we believe, tell us if we're wrong. *Also the script for YouTube video #1.*

### 2. "Where This Comes From"
The intellectual constellation piece. The Navy crypto-linguist background (woven in naturally, not leading). The influences — Qvist, Barenholtz, Faggin, Baird, Blume, Lee, Jones. How the threads converge on three pillars. This post establishes that ZeroPoint has roots, that it draws from a genuine intellectual lineage, and that the architecture reflects decades of cross-disciplinary thinking — not a weekend hackathon.

### 3. "The Pentest That Changed Everything"
The story of the April 2026 black-box pentest. Shannon found 20 findings. The structural insight wasn't the shell injection — it was that the gate was optional. "Actuality outrunning the grammar." How a security test became an architectural revelation.

### 4. "Why a Grammar, Not a System"
The trust-as-grammar reframe. Verification is re-derivation, not checking. Failure is meaningful, not just bad. The substrate is never finished. This is the intellectual core of ZeroPoint, explained for an audience that hasn't read the architecture doc.

### 5. "Autoregression Is Not Just for Language Models"
The philosophical piece. Autoregression as a universal computational principle — alongside recursion, iteration, and reduction. Why this reframes everything from agent governance to cognitive accountability. This is the post that establishes you as someone thinking at a different level than the "AI safety" crowd.

### 6. "Building Alone: What It's Actually Like"
The personal piece. Working in isolation. The moments of doubt. The moments of conviction. The strange experience of building something you believe is important while nobody's watching. This is the post that makes people root for you.

### 7. "Nobody Puts ZP in the Corner: How We Govern Hermes"
The GAR story. Hermes Agent has 106K GitHub stars. It's the leading edge of persistent agent capability. Here's how ZeroPoint wraps it, contains it, and constitutionalizes it — without replacing what it's good at. Technical enough to be credible, narrative enough to be shareable.

### 8. "The Abacus: How We Track Trust"
The canonicalization framework — the abacus metaphor, wires and beads, chain-only derivation. A concrete, visual explanation of how ZeroPoint's audit chain works in practice. Screenshots of `zp status`. This is the "show, don't tell" post.

### 9. "What I Got Wrong (And What That Taught Me)"
Pick 2-3 architectural decisions that changed. The move from .env files to vault. The realization that preflight JSON was a crutch. The evolution from "audit log with policy" to "grammar with productions." Show the thinking changing in real time.

### 10. "The Cognitive Accountability Layer (And Why It Has to Wait)"
The vision piece. LARQL, MEDS, reasoning fingerprints, the confabulation gap. What it would mean to have an IDE for minds. Why you deliberately parked it until the foundation is solid. This post says: the vision is bigger than what you see, and I'm disciplined enough not to chase it prematurely.

### 11. "X3: The Hardest Open Problem in Agent Governance"
Sequence-level constitutional compliance. Why individual actions can be fine but trajectories can be dangerous. Why this is the property that separates ZeroPoint from "a better audit log." Frame it as an invitation — this is an open research problem, and the field needs it solved.

---

## Content Production Workflow

Each post follows this cycle:

1. **Seed:** Identify the idea (usually something that happened in the build process — a breakthrough, a decision, a realization).
2. **Draft:** Write the first pass. Aim for 1500-3000 words. Don't self-edit while drafting.
3. **Refine:** Cut 20%. Sharpen the opening. Make sure the closing lands. Check that every paragraph earns its place.
4. **Extract short-form:** Pull 2-3 tweetable insights and one LinkedIn-ready paragraph from the draft.
5. **Publish:** Post the long-form. Schedule the short-form for the following 2-3 days.
6. **Engage:** Respond to comments. Follow people who engage thoughtfully. Build the graph.

Time budget: ~4-6 hours per post cycle (including short-form extraction). At biweekly cadence, that's 2-3 hours per week.

---

## Metrics That Matter (and Ones That Don't)

**Track:**
- Subscriber count (Substack + YouTube) — the core leading indicators
- YouTube watch hours and retention — are people staying for the depth?
- Email open rate — are readers actually reading?
- Replies and thoughtful comments — signal of depth of engagement
- Inbound messages (DMs, emails from people who found you through the content)
- GitHub stars / traffic correlated with content timing
- Donation/sponsorship revenue (GitHub Sponsors, Open Collective, YouTube)
- Grant application status and pipeline

**Ignore (for now):**
- Total impressions / views — vanity at this stage
- Follower count on X — lagging indicator, easily gamed
- Likes without comments — shallow engagement

**6-month targets (calibrated, not aspirational):**
- 500+ Substack subscribers
- 1,000+ YouTube subscribers (Partner Program threshold)
- 4,000+ YouTube watch hours (Partner Program threshold)
- Hedera grant submitted and in review
- 1+ additional grant applications submitted (AI safety, open-source infrastructure)
- Donation infrastructure live and generating any amount of recurring revenue
- 3-5 podcast guest appearances
- 1-2 inbound conversations with potential strategic partners or design partnership clients
- A recognizable name in the AI governance / trust infrastructure conversation
- GitHub stars tracking upward in correlation with content

---

## What Makes This Different From Every Other "Build in Public" Strategy

Most build-in-public content is about startups, products, and metrics. Yours is about ideas. The differentiator is not "I'm building a thing" — it's "I'm thinking through a problem that the entire field is going to hit, and I'm showing my work." The audience isn't just people who might use ZeroPoint. It's people who care about the question: *how do we make autonomous AI systems trustworthy at a structural level?*

That question has no shortage of interested parties — researchers, engineers, policymakers, investors, founders building agent frameworks who know their governance story is weak. You don't need to find your audience. You need to make yourself findable by the audience that already exists.

The writing does that. The transparency does that. The running code does that.

Start with Post 1. Publish it this week.

---

*This document is autorecursive: it will be revised based on what the first 30 days of publishing reveal about what resonates, what doesn't, and what the audience is actually hungry for.*
