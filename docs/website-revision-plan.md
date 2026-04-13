# ZeroPoint Website Revision Plan

## Guiding Principle

The website speaks to people who don't yet know why they need ZeroPoint. The whitepaper convinces people who already know they need something. The book convinces people who want to understand deeply. Each layer serves a different reader at a different moment.

The theoretical foundation ("trust as trajectory") should be *felt* on the website before it is understood. The phrase should land before the explanation arrives.

---

## index.html

### Current State
- Hero: "Portable Trust for the Post-Platform Internet"
- Subtitle: "Cryptographic governance primitives that produce proof..."
- Strong existing structure with feature sections, code examples, governance display

### Proposed Changes

**Hero evolution** (keep the practical, add the depth):

```
Current:  Portable Trust for the Post-Platform Internet
Proposed: Trust Unfolds — Portable Infrastructure for the Agentic Age
```

Secondary line below hero:
> Trust is not a state to be checked. It is a trajectory to be verified.
> ZeroPoint makes trajectories portable, provable, and permanent.

**New section: "Why It Works" (after "What ZeroPoint Does", before integration patterns)**

A brief, visual section — three cards or columns:

1. **Every action becomes evidence.**
   Each receipt is signed, timestamped, and hash-linked to every receipt before it. Rewriting history means rewriting every step that follows.

2. **Authority narrows, never widens.**
   Delegation chains constrain themselves as they lengthen. Each link is narrower than the last. Coherent authority emerges from the trajectory.

3. **Founding commitments propagate.**
   Constitutional rules established at Genesis evaluate before every action, forever. The origin shapes everything that follows.

These three cards are the trajectory thesis compressed to three visual beats. No jargon. No "autoregressive." Just the structural truth.

**Updated tagline for footer / meta**:
"Trust is infrastructure. Trust unfolds."

---

## whitepaper.html

### Current State
- Rendered version of whitepaper v1.1 markdown
- Clean dark theme, monospace header, good typography

### Proposed Changes
- Full re-render from whitepaper-v2.md source
- New Table of Contents reflecting v2.0 sections
- New Appendix D (Trajectory Correspondence Table) rendered as a styled table
- Add anchor link from index.html "Read the whitepaper" to the new §1 ("Why It Works")
- Update version badge: v1.1 → v2.0, March 2026 → April 2026

---

## letter.html

### Current State
- Need to read current content to assess

### Proposed Direction
The letter should remain personal — Ken's voice, not technical prose. The trajectory thesis enters as discovery, not assertion:

"When I started building ZeroPoint, I knew trust needed to be portable. I knew receipts needed to chain. I knew authority needed to narrow as it delegated. What I didn't have was the language for *why* these patterns felt right — why they felt necessary rather than merely useful.

The language came from an unexpected direction. Researchers studying language models, cognition, and even physics are converging on the same computational pattern: the present carries the full weight of the past, and coherent futures emerge from locally conditioned steps. They call it autoregression. I call it trust as trajectory.

ZeroPoint didn't adopt this theory. It converged on it independently — because this is how trust actually works. Not as a score to be checked, but as a path to be walked and verified."

This framing is honest (the architecture came first), personal (Ken's perspective), and positions the theory as a deepening rather than a retrofit.

---

## New Page: /theory.html

### Purpose
A standalone, accessible treatment of the "trust as trajectory" argument. More accessible than the whitepaper, more focused than the book. For the reader who clicked through from a blog post or social media link and wants to understand the idea without reading 700 lines of technical specification.

### Structure
1. **The snapshot problem** (2 paragraphs) — Why current trust systems are fragile: they check state, not trajectory.
2. **Trust as trajectory** (3 paragraphs) — The core idea. Trust accumulates through sequential interaction. Remove the history and the trust evaporates. The history *is* the trust.
3. **The pattern** (3 paragraphs) — How this same structure appears in language, cognition, and (suggestively) physics. Not to borrow credibility, but to show that the pattern is recognized as fundamental.
4. **How ZeroPoint builds it** (3 paragraphs) — Genesis, chains, delegation narrowing, reputation accumulation. Concrete, grounded, no jargon.
5. **What it means** (2 paragraphs) — Portable, history-aware trust is the antidote to platform capture. Trust unfolds.

### Design
- Same dark theme as the rest of the site
- Single-column, long-form reading layout (like whitepaper.html)
- No code examples — this is the ideas page
- Link to whitepaper for technical depth, link to /playground for hands-on experience

---

## for-agents.html

### Proposed Update
- Add a "trust as trajectory" angle to the agent-specific pitch
- Agents need trajectory-based trust more than humans do, because agents operate at speed, without the implicit trajectory that human relationships build through years of interaction
- ZeroPoint gives agents an explicit trajectory: every action → receipt → chain → reputation
- "Your agent's reputation is not a score assigned by a platform. It is a chain of evidence that your agent carries with it."

---

## Substack / Blog Post (not a website page, but part of the rollout)

A post announcing the v2.0 whitepaper and the trajectory thesis. Title candidates:

1. "Trust Is Not a State — It's a Trajectory"
2. "Why Your Trust Infrastructure Is Fragile (And What to Do About It)"
3. "The Architecture That Builds Itself: How ZeroPoint Converged on a Fundamental Pattern"

The post should be ~1500 words, accessible, and drive traffic to the whitepaper and the new /theory.html page.

---

## Implementation Priority

1. **whitepaper.html** — Re-render from v2.0 source. This is the canonical document and should be first.
2. **index.html** — Hero update, new "Why It Works" section.
3. **theory.html** — New page. Can be written from whitepaper §1.
4. **letter.html** — Update with trajectory framing.
5. **for-agents.html** — Minor update.
6. **Substack post** — Write and publish after website updates are live.
