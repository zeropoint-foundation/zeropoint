# ZeroPoint — Animated Explainer Storyboard & Script

**Duration:** 2:20 | **Format:** Animated motion graphics | **Audience:** Builders + decision-makers

---

## Creative Direction

**Tone:** Confident, understated, technical but accessible. Think Stripe or Linear — letting the ideas speak without hype. Dark backgrounds, clean typography, minimal animation that serves comprehension.

**Visual Language:** Dark theme (#0A0A0C background) matching the ZeroPoint site. Accent blue (#7EB8DA) for emphasis. Green (#4ADE80) for allow/valid, red (#F87171) for block/tamper. Monospace for hashes and code. Thin geometric lines connecting nodes. Flat, precise, structural.

**Typography:** Inter for body text, JetBrains Mono for technical elements. Large, readable type. Let text breathe.

**Music:** Ambient electronic — minimal, building tension through the problem statement, resolving into clarity through the solution. No drums until the governance gate reveal. Subtle pulse underneath.

---

## Scene 1: THE PROBLEM (0:00 – 0:20)

### Narration
AI agents are no longer just answering questions. They're booking flights. Moving money. Writing code that ships to production.

And right now, there's no way to prove what they did, whether they were authorized to do it, or who's accountable when something goes wrong.

Trust today depends on platforms. On central authorities. On hoping the system works.

### Visuals
Open on dark void. Small points of light appear — each one an agent. Agents start moving: lines extend from them showing actions (booking, transferring, deploying). Lines become tangled, overlapping. No structure. A red pulse ripples through — something went wrong. But which agent? Which action? No way to tell. Text fades in: "No proof. No accountability. No trust."

### Motion Notes
Agents appear as small circles with radiating action lines. Motion is chaotic, organic. The red pulse should feel unsettling but subtle — not alarmist.

### Asset: `scene-01-problem.svg`

---

## Scene 2: THE THESIS (0:20 – 0:35)

### Narration
ZeroPoint is portable trust infrastructure. Cryptographic primitives that make every action provable, every authority traceable, and every exit real.

No platform required. No central authority.

Your keys. Your chain. Your trust.

### Visuals
The chaos freezes. A clean geometric frame draws itself around the scene. The ZeroPoint wordmark appears center-screen. Below it, three words materialize one at a time: PROVABLE · TRACEABLE · AUDITABLE. The tagline lands: "Your keys. Your chain. Your trust."

### Motion Notes
The transition from chaos to order is the key moment. The frame should feel like structure being imposed — clean lines appearing, the noise resolving into geometry.

### Asset: `scene-02-thesis.svg`

---

## Scene 3: THE TENETS (0:35 – 1:00)

### Narration
ZeroPoint is built on four constitutional commitments. They're embedded in the protocol. They cannot be removed. Ever.

One: Do no harm. The system will not operate in services designed to harm humans.

Two: Sovereignty is sacred. Every participant has the right to refuse. Coercion is architecturally impossible.

Three: Action without evidence is no action. Every action produces a receipt. Every receipt joins a chain.

Four: The human is the root. Every delegation chain terminates at a human-held key. No agent may self-authorize.

### Visuals
Four pillars rise from the baseline, evenly spaced. Each pillar illuminates as its tenet is read. Roman numerals appear: I, II, III, IV.

- Tenet I: A shield icon. Brief flash of harmful keywords being rejected.
- Tenet II: Two nodes — one refuses a request. The refusal is honored. No override.
- Tenet III: A chain link forms. Then another. Each action adds a link.
- Tenet IV: At the base of a tree of nodes, a human silhouette holds the root key.

### Motion Notes
Pillars should feel monumental but minimal. Each one lights up with the accent blue. The transitions between tenets should be smooth cross-fades, not cuts.

### Asset: `scene-03-tenets.svg`

---

## Scene 4: THE GATE (1:00 – 1:30)

### Narration
Every action passes through the Governance Gate. Three stages. No exceptions.

Guard: the sovereign boundary check. Before any action, locally, without consulting external authority — the participant asks: may I?

Policy: composable rules evaluated in real time. Constitutional rules load first and cannot be overridden. The most restrictive decision wins.

Audit: every outcome joins a hash-chained record. Tamper-evident. Cryptographically signed. If it's not in the chain, it didn't happen.

### Visuals
A horizontal pipeline appears: three stages connected by arrows. **GUARD → POLICY → AUDIT**

An action (glowing orb) enters from the left.
- Guard stage: the orb passes through a gate. A green checkmark appears.
- Policy stage: rule labels stack up (HarmPrinciple, Sovereignty, Catastrophic). The orb is evaluated. Decision badge appears: ALLOW / BLOCK / REVIEW.
- Audit stage: the orb transforms into a chain link, snapping onto the end of a growing chain. A hash appears briefly.

Show a second action that gets **BLOCKED** — it stops at Policy, turns red, and still produces an audit entry.

### Motion Notes
The pipeline should feel mechanical and inevitable. The blocked action is important — it shows that even denied actions are recorded. The chain growing link by link should feel satisfying.

### Asset: `scene-04-gate.svg`

---

## Scene 5: THE CHAIN (1:30 – 1:50)

### Narration
Trust flows from human to agent through delegation chains.

A human holds a root key. They grant a capability to an agent: read this data, execute within this scope, for this duration.

That agent can delegate further — but never more than it was granted. The chain narrows at every link. Scope, depth, time — all constrained.

And if any link is tampered with? The chain breaks. Cryptographically. Detectably.

### Visuals
A human silhouette at the top of the screen, holding a key icon. A line extends down to Agent A. A capability badge appears: "Read: data/*"

Agent A delegates to Agent B. The badge narrows: "Read: data/public"

Agent B tries to delegate "Write" — rejected. A red X. Scope exceeded.

Pull back to show the full chain. One link glitches — turns red. "Chain Tampered" label appears. The break is instantly visible.

### Motion Notes
The delegation tree should grow downward like a family tree. The narrowing scope is key — visually show the capability badge getting smaller/more specific at each level. The tamper detection should be dramatic but brief.

### Asset: `scene-05-chain.svg`

---

## Scene 6: THE VISION (1:50 – 2:10)

### Narration
This is the infrastructure for the agentic internet.

Agents operating over any transport — HTTP, mesh radio, encrypted links. Identity is a keypair. Authentication is a signature.

The same protocol that runs over fiber at a gigabit runs over LoRa at 300 baud.

Agents, humans, and services are all first-class peers. Not distinguished by type — only by their cryptographic chain.

No central coordinator. Consensus happens peer-to-peer, through receipt exchange.

### Visuals
The view pulls back dramatically. Dozens of nodes appear — agents, humans, services — all connected by thin lines. Some links are labeled: HTTP, Mesh, LoRa. All carry the same protocol.

Zoom into a cluster: agents exchanging receipts. Chains being verified. Reputation scores adjusting.

The network pulses with activity but it's ordered, structured. Every action has proof.

Coverage badges appear briefly: NIST AI RMF, OWASP Top 10, MITRE ATLAS — fading in and out.

### Motion Notes
This is the big-picture moment. The network should feel alive but governed. The transport labels reinforce that this works everywhere. The framework badges add credibility without lingering.

### Asset: `scene-06-vision.svg`

---

## Scene 7: THE CLOSE (2:10 – 2:20)

### Narration
*Trust is infrastructure.*

zeropoint.global

### Visuals
Everything fades to the dark background. The closing quote appears, one line at a time, center-screen. Pause. The ZeroPoint wordmark and URL fade in below. Hold for 3 seconds.

### Motion Notes
Stillness. Let the words land. No animation on the text itself — just clean fades. The contrast with the previous scene's activity makes this feel definitive.

### Asset: `scene-07-close.svg`

---

## Asset List

| Asset | Filename | Description |
|-------|----------|-------------|
| Scene 1 | `scene-01-problem.svg` | Chaotic agent network with no governance |
| Scene 2 | `scene-02-thesis.svg` | ZeroPoint wordmark with order emerging |
| Scene 3 | `scene-03-tenets.svg` | Four pillars with tenet labels |
| Scene 4 | `scene-04-gate.svg` | Guard → Policy → Audit pipeline |
| Scene 5 | `scene-05-chain.svg` | Delegation tree from human to agents |
| Scene 6 | `scene-06-vision.svg` | Mesh network with multi-transport |
| Scene 7 | `scene-07-close.svg` | Closing quote and wordmark |
| Diagram | `diagram-governance-gate.svg` | Standalone gate pipeline diagram |
| Diagram | `diagram-delegation-chain.svg` | Standalone delegation chain diagram |
| Diagram | `diagram-trust-tiers.svg` | Trust tier hierarchy diagram |

---

## Production Notes

The script is written for a single narrator — confident, measured, not rushed. Aim for a pace similar to Stripe's product videos or Linear's release announcements. Let pauses do work.

Each scene corresponds to an SVG file that represents the key frame (the moment of maximum visual information). Motion designers should use these as composition targets and add entrance/exit animations as indicated in the MOTION notes.

The color palette is locked to the ZeroPoint brand: dark backgrounds (#0A0A0C), accent blue (#7EB8DA) for structure, green (#4ADE80) for allow/valid, red (#F87171) for block/tamper, amber (#FBBF24) for warnings. No other colors should appear.

**Audio:** Recommend commissioning a minimal ambient electronic track. The tempo should build subtly from Scene 1 through Scene 6, then drop to silence for Scene 7. No voiceover compression or processing — keep it natural and clear.
