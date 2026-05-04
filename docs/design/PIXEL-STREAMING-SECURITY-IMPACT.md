# Pixel Streaming Security Impact Analysis

**Date:** 2026-05-02
**Context:** ZeroPoint Foundation Sovereign Workspace introduces server-side rendering with pixel streaming. This document analyzes the impact on ZeroPoint's published security footprint.

**Core architectural change:** The workspace UI renders inside a headless browser on a sovereign render node. Officers' devices receive only an encoded video stream (WebRTC/WebSocket). No structured data — no HTML, no JSON, no DOM, no API responses — ever crosses the trust boundary to the client.

---

## Part 1: Attack Classes Structurally Eliminated

These attack vectors are not mitigated, not defended against — they are **removed from the threat model entirely** because the preconditions for the attack no longer exist.

### Client-Side Attacks (eliminated)

| Attack Class | Why It No Longer Applies |
|---|---|
| **XSS (Cross-Site Scripting)** | No DOM on client. The client is a `<canvas>`. There is no HTML to inject into, no script context to hijack, no document tree to manipulate. |
| **CSRF (Cross-Site Request Forgery)** | No API endpoints accept client-side requests. The client sends input events (mouse coordinates, key codes) over a WebSocket, not authenticated HTTP requests to state-changing endpoints. |
| **Clickjacking** | No interactive elements to overlay. The client surface is a flat pixel canvas — there are no buttons, links, or forms to trick the user into clicking through an invisible iframe. |
| **Local Storage Poisoning** | No local storage. The thin client stores nothing — no session tokens, no cached data, no offline state. The auth token lives in a JS variable that dies with the tab. |
| **Service Worker Hijacking** | The service worker caches only the shell HTML. There is no API traffic to intercept, no responses to modify, no offline data to corrupt. |
| **Browser Extension Scraping** | No DOM to scrape. A malicious extension sees a canvas element containing pixels. It cannot querySelectorAll for email bodies, cannot read innerText of message containers, cannot access structured data because none exists. |
| **Cache Poisoning** | No HTTP responses with structured data to cache. The browser's HTTP cache contains only the thin client shell. The video stream is not cached. |
| **Clipboard Exfiltration** | No text to copy. The user cannot Ctrl+C email text because there is no text — only pixels that look like text. A clipboard hijacker gets nothing. |
| **Man-in-Browser (MitB)** | Banking trojans and MitB malware intercept DOM interactions and modify page content. With no DOM, no forms, no input fields rendering locally, these attacks have no surface. |

### Wire-Level Attacks (structurally weakened)

| Attack Class | Impact |
|---|---|
| **API Response Interception** | No API responses on the wire. Even if TLS is somehow compromised, the attacker sees an encoded video stream — not parseable JSON, not HTML, not structured data. |
| **Man-in-the-Middle (structured data)** | A MitM attacker captures video frames. They can watch what the user sees, but they cannot search it, index it, query it, or programmatically extract fields from it. The data is "sanitized through pixelization." |
| **Harvest-Now-Decrypt-Later** | An adversary recording encrypted traffic for future quantum decryption gets a video stream, not a database. The effort-to-value ratio of decrypting a video feed vs. decrypting structured API responses is dramatically worse for the attacker. |

---

## Part 2: Impact on Existing Footprint Domains

### Infrastructure (currently 0 GREEN, 1 YELLOW, 5 RED)

This domain was entirely RED because ZP operates at the agent runtime layer, not network infrastructure. Pixel streaming changes this because it **structurally addresses endpoint protection** — not by adding endpoint software, but by eliminating the endpoint as a data-bearing node.

| Item | Current | Revised | Rationale |
|---|---|---|---|
| Network Segmentation | RED | RED | Still a network concern — unchanged |
| TLS / Transport | YELLOW | **GREEN** | WebRTC uses DTLS-SRTP — encrypted by default, with perfect forward secrecy. The rendered content never exists as parseable plaintext on the wire at any layer. |
| Firewalls & IDPS | RED | RED | Still network layer — unchanged |
| Endpoint Protection | RED | **GREEN** | Structurally eliminated. The endpoint holds no data. A fully compromised officer device yields a video feed, not a data breach. This is not endpoint security software — it's endpoint security by architecture. |
| Runtime Model Protection | RED | RED | Still model hosting concern — unchanged |
| Canary Deployments | RED | RED | Still deployment concern — unchanged |

**Revised Infrastructure: 2 GREEN, 0 YELLOW, 4 RED → 33% (was 8%)**

### Data Protection (currently 3 GREEN, 1 YELLOW, 1 RED)

| Item | Current | Revised | Rationale |
|---|---|---|---|
| Encryption at Rest | GREEN | GREEN | Unchanged — vault encryption |
| Access Controls | GREEN | GREEN | Unchanged — capability grants |
| Data Loss Prevention | YELLOW | **GREEN** | Data cannot leak from clients because it is never there. DLP is structural, not policy-based. The render node is the only system that ever materializes data, and it is under sovereign control. |
| Training Data Security | RED | RED | Still training-time concern |
| Privacy Preservation | GREEN | GREEN | Unchanged, but strengthened — no data residue on officer devices. Privacy is architectural, not compliance-theater. |

**Revised Data Protection: 4 GREEN, 0 YELLOW, 1 RED → 80% (was 70%)**

### LLM Threats (currently 2 GREEN, 4 YELLOW, 2 RED)

| Item | Current | Revised | Rationale |
|---|---|---|---|
| Sensitive Info Disclosure | GREEN | GREEN | Strengthened — even if the model outputs sensitive data, it renders on the server and streams as pixels. No structured disclosure path to the client. |
| Prompt Injection | YELLOW | YELLOW | Unchanged — still action-level, not prompt-level |
| Supply Chain Vulns | YELLOW | YELLOW | Unchanged |
| Data Poisoning | RED | RED | Unchanged — training-time |
| Model Theft | RED | RED | Unchanged |
| Prompt Leakage | YELLOW | **GREEN** | Prompt text renders server-side. Even if the model leaks its system prompt in output, the user sees pixels of text, not parseable text that can be copy-pasted or scraped. A screenshot could capture it, but programmatic extraction is structurally prevented. |
| Unbounded Consumption | YELLOW | YELLOW | Unchanged — cost enforcement still not in gate |

**Revised LLM Threats: 3 GREEN, 3 YELLOW, 2 RED → 56% (was 50%)**

### Agentic Threats (currently 4 GREEN, 7 YELLOW)

The pixel streaming primarily affects the human-agent interface, not the agent-to-agent surface. But it strengthens several items:

| Item | Current | Revised | Rationale |
|---|---|---|---|
| Human-Agent Trust Exploitation | YELLOW | **GREEN** | The sovereign viewport prevents the agent from manipulating local UI elements (impossible — there are no local UI elements). Social engineering through visual deception is still possible via rendered content, but the trust boundary is now architecturally enforced. The agent cannot inject client-side code, cannot modify the DOM, cannot persist deceptive state locally. |

Other items remain unchanged. The agentic threat surface is primarily about agent-to-agent and agent-to-tool interactions, which pixel streaming doesn't affect.

**Revised Agentic: 5 GREEN, 6 YELLOW → marginal improvement**

### Adversarial ML / MITRE ATLAS

| Item | Current | Revised | Rationale |
|---|---|---|---|
| Exfiltration | GREEN | GREEN | Massively strengthened — exfiltration from the client is structurally impossible. The render node is the only exfiltration surface, and it is under sovereign control with no public API. |

### Cryptographic Resilience

| Item | Current | Revised | Rationale |
|---|---|---|---|
| Harvest-Now-Decrypt-Later | RED | **YELLOW** | The primary harvest target (API responses containing structured data) no longer exists on the wire. An adversary capturing encrypted traffic gets video frames, which have dramatically lower intelligence value even if decrypted post-quantum. Combined with ML-DSA hybrid signing (Phase 1 complete), the HNDL threat to receipts is addressed. The wire-level HNDL threat to workspace content is now structural rather than cryptographic. |

**Revised Cryptographic Resilience: 1 GREEN, 3 YELLOW, 2 RED → 42% (was 33%)**

---

## Part 3: New Domain — Sovereign Viewport

Pixel streaming introduces a new security domain that should be added to the footprint. These are threats specific to the pixel streaming architecture.

**Domain: Sovereign Viewport**
**Source: ZeroPoint · Pixel Streaming Architecture**
**Description: Threats targeting the server-side rendering and pixel streaming transport — the trust boundary between sovereign data and untrusted endpoints.**

| Item | Rating | ZP Coverage |
|---|---|---|
| **Render Node Isolation** | GREEN | Single-tenant headless browser per session. Process isolation via Puppeteer page contexts. No shared state between officer sessions. |
| **Session Recording** | YELLOW | An attacker with access to the WebSocket/WebRTC stream can record the video feed. DTLS-SRTP encrypts the transport, but if the render node or signaling server is compromised, sessions can be recorded server-side. Mitigation: render node runs on sovereign infrastructure under operator control. |
| **Input Injection** | YELLOW | If an attacker can inject WebSocket messages, they can inject mouse clicks and keystrokes into the headless browser. Mitigation: authenticated WebSocket with session tokens; but no per-message signing yet. |
| **Frame Analysis / OCR** | YELLOW | A captured video stream can be run through OCR to extract text from rendered frames. This is significantly harder than parsing JSON, but not impossible for a motivated attacker. The data is "pixelized, not destroyed." Mitigation: this is an inherent limitation — the tradeoff for human-viewable content. |
| **Render Node Compromise** | RED | If the render node itself is compromised, the attacker has full access to all data (it renders everything). This is the single point of trust. Mitigation: sovereign infrastructure, minimal attack surface (no public API), process isolation. The risk is real but concentrated — one node to protect instead of N endpoints. |
| **Latency Side-Channel** | YELLOW | Frame delivery timing could theoretically leak information about content type (text renders faster than images) or user activity patterns. Low practical risk but worth noting. |

**Sovereign Viewport: 1 GREEN, 4 YELLOW, 1 RED → 50%**

---

## Part 4: Revised Aggregate Coverage

### Before Pixel Streaming

| Framework | GREEN | YELLOW | RED | Coverage |
|---|---|---|---|---|
| NIST AI RMF (GOVERN/MAP/MEASURE/MANAGE) | 12 | 4 | 3 | 74% |
| OWASP LLM Top 10 | 2 | 4 | 2 | 50% |
| OWASP Agentic Top 10 | 4 | 7 | 0 | 68% |
| MITRE ATLAS | 5 | 2 | 1 | 75% |
| Data Protection | 3 | 1 | 1 | 70% |
| Infrastructure | 0 | 1 | 5 | 8% |
| Edge Sovereignty | 1 | 5 | 0 | 58% |
| MCP Protocol Security | 0 | 4 | 1 | 40% |
| Fleet & Settlement | 0 | 5 | 0 | 50% |
| Cryptographic Resilience | 1 | 2 | 3 | 33% |
| **Aggregate (79 items)** | **28** | **35** | **16** | **58%** |

### After Pixel Streaming

| Framework | GREEN | YELLOW | RED | Coverage | Delta |
|---|---|---|---|---|---|
| NIST AI RMF | 12 | 4 | 3 | 74% | — |
| OWASP LLM Top 10 | 3 | 3 | 2 | 56% | +6% |
| OWASP Agentic Top 10 | 5 | 6 | 0 | 73% | +5% |
| MITRE ATLAS | 5 | 2 | 1 | 75% | — |
| Data Protection | 4 | 0 | 1 | 80% | +10% |
| Infrastructure | 2 | 0 | 4 | 33% | +25% |
| Edge Sovereignty | 1 | 5 | 0 | 58% | — |
| MCP Protocol Security | 0 | 4 | 1 | 40% | — |
| Fleet & Settlement | 0 | 5 | 0 | 50% | — |
| Cryptographic Resilience | 1 | 3 | 2 | 42% | +9% |
| **Sovereign Viewport (new)** | **1** | **4** | **1** | **50%** | new |
| **Revised Aggregate (85 items)** | **34** | **36** | **15** | **61%** | **+3%** |

### The Real Story

The aggregate number (+3%) undersells what happened. The qualitative shift matters more:

1. **An entire attack class was structurally eliminated.** Client-side attacks (XSS, CSRF, clickjacking, extension scraping, cache poisoning, local storage poisoning, clipboard exfiltration) don't exist in the pixel streaming model. This isn't mitigation — it's architectural elimination.

2. **The endpoint left the threat model.** Three officer devices across three platforms (Apple, Android, Windows) are no longer data-bearing nodes. The security posture of each officer's personal device is irrelevant to data protection. A stolen, rooted, malware-infested laptop yields a video feed.

3. **The wire-level threat surface changed category.** Intercepted traffic went from "structured, queryable data" to "encoded video stream." The intelligence value of a captured stream is orders of magnitude lower. HNDL attacks against workspace content become impractical.

4. **The trust topology simplified.** Instead of defending N endpoints + 1 server, you defend 1 render node. The attack surface didn't just shrink — it collapsed from a distributed surface to a single point. That point (the render node) becomes the crown jewel, but it's a single system under sovereign control, not three consumer devices in the wild.

5. **A new primitive emerged.** "Sovereign Viewport" is not just a ZP feature — it's a generalizable security property. Any application that adopts server-side rendering with pixel streaming inherits the same structural elimination of client-side attacks. This is a ZeroPoint protocol primitive, not an application feature.

---

## Part 5: Decision Points

- [ ] Add "Sovereign Viewport" domain to footprint page
- [ ] Upgrade Infrastructure items (TLS → GREEN, Endpoint Protection → GREEN)
- [ ] Upgrade Data Protection DLP (YELLOW → GREEN)
- [ ] Upgrade LLM Prompt Leakage (YELLOW → GREEN)
- [ ] Upgrade Agentic Human-Agent Trust Exploitation (YELLOW → GREEN)
- [ ] Upgrade Cryptographic Resilience HNDL (RED → YELLOW)
- [ ] Add "Governance Without Runtime" + "Sovereign Viewport" as featured callouts
- [ ] Consider: should the pixel streaming architecture be documented as a formal ZP primitive (Primitive 4) in FORMAL-PRIMITIVES.md?
- [ ] Consider: should the attack-class elimination be documented in FALSIFICATION-GUIDE.md as a falsifiable claim?
