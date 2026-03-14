#!/usr/bin/env python3
"""Generate ZeroPoint Whitepaper PDF directly"""

# First, ensure reportlab is available
import subprocess
import sys

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.units import inch
    from reportlab.pdfgen import canvas
except ImportError:
    print("Installing reportlab...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", "reportlab"])
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.units import inch
    from reportlab.pdfgen import canvas

# Create output path
output_pdf = "zeropoint.global/ZeroPoint_Whitepaper_v1.0.pdf"

# Create PDF
c = canvas.Canvas(output_pdf, pagesize=letter)
width, height = letter

# Cover Page
c.setFont("Helvetica-Bold", 32)
c.drawCentredString(width/2, height - 2*inch, "ZeroPoint")

c.setFont("Helvetica", 16)
c.drawCentredString(width/2, height - 3*inch, "Portable Proof Infrastructure")
c.drawCentredString(width/2, height - 3.4*inch, "for Autonomous Agent Systems")

c.setFont("Helvetica", 13)
c.drawCentredString(width/2, height - 4.2*inch, "Cryptographic Proof Primitives for the Agentic Age")

# Metadata
c.setFont("Helvetica", 9)
y = height - 5.2*inch
for line in [
    "Version: 1.0 — February 2026",
    "Author: Ken Romero, Founder, ThinkStream Labs",
    "Status: Public Technical Whitepaper",
    "License: CC BY 4.0 (text); MIT/Apache-2.0 (code)"
]:
    c.drawString(1*inch, y, line)
    y -= 0.3*inch

c.setFont("Helvetica-Oblique", 8)
y -= 0.3*inch
c.drawString(1*inch, y, "How to cite: Romero, Ken. \"ZeroPoint: Portable Proof Infrastructure")
y -= 0.15*inch
c.drawString(1*inch, y, "for Autonomous Agent Systems.\" ThinkStream Labs, v1.0, February 2026.")
y -= 0.15*inch
c.drawString(1*inch, y, "https://zeropoint.global/whitepaper")

c.showPage()

# Table of Contents
c.setFont("Helvetica-Bold", 16)
c.drawString(1*inch, height - 1*inch, "Table of Contents")

c.setFont("Helvetica", 10)
toc = [
    "Abstract",
    "Section 0: Why This Exists — The Portable Trust Thesis",
    "Section 1: Problem Statement",
    "Section 2: Design Goals",
    "Section 3: System Overview",
    "Section 4: Receipts and Chains",
    "Section 5: Governance Model",
    "Section 6: Threat Model",
    "Section 7: Transport Integrations",
    "Section 8: Implementation Status",
    "Section 9: Adoption Paths",
    "Section 10: Roadmap",
    "Section 11: Ethics, Non-Goals, and Misuse Resistance",
    "Section 12: Conclusion",
    "Appendix A: Protocol Sketch",
    "Appendix B: Glossary",
    "Appendix C: Example Integration Pattern"
]

y = height - 1.5*inch
for i, item in enumerate(toc, 1):
    c.drawString(1.25*inch, y, f"{i}. {item}")
    y -= 0.25*inch
    if y < 1*inch:
        c.showPage()
        y = height - 1*inch

c.showPage()

# Abstract
c.setFont("Helvetica-Bold", 14)
c.drawString(1*inch, height - 1*inch, "Abstract")

c.setFont("Helvetica", 9)
y = height - 1.4*inch

abstract = """ZeroPoint is portable proof infrastructure — cryptographic governance primitives that produce proof of authorization, compliance, and provenance without requiring central control. It restores real exit and real competition by moving trust from platform databases to verifiable cryptographic guarantees.

The framework operates at the protocol-primitives layer. Every significant action produces a verifiable receipt, linked into an immutable chain of accountability. The protocol is participant-agnostic: the same receipts, capability chains, and constitutional constraints work for humans, AI agents, automated services, or IoT devices.

Autonomous AI agents are the most urgent application: agents are proliferating faster than the trust infrastructure to govern them. ZeroPoint provides the cryptographic substrate they need. Any participant that holds a keypair can sign receipts, hold capability grants, delegate authority, and exercise sovereign refusal.

ZeroPoint is technically complete: 699 tests across 13 crates, six delivered development phases, and full documentation. It provides cryptographic primitives and governance constraints that produce proof of every action and make every participant refusable."""

for line in abstract.split('\n'):
    if line.strip():
        wrapped_lines = []
        words = line.split()
        current_line = ""
        for word in words:
            test_line = current_line + " " + word if current_line else word
            if c.stringWidth(test_line, "Helvetica", 9) < 5*inch:
                current_line = test_line
            else:
                if current_line:
                    wrapped_lines.append(current_line)
                current_line = word
        if current_line:
            wrapped_lines.append(current_line)
        for wl in wrapped_lines:
            c.drawString(1.25*inch, y, wl)
            y -= 0.2*inch
        y -= 0.15*inch

c.showPage()

# Main sections
sections_data = [
    ("Why This Exists — The Portable Trust Thesis", """The internet degraded because trust primitives were never built into the protocol layer. They were left to platforms. When your identity lives in a platform's database, you don't have trust. You have a lease that can be revoked anytime.

ZeroPoint's thesis: make trust portable, and you make exit real. Portable trust means your identity is a keypair you control, your reputation is a verifiable chain of receipts, your authorization is a cryptographic capability grant, and your history is a hash-chained audit trail.

Autonomous AI agents amplify the stakes. Every major AI lab is shipping agent frameworks, building on trust infrastructure designed for when humans were always in the loop. ZeroPoint provides the cryptographic primitives that produce portable proof — of what happened, who authorized it, and what constraints applied — without requiring any central authority."""),

    ("Problem Statement", """Three critical gaps exist:

1. Identity is centralized. Agent identities live in platform databases. Moving to a new system requires re-authentication and loses continuity.

2. Authorization is opaque. No standard way exists to grant, revoke, or audit capability grants between systems.

3. Accountability is mutable. Logs are stored in databases their owners control. Multi-agent systems have no shared source of truth.

ZeroPoint's assertion: accountability at the protocol layer solves all three gaps. When every action produces a verifiable receipt, and receipts chain into an immutable audit trail, then identity, authorization, and accountability become protocol properties."""),

    ("Design Goals", """2.1 Every Action Produces Proof — Any participant can sign a receipt for any action. Proof is not optional.

2.2 Proof Is Portable and Decentralized — A receipt exists independent of any platform. The participant can carry it to any system.

2.3 Governance Is Mathematical, Not Social — Constraints apply through cryptographic enforcement, not platform policies.

2.4 The System Is Transport-Agnostic — The same protocol works over HTTP, TCP, UDP, Reticulum, or any future transport.

2.5 Every Participant Is Refusable — Participants declare constraints governing what they will do. If a system asks them to violate constraints, their proof system rejects it."""),

    ("System Overview", """The core ZeroPoint flow:
1. Participant declares constraints
2. Action is proposed
3. Intent is validated
4. Action is executed
5. Proof is chained
6. Audit trail is immutable

Core thesis: "Every action becomes proof. Proof becomes a chain. The chain becomes shared truth." And: "Nothing passes without producing proof."

When trust is portable, platforms compete on service quality, not lock-in. When trust is portable, switching costs drop to near zero. The dependency loop enabling extraction never forms."""),
]

for section_title, section_content in sections_data:
    c.setFont("Helvetica-Bold", 14)
    c.drawString(1*inch, height - 1*inch, section_title)

    c.setFont("Helvetica", 8.5)
    y = height - 1.4*inch

    for paragraph in section_content.split('\n\n'):
        for line in paragraph.split('\n'):
            if line.strip():
                wrapped = []
                words = line.split()
                current = ""
                for word in words:
                    test = current + " " + word if current else word
                    if c.stringWidth(test, "Helvetica", 8.5) < 5.5*inch:
                        current = test
                    else:
                        if current:
                            wrapped.append(current)
                        current = word
                if current:
                    wrapped.append(current)
                for w in wrapped:
                    c.drawString(1.25*inch, y, w)
                    y -= 0.18*inch
        y -= 0.1*inch
        if y < 1*inch:
            c.showPage()
            y = height - 1*inch

    c.showPage()

# Receipts and Chains section
c.setFont("Helvetica-Bold", 14)
c.drawString(1*inch, height - 1*inch, "Receipts and Chains")

c.setFont("Helvetica", 8.5)
y = height - 1.4*inch

receipt_text = """A receipt is a signed cryptographic attestation containing: action, timestamp, authority_chain, constraints, outcome, actor, and signature.

A receipt proves: identity (signed by actor), integrity (tamper-evident), provenance (valid authority chain), compliance (constraints honored), and non-repudiation (actor cannot deny action).

A receipt chain is immutable. Each receipt includes the hash of the previous receipt. A single receipt can be forged. A chain cannot be forged without rewriting every subsequent receipt. This mechanism makes trust portable — your receipts belong to you."""

for line in receipt_text.split('\n'):
    if line.strip():
        wrapped = []
        words = line.split()
        current = ""
        for word in words:
            test = current + " " + word if current else word
            if c.stringWidth(test, "Helvetica", 8.5) < 5.5*inch:
                current = test
            else:
                if current:
                    wrapped.append(current)
                current = word
        if current:
            wrapped.append(current)
        for w in wrapped:
            c.drawString(1.25*inch, y, w)
            y -= 0.18*inch
    y -= 0.1*inch
    if y < 1*inch:
        c.showPage()
        y = height - 1*inch

c.showPage()

# Governance section
c.setFont("Helvetica-Bold", 14)
c.drawString(1*inch, height - 1*inch, "Governance Model: The Four Tenets")

c.setFont("Helvetica", 8.5)
y = height - 1.4*inch

tenets = """Tenet I: Authority Flows Through Provenance — Authority flows through cryptographic delegation chains. There is no platform-dependent root of trust.

Tenet II: Constraints Are Mathematical, Not Administrative — Constraints are mathematical properties that can be verified, not platform-administered policies.

Tenet III: Action Without Proof Is No Action — If an action does not produce proof, it did not happen. This creates automatic accountability.

Tenet IV: Exit Is Always Possible — Participants can exit any system and carry their proof with them because trust is portable."""

for line in tenets.split('\n'):
    if line.strip():
        wrapped = []
        words = line.split()
        current = ""
        for word in words:
            test = current + " " + word if current else word
            if c.stringWidth(test, "Helvetica", 8.5) < 5.5*inch:
                current = test
            else:
                if current:
                    wrapped.append(current)
                current = word
        if current:
            wrapped.append(current)
        for w in wrapped:
            c.drawString(1.25*inch, y, w)
            y -= 0.18*inch
    y -= 0.15*inch
    if y < 1*inch:
        c.showPage()
        y = height - 1*inch

c.showPage()

# Threat Model
c.setFont("Helvetica-Bold", 14)
c.drawString(1*inch, height - 1*inch, "Threat Model")

c.setFont("Helvetica", 8.5)
y = height - 1.4*inch

threats = """ZeroPoint produces proof, making systems refusable. Threats addressed:
• Lock-in — Portable identity and reputation enable immediate exit
• Unauthorized Delegation — Revocation is a signed receipt; changes auditable
• Constraint Violation — Proof includes constraints; verifiable compliance
• Audit Trail Tampering — Chain of signed receipts is tamper-evident
• Repudiation — Signed receipt provides cryptographic non-repudiation
• Authority Chain Forgery — Each link must be signed; forgery detectable

What ZeroPoint does NOT solve: prevent bad decisions, guarantee execution, prevent collusion, solve the oracle problem, make extraction impossible, or solve all of AI safety.

What it does: shift the burden of proof from "trust this platform" to "verify this proof" — and verification is mathematical."""

for line in threats.split('\n'):
    if line.strip():
        wrapped = []
        words = line.split()
        current = ""
        for word in words:
            test = current + " " + word if current else word
            if c.stringWidth(test, "Helvetica", 8.5) < 5.5*inch:
                current = test
            else:
                if current:
                    wrapped.append(current)
                current = word
        if current:
            wrapped.append(current)
        for w in wrapped:
            c.drawString(1.25*inch, y, w)
            y -= 0.18*inch
    y -= 0.08*inch
    if y < 1*inch:
        c.showPage()
        y = height - 1*inch

c.showPage()

# Implementation Status
c.setFont("Helvetica-Bold", 14)
c.drawString(1*inch, height - 1*inch, "Implementation Status")

c.setFont("Helvetica", 8.5)
y = height - 1.4*inch

impl = """ZeroPoint is technically complete. The codebase comprises 13 Rust crates with approximately 15,000 lines of code (excluding tests). It includes 699 unit and integration tests, full cryptographic implementation (Ed25519, BLAKE3), receipt generation and verification, delegation and constraint enforcement, HTTP/Reticulum/TCP transport layers, and complete API documentation.

Development through six complete phases:
• Phase 1: Cryptographic primitives and receipt generation
• Phase 2: Delegation chains and grant verification
• Phase 3: Constraint evaluation and enforcement
• Phase 4: Transport integrations
• Phase 5: Governance and refusal mechanisms
• Phase 6: Documentation and example integrations

The system is production-ready. All core algorithms are deterministic and cryptographically verifiable."""

for line in impl.split('\n'):
    if line.strip():
        wrapped = []
        words = line.split()
        current = ""
        for word in words:
            test = current + " " + word if current else word
            if c.stringWidth(test, "Helvetica", 8.5) < 5.5*inch:
                current = test
            else:
                if current:
                    wrapped.append(current)
                current = word
        if current:
            wrapped.append(current)
        for w in wrapped:
            c.drawString(1.25*inch, y, w)
            y -= 0.18*inch
    y -= 0.1*inch
    if y < 1*inch:
        c.showPage()
        y = height - 1*inch

c.showPage()

# Adoption Paths
c.setFont("Helvetica-Bold", 14)
c.drawString(1*inch, height - 1*inch, "Adoption Paths & Roadmap")

c.setFont("Helvetica", 8.5)
y = height - 1.4*inch

adoption = """Path 1: Single-Agent Governance — Deploy one agent with ZeroPoint, declaring constraints and maintaining receipt chains.

Path 2: Multi-Agent Orchestration — Agents across organizational boundaries share ZeroPoint trust substrate.

Path 3: Human-Agent Delegation — Humans delegate to agents via ZeroPoint grants, retaining revocation rights.

Path 4: Cross-Platform Interoperability — Platforms implement ZeroPoint transports; participants move while carrying proof.

Path 5: Regulatory Integration — Regulators audit receipt chains to verify constraint compliance.

Roadmap:
Q1-Q2 2026: Ecosystem development, production-grade libraries for Python/Go/JavaScript
Q3 2026: Multi-agent testbed with 10+ agents, security audit
Q4 2026: Reticulum deployment, pilot networks
2027+: Regulatory integration, healthcare systems deployment, long-term vision of portable trust"""

for line in adoption.split('\n'):
    if line.strip():
        wrapped = []
        words = line.split()
        current = ""
        for word in words:
            test = current + " " + word if current else word
            if c.stringWidth(test, "Helvetica", 8.5) < 5.5*inch:
                current = test
            else:
                if current:
                    wrapped.append(current)
                current = word
        if current:
            wrapped.append(current)
        for w in wrapped:
            c.drawString(1.25*inch, y, w)
            y -= 0.18*inch
    y -= 0.08*inch
    if y < 1*inch:
        c.showPage()
        y = height - 1*inch

c.showPage()

# Conclusion
c.setFont("Helvetica-Bold", 14)
c.drawString(1*inch, height - 1*inch, "Conclusion")

c.setFont("Helvetica", 8.5)
y = height - 1.4*inch

conclusion = """ZeroPoint solves a specific problem: how do you create trust without depending on a platform?

The answer is portable proof — proof that is cryptographically durable, portable, decentralized, governable, and refusable.

When trust is portable, exit is real. When exit is real, extraction is optional. When extraction is optional, platforms must compete on quality, not on lock-in.

The practical consequence: autonomous agents operate with mathematical guarantees about authority, constraints, and accountability. Humans delegate to agents without losing control. Systems interoperate without central coordinators. Regulators audit compliance without depending on operator goodwill.

The vision: Make proof portable, and trust follows. Make trust portable, and exit becomes real. Make exit real, and autonomous systems become feasible.

Proof produces trust. Trust is infrastructure.

This is not the end of ZeroPoint's development. Cryptographic governance primitives are new. The systems that emerge will be unexpected. But the foundational principle is solid: when every action produces proof, when proof is portable, and when participants can refuse and exit, the structural incentive shifts from exploit to serve.

The future of autonomous agent systems is not more regulation or monitoring. The future is mathematical proof that every participant can verify independently. ZeroPoint provides the primitives. The rest is up to us."""

for line in conclusion.split('\n'):
    if line.strip():
        wrapped = []
        words = line.split()
        current = ""
        for word in words:
            test = current + " " + word if current else word
            if c.stringWidth(test, "Helvetica", 8.5) < 5.5*inch:
                current = test
            else:
                if current:
                    wrapped.append(current)
                current = word
        if current:
            wrapped.append(current)
        for w in wrapped:
            c.drawString(1.25*inch, y, w)
            y -= 0.18*inch
    y -= 0.1*inch
    if y < 1*inch:
        c.showPage()
        y = height - 1*inch

c.showPage()

# Appendices
c.setFont("Helvetica-Bold", 14)
c.drawString(1*inch, height - 1*inch, "Appendix A: Protocol Sketch")

c.setFont("Helvetica", 8)
y = height - 1.4*inch

appendix_a = """Receipt Structure: version, action, timestamp, actor, authority_chain, constraints, outcome, nonce, previous_hash, signature.

Verification: (1) Verify signature using actor's public key (2) Verify previous_hash matches (3) Verify grants in authority_chain (4) Verify grant not revoked (5) Verify constraints satisfied.

Constraint Evaluation: MaxAmount(X), AllowedRecipients(R), TimeWindow(T1,T2), RateLimitPerDay(X), MustNotViolate(V).

Delegation Chain Valid if: all grants signed, each references previous grant, no grant revoked, most recent grant not expired, combined capabilities authorize action.

Proof of Action: receipt hash and full receipt, portable and verifiable indefinitely."""

for line in appendix_a.split('\n'):
    if line.strip():
        c.drawString(1.25*inch, y, line.strip())
        y -= 0.15*inch
        if y < 1*inch:
            c.showPage()
            y = height - 1*inch

c.showPage()

# Appendix B: Glossary
c.setFont("Helvetica-Bold", 14)
c.drawString(1*inch, height - 1*inch, "Appendix B: Glossary")

c.setFont("Helvetica", 8)
y = height - 1.4*inch

glossary = [
    ("Receipt", "Signed cryptographic attestation of an action with intent, constraints, authority, outcome"),
    ("Proof", "Signature and hash demonstrating action happened and constraints honored"),
    ("Chain", "Sequence of receipts linked by hashes, immutable audit trail"),
    ("Grant", "Signed delegation of authority with specific capabilities and constraints"),
    ("Constraint", "Mathematical assertion about what actions are permitted"),
    ("Authority", "Right to perform action, flowing through delegation chains"),
    ("Capability", "Specific ability granted to actor (e.g., 'transfer $100')"),
    ("Revocation", "Cancellation of previously issued grant, recorded as receipt"),
    ("Refusal", "Participant rejection of action violating constraints"),
    ("Portable Identity", "Keypair belonging to actor, not to any platform"),
    ("Portable Proof", "Cryptographic proof valid independent of creating system"),
    ("Exit", "Ability to move to different system retaining identity and proof"),
    ("Refusability", "Ability to reject actions violating declared constraints"),
    ("Tamper-Evidence", "Property making any modification detectable"),
    ("Non-repudiation", "Inability to deny performing signed action"),
]

for term, definition in glossary:
    c.drawString(1.25*inch, y, f"{term}: {definition}")
    y -= 0.18*inch
    if y < 1*inch:
        c.showPage()
        y = height - 1*inch

c.showPage()

# Appendix C: Integration Pattern
c.setFont("Helvetica-Bold", 14)
c.drawString(1*inch, height - 1*inch, "Appendix C: Example Integration Pattern")

c.setFont("Helvetica", 8)
y = height - 1.4*inch

pattern = """Step 1: Define Agent Identity — Create keypair; agent's identity is public key (portable).

Step 2: Declare Constraints — Issue declaration receipt specifying max amounts, rate limits, time windows, constitutional values.

Step 3: Issue Grant — Human signs grant receipt authorizing agent, enters human's chain.

Step 4: Agent Executes — Agent proposes action, verifies all constraints satisfied, signs and submits receipt.

Step 5: Verification — System verifies signature, grant validity, constraint satisfaction. Receipt enters agent's chain.

Step 6: Revocation (if needed) — Human signs revocation receipt; agent can no longer use grant.

Key Properties: Portability (receipts belong to agent), Verifiability (any system can verify), Auditability (human can audit all actions), Refusability (human can revoke cryptographically), Mathematical Enforcement (constraints enforced by agent's proof system).

This pattern scales to multi-agent systems, cross-organizational delegation, and complex governance structures."""

for line in pattern.split('\n'):
    if line.strip():
        wrapped = []
        words = line.split()
        current = ""
        for word in words:
            test = current + " " + word if current else word
            if c.stringWidth(test, "Helvetica", 8) < 5.5*inch:
                current = test
            else:
                if current:
                    wrapped.append(current)
                current = word
        if current:
            wrapped.append(current)
        for w in wrapped:
            c.drawString(1.25*inch, y, w)
            y -= 0.15*inch
    y -= 0.08*inch
    if y < 1*inch:
        c.showPage()
        y = height - 1*inch

c.showPage()

# Save
c.save()

# Print confirmation
import os
file_size = os.path.getsize(output_pdf)
print(f"PDF successfully created: {output_pdf}")
print(f"File size: {file_size:,} bytes ({file_size/1024:.1f} KB)")
print(f"Pages: approximately 15+")
