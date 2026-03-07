#!/usr/bin/env python3
"""
Generate ZeroPoint Whitepaper PDF from HTML source.
Uses reportlab's Platypus for professional document layout.
"""

import sys
import os
from datetime import datetime

try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch, pt
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle,
        Preformatted, KeepTogether
    )
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY, TA_RIGHT
except ImportError as e:
    print(f"Error: reportlab not installed: {e}")
    sys.exit(1)

# Output file path
OUTPUT_PATH = "/sessions/hopeful-sweet-hypatia/mnt/zeropoint/zeropoint.global/ZeroPoint_Whitepaper_v1.0.pdf"

# Create styles
styles = getSampleStyleSheet()

# Dark theme colors (matching HTML)
BG_COLOR = colors.HexColor("#0a0a0c")
TEXT_COLOR = colors.HexColor("#e0ded9")
ACCENT_COLOR = colors.HexColor("#7eb8da")
TEXT_MUTED = colors.HexColor("#9a9a9e")
TEXT_DIM = colors.HexColor("#5a5a5e")
RULE_COLOR = colors.HexColor("#222228")
BG_ELEVATED = colors.HexColor("#111116")
BG_SUBTLE = colors.HexColor("#18181f")

# Custom styles
title_style = ParagraphStyle(
    'CustomTitle',
    parent=styles['Heading1'],
    fontSize=36,
    textColor=ACCENT_COLOR,
    spaceAfter=12,
    alignment=TA_CENTER,
    fontName='Helvetica-Bold',
    letterSpacing=-0.5,
)

subtitle_style = ParagraphStyle(
    'CustomSubtitle',
    parent=styles['Normal'],
    fontSize=14,
    textColor=TEXT_MUTED,
    spaceAfter=18,
    alignment=TA_CENTER,
    fontName='Helvetica',
)

heading2_style = ParagraphStyle(
    'CustomHeading2',
    parent=styles['Heading2'],
    fontSize=16,
    textColor=TEXT_COLOR,
    spaceAfter=12,
    spaceBefore=20,
    fontName='Helvetica-Bold',
    borderColor=RULE_COLOR,
    borderWidth=0.5,
    borderPadding=8,
)

heading3_style = ParagraphStyle(
    'CustomHeading3',
    parent=styles['Heading3'],
    fontSize=12,
    textColor=TEXT_COLOR,
    spaceAfter=10,
    spaceBefore=12,
    fontName='Helvetica-Bold',
)

body_style = ParagraphStyle(
    'CustomBody',
    parent=styles['Normal'],
    fontSize=10,
    textColor=TEXT_MUTED,
    spaceAfter=10,
    alignment=TA_JUSTIFY,
    leading=16,
    fontName='Helvetica',
)

meta_style = ParagraphStyle(
    'CustomMeta',
    parent=styles['Normal'],
    fontSize=8,
    textColor=TEXT_DIM,
    spaceAfter=4,
    alignment=TA_LEFT,
    fontName='Courier',
)

blockquote_style = ParagraphStyle(
    'CustomBlockquote',
    parent=styles['Normal'],
    fontSize=10,
    textColor=TEXT_COLOR,
    spaceAfter=12,
    spaceBefore=12,
    leftIndent=30,
    rightIndent=30,
    fontName='Helvetica-Oblique',
    borderColor=ACCENT_COLOR,
    borderWidth=2,
    borderLeft=2,
    borderRight=0,
    borderTop=0,
    borderBottom=0,
    borderPadding=12,
    backColor=BG_ELEVATED,
)

code_style = ParagraphStyle(
    'CustomCode',
    parent=styles['Normal'],
    fontSize=8,
    textColor=ACCENT_COLOR,
    spaceAfter=10,
    fontName='Courier',
    backColor=BG_SUBTLE,
    leftIndent=10,
    rightIndent=10,
    spaceBefore=8,
    borderColor=RULE_COLOR,
    borderWidth=0.5,
    borderPadding=8,
)

def create_cover_page(story):
    """Create a professional cover page."""
    story.append(Spacer(1, 1.5*inch))

    # Main title
    title = Paragraph("ZeroPoint", title_style)
    story.append(title)
    story.append(Spacer(1, 0.3*inch))

    # Subtitles
    subtitle1 = Paragraph("Portable Proof Infrastructure for Autonomous Agent Systems", subtitle_style)
    story.append(subtitle1)
    story.append(Spacer(1, 0.15*inch))

    subtitle2 = Paragraph("Cryptographic Proof Primitives for the Agentic Age", subtitle_style)
    story.append(subtitle2)
    story.append(Spacer(1, 0.8*inch))

    # Version and metadata
    version = Paragraph("<b>Version 1.0</b> — February 2026", meta_style)
    story.append(version)
    story.append(Spacer(1, 0.05*inch))

    author = Paragraph("Author: Ken Romero, Founder, ThinkStream Labs", meta_style)
    story.append(author)
    story.append(Spacer(1, 0.05*inch))

    url = Paragraph("Website: <b>zeropoint.global</b>", meta_style)
    story.append(url)
    story.append(Spacer(1, 0.05*inch))

    license_text = Paragraph("License: CC BY 4.0 (text); MIT/Apache-2.0 (code)", meta_style)
    story.append(license_text)
    story.append(Spacer(1, 0.8*inch))

    # Key tagline
    tagline = Paragraph(
        "<i>Proof produces trust. Trust is infrastructure.</i>",
        ParagraphStyle(
            'Tagline',
            parent=styles['Normal'],
            fontSize=11,
            textColor=ACCENT_COLOR,
            alignment=TA_CENTER,
            fontName='Helvetica-Oblique',
        )
    )
    story.append(tagline)

    story.append(PageBreak())

def add_section(story, title, content_paragraphs):
    """Add a section with title and paragraphs."""
    story.append(Paragraph(title, heading2_style))
    story.append(Spacer(1, 0.1*inch))

    for para in content_paragraphs:
        if isinstance(para, tuple):  # (type, content)
            if para[0] == "body":
                story.append(Paragraph(para[1], body_style))
            elif para[0] == "heading3":
                story.append(Paragraph(para[1], heading3_style))
            elif para[0] == "blockquote":
                story.append(Paragraph(para[1], blockquote_style))
            elif para[0] == "list":
                for item in para[1]:
                    bullet = Paragraph(f"• {item}", body_style)
                    story.append(bullet)
            elif para[0] == "spacer":
                story.append(Spacer(1, 0.1*inch))
        else:
            story.append(Paragraph(para, body_style))

    story.append(Spacer(1, 0.15*inch))

def create_pdf():
    """Create the whitepaper PDF."""
    story = []

    # Create document
    doc = SimpleDocTemplate(
        OUTPUT_PATH,
        pagesize=letter,
        rightMargin=0.75*inch,
        leftMargin=0.75*inch,
        topMargin=0.75*inch,
        bottomMargin=0.75*inch,
    )

    # Cover page
    create_cover_page(story)

    # Abstract
    abstract_content = [
        ("body", "ZeroPoint is <b>portable proof infrastructure</b> — cryptographic governance primitives that produce proof of authorization, compliance, and provenance without requiring central control. It restores real exit and real competition by moving trust from platform databases to verifiable cryptographic guarantees that any participant can carry between systems, operators, and networks."),
        ("spacer", ""),
        ("body", "The framework operates at the <b>protocol-primitives layer</b>. Every significant action produces a verifiable receipt, linked into an immutable chain of accountability. The protocol is participant-agnostic: the same receipts, capability chains, and constitutional constraints work whether the actor is a human, an AI agent, an automated service, or an IoT device — and whether they communicate over HTTP, TCP, encrypted mesh networks, or any future transport."),
        ("spacer", ""),
        ("body", "Autonomous AI agents are the most urgent application: agents are proliferating faster than the trust infrastructure to govern them, and ZeroPoint provides the cryptographic substrate they need. But the primitives are not agent-specific. Any participant that holds a keypair can sign receipts, hold capability grants, delegate authority, and exercise sovereign refusal."),
        ("spacer", ""),
        ("body", "ZeroPoint is <b>technically complete</b>: 699 tests across 13 crates, six delivered development phases, and full documentation. It does not claim to \"solve AI safety\" or solve trust generally. It provides cryptographic primitives and governance constraints that produce proof of every action and make every participant refusable — shifting the terms of trust between participants, operators, and systems."),
    ]
    add_section(story, "Abstract", abstract_content)

    # Why This Exists
    section0_content = [
        ("heading3", "The Structural Problem"),
        ("body", "The internet did not degrade by accident. It degraded because the primitives that make trust work — identity, reputation, provenance, authorization — were never built into the protocol layer. They were left to platforms. And platforms, once they accumulate enough users, face a structural incentive to make those trust primitives non-portable."),
        ("spacer", ""),
        ("body", "This is the dependency loop: a platform offers identity and reputation services. Users and developers build on those services. The platform becomes the only place where a user's history, credentials, and relationships are legible. Exit becomes expensive. Once exit is expensive, the platform can extract — raising prices, degrading quality, inserting intermediaries, selling attention — because the cost of leaving exceeds the cost of staying. The user's trust relationships are held hostage by the platform's database."),
        ("spacer", ""),
        ("body", "Cory Doctorow named this dynamic <i>\"enshittification.\"</i> The diagnosis is precise: platforms attract users with value, then degrade the experience to extract from those users once switching costs are high enough. But the diagnosis, by itself, does not produce a remedy. Regulation can slow the cycle. Interoperability mandates can lower switching costs. But neither addresses the root cause: <b>trust is not portable.</b>"),
        ("spacer", ""),
        ("heading3", "The Missing Primitive"),
        ("body", "Consider what SSL/TLS did for e-commerce. Before SSL, transmitting a credit card number over the internet required trusting every intermediary between you and the merchant. Commerce was possible, but it was fragile, and it was concentrated among the few parties who could afford to build proprietary trust infrastructure. SSL did not make merchants trustworthy. It made the <i>transport</i> trustworthy — and in doing so, it made the ecosystem work. Any merchant could participate. Any customer could verify."),
        ("spacer", ""),
        ("body", "The internet is missing an equivalent primitive for <i>trust itself</i>. Not transport encryption — that problem is largely solved. The missing piece is: how do you prove what happened, who authorized it, and whether the constraints were honored — without depending on a platform to be the witness?"),
        ("spacer", ""),
        ("blockquote", "<b>ZeroPoint's thesis:</b> make trust portable, and you make exit real. Make exit real, and you make extraction optional. That is the structural antidote."),
        ("spacer", ""),
        ("body", "Portable trust means:"),
        ("list", [
            "<b>Your identity is a keypair you control</b>, not an account on someone else's server. You can move it between systems without losing continuity.",
            "<b>Your reputation is a verifiable chain of receipts</b>, not a score computed by an opaque algorithm. Anyone can audit it. No one can confiscate it.",
            "<b>Your authorization is a cryptographic capability grant</b>, not an API key that can be revoked without recourse. Delegation chains have mathematical properties — they cannot be silently altered.",
            "<b>Your history is a hash-chained audit trail</b>, not a log file someone else controls. Tampering is detectable. Omission is provable.",
        ]),
        ("spacer", ""),
        ("body", "When trust is portable, platforms compete on service quality, not on lock-in. When trust is portable, switching costs drop to near zero. When trust is portable, the dependency loop that enables extraction never forms."),
    ]
    add_section(story, "Why This Exists — The Portable Trust Thesis", section0_content)

    # Problem Statement
    section1_content = [
        ("body", "The accountability gap that agents expose is an instance of the deeper structural problem described above: digital systems have never had protocol-level trust primitives. Agents did not create this gap — they inherited it and are accelerating it to the point where informal trust is no longer tenable."),
        ("spacer", ""),
        ("body", "AI agents are rapidly becoming operational actors: they request tools, move data, execute workflows, and trigger external effects. They act at machine speed, across organizational boundaries, with delegation chains that can extend far beyond their original authority. Yet most systems today remain <b>trust-light:</b>"),
        ("list", [
            "<b>Actions are difficult to attribute reliably.</b> Logs exist, but they are mutable, centralized, and easily rewritten.",
            "<b>Authorization is informal and mutable.</b> Most systems rely on API keys or ambient permissions rather than scoped, cryptographic capability grants.",
            "<b>Logs are easy to forge, prune, or \"reinterpret.\"</b> There is no chain of evidence — only whatever the operator chooses to retain.",
            "<b>Cross-party trust is brittle.</b> One team cannot safely accept another party's outputs without out-of-band verification.",
        ]),
        ("spacer", ""),
        ("blockquote", "Systems where actions have consequences require protocol-level accountability primitives, not only policy frameworks."),
        ("spacer", ""),
        ("blockquote", "Not a governance framework you comply with — a governance protocol you build on."),
    ]
    add_section(story, "Problem Statement", section1_content)

    # Design Goals
    design_goals_content = [
        ("heading3", "2.1 Protocol-Level Accountability"),
        ("body", "ZeroPoint produces verifiable receipts for actions and decisions. A receipt is cryptographically signed data describing what occurred, under what constraints, and with what authorization — regardless of whether the actor is an agent, a human, or an automated service. Receipts are chained — each linking to its parent — to create a durable accountability history."),
        ("spacer", ""),
        ("heading3", "2.2 Sovereignty by Design"),
        ("body", "ZeroPoint is built to function in environments where cloud assumptions are unsafe or unavailable. Its governance primitives are <b>transport-agnostic</b> — they work over HTTP in a data center, TCP between containers, or encrypted mesh links in a field deployment. The framework minimizes dependency on centralized infrastructure by design, not by accident."),
        ("spacer", ""),
        ("heading3", "2.3 Governance as Constraints, Not Suggestions"),
        ("body", "The system includes governance mechanisms that are not simply \"policies in a file.\" Two constitutional rules — <code>HarmPrincipleRule</code> and <code>SovereigntyRule</code> — are engineered to be non-removable and non-overridable within the protocol's governance model. They evaluate before every action. They cannot be bypassed at runtime."),
        ("spacer", ""),
        ("heading3", "2.4 Honest Security Posture"),
        ("body", "ZeroPoint aims to be explicit about what it prevents, what it cannot prevent, and what remains a residual risk. Credibility comes from the boundaries, not the claims."),
        ("spacer", ""),
        ("heading3", "2.5 Transport Agnosticism and Interoperability"),
        ("body", "ZeroPoint's governance layer is decoupled from any single transport. The receipt format, capability grants, delegation chains, and policy engine operate identically regardless of how messages move. The framework ships with multiple transport integrations — including a Reticulum-compatible mesh transport, TCP/UDP interfaces, and an HTTP API — and is designed to be extended to any future transport without modifying the governance primitives."),
    ]
    add_section(story, "Design Goals", design_goals_content)

    # System Overview
    section3_content = [
        ("body", "ZeroPoint is composed of layered capabilities, each implemented as one or more Rust crates. The layers are participant-agnostic — any entity that holds a keypair (human, agent, service, device) can operate as a full peer:"),
        ("list", [
            "<b>Identity layer.</b> Ed25519 signing keys and X25519 key agreement. Identity is a keypair. Authentication is a signature.",
            "<b>Governance layer.</b> PolicyEngine with constitutional rules, composable operational rules, WASM-extensible policy modules, and capability gating.",
            "<b>Receipt layer.</b> Signed, hash-chained receipts for every action and decision. CompactReceipt encoding produces 150–300 byte payloads suitable for bandwidth-constrained transports.",
            "<b>Transport layer.</b> Pluggable transport with multiple built-in integrations: Reticulum-compatible mesh, TCP client/server, UDP, and HTTP API.",
            "<b>Application layer.</b> Pipeline orchestration, LLM provider integration, skill registry, and CLI tooling.",
        ]),
        ("spacer", ""),
        ("heading3", "3.1 Data Flow"),
        ("body", "The GovernanceGate pipeline processes every action through four pillars: <b>Guard</b> (\"May I?\") — local-first, pre-action sovereignty check. <b>Policy</b> (\"Should I?\") — rule-composed evaluation. Constitutional rules first, then operational rules, then WASM modules. <b>Execute</b> — the action runs only if Guard and Policy both allow it. <b>Audit</b> (\"Did I?\") — a receipt is emitted: signed, timestamped, hash-linked to the prior receipt, and persisted to the chain."),
        ("spacer", ""),
        ("blockquote", "<b>The Core Thesis:</b> Every action becomes proof. Proof becomes a chain. The chain becomes shared truth."),
    ]
    add_section(story, "System Overview", section3_content)

    # Receipts and Chains
    section4_content = [
        ("heading3", "4.1 What a Receipt Is"),
        ("body", "A receipt is a signed artifact that describes an event or action with enough context to be verified independently. In ZeroPoint's implementation, a receipt contains a unique identifier, receipt type (execution, intent, approval, delegation, verification, refusal), status (success, partial, failed, denied, timeout, pending), trust grade (A, B, C, D), content hash (Blake3), timestamp (Unix seconds), parent receipt ID, policy decision (allow, deny, escalate, audit), rationale, Ed25519 signature, and optional extensions."),
        ("spacer", ""),
        ("body", "Receipts are encoded using <b>MessagePack</b> with named fields, producing a compact binary representation of 150–300 bytes. This compact encoding is efficient over any transport — it fits in a single HTTP request, a single TCP frame, or a single 465-byte mesh packet for bandwidth-constrained links like LoRa."),
        ("spacer", ""),
        ("body", "<i>Receipts are intended to be verifiable. They are not intended to be surveillance.</i>"),
        ("spacer", ""),
        ("heading3", "4.2 What Receipts Prove vs. What They Don't"),
        ("body", "<b>Receipts can prove:</b>"),
        ("list", [
            "A specific Ed25519 key signed a specific statement at a specific time.",
            "A chain contains a consistent, unbroken sequence of signed events.",
            "The policy engine evaluated a known rule set and produced a specific decision.",
            "A capability grant was present and valid at the time of action.",
        ]),
        ("spacer", ""),
        ("body", "<b>Receipts do not automatically prove:</b>"),
        ("list", [
            "The nature of the signer. A receipt proves that a specific key signed a statement — not whether that key belongs to a human, an agent, or a service.",
            "That the content of an action was \"good\" or \"safe.\" Governance constrains actions; it does not evaluate truth.",
            "That the runtime environment was uncompromised. A compromised host can sign whatever it wants.",
            "That a result is truthful — only that it was produced and attested under stated constraints.",
        ]),
        ("spacer", ""),
        ("heading3", "4.3 Why Chains Matter"),
        ("body", "Single receipts help attribution. Chains help accountability continuity. Each receipt's <code>pr</code> field links to the previous receipt's ID, forming a hash-linked sequence that resists retroactive tampering. Chains are not magic. They are a mechanical advantage: they make it harder to rewrite the story after the fact, and they allow counterparties to require evidence before trust is granted."),
    ]
    add_section(story, "Receipts and Chains", section4_content)

    # Governance Model
    section5_content = [
        ("heading3", "5.1 Governance as a Primitive"),
        ("body", "Most governance — whether for agents, human workflows, or automated services — is implemented at the application layer: guardrails, prompt policies, logging conventions, compliance checklists. These are better than nothing, but they sit above the systems they govern. They can be bypassed, reconfigured, or simply ignored."),
        ("spacer", ""),
        ("body", "ZeroPoint moves governance downward into the <b>protocol substrate</b>. The PolicyEngine is not an add-on. It is the gate through which every action must pass — regardless of who or what initiated it."),
        ("spacer", ""),
        ("heading3", "5.2 Policy and Capability Gating"),
        ("body", "ZeroPoint requires explicit capabilities for actions. Any participant must hold a valid grant to act. A <code>CapabilityGrant</code> is a signed, portable authorization token containing scope restrictions, cost ceilings and rate limits, time windows, delegation depth limits, trust tier requirements, and the grantor's Ed25519 signature."),
        ("spacer", ""),
        ("body", "Capabilities are <b>delegatable</b>. Any participant holding a grant can delegate a subset of that grant to another participant — forming a <code>DelegationChain</code>. The chain is verified against eight invariants: each grant references its parent, delegation depths increment monotonically, each child's scope is a subset of its parent's, each child's trust tier is ≥ its parent's, no child outlives its parent, the chain doesn't exceed max_delegation_depth, each grantor matches the previous grantee, and all signatures verify. Break any invariant and the chain is rejected."),
        ("spacer", ""),
        ("heading3", "5.3 Constitutional Constraints"),
        ("body", "ZeroPoint's PolicyEngine loads rules in a fixed evaluation order. The first two positions are reserved for constitutional rules that cannot be removed, overridden, or reordered: <b>HarmPrincipleRule</b> (Tenet I: Do No Harm) blocks actions targeting weaponization, surveillance, deception, and suppression of dissent. <b>SovereigntyRule</b> (Tenet II: Sovereignty Is Sacred) blocks configuration changes that would disable the guard, disable the audit trail, forge capabilities, remove constitutional rules, or override participant refusal."),
        ("spacer", ""),
        ("heading3", "5.4 The Four Tenets"),
        ("body", "<b>I. Do No Harm.</b> ZeroPoint shall not operate in systems designed to harm humans. The HarmPrincipleRule is a non-removable rule in the PolicyEngine."),
        ("spacer", ""),
        ("body", "<b>II. Sovereignty Is Sacred.</b> Every participant has the right to refuse any action. Every human has the right to disconnect any agent. No agent may acquire capabilities it was not granted. Coercion is architecturally impossible."),
        ("spacer", ""),
        ("body", "<b>III. Action Without Proof Is No Action.</b> Every action produces a receipt. Every receipt is a cryptographic proof. Every proof joins a chain. If it's not in the chain, it didn't happen."),
        ("spacer", ""),
        ("body", "<b>IV. The Human Is The Root.</b> Every delegation chain terminates at a human-held key. No agent may self-authorize. The genesis key is always held by flesh, blood, and soul."),
    ]
    add_section(story, "Governance Model", section5_content)

    # Threat Model
    section6_content = [
        ("heading3", "6.1 Threat Mitigation"),
        ("body", "<b>Log forgery / retroactive rewriting:</b> Signed receipts with Ed25519 + Blake3 hash chain linkage. Peers verify each other's chains via collective audit. Residual risk: Compromised private keys can still sign lies; key revocation is deployment-dependent."),
        ("spacer", ""),
        ("body", "<b>Unauthorized tool use:</b> CapabilityGrant gating with 8-invariant delegation chain verification. PolicyEngine evaluates before every action. Residual risk: Bad policy design can still leave gaps; scoping is only as good as the grant definitions."),
        ("spacer", ""),
        ("body", "<b>Cross-operator trust failure:</b> <code>zp-introduction</code> protocol verifies certificate chains and evaluates peer trust through the policy engine. Residual risk: Peer network discovery is out of scope; cross-genesis introductions require operator-configured policy."),
        ("spacer", ""),
        ("body", "<b>Replay attacks:</b> MeshEnvelope sequence numbers (monotonic u64); 16-byte random nonces in link handshake; Ed25519 signatures over content hashes. Residual risk: Depends on peers tracking seen sequence numbers."),
        ("spacer", ""),
        ("heading3", "6.2 What ZeroPoint Intentionally Does Not Solve"),
        ("body", "<b>It does not prevent a determined actor from building harmful systems.</b> The MIT/Apache-2.0 license is permissive. Constitutional rules constrain the framework's own behavior; they cannot constrain a fork."),
        ("spacer", ""),
        ("body", "<b>It does not make intelligence tools impossible.</b> Receipt infrastructure could be repurposed for surveillance. The Tenets and constitutional rules resist this, but they are a friction, not a wall."),
        ("spacer", ""),
        ("body", "<b>It does not provide universal truth verification.</b> Receipts prove that a statement was signed, not that the statement is true."),
        ("spacer", ""),
        ("body", "<b>It does not solve key discovery.</b> Key distribution is solved; key discovery is not."),
        ("spacer", ""),
        ("blockquote", "ZeroPoint produces proof. Proof makes systems refusable. This is a practical, enforceable improvement: counterparties can demand receipts and reject agents that do not provide them or that violate constraints."),
    ]
    add_section(story, "Threat Model", section6_content)

    # Implementation Status
    section8_content = [
        ("body", "ZeroPoint is implemented in Rust and is technically complete:"),
        ("list", [
            "<b>699 tests</b> (all passing, zero warnings)",
            "<b>13 crates</b> in a Cargo workspace",
            "<b>6 development phases</b> delivered",
            "<b>59 integration tests</b> covering multi-node and cross-transport scenarios",
            "<b>Full documentation</b> for all crates",
        ]),
        ("spacer", ""),
        ("body", "The workspace includes: zp-core (core types), zp-audit (hash-chained audit), zp-policy (PolicyEngine), zp-mesh (transport), zp-pipeline (GovernanceGate), zp-trust (trust tiers), zp-llm (LLM integration), zp-skills (SkillRegistry), zp-learning (feedback), zp-server (HTTP API), zp-cli (interactive terminal), zp-receipt (serialization), and execution-engine (governed execution)."),
    ]
    add_section(story, "Implementation Status", section8_content)

    # Adoption Paths
    section9_content = [
        ("body", "This project will not win by marketing. It will win by being useful and trustworthy to the right early communities."),
        ("spacer", ""),
        ("heading3", "9.1 First Adopters"),
        ("list", [
            "<b>Multi-agent system builders</b> — teams orchestrating autonomous agents who need protocol-level trust between operators.",
            "<b>Rust networking and security-oriented builders</b> — developers who understand why governance belongs in the substrate.",
            "<b>Decentralized infrastructure communities</b> — projects building sovereign, local-first systems. The Reticulum ecosystem is a natural fit.",
            "<b>Privacy-aligned agent tooling builders</b> — teams who need accountability without surveillance.",
            "<b>Enterprise AI governance teams</b> — organizations looking for verifiable, auditable behavior from agents and humans alike.",
            "<b>Accountable-process builders</b> — teams in journalism, supply chain, humanitarian operations, or organizational governance.",
        ]),
        ("spacer", ""),
        ("heading3", "9.2 Integration Patterns"),
        ("body", "<b>Pattern A: Governed Agent-to-Agent Exchange.</b> Agents exchange tasks and outputs only when receipts validate authorization."),
        ("spacer", ""),
        ("body", "<b>Pattern B: Policy-Gated Tool Execution.</b> A tool runner requires receipts demonstrating valid capability grants before executing."),
        ("spacer", ""),
        ("body", "<b>Pattern C: Delegation Chains.</b> A human operator grants a root capability. The agent delegates subsets to specialist sub-agents, each with narrower scope."),
        ("spacer", ""),
        ("body", "<b>Pattern D: Human-Accountable Workflows.</b> A human operator performs sensitive actions through ZeroPoint's governance pipeline. Every action produces a signed receipt."),
        ("spacer", ""),
        ("body", "<b>Pattern E: Mixed Human-Agent Systems.</b> A workflow involves both human and agent participants. Every step — human and agent — produces receipts. The audit chain is continuous regardless of who acted."),
    ]
    add_section(story, "Adoption Paths", section9_content)

    # Conclusion
    section12_content = [
        ("body", "AI agents are the most urgent application — but the accountability gap they expose is not theirs alone. Any system where actions have consequences and trust cannot be left to good faith needs the same properties: <b>cryptographic proof of attribution, sovereign refusal, auditable chains of authority.</b>"),
        ("spacer", ""),
        ("body", "The structural problem is clear: trust primitives that are captured by platforms become leverage for extraction. Identity that lives in someone else's database is not identity — it is a lease. Reputation that cannot be carried between systems is not reputation — it is a hostage. Authorization that can be silently revoked is not authorization — it is permission."),
        ("spacer", ""),
        ("body", "ZeroPoint provides <b>protocol-level primitives</b> — receipts, chains, governance constraints, and sovereign transport compatibility — that produce proof of any system's actions and make its participants refusable. It does not solve AI safety. It makes proof portable — and portable proof makes trust portable — and portable trust is the structural antidote to the dependency loops that degrade every system where exit is too expensive."),
        ("spacer", ""),
        ("blockquote", "Make proof portable, and trust follows. Make trust portable, and exit becomes real. Make exit real, and extraction becomes optional."),
        ("spacer", ""),
        ("blockquote", "Proof produces trust. Trust is infrastructure."),
        ("spacer", ""),
        ("blockquote", "Power will diffuse. Accountability must diffuse with it."),
    ]
    add_section(story, "Conclusion", section12_content)

    # Glossary (Appendix B)
    glossary_content = [
        ("body", "<b>Receipt:</b> Cryptographic proof of an action or decision, containing identity, content hash, policy decision, chain linkage, and Ed25519 signature."),
        ("spacer", ""),
        ("body", "<b>Chain:</b> Linked sequence of receipts forming an accountable history. Each receipt's pr field references the previous receipt's id."),
        ("spacer", ""),
        ("body", "<b>Capability Grant:</b> Cryptographically signed permission token granting an action scope, with constraints on time, cost, rate, and delegation depth."),
        ("spacer", ""),
        ("body", "<b>Delegation Chain:</b> Ordered sequence of capability grants from root (human-held) to leaf (most-delegated agent), verified against eight invariants."),
        ("spacer", ""),
        ("body", "<b>Policy:</b> Constraints governing capability use and system behavior, evaluated by the PolicyEngine in a fixed order."),
        ("spacer", ""),
        ("body", "<b>Constitutional Constraint:</b> Non-overridable rule embedded in the PolicyEngine — HarmPrincipleRule and SovereigntyRule — that cannot be removed, bypassed, or overridden."),
        ("spacer", ""),
        ("body", "<b>Guard:</b> Pre-action sovereignty check. Local-first, runs before the PolicyEngine, enforces the participant's right to refuse."),
        ("spacer", ""),
        ("body", "<b>GovernanceGate:</b> The pipeline through which every action must pass: Guard → Policy → Execute → Audit."),
        ("spacer", ""),
        ("body", "<b>Reticulum-compatible:</b> Wire-interoperable with Reticulum's HDLC framing, 128-bit destination hashing, Ed25519/X25519 cryptography, and 500-byte MTU."),
        ("spacer", ""),
        ("body", "<b>CompactReceipt:</b> MessagePack-encoded receipt using short field names, optimized for single-packet mesh transmission."),
        ("spacer", ""),
        ("body", "<b>GenesisKey:</b> Self-signed root of trust in the key hierarchy (one per deployment). Always held by a human."),
        ("spacer", ""),
        ("body", "<b>OperatorKey:</b> Signed by the GenesisKey. Represents a node operator in the key hierarchy."),
        ("spacer", ""),
        ("body", "<b>AgentKey:</b> Signed by an OperatorKey. Represents a single agent instance."),
        ("spacer", ""),
        ("body", "<b>Certificate Chain:</b> A sequence of signed certificates (genesis → operator → agent) that proves an agent's identity."),
    ]
    add_section(story, "Appendix B: Glossary", glossary_content)

    # Build PDF
    doc.build(story)
    print(f"PDF created successfully: {OUTPUT_PATH}")

    # Verify file
    if os.path.exists(OUTPUT_PATH) and os.path.getsize(OUTPUT_PATH) > 0:
        print(f"PDF file size: {os.path.getsize(OUTPUT_PATH)} bytes")
        return True
    else:
        print("Error: PDF file was not created or is empty")
        return False

if __name__ == "__main__":
    try:
        success = create_pdf()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"Error creating PDF: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
