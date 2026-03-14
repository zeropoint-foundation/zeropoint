#!/usr/bin/env python3
"""Generate ZeroPoint v2 Whitepaper PDF with updated text."""

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle, HRFlowable
from reportlab.lib import colors

WIDTH, HEIGHT = letter

def get_styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='CustomTitle', parent=styles['Heading1'], fontSize=28,
        textColor=colors.black, spaceAfter=12, alignment=TA_CENTER, fontName='Helvetica-Bold'))
    styles.add(ParagraphStyle(name='CustomSubtitle', parent=styles['Normal'], fontSize=14,
        textColor=colors.grey, spaceAfter=6, alignment=TA_CENTER, fontName='Helvetica'))
    styles.add(ParagraphStyle(name='CustomHeading', parent=styles['Heading1'], fontSize=14,
        textColor=colors.black, spaceAfter=12, spaceBefore=12, fontName='Helvetica-Bold'))
    styles.add(ParagraphStyle(name='CustomBlockquote', parent=styles['Normal'], fontSize=11,
        textColor=colors.HexColor('#333333'), spaceAfter=12, leftIndent=20, rightIndent=20,
        fontName='Helvetica-Oblique', alignment=TA_CENTER))
    styles.add(ParagraphStyle(name='CustomBody', parent=styles['Normal'], fontSize=11,
        leading=15, spaceAfter=12, alignment=TA_JUSTIFY, fontName='Helvetica'))
    return styles

class PageNumberCanvas:
    def __init__(self):
        self.page_num = 0
    def onPage(self, canvas, doc):
        self.page_num += 1
        canvas.saveState()
        canvas.setFont("Helvetica", 9)
        canvas.setFillColor(colors.HexColor('#666666'))
        canvas.drawString(0.5*inch, 0.5*inch, "ZeroPoint v2 Whitepaper v1.0 -- ThinkStream AI Labs -- February 2026")
        canvas.drawRightString(WIDTH-0.5*inch, 0.5*inch, f"Page {self.page_num}")
        canvas.restoreState()

def generate_pdf(output_path):
    doc = SimpleDocTemplate(output_path, pagesize=letter, rightMargin=0.75*inch,
        leftMargin=0.75*inch, topMargin=0.75*inch, bottomMargin=0.75*inch)
    story = []
    styles = get_styles()

    # PAGE 1: TITLE PAGE
    story.append(Spacer(1, 1.5*inch))
    story.append(Paragraph("ZeroPoint v2", styles['CustomTitle']))
    story.append(Spacer(1, 0.3*inch))
    story.append(Paragraph("Cryptographic Proof Primitives", styles['CustomSubtitle']))
    story.append(Paragraph("for Accountable Systems", styles['CustomSubtitle']))
    story.append(Spacer(1, 0.6*inch))
    story.append(Paragraph("Whitepaper v1.0 -- February 2026", styles['CustomBody']))
    story.append(Paragraph("Ken Romero, Founder, ThinkStream AI Labs", styles['CustomBody']))
    story.append(Spacer(1, 0.2*inch))
    story.append(Paragraph("Status: Public Technical Overview", styles['CustomBody']))
    story.append(Paragraph("License: CC BY 4.0 (text); MIT/Apache-2.0 (code)", styles['CustomBody']))
    story.append(Paragraph("https://zeropoint.global/whitepaper", styles['CustomBody']))
    story.append(Spacer(1, 0.4*inch))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.grey))
    story.append(Spacer(1, 0.3*inch))
    story.append(Paragraph('<b>How to cite:</b> Romero, Ken. "ZeroPoint v2: Cryptographic Proof Primitives for Accountable Systems." ThinkStream AI Labs, Whitepaper v1.0, February 2026.', styles['CustomBody']))
    story.append(PageBreak())

    # PAGE 2: CONTENTS
    story.append(Paragraph("Contents", styles['CustomHeading']))
    story.append(Spacer(1, 0.2*inch))
    for item in ["1. Problem Statement", "2. Design Goals", "3. System Overview", "4. Receipts and Chains",
                 "5. Governance Model", "6. Threat Model", "7. Transport Integrations", "8. Implementation Status",
                 "9. Adoption Paths", "10. Roadmap", "11. Ethics and Non-Goals", "12. Conclusion",
                 "Appendix A: Protocol Sketch", "Appendix B: Glossary", "Appendix C: Example Integration Pattern"]:
        story.append(Paragraph(item, styles['CustomBody']))
        story.append(Spacer(1, 0.08*inch))
    story.append(PageBreak())

    # PAGE 3+: ABSTRACT
    story.append(Paragraph("Abstract", styles['CustomHeading']))
    story.append(Spacer(1, 0.1*inch))
    story.append(Paragraph("""ZeroPoint v2 is a Rust framework that provides cryptographic governance primitives for any system
    where actions have consequences and trust cannot be left to good faith. It produces proof that actions
    are authorized, auditable, and policy-bound -- without requiring central control or relying on
    compliance-only frameworks. The protocol is participant-agnostic: the same receipts, capability chains,
    and constitutional constraints work whether the actor is a human, an AI agent, an automated service, or an
    IoT device -- and whether they communicate over HTTP, TCP, encrypted mesh networks, or any future
    transport.""", styles['CustomBody']))
    story.append(Spacer(1, 0.15*inch))
    story.append(Paragraph("""Autonomous AI agents are the most urgent application: agents are proliferating faster than the trust
    infrastructure to govern them, and ZeroPoint provides the cryptographic substrate they need. But the
    primitives are not agent-specific. Any participant that holds a keypair can sign receipts, hold capability
    grants, delegate authority, and exercise sovereign refusal.""", styles['CustomBody']))
    story.append(Spacer(1, 0.15*inch))
    story.append(Paragraph("""ZeroPoint v2 is technically complete: 623 tests across 11 crates, six delivered development phases,
    and full documentation. It ships with multiple transport integrations including a Reticulum-compatible
    mesh, TCP/UDP interfaces, and an HTTP API.""", styles['CustomBody']))
    story.append(Spacer(1, 0.15*inch))
    story.append(Paragraph("""ZeroPoint does not claim to "solve AI safety" or solve trust generally. It provides cryptographic
    primitives and governance constraints that produce proof of every action and make participants refusable.""", styles['CustomBody']))
    story.append(Spacer(1, 0.2*inch))

    # PROBLEM STATEMENT
    story.append(Paragraph("1. Problem Statement", styles['CustomHeading']))
    story.append(Spacer(1, 0.1*inch))
    story.append(Paragraph("""AI agents are rapidly becoming operational actors: they request tools, move data, execute workflows, and
    trigger external effects. They act at machine speed, across organizational boundaries, with delegation chains
    that can extend far beyond their original authority. Yet most systems today remain trust-light:""", styles['CustomBody']))
    story.append(Spacer(1, 0.1*inch))
    for bullet in ["<b>Actions are difficult to attribute reliably.</b> Logs are mutable, centralized, and easily rewritten.",
                   "<b>Authorization is informal and mutable.</b> Most systems rely on API keys rather than cryptographic capability grants.",
                   "<b>Logs are easy to forge, prune, or \"reinterpret.\"</b> No chain of evidence exists.",
                   "<b>Cross-party trust is brittle.</b> One party cannot safely accept another's outputs without out-of-band verification."]:
        story.append(Paragraph(f"• {bullet}", styles['CustomBody']))
        story.append(Spacer(1, 0.08*inch))
    story.append(Spacer(1, 0.15*inch))
    story.append(Paragraph("""These are not agent-specific problems. Agents inherited the accountability gap from systems humans were
    already building -- but they are accelerating it to the point where informal trust is no longer tenable.""", styles['CustomBody']))
    story.append(Spacer(1, 0.15*inch))
    story.append(Paragraph("Systems where actions have consequences require protocol-level accountability primitives, not only policy frameworks.", styles['CustomBlockquote']))
    story.append(Spacer(1, 0.15*inch))
    story.append(Paragraph("Not a governance framework you comply with -- a governance protocol you build on.", styles['CustomBlockquote']))
    story.append(Spacer(1, 0.2*inch))

    # DESIGN GOALS
    story.append(Paragraph("2. Design Goals", styles['CustomHeading']))
    story.append(Spacer(1, 0.1*inch))
    story.append(Paragraph("2.1 Protocol-Level Accountability", styles['CustomHeading']))
    story.append(Paragraph("""ZeroPoint produces verifiable receipts for actions and decisions -- regardless of whether the actor is an
    agent, a human, or a service. Receipts are chained -- each linking to its parent -- to create a durable
    accountability history.""", styles['CustomBody']))
    story.append(Spacer(1, 0.15*inch))
    story.append(Paragraph("2.2 Sovereignty by Design", styles['CustomHeading']))
    story.append(Paragraph("""Built to function where cloud assumptions are unsafe or unavailable. Governance primitives are
    transport-agnostic -- they work over HTTP in a data center, TCP between containers, or encrypted mesh
    links in a field deployment.""", styles['CustomBody']))
    story.append(Spacer(1, 0.15*inch))
    story.append(Paragraph("2.3 Governance as Constraints, Not Suggestions", styles['CustomHeading']))
    story.append(Paragraph("""Two constitutional rules -- HarmPrincipleRule and SovereigntyRule -- are non-removable and non-overridable.""", styles['CustomBody']))
    story.append(Spacer(1, 0.15*inch))
    story.append(Paragraph("2.4 Honest Security Posture", styles['CustomHeading']))
    story.append(Paragraph("Explicit about what it prevents, cannot prevent, and what remains residual risk.", styles['CustomBody']))
    story.append(Spacer(1, 0.15*inch))
    story.append(Paragraph("2.5 Transport Agnosticism and Interoperability", styles['CustomHeading']))
    story.append(Paragraph("""Governance layer is decoupled from any single transport. Ships with Reticulum-compatible mesh, TCP/UDP,
    and HTTP API. Designed to extend to any future transport without modifying governance primitives.""", styles['CustomBody']))
    story.append(Spacer(1, 0.2*inch))

    # SYSTEM OVERVIEW
    story.append(Paragraph("3. System Overview", styles['CustomHeading']))
    story.append(Spacer(1, 0.1*inch))
    for bullet in ["<b>Identity layer.</b> Ed25519 signing + X25519 key agreement.",
                   "<b>Governance layer.</b> PolicyEngine with constitutional rules, WASM modules, capability gating.",
                   "<b>Receipt layer.</b> Signed, hash-chained receipts. CompactReceipt: 150-300 bytes, efficient over any transport.",
                   "<b>Transport layer.</b> Pluggable: Reticulum-compatible mesh, TCP/UDP, HTTP API. Governance primitives are transport-independent.",
                   "<b>Application layer.</b> Pipeline orchestration, LLM integration, skill registry, CLI tooling."]:
        story.append(Paragraph(f"• {bullet}", styles['CustomBody']))
        story.append(Spacer(1, 0.08*inch))
    story.append(Spacer(1, 0.15*inch))
    story.append(Paragraph("3.1 Data Flow", styles['CustomHeading']))
    story.append(Spacer(1, 0.1*inch))
    for item in ['<b>1. Guard ("May I?")</b> -- Local-first sovereignty check.',
                 '<b>2. Policy ("Should I?")</b> -- Constitutional first, then operational, then WASM. Most restrictive wins.',
                 '<b>3. Execute</b> -- Runs only if Guard and Policy allow.',
                 '<b>4. Audit ("Did I?")</b> -- Receipt emitted: signed, timestamped, hash-linked.',
                 '<b>5. Transport</b> -- Receipts propagate to peers over whichever transport is configured.']:
        story.append(Paragraph(item, styles['CustomBody']))
        story.append(Spacer(1, 0.08*inch))
    story.append(Spacer(1, 0.15*inch))
    story.append(Paragraph("Every action becomes proof. Proof becomes a chain. The chain becomes shared truth.", styles['CustomBlockquote']))
    story.append(Spacer(1, 0.2*inch))

    # RECEIPTS AND CHAINS
    story.append(Paragraph("4. Receipts and Chains", styles['CustomHeading']))
    story.append(Spacer(1, 0.1*inch))
    story.append(Paragraph("4.1 What a Receipt Is", styles['CustomHeading']))
    story.append(Spacer(1, 0.1*inch))

    receipt_data = [
        ['Field', 'Wire', 'Description'],
        ['Receipt ID', 'id', 'Unique identifier'],
        ['Receipt Type', 'rt', 'execution, intent, approval, delegation, verification, refusal'],
        ['Status', 'st', 'success, partial, failed, denied, timeout, pending'],
        ['Trust Grade', 'tg', 'A, B, C, D'],
        ['Content Hash', 'ch', 'Blake3 hash'],
        ['Timestamp', 'ts', 'Unix seconds'],
        ['Parent Receipt', 'pr', 'Chain linkage (optional)'],
        ['Policy Decision', 'pd', 'allow, deny, escalate, audit'],
        ['Rationale', 'ra', 'Policy explanation'],
        ['Signature', 'sg', 'Ed25519 over content hash'],
        ['Extensions', 'ex', 'Domain-specific JSON'],
    ]
    table = Table(receipt_data, colWidths=[1.2*inch, 0.8*inch, 2.2*inch])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#cccccc')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 9),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f5f5f5')]),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    story.append(table)
    story.append(Spacer(1, 0.15*inch))
    story.append(Paragraph("""Encoded using MessagePack: 150-300 bytes typical. Efficient over any transport -- fits a single HTTP
    request, TCP frame, or 465-byte mesh packet.""", styles['CustomBody']))
    story.append(Spacer(1, 0.2*inch))

    story.append(Paragraph("4.2 What Receipts Prove vs. What They Don't", styles['CustomHeading']))
    story.append(Spacer(1, 0.1*inch))
    story.append(Paragraph("<b>Can prove:</b> a key signed a statement; a chain is consistent; policy engine evaluated a known rule set.", styles['CustomBody']))
    story.append(Spacer(1, 0.08*inch))
    story.append(Paragraph("<b>Cannot prove:</b> signer is human; action was \"good\"; environment uncompromised; result is truthful.", styles['CustomBody']))
    story.append(Spacer(1, 0.2*inch))

    # GOVERNANCE MODEL
    story.append(Paragraph("5. Governance Model", styles['CustomHeading']))
    story.append(Spacer(1, 0.1*inch))
    story.append(Paragraph("5.2 Capability Gating and Delegation", styles['CustomHeading']))
    story.append(Spacer(1, 0.1*inch))
    story.append(Paragraph("""CapabilityGrant: signed authorization token with scope, cost, rate, time, delegation depth, trust tier.
    Delegation chains verified against eight invariants:""", styles['CustomBody']))
    story.append(Spacer(1, 0.1*inch))
    for inv in ["1. Parent grant linkage", "2. Monotonic depth (0, 1, 2...)", "3. Scope subset",
                "4. Trust tier inheritance", "5. Expiration inheritance", "6. Max delegation depth",
                "7. Grantor-grantee match", "8. Ed25519 signature verification"]:
        story.append(Paragraph(inv, styles['CustomBody']))
        story.append(Spacer(1, 0.08*inch))
    story.append(Spacer(1, 0.15*inch))

    story.append(Paragraph("5.3 Constitutional Constraints", styles['CustomHeading']))
    story.append(Spacer(1, 0.1*inch))
    story.append(Paragraph("""<b>HarmPrincipleRule (Tenet I)</b> -- Blocks weaponization, surveillance, deception, suppression.
    Non-removable.""", styles['CustomBody']))
    story.append(Spacer(1, 0.1*inch))
    story.append(Paragraph("""<b>SovereigntyRule (Tenet II)</b> -- Blocks disabling guard, truncating audit, forging capabilities, removing
    constitutional rules.""", styles['CustomBody']))
    story.append(Spacer(1, 0.1*inch))
    story.append(Paragraph("""<b>Evaluation:</b> (1) HarmPrincipleRule, (2) SovereigntyRule, (3) ReputationGateRule, (4) WASM modules, (5)
    DefaultAllowRule. <b>Severity:</b> Block(5) > Review(4) > Warn(3) > Sanitize(2) > Allow(1).""", styles['CustomBody']))
    story.append(Spacer(1, 0.2*inch))

    # FOUR TENETS
    story.append(Paragraph("5.4 The Four Tenets", styles['CustomHeading']))
    story.append(Spacer(1, 0.1*inch))
    story.append(Paragraph("<b>I. Do No Harm.</b> Non-removable HarmPrincipleRule. Architecture is politics.", styles['CustomBody']))
    story.append(Spacer(1, 0.12*inch))
    story.append(Paragraph("<b>II. Sovereignty Is Sacred.</b> Every participant can refuse. Coercion is architecturally impossible.", styles['CustomBody']))
    story.append(Spacer(1, 0.12*inch))
    story.append(Paragraph("<b>III. Action Without Proof Is No Action.</b> Every action produces a receipt -- human or agent.", styles['CustomBody']))
    story.append(Spacer(1, 0.12*inch))
    story.append(Paragraph("<b>IV. The Human Is The Root.</b> Every chain terminates at a human-held key. The human at the root is a participant, not merely an overseer.", styles['CustomBody']))
    story.append(Spacer(1, 0.2*inch))

    # THREAT MODEL
    story.append(Paragraph("6. Threat Model", styles['CustomHeading']))
    story.append(Spacer(1, 0.1*inch))
    threat_data = [
        ['Threat', 'Mitigation', 'Residual Risk'],
        ['Log forgery', 'Ed25519 receipts + Blake3 chain; collective audit', 'Compromised keys sign lies'],
        ['Unauthorized tool use', 'CapabilityGrant + 8-invariant chain', 'Scoping depends on grant quality'],
        ['Cross-operator trust', 'Independent receipt verification', 'Key bootstrapping unsolved'],
        ['Security theater', 'Constitutional rules non-removable', 'Forks can gut constraints'],
        ['Surveillance co-option', 'Tenets + constitutional rules', "MIT/Apache can't prevent misuse"],
        ['Replay attacks', 'u64 sequence + 16-byte nonces', 'Long-offline gaps possible'],
        ['Injection attacks', 'HDLC CRC + Ed25519 + X25519', 'Unlinked broadcast unencrypted'],
        ['WASM escape', 'Fuel limiting + hash verification', 'Requires wasmtime vulnerability'],
        ['Identity misbinding', 'Trust tiers 0/1/2', 'Physical binding is external'],
    ]
    table = Table(threat_data, colWidths=[1.5*inch, 2.2*inch, 1.5*inch])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#cccccc')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 9),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 8),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f5f5f5')]),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    story.append(table)
    story.append(Spacer(1, 0.15*inch))
    story.append(Paragraph("ZeroPoint produces proof. Proof makes systems refusable.", styles['CustomBlockquote']))
    story.append(Spacer(1, 0.2*inch))

    # TRANSPORT INTEGRATIONS
    story.append(Paragraph("7. Transport Integrations", styles['CustomHeading']))
    story.append(Spacer(1, 0.1*inch))
    story.append(Paragraph("Governance primitives are transport-agnostic. The framework ships with several integrations:", styles['CustomBody']))
    story.append(Spacer(1, 0.15*inch))
    story.append(Paragraph("7.1 HTTP API", styles['CustomHeading']))
    story.append(Paragraph("Axum-based REST API. Standard HTTP/HTTPS for cloud, container, and web service deployments.", styles['CustomBody']))
    story.append(Spacer(1, 0.1*inch))
    story.append(Paragraph("7.2 TCP and UDP", styles['CustomHeading']))
    story.append(Paragraph("Direct socket communication with HDLC framing and CRC. Multiple interfaces run simultaneously.", styles['CustomBody']))
    story.append(Spacer(1, 0.1*inch))
    story.append(Paragraph("7.3 Reticulum-Compatible Mesh", styles['CustomHeading']))
    story.append(Paragraph("""Wire-level interop with Reticulum: HDLC/CRC-CCITT, 128-bit destination hashing, Ed25519/X25519,
    500-byte MTU, 3-packet handshake with 16-byte nonces. Philosophically aligned with Reticulum's
    commitment to sovereignty and harm minimization. Interop testing with MeshChat and NomadNet underway.""", styles['CustomBody']))
    story.append(Spacer(1, 0.1*inch))
    story.append(Paragraph("7.4 Extending to Other Transports", styles['CustomHeading']))
    story.append(Paragraph("""Implement the interface trait and provide envelope serialization. Governance primitives remain unchanged.
    Deployable over industrial IoT, satellite links, air-gapped networks, or standard enterprise infrastructure.""", styles['CustomBody']))
    story.append(Spacer(1, 0.2*inch))

    # IMPLEMENTATION STATUS
    story.append(Paragraph("8. Implementation Status", styles['CustomHeading']))
    story.append(Spacer(1, 0.1*inch))
    story.append(Paragraph("623 tests (all passing), 11 crates, 6 phases, 59 integration tests.", styles['CustomBody']))
    story.append(Spacer(1, 0.15*inch))
    impl_data = [
        ['Crate', 'Purpose'],
        ['zp-core', 'CapabilityGrant, DelegationChain, GovernanceEvent, Blake3, Ed25519'],
        ['zp-audit', 'Hash-chained audit, chain verification, collective audit'],
        ['zp-policy', 'PolicyEngine, constitutional rules, WASM runtime'],
        ['zp-mesh', 'Transport: MeshNode, pluggable interfaces (TCP, UDP, serial), Reticulum-compatible mesh, CompactReceipt, consensus, reputation'],
        ['zp-pipeline', 'GovernanceGate, MeshBridge, 14-step action flow'],
        ['zp-trust', 'Trust tiers (0/1/2), grade computation'],
        ['zp-llm', 'LLM provider abstraction'],
        ['zp-skills', 'SkillRegistry, SkillMatcher'],
        ['zp-learning', 'Feedback collection, outcome tracking'],
        ['zp-server', 'HTTP API (Axum)'],
        ['zp-cli', 'Terminal: chat, guard, mesh, audit, delegation'],
    ]
    table = Table(impl_data, colWidths=[1.2*inch, 3.8*inch])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#cccccc')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 9),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 8),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f5f5f5')]),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    story.append(table)
    story.append(Spacer(1, 0.2*inch))

    # ADOPTION PATHS
    story.append(Paragraph("9. Adoption Paths", styles['CustomHeading']))
    story.append(Spacer(1, 0.1*inch))
    story.append(Paragraph("""First adopters: multi-agent system builders, Rust security developers, decentralized infrastructure projects,
    privacy-aligned agent tooling teams, enterprise AI governance teams, and accountable-process builders in
    journalism, supply chain, and humanitarian operations.""", styles['CustomBody']))
    story.append(Spacer(1, 0.15*inch))
    for pattern in ["<b>Pattern A:</b> Governed agent-to-agent exchange via receipt validation.",
                    "<b>Pattern B:</b> Policy-gated tool execution via capability chain proof.",
                    "<b>Pattern C:</b> Delegation chains with narrowing scope from human root.",
                    "<b>Pattern D:</b> Human-accountable workflows -- teams using receipts and chains for provable organizational decisions, no agents required.",
                    "<b>Pattern E:</b> Mixed human-agent systems -- humans and agents as peers in the same governance substrate, over Reticulum or any transport."]:
        story.append(Paragraph(f"• {pattern}", styles['CustomBody']))
        story.append(Spacer(1, 0.08*inch))
    story.append(Spacer(1, 0.2*inch))

    # ROADMAP
    story.append(Paragraph("10. Roadmap", styles['CustomHeading']))
    story.append(Spacer(1, 0.1*inch))
    for item in ["1. Public repository + crates.io publish",
                 "2. Transport integration test suite (incl. Reticulum interop)",
                 "3. Threat model expansion + key revocation",
                 "4. Example applications",
                 "5. Sustainability layer"]:
        story.append(Paragraph(item, styles['CustomBody']))
        story.append(Spacer(1, 0.08*inch))
    story.append(Spacer(1, 0.2*inch))

    # ETHICS
    story.append(Paragraph("11. Ethics and Non-Goals", styles['CustomHeading']))
    story.append(Spacer(1, 0.1*inch))
    story.append(Paragraph("""Constitutional constraints are non-removable. Public tenets are first in the PolicyEngine. Protocol frames
    accountability of actions, not control of people. Non-goals: compliance product, centralized authority,
    preventing all misuse, dependence on any single transport, agent-only infrastructure.""", styles['CustomBody']))
    story.append(Spacer(1, 0.2*inch))

    # CONCLUSION
    story.append(Paragraph("12. Conclusion", styles['CustomHeading']))
    story.append(Spacer(1, 0.1*inch))
    story.append(Paragraph("""ZeroPoint v2 provides protocol-level primitives -- receipts, chains, governance constraints, sovereign
    transport -- that produce proof of any system's actions and make participants refusable. Agents are the most
    urgent application, but the protocol serves everyone who participates in systems where trust matters. It does
    not solve AI safety or trust generally. Proof produces trust. Trust is infrastructure.""", styles['CustomBody']))
    story.append(Spacer(1, 0.15*inch))
    story.append(Paragraph("The tool is never neutral. We have chosen our side.", styles['CustomBlockquote']))
    story.append(Spacer(1, 0.1*inch))
    story.append(Paragraph("Power will diffuse. Accountability must diffuse with it.", styles['CustomBlockquote']))
    story.append(Spacer(1, 0.2*inch))
    story.append(Paragraph("ZeroPoint v2 -- ThinkStream AI Labs -- ken@thinkstreamlabs.ai -- https://zeropoint.global", styles['CustomBody']))
    story.append(Spacer(1, 0.05*inch))
    story.append(Paragraph("CC BY 4.0 (text) -- MIT/Apache-2.0 (code)", styles['CustomBody']))

    # Build PDF
    page_canvas = PageNumberCanvas()
    doc.build(story, onFirstPage=page_canvas.onPage, onLaterPages=page_canvas.onPage)
    print(f"SUCCESS: PDF generated at {output_path}")

if __name__ == '__main__':
    import sys
    output = sys.argv[1] if len(sys.argv) > 1 else 'ZeroPoint_Whitepaper_v1.0.pdf'
    generate_pdf(output)
