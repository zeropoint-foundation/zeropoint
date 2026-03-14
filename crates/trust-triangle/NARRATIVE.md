# Trust Triangle — Narrative Script

*YouTube video script · ~4 minutes · mixed audience*

---

This is the Trust Triangle — an open source example implementation built on ZeroPoint, a cryptographic governance substrate for autonomous agent systems. It's one representation of what becomes possible when trust is portable.

Alex Chen opens their phone and asks a simple question:

**"Why is my prescription late?"**

That's it. One sentence. But answering it requires something that doesn't exist yet in the agent world — trust between strangers.

Alex's AI assistant doesn't know the answer. It doesn't have access to medical records or pharmacy databases. But it knows who might: a clinic where Alex has a follow-up scheduled, and a pharmacy where a doctor prescribed Alex's medication. Each runs its own AI system, controlled by a completely different organization. The clinic and pharmacy don't talk to each other — they don't need to. Alex's assistant is the one that needs to reach out to both.

Here's the problem: these three systems have never met. They don't share a database. They don't share a login. They don't even share the same cloud provider. They're strangers on the internet.

So how does Alex's assistant get answers from two organizations it has no relationship with?

---

## The Introduction

Before any data moves, the systems need to shake hands — cryptographically.

Each organization has what ZeroPoint calls a **genesis key**. Think of it like the root of a family tree. The clinic's genesis key belongs to MediCare Foundation. The pharmacy's belongs to QuickRx Holdings. Alex's assistant has one too, from Patient Cloud. Three separate roots. Three separate domains of trust.

From each genesis key, a chain of authority flows downward: genesis signs an operator key, the operator signs an agent key. Every agent carries this chain with them like a passport — a portable certificate chain that proves exactly who authorized them to act.

When Alex's assistant reaches out to the clinic, it doesn't just say "hey, give me data." It sends its certificate chain along with a challenge nonce. The clinic verifies the chain from leaf back to root, runs the request through its own policy engine, and — if everything checks out — sends back its own chain. Both sides now hold verified proof of the other's identity and authority.

No central directory was consulted. No shared database was queried. Two organizations that have never interacted before just established mutual trust using nothing but math and their own keys.

And here's what's crucial: the clinic made this decision *itself*. Its own policy engine evaluated the request and decided exactly what to share. Not a platform. Not a middleware layer. Not some SaaS vendor's access control dashboard. The clinic — the actual data owner — defined the rules, ran the evaluation, and controlled the outcome. That's the difference. Today, when organizations share data through platforms, the platform decides (or at least mediates) what gets shared. With ZeroPoint, the data owner's governance is the only governance. It travels with the data, not around it.

---

## The Data Exchange

Now trust is established, and the actual query happens.

Alex's assistant asks the clinic about patient-12345. The clinic looks up the record, applies its own policy, and sends back the answer: Alex's follow-up appointment was rescheduled from March 1st to March 8th.

But the clinic doesn't just send data. It sends a **signed receipt** — a cryptographic proof that this data access happened, recording what was accessed, by whom, under what policy, and when. The receipt's content is hashed with Blake3, and the hash is signed with Ed25519. If anyone changes a single byte later, the hash breaks. The signature proves who created it.

The same thing happens with the pharmacy. Introduction, policy evaluation, response, signed receipt. Alex's Lisinopril prescription was filled on March 4th and has been ready for pickup since the 5th.

---

## The Answer

Now Alex's assistant has both pieces of the puzzle. It synthesizes the answer:

*Your prescription was filled and is ready for pickup. Your follow-up appointment was rescheduled, which delayed the notification.*

Simple. Conversational. The kind of answer you'd expect from any good assistant.

But underneath that answer is something no AI assistant can produce today — a **provenance chain**. Four signed receipts, linked together: the original intent, the clinic access, the pharmacy access, and the synthesis. Three independent trust domains. Every step signed, hashed, and independently verifiable.

Anyone can check this chain after the fact. Did the clinic actually authorize this access? Verify the receipt. Did the pharmacy's policy engine approve the query? It's in the receipt. Was any data accessed beyond what was sanctioned? The sanitization counts are recorded and signed.

---

## What's Not Here

This is the part that matters most.

There's no platform in the middle. No API gateway that both organizations had to register with. No shared identity provider. No OAuth handshake through a third party. No vendor lock-in.

The clinic runs its own server. The pharmacy runs its own server. They make their own policy decisions using their own rules. The governance travels *with the data*, not through a platform that sits between them.

This is what portable trust infrastructure means. Trust that works over plain HTTPS between systems that have never met, governed by cryptography rather than contracts, verifiable by anyone without calling home to a central authority.

The agentic age is coming. Billions of AI agents will need to coordinate across organizational boundaries. The question isn't whether they'll exchange data — it's whether anyone will be able to prove what happened after the fact.

ZeroPoint makes the math do the work.

---

## Try It Yourself

Everything you just saw runs on your laptop. Three terminals, three organizations, zero cloud dependencies.

The Trust Triangle is one example of what you can build on ZeroPoint. Clone the repo, run the demo, and watch three independent trust domains coordinate in real time. Then start building your own. ZeroPoint's primitives — key hierarchies, portable certificates, signed receipts, policy engines — are designed to be embedded into any agent system that needs to cross organizational boundaries.

The Trust Triangle is healthcare. Your implementation could be supply chain, finance, legal, or anything where autonomous systems need to prove what happened. The substrate is the same.

**GitHub**: github.com/zeropoint-foundation/zeropoint
**Docs**: zeropoint.global
