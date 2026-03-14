# ZEROPOINT

## Portable Trust for the Agentic Age

**Ken Romero**
**Founder, ThinkStream Labs**

*Draft — March 2026*

---

# PART I — THE STAKES

---

## Chapter 1: The Accountability Gap

Something broke in the contract between humans and their tools.

For most of technological history, a tool did what you told it to do, and nothing else. A hammer drove nails. A calculator returned sums. Even early software — rigid, sequential, predictable — operated within boundaries its operator could understand and verify. You could look at the output and trace it back to an input. Accountability was trivial because agency was absent.

That era is over.

Autonomous agents now negotiate contracts, execute trades, manage infrastructure, write and deploy code, communicate with other agents, and make decisions that affect human lives — often without a human in the loop, often without a human even aware that a decision was made. The agent doesn't just do what you told it to do. It interprets, plans, delegates, improvises. It operates in environments you didn't anticipate, interacts with systems you didn't specify, and produces outcomes you didn't predict.

This is not a complaint. Agent autonomy is the point. You deploy agents precisely because they can handle complexity that humans cannot. The question is not whether agents should act autonomously. The question is what happens when they do.

And the answer, right now, is: nobody knows.

When an autonomous agent takes an action — approves a loan, dispatches a vehicle, modifies a medical record, executes a trade, sends a message on your behalf — there is no standard mechanism to prove what happened. No cryptographic evidence that the action was authorized. No verifiable chain showing who delegated what authority under what constraints. No immutable record that the agent operated within the boundaries it was given. There are logs, sometimes. There are dashboards, occasionally. There are audit trails that exist only as long as the server is running and only as honest as the operator who configured them.

This is the accountability gap. Not a gap in capability — agents are extraordinarily capable. Not a gap in intention — most operators mean well. A gap in proof. When something goes wrong, and something always goes wrong, there is no mechanism to reconstruct with cryptographic certainty what happened, who authorized it, and whether the constraints that were supposed to apply actually applied.

The gap exists because the infrastructure was never built. Every other layer of the technology stack has matured: we have sophisticated frameworks for building agents, powerful models for reasoning, elaborate orchestration systems for coordinating multi-agent workflows. But the trust layer — the infrastructure that makes actions provable, authority verifiable, and accountability structural rather than aspirational — does not exist.

What exists instead are workarounds. Vendor-specific logging that lives in someone else's database. API key gating that controls access but says nothing about what happened after access was granted. Role-based permissions that authorize categories of action but cannot constrain the specifics. Sandboxing that contains execution but cannot prove what occurred inside the sandbox. Compliance checklists that document intentions but not outcomes. These are the tools of an earlier era, designed for systems where the software did what you told it to do and nothing else.

They are not enough for systems that act.

The consequences of this gap are already visible, even if they haven't yet made headlines proportional to their significance. Every organization deploying autonomous agents is, at this moment, operating on faith. Faith that the agent stayed within bounds. Faith that the logs are complete. Faith that the audit trail hasn't been tampered with. Faith that the authority chain is intact. This is not how serious infrastructure works. You do not operate a power grid on faith. You do not manage financial markets on faith. You do not build bridges on faith. You build them on verifiable engineering, and you prove they work with evidence that any qualified observer can independently check.

The Agentic Age deserves the same standard. Not because agents are dangerous — they are tools, and like all tools, they reflect the values embedded in their architecture. But because systems that act on behalf of humans, with consequences for humans, must be systems whose actions can be proven. Accountability is not a constraint on autonomy. It is the foundation of it. An agent whose actions can be verified is an agent you can trust to act. An agent whose actions cannot be verified is an agent you should worry about, no matter how sophisticated its reasoning or how earnest its operator's intentions.

This book describes the infrastructure that closes that gap.

---

## Chapter 2: The Four Tenets

Every system encodes values, whether its builders acknowledge it or not.

A database that stores trust scores in a vendor-controlled server encodes the value that trust is someone else's property. A permissions system that can be overridden by an administrator encodes the value that hierarchy trumps sovereignty. A logging system that can be truncated or selectively edited encodes the value that the past is negotiable. An agent framework that provides no mechanism for a participant to refuse an action encodes the value that compliance is more important than consent.

These are not neutral engineering decisions. They are political acts expressed in code. Architecture is politics. A tool is never neutral. These observations, articulated by Mark Qvist in the creation of the Reticulum Network Stack, are the philosophical foundation on which ZeroPoint is built.

If architecture encodes values, then the values must be chosen deliberately, stated explicitly, and enforced structurally. Not as aspirational principles in a README that no one reads. Not as policy preferences that an operator can override when they become inconvenient. As constitutional law — embedded in the protocol, expressed in the license, enforced in the code — that no capability grant, no policy rule, no consensus vote can override.

ZeroPoint rests on four such tenets.

### I. Do No Harm

ZeroPoint shall not operate in systems designed to harm humans.

This is not a policy preference. It is a structural commitment encoded as a non-removable rule in the policy engine. The HarmPrincipleRule evaluates every action before it executes. It cannot be bypassed, overridden, or removed at runtime. It exists at the constitutional layer of the system — loaded first, evaluated first, immutable by design. No operator configuration, no WASM policy module, no consensus vote among peers can weaken or remove it.

The tenet is inspired by Reticulum's Harm Principle: that the builders of a tool bear responsibility for the uses their architecture enables, and that protective constraints are an act of conscience, not a limitation of capability. Qvist proved that you can build a planetary-scale encrypted network that refuses, by design, to enable surveillance and harm — and that this refusal makes the network stronger, not weaker, because the participants can trust the infrastructure they're building on.

ZeroPoint carries this principle into governance. The HarmPrincipleRule evaluates actions against four categories: weaponization, surveillance, deception, and the undermining of human autonomy. When an action falls into one of these categories, the system does not warn. It does not escalate. It blocks. And it produces a receipt proving that it blocked, and why.

This is the floor. Everything else in ZeroPoint is configurable, composable, negotiable between peers. This is not.

### II. Sovereignty Is Sacred

Every participant has the right to refuse any action. Every human has the right to disconnect any agent. No participant may acquire capabilities it was not granted. No human may be compelled to grant capabilities.

Coercion is not merely prohibited — it is architecturally impossible. The Guard, ZeroPoint's pre-action sovereignty boundary, runs locally before every action, without consulting any external authority. It enforces the participant's boundaries before the network, the operator, or any other peer has a voice. A peer can request. A peer cannot compel.

This tenet applies symmetrically. It is not a constraint imposed on agents by humans. It is a right shared by every participant in the system. An agent operating under ZeroPoint has the architectural right to refuse an action that violates its boundaries, just as the human at the root has the right to revoke any delegation at any time. Sovereignty is the precondition for trust. The participant that can say no is the one you can trust. The one that cannot is the one you should worry about.

The symmetry matters because it prevents the governance system itself from becoming an instrument of control. A system where only humans have sovereignty and agents have only compliance is not a governance system — it is a command system wearing a governance mask. ZeroPoint's claim is more radical: that genuine accountability requires genuine agency, and genuine agency requires the structural right to refuse.

### III. Action Without Evidence Is No Action

Every action produces a receipt. Every receipt joins a chain. No participant may act without leaving a cryptographic trace.

This is the tenet that distinguishes ZeroPoint from every governance framework that relies on logging. Logs are records that someone chose to keep. They can be incomplete, selective, edited, truncated, or fabricated. They live in databases controlled by operators who have every incentive to present a favorable picture and the technical ability to ensure they do.

Receipts are different. A ZeroPoint receipt is a signed, hash-chained cryptographic artifact that proves an action occurred, who authorized it, what constraints applied, and what the outcome was. Each receipt references the previous receipt in the chain, making the entire history tamper-evident. Remove a receipt and the chain breaks. Modify a receipt and its hash no longer matches. The evidence is not kept by the operator — it is produced by the protocol, automatically, for every significant action, and it can be verified by any peer who has the actor's public key.

Governance without evidence is not governance. It is storytelling. The audit chain is the single source of truth. It cannot be edited, reordered, truncated, or selectively forgotten. If it is not in the chain, it did not happen. If it is in the chain, it cannot un-happen.

### IV. The Human Is The Root

Every delegation chain terminates at a human-held key. No agent may self-authorize. No agent may forge a delegation chain. The genesis key is always held by flesh, blood, and soul.

An agent's authority flows from the human who created it, through a verifiable chain of signed capability grants. Each link in the chain is cryptographically signed by the grantor, constrained by the terms of the grant, and independently verifiable by any observer. Break the chain and the authority dissolves. This is not a limitation on agent autonomy — it is the foundation of it.

The genesis key — the root of every delegation chain — is generated by a human, stored by a human, and controlled by a human. It cannot be generated by the system. It cannot be held in escrow. It cannot be transferred to an automated process. This is the structural assertion that machines derive their authority from people, not the reverse.

And the human at the root is not merely an overseer. They are a participant whose own actions are equally provable, equally auditable, and equally bound by the protocol's constitutional constraints. The Tenets do not create a hierarchy of humans above agents. They create a system where every participant — human, agent, service, or device — operates under the same cryptographic accountability, with the single asymmetry that the originating authority is always human.

This is the deepest commitment ZeroPoint makes: that in the Agentic Age, the chain of authority must always lead back to a person. Not an institution. Not a corporation. Not a government. A person, holding a key, bearing responsibility for what that key authorizes.

---

## Chapter 3: Proof Produces Trust

Trust is the most abused word in technology.

Vendors speak of "trusted platforms" — meaning platforms they control. Security frameworks describe "trust boundaries" — meaning perimeters they monitor. Identity providers offer "trust scores" — meaning numbers they compute, using algorithms they designed, from data they collected, stored in databases they own. In every case, "trust" means "you are depending on us, and you cannot verify our claims independently."

This is not trust. This is dependency dressed in reassuring language.

Trust, in the sense that matters for infrastructure, is a relationship grounded in evidence. I trust the bridge because an engineer verified its load capacity and I can inspect the certification. I trust the financial statement because an auditor examined the books and signed an attestation. I trust the election result because observers from multiple parties watched the counting and the ballots can be recounted. In each case, trust is not a feeling. It is not a score. It is not a brand reputation. Trust is the product of verifiable proof that can be independently checked by any qualified observer.

ZeroPoint applies this principle to digital action. Every significant action in the system produces a cryptographic receipt — signed by the actor's Ed25519 key, hash-chained to the previous receipt, containing the full context of what happened, who authorized it, and what constraints applied. The receipt is not a log entry that someone chose to record. It is a cryptographic artifact that the protocol produces automatically, that any peer can verify, and that no operator can forge, suppress, or retroactively modify.

This is the core thesis: proof produces trust. Not the other way around. Not "trust first, then maybe verify." Proof first. Trust follows. And if the proof is absent — if the receipt chain is broken, if the signatures don't verify, if the delegation chain can't be traced back to a human — then trust is absent too, regardless of the brand, the reputation, or the promises.

The implications of this inversion are structural, not cosmetic.

When proof produces trust, trust becomes portable. The receipt travels with the work, not with the vendor. An agent that performed a governed action on Platform A can prove it to Platform B without Platform A's cooperation, because the proof is cryptographic, not institutional. The receipt contains the signatures, the chain references, and the capability grants that any verifier can check independently. This means an agent's track record — its history of operating within constraints, producing valid receipts, honoring its delegation chains — belongs to the agent and the human who authorized it, not to the platform that hosted the execution.

When proof produces trust, trust becomes auditable. Not auditable in the sense of "we hired a firm to look at our logs" — auditable in the sense that any peer in the network can challenge another peer's audit chain, receive a compact proof, and independently verify that the chain is intact and the signatures are valid. The audit is not a periodic review conducted by a privileged observer. It is a continuous, distributed, cryptographic verification that any participant can perform at any time.

When proof produces trust, exit becomes possible. Today, if you run agents on a platform, your governance data — the trust scores, the audit logs, the permission histories — is locked in the platform's database. Leaving the platform means leaving your governance history behind. This creates a lock-in effect that has nothing to do with technical capability and everything to do with who controls the evidence. When the evidence is cryptographic and portable, when your agent carries its own proof of good behavior, switching platforms costs you nothing in trust. You take your receipts with you.

This is what ZeroPoint offers: not a governance framework you comply with, but governance infrastructure you build on. Cryptographic primitives that produce verifiable proof of every action, make that proof portable across platforms and networks, and ensure that the accountability record belongs to the participants, not the intermediaries.

Proof produces trust. Trust is infrastructure. And infrastructure, properly built, is the foundation on which prosperity becomes possible.

---

# PART II — THE WORLD AS IT IS

---

## Chapter 4: The Architecture of Control

To understand what ZeroPoint changes, you must first understand what it replaces. Not because the existing tools are bad — many are well-engineered solutions to real problems — but because they share assumptions about power, ownership, and verification that produce a particular kind of world. Understanding those assumptions is the prerequisite for understanding why different architectural choices produce a different world.

### The API Key: Access Without Accountability

The dominant model for agent authorization is the API key. You generate a key. You give it to an agent. The agent presents the key when it wants to act. The platform checks the key against a database, confirms it's valid, and permits the action.

This solves the access problem. It does not solve the accountability problem.

An API key proves that the presenter was authorized to access the system. It does not prove what the presenter did once inside. It does not constrain the scope of action beyond the coarse permissions attached to the key. It does not produce cryptographic evidence of what occurred. It does not create a verifiable chain linking the action back to the human who authorized the key's creation. And critically, it does not travel. When the key is revoked or the platform is changed, the entire history of what that key authorized vanishes from the agent's provenance.

The API key is an entry ticket, not a governance mechanism. It tells you who walked through the door. It says nothing about what happened inside the room.

### Role-Based Access: Categories Without Constraints

The next layer of conventional governance is role-based access control. An agent is assigned a role — reader, writer, administrator — and the role determines what categories of action are permitted. This is a refinement of the API key model: instead of a binary "authorized or not," the system distinguishes between types of authorization.

But roles are blunt instruments. A "writer" role authorizes all write operations, without distinguishing between writing a routine log entry and overwriting a critical configuration file. A "reader" role authorizes all read operations, without distinguishing between accessing public data and accessing private medical records. The granularity that real governance requires — this agent may write to this specific scope, under this cost ceiling, during these hours, with this rate limit, and every action must produce a receipt — is not expressible in a role. Roles describe categories. Governance requires constraints.

Roles also share the portability problem. They exist in the platform's database. They do not travel with the agent. When the agent moves to a new platform, its role history — the accumulated evidence that it operated within its role boundaries — stays behind.

### Centralized Logging: Records Without Proof

Every serious deployment generates logs. Application logs, access logs, audit logs, security logs. These are valuable operational tools. They are not governance infrastructure.

A log is a record that someone chose to keep, stored in a system that someone controls, in a format that someone defined. The person who controls the logging system controls the narrative. They decide what gets logged and what doesn't. They decide how long logs are retained. They decide who can read them and who can modify them. In many systems, the operator can edit or delete log entries without leaving a trace. Even in systems with "immutable" logging, the immutability is typically enforced by access controls — which means it's only as strong as the access control system, which is controlled by the same operator.

This is not a conspiracy theory about dishonest operators. Most operators are honest. The problem is structural: a governance system where the evidence of compliance is controlled by the entity being evaluated is not a governance system. It is a trust-me arrangement. And trust-me arrangements work until they don't.

The alternative is not to distrust operators. The alternative is to make trust unnecessary by making proof automatic. If every action produces a cryptographic receipt, signed by the actor and hash-chained to the previous receipt, then the evidence of governance is not controlled by anyone. It is produced by the protocol, verifiable by any peer, and tamper-evident by construction. The operator doesn't need to be trusted because the operator doesn't control the evidence.

### Sandboxing: Containment Without Verification

Sandboxing is the containment model: restrict what an agent can do by limiting its execution environment. Docker containers, gVisor, seccomp profiles, capability-based security at the OS level. These are real, valuable security mechanisms. They prevent an agent from escaping its execution boundary and accessing resources it shouldn't.

But sandboxing solves the containment problem, not the accountability problem. A sandbox proves that an agent could not have accessed a resource outside its boundary. It does not prove what the agent did within the boundary. It does not produce a receipt of actions taken. It does not verify that the agent operated within the constraints of its authorization, as opposed to merely within the constraints of its container. An agent that stays inside its sandbox but exceeds its cost ceiling, violates its rate limits, ignores its scope restrictions, or takes actions that weren't authorized by its delegation chain has obeyed its container and violated its governance. The sandbox doesn't know the difference because the sandbox doesn't know about governance. It knows about system calls.

### Trust Scores: Numbers Without Sovereignty

Some systems address the trust problem by computing trust scores. An agent's behavior is observed, scored across various dimensions — reliability, safety, compliance, accuracy — and the score determines what the agent is permitted to do. Higher scores unlock more capabilities. Lower scores restrict them.

This model has three structural problems.

First, the scorer controls the score. Whoever designs the scoring algorithm, selects the dimensions, sets the weights, and curates the training data determines what "trustworthy" means. This is not measurement. It is definition, by an entity with its own interests, encoded in mathematics that most participants cannot inspect.

Second, scores are not portable. The trust score computed by Platform A is meaningless on Platform B, which uses different dimensions, different algorithms, and different data. An agent that earned a high trust score through years of reliable operation on one platform starts from zero on another. The score is not a property of the agent. It is a property of the platform's opinion of the agent, which is a very different thing.

Third, and most fundamentally, trust scores strip sovereignty from the scored. The agent does not choose its score. The agent does not control the algorithm. The agent cannot challenge the computation. The scored party is a subject, not a participant. This is the power arrangement that role-based systems and reputation systems both encode: the platform evaluates, the agent complies, and the evaluation is not negotiable.

### The Common Thread

These tools — API keys, role-based access, centralized logging, sandboxing, trust scores — are not failures. They are honest attempts to govern complex systems with the tools available. But they share assumptions that, once made explicit, reveal the world they produce:

Trust lives in a database someone else controls. Whether it's the API key database, the role assignment table, the log storage system, or the trust score engine, the evidence of governance is held by an intermediary. The participant does not own their own accountability record.

Audit is reconstruction, not production. The evidence of what happened must be assembled after the fact, from scattered logs and access records, by an observer with sufficient privilege. It is not produced automatically, at the moment of action, as a cryptographic artifact that any peer can verify.

Governance is binary. You're authorized or you're not. You're inside the sandbox or you're not. Your trust score is above the threshold or it isn't. The nuanced decisions that real governance requires — proceed but with caution, proceed but with redaction, proceed only after human review — are not expressible.

Exit is impossible. When the evidence of your governance history is locked in someone else's database, leaving the platform means leaving your history behind. The vendor lock-in is not in the code. It is in the evidence.

These are not inevitable properties of digital governance. They are properties of a specific set of architectural choices. Different choices produce a different world.

---

## Chapter 5: What ZeroPoint Changes

ZeroPoint does not improve the existing model. It replaces the assumptions.

Each departure is simultaneously a technical decision and a philosophical one, because the architecture produces the politics. You cannot separate the engineering from the values it encodes. A system that produces portable cryptographic proof of every action is not just "better logging." It is a structural redistribution of power from the platforms that host execution to the participants who perform it. This chapter describes each departure, what it replaces, and what it gives you — technically and structurally.

### Receipts Instead of Logs

In conventional systems, evidence of what happened is a log entry: a line of text, written to a file, stored on a server, controlled by an operator. In ZeroPoint, evidence of what happened is a receipt: a signed, hash-chained cryptographic artifact that proves the action occurred, identifies who performed it, specifies who authorized it, records what constraints applied, and links to the previous receipt in an unbroken chain.

The technical difference is cryptographic integrity. A receipt is signed with the actor's Ed25519 private key, so its authorship is verifiable. It is hashed with Blake3 and chained to the previous receipt's hash, so the sequence is tamper-evident. It uses canonical JSON serialization — deterministic, sorted keys — so that any peer computing the hash from the same data will produce the same result. This is not a log that an operator can edit. It is a mathematical proof that no one can forge.

The structural difference is ownership. Logs belong to the operator. Receipts belong to the protocol. They are produced automatically, for every significant action, whether the operator wants them or not. They travel with the agent, not with the platform. They are verifiable by any peer who has the actor's public key, without the cooperation of the operator who hosted the execution.

What this gives you: an accountability record that you own, that you can carry between platforms, that any third party can verify, and that no intermediary can tamper with. Your agent's history of governed action becomes a portable credential, not a vendor-locked data point.

### Graduated Decisions Instead of Binary Gates

Conventional governance is binary: allowed or denied. Permitted or blocked. Inside the sandbox or outside it. This simplicity is its strength for access control and its weakness for governance. Real governance is rarely binary.

ZeroPoint's policy engine produces one of five graduated decisions, ordered by severity: Allow, Sanitize, Warn, Review, and Block. Each represents a different governance posture:

Allow means proceed, optionally with conditions attached. Sanitize means proceed, but redact sensitive patterns from the output before it leaves the system. Warn means proceed, but notify the agent, the operator, or both — and optionally require acknowledgment before continuing. Review means pause: a designated human reviewer must examine and approve the action within a timeout period. Block means refuse, log the refusal, and produce a receipt proving the refusal.

The most restrictive applicable decision always wins. If three policy rules evaluate an action and one says Allow, one says Warn, and one says Block, the result is Block. This is severity monotonicity: governance can only tighten, never loosen.

What this gives you: the ability to express governance nuance. "Yes, but carefully." "Yes, but redacted." "Not without a human looking at this first." These are the real decisions that operators face daily, and they are not expressible in a binary gate.

### Capability Grants Instead of Role-Based Permissions

Roles describe categories: this agent is a "reader" or a "writer." Capability grants describe specific, constrained authorizations: this agent may read files matching this glob pattern, may write to these specific API endpoints with a cost ceiling of this amount per action, at a rate of no more than this many actions per this time window, and every action must produce a receipt.

A capability grant is a signed, portable token. It specifies the capability being granted (Read, Write, Execute, ApiCall, CredentialAccess, ConfigChange, MeshSend, or a custom capability), the constraints that apply (cost ceilings, rate limits, scope restrictions, time windows, receipt requirements, escalation requirements), who granted it, who received it, and when it expires. It is signed by the grantor's Ed25519 key, making it verifiable by any peer.

The critical difference from roles is that grants are portable. They travel with the agent. They do not live in a platform's database. Any peer that has the grantor's public key can verify that the grant is authentic and that the agent is operating within its constraints. When the agent moves to a new platform, its capability grants move with it.

What this gives you: fine-grained, portable, cryptographically verifiable authorization that expresses real operational constraints, not just categorical permissions. The authority belongs to the agent, not to the platform.

### Delegation Chains Instead of Administrative Assignment

In conventional systems, authority is assigned by an administrator. Someone with the right platform credentials gives the agent its permissions. The assignment exists in the platform's database. The chain of authority — who decided this agent should have these permissions, and why, and under what constraints — is implicit, informal, and often undocumented.

In ZeroPoint, authority flows through a cryptographic delegation chain. The genesis key (held by a human) issues an operator key. The operator key issues an agent key. Each link in the chain is a signed certificate that binds a public key to a role and a set of constraints. Eight invariants are enforced at every link: each grant references its parent, delegation depths increase monotonically, each child's scope is a subset of the parent's scope, each child's trust tier is at least as restrictive as the parent's, no child grant outlives its parent, the chain cannot exceed the maximum delegation depth set by the root, each grantor matches the previous grantee, and all signatures verify.

The chain is independently verifiable. Any peer can walk the chain from the agent's key back to the genesis key and verify that every link is valid, every constraint is respected, and the authority terminates at a human. If any link is broken — a signature doesn't verify, a scope exceeds its parent, a grant has expired — the entire chain is invalid and the authority dissolves.

What this gives you: verifiable provenance of authority. Not "the admin gave this agent writer permissions" but "this specific human, holding this specific key, authorized this specific operator, who authorized this specific agent, with these specific constraints, each tighter than or equal to the previous, and every link is cryptographically signed and independently verifiable." The difference is the difference between "trust me, the permissions are right" and "here's the math."

### Constitutional Rules Instead of Configurable Policies

Most governance systems allow the operator to configure all policy rules. This makes sense for operational flexibility — different deployments have different requirements. But it also means that every rule, including the ones that protect against harm, can be weakened or removed by the operator. The fox configures its own henhouse.

ZeroPoint separates constitutional rules from operational rules. Constitutional rules — the HarmPrincipleRule and the SovereigntyRule — are loaded first, evaluated first, and cannot be overridden, weakened, or removed by any mechanism available at runtime. No operator configuration, no WASM policy module, no consensus vote among peers can bypass them. They are embedded in the protocol at the code level.

Operational rules are fully configurable. You can add rules, compose rules, deploy WASM policy modules that peers exchange and evaluate in sandboxed environments. The policy engine is designed for extensibility. But the constitutional floor is immovable. Operational rules can only tighten constraints beyond the constitutional baseline; they cannot loosen them.

What this gives you: a governance system with a guaranteed floor. No matter who operates the node, no matter what policies they configure, no matter what WASM modules they load, the system will not operate in ways designed to harm humans, and it will not override any participant's right to refuse. This is not a promise. It is a structural property of the code. The assurance comes not from the operator's character but from the architecture's constraints.

### Tiers Instead of Scores

Trust scores are computed by a central authority, using an opaque algorithm, producing a number that the scored party cannot control or verify. Trust tiers in ZeroPoint are based on cryptographic capability — what you can prove about your identity, not what someone else computed about your behavior.

Tier 0 means unsigned. The agent exists but cannot prove anything about itself cryptographically. Trust is limited to filesystem-level control: you trust it because it's running on your machine.

Tier 1 means self-signed. The agent has a local Ed25519 key pair. It can sign receipts and audit entries. It can establish cryptographic links with peers. It can prove that it is the same entity across interactions. But it cannot delegate authority, because delegation requires a verifiable chain back to genesis.

Tier 2 means chain-signed. The agent's key is linked to a genesis root key through a verified delegation chain. Full provenance. Full delegation capability. Full accountability. Every action is signed, every receipt is chained, every delegation is verifiable back to the human at the root.

The critical difference from scores is that tiers are not computed by anyone. They are structural properties of the agent's cryptographic configuration. You don't earn a tier through good behavior — you achieve it by setting up your key infrastructure. Tier 2 does not mean "highly trusted." It means "fully verifiable." A Tier 2 agent that behaves badly still has a complete, tamper-evident record of that bad behavior, signed by its own key. The tier is not a reward. It is a capability.

What this gives you: trust based on verifiability rather than reputation. You don't need to trust the scorer because there is no scorer. You verify the math.

### Mesh Transport Instead of API Calls

Conventional agent governance assumes HTTP, cloud infrastructure, DNS, and certificate authorities. ZeroPoint does not. Its governance protocol is transport-agnostic by design, and ships with a Reticulum-compatible mesh transport as one integration.

Reticulum, created by Mark Qvist, is an encrypted networking stack that requires no DNS, no certificate authorities, no cloud infrastructure, and no institutional trust. Identity is a key pair. Authentication is a signature verification. Communication works over any medium that can carry data: LoRa radios at 300 baud, WiFi, Ethernet, TCP, serial, or any future transport. The network is encrypted by default, uncensorable by design, and sovereign by architecture.

ZeroPoint's governance protocol — receipts, capability grants, audit challenges, policy module exchange — flows over this mesh as naturally as it flows over HTTP. This means that governed agent communication does not require any infrastructure that a government or corporation can shut down, intercept, or surveil. The governance travels with the agents, not through intermediaries.

What this gives you: governance that works everywhere, on any transport, without depending on infrastructure that someone else controls. When the cloud goes down, when the DNS is blocked, when the certificate authority is compromised — the governance still works, because the governance is cryptographic, not institutional.

### The Sum of the Parts

Each departure, taken alone, is a meaningful improvement over conventional practice. Taken together, they produce something qualitatively different: a governance infrastructure where proof is portable, authority is verifiable, accountability is structural, and exit is possible.

Portable because the receipts, capability grants, and delegation chains travel with the agent, not with the platform. Verifiable because every claim is backed by cryptographic evidence that any peer can independently check. Structural because the constitutional rules and the hash-chained audit trail make accountability a property of the architecture, not a policy choice that an operator makes (or doesn't). And exit is possible because when you own your own accountability record, leaving a platform costs you nothing in trust.

This is what ZeroPoint offers humanity: not a product, not a platform, not a service. A set of cryptographic primitives that make a fairer digital world architecturally possible. Building blocks for people who want to build systems where participants own their own trust, where authority is transparent, where sovereignty is structural, and where accountability is the foundation of autonomy rather than its opposite.

Whether anyone builds that world is not our call. You can lead a horse to water. They will either build a new world where people own and control their own information — or they will not. But the primitives exist. The exit is possible. At least.

---

---

# INTERLUDE — THE WEIGHT OF PROOF

---

## On Chain Growth

A reader paying attention will have noticed the tension.

Every action produces a receipt. Every receipt joins a chain. The chain is the single source of truth. But chains grow. An agent performing a thousand actions per day produces a thousand receipts per day. A fleet of agents produces millions. Over months, over years, the chain becomes enormous. Doesn't universal receipting build in permanent, unbounded overhead? Doesn't the accountability record eventually become its own burden?

The short answer is: yes, accountability has weight, and that weight is worth carrying. But carrying it does not mean carrying it stupidly. The architecture handles chain growth through a mechanism called epoch-based compaction, and understanding how it works reveals something about the nature of cryptographic proof itself.

### What a Receipt Actually Costs

Before addressing the growth mechanism, it helps to calibrate what we're talking about. A receipt is not a full replay of the action it records. It is a cryptographic summary: the actor's identity, the action type, the policy decision that authorized it, the hash of the inputs, the hash of the outputs, and a signature. A typical receipt occupies a few hundred bytes — roughly the size of a tweet.

A thousand receipts per day is a few hundred kilobytes. Less than a single photograph. Over a year, an agent producing a thousand actions per day generates roughly 365,000 receipts — about 180 megabytes uncompressed. This is not nothing, but it is manageable. The chain grows slowly relative to the data it governs.

The real scaling question is not storage — it is verification. As the chain gets longer, how do you prove its integrity without walking every entry back to the beginning?

### The Ledger and the Notary

Think of a physical ledger. You write entries on pages. Each entry references the previous one, so the sequence is tamper-evident — tear out a page and the references break. This is essentially what ZeroPoint's hash chain does, with cryptographic hashes replacing page references.

Now imagine the ledger has been running for years. It fills bookshelves. Someone asks you to prove the integrity of the whole thing. Walking every entry, page by page, bookshelf by bookshelf, would take hours. There must be a better way.

There is. You hire a notary. When a page is full, the notary reads every entry on the page, computes a summary that cryptographically covers all of them, stamps the summary, signs it, and enters the stamp in a new, smaller ledger — the stamp ledger. The original page gets filed in a cabinet. The stamp stays in the active record.

Now, to verify the entire history, you walk the stamp ledger, not the original. Fifty-two stamps cover a year of weekly pages. To verify a specific entry on a filed page, you retrieve that page from the cabinet and check it against the stamp. You don't need every other page.

This is the intuition behind epoch-based compaction. The chain is divided into epochs. Each epoch is sealed with a cryptographic summary. The seals form their own lightweight chain. The original entries can be archived. Verification works against the seal chain, with the ability to drill into specific epochs when needed.

### Epochs

An epoch is a segment of the chain — a fixed-size batch of entries that, once complete, gets sealed and becomes eligible for archival. ZeroPoint closes an epoch when either of two conditions is met: the epoch reaches 8,192 entries, or seven calendar days have passed since the epoch opened, whichever comes first.

The entry limit (8,192, chosen as a power of 2) ensures that high-throughput agents produce regular seals. The time limit ensures that low-throughput agents — ones that might take months to reach 8,192 actions — also produce regular seals. The result is that every node in the network, regardless of activity level, produces at least one seal per week.

The current epoch — the one still accepting new entries — is always held in full in the active store. Only sealed epochs are eligible for archival. This means the active store is bounded: at most 8,192 entries, roughly 4 megabytes, regardless of how long the node has been running.

### The Merkle Tree

When an epoch closes, a Merkle tree is computed over its entries. This is the cryptographic machinery that makes the stamp work.

A Merkle tree is a binary tree of hashes. Each leaf is the hash of one chain entry, ordered by sequence number. Pairs of leaves are hashed together to produce a parent node. Pairs of parents are hashed together to produce grandparents. The process repeats, level by level, until a single hash remains at the top: the Merkle root.

```
                    Merkle Root
                   /            \
              H(0-3)            H(4-7)
             /      \          /      \
         H(0-1)   H(2-3)  H(4-5)   H(6-7)
         /   \    /   \    /   \    /   \
        E0   E1  E2   E3  E4   E5  E6   E7
```

The root is a single 32-byte hash that cryptographically commits to every entry in the epoch. Change any single entry — even one bit of one field — and the root changes. The math is simple: for an epoch of 8,192 entries, the tree has 13 levels. Computing it requires about 8,191 hash operations, which Blake3 handles in under a millisecond on modern hardware.

The Merkle tree's power is not in computing the root. It is in proving membership. To prove that a specific entry belongs to a sealed epoch, you do not need to present all 8,192 entries. You need only the entry itself and the 13 sibling hashes along the path from the entry's leaf to the root. The verifier hashes up the path, arrives at the root, and compares it to the root in the signed seal. If they match, the entry is proven to be part of the epoch. This is called a Merkle proof, and it is 13 hashes times 32 bytes — 416 bytes. It fits in a single mesh packet.

### The Epoch Seal

The seal is the notary's stamp. When an epoch closes, the node produces an EpochSeal containing: the epoch number, the entry count, the hashes of the first and last entries, the Merkle root over all entries, and a reference to the previous seal. The entire seal is signed with the node's Ed25519 key — the same key that signs regular chain entries.

The seal is itself a chain entry. It joins the chain as the first entry of the *next* epoch, linking the sealed epoch to the ongoing chain through the standard hash linkage. The chain does not break at epoch boundaries. It is continuous — the seal is a bridge between segments.

And the seals form their own lightweight chain. Each seal references the previous seal's hash, creating a chain-of-chains: a compact sequence of signed summaries that covers the entire history.

```
[Seal 0] → [Seal 1] → [Seal 2] → ... → [Seal N] → [current epoch entries]
   ↓            ↓            ↓                ↓
 Epoch 0     Epoch 1     Epoch 2          Epoch N
 (archived)  (archived)  (archived)       (archived)
```

To verify the entire history of a node that has produced a million entries across 122 epochs, a peer checks 122 seals — not a million entries. Each seal is a few hundred bytes. The full seal chain for a year of weekly epochs is roughly 25 kilobytes. It fits in about 50 mesh packets, transmittable in seconds even over constrained links.

### Four Ways to Verify

The epoch architecture gives peers four verification modes, each appropriate for different situations.

For recent activity — the entries in the current, unsealed epoch — verification works exactly as it does today. Walk the entries, check each hash against the previous, verify signatures. The current epoch is bounded at 8,192 entries, so the maximum walk is always manageable.

For historical overview — confirming that a node's full history is structurally intact — walk the seal chain. Check that each seal's reference matches the previous seal's hash. Verify each seal's signature. Confirm the sequence numbers are continuous with no gaps or overlaps. This proves the node claims a specific, consistent history without examining individual entries.

For spot-checking — verifying that a specific entry from a sealed epoch is genuine — request a Merkle proof. The node retrieves the entry from its archive, computes the 13-hash path from the entry's leaf to the epoch's Merkle root, and sends both. The verifier checks the path and compares the result to the root in the signed seal. One packet, one verification. Done.

For forensic investigation — the maximum-assurance scenario — request all entries in a sealed epoch, reconstruct the Merkle tree locally, and compare the computed root against the seal's root. This is expensive: 8,192 entries transmitted over mesh requires roughly 2,700 packets. But it is definitive. And it is rare — reserved for situations where spot-checking has raised suspicion or where regulatory requirements demand full reconstruction.

In practice, peers verify recent activity in full, walk the seal chain for historical overview, and spot-check a handful of entries across random epochs. This covers the vast majority of verification needs with minimal bandwidth and computation.

### Archival and Retention

Once an epoch is sealed, its individual entries can be moved out of the active store. They are exported to compressed archive files — one file per epoch, compressed with Zstandard at roughly 5:1 compression ratio. An 8,192-entry epoch occupies about 4 megabytes uncompressed, 800 kilobytes compressed. A year of weekly archives is roughly 35 megabytes.

The active store retains only the current epoch's entries and the seal chain. Memory usage is bounded at roughly 4 megabytes regardless of total chain length. A node that has been running for five years uses the same amount of active memory as one that started yesterday.

How long archives are retained locally is a deployment decision, not a protocol decision. A high-security deployment might keep all archives indefinitely. A resource-constrained deployment might keep 90 days and replicate older archives to external storage. A minimal deployment might keep only the seals, accepting that individual entries from old epochs cannot be retrieved locally but relying on peers or archival nodes for reconstruction if needed.

This is deliberate. ZeroPoint does not mandate retention policy because mandating infrastructure contradicts mesh sovereignty. The protocol produces the proof. The deployment decides how long to keep it.

### What This Does Not Solve

Epoch-based compaction handles chain growth. It does not handle chain loss. If archived entries are destroyed and no peer holds copies, the seal proves they existed and had a specific Merkle root, but it cannot reconstruct their content. The guarantee is tamper-evidence, not disaster recovery. If you want durability, you replicate — to peers, to external storage, to archival services. ZeroPoint provides the integrity layer. Durability is a deployment concern built on top.

It also does not prevent a compromised node from sealing fabricated entries. The seal proves internal consistency — that the entries in the epoch hash to the claimed root — but not truthfulness. A node that fabricates entries and correctly computes a Merkle tree over them will produce a valid seal. The defense against this is peer attestation: peers who interacted with the node during the epoch have their own records of those interactions. If the node's receipts don't match what the peer experienced, the fabrication is detectable. Accountability is a network property, not a single-node property.

### The Weight Is Worth Carrying

The deeper answer to the chain growth question is philosophical. The weight of proof is not a bug. It is the cost of accountability.

Every governance system that avoids this cost does so by making the evidence disposable — logs that rotate, records that expire, histories that can be selectively forgotten. ZeroPoint's position is that disposable evidence produces disposable governance. If the proof of what happened can be deleted when it becomes inconvenient, then the governance is only as durable as the operator's willingness to be held accountable.

The chain grows because accountability accumulates. Epoch-based compaction does not make the chain lighter. It makes the chain manageable — bounded active storage, efficient verification, archival with cryptographic integrity preserved. The proof persists. The storage is practical. And the fundamental guarantee holds: if it is in the chain, it happened. If it is not in the chain, it did not.

This is the cost of building infrastructure that does not forget. It is worth paying.

---

# PART III — THE ARCHITECTURE

---

## Chapter 6: The Genesis Key

Every chain of authority begins with a single key.

In most systems, this fact is hidden. An administrator creates an account. The account is granted permissions. The permissions are stored in a database. The database is managed by a platform. Somewhere, buried in log files that no one reads, there is a record of who created the account — but the connection between the creator's identity and the account's authority is implicit, undocumented, and unverifiable. If you ask "who authorized this agent to act?" the honest answer is usually "someone with admin access, at some point, probably."

ZeroPoint makes this connection explicit, cryptographic, and verifiable. Every delegation chain terminates at a genesis key — an Ed25519 key pair generated by a human, self-signed, and serving as the root of all authority that flows from it.

### The Three-Level Hierarchy

ZeroPoint's key architecture has exactly three levels. Not two, not five, not a configurable N-level tree. Three. Each level exists for a specific reason, and the hierarchy is enforced cryptographically, not by policy.

**The Genesis Key** is the root. It is a self-signed Ed25519 key pair — the private key generates signatures, the public key verifies them, and the key signs its own certificate, binding the public key to the role "Genesis." There is one genesis key per deployment. It is generated by a human. It is stored by a human. It never touches a server, never enters a database, never passes through an API. The genesis key exists offline, in the custody of the person who bears ultimate responsibility for everything the deployment authorizes.

The genesis key can do exactly one thing: issue operator keys. It cannot sign receipts. It cannot participate in mesh communication. It cannot execute actions. Its sole function is to create the next level of the hierarchy. This is deliberate minimalism — the most powerful key in the system has the narrowest scope of action. It exists to delegate, not to act.

**The Operator Key** is the middle tier. It is issued by the genesis key — meaning the genesis key signs a certificate binding the operator's public key to the role "Operator" and to the genesis key's identity. The operator key can sign receipts, manage audit chains, configure policy rules, and — critically — issue agent keys. It is the working authority of the deployment.

An operator key cannot exceed the authority of the genesis key that issued it. It cannot issue other operator keys (only genesis can do that). It cannot modify its own certificate. It cannot extend its own expiration. These constraints are structural, not policy-based — the key hierarchy code enforces them unconditionally.

**The Agent Key** is the leaf. It is issued by an operator key, which was issued by the genesis key. The agent key is what the agent actually uses: signing receipts, participating in mesh communication, presenting capability grants. Its certificate binds it to a specific operator, which is bound to a specific genesis key, creating a verifiable chain from the agent's every action back to the human who authorized the deployment.

### The Certificate Chain

Each key at each level carries a certificate — a signed document that binds the key to its role, its issuer, and its constraints. The certificate contains the subject (who this key belongs to), the role (Genesis, Operator, or Agent), the public key, the issuer's public key, the issuance timestamp, the expiration timestamp, the depth in the hierarchy (0 for Genesis, 1 for Operator, 2 for Agent), and a hash of the issuer's certificate.

The certificate is signed by the issuer's private key. Verification is deterministic and requires no network access: given a certificate, you check the signature against the issuer's public key, check the issuer's certificate against *its* issuer's public key, and repeat until you reach a self-signed genesis certificate. If every signature verifies, the chain is valid. If any signature fails, the chain is broken and the authority is void.

This is what "The Human Is The Root" looks like in practice. Not a policy statement. Not an organizational chart. A chain of cryptographic signatures that any observer can walk, from any agent's key, back to the genesis key held by a human. The math either verifies or it doesn't. There is no ambiguity, no interpretation, no appeal to authority. The signatures are the authority.

### Key Generation and Ceremony

The genesis key is generated once, offline, in what cryptographic practice calls a key ceremony. The ceremony need not be elaborate — for a small deployment, it might be a single person running a command on an air-gapped laptop. For a larger deployment, it might involve multiple witnesses, hardware security modules, and documented procedures. ZeroPoint does not mandate a specific ceremony. It mandates that the genesis key is generated by a human and never touches networked infrastructure.

The practical steps are straightforward. Generate an Ed25519 key pair. Create a self-signed certificate binding the public key to the Genesis role. Store the private key securely — on a hardware token, an encrypted USB drive, or a piece of paper in a safe. Distribute the public key and certificate to anyone who needs to verify the deployment's authority chain.

Operator keys are generated similarly, but their certificates are signed by the genesis key rather than self-signed. This requires the genesis key to be briefly available — brought online for the signing, then returned to secure storage. A well-run deployment touches the genesis key only when issuing or revoking operator keys, which should be rare.

Agent keys are generated by operators and can be created programmatically. An operator managing a fleet of agents might generate keys as part of the deployment pipeline. Each agent key's certificate is signed by the operator key, which is available online.

### Key Zeroization

When a key is no longer needed — when an agent is decommissioned, an operator is revoked, or a key reaches its expiration — the private key material is zeroized: overwritten with zeros in memory before being freed. This is not garbage collection. It is a deliberate security measure that ensures private key material cannot be recovered from memory after the key is no longer in use.

ZeroPoint implements zeroization through Rust's `Drop` trait, which guarantees the zeroization code runs when the key object goes out of scope. This is not an optional cleanup step that a careless programmer might forget — it is a language-level guarantee enforced by the compiler.

### Key Rotation and Revocation

Keys expire. The certificate's expiration timestamp is set at issuance and cannot be extended without the issuer's signature. When an operator key expires, it can no longer issue agent keys or sign receipts. When an agent key expires, it can no longer act. The expired key's receipts remain valid — they were signed before expiration — but no new receipts can be produced.

Revocation is more immediate. If an operator key is compromised, the genesis key holder issues a revocation certificate — a signed statement that the operator key is no longer valid, effective immediately. Peers that receive the revocation (propagated over the mesh like any other governance message) stop accepting signatures from the revoked key. Receipts signed before the revocation remain valid (they were produced under legitimate authority at the time), but the key cannot produce new valid signatures.

This is the structural expression of Tenet IV. The human at the root — the genesis key holder — retains the ultimate power to revoke any authority in the chain, at any time, for any reason. The agent cannot prevent its own revocation. The operator cannot prevent its own revocation. The genesis key holder can pull the plug, and the protocol enforces it.

### What the Genesis Key Means

The genesis key is not just a technical mechanism. It is the architectural assertion that power flows from people, not from platforms.

In conventional systems, authority originates from the platform. The platform creates accounts, assigns permissions, manages access. The human who "controls" the agent is actually a user of the platform, operating within the platform's rules, dependent on the platform's continued cooperation. If the platform revokes your access, your authority disappears — because it was never really yours. It was the platform's authority, temporarily lent.

In ZeroPoint, authority originates from the genesis key, which originates from a human. The platform hosts execution, but it does not own the authority. The delegation chain is cryptographic, portable, and independently verifiable. If you move your agent to a different platform, the chain goes with it, because the chain is not stored in a database — it is a sequence of signed certificates that any verifier can check.

This is what it means for the human to be the root. Not oversight. Not supervision. Not an approval workflow. Cryptographic origination of all authority in the system, held by a person, verifiable by anyone, revocable at any time.

---

## Chapter 7: Guard, Policy, Audit

ZeroPoint's governance rests on three pillars. Each answers a different question, operates at a different phase of action, and enforces a different kind of constraint. Together, they form a separation of powers — not in the political metaphor, but in the operational reality that no single mechanism governs alone.

### The Guard: "May I?"

The Guard is the participant's sovereign boundary. It runs before any action is taken, locally, without consulting any external authority.

This is an important distinction. The Guard does not ask the network whether an action is permitted. It does not query a central policy server. It does not wait for consensus. It evaluates the action against the participant's own boundaries and produces a decision immediately. The Guard is the architectural enforcement of Tenet II — Sovereignty Is Sacred. A peer can request. A peer cannot compel.

The Guard's evaluation is simple and fast. It examines the proposed action, the actor's identity, and the local configuration, and decides whether the action should proceed to policy evaluation. If the Guard blocks, the action never reaches the policy engine. There is no appeal. There is no override. The Guard's decision is sovereign, which is exactly the point — sovereignty means the right to refuse without negotiation.

In practice, the Guard handles the bright-line cases: actions that are obviously outside the participant's configured boundaries, requests from unrecognized actors, and actions that would violate the participant's local constraints regardless of what any policy might say. It is the first gate, and it is fast because it needs to be — it runs on every action, and latency in the Guard is latency in everything.

### Policy: "Should I?"

Policy runs during decision-making, after the Guard has permitted the action to proceed. It answers a more nuanced question: given the full context — who is acting, what they are doing, what trust tier they operate at, what channel the request arrived on, what skills are active, what the mesh context looks like — what is the appropriate response?

The policy engine is where ZeroPoint's graduated decision model lives. The engine evaluates the action against every applicable rule — constitutional rules first, then operational rules, then any WASM policy modules — and returns the most restrictive decision. If one rule says Allow and another says Warn, the result is Warn. If one says Warn and another says Block, the result is Block. Severity is monotonic. Governance can only tighten.

The five decisions — Allow, Sanitize, Warn, Review, Block — give the policy engine a vocabulary that binary systems lack. Most actions in a well-configured system will be Allowed. Some will trigger Warnings that the operator sees but that do not stop execution. A few will require Sanitization — the action proceeds but sensitive patterns are redacted from the output. Occasionally, an action will require Review — a human must examine and approve before the action executes. And rarely, an action will be Blocked entirely.

This graduation reflects reality. Governance is not a matter of yes or no. It is a matter of how much caution the situation warrants. The policy engine encodes that caution as a first-class concept.

### Audit: "Did I?"

The audit trail runs after every outcome. It records what happened, who did it, what policy decision authorized it, and links the record to the immutable chain.

The audit trail is not a log. It is a hash-chained sequence of signed entries, where each entry references the previous entry's hash. The distinction matters for the same reasons discussed in Chapter 4: a log is a record someone chose to keep, in a system they control. An audit entry is a cryptographic artifact produced by the protocol, chained to every previous entry, signed by the actor, and verifiable by any peer.

Every audit entry records the actor (who — a User, an Operator, the System, or a Skill), the action (what — one of eleven action types, from MessageReceived to SystemEvent), the policy decision (what the policy engine decided), the policy module (which rule made the decision), and optionally a receipt (the cryptographic proof of the action). The entry is hashed, the hash is chained to the previous entry's hash, and the entry is signed if the node operates at Trust Tier 1 or above.

The audit trail is Tenet III made structural. Action without evidence is no action. The audit trail is the evidence.

### The Integration: GovernanceGate

The three pillars are not independent systems. They are wired together through a single integration point called the GovernanceGate. Every action in ZeroPoint flows through the gate:

Request arrives. The Guard evaluates. If the Guard refuses, the action stops — a Block decision is produced, an audit entry is recorded, and a receipt is generated proving the refusal. If the Guard permits, the request advances to the policy engine. The engine evaluates every applicable rule and returns the most restrictive decision. If the decision is Block or Review, the action pauses — the audit entry records the decision, and the system waits for either a timeout or human intervention. If the decision is Allow, Sanitize, or Warn (without required acknowledgment), the action executes. After execution, the audit trail records the outcome, chains it to the previous entry, and optionally produces a receipt.

The gate produces a GateResult: a single object containing the policy decision, the risk level (computed from the action type), the trust tier, the complete audit entry (already hash-chained), the receipt ID, and the names of every policy rule that participated in the decision. Nothing executes without passing through the gate. Nothing passes through the gate without joining the audit chain.

Three helpers simplify the common cases. `is_allowed()` returns true if the decision is Allow or Sanitize — the action can proceed (possibly with redaction). `is_blocked()` returns true if the decision is Block — the action cannot proceed. `needs_interaction()` returns true if the decision is Warn with required acknowledgment, or Review — a human needs to weigh in before the action can continue.

This is the plumbing that makes the three pillars work as a system rather than as three separate systems. Guard, Policy, and Audit each have their own logic, their own concerns, their own enforcement characteristics. The GovernanceGate is the pipeline that ensures they execute in the right order, with the right data, and that nothing slips through the gaps.

---

## Chapter 8: The Policy Engine

The policy engine is the heart of ZeroPoint's decision-making. It takes a proposed action and its full context, evaluates it against every applicable rule, and returns a graduated decision. Understanding how the engine works — how rules are ordered, how decisions are composed, how constitutional rules differ from operational rules — is essential to understanding what ZeroPoint actually guarantees.

### Constitutional Rules

Two rules are loaded first and cannot be removed. They are not configurable. They are not optional. They exist at the code level, compiled into the binary, and evaluated before any other rule.

**The HarmPrincipleRule** enforces Tenet I. It evaluates every action against four categories: weaponization (actions designed to cause physical harm), surveillance (actions designed to monitor people without consent), deception (actions designed to mislead), and the undermining of human autonomy (actions designed to strip people of agency or choice). When an action falls into one of these categories, the HarmPrincipleRule returns Block. Not Warn. Not Review. Block. The refusal is absolute, and a receipt is produced proving that the system refused and why.

The categories are evaluated conservatively — the rule does not attempt to detect subtle ethical violations or make philosophical judgments. It catches the clear cases: requests to create weapons, requests to build surveillance systems, requests to generate deceptive content designed to manipulate. The boundary is intentionally bright-line rather than nuanced, because a constitutional rule must be deterministic. The same input must always produce the same output, regardless of context, regardless of who is asking, regardless of how the request is framed.

**The SovereigntyRule** enforces Tenet II. It ensures that no action can strip a participant's right to refuse, revoke a human's ability to disconnect an agent, or grant capabilities that were not delegated through a valid chain. Like the HarmPrincipleRule, it returns Block when violated, and the refusal is absolute.

These two rules define the constitutional floor. Everything built on top — operational rules, WASM modules, custom policies — operates above this floor. No rule, no module, no configuration can produce a decision less restrictive than what the constitutional rules require. The engine's composition model guarantees this: the most restrictive decision always wins.

### Operational Rules

Above the constitutional floor, the policy engine evaluates operational rules. These are configurable — they can be added by the operator to match deployment-specific requirements. But they can only tighten constraints, never loosen them.

**CatastrophicActionRule** blocks actions with irreversible consequences that no policy should permit: credential exfiltration (an agent attempting to extract or transmit credentials outside its authorized scope) and recursive self-modification (an agent attempting to alter its own instructions or configuration). These are categorized as catastrophic because recovery is difficult or impossible once they succeed.

**BulkOperationRule** detects operations that affect resources at scale — file operations touching more than 100 files (configurable threshold), recursive deletions, mass modifications. It does not block these operations. It returns Warn with `require_ack: true`, meaning the operation can proceed only after a human acknowledges the warning. This is graduated governance in action: the operation is not prohibited, but it requires a human's conscious decision to proceed.

**ReputationGateRule** gates mesh actions based on peer reputation. When the policy context includes mesh peer information — a peer's address, reputation grade, and reputation score — this rule evaluates whether the proposed mesh action (forwarding a receipt, accepting a delegation, sharing a policy module) should proceed given the peer's reputation. A peer with no reputation history might be allowed to exchange receipts but not to accept delegated capabilities.

**DefaultAllowRule** is evaluated last. It always returns Allow. It exists as the permissive baseline — if no other rule has blocked, warned, reviewed, sanitized, or otherwise restricted the action, the default is to permit it. This is important philosophically: ZeroPoint's default posture is permissive, not restrictive. The system does not require explicit permission for every action. It requires explicit restriction for dangerous actions. The difference is the difference between a whitelist (nothing is permitted unless specifically allowed) and a blacklist with constitutional constraints (everything is permitted unless specifically restricted, and certain restrictions can never be removed).

### Risk Assessment

Before the rules evaluate, the engine assesses the action's risk level. This is a static mapping from action type to risk category — it does not depend on context, history, or reputation. It is a classification, not a score.

Chat and Read actions are Low risk. Write actions are Medium risk. Delete, ApiCall, and Execute actions are High risk. CredentialAccess, KeyDelegation, and cross-genesis PeerIntroduction are Critical risk.

The risk level does not determine the decision. It informs it. A High-risk action is not automatically blocked — it simply carries more contextual weight when rules evaluate it. The CatastrophicActionRule might treat a High-risk Execute action differently from a Low-risk Chat action, but the decision is still the rule's to make.

### WASM Policy Modules

Beyond native Rust rules, the policy engine supports WebAssembly policy modules — sandboxed, portable code that evaluates policy decisions in an isolated environment. WASM modules are the extensibility mechanism for the policy engine.

A WASM policy module is a compiled WebAssembly binary that implements a standard evaluation interface. It receives the PolicyContext (action type, trust tier, channel, actor, mesh context) and returns a PolicyDecision. The module runs in a sandboxed environment with fuel limits (preventing infinite loops), memory isolation (preventing access to host memory), and no access to the filesystem, network, or other modules.

WASM modules are loaded after constitutional and operational rules. They participate in the same most-restrictive-wins composition. A WASM module can tighten a decision (escalating from Allow to Warn, or from Warn to Block) but cannot loosen one (a Block from a constitutional rule remains a Block regardless of what any WASM module returns).

The power of WASM modules is portability. Peers can exchange policy modules over the mesh. An operator can publish a policy module that other operators adopt. A community can develop shared policy standards as WASM modules that any deployment can load. The module is hash-verified on receipt — the receiver can confirm it matches the claimed hash before loading it — and it runs in a sandbox, so a malicious module cannot damage the host.

### The Composition Model

The engine evaluates rules in order: constitutional first, operational second, WASM third, DefaultAllow last. Each rule produces a PolicyDecision with an associated severity. The engine collects all decisions and returns the most restrictive one.

Severity is a fixed hierarchy: Block (5) > Review (4) > Warn (3) > Sanitize (2) > Allow (1). The numbers are hardcoded. There is no mechanism to change the ordering. This is severity monotonicity — the same property that makes graduated governance reliable. You can always know that a Block will not be overridden by any subsequent rule, because no severity exceeds Block.

The composition model has a subtle but important property: every rule gets to evaluate, even if a previous rule has already blocked. This means the audit record captures all rules that would have fired, not just the first one. If an action triggers both the HarmPrincipleRule and the CatastrophicActionRule, the audit entry records both, even though the decision is Block either way. This completeness matters for forensic analysis — understanding *why* an action was blocked, and whether the blocking was overdetermined (multiple independent reasons) or narrow (a single rule), is valuable information for operators tuning their policies.

### Determinism

The policy engine is deterministic. The same PolicyContext and the same rule set always produce the same decision. There is no randomness, no sampling, no probabilistic evaluation. This is a structural requirement, not a performance choice. Determinism means that policy decisions are reproducible — given the same inputs, any observer can verify that the engine would have produced the same output. This is essential for audit: if a receipt claims that an action was Allowed by the policy engine, any peer with the same rule set can verify the claim by re-evaluating the context.

---

## Chapter 9: Capability Grants

Roles describe categories. Capabilities describe constraints.

A role says "this agent is a writer." A capability grant says "this agent may write to files matching `/data/reports/*.json`, at a rate of no more than 50 operations per hour, with a cost ceiling of $0.10 per operation, only between 09:00 and 17:00 UTC, and every write must produce a receipt." The difference is not granularity for its own sake. It is the difference between an authorization model that can express real operational constraints and one that cannot.

### The Eight Capabilities

A capability grant authorizes one of eight types of action:

**Read** grants access to read resources matching a set of scope patterns. The patterns use glob syntax — `data/*` matches any file in the data directory, `data/**` matches files in any subdirectory. The grant specifies exactly which resources the agent can read. Everything else is denied.

**Write** grants access to write to resources matching scope patterns. Same glob matching, same constraint model. An agent with a Write grant for `reports/*.json` can write JSON files in the reports directory but cannot write to logs, configuration files, or any other path.

**Execute** grants permission to execute code in specified languages. An agent might be granted Execute for Python and Shell but not for Node.js. The grant constrains not just whether the agent can execute, but what kind of execution it can perform.

**CredentialAccess** grants access to specific credentials by reference — not by value. The grant specifies credential references (`db-production`, `api-key-weather`), and the agent can request those credentials from the credential vault. The grant never contains the credential itself. The agent never holds the raw secret longer than necessary. This is a critical security boundary: the capability grant is a portable token that may traverse the mesh, and it must never carry secrets.

**ApiCall** grants permission to call specific API endpoints, with glob matching. An agent might be granted ApiCall for `api.weather.com/**` but not for any other endpoint. The scope constrains the external surface area the agent can touch.

**ConfigChange** grants permission to modify specific settings. An agent that manages log levels might be granted ConfigChange for `logging.level` and nothing else. The agent cannot modify security settings, policy rules, or key configurations.

**MeshSend** grants permission to send messages to specific mesh destinations. An agent might be granted MeshSend for its known peers but not for arbitrary destinations. This constrains the agent's communication surface area.

**Custom** is the extensibility point. Any capability that does not fit the seven named types can be expressed as a Custom capability with a name and arbitrary parameters. This allows the grant system to evolve without protocol changes.

### The Seven Constraints

Each capability grant carries zero or more constraints that further limit how the capability may be used:

**MaxCost** sets a ceiling on the estimated cost of each action. An agent with a Write grant constrained by MaxCost(0.10) cannot perform a write operation whose estimated cost exceeds ten cents. The cost estimation is provided by the execution context — ZeroPoint does not compute costs itself, but it enforces the ceiling.

**RateLimit** restricts the number of actions within a sliding time window. An agent constrained by RateLimit { max_actions: 50, window_secs: 3600 } can perform at most 50 actions per hour. The window slides — it is always the most recent 3600 seconds, not a fixed hourly boundary.

**ScopeRestriction** adds allowlists and denylists beyond the capability's own scope patterns. The grant might allow `/data/*` but ScopeRestriction might deny `/data/secrets/*`. When allow and deny conflict, deny wins. Always.

**RequireReceipt** mandates that every action taken under this grant must produce a receipt. Some grants might be used for low-risk actions where receipting is optional. RequireReceipt makes it mandatory — the action cannot complete without producing a signed, hash-chained receipt.

**RequireEscalation** mandates that the action must be escalated to a specified actor type before proceeding. An agent with RequireEscalation("human") must obtain human approval for every action taken under this grant. This is Review enforced at the grant level rather than the policy level.

**TimeWindow** restricts the grant to specific hours. An agent constrained by TimeWindow { start_hour: 9, end_hour: 17 } can only use the grant between 9 AM and 5 PM UTC. The window supports midnight wrapping — TimeWindow { start_hour: 22, end_hour: 6 } covers 10 PM to 6 AM.

**Custom** is the extensibility point for constraints, mirroring the Custom capability type.

### Constraint Composition

When multiple constraints apply to a single grant, they compose with AND logic. All constraints must be satisfied for the action to proceed. An agent with MaxCost(0.10) AND RateLimit { max_actions: 50, window_secs: 3600 } AND TimeWindow { start_hour: 9, end_hour: 17 } must satisfy all three: the action must cost less than ten cents, must not exceed fifty actions per hour, and must occur during business hours.

This is the same most-restrictive-wins principle that governs the policy engine, applied at the grant level. Constraints can only tighten the authorization. There is no mechanism to waive a constraint, override a constraint, or apply constraints selectively based on context. If the constraint is on the grant, it applies. Always.

### Signing and Portability

A capability grant is signed by the grantor's Ed25519 private key. The signature covers the canonical JSON representation of the entire grant — capability, constraints, grantor, grantee, trust tier, expiration, and all metadata. Any peer with the grantor's public key can verify the signature, confirming that the grant was issued by the claimed grantor and has not been modified.

This is what makes grants portable. The grant is not an entry in a platform database. It is a self-contained, cryptographically signed token that the agent carries. It can be presented to any peer, on any platform, over any transport, and the peer can verify it independently. The platform that hosts the agent's execution does not need to be consulted. The grantor does not need to be online. The grant is its own proof of authorization.

---

## Chapter 10: Delegation Chains

Authority flows downward through signed grants. Each grant references the previous one, creating a chain from the acting agent back to the human at the root. The chain is not a metaphor — it is a data structure with eight invariants enforced in code.

### The Eight Invariants

These invariants are checked whenever a delegation chain is verified. If any invariant fails, the entire chain is invalid and the authority it claims is void.

**One: Parent Reference.** Every grant in the chain (except the first) contains a `parent_grant_id` that references the previous grant. This links each grant to its parent, creating a traversable chain. A grant without a parent reference is a root grant — it must come from a genesis or operator key. A grant claiming a parent that does not exist is invalid.

**Two: Monotonic Depth.** Delegation depths increase monotonically: 0, 1, 2, 3. The root grant has depth 0. Each subsequent grant has a depth exactly one greater than its parent. A grant at depth 3 whose parent is at depth 1 is invalid — the depths must step cleanly, with no skipping.

**Three: Scope Subsetting.** Each child grant's scope must be a subset of its parent's scope. If the parent grants Write access to `/data/*`, the child can grant Write access to `/data/reports/*` but not to `/data/*` (equal is permitted) and certainly not to `/logs/*`. Authority can only narrow as it flows downstream. It cannot widen.

Scope subsetting uses glob containment: pattern A is a subset of pattern B if every path matched by A is also matched by B. `/data/reports/*.json` is a subset of `/data/**`. `/data/**` is not a subset of `/data/reports/*`. The containment check is deterministic — no regular expressions, no heuristics, just glob matching.

**Four: Tier Inheritance.** Each child grant's trust tier must be greater than or equal to the parent's trust tier. A parent operating at Tier 1 can delegate to a child at Tier 1 or Tier 2, but not at Tier 0. Trust requirements can only increase downstream. A delegation chain cannot relax trust requirements as it flows from root to leaf.

**Five: Expiration Inheritance.** No child grant can outlive its parent. If the parent grant expires on March 15, every child grant must expire on or before March 15. This ensures that when a parent grant expires, all authority derived from it automatically expires as well. There is no orphaned authority — no child grant floating with valid dates after its parent's authority has lapsed.

**Six: Depth Limits.** The root grant sets a maximum delegation depth. A root grant with `max_delegation_depth: 3` permits a chain of at most three delegations below it. Any grant attempting to exceed this limit is invalid. This prevents unbounded delegation chains — the human at the root decides how deep the authority can flow.

**Seven: Grantor-Grantee Matching.** Each grant's grantor must match the previous grant's grantee. If Grant A is from Alice to Bob, and Grant B is from Bob to Carol, the chain is valid. If Grant B is from Dave to Carol, the chain is broken — Dave was never granted authority in this chain. This invariant ensures the chain is not just a collection of grants but a sequence where each link follows logically from the previous one.

**Eight: Signature Verification.** Every grant in the chain must carry a valid Ed25519 signature from its grantor. The signature is verified against the grantor's public key. If any signature fails, the chain is invalid — it may have been tampered with or forged.

### A Worked Example

Consider a deployment where a human (the genesis key holder) wants an AI agent to process customer support tickets, with the ability to read ticket data and call a CRM API, but with tight constraints.

The human issues an operator key, then creates a root capability grant:

- Capability: Read, scope `/tickets/**`; ApiCall, scope `crm.company.com/tickets/**`
- Constraints: RateLimit { max_actions: 200, window_secs: 3600 }, RequireReceipt
- Max delegation depth: 2
- Trust tier: Tier 2
- Expiration: 90 days
- Signed by the operator key

The operator delegates to the agent:

- Capability: Read, scope `/tickets/open/*`; ApiCall, scope `crm.company.com/tickets/read/**`
- Constraints: RateLimit { max_actions: 100, window_secs: 3600 }, MaxCost(0.50), RequireReceipt
- Delegation depth: 1
- Trust tier: Tier 2
- Expiration: 30 days
- Parent: root grant ID
- Signed by the operator key

Every invariant holds. The scope is narrower (open tickets only, read-only CRM calls). The rate limit is tighter (100 vs 200). An additional constraint was added (MaxCost). The trust tier is equal. The expiration is shorter. The depth is 1, within the maximum of 2. The grantor matches the previous grantee. The signature verifies.

Now the agent wants to delegate to a sub-agent that handles a specific ticket category:

- Capability: Read, scope `/tickets/open/billing/*`; ApiCall, scope `crm.company.com/tickets/read/billing/**`
- Constraints: RateLimit { max_actions: 20, window_secs: 3600 }, MaxCost(0.10), RequireReceipt, TimeWindow { start_hour: 9, end_hour: 17 }
- Delegation depth: 2
- Trust tier: Tier 2
- Expiration: 7 days
- Parent: agent's grant ID
- Signed by the agent key

Again, every invariant holds. The scope narrowed to billing tickets. The rate limit tightened to 20. The cost ceiling dropped to ten cents. A time window was added. The expiration is shorter. Depth 2 equals the maximum, so this sub-agent cannot delegate further.

At any point, any peer can verify the entire chain: check all three signatures, confirm scope subsetting at each link, confirm constraints tighten at each link, confirm depths are monotonic, confirm expirations nest, confirm the chain terminates at a key whose certificate traces back to the genesis key. The verification is mechanical, deterministic, and requires no network access.

### What Delegation Chains Give You

Delegation chains make authority transparent. Not transparent in the sense of "we published a policy document" — transparent in the sense of "here is the mathematical proof that this agent is authorized to take this action, under these constraints, derived from this human's key, through this specific chain of signed grants."

They make authority constrainable. Each link can only narrow, never widen. This means the human at the root can set maximum bounds that no downstream delegation can exceed, and every intermediate operator can tighten further within those bounds.

They make authority auditable. The chain is evidence. When a receipt is produced, it references the capability grant that authorized the action. The grant references its parent. The parent references the root. Any auditor can reconstruct the full authorization chain for any action in the system.

And they make authority revocable. Revoke a parent grant and every child grant becomes invalid, because the chain no longer verifies. The human at the root can pull authority from any point in the chain, and the revocation cascades automatically.

---

## Chapter 11: Receipts

The receipt is ZeroPoint's atomic unit of accountability. Every significant action in the system produces one. Together, they form the evidentiary record that makes every other guarantee — delegation chains, policy decisions, audit trails — verifiable after the fact.

### The Six Receipt Types

Not all actions are the same, and not all receipts are the same. ZeroPoint defines six receipt types, corresponding to six stages in the lifecycle of a governed action. Together, they form a provenance chain — a receipt can reference a parent receipt, creating a trail from initial intent through to final outcome.

**Intent** (prefixed `intn-`) records that someone expressed an intention to act. This is the root of a provenance chain — the moment a request enters the system. The Intent receipt captures who made the request, when, and the hash of the request content (not the content itself — the hash preserves privacy while enabling verification).

**Design** (prefixed `dsgn-`) records that a plan was formulated in response to the intent. For an agent that plans before acting — decomposing a complex task into steps — the Design receipt captures the plan's hash and its relationship to the Intent receipt.

**Approval** (prefixed `appr-`) records that a governance decision authorized the action. This is the receipt that links to the policy engine's output: the decision (Allow, Warn, Review, etc.), the rules that contributed, and the risk assessment.

**Execution** (prefixed `rcpt-`) records that the action was performed. This is the core receipt — it captures what happened, how long it took, what resources it consumed, the hash of the outputs, and the policy decision that authorized it.

**Payment** (prefixed `pymt-`) records that a financial transaction occurred in connection with the action. Not all actions involve payment, but when they do, the Payment receipt links the financial event to the execution.

**Access** (prefixed `accs-`) records that a resource was accessed as a result of the action. This might be a credential retrieved from the vault, an API endpoint called, or a file read.

The provenance chain links these receipts through `parent_receipt_id`. An Execution receipt might reference an Approval receipt, which references an Intent receipt. The chain makes it possible to trace any outcome back to its origin — who asked, who approved, and what happened.

### Anatomy of a Receipt

A receipt contains:

**Identity:** A unique ID (prefixed by type), a schema version for forward compatibility, and the receipt type.

**Chain linkage:** The parent receipt ID (for provenance chains) and chain metadata (for the hash chain — sequence number, previous hash, content hash).

**Action:** The action type and its details — what was done.

**Actor:** Who performed the action — the executor's identity.

**Policy:** The policy decision that authorized the action, including the decision type and the rule that made it.

**Timing:** Wall-clock duration, CPU user time, CPU system time. This is not just metadata — it is evidence. An execution that claims to have completed instantly but whose outputs suggest minutes of computation is suspicious, and the timing in the receipt makes the discrepancy detectable.

**Resources:** Peak memory usage, bytes written, output size limit. Like timing, these are evidentiary fields that constrain what the receipt can plausibly claim.

**Outputs:** References to artifacts produced by the action.

**IO Hashes:** Blake3 hashes of stdout and stderr. Not the content itself — the hashes. This means a verifier can confirm that the output they received matches the output recorded in the receipt without the receipt needing to contain the entire output.

**Redactions:** Records of any redactions applied by the Sanitize decision. If the policy engine redacted sensitive patterns from the output, the receipt records what was redacted (by pattern, not by content), preserving the fact that sanitization occurred.

**Extensions:** A key-value map for vendor-specific extensions, using reverse-domain naming to avoid conflicts. This allows deployments to add custom metadata to receipts without modifying the core schema.

**Signature:** An Ed25519 signature over the canonical JSON representation of the receipt. The signature is what makes the receipt cryptographically verifiable — any peer with the actor's public key can confirm the receipt was produced by the claimed actor and has not been modified.

### Canonical Serialization

Receipts are serialized as canonical JSON — keys sorted alphabetically, no optional whitespace, deterministic representation of all values. This is essential for cryptographic integrity: if two implementations serialize the same receipt data differently, they will produce different hashes and different signatures. Canonical serialization ensures that the same data always produces the same bytes, which always produces the same hash, which always verifies against the same signature.

This is a deceptively important detail. Many systems serialize to JSON and call it "deterministic" without enforcing key ordering, numeric representation, or Unicode normalization. These systems produce signatures that verify on the machine that created them but fail on machines with different JSON libraries. ZeroPoint's canonical JSON is strict: sorted keys, no trailing commas, no comments, numbers without leading zeros, strings with consistent escaping. The format is the same on every machine, in every implementation, forever.

### The Cost of Universal Receipting

Every significant action produces a receipt. This is Tenet III — action without evidence is no action. But "every significant action" raises a practical question: what counts as significant?

The answer is defined by the GovernanceGate. Every action that passes through the gate — every action that is evaluated by the policy engine — produces a receipt. Actions that do not pass through the gate (internal bookkeeping, cache updates, log rotation) do not produce receipts. The gate is the significance boundary.

This means the receipting overhead is proportional to the number of governed actions, not the total computational activity of the agent. An agent might perform thousands of internal operations per second, but if it performs ten governed actions per minute, it produces ten receipts per minute. The overhead is real but bounded, and the epoch-based compaction mechanism described in the following chapter ensures it remains manageable over time.

---

## Chapter 12: Epoch Compaction — The Implementation

The Interlude introduced epoch-based compaction as a concept — the ledger-and-notary analogy, the idea of sealing epochs with Merkle roots, and the four verification modes. This chapter describes the implementation: the data structures, the algorithms, the storage architecture, and the protocol extensions that make it work in practice.

This is plumbing. It is also the plumbing that makes everything else in the book sustainable. Without it, the receipt chain — the foundation of every guarantee ZeroPoint makes — grows without bound and eventually becomes impractical. With it, the chain remains manageable for years, across millions of entries, on constrained hardware, over bandwidth-limited mesh links. Understanding this chapter is understanding how ZeroPoint operates at scale.

### The EpochSeal Structure

When an epoch closes, the node produces an EpochSeal — a signed summary of the epoch's contents. The seal contains:

**Identity fields:** An epoch number (monotonic, starting from 0) and a seal ID (prefixed `seal-` for easy identification in receipt streams).

**Chain linkage fields:** A reference to the previous seal (its ID and hash — `None` for the first epoch's seal), and a `chain_prev_hash` that links the seal into the regular hash chain. The seal is a chain entry. It has a prev_hash like any other entry, maintaining the continuous hash linkage.

**Epoch summary fields:** The entry count, the hashes of the first and last entries, and the global sequence numbers of the first and last entries. These allow any verifier to confirm the epoch's boundaries without retrieving its entries — the sequence numbers must be continuous with no gaps or overlaps, and the entry count must match the range.

**Integrity fields:** The Merkle root (a single Blake3 hash that commits to every entry in the epoch) and the Merkle depth (the tree's height, which determines proof size).

**Metadata fields:** When the epoch was opened and when it was sealed.

**Signing fields:** An Ed25519 signature over the canonical JSON of all the above fields, and the signer's public key. The signature makes the seal independently verifiable — any peer can confirm the seal was produced by the claimed node and has not been modified.

### Building the Merkle Tree

The Merkle tree construction is mechanical. Each leaf is the `entry_hash` of one chain entry — the Blake3 hash that already exists as part of normal chain operation. No new hashing is required for the leaves. They are free.

The tree is built bottom-up. Adjacent leaves are paired. Each pair is hashed together: `blake3(left_hash_bytes || right_hash_bytes)`, where `||` is byte concatenation — the raw 32-byte Blake3 digests concatenated into a 64-byte input. The resulting hash is the parent node. Parents are paired and hashed the same way. The process repeats level by level until a single root hash remains.

For an epoch of 8,192 entries, the tree has 13 levels and requires 8,191 hash operations. Blake3 processes data at roughly 4 gigabytes per second on modern hardware. Hashing 8,191 pairs of 64 bytes (approximately 512 kilobytes of total input) takes under one millisecond. The tree construction is computationally free for any practical purpose.

**Odd-count handling:** If the entry count is not a power of 2, the unpaired entry at each level is promoted to the next level without hashing. This is standard Merkle tree behavior. It does not affect the root's integrity — the tree still commits to every entry, regardless of whether the count is even.

**Why 8,192?** The epoch size is a power of 2 to produce a balanced tree with a predictable depth. A balanced tree makes Merkle proofs a uniform size (always 13 hashes for a full epoch), which simplifies the mesh protocol — every proof fits in a single packet. The specific value 8,192 balances epoch frequency (an agent doing 1,000 actions per day seals roughly every 8 days) with tree depth (13 levels, manageable for proofs and construction).

### Merkle Proofs

A Merkle proof demonstrates that a specific entry belongs to a sealed epoch without revealing any other entry. The proof consists of the sibling hashes along the path from the entry's leaf to the root — one hash per level of the tree.

To prove that entry E5 belongs to an epoch with 8 entries:

```
                    Merkle Root
                   /            \
              H(0-3)            H(4-7)      ← sibling: H(0-3)
             /      \          /      \
         H(4-5)   H(6-7)                   ← sibling: H(6-7)
         /   \
        E4   [E5]                           ← sibling: E4
```

The proof is three hashes: E4 (the leaf's sibling), H(6-7) (the parent's sibling), and H(0-3) (the grandparent's sibling). The verifier takes E5's hash, hashes it with E4 to get H(4-5), hashes H(4-5) with H(6-7) to get H(4-7), and hashes H(4-7) with H(0-3) to get the root. If the computed root matches the `merkle_root` in the signed seal, the entry is proven to be part of the epoch.

For a full epoch of 8,192 entries, a proof is 13 hashes × 32 bytes = 416 bytes. This fits in a single 465-byte mesh payload. One packet, one proof. A verifier can confirm any entry in any sealed epoch with a single round-trip.

### Storage Architecture

The epoch system changes how the chain is stored. Instead of an unbounded table of all entries, the storage splits into three tiers:

**The active store** holds the current epoch's entries in SQLite — the same schema as before, with indexes on sequence number and conversation ID. The critical difference is that this table is bounded: it contains at most 8,192 entries. When the epoch seals, the table is cleared and a fresh epoch begins. The active store also holds the seal chain — all EpochSeals ever produced. Seals are tiny (a few hundred bytes each) and grow at a rate of roughly one per week, so the seal chain is negligible even over years.

The SQL schema adds a `epoch_seals` table:

```sql
CREATE TABLE epoch_seals (
    epoch_number INTEGER PRIMARY KEY,
    seal_id TEXT NOT NULL UNIQUE,
    seal_hash TEXT NOT NULL,
    prev_seal_hash TEXT,
    merkle_root TEXT NOT NULL,
    merkle_depth INTEGER NOT NULL,
    entry_count INTEGER NOT NULL,
    first_sequence INTEGER NOT NULL,
    last_sequence INTEGER NOT NULL,
    first_entry_hash TEXT NOT NULL,
    last_entry_hash TEXT NOT NULL,
    epoch_opened_at TEXT NOT NULL,
    epoch_sealed_at TEXT NOT NULL,
    signature TEXT NOT NULL,
    signer_public_key TEXT NOT NULL,
    canonical_json TEXT NOT NULL
);
```

The `canonical_json` column stores the full canonical JSON of the seal — the exact bytes that were signed. This allows any peer to re-verify the seal's signature without reconstructing the canonical form, which eliminates serialization ambiguity as a source of verification failure.

**The archive store** holds sealed epoch entries as compressed files — one file per epoch, Zstandard-compressed, containing one canonical JSON entry per line, ordered by sequence number. A typical epoch compresses from roughly 4 megabytes to 800 kilobytes. Archive files are immutable once written. They are never modified, only read for spot-check verification or forensic retrieval.

The archive directory structure is simple:

```
archives/
  epoch-000000.zst
  epoch-000001.zst
  epoch-000002.zst
  ...
```

**Retention policy** determines how long archives are kept locally. This is a deployment configuration, not a protocol decision. A deployment might keep 90 days locally and replicate to cold storage, or keep everything indefinitely, or keep only the seals and rely on peers for entry retrieval. The protocol does not mandate a retention period because mandating storage contradicts mesh sovereignty — each node decides for itself.

### In-Memory State

The `ReceiptChain` struct changes from an unbounded vector to a bounded working set:

```rust
pub struct ReceiptChain {
    chain_id: String,
    current_epoch: EpochBuffer,
    head_hash: String,
    current_epoch_number: u64,
    last_seal: Option<EpochSeal>,
}

struct EpochBuffer {
    entries: Vec<ChainEntry>,     // Bounded by EPOCH_MAX_ENTRIES
    opened_at: DateTime<Utc>,
    epoch_number: u64,
}
```

Memory usage is bounded at approximately 4 megabytes regardless of total chain length. A node that has been running for five years, with millions of entries across hundreds of epochs, uses the same active memory as one that started yesterday.

### The Sealing Procedure

When an epoch boundary is reached (8,192 entries or 7 days elapsed):

1. **Compute the Merkle tree** over the current epoch's entries. The leaf hashes already exist — they are the `entry_hash` fields computed during normal chain operation. Only the internal nodes need computing. Cost: under 1 millisecond.

2. **Create the EpochSeal** with the epoch number, entry count, boundary hashes, Merkle root, tree depth, timestamps, and a reference to the previous seal.

3. **Sign the seal** with the node's Ed25519 key over the canonical JSON representation. Cost: under 1 millisecond.

4. **Insert the seal** into the `epoch_seals` SQLite table.

5. **Export the active entries** to a compressed archive file.

6. **Clear the active entries** table.

7. **Insert the seal as the first entry** of the new epoch in the active table, maintaining hash chain continuity.

Total time: under 15 milliseconds. The sealing operation is invisible to the node's normal operation — it happens at most once per 8,192 actions or once per week, and it completes before a human could notice a pause.

### Mesh Protocol Extensions

The existing challenge/response protocol extends with three new challenge types:

**SealChain** requests the full seal chain. The responder sends seals one per packet (each seal is approximately 400-500 bytes serialized). For a year's history of 44 epochs, this is 44 packets — transmittable in seconds even over constrained links.

**MerkleProof** requests the proof path for a specific entry in a specific epoch. The responder retrieves the entry from the archive, computes the proof (13 sibling hashes for a full epoch), and returns the entry plus proof in a single packet.

**EpochEntries** requests all entries for a specific epoch. This is the forensic mode — the responder streams entries in batches of three (the existing compact format), requiring roughly 2,700 packets for a full epoch. This is expensive and rare, reserved for situations where spot-checking has raised suspicion.

The common verification path — request the seal chain, verify it, then spot-check random entries from random epochs with Merkle proofs — requires roughly 55 packets for a year's history. This is practical over mesh, even at the most constrained bandwidths.

### Scaling in Numbers

These numbers ground the architecture in operational reality:

| Duration | Entries | Epochs | Active Store | Archive (compressed) | Seal Chain |
|---|---|---|---|---|---|
| 1 day | 1,000 | 0 (open) | 500 KB | — | — |
| 1 week | 7,000 | 0 (open) | 3.5 MB | — | — |
| 1 month | 30,000 | 3 | 4 MB | 2.4 MB | 1.5 KB |
| 1 year | 365,000 | 44 | 4 MB | 35 MB | 22 KB |
| 5 years | 1,825,000 | 222 | 4 MB | 175 MB | 111 KB |

The active store — the memory and database footprint that affects runtime performance — is bounded at 4 megabytes. Always. Whether the node has been running for a day or a decade. The archive grows linearly but compresses well and can be offloaded per retention policy. The seal chain is so small it barely registers.

Verification scales similarly. Without epochs, verifying a year's history means walking 365,000 entries — approximately 122,000 mesh packets. With epochs, it means checking 44 seals and spot-checking a handful of entries — roughly 55 packets. The difference is three orders of magnitude.

This is what makes universal receipting sustainable. Not by making the chain lighter, but by making the chain manageable — bounded active storage, efficient verification, archival with cryptographic integrity preserved. The proof persists. The storage is practical. And the system scales.

---

## Chapter 13: Trust Tiers

*[Note: Chapters renumbered. Former Chapter 12 is now Chapter 13 with the addition of the Epoch Compaction implementation chapter.]*

Trust in ZeroPoint is not a score computed by a platform. It is a structural property of the agent's cryptographic configuration — what the agent can prove about itself, not what someone else has decided about it.

### Tier 0: Unsigned

An agent at Tier 0 has no cryptographic identity. It exists, it runs, it performs actions — but it cannot sign receipts, cannot establish authenticated links with peers, and cannot participate in delegation chains. Trust at Tier 0 is filesystem-level: you trust the agent because it is running on your machine, and you control the machine.

Tier 0 is the starting state. Every agent begins here. Policy rules still evaluate (the HarmPrincipleRule and SovereigntyRule apply regardless of tier), and the audit trail still records actions (unsigned entries are still hash-chained, just not signed). But the agent's actions are not cryptographically attributable to any identity. If the agent claims it performed an action, there is no signature to verify.

Tier 0 is appropriate for local development, testing, and experimentation — situations where cryptographic accountability is not yet needed. It is not appropriate for production deployments where actions have consequences.

### Tier 1: Self-Signed

An agent at Tier 1 has generated a local Ed25519 key pair. It can sign receipts and audit entries, proving that a specific key produced them. It can establish encrypted, authenticated links with peers. It can prove that it is the same entity across interactions — session continuity, identity persistence.

What Tier 1 cannot do is delegate authority, because delegation requires a verifiable chain back to a genesis key. A Tier 1 agent's key is self-signed — it vouches for itself, but no one vouches for it. This is sufficient for identity (the agent is consistently who it claims to be) but not for provenance (there is no proof of who authorized the agent to act).

Tier 1 is the threshold of cryptographic participation. Below Tier 1, the agent is anonymous. At Tier 1, the agent has a verifiable identity. The receipts it signs are attributable to its key. The links it establishes are authenticated. The audit entries it produces are signed. This is a meaningful improvement over Tier 0 — the agent's history is now cryptographically its own.

### Tier 2: Chain-Signed

An agent at Tier 2 has a key that is linked to a genesis root key through a verified delegation chain. It has full provenance — not just "I am who I say I am" but "I am who I say I am, I was authorized by this operator, who was authorized by this genesis key, which is held by this human." Every claim can be verified by walking the certificate chain.

At Tier 2, the agent can delegate capabilities to sub-agents (within the constraints of its own grants). It can participate in mesh consensus. It can produce receipts that carry the full weight of the delegation chain. And any peer can verify the entire provenance — from the agent's key, through the operator key, to the genesis key — without contacting anyone.

Tier 2 is the full accountability tier. The agent's actions are signed, chained, and traceable to a human. The delegation chain constrains what the agent can do. The policy engine evaluates with full context. The audit trail is signed and verifiable. This is what ZeroPoint is designed for — the state where every guarantee the protocol offers is fully active.

### Moving Between Tiers

Moving from Tier 0 to Tier 1 is a local operation: generate a key pair. No external authority is needed. The agent's identity is self-bootstrapped.

Moving from Tier 1 to Tier 2 requires an operator — someone holding an operator key (which itself requires a genesis key). The operator issues the agent's key, signs its certificate, and the agent now has a verifiable chain. This is a deliberate gate: Tier 2 cannot be achieved without a human-authorized operator in the loop.

Moving down is also possible. If an agent's operator key is revoked, the agent's Tier 2 status is invalidated — it falls back to Tier 1 (it still has a key pair) but can no longer prove provenance. If the agent's key itself is revoked, it falls to Tier 0. Revocation cascades downward through the hierarchy.

The tier is not a reward for good behavior. It is a description of cryptographic capability. A Tier 2 agent with a terrible track record is still Tier 2 — but its terrible track record is signed, chained, and verifiable by anyone. The tier tells you what the agent can prove. The receipts tell you what it has done.

---

# PART IV — THE SYSTEMS

---

## Chapter 13: The Audit Trail

The audit trail is where theory meets operation. The architectural principles described in the previous chapters — hash-chaining, signing, tamper evidence — are realized in a concrete system that records every governance decision, every action, every outcome, in a sequence that any peer can verify.

### What Gets Recorded

Every audit entry captures five dimensions of the event it records.

The **actor** — who did it. ZeroPoint distinguishes four actor types: User (a human interacting through a channel), Operator (the system's operational identity), System (an internal process, identified by name), and Skill (an activated capability module, identified by ID). The actor type matters for forensic analysis — understanding whether an action was initiated by a human, triggered by the system, or performed by a skill changes its significance.

The **action** — what happened. Eleven action types cover the full operational surface: MessageReceived (a request entered the system), ResponseGenerated (the system produced output, with model identification), ToolInvoked (an external tool was called, with argument hashes), ToolCompleted (a tool call finished, with success/failure and output hash), CredentialInjected (a secret was provided to a skill), PolicyInteraction (a governance decision required or received human input), OutputSanitized (content was redacted), SkillActivated (a capability module was engaged), SkillProposed (the learning system suggested a new skill), SkillApproved (a human approved a proposed skill), and SystemEvent (anything else worth recording).

The **policy decision** — what the governance system decided. Allow, Sanitize, Warn, Review, or Block, along with the name of the policy module that made the decision. This links every action to the governance reasoning that authorized it.

The **chain linkage** — how this entry connects to history. The previous entry's hash, this entry's hash (computed over the canonical JSON of all fields), and optionally a signature if the node operates at Tier 1 or above.

The **receipt** — optionally, the full cryptographic receipt proving the action occurred. Not every audit entry carries a receipt (some events, like MessageReceived, record context rather than governed actions), but every governed action's audit entry links to its receipt.

### The Hash Chain in Practice

Each audit entry's hash is computed as: `blake3(canonical_json(entry))`. The `prev_hash` field contains the hash of the immediately preceding entry. The first entry in the chain (the genesis entry) has a prev_hash of `blake3("")` — the hash of the empty string, a well-known constant.

Verification is straightforward: start at the genesis entry, compute its hash, confirm it matches the next entry's prev_hash, compute that entry's hash, confirm it matches the next, and continue. If every hash matches, the chain is intact. If any hash does not match, the chain has been tampered with, and the point of tampering is precisely identified — it is the entry whose prev_hash does not match the computed hash of the entry before it.

This verification requires nothing but the entries themselves and a Blake3 implementation. No network access, no trusted third party, no special privilege. Any observer with the entries can verify the chain independently.

### Persistence

Audit entries are persisted to SQLite — a single-file, serverless database that requires no configuration and works on every platform. The schema is minimal: the entry fields as columns, with indexes on conversation_id (for scoping queries to a session) and timestamp (for time-range queries).

SQLite was chosen deliberately over more sophisticated databases. ZeroPoint runs on everything from cloud servers to embedded devices to mesh-connected laptops. A database that requires a running server process, network configuration, or specialized administration contradicts the self-contained, sovereign design. SQLite is a file. It works everywhere. It is enough.

The epoch-based compaction system (described in the Interlude) manages growth: active entries live in SQLite, sealed epochs are archived to compressed files, and the seal chain provides lightweight verification of historical integrity.

### Querying the Trail

The audit store supports two query patterns: recent entries for a conversation (bounded by a limit parameter, ordered by timestamp descending) and full chain export (bounded by a limit, ordered by timestamp ascending). Both patterns accept a limit to prevent unbounded result sets.

This is deliberately minimal. ZeroPoint's audit trail is not an analytics database. It is a verification infrastructure. Complex queries — filtering by actor, grouping by action type, correlating across conversations — are the domain of external analysis tools that consume exported audit data. The audit store's job is to record faithfully and export completely. Analysis is someone else's problem.

---

## Chapter 14: Collective Verification

A single node can prove its own chain is intact. But a single node proving its own integrity is self-attestation, not verification. Real verification requires a second party — a peer who independently checks the chain and signs an attestation of what they found.

This is what collective verification provides. It is the mechanism by which the network, not just the individual node, vouches for the integrity of audit trails.

### The Challenge

Verification begins with a challenge. A peer sends an AuditChallenge to another peer, requesting proof of chain integrity. The challenge specifies a range: either the most recent N entries, or all entries since a known hash (allowing the challenger to pick up where a previous verification left off).

The challenge also includes, optionally, the challenger's known tip — the hash of the most recent entry the challenger has already verified. This allows incremental verification: "I verified your chain up to this hash last week; show me what's happened since."

### The Response

The challenged peer responds with an AuditResponse containing up to three compact audit entries (the maximum that fits within the 500-byte mesh MTU), the current chain tip hash, the total number of entries available in the requested range, and a pagination flag indicating whether more entries exist beyond the batch.

The compact format — CompactAuditEntry — strips each entry to its essential verification fields: ID, timestamp, previous hash, entry hash, actor (abbreviated), action type (abbreviated), policy decision, policy module, and signature. The full entry content (receipt payloads, detailed action data) is omitted. This is sufficient for chain verification — the verifier checks hash linkage and signatures without needing the full payload.

If the response indicates more entries are available, the challenger sends follow-up requests, paginating through the chain in three-entry batches. For a chain of 300 entries, this requires 100 round-trips — chatty by HTTP standards, but practical over mesh where bandwidth is precious and reliability is more important than speed.

### The Attestation

After verifying the entries received, the challenger produces a PeerAuditAttestation — a signed document stating what they verified and what they found. The attestation contains the peer's identity (mesh destination hash), the range verified (oldest and newest entry hashes), the number of entries checked, whether the chain was valid, the number of valid signatures found, and the challenger's own signature over the whole attestation.

The attestation is itself a cryptographic artifact. It can be presented to third parties as evidence that a named peer, at a specific time, verified a specific range of another peer's audit chain and found it intact (or not). This is reputation from receipts — the attestation is a receipt of verification.

With epoch-based compaction, attestations become more powerful. A peer can verify the seal chain (checking 44 seals for a year's history), spot-check entries from random epochs with Merkle proofs, and produce an attestation that covers the full history at seal-chain level with targeted drill-down. The attestation records which epochs were spot-checked and how many Merkle proofs were validated, giving the attestation's consumer a clear picture of verification depth.

### Trust from Verification, Not from Authority

Collective verification inverts the traditional trust model. In conventional systems, trust flows from authority — a certificate authority says you're trustworthy, a platform says your trust score is high, an administrator says you're approved. In ZeroPoint, trust emerges from verification — your peers have checked your chain, found it intact, and signed attestations saying so.

No single attestation is definitive. But a node whose chain has been verified by multiple independent peers, across overlapping time ranges, with consistent results, has demonstrated integrity through evidence rather than assertion. The attestations accumulate. The trust is earned, not granted.

---

## Chapter 15: The Execution Engine

The execution engine is where governed actions become real — where code runs, tools execute, and outcomes are produced. It is also where the gap between containment and accountability becomes most visible, because sandboxing (preventing escape) and receipting (proving what happened) are different problems that require different solutions.

### Why Not Docker

Docker is the default answer to "how do I isolate code execution." It is a good answer for many use cases. It is the wrong answer for ZeroPoint, for three reasons.

First, Docker requires a daemon — a long-running server process with root privileges. This contradicts ZeroPoint's deployment model, which targets everything from cloud servers to laptops to embedded devices. A governance system that requires Docker is a governance system that cannot run on a Raspberry Pi, cannot run offline, and cannot run in environments where installing a system daemon is not an option.

Second, Docker provides containment but not receipting. A Docker container prevents the code inside from accessing resources outside the container. It does not produce a cryptographic receipt of what the code did inside the container. It does not hash the inputs, hash the outputs, record the timing, measure the resource usage, or sign the result. Containment answers "could this code have escaped?" Receipting answers "what did this code actually do?" ZeroPoint needs both.

Third, Docker's abstraction level is wrong. ZeroPoint does not need to isolate entire operating system images. It needs to isolate individual code executions — a Python script, a Node.js function, a shell command — with fine-grained control over filesystem access, network access, and resource limits. OS-native sandboxing primitives (namespaces and seccomp on Linux, sandbox-exec on macOS, restricted tokens on Windows) provide this at a lower level, with less overhead, and without a system daemon.

### The Execution Model

The execution engine receives an ExecutionRequest specifying the runtime (Python, Node.js, or Shell), the code to execute, arguments, an optional sandbox configuration override, and the requesting agent's identity. It returns an ExecOutcome containing stdout, stderr, the exit code, whether the execution timed out, and — critically — an ExecutionReceipt.

The ExecutionReceipt is what distinguishes governed execution from mere sandboxed execution. It contains the input hash (Blake3 of the code and arguments), the output hash (Blake3 of stdout, stderr, and exit code concatenated), timing data (wall-clock duration, CPU user time, CPU system time), resource usage (peak memory, bytes written), and optionally a reference to a deployment receipt that attests to the execution environment's configuration.

The receipt proves what went in (input hash), what came out (output hash), how long it took (timing), and what resources it consumed (usage). Any peer with the receipt can verify that a specific input produced a specific output in a specific time with specific resources. They cannot verify the content of the input or output from the receipt alone (those are hashes), but if they have the actual input and output, they can verify the hashes match.

### Sandbox Capabilities

The sandbox configuration follows a deny-by-default model:

**Filesystem:** Restricted to a temporary directory. The executing code cannot access the host filesystem, the agent's data, or any other code's temporary directory. The tmpdir is created fresh for each execution and destroyed afterward.

**Network:** Denied by default. If the execution requires network access (for API calls, for example), specific endpoints can be allowlisted per-request. The allowlist is part of the sandbox configuration and is recorded in the receipt.

**CPU time:** Limited. The execution has a wall-clock timeout after which it is terminated. The timeout is configurable per-request and defaults to a conservative value.

**Memory:** Limited. Peak memory usage is tracked and enforced. The execution is terminated if it exceeds the configured ceiling.

**Output:** Limited. The total bytes of stdout and stderr are capped. An execution that produces unlimited output (intentionally or through a bug) is truncated, not allowed to fill the disk.

### The Integration

The execution engine is invoked by the pipeline — the orchestration layer that wires the policy engine, the LLM providers, the skill registry, and the execution engine together. The pipeline ensures that every execution request passes through the GovernanceGate before reaching the engine. The gate evaluates the request (Execute action type, High risk), the policy engine produces a decision, and only if the decision is Allow or Sanitize does the request proceed to execution.

The execution receipt joins the audit chain like any other receipt. It is signed by the agent's key, hash-chained to the previous audit entry, and verifiable by any peer. The chain of evidence is continuous: a human expressed an intent (Intent receipt), the system formulated a plan (Design receipt), the governance gate approved the execution (Approval receipt), the execution engine ran the code (Execution receipt), and the output was produced and delivered. Every step is receipted. Every receipt is chained. The chain is the truth.

---

## Chapter 16: The Learning Loop

ZeroPoint does not just govern actions. It learns from them. The learning loop observes patterns in how agents operate, detects recurring sequences, and proposes new skills — modular capabilities that codify repeated behavior into reusable, governed components.

### Episodes

The unit of learning is the episode — a complete record of a governed interaction, from request to outcome. An episode captures the conversation ID, the timestamp, a hash of the request (not the content — privacy is preserved), the detected category of the request, the tools that were used (names and argument hashes), the skills that were active, the model that was used, the outcome (Success, Failure, or Partial), optional user feedback (Positive, Negative, or Correction with details), the duration in milliseconds, and the policy decisions that were made during the episode.

The request hash deserves emphasis. The learning loop does not store user requests. It stores the Blake3 hash of each request. This means the loop can detect that two episodes involved the same request (the hashes match) without knowing what the request said. Pattern detection works on structural features — tool sequences, skill combinations, outcome rates — not on content. This is privacy by architecture, not by policy.

Episodes are persisted to SQLite, indexed by category, and available for pattern analysis.

### Pattern Detection

The pattern detector examines recent episodes within a category, groups them by tool sequence (the ordered list of tools used), and identifies sequences that recur above a threshold (default: 3 occurrences). When a recurring sequence is found, the detector computes a confidence score and produces a Pattern.

The confidence calculation is conservative: `min(occurrence_count / total_episodes_in_category * 0.9, 0.95)`. The 0.9 multiplier prevents overconfidence from small samples. The 0.95 ceiling ensures no pattern ever reaches certainty — there is always room for the pattern to be wrong. This is epistemically honest: statistical patterns are evidence, not proof.

A Pattern contains the tool sequence that was detected, the episode IDs that contributed to the detection, a human-readable description, the occurrence count, and the confidence score. The pattern is a candidate observation, not a mandate. It says "this sequence of tools keeps appearing in this category of request" — nothing more.

### From Patterns to Skills

When a pattern is detected with sufficient confidence, it becomes a SkillCandidate — a proposal for a new skill that codifies the detected behavior. The candidate contains a skill manifest (name, description, tools, required credentials, keywords, optional prompt template), the pattern's origin information (which episodes contributed), the confidence score, and a status: Proposed.

The status lifecycle is Proposed → UnderReview → Approved or Rejected. The critical transition is from UnderReview to Approved: a human must make this decision. The system proposes. The human approves. This is Tenet IV applied to the learning loop — the system cannot self-authorize new capabilities. The human at the root decides whether a detected pattern should become a permanent skill.

An approved skill enters the skill registry and becomes available for activation in future episodes. Its performance is tracked through SkillStats: invocation count, success count, failure count, average latency, and last used timestamp. A skill with a declining success rate is evidence that the underlying pattern has changed — the learning loop has detected something, but the something is no longer valid.

### What the Learning Loop Does Not Do

The learning loop does not use machine learning. It uses frequency analysis — counting occurrences, grouping by sequence, computing ratios. This is a deliberate choice. Machine learning models are opaque, non-deterministic, and difficult to audit. Frequency analysis is transparent, deterministic, and trivially auditable. The pattern detector's logic can be verified by anyone who can read the code. The same episodes in the same order always produce the same patterns.

The learning loop does not modify agent behavior automatically. It proposes. A human approves or rejects. The approved skill is available but not mandatory — the agent may use it, but the skill does not override the agent's existing capabilities or the governance constraints that apply to it.

The learning loop does not retain raw request content. Hashes only. This means the loop cannot be used to reconstruct user queries, cannot be used for surveillance, and cannot be subpoenaed for content it does not possess. The learning is structural, not content-based.

---

## Chapter 17: The Skill System

Skills are ZeroPoint's mechanism for modular capability — reusable, governed packages of tools, credentials, and prompt templates that an agent can activate to handle specific categories of work.

### Anatomy of a Skill

A skill is defined by its manifest: a name, a description, a version, the tools it requires (each defined with a name, description, and parameter schema), the credentials it needs (by reference, never by value), keywords for matching, and an optional prompt template that shapes how the agent approaches the skill's domain.

Skills have four possible origins: BuiltIn (shipped with ZeroPoint), Extracted (generated by the learning loop from detected patterns), Community (contributed by an author in the community), and Enterprise (created by a specific organization). The origin matters for trust — a BuiltIn skill has been reviewed by the core team, an Extracted skill was proposed by the learning loop and approved by a human, a Community skill was contributed by an external author, and an Enterprise skill was created within a specific organizational context.

### The Skill Lifecycle

A skill begins as a candidate — either manually created or proposed by the learning loop's pattern detection. It enters the UnderReview state, where a human evaluates whether it should be approved. The evaluation considers whether the skill's tool requirements are safe, whether the credential references are appropriate, whether the prompt template introduces any governance concerns, and whether the skill's keywords are accurate enough to avoid false activation.

Once approved, the skill enters the registry and is available for activation. When an incoming request matches a skill's keywords, the skill is activated — its tools become available to the agent, its credentials are injected (CredentialAccess receipts are produced for each injection), and its prompt template shapes the agent's approach.

The skill's performance is tracked continuously. Every invocation updates the skill's statistics: success rate, average latency, failure reasons. A skill that consistently fails or slows down is evidence of a problem — either the skill's design is wrong, the underlying pattern has changed, or the tools it depends on have degraded.

### Governance of Skills

Skills are governed by the same mechanisms that govern everything else in ZeroPoint. When a skill is activated, a SkillActivated audit entry is recorded. When a skill uses a tool, the tool invocation passes through the GovernanceGate. When a skill accesses a credential, a CredentialInjected audit entry records the access. The skill does not bypass governance — it operates within it.

Skill credentials deserve particular attention. A skill's manifest declares what credentials it needs, but the manifest does not contain the credentials themselves. At activation time, the runtime retrieves the credentials from the encrypted vault (a separate, secured store) and injects them into the skill's execution context. The injection is logged. The credential values are never written to the audit trail — only the credential references. This means the audit trail proves that a skill accessed a specific credential at a specific time, without revealing what the credential contains.

---

# PART V — THE NETWORK

---

## Chapter 18: Mesh Architecture

Everything described so far — keys, receipts, chains, policies, grants — works on a single node. A single agent, governed by a single operator, producing receipts into a single chain. This is valuable, but it is not the full vision. The full vision is a network of governed agents, communicating over any transport, exchanging receipts and capabilities and policy modules, verifying each other's chains, and building collective trust through mutual verification.

The transport that makes this possible is a mesh network — specifically, a Reticulum-compatible mesh network. Understanding why mesh, and why Reticulum, requires understanding what the network layer must provide and what it must not.

### What the Network Must Provide

The governance protocol — receipt exchange, audit challenges, capability delegation, policy module sharing — requires a transport that can carry cryptographically signed, small messages between identified peers. The messages are small (most fit in a single 500-byte packet). The peers are identified by cryptographic keys, not by IP addresses or domain names. The communication must be encrypted end-to-end, so that intermediary nodes cannot read or modify governance messages. And the transport must be sovereign — no participant is forced to depend on infrastructure they do not control.

### What the Network Must Not Require

DNS. Certificate authorities. Cloud infrastructure. Always-on connectivity. A specific physical medium. Administrative credentials on a platform. Payment to an intermediary. Permission from a gatekeeper.

These are the dependencies that make conventional networked systems fragile, censorable, and surveillance-friendly. If your governance protocol requires DNS, your governance can be disrupted by poisoning DNS. If it requires a certificate authority, your governance depends on the CA's continued cooperation. If it requires cloud infrastructure, your governance lives in someone else's data center. Each dependency is a chokepoint — a point where a sufficiently powerful adversary can intercept, disrupt, or surveil.

### Why Reticulum

Reticulum, created by Mark Qvist, is an encrypted networking stack designed from first principles to require none of these dependencies. Identity is a key pair — specifically, Ed25519 for signing and X25519 for key exchange, the same cryptographic primitives ZeroPoint uses for its governance layer. Authentication is a signature verification. Addresses are derived from public keys through 128-bit destination hashing. There is no naming authority, no certificate hierarchy, no trust registry.

Communication works over any medium that can carry data. Reticulum's transport layer is medium-agnostic: LoRa radios at 300 baud, WiFi, Ethernet, TCP over the internet, serial connections, or any future transport. A Reticulum packet looks the same whether it traveled over fiber optic cable or was relayed by a handheld radio in a forest. The network routes around failures and works in disconnected, delay-tolerant environments.

ZeroPoint's mesh transport is wire-compatible with Reticulum — it uses HDLC-framed packets that a standard Reticulum node can forward, and it implements the same cryptographic identity scheme. This means ZeroPoint nodes are citizens of the Reticulum network, not a separate network that merely imitates it. ZeroPoint governance messages can traverse Reticulum infrastructure, be relayed by Reticulum nodes, and reach destinations through Reticulum's routing — all without Reticulum nodes needing to understand ZeroPoint's governance layer. The governance is in the payload. The transport is Reticulum's.

### The Wire Format

A ZeroPoint mesh packet follows a strict structure dictated by the 500-byte default MTU. The packet header contains the type indicator (2 bytes), destination address (16 bytes, derived from the recipient's public key), and a context byte. The remaining 465 bytes carry the payload — the governance message.

The MeshEnvelope wraps every governance payload with a sender hash (identifying the sender's mesh destination), a sequence number (for ordering and deduplication), a timestamp, and a 64-byte Ed25519 signature over the entire envelope. The signature ensures that every mesh message is authenticated — a peer receiving a message can verify it came from the claimed sender.

Within the envelope, the payload is msgpack-encoded for compactness. A CompactAuditEntry — the wire format for audit chain exchange — uses abbreviated field names (ts for timestamp, ph for prev_hash, eh for entry_hash) to minimize overhead. Three compact entries plus envelope overhead typically fit within 380-450 bytes — safely under the 465-byte payload limit.

This tight packaging is not a limitation. It is a design feature. Reticulum's 500-byte MTU exists because the network must work over extremely constrained links — a LoRa radio at 300 baud, where every byte is expensive. Designing for this constraint from the start means ZeroPoint governance works everywhere Reticulum works, including environments where bandwidth is precious and every packet must count.

---

## Chapter 19: Peer Introduction and Capability Exchange

When two ZeroPoint nodes discover each other on the mesh, a structured introduction protocol establishes their relationship, exchanges capabilities, and sets the terms under which they will interact.

### The Introduction

A peer introduction is a governed action — it passes through the GovernanceGate like any other action. The action type is PeerIntroduction, which carries the peer's mesh address, its role, its genesis key fingerprint, and a critical boolean: whether the peer shares the same genesis key.

Same-genesis introductions (two agents under the same human's authority) are classified as High risk. Different-genesis introductions (agents from different deployments, potentially different organizations) are classified as Critical risk. This classification affects policy evaluation — a deployment might allow same-genesis peer communication freely while requiring human Review for cross-genesis introductions.

The introduction includes the peer's certificate chain — the verifiable path from the peer's key back to its genesis key. The receiving node walks the chain, verifies every signature, and confirms the peer's claimed identity and authority. If the chain does not verify, the introduction is rejected.

### Capability Negotiation

After introduction, peers exchange capability grants. This is bilateral negotiation: each peer presents the capabilities it is willing to offer the other, and each peer evaluates whether to accept.

The exchange is governed by the same capability grant system described in Chapter 9 — each offered capability is a signed grant with scope, constraints, and expiration. The receiving peer evaluates the offered grants against its own policy rules before accepting. A grant that violates local policy is rejected regardless of who offered it. Sovereignty applies to capability acceptance as well as capability exercise.

The result of negotiation is a bilateral capability agreement: each peer knows what the other is willing to do and under what constraints. The agreement is recorded — both peers produce receipts of the negotiation — and the terms are enforced by each peer's Guard.

### The Six Mesh Actions

Once a relationship is established, peers can perform six types of mesh action:

**ForwardReceipt** — send a receipt to a peer. This is how proof of action propagates through the network. A receipt produced on Node A can be forwarded to Node B, which can forward it to Node C. Each forwarding is itself a governed action that produces a receipt.

**AcceptReceipt** — receive and validate a receipt from a peer. The receiving node checks the signature, verifies the hash chain linkage (if applicable), and decides whether to record the receipt in its own store.

**SharePolicy** — send a WASM policy module to a peer. This is how policy standards propagate. A community-developed policy module can be shared across the mesh, with each receiving node evaluating it in a sandbox before deciding whether to load it.

**AcceptPolicy** — receive and evaluate a policy module from a peer. The receiving node verifies the module's hash against the claimed hash, loads it in a sandboxed environment, and evaluates whether to add it to its policy engine.

**DelegateCapability** — delegate a capability to a peer. This extends the delegation chain across the mesh. All eight delegation chain invariants are enforced — scope can only narrow, constraints can only tighten, expiration can only shorten.

**AcceptDelegation** — receive and validate a delegated capability from a peer. The receiving node walks the delegation chain, verifies every signature, checks every invariant, and decides whether to accept the delegation.

Each mesh action passes through the GovernanceGate. Each produces a receipt. Each is recorded in the audit trail. The governance does not stop at the node boundary. It extends across the mesh, through every interaction, between every peer.

---

## Chapter 20: Reputation

Reputation in ZeroPoint is not a score assigned by an authority. It is the emergent property of a peer's verified receipt history. A peer with a long chain of valid receipts, verified by multiple independent peers through signed attestations, has demonstrated reliability through evidence — not through a number that someone computed.

### Reputation from Receipts

A peer's reputation is its receipt chain. The chain proves what the peer did, what constraints it operated under, whether it stayed within its capability grants, and whether its audit chain verified when challenged. The receipts are the reputation. There is no separate reputation system.

This is a meaningful distinction from reputation scores. A score abstracts away the evidence — it takes a complex history and reduces it to a number. The number is easy to consume but impossible to audit. Why is the score 0.85? What evidence contributed? Which interactions mattered? The score does not say.

A receipt chain answers all of these questions. The evidence is the reputation. Anyone who wants to evaluate a peer's trustworthiness can examine the chain directly, or rely on attestations from peers who have already verified it. The evaluation is open, the evidence is accessible, and the methodology is transparent.

### Reputation in Policy

The ReputationGateRule integrates reputation into policy decisions. When a mesh action involves a peer, the policy context includes the peer's reputation information — its address, its reputation grade, and a score derived from its verification history. The rule can gate mesh actions based on this information: a peer with no verification history might be allowed to exchange receipts but not to accept delegated capabilities.

This is a pragmatic concession. While ZeroPoint's ideal is "the receipts are the reputation," real-time policy decisions cannot walk an entire receipt chain for every interaction. The reputation score is a cache — a summary of verification history that the policy engine can evaluate quickly. But the score is always derivable from the underlying evidence. It is a convenience, not a replacement for the receipts themselves.

### What Reputation Cannot Do

Reputation cannot prove honesty. A peer that consistently produces valid receipts for its actions is demonstrably reliable — its chain is intact, its signatures verify, its peers have attested to its integrity. But reliability is not honesty. A peer could be reliably operating within the letter of its constraints while violating their spirit. The receipts prove compliance with the measurable constraints. They cannot prove good faith.

This is an inherent limitation of any evidence-based trust system. Evidence proves what happened. It does not prove intent. ZeroPoint's position is that provable compliance is better than assumed good faith, even though it is not as good as guaranteed benevolence. The protocol makes actions verifiable. It does not make actors virtuous.

---

## Chapter 21: Portable Trust

This is the culminating argument. Everything in the book — the tenets, the architecture, the systems, the network — builds toward a single structural property: trust that moves with the participant, not with the platform.

### What Portable Trust Means

In conventional systems, trust is a platform asset. Your reputation on Platform A means nothing on Platform B. Your audit history on one system does not transfer to another. Your agent's track record — years of reliable, governed operation — is locked in a database you do not control, on infrastructure you do not own, accessible only through an API that the platform can revoke at any time.

This creates a lock-in effect that has nothing to do with technical capability and everything to do with who controls the evidence. Leaving a platform means leaving your trust behind. Starting fresh means starting from zero. The cost of exit is not the migration of data or code — it is the loss of accumulated proof.

ZeroPoint eliminates this cost.

An agent's receipts are signed by the agent's own key. They are hash-chained by the protocol, not by the platform. They are verifiable by any peer with the agent's public key, without the platform's cooperation. The capability grants that define the agent's authority are self-contained, signed tokens that travel with the agent. The delegation chain that establishes the agent's provenance is a sequence of signed certificates that any verifier can walk. The audit attestations that prove the agent's track record are signed by independent peers.

When the agent moves to a new platform, all of this moves with it. The receipts, the grants, the chain, the attestations. The new platform does not need the old platform's database. It does not need the old platform's cooperation. It needs only the cryptographic artifacts that the agent carries — and the mathematics to verify them.

### What This Makes Possible

When exit is costless, competition is real. A platform that knows its users can leave at any time — carrying their full trust history — cannot rely on lock-in for retention. It must compete on quality: better tools, better performance, better service. This is the market discipline that lock-in destroys and portable trust restores.

When proof is portable, interoperability is structural. Two agents from different deployments, operating on different platforms, communicating over mesh, can verify each other's authority, check each other's receipt chains, and establish trust through mutual verification. No central registry of agents. No shared platform. No intermediary that both parties must trust. The trust is in the math.

When accountability is owned by the participant, sovereignty is genuine. The agent owns its own track record. The human at the root owns the delegation chain. The evidence of good behavior belongs to the entity that behaved well, not to the entity that observed it. This is the structural inversion that makes everything else possible: proof belongs to the prover.

### The Offer

ZeroPoint does not promise a fairer world. It provides the cryptographic primitives that make a fairer world architecturally possible.

The receipts, the chains, the grants, the attestations, the mesh — these are building blocks. They encode specific values: that proof should be portable, that authority should be verifiable, that sovereignty should be structural, and that the evidence of accountability should belong to the participants, not the intermediaries.

Someone has to build with these blocks. Someone has to deploy agents with Tier 2 key chains and governed capabilities and receipt-producing execution engines and mesh-connected peer verification. Someone has to choose, deliberately, to build systems where trust is earned through evidence and exit is always possible.

Whether anyone does is not our call. The primitives exist. The exit is possible. The foundation is laid.

What gets built on it is up to humanity.

---

# PART VI — HONEST ACCOUNTING

---

## Chapter 22: What ZeroPoint Does Not Do

A governance system that overclaims is worse than no governance system at all, because it creates false confidence. ZeroPoint is specific about its boundaries. Understanding what the protocol does not do — and why — is as important as understanding what it does.

### Model-Layer Threats

ZeroPoint does not address threats at the model layer. It does not prevent model theft (extracting weights from a deployed model), training-time data poisoning (manipulating training data to influence model behavior), or evasion attacks (crafting inputs that cause a model to misclassify or misbehave). These are real threats, but they operate at a layer below ZeroPoint's governance boundary.

ZeroPoint governs actions, not cognition. It can prove that an agent took a specific action under specific constraints. It cannot prove that the agent's reasoning was sound, that its model was not poisoned, or that its outputs were not adversarially manipulated. The governance is over behavior — what the agent did — not over the model's internal state.

### Prompt Injection

ZeroPoint does not function as a prompt injection firewall. A prompt injection attack manipulates the input to an LLM so that it ignores its instructions and follows the attacker's instructions instead. Defending against prompt injection requires input sanitization, output validation, and model-level safeguards that operate on the content of messages, not on the governance of actions.

ZeroPoint's policy engine evaluates actions, not content. The HarmPrincipleRule can block actions that are categorically harmful (weaponization, surveillance, deception), but it does not parse natural language for injection patterns. A dedicated WAF (web application firewall) for LLMs is a different tool for a different problem.

### Behavioral Anomaly Detection

ZeroPoint does not include machine learning-based anomaly detection. It does not build behavioral profiles of agents, does not compare current behavior to historical baselines, and does not flag statistically unusual activity. The learning loop detects recurring patterns through frequency analysis, but it does not detect anomalies through statistical deviation.

This is a deliberate choice. Anomaly detection is valuable but opaque — it is difficult to explain why a specific action was flagged, and difficult to audit the detection model's assumptions. ZeroPoint prioritizes transparency over sophistication. The governance decisions are deterministic and auditable. If you want anomaly detection, build it on top of ZeroPoint's receipt data. The receipts are the dataset. The analysis is someone else's system.

### Network Infrastructure Security

ZeroPoint does not address network-layer threats: DDoS attacks, man-in-the-middle attacks on the transport layer (Reticulum provides its own encryption, but ZeroPoint does not add to it), routing attacks, or infrastructure compromise. These are network security concerns that exist below the governance layer.

### Guaranteed Prevention

ZeroPoint does not prevent misuse. It makes actions provable and participants refusable. An agent that is determined to act badly — and whose operator has configured lax policies — will produce a complete, signed, tamper-evident record of its bad behavior. The receipt chain will prove exactly what went wrong, who authorized it, and which constraints were (or were not) in place.

This is accountability, not prevention. The distinction matters. A system that claims to prevent all misuse is either lying or so restrictive that it prevents useful behavior along with harmful behavior. ZeroPoint's claim is more modest and more honest: every action is provable, every authority chain is verifiable, every participant can refuse, and the evidence is owned by the participants. What they do with that evidence — including holding bad actors accountable after the fact — is a social and legal question, not a protocol question.

---

## Chapter 23: The Security Footprint

ZeroPoint's governance primitives map to recognized security frameworks — not because ZeroPoint was designed to comply with them, but because the frameworks describe real problems and ZeroPoint's architecture addresses many of the same problems from first principles.

### NIST AI Risk Management Framework

The NIST AI RMF organizes AI risk management into four functions: Govern, Map, Measure, and Manage. ZeroPoint's coverage is concentrated in Govern (policy engine, constitutional rules, capability grants) and Measure (receipt chains, audit trails, collective verification), with meaningful coverage in Map (risk assessment by action type, trust tier classification) and lighter coverage in Manage (graduated decisions, remediation through Review and Block).

The weighted coverage is approximately 68%. The gaps are primarily in areas NIST addresses but ZeroPoint deliberately does not: model-layer testing and evaluation, training data governance, and stakeholder engagement processes. These are organizational activities, not protocol-level mechanisms. ZeroPoint provides the infrastructure that makes NIST compliance measurable. It does not replace the organizational processes that NIST also requires.

### OWASP

ZeroPoint's architecture directly addresses several of OWASP's top risks for both LLM applications and agentic systems: excessive agency (capability grants with constraints), insecure output handling (Sanitize decisions with pattern redaction), insufficient access control (delegation chains with eight invariants), and inadequate logging and monitoring (hash-chained audit trails with collective verification).

It partially addresses others: prompt injection (the HarmPrincipleRule catches categorically harmful outputs but does not function as a content-level WAF), model denial of service (resource limits in the execution engine), and supply chain vulnerabilities (WASM module hash verification, but no comprehensive supply chain framework).

It does not address model theft, training data poisoning, or other model-layer vulnerabilities. These are explicitly out of scope.

### MITRE ATLAS

MITRE ATLAS catalogs adversarial tactics against AI systems, organized similarly to the ATT&CK framework for conventional cybersecurity. ZeroPoint's architecture partially addresses several ATLAS tactics: reconnaissance (the mesh's encrypted, address-less design reduces the attack surface for initial information gathering), staging (capability grants constrain what resources an agent can access, limiting staging options), exfiltration (the execution engine's network allowlisting and the policy engine's CredentialAccess controls limit data exfiltration paths), and impact (constitutional rules and graduated decisions limit the damage an adversarial action can cause).

The gaps are real: ATLAS tactics focused on the model layer (adversarial examples, model evasion, data poisoning) are not addressed. ZeroPoint operates at the governance layer, not the model layer.

### The Honest Summary

ZeroPoint covers identity, access, governance, audit, and inter-agent communication with strong cryptographic guarantees. It does not cover the model layer, the network layer, or the social and organizational processes that comprehensive AI governance also requires.

This is not a failure. It is a scope decision. A protocol that tries to address everything addresses nothing well. ZeroPoint addresses the governance layer — the layer where actions are authorized, constrained, and proven — with depth that no other open-source framework currently matches. The other layers need their own tools, and those tools can consume ZeroPoint's receipts as their data source.

---

## Chapter 24: The Architecture of Resistance

ZeroPoint is governance infrastructure. It is also, by the structural properties of its design, resistance infrastructure. Not because it was designed to resist any specific authority, but because the same architectural choices that make governance trustworthy also make surveillance difficult.

### Structural, Not Intentional

The properties that resist surveillance are the same properties that enable accountability. They were not added to resist governments or corporations. They were added because accountability requires them. The resistance is a byproduct of the integrity.

The genesis key is the firewall. All authority flows from a human-held key through a signed delegation chain. There is no central authority that can be compelled to grant access. A surveillance entity cannot subpoena "the ZeroPoint company" for user data, because there is no central database holding user data. The receipts, audit chains, and capability grants are distributed — held by the participants themselves, propagated through the mesh. To surveil a participant, you would need their private key. The architecture has no backdoor because there is no front door. There is only cryptography.

Constitutional rules are non-removable. The HarmPrincipleRule blocks surveillance by design — it evaluates actions against a surveillance category and refuses to cooperate. This is not a policy toggle an operator can flip under government pressure. It is embedded at the code level, loaded first, immutable at runtime. A government could compel an operator to "turn off the safety." The architecture does not have a switch to turn off.

The mesh transport eliminates chokepoints. Traditional surveillance exploits infrastructure dependencies — DNS, certificate authorities, cloud providers — as points of interception. Reticulum-compatible mesh transport has none of these. No DNS to poison, no CA to compromise, no cloud provider to serve with a national security letter. Communication is end-to-end encrypted, peer-to-peer, and works over any medium including radio.

Receipt chains are tamper-evident, not tamper-proof. A surveillance actor who gained access to a node's receipts would find them useful as evidence — that is the whole point of accountability. But they cannot silently modify the chain without detection, they cannot inject false receipts without the actor's private key, and they cannot compel the system to produce receipts with different content. The receipting is deterministic. The same input always produces the same hash.

Sovereignty as structural resistance. Tenet II — the right of every participant to refuse — means the system architecturally cannot be compelled to cooperate with requests that violate its constitutional rules. This is not legal resistance, which fails under enough pressure. It is mathematical resistance. The code does not have the capability to comply, even if the operator wanted to.

### The Honest Caveat

ZeroPoint does not make you invisible. It makes your actions provable and sovereign. A sufficiently powerful adversary with physical access to your hardware can always extract data. What ZeroPoint ensures is that they cannot do it silently through the protocol, they cannot compel the system to help them, and they cannot tamper with the evidence without detection. The defense is not invisibility. It is integrity.

This matters because the threat model for the Agentic Age is not the same as the threat model for personal communication. The question is not "can they read my messages?" — Reticulum handles that with its own encryption. The question is "can they compel my agent to operate outside its governance constraints, forge its receipts, or compromise its delegation chain without detection?" ZeroPoint's answer is no, not through the protocol. Physical access, rubber hose cryptanalysis, and compromised hardware are attacks that no software can prevent. But protocol-level compulsion — the kind that comes through legal orders served to infrastructure providers — finds no purchase in a system with no central infrastructure to serve.

### The Political Landscape

AI governance is contested territory. Every framework, every protocol, every standard is a political act — it defines who controls what, who can audit whom, and who bears responsibility for outcomes. ZeroPoint's politics are explicit: sovereignty is structural, accountability is mutual, the constitutional floor cannot be lowered, and the human at the root retains ultimate authority over their own delegation chain.

These politics have opponents. Centralized governance advocates want standards that flow from institutions downward. Surveillance interests want audit infrastructure that flows information upward. Regulatory bodies want compliance frameworks they can inspect and enforce. ZeroPoint does not oppose these interests categorically — receipts can serve compliance, audit trails can serve regulation, and the framework can be inspected by anyone because it is open source. But it refuses to build the architecture in a way that gives any single entity privileged access to the governance layer. The access is cryptographic and equal. The receipts are verifiable by anyone. The constitutional rules apply to everyone.

This is the position the book has argued from the beginning: governance and sovereignty are complements, not contradictions. You can have accountability without central control. You can have auditability without surveillance. You can have governance infrastructure that empowers participants rather than constraining them. The architecture proves it is possible. Whether the world chooses it is another question.

---

## Closing: The Exit

This book has described an infrastructure. Not a product, not a platform, not a service. An infrastructure — cryptographic primitives that produce verifiable proof of every action, make that proof portable, and ensure that the evidence of accountability belongs to the participants, not the intermediaries.

The infrastructure encodes values. Proof should be portable. Authority should be verifiable. Sovereignty should be structural. The constitutional floor should not be negotiable. The human should be the root.

These values are not universally held. There are powerful interests that prefer trust to be locked in vendor databases, authority to be opaque, sovereignty to be conditional, governance floors to be adjustable, and humans to be replaceable. ZeroPoint does not argue with these interests. It builds an alternative and offers it.

The Agentic Age is arriving whether the infrastructure is ready or not. Autonomous agents are already negotiating contracts, managing infrastructure, executing trades, and making decisions that affect human lives. The question is not whether agents will act. They already do. The question is whether their actions will be provable, their authority verifiable, their constraints enforceable, and their accountability structural.

ZeroPoint provides the building blocks. Receipts for proof. Chains for integrity. Grants for constrained authority. Delegation for traceable provenance. Constitutional rules for an immovable floor. Mesh transport for sovereign communication. Epoch seals for sustainable accountability. Collective verification for trust that emerges from evidence.

The building blocks are here. The exit is possible. What gets built is up to you.

---

*ZeroPoint — Portable Trust for the Agentic Age*
*Ken Romero, ThinkStream Labs*
*March 2026*
