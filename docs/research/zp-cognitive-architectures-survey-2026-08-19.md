# Cognitive Architectures Survey — Design Lessons for ZeroPoint

**For:** Ken Romero, ThinkStream Labs
**Date:** 2026-08-19
**Scope:** Design-oriented survey of five declared-primitive cognitive architectures — Soar, ACT-R, CLARION, CRAM, CALYSA — read against ZeroPoint's substrate primitives. The lens is: *what has 40 years of the "cognitive architectures" tradition already learned that ZP should absorb, adapt, or reject?* This is not a general AI landscape sweep and not marketing for the tradition. Every recommendation is a candidate for operator decision, not a directive. All specific claims are cited; unverifiable framings (notably around CALYSA) are flagged as such.

A note on primitive vocabulary before we begin: throughout, "ZP primitives" refers to the surface Ken laid out — Chain, Cartographer, Regent, Officers, Proposal Candidates, Delegation Gates, Standing Corrections, Cognitive Input Plane, Precedent, Cognitive Self-Observer, Lens Discipline, Shadow-Evaluation, and the "detectability over invulnerability" stance from KEEL III.19. Where the mapping to a cognitive-architecture construct is speculative rather than structural, that is called out.

---

## 1. Soar

### Origin and lineage

Soar was launched in 1983 at Carnegie Mellon by John Laird, Allen Newell, and Paul Rosenbloom, as the concrete embodiment of Newell's "unified theories of cognition" program. Its intellectual anchor was Newell's claim that a mind must be a single coherent architecture rather than a bag of task-specific tricks. Development moved with Laird to Michigan, where the Soar Group at U-M EECS remains the primary steward. Soar is very much active: the codebase lives on GitHub under `SoarGroup/Soar`, workshops continue (the 44th was recent), and Laird's 2022 arXiv introduction and 2019 MIT Press monograph are the current canonical references. Soar has evolved substantially since ~2005: the classical rule-and-impasse machine of the 1980s has since acquired semantic memory, episodic memory, reinforcement learning, and a spatial-visual system (SVS) for sub-symbolic imagery.

### Central hypothesis

A cognitive agent is a **problem-space searcher** that operates by proposing, evaluating, and applying operators in a working-memory state, and when the knowledge to make the next move is missing, it *automatically* falls into a substate ("impasse") and reasons about the impasse itself. Learning is the *compilation of substate reasoning into new procedural rules* ("chunking"). Everything a Soar agent does is a special case of this loop.

### Structural primitives

- **Working memory:** a graph of symbolic structures currently active.
- **Long-term memory tiers:** procedural (production rules), semantic (declarative facts with base-level activation), episodic (auto-captured topstate snapshots, temporally navigable).
- **Perceptual/motor:** the Spatial-Visual System (SVS), which handles 2D and 3D non-symbolic representations, projection, rotation, collision — a bridge between symbolic WM and modality-specific reasoning.
- **Decision cycle:** input → elaboration (parallel rule firing to propose/evaluate operators) → operator selection (fixed procedure over preferences) → operator application → output.
- **Impasse and substates:** when preferences are insufficient/tied/inconsistent, a new substate opens and the agent reasons *about* the impasse; substate results feed back to the superstate.
- **Learning:** chunking (now reimplemented as Explanation-Based Behavior Summarization, EBBS) back-traces the substate to build a rule that skips the substate next time; RL rules learn numeric preferences; semantic and episodic memories are populated online.

### Notable strengths

Long-running agents, tight cognitive-cycle latency (~50 ms per cycle target, matching human RT), extremely wide task coverage (games, planning, tutoring, robotics, natural language fragments), and the cleanest working demonstration of *automatic subgoal creation from knowledge gaps* in the field. Soar has been in continuous production use across military simulation (TacAir-Soar) and cognitive robotics for over three decades.

### Notable limits and known failure modes

Laird himself is unusually candid in the 2022 introduction: 8/16 evaluated general-agency capabilities rated "yes," 5 "partial," 2 "no." Explicit gaps include self-representation (no reflective model of the agent's own capabilities), commonsense/core knowledge (no innate scaffolding), unrestricted natural language, and *semantic concept learning* (agents can memorize facts but do not induce new concepts). Chunking historically over-generalized (a rule learned in one substate would fire in inappropriate ones); the EBBS rewrite is designed to fix this by tighter dependency tracking. The bootstrapping problem — moving from architecture-plus-innate-knowledge to a fully capable agent without close human curation — remains open. Laird: *"even I have to admit that in working with Soar for 40 years, it feels like there are essential elements that are still missing."*

### Mapping to ZP

- **Regent cognitive cycle ↔ Soar decision cycle.** Structurally very similar: assemble context, propose/evaluate, commit. ZP's fast-layer/slow-layer disagreement discipline has no direct Soar analogue; Soar's slow-layer equivalent is the impasse-driven substate, which is opened *reactively* when knowledge fails rather than *preemptively* to verify.
- **Chain ↔ episodic memory (partial).** Both are append-only records of what happened. Different in purpose: Chain is signed cryptographic ground truth for accountability; Soar episodic memory is a cognitive resource for the agent itself. Chain is not a memory the Regent retrieves *as* memory — the Cartographer mediates that.
- **Cartographer ↔ semantic memory + chunking (partial).** Both derive structured knowledge from experience. Cartographer maintains typed objects and relationships; Soar chunking compiles operational rules. Different targets: ontology of understanding vs. procedural shortcut.
- **Impasse substates ↔ (no direct analogue).** ZP does not yet have a first-class primitive for "the substrate noticed it doesn't know how to proceed and opened a bounded sub-problem to figure it out." This is a gap.
- **Proposal candidates ↔ operator preferences (partial).** Soar allows multiple candidate operators with preference structures; selection is via a fixed algorithm, not operator ceremony. Un-collapsed persistence is not Soar-native — once selected, the operator applies.

### Concrete design questions raised

1. Should ZP have an explicit **impasse primitive** — a typed event on the Chain that says "the Regent detected that context is insufficient to reach a decision, and opened a scoped sub-cycle to acquire what it lacks"? This would give the Cartographer a structural record of *known unknowns* the substrate encountered.
2. Chunking's over-generalization history is a warning about *any* mechanism that automatically compiles reasoning into faster paths. If the Cartographer ever moves from passive ontology to active rule extraction, what invariants must it preserve to avoid the same failure mode?
3. Soar semantic memory uses base-level activation to bias retrieval by recency/frequency. Should Precedent citation in ZP be pure lookup, or should there be a base-level-activation-analogue that biases which precedents surface into the Cognitive Input Plane? (Base-level activation is a known correlate of human forgetting curves — using it silently could introduce recency bias no operator signed for.)

---

## 2. ACT-R

### Origin and lineage

ACT-R (Adaptive Control of Thought — Rational) is John Anderson's architecture, developed at Carnegie Mellon starting with ACT in the 1970s, formalized as ACT-R in 1993, and maintained continuously since. Anderson's group and downstream labs (Lebiere at CMU, Taatgen at Groningen, Byrne at Rice, etc.) still publish actively; ACT-R 7 / 7.30+ is current. Its distinctive intellectual commitment is that the architecture is not just an AI system but a *falsifiable psychological theory* — every parameter has (in principle) a defense from cognitive-science data. It has been the most heavily used architecture in empirical human-modeling work, and the Cognitive Tutors that emerged from ACT-R shaped a generation of adaptive learning software.

### Central hypothesis

Cognition is a symbolic production system running on top of sub-symbolic activation dynamics. The symbolic layer chooses what to do; the sub-symbolic layer decides *what is available to think about* — via activation, retrieval latency, and utility. Bounded rationality is not a design compromise but the point.

### Structural primitives

- **Modules:** declarative (facts), procedural (productions), goal, imaginal (mental workspace), visual, aural, manual, vocal. Each module is roughly a brain region in Anderson's neural mapping.
- **Buffers:** each module has a single buffer holding one chunk at a time — the sole channel through which the module talks to the production system. This is the throughput bottleneck that makes ACT-R match human serial cognition.
- **Production system:** only one production fires per 50 ms cycle; it may issue requests into module buffers and modify them.
- **Symbolic representation:** chunks (typed slot-value structures) and productions (condition-action pairs matching over buffer contents).
- **Sub-symbolic dynamics:** base-level activation (recency + frequency), spreading activation (from current buffer contents), noise, and utility (reward-tuned production selection).
- **Learning:** base-level activation updates automatically; production compilation combines rule sequences into single rules; utility learning tunes production selection under reward.

### Notable strengths

The tightest quantitative fit to human behavioral and neuroimaging data of any cognitive architecture. Anderson's group has predicted RTs, error patterns, fMRI BOLD signals across tasks from arithmetic to algebra tutoring to air-traffic-control models. When you want *a mechanism that plausibly implements something a human does*, ACT-R is often the first architecture people reach for. The symbolic/sub-symbolic separation is unusually clean and disciplined — the sub-symbolic layer is a small number of equations, not a black box.

### Notable limits and known failure modes

Serial single-production-per-cycle constraint scales poorly when reasoning requires large parallel search. Buffer-per-module means each module can hold *exactly one* chunk at a time — hard to model rich concurrent state without extending the architecture. Learning is real but slow — ACT-R models learn on human timescales (minutes to hours) and typically cannot bootstrap from raw perception. Perception modules are usually simulated, not sensor-grounded. The 40-year-review paper flagged that despite an explicit hybrid claim, ACT-R's sub-symbolic layer is a small collection of activation equations, not a modern learned representation — the mechanism is old-school and it shows.

### Mapping to ZP

- **Cognitive Input Plane ↔ ACT-R buffer state at cycle start.** Both are the constrained working surface a single cognitive step is allowed to see. ZP's tiered priority (standing corrections > precedent > situational) is *stricter* — ACT-R has no notion of "some inputs are non-overridable by others."
- **Precedent ↔ base-level + spreading activation (partial).** ACT-R retrieves what was recently and frequently activated; ZP retrieves what past decisions cite. Both are memory-shaped; ACT-R's is unsigned and probabilistic, ZP's is signed and cited.
- **Regent's fast/slow layer ↔ procedural/declarative split (partial).** In ACT-R, the "slow" reflective work is done by chaining productions through declarative retrievals; there is no dedicated verifier that adjudicates the fast layer's output. The Cognitive Self-Observer is more like an *external* module whose closest ACT-R relative is the metacognitive extensions (which are add-ons, not core).
- **Officers ↔ (no analogue).** ACT-R has no adversarial verification agents. Verification is implicit in whether the production sequence produces a coherent buffer state.
- **Sub-symbolic activation ↔ vector-space priors on proposal candidates (speculative).** If ZP ever attaches numeric priors to candidates (e.g. a Cartographer-derived "typicality score"), ACT-R is the cleanest prior art for how to keep such priors from silently overriding operator-declared symbolic structure.

### Concrete design questions raised

1. ACT-R's single-buffer-per-module rule is a hard architectural bottleneck that produces cognitively plausible serial behavior. Does ZP want *any* analogous throughput constraint, or is unbounded parallel context assembly a bug in disguise (letting the Regent see too much at once and lose the serial discipline that keeps decisions auditable)?
2. Base-level activation in ACT-R is applied *silently* by the architecture. If the Cognitive Input Plane ever grows recency/frequency weighting, does that weighting need to appear on the Chain — i.e., does the substrate owe operators a receipt that says "this precedent surfaced because it was recent, not because it was cited"?
3. ACT-R's sub-symbolic layer is a *closed-form equation*, not a learned model. This is a deliberate choice: it keeps the mechanism explainable. Would ZP accept that constraint on any sub-symbolic component it adds — no black-box priors — or is that too restrictive for the coherent-vector work the Pathway/BDH conversation opened?

---

## 3. CLARION

### Origin and lineage

CLARION (Connectionist Learning with Adaptive Rule Induction ON-line) was designed by Ron Sun starting in 1997 and developed continuously at RPI. Sun's core intellectual claim, drawn from decades of psychology of skill acquisition, is that *implicit* and *explicit* cognition are not two ways of describing the same thing but two representationally distinct systems that interact bidirectionally. CLARION is the most systematic computational commitment to that thesis. It is less "shipped software product" than Soar or ACT-R and more "long-running research program"; the CLARION Java implementation exists but the tradition's leverage is theoretical rather than deployment-based.

### Central hypothesis

Cognition is *dual-process by construction*. Every subsystem (action, non-action, motivation, metacognition) has both an explicit top level (rule-like, localist, symbolic) and an implicit bottom level (network-like, distributed, sub-symbolic). Learning goes bidirectionally: bottom-up via Rule-Extraction-Refinement (RER) that reads rules out of the network layer; top-down via rules guiding network development. Meta-cognition is a *first-class subsystem*, not an afterthought.

### Structural primitives

- **ACS (Action-Centered Subsystem):** action selection; top = action rules, bottom = Action Neural Networks.
- **NACS (Non-Action-Centered Subsystem):** general knowledge; top = associative rules, bottom = Associative Neural Networks; splits into semantic (generalized) and episodic (situation-specific) knowledge.
- **MS (Motivational Subsystem):** low-level drives and high-level drives (affiliation, recognition, dominance, fairness), with explicit goals riding on top.
- **MCS (Meta-Cognitive Subsystem):** monitors, directs, and modifies operations of the other subsystems — sets goals for ACS, adjusts subsystem parameters, modifies ongoing processes.
- **Interaction shape:** implicit and explicit layers combine *weighted* rather than one verifying the other. Sun's canonical example: performance degradation under pressure results from anxiety shifting the weighting toward explicit-over-implicit, disrupting well-practiced skill.

### Notable strengths

CLARION has the most disciplined *meta-cognitive subsystem as first-class primitive* in the tradition. It has been validated against a wide range of concrete cognitive phenomena: serial RT, artificial grammar learning, process control, Tower of Hanoi, minefield navigation, organizational decision-making, social simulation. The bottom-up rule extraction is genuinely interesting — the system can start with only a neural component and grow explicit rules as competence stabilizes, mirroring the well-known "verbal report emerges after skill" pattern from human learning.

### Notable limits and known failure modes

CLARION's engineering footprint is small compared to Soar/ACT-R. Documented failure modes are less well-catalogued in the literature — partly because critical replication and stress-testing of CLARION runs is thinner. The weighted-combination of implicit and explicit is theoretically elegant but the *weights themselves* are parameters that a modeler tunes — they are not derived from anything, so the architecture's fit-to-data is partly free-parameter fitting. The MCS is a first-class subsystem in the theory but concrete demonstrations of it doing non-trivial supervisory work (as opposed to setting parameters) are sparser than the theory implies. And there is no clean story for how bottom-up RER avoids over-fitting network idiosyncrasies into over-confident explicit rules — the same over-generalization risk Soar chunking hit, expressed in a different medium.

### Mapping to ZP

- **Regent fast/slow layer ↔ CLARION implicit/explicit levels.** This is the closest structural analogue in the entire survey. Both architectures have deliberately built in a two-track cognitive substrate where the tracks disagree productively. **Difference:** CLARION combines them *weighted*; ZP's slow layer *verifies* the fast layer before commit. ZP's discipline is stricter and more auditable.
- **Cognitive Self-Observer ↔ MCS.** Both are first-class meta-cognitive components. CLARION's MCS is more empowered (it modifies parameters, sets goals); ZP's Self-Observer is narrower (watches for confabulation-vs-knowing). ZP has room to broaden if the operators want it.
- **Officers ↔ MCS (partial).** Officers are adversarial verifiers, each with a specific concern (Aegis for alignment). CLARION's MCS is a single unified monitor. ZP's decomposition into named specialized verifiers is *not* a CLARION move; it is more like the "multiple critics" pattern from RL. But the *idea that meta-cognition is architectural rather than emergent* is genuinely shared.
- **Standing corrections ↔ (no analogue).** CLARION has motivations and goals but no persistent operator-authored guidance that enters every cycle at highest priority.
- **Bottom-up rule extraction ↔ Cartographer (partial).** Both read structure out of underlying substrate. CLARION reads rules from networks; Cartographer reads typed objects from Chain events. Same *shape of move*, different substrate.

### Concrete design questions raised

1. CLARION explicitly *does not* commit to the slow layer verifying the fast layer — it commits to weighted combination. ZP has chosen verification. Is that choice load-bearing enough to write into the Regent's contract, or is there a class of cognitive work where weighted combination is right and verification is over-conservative?
2. CLARION's MCS modifies subsystem parameters at runtime. Does the Cognitive Self-Observer have the authority to change any Regent parameter, or is its power strictly diagnostic (flag confabulation, do not intervene)? The tradition suggests the diagnostic-only stance is under-powered; the safety-first stance suggests it is the only stance a signed substrate can defend.
3. If the Cartographer ever generates *rules* rather than *ontology* (RER-analogue: "when I see a Decision followed by a Friction, propose a Trajectory of shape X"), what mechanism catches the CLARION-and-Soar failure mode of over-general rules extracted from noisy substrate?

---

## 4. CRAM

### Origin and lineage

CRAM (Cognitive Robot Abstract Machine) is Michael Beetz's architecture at the University of Bremen's Institute for Artificial Intelligence (IAI), begun around 2010. Its home is the CRC EASE ("Everyday Activity Science and Engineering") research center. CRAM is unusual in this list: it is a *robotics* cognitive architecture, targeted at real physical manipulation in everyday human environments (pouring, cutting, setting a table). The 2023 arXiv paper and the 2025 Cognitive Systems Research paper "Robot manipulation in everyday activities with the CRAM 2.0 cognitive architecture and generalized action plans" (Beetz, Kazhoyan et al.) are the current canonical references. It is active: the GitHub org `cram2` is maintained, docs describe current components (CoraPlex, KRROOD, Giskardpy, Semantic Digital Twin), and it plugs into euRobin and the Robotics Institute Germany.

### Central hypothesis

Robot action plans should be *underdetermined* by design — the plan says "pour the milk into the cup" but leaves grip pose, pour angle, motion trajectory, and error recovery as *parameters to be resolved by reasoning against the current world state*. The architecture's job is to close the gap between abstract intention and concrete physical action, in context, at runtime, using knowledge.

### Structural primitives

- **CPL (CRAM Plan Language):** Lisp-based language for writing generalized plans that reference abstract actions and objects rather than motor commands.
- **CoraPlex:** central control unit; interprets and executes CPL plans.
- **Generalized action plans:** underdetermined action designators (e.g. `(perform (an action (type pouring) (source ?cup1) (target ?cup2)))`) that must be resolved against the current world state before motor execution.
- **KRROOD / KnowRob-lineage knowledge base:** symbolic knowledge representation, ontological queries, rule-based reasoning about objects, actions, environments.
- **Semantic Digital Twin:** integrates sensor data, robot models, and semantic annotations into a queryable world representation.
- **NEEMs (Narrative-Enabled Episodic Memories):** rich episodic records of past executions — motions, sensor traces, decisions, outcomes — reusable for future task grounding and explanation. OpenEASE hosts NEEMs across research groups as a shared corpus.
- **Giskardpy:** constraint-based motion optimization; takes resolved parameters and produces trajectories.
- **Probabilistic reasoning layer:** for random events and uncertain physical outcomes.

### Notable strengths

CRAM is the *only* architecture in this survey that has been repeatedly shown to close the loop from abstract task specification to physical execution on real robots in real kitchens. The NEEM corpus — a shared, queryable episodic memory of *actual robot executions* — is a research-community-scale asset that no other architecture matches. The commitment to underdetermined plans is a genuinely different design stance from Soar/ACT-R: instead of the operator picking a *specific* operator to apply, CRAM picks an *abstract* one and defers the specifics until execution context is available.

### Notable limits and known failure modes

Everyday robot manipulation is still enormously brittle in practice — CRAM demonstrations show impressive capability in constrained kitchens but do not generalize to arbitrary novel environments the way the abstraction level might suggest. The KRROOD/KnowRob ontology has grown large and the classic problem with ontological knowledge bases (maintenance debt, silent contradictions, expert-authored bottleneck) applies. The 2025 CRAM 2.0 paper explicitly flags future work on transformational learning and metacognition — i.e., the architecture does not yet learn new generalized action plans from experience in a strong sense, nor deeply reflect on its own execution.

### Mapping to ZP

- **Generalized action plans ↔ proposal candidates.** This is the *tightest structural analogue in the entire survey.* Both hold abstract, un-collapsed possibilities; both defer commitment until context-and-authority collapse them. CRAM collapses at execution time via reasoning + world state; ZP collapses at signing time via operator ceremony. The *shape of "hold multiple possibilities, resolve at commit"* is genuinely shared.
- **NEEMs ↔ Chain + Cartographer (partial).** Both are structured records of past execution. NEEMs are richer per-episode (they include sensor traces and motion data) but they are not signed or append-only-with-legal-force. Chain is thinner per-event but has integrity guarantees NEEMs lack.
- **CoraPlex ↔ Regent (partial).** Both are the central controllers that orchestrate the cognitive cycle over the plan.
- **Semantic Digital Twin ↔ Cartographer (partial).** Both are queryable world representations derived from raw substrate. Digital Twin includes sensor data and geometric models; Cartographer is currently symbolic-object-centric.
- **KRROOD ontology ↔ Cartographer ontology.** Both are typed-object knowledge bases the reasoner queries. The tradition warns that the *authoring bottleneck* is real: if the Cartographer ontology depends on human curation to stay coherent, it will not scale.

### Concrete design questions raised

1. CRAM's collapse point is *reasoning + world state* at execution; ZP's is *operator signature* at commit. Both are principled but they answer different questions. When ZP proposals collapse, should the substrate present the operator with the *reasoning-would-have-collapsed-to-X* projection as a default, or would that be a subtle authority-shift toward the substrate?
2. NEEMs let CRAM replay and analyze past executions in rich sensor detail. Does the Chain need a per-event *depth* field — signed evidence of what the Regent saw and thought at that moment, not just what it emitted — to give the Cartographer something as generative as a NEEM to reason over?
3. CRAM's ontology grew heavy. What is ZP's plan for keeping the Cartographer's typed-object ontology from becoming a maintenance liability? Is there a discipline for *retiring* an ontology type as concepts sharpen or drift?
4. CRAM does not (yet) learn new generalized plans strongly from experience. Should the substrate be able to *propose* new proposal-candidate templates from Cartographer patterns, or is that a boundary the substrate should never cross — templates are always operator-authored?

---

## 5. CALYSA — verification and honest reading

### Origin and lineage — what I actually found

The user was right to flag this one for verification. **CALYSA does not appear to be a published academic cognitive architecture in the sense that Soar, ACT-R, CLARION, and CRAM are.** A search across scholarly indexes (arXiv, Semantic Scholar, ResearchGate, Google Scholar-adjacent surfaces) returns *no* CALYSA cognitive-architecture publications. Searches for the acronym in cognitive-science contexts return unrelated projects: "CALyX" (an entirely different computational architecture, ResearchGate figure only), and a Wikipedia entry on cognitive architectures that does not list CALYSA at all. The most comprehensive recent survey I could reach — Kotseruba & Tsotsos, *40 Years of Cognitive Architectures* (2018, Artificial Intelligence Review; arXiv:1610.08602) — inventories ~84 architectures and does not list CALYSA.

The traces I *can* find come from the YouTube channel `@calysa_project`, run by **Alex Sanders**, who describes himself as a cognitive science researcher and AI philosopher working on hybrid cognitive architectures since 2010. His channel bio lists CALYSA alongside Soar, ACT-R, CLARION, and OpenCog Hyperon as architectures he has experience with, and states his research focus as the symbol grounding problem, causal (counterfactual) world models, and autonomous long-term memory systems. No papers, no code repository publicly located, no institutional affiliation named on the channel bio I could reach.

### Honest reading

CALYSA at this moment appears to be an **individual research project or personal cognitive architecture in development**, with public presence primarily as YouTube-based communication of Sanders' thinking about cognitive-architecture design, but without the peer-reviewed publication trail or maintained public codebase that would let a survey like this one take design lessons from concrete mechanisms. That is not a dismissal — many important ideas start this way, and the commenter's substantive engagement in the BDH thread is a legitimate signal that Sanders is *thinking* usefully. It is a warning against citing "what CALYSA does" as if there were a canonical answer.

### Central hypothesis (as best it can be stated from public traces)

From Sanders' stated research focus: cognition must ground symbols in causal counterfactual world models rather than in statistical association, and long-term memory must be autonomous rather than externally curated. This aligns CALYSA with the "hybrid cognitive architecture / neuro-symbolic AGI" wing of the tradition rather than with pure symbolic or pure connectionist camps. Beyond that, structural claims about CALYSA's memory tiers, control loop, or learning mechanism cannot be responsibly extracted from public sources at this time.

### Structural primitives, strengths, limits

Cannot be responsibly reported. The substantive design content lives in videos I have not transcribed and in Sanders' private notes/code.

### Mapping to ZP

The one mappable thing is Sanders' stated commitment to **causal counterfactual world models** and **autonomous long-term memory**. Both echo ZP concerns:

- Cartographer as a live-derived ontology of understanding rather than a curated one echoes "autonomous LTM."
- The shadow-evaluation primitive (candidate vs. control in parallel) is *structurally* a counterfactual mechanism — what would have happened without this intervention — even if the framing is different.

Beyond this, mapping is speculative.

### Concrete design questions raised

1. Is there value in reaching out to Sanders directly (with Ken's permission and framing) for a conversation about the causal-counterfactual world model question? He is a substantive thinker in a small niche and might be a productive interlocutor rather than a survey subject.
2. If ZP frames the shadow-evaluation primitive as a *counterfactual* rather than as an A/B test, does that reframe change what evidence the substrate should accumulate before collapse? (An A/B test wants effect-size and significance; a counterfactual wants a causal graph over which the intervention operated.)
3. The recurring under-published/single-researcher pattern in cognitive-architecture history (CALYSA is not unique here — MicroPsi, MANIC, and others follow the same shape) is itself a warning: architectures that live in one person's head do not compound. What does ZP's design commit to that keeps the substrate compounding across operators and time, not just in Ken's head?

---

## Synthesis

Now the actual design work.

### Cross-cutting patterns

Several primitives and control shapes appear across three or more of these architectures. When something converges across independent 40-year research programs, it is usually a hint that the substrate you are building will need something structurally similar, whether you like the specific implementations or not.

**1. A cognitive cycle at ~50 ms.** The Common Model of Cognition consensus (Laird, Lebiere, Rosenbloom, 2017 AI Magazine) crystallizes the point: Soar, ACT-R, and Sigma all converge on a serialized cognitive cycle that runs at approximately human decision-latency scale. This is not accidental — it is what constrains any single reasoning step to be *auditable*. The lesson for ZP is that the Regent's cognitive cycle is doing the same architectural work: it is the unit that operators can inspect, sign, and cite from. Whatever the eventual latency, the cycle-as-atomic-audit-unit is a good commitment.

**2. Three memory tiers.** Working memory / procedural / declarative recurs everywhere. Soar splits declarative into semantic + episodic; ACT-R uses buffer + declarative + productions; CLARION doubles each tier into implicit/explicit variants; CRAM has Digital Twin + NEEM + KRROOD. The lesson for ZP: the Chain, the Cartographer, and the Regent's active context are cleanly homologous to episodic, semantic, and working memory respectively — but ZP does not yet have a clear analogue to *procedural* memory (rule-like knowledge of "how the substrate does things," compiled from past cycles). This is a substantive gap worth naming.

**3. Meta-cognition as first-class subsystem, not an afterthought.** CLARION built the MCS in; Soar acquired self-representation as an *open problem* Laird names explicitly; CRAM's roadmap lists metacognition as future work; ACT-R has been extended with metacognitive layers. Every serious cognitive-architecture design either has meta-cognition first-class or wishes it did. ZP's Cognitive Self-Observer + Officers are already this move.

**4. Bounded rationality by construction.** The Standard Model paper is explicit: *"the purpose of architectural processing is to support bounded rationality, not optimality."* Every architecture in the survey deliberately imposes constraints — one production per cycle, one chunk per buffer, one operator per decision, one motor plan at a time. The lesson: ZP's delegation gates (scope narrows, never widens) and the Cognitive Input Plane's tiered priority are ZP's version of this discipline. Do not soften them under performance pressure.

**5. Dual-process / two-layer cognition.** CLARION explicit/implicit, ACT-R symbolic/sub-symbolic, Soar deliberate/reactive (via impasse), CRAM plan/motion. Every architecture in the survey has *some* form of a two-layer split where the fast layer proposes and a slower or more constrained mechanism regulates. ZP's Regent fast/slow disagreement discipline is not an idiosyncratic ZP move — it is the canonical shape.

**6. Underdetermined-plan-plus-context-collapse.** CRAM's generalized action plans and ZP's proposal candidates are the clearest analogue in the survey, but the shape shows up more subtly in Soar operator preferences (multiple candidates, selection procedure collapses) and even in ACT-R production competition (utility learning collapses over time). The lesson: holding multiple possibilities un-collapsed until commit is a mature idea across the tradition. ZP's operator-signing collapse is the novel piece — everyone else collapses via reasoning; ZP collapses via *authority*.

### Direct steal candidates

Concrete mechanisms ZP should consider adopting, in ZP-native form.

**Steal #1: An impasse primitive on the Chain.** Soar's most distinctive move is that when the agent detects insufficient knowledge to proceed, it *opens a sub-problem to close the gap*, and that sub-problem is itself first-class cognitive activity. ZP has nothing structurally equivalent — when the Regent lacks context, we have no receipt for "the Regent noticed a gap." The steal: introduce a Chain event type like `impasse.opened` and `impasse.closed`, carrying the gap description, the sub-cycle that ran to close it, and what was learned. This gives the Cartographer a corpus of *known-unknowns the substrate has hit*, which is directly usable for improving the Cognitive Input Plane's priors. Do not adopt Soar's automatic chunking of the sub-cycle result into a new rule — that is where Soar hit over-generalization. Keep the impasse *legible*, not automatically compiled.

**Steal #2: A NEEM-shaped depth field on Chain events.** CRAM's NEEMs are episodic memories that include sensor traces alongside symbolic decisions — enough to *replay* an execution. ZP's Chain is currently thin per-event (what happened; who signed). For high-consequence Regent cycles, consider adding an optional signed *cognitive trace*: what context was assembled at each Tier of the CIP, which precedents were cited, which candidates were considered and rejected, which Officer flagged what. The value is not just accountability — it is that a rich trace makes the Cartographer's ontology-building substantively better, because it can reason about *rejected* candidates and *considered* precedents, not just committed decisions. Cost: storage. Mitigation: only attach depth-trace to cycles above a scope threshold.

**Steal #3: CLARION's bidirectional layer interaction, with ZP's verification discipline.** CLARION combines implicit and explicit *weighted*; ZP verifies. But CLARION also allows *top-down* teaching — explicit rules guide the implicit layer's development. ZP's standing corrections already do a version of this top-down move. Consider making the reverse motion explicit too: when the fast layer's answer is verified and committed enough times in a pattern the slow layer had to construct, that pattern becomes a *candidate standing correction* the operators can review. This is not automatic learning; it is *surfacing candidates for operator ratification*, which fits ZP's authority discipline.

**Steal #4: ACT-R-style declared sub-symbolic equations rather than learned priors.** If the Cartographer ever attaches numeric priors to typed objects or if the CIP ever weights precedents by more than presence/absence, use ACT-R's approach: a small number of closed-form equations with named, defensible parameters, not a learned model. This preserves the property that every mechanism affecting decisions can be inspected, cited, and (if wrong) *edited by an operator*. A learned prior model is an opaque authority the operators cannot correct.

### Deliberate rejections

Specific things this tradition does that ZP should *not* adopt.

**Reject #1: Automatic rule compilation from substate reasoning (Soar chunking, ACT-R production compilation).** These are the tradition's canonical learning mechanisms and they are *precisely wrong* for a signed substrate. Both have documented over-generalization histories; both silently install new procedural knowledge that no operator ratified. The whole ZP premise is that consequential capabilities enter the substrate by operator authority. If the substrate compiles its own new productions, the authority story fails at the substrate level.

**Reject #2: Localist symbolic chunks as the only representation for concepts (Soar/ACT-R style).** The Cartographer's typed objects (Trajectories, Decisions, Insights, Frictions, Artifacts) are locally-named symbolic types, but if the Pathway/BDH conversation goes where Ken and I sketched it going, some concepts will not fit cleanly into a single-slot chunk. CLARION's dual-representation intuition (localist explicit + distributed implicit) is closer to right than a pure Soar/ACT-R commitment.

**Reject #3: CLARION-style weighted combination of fast and slow.** CLARION's implicit and explicit combine by a weight that a modeler tunes. This is elegant for fitting human data, but for a substrate whose commit-events carry legal-and-operational force, weighted combination without verification is under-disciplined. ZP has the right stance: the slow layer *verifies* the fast layer; combination is downstream of that verification.

**Reject #4: Single-modeler ontologies (CRAM/KnowRob style).** KnowRob and its descendants concentrate ontology curation in a small expert group and pay a real maintenance cost. If the Cartographer's ontology becomes anything like KnowRob-sized, it must have a discipline for distributed authoring, versioning, and *retirement* of concepts. Do not assume one careful curator can keep it coherent.

**Reject #5: Any move to make the Cognitive Self-Observer authoritative rather than diagnostic.** CLARION's MCS modifies subsystem parameters at runtime. This is powerful and, for a signed substrate, dangerous — a meta-cognitive component that can *change how the Regent operates* is a hidden authority pathway. The Self-Observer should flag, not intervene; intervention should always route through operator signature.

### Novel design questions the survey surfaces

These are the questions I most want Ken to sit with. They are places where the tradition asks something ZP has not yet answered.

1. **Does ZP need a procedural memory tier at all?** Soar, ACT-R, CLARION, and CRAM all have one; ZP effectively rebuilds procedural knowledge from Chain+Cartographer+Standing Corrections every cycle. This may be exactly right (procedural memory is where over-generalization hides), but it is worth naming: ZP has chosen *not to have compiled procedural memory*, and that is a substantive commitment. What is the cost, and when will it start to bite?

2. **What is ZP's impasse story?** Every architecture in the survey has *some* mechanism for the moment when the substrate detects it cannot proceed. ZP does not yet have a named primitive for this. Is it a Regent-internal move? A shadow-evaluation? An implicit "no proposal collapses this cycle"? Naming it explicitly would make the substrate's known-unknowns legible.

3. **Where does the "collapse point" live for proposal candidates?** CRAM collapses at execution time via reasoning; Soar collapses at decision time via preference procedure; ZP collapses at signing time via operator ceremony. All three are principled. But there are edge cases — the operator is unavailable, the deadline is now, the reasoning is decisive — where an authority-only collapse is under-powered. Does ZP need a *delegated collapse* primitive with a scope narrower than the original, or is that a slippery slope back to substrate authority?

4. **When (if ever) does the Cartographer generate rules and not just ontology?** The tradition has learned painfully that automatic rule generation over-generalizes. But the Cartographer already reads structure from Chain; the boundary between "typed ontology of what happened" and "generalized template for what tends to happen" is thin. Making that boundary explicit — with, say, a "template candidate" event type that requires operator ratification before it becomes precedent-eligible — would be honest about the risk.

5. **Should the Cognitive Input Plane carry receipts?** ACT-R's base-level activation silently biases retrieval. ZP's CIP explicitly tiers priority. Both make the substrate's context-assembly consequential to decisions. If a decision was materially shaped by *which precedent surfaced* into Tier 2, does the Chain event owe a receipt for that surfacing — not just "precedent P was cited" but "precedents {P, Q, R} were candidates and P surfaced because ..."? Without that receipt, the CIP is an unaudited authority.

### A note on the vector-graph composition thesis

The earlier conversation with Ken developed a mapping between Pathway's BDH coherent vectors and ZP's proposal candidates, and framed the Cartographer as potentially a vector-graph SSOT. This survey sits on the other side of that composition: declared symbolic primitives, typed objects, rule-based reasoning, cognitive cycles rather than continuous vector dynamics.

My honest read, having done the survey: **the composition is genuinely two-sided, and neither tradition subsumes the other.** Here is why.

The cognitive-architectures tradition has, across 40 years, discovered that certain structures are necessary for *auditable, cite-able, signable* cognition: a decision cycle atomic enough to inspect, memory tiers you can point at, meta-cognition as first-class, bounded rationality by construction, dual-process discipline, un-collapsed candidates that resolve on commit. These are all *symbolic* moves and they carry a specific kind of guarantee — you can *say what happened and why*. ZP inherits this directly because the Chain-plus-Cartographer-plus-signing story is nothing without that guarantee.

The coherent-vector tradition (BDH, and the broader post-transformer thread) has discovered that certain reasoning behaviors — pattern completion, associative bridging, holding-in-mind of soft possibilities — do not want to be forced into symbolic types before they resolve. A coherent vector is not a symbol; it is a shape of activation that a downstream cognitive step can *interpret* into a symbol. Forcing that resolution too early is the transformer's failure mode, and it will be ZP's failure mode too if the Regent has to speak in typed objects only.

The productive composition, then: **coherent vectors as the substrate for un-collapsed candidate reasoning; typed objects as the substrate for signed commits.** The Cartographer's job is the *bridge* — a vector-graph derived from the vector-level substrate, whose typed-object surface is what operators cite and sign. This is not two-sided as in "sometimes we use one, sometimes the other." It is two-sided as in *the substrate must be able to translate between the two, and every consequential commit must resolve to the typed side*.

Where I disagree with the earlier framing: I would not describe the Cartographer as *a* vector-graph SSOT. The Chain is the SSOT. The Cartographer is a *typed derivation over the Chain* that may internally use vector representations for candidate reasoning but whose external surface is typed. The vector graph, if it exists, is Cartographer-internal machinery — not the operator-facing truth.

The cognitive-architectures tradition validates this stance strongly. Every architecture in the survey that tried to keep too much of its reasoning in the sub-symbolic layer (CLARION's implicit-only agents, Soar without SVS in early years) lost the auditability property. Every architecture that tried to keep everything symbolic (pure Soar of the 1980s, ACT-R without base-level activation) lost the ability to model soft partial knowledge. The mature answer, in each case, was: *both, with a disciplined interface*. That interface — where the sub-symbolic bottoms out in a signed typed commit — is where ZP has a chance to do something novel that the tradition has not fully solved.

---

## Appendix — Related architectures worth naming, briefly

**LIDA** (Stan Franklin, University of Memphis; 1999–present). Computational model of Bernard Baars' Global Workspace Theory. Distinctive move: a *cognitive cycle organized around a broadcast* — a coalition of processes competes for the "global workspace," and whichever wins broadcasts its content to all other processes. Relevance to ZP: LIDA's broadcast pattern is a candidate design for how Officer verdicts propagate — instead of the Regent polling Officers, the Officer whose concern is most salient could broadcast a flag into every subsequent cycle context. Worth reading Franklin's 2012 *IJMC* paper if this pattern becomes appealing. Not surveyed in full because the broadcast pattern does not fundamentally change the ZP design recommendations above.

**Sigma** (Paul Rosenbloom, USC; 2011–present). Attempt at a *functionally elegant* grand unification via graphical models — everything (procedural, declarative, perceptual) as message-passing on a factor graph. Historically important as the third-corner architecture in the Common Model of Cognition consensus with Soar and ACT-R. Relevance to ZP: Sigma's insistence that a small set of primitives (piecewise-continuous functions on a factor graph) can implement all of cognition is close in spirit to ZP's minimalism about primitives. Not surveyed in full because Sigma has been more theoretically influential than deployed, and its graphical-model substrate is far enough from ZP's typed-object-plus-Chain substrate that the mapping is speculative.

**ICARUS** (Pat Langley et al.; 2000s–2010s). Distinctive for its skills-and-concepts hierarchy, where hierarchical skills are indexed by hierarchical concepts. Relevance to ZP: the concept/skill separation is a candidate structure for how the Cartographer's typed-object ontology (concepts) might relate to a future procedural memory (skills), if ZP ever chooses to have one. Not surveyed in full because activity in ICARUS has waned and its lessons are already implicit in the Soar/ACT-R comparisons.

**EPIC, MicroPsi, OpenCog Hyperon.** All named in Sanders' CALYSA channel bio and in the 40-year review. EPIC's contribution is fine-grained perceptual-motor timing (relevant if ZP ever adds low-level sensorimotor loops). MicroPsi and OpenCog Hyperon are hybrid architectures with active but small communities; their design lessons are subsumed by CLARION and by the "single-modeler ontology risk" note above.

---

## Sources

- Laird, J. E. (2022). *Introduction to the Soar Cognitive Architecture.* [arXiv:2205.03854](https://arxiv.org/abs/2205.03854).
- Laird, J. E. (2019). *The Soar Cognitive Architecture.* MIT Press. [MIT Press page](https://mitpress.mit.edu/9780262122962/the-soar-cognitive-architecture/).
- Soar Group, University of Michigan. [soar.eecs.umich.edu](https://soar.eecs.umich.edu/), [SoarGroup/Soar on GitHub](https://github.com/SoarGroup/Soar).
- Anderson, J. R. et al. ACT-R project, Carnegie Mellon. [act-r.psy.cmu.edu/about](http://act-r.psy.cmu.edu/about/).
- Ritter, F. E. et al. *ACT-R: A Cognitive Architecture for Modeling Cognition.* [PDF](https://acs.ist.psu.edu/papers/ritterTOip.pdf).
- Bothell, D. *ACT-R 7.30+ Reference Manual.* [PDF](http://act-r.psy.cmu.edu/actr7.x/reference-manual.pdf).
- Stocco, A. et al. (2022). *An Analysis and Comparison of ACT-R and Soar.* [arXiv:2201.09305](https://arxiv.org/abs/2201.09305).
- Sun, R. Wikipedia entry for CLARION. [CLARION (cognitive architecture)](https://en.wikipedia.org/wiki/CLARION_(cognitive_architecture)).
- Sun, R. et al. *The CLARION Cognitive Architecture: A Tutorial.* [PDF via escholarship](https://escholarship.org/content/qt149589jb/qt149589jb_noSplash_98d7d2205ec09e80b8e1b1d32192b257.pdf?t=op2j5l).
- Sun, R. Personal site and CLARION project page. [drronsun/clarion](https://sites.google.com/site/drronsun/clarion/clarion-project).
- Beetz, M., Kazhoyan, G. et al. (2023). *The CRAM Cognitive Architecture for Robot Manipulation in Everyday Activities.* [arXiv:2304.14119](https://arxiv.org/abs/2304.14119).
- Beetz, M., Kazhoyan, G. et al. (2025). *Robot manipulation in everyday activities with the CRAM 2.0 cognitive architecture and generalized action plans.* Cognitive Systems Research. [Semantic Scholar entry](https://www.semanticscholar.org/paper/Robot-manipulation-in-everyday-activities-with-the-Beetz-Kazhoyan/2001418724e1317c9d2552b78d4300adbae57565).
- CRAM Documentation. [cram2.github.io/cognitive_robot_abstract_machine](https://cram2.github.io/cognitive_robot_abstract_machine/).
- EASE CRC. [ease-crc.org](https://ease-crc.org/open-ease/ease-open-source-software/); NEEM Handbook [PDF](https://ease-crc.github.io/soma/owl/1.1.0/NEEM-Handbook.pdf).
- Laird, J. E., Lebiere, C., Rosenbloom, P. S. (2017). *A Standard Model of the Mind.* AI Magazine 38(4). [ACT-R hosted PDF](http://act-r.psy.cmu.edu/wordpress/wp-content/uploads/2018/03/Lebiere-StandardModeloftheMind.pdf).
- Kotseruba, I., Tsotsos, J. K. (2018). *40 years of cognitive architectures: core cognitive abilities and practical applications.* Artificial Intelligence Review. [Springer](https://link.springer.com/article/10.1007/s10462-018-9646-y); [arXiv:1610.08602](https://arxiv.org/abs/1610.08602).
- Franklin, S. et al. LIDA. Wikipedia: [LIDA (cognitive architecture)](https://en.wikipedia.org/wiki/LIDA_(cognitive_architecture)).
- Rosenbloom, P. S. Sigma. [Rosenbloom's USC site](https://sites.usc.edu/rosenbloom/recent-publications/); [arXiv:2101.02231](https://arxiv.org/abs/2101.02231).
- Langley, P. ICARUS Tutorial. [PDF](https://escholarship.org/content/qt9283v6nd/qt9283v6nd_noSplash_f068dfd3469e2d5c4a9836f7ad946057.pdf?t=op2mtc).
- Sanders, A. `@calysa_project` YouTube channel. [youtube.com/@calysa_project](https://www.youtube.com/@calysa_project). No academic publications located for CALYSA as of the search date.
