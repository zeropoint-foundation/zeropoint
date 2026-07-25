# Demonstrative Use Cases — Proving Sovereign Usefulness on APOLLO + PI5 (2026-07)

**Design input, not a canonical elaboration.** Defines the concrete jobs the reference implementation must be *useful at*, so the hardware benchmark and the PI5 build have a purpose instead of being infrastructure in search of one. Does not amend KEEL. Composes with `LOCAL-MODEL-SELECTION-2026-07`, `INFERENCE-ROUTING-DISCIPLINE-2026-07`, `AI-LANDSCAPE-SIGNAL-2026-07`, `MULTI-DEVICE-OPERATION-2026-07`, `SUBSTRATE-BLINDNESS-HEURISTICS-2026-07`, and `FIELD-TESTING-DISCIPLINE-2026-07`.

## The point

We drifted into designing architecture before measuring the tech stack's floors/ceilings *and* before understanding how the pair actually gets used. The correction is to let concrete, genuinely-useful use cases drive both. A well-chosen use case is three things at once: a **demo** (proves the thesis to an observer), a **dogfood** (real need, so usage data is honest), and an **instrument** (being useful *requires* exercising a specific floor and revealing a specific seam). The demos *are* the empirical program.

## The framing principle: sovereignty is the feature, not the footnote

The weak use case is "like a cloud assistant, but private." An observer thinks *so… the cloud assistant.* The strong use case is one where **cloud is pointless, impossible, or absurd** — so local/yours is *why it's good*, not a compliance checkbox. Every candidate passes a two-part filter:

1. **Sovereignty test — "Would this be pointless or impossible on a cloud tool?"** If yes, it demonstrates ZeroPoint. If "same but private," reject it.
2. **Reality test — "Would the operator use this anyway, today?"** If no, it's demo-ware; the usage/seam data it generates is fake. Reject it.

Only use cases that pass *both* are built.

## The scenario template

A use case is a story with a pointable payoff and a floor it stresses — not a feature list. Each is framed as:

- **Scenario** — the operator does X.
- **Why sovereign** — why cloud can't or shouldn't.
- **Stress-tests** — which floor/ceiling it forces (feeds the benchmark).
- **Node(s) + seam** — where it runs, and the reach-across moment (feeds the mesh backlog).
- **Payoff** — the observable "aha."
- **Standalone check** — still useful if the other node is off? (sovereignty requires yes.)

---

## UC-1 — Research corpus synthesis (FLAGSHIP; build first)

The loop we performed by hand across this session, automated.

- **Scenario.** The operator feeds a source (a YouTube URL, a paper, an article). The system ingests it and reports which of the operator's *existing design docs* it confirms, contradicts, or updates — e.g. "this video pressure-tests dimension 1 of the AI-LANDSCAPE-SIGNAL brief; it updates the DEPENDENCY-POSTURE local-inference gap."
- **Why sovereign.** It reasons over the operator's *whole private corpus* (the chain/ontology, the design docs). No cloud tool has that corpus, and the operator wouldn't hand it over. The value is inseparable from the data being local.
- **Stress-tests.** Long-context reflection over the accumulated corpus — **APOLLO's prefill ceiling**, the single most important unknown. Also ingestion throughput (PI5) and structured extraction (does the model emit clean entity/finding JSON).
- **Nodes + seam.** PI5 ingests sources to the chain continuously; APOLLO reflects over the corpus (non-realtime horizon). **The seam** is exactly PI5-ingest → APOLLO-reflect — the first real mesh coordination requirement, discovered by use.
- **Payoff.** "This source updates that brief" — *generated*, not hand-done. Already proven useful because the operator needed it this session.
- **Standalone check.** ✅ PI5 ingests to the chain alone; APOLLO reflects over whatever's in the chain alone. Mesh makes it continuous.

**Filters:** Sovereignty ✅ (private corpus reasoning) · Reality ✅ (the operator's primary research flow — confirmed). Build first: it is the demo, the dogfood, and the prefill-wall instrument simultaneously, and it turns the session into its own proof. Reuses the already-built `youtube-transcript-mcp` as one ingest source.

## UC-2 — Ambient capture-to-chain (PI5 standalone)

- **Scenario.** The operator speaks a thought; PI5 transcribes it locally (piper/whisper already on PI5), classifies it, and files it into the chain/ontology.
- **Why sovereign.** Your stray, half-formed thoughts *never leave the house* — "private" ambient capture on a cloud service is a contradiction in terms. Impossible to do sovereignly any other way.
- **Stress-tests.** The **PI5 edge floor**: local ASR + a tiny classifier (Qwen3-0.6B clear, or LFM2.5-230M elected) at usable latency on 8GB CPU-only. Establishes what an always-on sovereign node can actually sustain.
- **Nodes + seam.** PI5 alone for capture; the reach-across is *later* — APOLLO reflecting over captured thoughts (feeds UC-1). Seam: capture (PI5) → reflect (APOLLO).
- **Payoff.** A week later: "what was I thinking about GLM streaming?" — it's there, yours, retrievable, and it was captured with zero friction and zero egress.
- **Standalone check.** ✅ Fully useful on PI5 with APOLLO off — this is the atomic sovereign node doing one real thing.

**Filters:** Sovereignty ✅ (ambient private capture is cloud-impossible) · Reality ✅ (frictionless thought capture is a real want). This is the smallest "PI5 does one useful thing standalone" build — the atomic-unit proof.

## UC-3 — Reason over the documents you'd never paste into a cloud (APOLLO standalone)

- **Scenario.** The operator asks questions of the documents that never go to a cloud model: financials, contracts, health records, personal journals. APOLLO runs a resident model over local documents.
- **Why sovereign.** This is the category cloud *categorically cannot serve* — not "shouldn't," *can't*, because the operator will never upload it. Sovereignty is the entire premise.
- **Stress-tests.** Resident model quality + **local retrieval** over a private document set; the int4 quant-degradation question bites here (bad reasoning over your finances is worse than none).
- **Nodes + seam.** APOLLO alone (the heavy resident tier). Productively bumps `SUBSTRATE-BLINDNESS-HEURISTICS`: some of this the substrate should reason over on demand but *not retain* — which is itself a demonstration of what makes ZP different from "local ChatGPT."
- **Payoff.** "What did I commit to in the Q3 contract, and does it conflict with the new one?" — answered, on your metal, from documents you'd never surrender.
- **Standalone check.** ✅ Fully useful on APOLLO with PI5 off.

**Filters:** Sovereignty ✅ (cloud-impossible by the operator's own line) · Reality ✅ (everyone has never-upload documents). Also the cleanest public-facing demo of *why sovereign* — it needs no ZP vocabulary to land.

---

## Scoreboard

| Use case | Sovereignty filter | Reality filter | Primary node | Floor it measures | Seam it reveals |
|---|---|---|---|---|---|
| UC-1 Research synthesis | ✅ private corpus | ✅ operator's flow | APOLLO (+PI5) | APOLLO prefill ceiling | ingest → reflect |
| UC-2 Ambient capture | ✅ cloud-impossible | ✅ frictionless want | PI5 | PI5 edge ASR+classify | capture → reflect |
| UC-3 Private-doc reasoning | ✅ never-upload | ✅ universal | APOLLO | resident quality + retrieval | (single-node; blindness line) |

## What this gives the infrastructure

Each use case hands the empirical program a concrete job:

- **The APOLLO benchmark** now has a *purpose-shaped* target: UC-1 says "measure prefill at corpus-scale context," UC-3 says "measure resident quality + retrieval," not just abstract tok/s.
- **The PI5 build** has a first job: UC-2, the smallest standalone-useful thing (ASR + classify + file), which is also the edge-floor instrument.
- **The mesh backlog** writes itself from the seams: `ingest → reflect` (UC-1/UC-2) is the first coordination primitive to design — *after* it's been felt, not before.

## Sequencing

1. Run the APOLLO benchmark (`tools/local-model-bench`) — with UC-1 and UC-3's shapes in mind, so the context lengths and eval prompts reflect real jobs.
2. Build UC-2 on PI5 (standalone-useful, GGUF track) — proves the atomic node and measures the edge floor.
3. Wire UC-1's ingest→reflect loop across the pair — the first mesh seam, designed from observed friction.
4. Keep a running seam log while using all three; the reach-across moments are the mesh design, written by behavior.

The through-line: **build things that are useful because they're sovereign, on jobs the operator already does, and let being useful be the thing that measures the floors and reveals the seams.**
