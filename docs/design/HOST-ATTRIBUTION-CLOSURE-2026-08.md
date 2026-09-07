# Host Attribution Closure — the deployability precondition, admitted as a dynamic

**Document type:** Design note. Admits one dynamic under `DYNAMICS-DISCIPLINE-2026-08.md` §3 and specifies its discriminator as a measure. Not a Tier 2 canonical elaboration — nothing here is a Layer A or Layer B claim yet.

**Date:** 2026-08-16.

**Author:** Ken Romero, with synthesis assistance from Claude.

**Status:** Proposed. No code written. Resolves the `OPEN` field of `DECIDED-006` in `DELIBERATION-LOG-2026-08.md`, which recorded that "deployable maturity" had no test. This document proposes the test. It is not yet the test — §8's first reading has not been run, and until it has, the definition below is a hypothesis about a distribution nobody has looked at.

**Composes with:** `DYNAMICS-DISCIPLINE-2026-08.md` (admission schema, §6 anti-targeting), `OBSERVATION-PLANE-2026-07.md` (the `observe:` / `observation:process:` families this measure would be built on — reserved 2026-08-16, unbuilt), `HOST-BROKER-2026-08.md` (the governance half; `no_raw_spawn_outside_zp_host` landed as a discipline pin 2026-08-14, Phases 1–5 unbuilt), `SUBSTRATE-BLINDNESS-HEURISTICS-2026-07.md` (§"What the substrate does NOT blind" permits this observation; Layer 3 constrains its content), `SUBSTRATE-FORM-2026-07.md` (Form determines the size of the delegated baseline, §5), `SUBSTRATE-READINESS-CONTRACT-2026-07.md` (nearest existing frame for readiness; its `substrate:readiness:` receipts are reserved-not-built).

---

## 1. What is being admitted

The proposal arrived as a metric. It is admitted here as a **dynamic**, because that is what it is: a metric is not admissible under `DYNAMICS-DISCIPLINE`, but the thing the metric would detect is, and the metric is that entry's `discriminator` field.

**The dynamic: ungoverned host accretion.** Processes accumulate on a host that the substrate cannot account for. Each arrival is individually unremarkable — an installer, a helper daemon, an update agent, a login item, a language-server child. None is a fault. The composition is that the substrate's *actual* reach diverges from its *claimed* reach, silently and monotonically, and nothing anywhere emits when it does.

This is the failure the substrate is least equipped to see, for a structural reason: an unaccounted process is unaccounted *by definition*. It generates no finding, trips no gate, and appears in no receipt. The substrate's own instrumentation cannot report the thing it does not know about. That is `quiet` in the §4 sense — not merely uninstrumented, but eventless.

## 2. Register entry

Per `DYNAMICS-DISCIPLINE` §3.

| Field | Content |
|---|---|
| `mechanism` | Processes start on the host outside any substrate-mediated path → the substrate has no record of what they are or what authorized them → substrate reach silently diverges from claimed reach → governance claims about the host become progressively less true without any claim being retracted |
| `signature` | `quiet` — an unaccounted process emits nothing by construction |
| `healthy_twin` | A busy machine legitimately running many things. High process count is not pathology; a developer workstation mid-build looks identical to a compromised one by count alone |
| `discriminator` | **Attribution state per process, mechanically determined** (§3). The host supplies the population; set membership answers the question. This is the measure — §4 |
| `disposition` | `instrumented` — proposed. Would be the register's **first `quiet` entry to reach `instrumented`** rather than `designed-out` or `admitted-unresolved` |
| `disconfirming_test` | §8. If unaccounted process-seconds are dominated by one shape, the measure is really measuring that one thing and should be renamed for it |
| `prior_art` | None found for the specific formulation. Adjacent: allowlisting and application control (NIST SP 800-167), EDR process-provenance trees, and the host-integrity tradition generally. Those govern to *block*; this one measures to *know*, which is a different objective and a weaker claim |

**Why this entry matters beyond itself.** `DYNAMICS-DISCIPLINE` §5 observed that every `loud` entry is instrumented or designed out while the `quiet` and `inverted` columns are unresolved, and concluded the corpus has no template for dynamics whose signature is everything reading healthy. This is the first candidate to supply one.

## 3. Why the discriminator qualifies

Two gates the corpus has used to kill measures, and how this one passes.

**`BUFFER-OBSERVATION` §6 — the exhaustion condition must be mechanically determined.** "The operator is depleted" has no mechanical threshold and any number standing in for it becomes the target immediately. A process is either in the accounted set or it is not; the host answers, and the answer is a fact rather than a judgment. This is the gate that killed *operator attention* and *unexercised judgment*, and it is the reason those remain `admitted-unresolved`.

**`TRIAGE-FOR-COHERENCE` §6 — the denominator must not be authored.** Coherence coverage moved the wrong way under honest authoring because both halves of the ratio were written by us. Here the denominator is supplied by the operating system. **The measure cannot be raised by writing anything** — not a document, not a reservation, not a comment. On 2026-08-16 substrate maturity was raised 22.2 points across three batches of reservations while `live` stayed at 581 and nothing was built; that is impossible against this measure by construction.

An externally-supplied denominator is the structural property that distinguishes this from every measure currently instrumented in the corpus.

## 4. The measure

### 4.1 Three states, closed set

Every process on the host resolves to exactly one:

- **`governed`** — the process was started through a substrate-mediated path, its side-effecting actions pass the gate, and it emits receipts. The `no_raw_spawn_outside_zp_host` pin (`HOST-BROKER` Phase 0, landed 2026-08-14) is the beginning of this state's enforcement.
- **`attributed`** — not gated, but the substrate can name three things: the executable's identity (path plus content hash), what authorized it (package, OS baseline delegation, operator-signed exception, or parent attribution), and its expected behavior class. Attribution is a *claim with provenance*, not an entry in a list.
- **`unaccounted`** — present and unexplained.

**Attribution categories are a closed set.** This is load-bearing. One free-text or `allowed:unknown` bucket and the measure hollows out within a week, because attributing becomes cheaper than understanding. Adding a category is a ceremony, not a config edit.

### 4.2 Provenance, not presence

The failure mode to design against is the one the corpus has already demonstrated: on 2026-07-27 an undocumented-crate count fell 8 → 1 because a document was added that *lists the undocumented crates by name*, satisfying a check that only tested for a mention. The same defect is available here. If `accounted` means "appears in an enumeration," then `ps` piped into a receipt is the whole implementation and it knows nothing.

Hence the three-part attribution requirement above. A process is attributed when the substrate can answer *what authorized this*, not when the substrate has noticed it exists.

### 4.3 Windowed, not point-in-time

**The measure is `unaccounted_process_seconds` over a declared window, with `distinct_unaccounted_executables` as its companion count.** Not a snapshot.

Processes churn. Zero unaccounted at an idle moment is trivially achievable and means nothing, and a snapshot metric would be dominated by sampling noise. Worse, short-lived processes are exactly where the interesting cases live — a forty-millisecond `curl` is the case worth catching and the case a periodic sample will essentially never see.

The two numbers answer different questions and both are needed: process-seconds says how much unaccounted execution happened, the distinct count says how many kinds. A single long-lived unknown daemon and a thousand brief unknown invocations are different problems with the same total.

### 4.4 Milestone definitions

- **Host attribution closure** — `unaccounted` reaches zero over a declared window. The substrate can account for everything executing on the host, though most of it is not governed.
- **Full governance** — `governed` reaches 100%. Only coherent on a hardware-sovereign system where no delegated baseline exists.

**These must not share a name.** The proposal called the first "fully governed," and the label will collapse the distinction the first time it is quoted. Attribution closure satisfies §III.19 detectability and says *nothing* about §III.18 delegable safety: 100% attributed does not mean the gate would stop a bad action, only that nothing is executing unseen. Reserving the stronger phrase costs nothing now and prevents a future 100% from reading as "safe."

## 5. Form determines the baseline, and that is the host/sovereign line

A large fraction of PIDs on any host are kernel threads, init-system children, and platform services. They must resolve to `attributed` or the number never reaches zero and the measure is dead on arrival.

But attributing them means declaring an authority: *I accept the vendor's base image as attesting to its own processes.* That is a delegation — chain-anchorable, scoped, revocable, and exactly the shape of Form Disclosure.

So the host-versus-sovereign distinction does not need to be asserted alongside the measure. **It falls out of it.** On Companion or Appliance Form, attribution closure includes a signed delegation covering the vendor's process set, and the size of that delegation is visible. On hardware-sovereign Form the delegation is empty and the `governed` tier can reach 100%. Same measure, different Form, and the gap between them is legible as a specific signed grant rather than a claim about posture.

This also gives the delegated baseline a number — *what fraction of this host is trusted rather than known* — which is a more honest description of Companion Form than any prose currently in the corpus.

## 6. Goodhart analysis

Required by §6 of the discipline, and the answer is not clean.

**The available cheat is shrinking the denominator.** Uninstall things, run a minimal host, close the browser. The measure quietly rewards not using the computer, which is structurally identical to coverage rewarding not writing things down — the defect this corpus has already been bitten by.

Three constraints follow, and they are part of the specification rather than advice:

1. **Never comparable across hosts.** A tidy machine and a governed machine produce the same figure.
2. **Never a target across operators.** Any leaderboard or shared threshold makes austerity the winning move.
3. **The denominator publishes with the ratio, always.** A closure percentage without its process count is not a reading.

**A second cheat: liberal attribution.** Categories that stretch — a generous `parent-attributed` rule, say — raise the number without raising understanding. The closed-set requirement in §4.1 is the control, and its enforcement is that adding a category is a ceremony.

**What is not defended against.** A sufficiently determined operator can attribute everything and learn nothing, and no structural control prevents that. The measure assumes good faith from the operator toward their own substrate, which is a reasonable assumption for a sovereignty tool and an unreasonable one for a compliance tool. This measure is not a compliance artifact and should never be used as one.

## 7. Composition with aligned blindness

Permitted, with one constraint.

`SUBSTRATE-BLINDNESS-HEURISTICS` §"What the substrate does NOT blind" lists the substrate's own operational state — process states, port bindings, extension activity — as explicitly not a candidate for blindness, since the substrate self-observes to maintain the lsof-test discipline. Enumeration is therefore in scope.

**The constraint is Layer 3.** Command-line arguments carry secrets, and §III.24's Layer 3 names command-line secret patterns as scrub-before-anchoring. Attribution must key on executable identity — path plus content hash — and authorization provenance. Raw `argv` is scrubbed before the observation is chain-anchored. This is not a limitation on the measure: argv is not what attribution needs.

## 8. The first reading — to run before this becomes canonical

Per `TRIAGE-FOR-COHERENCE`: a new measure's first reading is evidence about the measure, not about the system.

**The experiment.** Enumerate processes on APOLLO-4 over a declared window. Bucket by parent, by executable, and by candidate attribution source. Publish the distribution — not the closure percentage.

**What it would establish.** Whether `unaccounted` is heterogeneous or is one shape wearing many PIDs. The precedent is direct: 498 of 656 corpus defects turned out to be a single class, which meant the elaborate ranking rule governed a minority and the bulk was one measurable problem. If unaccounted execution is similarly dominated — say, one package manager's helper churn — then this is not a general attribution measure and should be renamed for what it actually tracks.

**The disconfirming outcome.** If the unaccounted set at a normal working moment is already near zero without any substrate work, the dynamic in §2 is not occurring on this host and the measure is premature. That is a cheap refutation and it should be run before anything is built.

**Cost.** An afternoon. No code that survives the experiment.

## 9. What this does not claim

- Not that attribution closure makes a host secure. It makes it *known*. §III.19 detectability, not §III.18 safety.
- Not that the three states are the right decomposition. They are a first proposal, and §8 may collapse or split them.
- Not that this is the only deployability precondition — only that `DECIDED-006` recorded having none, and this is a candidate with a mechanically-determined test.
- Not instrumented. `observe:process:` and `observation:process:` are reserved-not-built as of 2026-08-16, and `HOST-BROKER` Phases 1–5 are unbuilt. Adopting this measure gives both their first concrete forcing function; it does not build either.

## 10. Open positions

1. **Window length.** Process-seconds needs a declared window and none is proposed. Too short and short-lived execution dominates; too long and the figure stops responding to change. §8's distribution should determine it rather than a guess.
2. **Containers, VMs, and this session.** A process inside a container is one process to the host and many to itself. Nested execution contexts have no treatment here, and the device bridge this document was drafted through is itself an example.
3. **Graduation path.** When the measure lands, `observe:process:` moves from `RESERVED_RECEIPT_PREFIXES` to `KNOWN_RECEIPT_PREFIXES` — the graduation ceremony the array documents. That is the first reserved family with a named condition for graduating, and it should be recorded as the worked example.
4. **Relationship to `live`.** `DYNAMICS-DISCIPLINE` §6 recommends tracking `live` — connections holding something that would fail. Attribution closure is a second externally-denominated measure. Whether the substrate should carry two or whether one subsumes the other is unresolved; carrying two composite health numbers risks exactly the composite scoring `BUFFER-OBSERVATION` §6 forbids.

---

## Framing note

The corpus asked for a definition of deployable maturity and got one that is unusual in a specific way: it cannot be satisfied by writing. Every other maturity figure here — coherence coverage, connection maturity, reserved-family count — has an authored denominator, and the session that produced this document demonstrated that property by moving one of them twenty-two points without building anything.

The operating system supplies this denominator, and it does not care what the corpus says about itself. That is the whole argument for the measure, and it is also the reason to be careful with it: a number the substrate cannot talk its way into improving is a number the substrate will be tempted to shrink instead.
