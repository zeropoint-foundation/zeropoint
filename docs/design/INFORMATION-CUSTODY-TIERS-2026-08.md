# Information Custody Tiers

**Tier 2 canonical elaboration.** Elaborates `KEEL-2026-07.md` §III.24 (Aligned
blindness), §II.17 (Cognitive discipline sandwich), and §III.13 (Chain is truth;
ontology is understanding). States as one model a distinction the corpus has
been making in pieces: which information the substrate may reason over, which it
may only carry, and which it must refuse to hold. Canonical claims live in KEEL.

Draft — 2026-08-06 — internal audience only. Composes with
`SINGULAR-SOVEREIGN-ROOT-2026-05.md` (the vault master key derives from Genesis),
`COGNITIVE-INPUT-PLANE-2026-07.md` (what reaches Regent's context),
`SUBSTRATE-BLINDNESS-HEURISTICS-2026-07.md` (the §III.24 elaboration this
completes), `SUBSTRATE-FORM-2026-07.md` (Sealed FDE and at-rest protection per
Form), and `SUBSTRATE-BOOT-INVARIANT-CEREMONY-2026-07.md` (which should verify
custody assignments persist).

---

## 1. The question this answers

Asked by the operator on 2026-08-06, after finding roughly two dozen live
credentials in plaintext `.env.pre-vault` files while the vault sat empty:

> I think all information is supposed to be encrypted at rest at any rate, so
> I'm not sure what the distinction between secrets and private information in
> general.

It is the right question, and the answer is not "secrets are more sensitive."
Sensitivity is a spectrum and spectrums do not produce architectures. The
distinction that produces one is **what the substrate is permitted to do with
the material**, and it sorts cleanly into three tiers.

## 2. Why encryption at rest does not settle it

Full-disk encryption protects a **powered-off device**. FileVault on Companion
Form, Sealed FDE bound to TPM PCR state on Sovereign Form (§XIV). Against a
stolen laptop it is decisive.

Against the adversary that actually matters here it does nothing. The substrate
runs on an unlocked machine. At that moment the disk is decrypted, and every
process running as the operator can read `~/ZeroPoint/` — a malicious npm
postinstall, a compromised transitive dependency, anything reached by
`curl | sh`. Disk encryption has already done its whole job and offers no
further protection.

The vault holds against exactly that adversary, because its key is not on the
disk. It derives from Genesis via `load_sovereign_root`, exists only in process
memory, and requires a sovereignty ceremony to obtain. A process that can read
every file the operator can read still cannot read the vault.

**They are not layers of the same protection. They are answers to different
questions**, and the vault answers the one that applies while the substrate is
running — which is always.

## 3. Tier 1 — Secrets

**Definition: possession confers authority to act as the operator.**

An API key is not sensitive because it reveals something; it is sensitive
because holding it *is* being you, to the service that accepts it. That is the
property, and it has three consequences.

**Machine-consumed, never reasoned over.** A secret is injected into a process
environment or a request header. Nothing in the substrate needs to *understand*
it. Regent has no use for the bytes of an Anthropic key and every reason not to
have them.

**Rotatable, therefore lifecycle-bearing.** A leaked key is revoked and
reissued. This demands a mutable store with `store`, `retrieve`, `remove` — not
an append-only ledger.

**Blast radius is action, not disclosure.** A leaked key lets someone spend your
money and act in your name. That is categorically different from someone knowing
your schedule.

**Custody**: the credential vault. ChaCha20-Poly1305, per-tier derived keys,
master key from the sovereign root. Path prefix selects the tier —
`providers/`, `tools/`, `system/`, `ephemeral/`.

**Cognitive rule: never admitted.** Officers hold a `VaultKeyLister` that
exposes key *names* only — the R1 privilege invariant. The operator's standing
correction `d267fe48970a5e2f` states it directly: *vault values must never enter
cognitive-layer context.*

**Chain rule: the fact, never the value.** `vault:secret:stored`,
`vault:secret:revealed`, `vault:secret:removed` carry the key name. That an
inference credential was read at 14:02 is auditable; what it was is not on the
chain and never will be.

## 4. Tier 2 — Subject matter

**Definition: the substrate must reason over it. This is what it is for.**

Trajectories, decisions, insights, frictions, chain history, the operator's work
and its shape. Private, often more personally revealing than any API key, and
nonetheless the material the cognitive layer exists to think about. A substrate
that cannot see it is not protecting the operator; it is failing them.

**Not rotatable.** You can reissue a key. You cannot reissue last Tuesday. The
correct structure is append-only and signed, not mutable and re-keyed.

**Custody**: the chain, and the ontology the Cartographer derives from it.
At-rest protection comes from the Form's disk encryption, not from a second
envelope.

**Why not vault this too** — the question the tiering has to answer honestly.
Because encrypting the chain per-entry would break the architecture that depends
on reading it. Officers query it. The Cartographer materializes an ontology from
it. Claim 2 (collective audit) requires that a third party can verify chain
integrity. Hash-linkage and signature verification over opaque ciphertext is
possible; *understanding* over it is not, and understanding is the point. The
chain is protected by being signed and by the disk beneath it, not by being
unreadable.

**Cognitive rule: admissible.** Subject to the priority-weighted composition of
`COGNITIVE-INPUT-PLANE`, but admissible by design.

## 5. Tier 3 — Refused

**Definition: an aligned substrate has no business holding it, whoever
authorizes it.**

§III.24 and its elaboration in `SUBSTRATE-BLINDNESS-HEURISTICS`. Not a storage
decision — a **non-acquisition** decision. There is no encrypted form of a
keylogger that makes it acceptable.

Keystroke capture, full-screen capture, clipboard monitoring, cryptographic key
observation, continuous location as background telemetry, individual financial
transactions, medical diagnoses, inferred mental-health state.

The test is not "would the operator consent" but "does holding this create only
harm — directly through breach, or downstream through chain-anchored records
used against the operator in circumstances they cannot foresee." Some material
is toxic to hold at any encryption.

## 6. The admissibility test

One question sorts the tiers:

> **Does the substrate need to *think* about this, or merely *pass it along*?**

| Answer | Tier | Custody | In cognitive context |
|---|---|---|---|
| Think about it | 2 | chain + ontology | yes |
| Pass it along | 1 | vault | never |
| Neither | 3 | not held | n/a |

### Edge cases, because the clean cases were never the problem

**`DATABASE_URL=postgres://user:hunter2@host/db`** — Tier 1. It reads as
configuration and contains a password, and the embedded credential governs.
Anything carrying a bearer credential is Tier 1 entire; there is no partial
custody of a connection string.

**A model name (`qwen3:8b`)** — Tier 2. It is a fact about the substrate that
the substrate must reason over, and it confers nothing.

**The *existence* of an API key** — Tier 2. That `tools/ember/OPENAI_API_KEY`
exists is chain-anchored fact and the operator should be able to see it. The
value is Tier 1. Existence and content take different tiers, which is exactly
what `list()` returning names is expressing.

**A command line containing a token** — Tier 1 material that has strayed into a
Tier 2 surface. This is why `zp-audit/src/scrub.rs` exists and is always-on with
no disable flag: it is the **boundary enforcement point** where Tier 1 leaks
into Tier 2 and must be redacted before the chain accepts it. Worth naming
plainly — the scrubber is not a nicety, it is the tier boundary made mechanical.

## 7. What this implies for onboarding

Onboarding already does more than it appears to. `crates/zp-server/src/onboard/credentials.rs` calls
`vault.store()`; `crates/zp-server/src/onboard/deep_scan.rs` actively hunts credentials in project
configs and has redaction tests for `postgres://user:secret@…` and
`POSTGRES_PASSWORD`. The April 2026 migration that produced the `.env.pre-vault`
files almost certainly ran through it.

**The gap is not capability. It is that onboarding is a one-shot ceremony while
custody is a continuous invariant.**

Onboarding established the vault in April. The vault was subsequently lost.
Nothing re-checked, because nothing was ever asked to. Four months later the
operator's credentials were in plaintext on disk and the substrate's only signal
was `vault_empty` at Info severity — a tier that was, until 2026-08-06,
discarded before reaching the chain.

So the refactor is less about adding secret handling than about splitting two
responsibilities that are currently fused:

- **Onboarding assigns custody.** For each piece of material it encounters, it
  decides a tier and puts it there. This mostly exists.
- **Boot invariants verify the assignment held.** This does not exist at all.

A secret added after onboarding has no path in — there is no re-entry ceremony,
which is why `zp vault put` had to be built on 2026-08-06 before any of this was
actionable.

## 8. What this implies for boot invariants

`SUBSTRATE-BOOT-INVARIANT-CEREMONY-2026-07.md` is specified and unimplemented.
Its vault invariant, `vault_key_composes_with_provider`, asserts that
`resolve_vault_key()` returns `Ok` with `source = SovereigntyProvider`.

**The 2026-08-06 defect satisfies that invariant.** The key resolved, with that
source. It simply arrived after `spawn_regent` had read an unpopulated
`OnceLock` and fallen back to plaintext. The invariant tests whether the
capability exists; the failure was in delivery.

Custody-derived invariants, all checkable:

| Invariant | Catches |
|---|---|
| `vault_key_present_before_consumers_run` | the delivery race |
| `vault_nonempty_if_tools_were_governed` | custody silently lost |
| `no_tier1_material_in_chain` | scrubber gap or bypass |
| `governed_tool_env_resolves_from_vault` | Tier 1 injection path broken |

The second deserves emphasis. Six `.env.zp` files exist on disk, each proof that
a tool was governed once. An empty vault alongside them is a contradiction that
was observable at any moment for four months, and nothing was looking. It is
also a cross-surface agreement check, which makes the bedrock checklist and
`METACOGNITIVE-FIDELITY-HARNESS` the same mechanism at different urgency: boot
invariants are the existential subset that should **refuse** rather than report.

## 9. Vault lifecycle and the copy prohibition

Observed 2026-08-11: three byte-identical copies of the vault sat in the runtime
home — `vault.json` (Aug 10), `vault.json.bak` (Aug 6), and `vault.json.bak.keep`
(Aug 10) — distinguishable only by mtime, the third named that way because `.bak`
was already taken. A restore command nearly put the Aug 6 copy over the Aug 10
one. They were identical, so nothing was lost, but the near-miss is the finding.

**A `.bak` of the vault is rollback**, and §III.20 is unambiguous that this
substrate rolls forward. Ad-hoc file copies smuggle rollback in through the
filesystem, past every discipline that governs the chain.

For a secrets store the objection is sharper than that. Rolling a vault back is
not recovery — it is a security regression, because it resurrects credentials
that were deliberately rotated or revoked. A backup of the vault, in the ordinary
sense of the word, is an anti-feature. Each copy is also one more ciphertext an
attacker can take offline and work on without time pressure, which is a direct
enlargement of the Tier 1 attack surface that §3 exists to keep minimal. And a
substrate reasoning about "the vault" while four files answer to that description
has lost the singularity the sovereign-root argument depends on.

**The prohibition: no vault copies in the runtime home. Ever.** Four mechanisms,
where the first two remove the reasons anyone reaches for a copy:

1. **Atomic writes** — temp file, fsync, rename. A crash mid-write cannot
   corrupt the vault, so no sibling copy is needed for crash safety.
2. **`vault:mutated` receipts** — tier, key count, before-and-after hash. *Did
   this change, when, and to what* becomes a chain query instead of a diff
   against a stale copy.
3. **A signed export ceremony** — `vault:exported`, Genesis-signed, to an
   operator-chosen destination **outside** the runtime home. This is the only
   legitimate way a second copy comes to exist, and it is deliberate, recorded,
   and not sitting next to the original wearing a similar name.
4. **Bedrock invariant `no_vault_siblings`** — anything matching the vault's path
   with a suffix is a violation. Bedrock already knows where the vault is and how
   many keys it holds (§8); this is the same shape, and it is what makes the
   prohibition enforced rather than merely agreed.

**A fifth piece, which is why these files existed at all.** They were created by
hand to test whether bedrock notices an absent vault, and `mv` was the only way
to run that test. Per §III.18, restrictions without paths get bypassed — when the
sole route to a legitimate operation is improvisation, the residue is the
substrate's fault. That test wants a governed mode that simulates absence without
moving the file.

**Open: re-import.** Export handles the case where the operator loses the device.
Importing what was exported is legitimate disaster recovery, but it reintroduces
the resurrection problem in a setting where the alternative — losing every
credential — is worse. The shape is probably a ceremony that anchors
`vault:imported` with the export's age and hash, refuses to be silent, and
surfaces what has rotated since. It is not specified here, and should not be
implemented as a quiet inverse of export.

## 10. How you would know this model is violated

- A secret value appears in a chain receipt → scrubber gap (§6 boundary)
- Regent quotes credential material → cognitive admission failure
- Live credentials in a file outside the vault → custody failure *(observed
  2026-08-06: ~176 entries across five tools)*
- Vault empty while `.env.zp` files exist → custody lost *(observed 2026-08-06)*
- Any file matching the vault path with a suffix → copy prohibition violated
  *(observed 2026-08-11: three copies, §9)*
- An observation surface acquires a Tier 3 class → §III.24 violation

Five of six are mechanically checkable today. The exception is the second, which
needs the Cognitive Self-Observer's Class 2 verification.

## 11. Connects to

**§III.24 (Aligned blindness)** — supplies Tier 3 and its non-acquisition
character. This document's contribution is placing it in a model alongside the
two tiers the substrate *does* hold, so "we refuse this" and "we protect this"
and "we reason over this" are one decision rather than three unrelated ones.

**§II.17 (Cognitive discipline sandwich)** — the admissibility test is a
statement about what may enter the filling.

**§III.13 (Chain is truth; ontology is understanding)** — Tier 2's custody. The
chain is not encrypted because it must be *understood*, and that is a
consequence of what it holds, not an oversight.

**§II.13 P1 (Signing is gravity)** — Tier 2's protection is signature and
append-only structure, not confidentiality. Different guarantee, deliberately.

**Singular sovereign root** — Tier 1's whole security reduces to one derivation
from Genesis. The vault is only as good as that root being singular, which is
why a second credential path is a vault compromise and not merely an
inconvenience.

**§III.20 (Forward-only recovery)** — §9's basis. The axiom is usually read as a
statement about the chain, but a vault `.bak` is the same violation reached
through the filesystem, and for a secrets store it is worse: rolling the chain
back would lose truth, while rolling the vault back restores credentials that
were deliberately destroyed.

**§III.18 (Delegable safety)** — why §9 ends with a governed test mode rather
than a rule. The copies existed because a legitimate operation had no path, and
a prohibition that leaves the operator improvising is one that will be bypassed
again.

**The lsof test** — its custody counterpart: the substrate is mature when every
piece of material it holds is assigned a tier, and nothing sits in a file
outside one.
