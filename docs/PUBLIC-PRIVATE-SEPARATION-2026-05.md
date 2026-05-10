# Public / Private Separation

*Drafted 2026-05-10. Defines the publication rules that keep ZP Foundation
operations private while making the Foundation a credible public reference
implementation of the ZP stack.*

## The principle

ZeroPoint Foundation runs its own workspace on its own substrate. That dogfood
story is a load-bearing credibility lever — it shifts ZP from "trust
infrastructure other people might use" to "trust infrastructure the people
building it actively rely on."

But running a real workspace produces real operational data, and a real
operational data set is **private by default**. Member identities, actual
delegations, audit chain contents, conversation histories, in-flight
negotiations, financial details — none of this should ever leak into a
public repo.

The two pulls — *be a reference implementation* and *protect operational
data* — are reconciled by **separating code, configuration, and data** at
the repository layer. They have different publication rules, and the
boundary between them is enforced by discipline (and eventually by pins).

> **Anyone in the world should be able to recreate a Foundation-style
> stack from scratch by reading the public material. Nobody should be
> able to recreate the Foundation's actual operational state from the
> public material.**

## The three layers

| Layer | Examples | Publication |
|-------|----------|------------|
| **Code** | Substrate (`zeropoint`), IronClaw fork with ZP integration commits, bridge crates (`zp-ironclaw`), MCP adapters (`zp-mcp`, `zp-agui`), CLI (`zp`), helper scripts | **Public** |
| **Configuration templates** | `.zp-configure.toml` files, deployment manifests, runbook docs, delegation *schemas*, gate *rule templates*, MCP server *catalogs* (with secrets as `${vault:...}` placeholders), architecture docs, onboarding guides | **Public** |
| **Operational data** | Audit chain contents, Genesis keys, vault contents (encrypted or not), session tokens, actual delegations (who/when/what scope), real conversations, calendar/email/task content, financial/legal details flowing through workflows, member identities beyond the already-public team list | **Private — and not in GitHub at all if avoidable** |

The boundary isn't always obvious. When in doubt, ask:

- **Could a competitor or adversary use this to harm a Foundation member or
  partner?** If yes, private.
- **Could an external adopter use this to set up their own ZP-governed
  workspace?** If yes, public.
- **Does this belong to the Foundation's *story* or the Foundation's
  *operations*?** Story is public; operations are private.

## Repo structure for `github.com/zeropoint-foundation/`

| Repo | Content | Visibility |
|------|---------|-----------|
| `zeropoint` | The substrate. Source of truth for every public artifact. | **Public** |
| `ironclaw` | Fork of `nearai/ironclaw` with ZP integration commits applied. | **Public** |
| `zp-ironclaw` | Bridge crate (interface code only — no operational state). | **Public** |
| `foundation-stack` *(new)* | Reference deployment: setup scripts, configuration templates, runbooks, architecture diagrams showing how the Foundation runs the stack, with all secrets templated out. | **Public** |
| `foundation-workspace` *(if needed)* | Operational state across members. Real configs, audit-DB snapshots, shared delegations, member-specific tenancy files. | **Private — preferably not on GitHub at all** |

The Foundation's actual *runtime state* lives on member machines, not in any
repo:

- `~/ZeroPoint/` (audit DB, vault, session, keys) — local-only per member
- `~/.ironclaw/` (IronClaw runtime DB, MCP server connections, channels) —
  local-only per member
- Shared operational state (cross-member delegations, fleet registry data) —
  if it must be shared, lives on Foundation-only infrastructure (private S3,
  internal git, `foundation-workspace` private repo); never public.

## Discipline

The separation only holds if it's *enforced*, not just *aspirational*. Three
mechanisms:

**(1) `.gitignore` patterns at every public repo.** ZP tenancy files,
session.json, vault contents, audit DBs — all gitignored from any repo that
might be made public. Already established (Ken's commit `b4e42b4a chore:
gitignore ZP tenancy files and macOS metadata` is the pattern).

**(2) Pre-commit / pre-push checks.** Before any commit lands on a public
branch, scan for operational-state markers. Patterns to forbid:

- Hardcoded bearer/session tokens (regex: long hex strings near `Bearer`,
  `token`, `auth` keywords)
- API keys (regex: provider-specific patterns — `sk-...`, `xoxp-...`, etc.)
- Real email addresses or phone numbers beyond the already-public Foundation
  team identifiers
- BLAKE3 hashes that match audit chain entries (would imply a chain leak)
- File paths under `~/ZeroPoint/`, `~/.ironclaw/`, or other operational
  directories committed by accident

**(3) A discipline pin in `zp-discipline`.**
Candidate name: `no_operational_state_in_public_repo`. Same shape as the
existing pins — regex-based scan over public-eligible files. Fires
during pre-push hook. Runs in CI on the Foundation's public repos.

**(4) Periodic review.** Once a quarter, audit what's been published since
the last review. Operational drift is normal and addressable; the discipline
is in *catching* it, not in being perfect on every commit.

## Onboarding implications

**For new Foundation members:**

- Day-1 setup: clone `zeropoint`, clone `ironclaw`, clone `foundation-stack`
  (all public). Run `foundation-stack/scripts/onboard.sh` (or equivalent).
- This produces their own `~/ZeroPoint/` directory with their own Genesis key,
  their own audit chain, their own session token. None of this gets pushed.
- They're added to the Foundation's shared delegation registry (lives in
  `foundation-workspace` private repo or Foundation-only infra), which gives
  them scoped capabilities to act on Foundation behalf.
- They can contribute to public repos like any open-source project.

**For external adopters:**

- They clone the same public repos.
- They run `foundation-stack/scripts/onboard.sh` *with their own
  configuration overrides*.
- They produce their own private operational state on their own infra.
- They never need access to the Foundation's `foundation-workspace` —
  the public material is sufficient to bootstrap a working ZP-governed
  workspace.

This is the **payoff** of the separation: the same public reference
implementation serves both Foundation members and external adopters. The
adoption story is "follow the docs the Foundation publishes; you'll end
up with the same architecture they use."

## Generalizing the pattern as a ZP product

The public/private separation isn't just internal hygiene — it's *the
deployment pattern* ZP recommends to everyone who adopts it. Every
ZP-governed workspace has the same shape:

- Public reference (could be the Foundation's, could be the adopter's own
  reference fork)
- Private operational state (always per-org)
- Per-member local runtime state

When ZP gets formally productized (post-V.5 trust portability,
post-`zp-mcp` adoption, etc.), the docs and bootstrapping tools should
make this separation the default. New users shouldn't have to invent the
pattern; they should inherit it from the Foundation's reference.

## Status and next steps

- This doc establishes the principle. Adoption is incremental.
- Immediate consequence: `ironclaw` fork at `zeropoint-foundation/ironclaw`
  is **public** (no operational state in the 7 ZP integration commits;
  reference-implementation grade content). `zp-daily-driver` branch pushes
  there.
- Next-week consequence: `foundation-stack` repo gets created, holds the
  setup scripts and runbooks new Foundation members follow.
- Eventual consequence: `no_operational_state_in_public_repo` discipline
  pin lands; CI enforces it.

## Open questions

- **Does each Foundation member need a personal fork, or is one Foundation
  fork sufficient?** Probably one Foundation fork — members make PRs the
  same way they would to any team-owned open-source repo. Personal forks
  would multiply the surface area for accidental operational-state leaks.
- **What's the right home for cross-member shared operational state**
  (e.g. shared delegations, fleet registry)? Private repo, internal infra,
  or each member holds their own copy and synchronizes via mesh? V.5 trust
  portability is the structural answer eventually; in the interim, a
  private repo is pragmatic.
- **How do we handle the gradient between "obviously public" (substrate
  code) and "obviously private" (audit chain) for borderline material**
  (e.g. a configuration file that's templated but contains an organization
  name)? The discipline pin needs a small allowlist for known-public
  identifiers. Tractable but worth surfacing during pin design.
