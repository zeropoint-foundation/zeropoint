# Handoff Brief: L3 Floor Completion

*Session brief for the terminal Claude that will land tasks #116, #90,
#92, #97. Anchored in `docs/OBSERVABILITY-2026-05.md` and `docs/RESTORE-2026-05.md`.
Use this as the entry point — the principles in those docs are the
*why*, this brief is the *what* and the *where*.*

## Read first

1. **`docs/OBSERVABILITY-2026-05.md`** — the six legibility principles.
   #90 and #92 implement principles #2 and #4 respectively.
2. **`docs/RESTORE-2026-05.md`** — the restore procedure that #97
   validates by running.
3. **The previous handoff:** `docs/HANDOFF-2026-05-observability-patches.md`
   — context for what `observability-2026-05` branch already landed.
   The patches in this brief continue that arc.

## Context

L3 "load-bearing-honest" hardening pass (#91) is mostly shipped:
Cloudflare infrastructure, IronClaw OIDC, observability primitives,
backup script + restore doc, identity design. Four tasks remain to
declare L3 structurally complete — small in code, large in operator
confidence:

- **#116** — IronClaw: skip `GATEWAY_AUTH_TOKEN` auto-gen when OIDC
  is configured. Closes the bearer-token-coexistence wart.
- **#90** — zp-cli: unify `--data-dir` resolution across writers; add
  navigable error when canonical path exists nearby.
- **#92** — Automated tests for degrade-closed behavior. Validates
  #91 claims with test infrastructure, not just empirical luck.
- **#97** — Run the restore drill on a clean tmpdir (or ARTEMIS).
  Prove backup actually restores. Update RESTORE-2026-05.md with drill
  results.

Land all four on a single branch `l3-floor-2026-05` (one in each
repo as needed). PR per repo. Each task its own commit, with the
hygiene convention from the previous handoff: each commit references
the principle and task ID in the body.

## Execution order

Order matters: #116 first (smallest, fixes today's UX wart);
#90 second (daily papercut, unblocks every subsequent run);
#92 third (validates work already done);
#97 last (procedural, runs against the previous three).

### 1. #116 — IronClaw: skip GATEWAY_AUTH_TOKEN auto-gen when OIDC active

**Principle anchor:** #4 (convergent paths, convergent observability) from
OBSERVABILITY-2026-05.md. The auth ladder's bearer-first ordering means OIDC
silently never runs when a bearer token exists — even when OIDC is the
configured primary auth path. Two paths that "do the same thing"
(authenticate a request) currently produce divergent results depending on
whether a localStorage cache holds the auto-generated bearer.

**Code locations:**
- `~/projects/ironclaw/src/main.rs` around line 1015: the
  `upsert_bootstrap_var("GATEWAY_AUTH_TOKEN", &token_to_persist)`
  call that unconditionally persists the auto-generated token to
  `~/.ironclaw/.env` on every boot.
- `~/projects/ironclaw/src/config/channels.rs` around line 299: the
  `auth_token` resolution that drives the bearer-token middleware.
- `~/projects/ironclaw/src/channels/web/platform/auth.rs` around
  the `auth_middleware` ladder (Bearer → DB-token → OIDC → 401).

**Proposed fix:** In `main.rs` before the auto-gen step, check whether
OIDC is enabled (look at `config.gateway.oidc.is_some()` or
equivalent from the resolved `GatewayConfig`). If yes:
- Skip the auto-generation step entirely.
- Skip the `upsert_bootstrap_var` call.
- Emit `tracing::info!("Bearer token disabled: OIDC enabled as primary auth")` — visible in the log file now that #117 landed.
- Auth ladder still works because Bearer check finds no token,
  falls through to DB-token (none), falls through to OIDC (configured), enforces correctly.

When OIDC is *not* configured, preserve the existing auto-gen
behavior — that's the standalone-developer case and we don't want to
break it. Strict guard: only disable bearer when OIDC is fully
configured (jwks_url, issuer, audience all present and non-empty).

**Optional SPA-side complement:** The index page's "Paste your
token" form checks localStorage for a bearer token. Ideally it
*also* checks `/api/auth/mode` (new endpoint returning
`{"mode": "oidc"}`) and skips the form when OIDC is active. If
that's a larger SPA refactor, skip it — file as follow-up #116b
and let the workaround (clear localStorage in onboarding doc) stand.

**Acceptance test:**

```sh
# Remove GATEWAY_AUTH_TOKEN from ~/.ironclaw/.env (commented + uncommented forms)
sed -i.bak '/^#*GATEWAY_AUTH_TOKEN/d' ~/.ironclaw/.env

# Launch IronClaw with OIDC env active
GATEWAY_OIDC_ENABLED=true \
GATEWAY_OIDC_JWKS_URL=https://zp-foundation-team.cloudflareaccess.com/cdn-cgi/access/certs \
GATEWAY_OIDC_HEADER=cf-access-jwt-assertion \
GATEWAY_OIDC_ISSUER=https://zp-foundation-team.cloudflareaccess.com \
GATEWAY_OIDC_AUDIENCE=26abcb60de0562e82e5417b346e0d6ee1d7c0a157a13a38a832dc86b6926c478 \
~/projects/ironclaw/target/release/ironclaw run &

# Expect: ~/.ironclaw/.env does NOT have GATEWAY_AUTH_TOKEN added back
sleep 5
grep '^GATEWAY_AUTH_TOKEN' ~/.ironclaw/.env  # should print nothing

# Boot log should contain "Bearer token disabled: OIDC enabled as primary auth"
grep -F 'Bearer token disabled' ~/.ironclaw/logs/ironclaw-*.log
```

---

### 2. #90 — zp-cli: unified data-dir resolution + navigable error

**Principle anchor:** #2 (errors must be navigable) and #4 (convergent
paths) from OBSERVABILITY-2026-05.md. The current `--data-dir` default
of `./data/zeropoint` is cwd-relative, which is a divergence from `zp
doctor`'s canonical-path resolution. Two code paths that "open the
audit chain" produce different results depending on where the operator
ran the command from.

**Code locations:**
- `~/projects/zeropoint/crates/zp-cli/src/emit.rs` — `--data-dir`
  default `./data/zeropoint`
- `~/projects/zeropoint/crates/zp-cli/src/run.rs` — same default
- Likely other subcommands with the same default; search:
  `grep -rn 'default.*data.*zeropoint' ~/projects/zeropoint/crates/zp-cli`
- `~/projects/zeropoint/crates/zp-config/src/` — the path resolution
  logic that `zp doctor` already uses correctly via
  `ConfigResolver::resolve_standard()`.

**Proposed fix:** Establish a single `resolve_data_dir()` helper in
zp-config (or zp-cli, wherever the shared resolution belongs) with
this priority order:

1. `--data-dir` flag if explicitly passed (operator override)
2. `ZP_DATA_DIR` env var if set
3. `data.dir` key in `~/ZeroPoint/config.toml` (or `$ZP_HOME/config.toml`)
4. `$ZP_HOME/data` (XDG-style)
5. `~/ZeroPoint/data` (canonical default)
6. Error with navigable message — see below

Replace per-subcommand `--data-dir` defaults with calls to this
helper. The flag remains, but its *default* is no longer
cwd-relative.

**Navigable error implementation:** When `resolve_data_dir()` cannot
find an existing audit DB at the resolved path, the error message
must include:
- The path that was tried (with which resolution rule produced it)
- The next-most-likely existing path if any nearby (e.g., scan
  `~/ZeroPoint/data/`, `~/.zp/data/`, `./data/zeropoint/`)
- A concrete fix (set env var, edit config.toml, or pass --data-dir)

Example:

```
✗ Cannot open audit store at ./data/zeropoint/audit.db
  Resolved via: cwd-relative default (no --data-dir, no ZP_DATA_DIR, no config.toml [data].dir)
  Nearby paths that exist:
    ~/ZeroPoint/data/audit.db (matches canonical default)
  Fix:
    - Pass: zp <cmd> --data-dir ~/ZeroPoint/data
    - Set:  export ZP_DATA_DIR=~/ZeroPoint/data
    - Edit: ~/ZeroPoint/config.toml → [data] dir = "~/ZeroPoint/data"
```

This is the principle #2 model literally applied — what was tried,
what was found, what to do.

**Acceptance test:**

```sh
# From a non-canonical cwd
cd /tmp
zp emit zp-data-dir-test --meta source=acceptance 2>&1

# Should either succeed (resolved to canonical via priority chain)
# OR fail with the navigable error above. NOT the cryptic "Failed to open audit store"

cd /tmp && ZP_DATA_DIR=~/ZeroPoint/data zp emit zp-data-dir-test
# Should succeed

cd /tmp && zp --data-dir ~/ZeroPoint/data emit zp-data-dir-test
# Should succeed
```

Update `~/ZeroPoint/config.toml` `[data]` section with a `dir` key so
the resolution chain has a config-file rung to test. Document the
priority order in zp-cli's help text.

---

### 3. #92 — Automated tests for degrade-closed behavior

**Principle anchor:** Validates claim #1 from ARCHITECTURE-2026-04.md
Part I §2 (audit chain integrity) and the substrate's degrade-closed
guarantee. Tonight's session validated this empirically (zp run
refused to launch when audit chain was held by zp serve). The test
suite needs to make the validation structural so future changes
can't quietly degrade-open.

**Scope:** Add integration tests covering the following degrade-
closed conditions. Each should set up the failure mode in a tmpdir,
attempt the operation, and assert the operation refuses.

1. **Audit chain unreachable** — corrupt the audit.db file (or
   point at a non-existent path); attempt `zp run <tool>`; assert
   refusal with a navigable error message.

2. **Audit chain integrity broken** — modify a row in the audit_entries
   table after the signing pass; attempt `zp doctor` and `zp run`;
   assert both detect tamper (signature mismatch) and refuse.

3. **Genesis secret unavailable** — point ZP at a fresh `~/ZeroPoint`
   with no `keys/` directory; attempt `zp run`; assert refusal.

4. **Manifest hash mismatch** — configure a tool, then modify
   `.zp-configure.toml`; attempt `zp run <tool>` without
   `--refresh`; assert refusal with the existing hash-mismatch error.

5. **Vault locked** (if applicable to current vault model) — make
   the vault unreadable; attempt `zp run` for a tool that requires
   vault secrets; assert refusal.

**Code location:** `~/projects/zeropoint/crates/zp-audit/tests/` for
chain-related tests, `~/projects/zeropoint/crates/zp-cli/tests/` for
launch-related tests, or a new `~/projects/zeropoint/crates/zp-tests/`
integration crate if the surface warrants it.

**Use existing test infrastructure:** the workspace already has
SQLite-based test helpers (per #15 tests in zp-audit) and tmpdir
patterns. Don't invent new infrastructure unless gaps surface.

**Acceptance test:**

```sh
cd ~/projects/zeropoint
cargo test --workspace degrade_closed
# Expect: 5+ tests pass, each named obviously (e.g., test_degrade_closed_audit_chain_unreachable)
```

---

### 4. #97 — Run the L3 restore drill

**Principle anchor:** No principle violation; this validates the
backup/restore claim from L3 hardening. RESTORE-2026-05.md
documents the procedure. The drill *runs* it.

**Procedure:** Per RESTORE-2026-05.md §"Restore drill":

1. Take a fresh backup of `~/ZeroPoint/` via `scripts/zp-backup.sh`.
2. In a clean tmpdir (or on ARTEMIS), set `ZP_HOME` to the tmpdir
   and run the restore procedure step-by-step.
3. Verify integrity at each step: hash check, schema match, file
   permissions, audit-chain readability.
4. Run `zp doctor` from the restored state. Expect ✓ on all checks.
5. Run a smoke `zp emit zp-restore-drill-test --meta context=acceptance`.
   Expect a new receipt appended to the restored chain.

**Update RESTORE-2026-05.md** at end of drill with:
- Date drill was run
- What machine / environment
- Total wall-clock time
- Any procedural gaps discovered (and fixes)
- "Drill passed" assertion

**Acceptance test:** The drill itself is the test. Successful drill
plus updated doc = task complete. If drill fails, the failure
reveals procedural gaps in RESTORE-2026-05.md — fix the procedure,
re-run, document.

If running on ARTEMIS isn't accessible to terminal Claude, run in a
clean tmpdir on APOLLO with `ZP_HOME=/tmp/zp-restore-drill-$$`. The
tmpdir variant covers the same procedural ground.

---

## Cross-cutting concerns

### Branch strategy

Single branch `l3-floor-2026-05` per repo:

- `zeropoint` repo: branch off `main`, four commits (#116 NA — that's
  ironclaw; #90, #92, #97). Push, PR.
- `ironclaw` repo: branch `l3-floor-2026-05` off `zp-daily-driver`,
  one commit (#116). Push, PR.

Coordinate with whatever is on `observability-2026-05` if it hasn't
merged yet — these are independent branches and shouldn't conflict.

### Commit message convention

Each commit:
- One-line subject naming the task ID and the operation
- Body referencing the principle from OBSERVABILITY-2026-05.md and
  the relevant doc(s)
- Body includes the acceptance-test command(s)

Example:

    zp-cli: unified data-dir resolution with navigable error (#90)

    Replaces the cwd-relative `--data-dir` default with a priority chain:
    --data-dir flag > ZP_DATA_DIR env > config.toml [data].dir > canonical.

    Resolves convergent-path divergence between `zp doctor` (canonical)
    and writers like `zp emit` / `zp run` (cwd-relative). Implements
    principles #2 and #4 from OBSERVABILITY-2026-05.md.

    Acceptance:
      cd /tmp && zp emit test --meta x=y    # succeeds via canonical resolution
      cd /tmp && zp emit test               # fails with navigable error

### Documentation updates after landing

1. `docs/OBSERVABILITY-2026-05.md` — mark principles #2 and #4 as
   "structurally enforced" with #90's commit hash, when applicable.
2. `docs/FOUNDATION-ONBOARDING-2026-05.md` — remove the "shell alias
   workaround" / `--data-dir` mention from member-facing diagnostic
   affordances; the bug is fixed.
3. `docs/RESTORE-2026-05.md` — add the drill-result section
   produced by #97.

### Discipline pin candidates after #92 lands

Once degrade-closed tests exist, consider a pin (in
`crates/zp-discipline/`) that requires every new gated operation to
have a degrade-closed test. Companion to the existing pins.
Pin candidate not required to ship with this batch — flag for
follow-up.

## What to leave alone

- The `observability-2026-05` branches in both repos. Already merged
  or merging; don't conflict.
- `docs/IDENTITY-2026-05.md` and its task #120 — separate workstream,
  not in this scope.
- The compositional-defense tasks #124-128 — long-term work, separate
  brief when started.
- IronClaw's TUI / channels / model layers — out of scope. Only
  touch what #116 requires (main.rs auto-gen path).

## What you'll need from the operator

- Confirmation that `observability-2026-05` is fully merged in both
  repos (or rebase strategy if not).
- Whether to push feature branches and stop (operator cuts PRs), or
  push + auto-open PRs via gh CLI.
- For #97: which target machine — APOLLO tmpdir, or ARTEMIS if
  remote access is wired up.

## Stop conditions

If any of these surface, stop and report:

- Degrade-closed test reveals a *real* degrade-open behavior that
  wasn't tonight's case. That's not a test bug, that's a regression.
  Stop, document, don't paper over.
- #90's resolution chain reveals a path that the substrate currently
  reads from but isn't in the priority order — surface it before
  shipping, may need an additional rung.
- #116's OIDC-enabled-check finds the boolean isn't actually
  reachable in the gateway-init path (terminal Claude's choice of
  where the check goes matters; if there's no clean site, stop and
  ask).
- #97 drill fails. Don't update RESTORE-2026-05.md as "drill
  passed" if it didn't. Document the failure mode and fix the
  procedure.

## Final note

L3 floor completion is the last step before Foundation team
onboarding can proceed confidently. These four tasks are small in
code but large in operator confidence — they convert "we tested
this manually tonight" into "the substrate enforces this
structurally." Treat them with that weight.

When all four land, #91 (L3 hardening pass) can be marked completed
and #99/#100 (multi-tenant config + member ceremony) become the
next-up workstream toward L4 outreach.
