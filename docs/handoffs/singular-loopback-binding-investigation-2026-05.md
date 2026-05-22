# Handoff — Singular loopback binding (structural sweep)

*2026-05-21. Target: terminal Claude working in `~/projects/zeropoint`,
with a coordinated follow-up CLIC at `~/projects/ironclaw` for the
client-side portion. Opus tier for the design pass; Sonnet for the
execution phases that follow. Today's two-site fix already landed
(Phase 0); this brief turns those localized patches into a structural
guarantee that the trap cannot reappear elsewhere in the substrate.*

## Why this exists

The localhost dual-stack trap surfaced on 2026-05-21 when IronClaw's
`chain_render` tool failed for days with "ZP gate unreachable: zp
transport: error sending request" — even though `zp serve` was
listening on port 17010 and responding correctly to `curl` from the
same host. The cause: ZP bound IPv4 only (`127.0.0.1`), macOS's
resolver returns `::1` first for `localhost`, IronClaw's HTTP client
doesn't do RFC 6555 happy-eyeballs fallback, so it tried `::1`, got
connection-refused, and surfaced the failure without trying
`127.0.0.1`.

We patched the two ZP bind sites (HTTP at `zp-server/src/lib.rs:1423`,
gRPC at the same file `1474`) to also bind `[::1]:<port>` when in
loopback mode. That unblocks today's symptom. But it does NOT prevent:

1. **The next bind site** added anywhere in the substrate from
   repeating the trap (no enforcement against direct
   `TcpListener::bind("127.0.0.1:N")` calls)
2. **The next client** opening `http://localhost:<port>` to reach
   a peer service from getting tripped by IPv6-first resolution
3. **Future tools and providers** launched by `tool_proxy` and
   `launch_inference` from inheriting the same trap
4. **The PortRegistry** from being incomplete — its receipts
   record one stack when reality may have both
5. **Cross-listener graceful shutdown** from being incoherent — we
   now have four listeners (HTTP v4, HTTP v6, gRPC v4, gRPC v6)
   with two different shutdown stories

Without structural coherence here, every future operator interaction
that crosses the loopback boundary risks a silent class-of-bug
failure that surfaces only after days of unexplained friction. The
substrate's promise of "trust is infrastructure" requires the
infrastructure to be coherent at this layer, not patched site by
site.

This is Principle 8 (one canonical path per substrate concern)
applied to loopback networking. Same shape as Singular Sovereign
Root (CLAUDE.md heuristic): one canonical binding pattern,
everything derives from it. The friction we just discovered IS the
architecture asking for the structural fix.

## Phases

### Phase 0 — landed 2026-05-21

Two-site fix in `crates/zp-server/src/lib.rs`:
- HTTP listener: binds both `127.0.0.1:<port>` and `[::1]:<port>` in
  loopback mode
- gRPC listener: same pattern, both `<grpc_bind>:<port+1>` and
  `[::1]:<port+1>`
- IPv6 bind failure is logged-and-continue, not fatal

Status: shipped. IronClaw `chain_render` now reaches the gate.
This phase does not block on the structural work below; it stands
alone as a tactical fix that any further structural work composes
on top of.

### Phase 1 — `zp_net::bind_loopback` helper (canonical bind path)

**Goal:** every loopback bind in the substrate routes through one
function. Direct `TcpListener::bind` calls with string addresses
become a discipline-pin violation.

**Shape:**

New module (or new crate `zp-net`) exposing:

```rust
/// Bind a TCP listener on both IPv4 and IPv6 loopback at the given
/// port. Returns both listeners when both succeed; returns a single
/// IPv4 listener with a logged warning when IPv6 is unavailable.
/// Never returns IPv6-only — IPv4 is the required minimum.
pub async fn bind_loopback(
    port: u16,
) -> anyhow::Result<DualStackListener>;

pub struct DualStackListener {
    pub v4: tokio::net::TcpListener,
    pub v6: Option<tokio::net::TcpListener>,
}

/// Bind for non-loopback (network-facing) deployment. Single
/// listener at the explicit address. Emits the existing network-
/// facing warning. Use this for `bind_addr=0.0.0.0` or public IPs.
pub async fn bind_network(
    addr: &str,
    port: u16,
) -> anyhow::Result<tokio::net::TcpListener>;
```

Migrate today's two sites to use the helper. Refactor any other
`TcpListener::bind` call in the workspace to route through it.

**Discipline pin:** add a check to the pre-commit hook (or a
dedicated CI rule) that greps for `TcpListener::bind\(` outside of
`zp-net/src/lib.rs` and fails the commit if found. Equivalent
pattern for tonic: `tonic::transport::Server::builder().*\.serve\(`
outside the same module.

Tonic doesn't expose pre-bound listeners cleanly; the helper may
need a tonic-specific cousin (`serve_loopback_grpc`) that builds
two server tasks behind the dual-stack abstraction. Resolve during
design.

### Phase 2 — Peer-service URL builder (canonical client path)

**Goal:** every substrate client that connects to a peer service
routes through one URL builder that picks a stack the peer is
guaranteed to be on. No more raw `http://localhost:<port>` strings
in client code.

**Shape:**

```rust
/// Build a URL for a substrate peer service. Always returns an
/// IPv4 explicit URL (http://127.0.0.1:<port>/...) — the substrate's
/// canonical loopback stack for client-to-peer-service calls.
/// Servers are guaranteed dual-stack via Phase 1, so IPv4 is always
/// reachable and avoids resolver-order surprises.
pub fn peer_url(port: u16, path: &str) -> String;

/// Same shape for gRPC clients — returns the IPv4 explicit URI.
pub fn peer_grpc_uri(port: u16) -> http::Uri;
```

Migrate all substrate clients (anywhere ZP or its tools connect to
a peer ZP-service URL) to use the builder. The cognition-governance
hook config, the chain_render tool config, anything in
`tool_proxy.rs` that constructs peer URLs.

**Discipline pin:** grep for `http://localhost` and `http://127.0.0.1`
in `crates/` and `tools-src/`; any hit outside the URL builder
module fails the commit.

**IronClaw is separate scope** — see Phase 5.

### Phase 3 — Cross-listener graceful shutdown

**Goal:** all four listeners (HTTP v4, HTTP v6, gRPC v4, gRPC v6 — and
any future ones from Phase 1's helper) shut down coherently on
`SIGINT`/`SIGTERM` rather than HTTP v4 draining gracefully while the
others die abruptly with the process.

**Shape:**

Replace the current `shutdown` async block (which can only be
awaited once) with a `tokio_util::sync::CancellationToken` or
`tokio::sync::broadcast` channel pattern:

```rust
let shutdown = CancellationToken::new();
let signal_shutdown = shutdown.clone();
tokio::spawn(async move {
    tokio::signal::ctrl_c().await.ok();
    info!("Shutdown signal received — stopping launched tools...");
    // ... existing PID cleanup ...
    signal_shutdown.cancel();
});

// Each listener task watches the same token:
axum::serve(listener, app)
    .with_graceful_shutdown(shutdown.cancelled_owned())
    .await?;
```

Confirm whether `tokio_util` is already a dependency (likely yes via
tonic). If not, accept the small dependency add.

### Phase 4 — PortRegistry stack-awareness

**Goal:** chain-anchored port allocation receipts record which
stacks are bound (`["ipv4", "ipv6"]`), not just the port number.
This makes the chain the canonical answer to "what's listening
where" — Principle 8 applied to port state.

**Shape:**

Receipt schema extension — `port:allocated` receipts gain a
`bound_stacks: ["ipv4", "ipv6"]` field. Backfill is not required;
new receipts carry the field, old receipts continue to validate.
The canonical port-state resolver (whatever reads PortRegistry to
answer "is port N in use") returns both the port AND its stacks.

This composes with the canonicalization receipt pattern (Principle
1: signing is gravity). The receipt structurally encodes what's
true at allocation time, and validators can later verify the bind
actually matches the receipt.

### Phase 5 — IronClaw side (separate repo, coordinated)

**Goal:** IronClaw stops being the substrate's IPv6-resolution
failure point. Either implements RFC 6555 happy-eyeballs in its
HTTP client, or uses an explicit IPv4 peer URL via a builder that
mirrors Phase 2 on the IronClaw side.

**Decision needed:** which one?

- **Happy-eyeballs** — IronClaw's HTTP client becomes RFC 6555
  compliant. Correct at the protocol layer. More invasive change.
  Composes well if IronClaw ever talks to other dual-stack peers
  beyond ZP.
- **IPv4 explicit via builder** — IronClaw mirrors ZP's Phase 2:
  every peer URL routes through a builder that returns
  `http://127.0.0.1:<port>`. Smaller change. Relies on ZP's
  Phase 1 dual-stack guarantee to always make IPv4 reachable.

Recommendation: **IPv4 explicit via builder** for IronClaw v1, with
happy-eyeballs as a v2 substrate-wide upgrade. The builder pattern
is consistent with ZP's Phase 2 and gets us coherence faster.
Happy-eyeballs is the right long-term answer but is independent
work that can land later without blocking the structural sweep.

This phase is a separate CLIC dispatched from `~/projects/ironclaw`
after Phases 1-4 land in ZP.

## Investigation surface

```sh
# All TcpListener bind sites in zeropoint (should converge to one
# after Phase 1)
grep -rn "TcpListener::bind\|::bind(" \
   ~/projects/zeropoint/crates 2>/dev/null

# All tonic Server::builder + .serve sites (gRPC binds)
grep -rn "Server::builder" \
   ~/projects/zeropoint/crates 2>/dev/null

# All "localhost" or "127.0.0.1" string usages in substrate code —
# Phase 2 audit
grep -rn "localhost:\|127\.0\.0\.1:" \
   ~/projects/zeropoint/crates 2>/dev/null \
   | grep -v "//" | grep -v "test"

# All peer URL construction in tools and providers
grep -rn "http://localhost\|http://127\." \
   ~/projects/zeropoint/crates \
   ~/projects/zeropoint/tools 2>/dev/null

# tokio_util dependency check for Phase 3
grep -rn "tokio_util\|tokio-util" \
   ~/projects/zeropoint/Cargo.toml \
   ~/projects/zeropoint/crates/*/Cargo.toml 2>/dev/null

# PortRegistry definition and receipt schema (Phase 4)
grep -rn "PortRegistry\|port_registry\|port:allocated" \
   ~/projects/zeropoint/crates 2>/dev/null

# IronClaw cognition-governance hook config (Phase 5)
grep -rn "localhost:17010\|gate.*url\|cognition.*governance" \
   ~/projects/ironclaw 2>/dev/null
```

Confirm during design:

- Whether `zp-net` should be a new crate or a module in an existing
  crate (likely module in `zp-config` or `zp-server`; new crate
  only if other crates need to depend on it independently)
- Whether tonic's `serve_with_incoming` can take pre-bound listeners
  cleanly, or whether the gRPC helper needs a different shape
- The current PortRegistry receipt schema — what fields exist, where
  is the canonical definition, what's the migration impact of adding
  `bound_stacks`
- Whether the substrate has ad-hoc tool processes (launched by
  `tool_proxy`/`launch_inference`) that bind their own ports outside
  ZP's main listener — those need to route through `bind_loopback`
  too if so

## Deliverable

Per phase:

**Phase 1:** One commit. `zp-net::bind_loopback` introduced; two
existing ZP sites migrated; discipline pin / grep check added to
pre-commit hook.

**Phase 2:** One commit. `peer_url` and `peer_grpc_uri` helpers
introduced; all substrate clients migrated; discipline pin added.

**Phase 3:** One commit. CancellationToken pattern replaces the
single-shot shutdown closure; all four listeners share the same
token; existing PID-cleanup logic preserved.

**Phase 4:** One commit. PortRegistry receipt schema extended with
`bound_stacks`; receipt emission updated; new validator (optional)
that checks the bind matches the receipt at startup.

**Phase 5:** Separate brief and commit in `~/projects/ironclaw`.
Either happy-eyeballs HTTP client or peer-URL builder mirroring
Phase 2. Decision needed before that brief is written.

Run the pre-commit safety script before each push.

## Acceptance criteria

After all phases land:

1. **Zero direct `TcpListener::bind` calls** anywhere in
   `crates/` outside the `zp-net` helper module. The discipline pin
   enforces this.
2. **Zero hardcoded `http://localhost:` or `http://127.0.0.1:`
   strings** in substrate client code outside the peer-URL builder.
   The discipline pin enforces this.
3. **All four listeners (HTTP v4/v6, gRPC v4/v6) drain gracefully**
   on `SIGINT` — observable as orderly log messages from each,
   followed by clean process exit, in the test harness.
4. **PortRegistry receipts include `bound_stacks`** — visible in
   the chain via `zp chain show port:allocated`. Old receipts
   continue to validate; new ones carry the field.
5. **IronClaw `chain_render` works on first attempt** after a
   clean ZP restart, without falling back through a transport
   error retry cycle. (This is the original symptom; Phase 0
   already fixes it; Phase 5 makes the fix architectural.)
6. **The localhost trap cannot reappear by construction.** A new
   bind site or peer URL added in a future commit will fail the
   discipline pin if it bypasses the helpers. Drift is structurally
   prevented, not just discovered post-hoc.

## Composition with existing principles and plans

- **Principle 8 (one canonical path)** — this brief is Principle 8
  applied to loopback networking. One bind helper, one URL builder,
  one shutdown coordinator. The discipline pins make "canonical" a
  structural guarantee, not a convention.
- **Singular Sovereign Root** (CLAUDE.md heuristic) — same shape on
  a different concern. Loopback binding is the sovereign root for
  intra-substrate connectivity; everything derives from
  `bind_loopback` and `peer_url`. The heuristic predicts that any
  other place we run N redundant patterns for one concern is
  architectural drift waiting to bite.
- **Principle 4 (every bit counts)** — eliminating four redundant
  ways to bind a port (direct TcpListener, tonic builder, future
  tool bind, future provider bind) collapses to one.
- **Operator-surface hygiene principle** — when an operator runs
  `lsof -iTCP -sTCP:LISTEN`, they should see one ZP-managed port
  per service with the substrate knowing both stacks are bound.
  Phase 4's PortRegistry stack-awareness directly contributes to
  this legibility.
- **The lsof test** (CLAUDE.md heuristic) — substrate maturity is
  when the host's listening process inventory traces back to chain
  state. Stack-aware PortRegistry receipts close part of that gap.
- **The friction-is-the-finding heuristic** — the IronClaw 3-day
  chain_render failure was the substrate asking for this work.
  Patching the two ZP bind sites without doing the structural sweep
  would leave the same trap latent elsewhere.

## Refs

- 2026-05-21 IronClaw `chain_render` gate-unreachable diagnosis
  (this session — the diagnostic that surfaced the trap)
- Phase 0 commit (HTTP + gRPC dual-stack in `zp-server/src/lib.rs`)
- `docs/ARCHITECTURE-2026-04.md` Principle 8
- `~/projects/zeropoint/CLAUDE.md` — Singular Sovereign Root,
  config-reflects-today, the lsof test, friction-is-the-finding
- `crates/zp-server/src/lib.rs:1423` and `:1474` — Phase 0 patch
  sites; the canonical places to migrate to `bind_loopback`
- `crates/zp-server/src/tool_ports.rs` — likely contains the
  PortRegistry; confirm during investigation
- `~/projects/ironclaw/` — Phase 5 target, separate repo, separate
  CLIC

---

*The dual-stack fix we just landed unblocks today. The structural
sweep makes the same trap impossible to reintroduce tomorrow.
Without complete coherence here, the substrate keeps producing
this class of bug under different names; with it, the question is
answered once and stays answered.*
