# ZeroPoint Structural Audit — May 2026

**Document type:** Companion to `ARCHITECTURE-2026-04.md` (the operating spec). This document maps the structural deficiencies of the substrate as of May 2026 — the places where intent is documented in prose but not enforced in code, and the architectural commitments (the *wires*) that would close each one.

**Author:** Ken Romero, with synthesis assistance from Claude.
**Date:** 2026-05-06.
**Status:** Active. Conditioned on Phase 1 + Phase 2 closure (signing, gate parser, ciphertext nonce, file mode, keychain namespace). The remaining seams are the May 2026 work surface.

**Companion documents:**
- `docs/ARCHITECTURE-2026-04.md` — the operating spec (four claims, seven principles, three layers, the catalog vocabulary).
- `security/pentest-2026-04-06/INVARIANT-CATALOG-v0.md` — the grammar (M1–M10, P1–P5, X1–X2).
- `security/pentest-2026-04-06/REMEDIATION-NOTES.md` — the tactical workshop notes.
- `docs/audit-invariant.md` — the audit chain's invariant contract.

This document sits *under* the architecture record and *over* individual remediation patches. The architecture says what ZeroPoint is. This document says where the substrate is leaky and which seams are still missing wires. The patches say how each wire was wound.

---

## Part I — The Heuristic

### 1. Convention vs invariant

The pentest's central finding (per `ARCHITECTURE-2026-04.md` §5) was that gate coverage was **disciplinary, not structural**. The gate works *when consulted*; the failure was that some code paths didn't consult it. Translated to a single sentence:

> Conventions get violated. Invariants do not — because the type system or the runtime makes the violation impossible.

A *convention* is a rule developers must remember to follow. A *invariant* is a rule the code structure makes impossible to violate. Every place where a discipline lives in a comment ("callers must…", "this function assumes…", "always go through…") is a convention. Every place where the only path to the desired effect goes through a single function, a single middleware, or a typed handle, is an invariant.

The remediation work is largely the work of converting conventions to invariants.

### 2. The wire heuristic

Every piece of state in ZeroPoint should be threaded onto a structural discipline that constrains what it can be and what can act on it.

- A **bead** is a piece of state, an operation, a value, a decision.
- A **wire** is the structural discipline that constrains the bead's movement — the function, the middleware, the type, the schema dispatch.
- A **seam** is a place where intent should crystallize into a wire-bound bead but currently doesn't.

A bead without a wire drifts: every consumer chooses its own behavior, "the right thing" depends on each developer remembering, and fixes are local to each call site. A bead on a wire can only move along the wire: the wrong move is impossible to express. The architectural fix isn't fixing one bead at a time; it's identifying which wires are missing.

### 3. The carrier

For each seam, the wire takes the form of a **carrier** — the singular thing that owns enforcement. Some examples from Phase 1 closure:

- `AuditStore::append` is the carrier for "no unsigned non-genesis row reaches disk." Anyone wanting to add an entry must go through this function; it signs internally; there's no parallel path.
- `evaluate(parsed_command)` is the carrier for "every command sees the rule engine before classification." The fast-path safe-list is now downstream of rule evaluation, not upstream.
- `verify_strict` (when there's one helper) is the carrier for "no signature is malleable." Today this is *partially closed*: the call sites are swept but there's no single helper function — five independent invocations exist.

A wire without a carrier is an aspiration. Naming the carrier names the architectural commitment.

---

## Part II — The Seam Catalog

Each seam below has six fields:

- **Intent.** What MUST/SHOULD/NEVER be true, in modal vocabulary.
- **Carrier.** The singular thing that should own enforcement. May not exist yet.
- **Status.** `closed` (carrier exists, all paths route through it), `partial` (carrier exists or sweep done, but coverage is incomplete), `open` (no carrier yet).
- **Catalog rule.** Which M-rule, P-rule, or X-rule from `INVARIANT-CATALOG-v0.md` this seam serves.
- **Wire.** The structural commitment that closes the seam, in implementation terms.
- **Blast radius.** The files that need to change when the seam is closed.

### Seam 1 — Audit chain write path

- **Intent.** No non-genesis entry reaches storage unsigned.
- **Carrier.** `AuditStore::append` (in `crates/zp-audit/src/store.rs`).
- **Status.** **Closed** (Phase 1.B + 1.C). Production callers use `open_signed(path, signer)`; reads use `open_readonly`; tests use `open_unsigned` (cfg-gated). `append` signs internally via held `AuditSigner`. SQLite `BEFORE UPDATE`/`BEFORE DELETE` triggers reject row mutation at the storage layer.
- **Catalog rule.** P1 (Chain extension), M3 (hash-chain continuity), M4 (signature integrity).
- **Wire.** Three-constructor split (signed/readonly/unsigned), held signer, atomic append, storage-layer triggers.
- **Blast radius (when first closed).** `zp-core/audit.rs`, `zp-audit/{chain,store,signer,verifier}.rs`, `zp-keys/audit_signer.rs`, ~28 caller sites.

### Seam 2 — Gate evaluation

- **Intent.** Every command sees the rule engine before classification; structural patterns that span statement boundaries still match.
- **Carrier.** `guard::evaluate(command)` and `shell::parse(command)` (in `crates/zp-cli/src/{guard,shell}.rs`).
- **Status.** **Closed** (Phase 1.A/D). Parser splits at `;`/`&&`/`||`/`&`/newline; pipes are intra-statement. Rules-first per statement, safe-list as fallback. Structural pass also runs rules against the unsplit input so cross-statement patterns (fork bombs) match.
- **Catalog rule.** M1 (gate coverage), P3 (the gate).
- **Wire.** Parser front-end, per-statement rule evaluation, structural pass over original input.

### Seam 3 — Fleet/node identity authentication

- **Intent.** No endpoint that mutates `state.node_registry` accepts an unauthenticated request. Identity is derived from a key, never asserted by the client.
- **Carrier.** A new `fleet_sig_middleware` that verifies Ed25519 over `(node_id || policy_version || timestamp || nonce)` against a registered public key. Today there is no carrier.
- **Status.** **Open**. `/api/v1/fleet/heartbeat` is on the auth-bypass list (`crates/zp-server/src/auth.rs`); the handler trusts client-supplied `node_id` and `trust_tier`.
- **Catalog rule.** M1 (gate coverage extends to network-facing surfaces).
- **Wire.** `fleet_sig_middleware` middleware that verifies a sigblock and binds `node_id` to the verifying key as a middleware extension. Handlers read `node_id` from the extension, never from the JSON body. Read endpoints stay session-authed or public; mutating endpoints require the middleware.
- **Blast radius.** `zp-server/src/auth.rs` (is_exempt), `zp-server/src/fleet.rs` (handlers), `zp-mesh/src/discovery.rs` (signed-payload schema if shared), `zp-cli` (whatever issues node heartbeats).

### Seam 4 — Receipt generation authority

- **Intent.** A receipt attests to an authorized action by an authorized actor; the signed action body is constrained by a held capability.
- **Carrier.** `/api/v1/receipts/generate` handler downstream of a capability check; the signed payload structure is `(action_type, params_hash, capability_id, content_hash)`.
- **Status.** **Open**. The handler signs `body.action: String` — free-form attacker-controlled.
- **Catalog rule.** P2 (Delegation), X1 (Possible ⊆ Required), X2 (Actual ⊆ Possible).
- **Wire.** Endpoint takes `(capability_id, action_type, params)`. Handler verifies the capability is held by the session subject and the action fits the capability's schema. Free-form `body.action` is rejected as malformed input.
- **Blast radius.** `zp-server/src/lib.rs` receipt endpoint, `zp-receipt/src/builder.rs`, capability/lease module (which also doesn't fully exist yet — this is Phase 4 in the original architecture's roadmap).

### Seam 5 — Verifier symmetry

- **Intent.** Verification is local and pure; there is one Ed25519 verify primitive in the codebase, and it is `verify_strict`.
- **Carrier.** A single `zp_crypto::verify_signature(pk, msg, sig) -> Result<(), VerifyError>` helper. **Does not yet exist.**
- **Status.** **Partial**. Phase 1.C swept five `.verify(` sites to `.verify_strict(` (zp-verify, zp-receipt, zp-server attestations, zp-mesh runtime + discovery). The harvest survey reports ~138 call sites doing manual `verify_strict().is_ok()` without a wrapper. Without a single helper, future drift is one PR away.
- **Catalog rule.** M4 (signature integrity).
- **Wire.** Introduce `zp_crypto::verify_signature` (or `zp_audit::verify_block`-equivalent) and replace the 138 manual sites. Lint or `forbid(...)` an attribute that bans direct `verify`/`verify_strict` calls outside the helper module.
- **Blast radius.** New crate or module + sweep across zp-verify, zp-receipt, zp-server, zp-mesh, zp-policy, zp-trust, zp-keys (cert verification path).

### Seam 6 — Sovereignty key encryption

- **Intent.** Every `(wrapping_key, nonce)` pair is unique; re-running Genesis on the same device cannot leak prior secrets.
- **Carrier.** `encrypt_secret` (in `crates/zp-keys/src/sovereignty/hardware/mod.rs`).
- **Status.** **Closed** (Phase 2 CRIT-3). Ciphertext format v2: `[0x02 | nonce_12 | ct | tag]`; fresh `OsRng` nonce per call. v0/v1 still decrypt (read-only) for existing enrollments; v1 is rejected on the encrypt path.
- **Catalog rule.** Sovereignty / M-layer (the constitutional rule's confidentiality property).
- **Wire.** Versioned dispatch on ciphertext blob; encrypt path emits one current version; legacy versions are decrypt-only.

### Seam 7 — Secret file I/O mode and atomicity

- **Intent.** Secret material on disk is mode 0600 from creation, written atomically (no torn writes, no chmod-after-write race).
- **Carrier.** `zp_keys::secret_file::write_atomic` (in `crates/zp-keys/src/secret_file.rs`).
- **Status.** **Closed** (Phase 2 CRIT-8). Helper does tempfile + fsync + atomic rename, with `O_CREAT | O_EXCL | mode 0600` from creation. Re-exported as `zp_keys::write_secret_file`. Swept across `zp-keys/{keyring, sovereignty/file_based, sovereignty/face, sovereignty/hardware/mod}`, `zp-cli/commands.rs`, `zp-server/lib.rs` bootstrap.
- **Catalog rule.** Sovereignty / confidentiality.
- **Wire.** Single helper, all secret-write call sites route through it. CI lint to flag direct `std::fs::write` calls under `crates/zp-keys/` would harden.

### Seam 8 — Discovery announce replay window

- **Intent.** Every signed announce carries a monotonic `(seq, ts)`; receivers reject stale or regressing values.
- **Carrier.** `AgentAnnounce` signed payload schema + a per-agent receiver-side state map. Today the signed payload omits both fields.
- **Status.** **Open**.
- **Catalog rule.** M9, M10 (discovery layer integrity).
- **Wire.** Extend signed payload to include `(seq: u64, announced_at_ms: i64)`. Receiver maintains `HashMap<AgentId, (last_seq, last_ts)>`. Reject when `seq <= last_seq || ts < now - SKEW || ts > now + SKEW`. Default `SKEW = 5 minutes`.
- **Blast radius.** `zp-mesh/src/discovery.rs` payload schema, `zp-mesh/src/runtime.rs` receiver state, all senders.

### Seam 9 — Tool launch + token plumbing

- **Intent.** Tools run argv-form (no shell interpretation). Tokens flow through headers or postMessage handshake, never URL.
- **Carrier.** A `ToolSpec { argv: Vec<String>, env: HashMap<String, String> }` type for launch; a postMessage handshake from parent dashboard to tool iframe for token plumbing.
- **Status.** **Open**. `Command::new("sh").arg("-c")` with auto-detected start commands. `auth_token` written to `window.location.search` via history.replaceState (leaks via referrer, devtools, browser history sync).
- **Catalog rule.** M1 (gate coverage on side effects), M6 (sovereignty leakage).
- **Wire.** Replace string-form launch specs with `ToolSpec`. Replace URL-token injection with parent-frame `postMessage("zp.token", token)`. Lint or `forbid` `sh -c` patterns under `crates/zp-server/src/tool_*`.
- **Blast radius.** `zp-server/src/{tool_proxy,tool_chain,lib}.rs`, dashboard JS (the iframe parent), every tool that reads token from URL.

### Seam 10 — Public-page supply chain

- **Intent.** Every external script the user's browser executes is exactly the bytes the developer signed off on.
- **Carrier.** CI lint over `*.html`; either pin SRI hashes or self-host vendored copies.
- **Status.** **Open**. CDN scripts (`cdnjs.cloudflare.com`) loaded with no `integrity=` on the public site (`zeropoint.global/*.html`). Private dashboard has the same problem to a smaller blast radius.
- **Catalog rule.** Outside the substrate proper; this is the trust-of-the-shopfront layer.
- **Wire.** CI script that scans HTML files and fails the build if any external `<script src="https://">` lacks `integrity` and `crossorigin`. Or self-host pinned copies.
- **Blast radius.** `zeropoint.global/*.html`, `crates/zp-server/assets/*.html`, CI workflow.

### Seam 11 — Test/production identity isolation

- **Intent.** No test build can ever reach a production-namespaced credential, regardless of which crate is being compiled. Tests round-trip credentials reliably across cargo rebuilds.
- **Carrier.** Two layers, both required:
  1. *Namespace functions* in `crates/zp-keys/src/keyring.rs` that consult both `cfg!(test)` AND the `ZP_KEYCHAIN_TEST_NAMESPACE` env var. ~14 call sites swept.
  2. *In-memory mock credential builder* in `crates/zp-keys/src/test_helpers.rs` implementing `keyring::credential::CredentialBuilderApi` directly with an `Arc<Mutex<HashMap>>` shared across every credential the builder produces. Installed once per process via `install_mock_keyring()`.
- **Status.** **Closed.** Namespace guard prevents tests from reaching `zeropoint-genesis` (production) regardless of compile-time cfg. Mock backend prevents tests from reaching the OS Keychain at all — `zp-keys`'s own tests install via `serial_guard()`; `zp-hardening-tests` installs at harness startup; `set_default_credential_builder` is process-global, idempotent via `Once`.
- **Catalog rule.** Operational integrity. Not in the original M-rules; this is a wire we discovered through the May 2026 keychain debugging.
- **Wire.** Two reinforcing structural commitments:
  1. Namespace function = "tests can't reach production-named credentials." A security invariant.
  2. Mock backend = "tests don't touch OS-level credential state at all." A reliability invariant.

#### Why the mock backend earned its place (the May 2026 lesson)

An earlier pass declined the mock backend on the principle "no mock data in the codebase unless it earns its place." The reasoning was that the namespace guard alone provided the security invariant, and suppressing the macOS Keychain dialog was comfort rather than crystallization.

That reasoning was insufficient. The **reliability** dimension was under-weighted:

- macOS binds Keychain ACLs to the calling binary's code-signature hash.
- Every `cargo test` rebuild produces a binary with a fresh signature.
- When the new signature differs from whatever signature originally wrote to a `(service, account)` slot, `set_password` returns `Ok` at the API level but the kernel may **silently** decline the replacement, leaving the prior bytes in place.
- A subsequent `get_password` then returns the stale bytes — and the test asserting `loaded == saved` fails with bytes that aren't even from this run.
- This isn't a bug we can write a discipline against; the failure mode is invisible at the call site.

The namespace guard couldn't fix this because the failure isn't about *which* slot tests target — it's about whether write-then-read round-trips at all. The only structural answer is: don't touch OS Keychain in tests. The mock backend turns the credential store into a deterministic in-process map.

The "mock data in the codebase" framing also missed what the mock actually is. It isn't fake business logic. It's an in-memory implementation of an OS interface, gated behind a test-only feature, ~150 lines under our control end-to-end. The third-party `keyring::mock` module (which an earlier attempt tried) had opaque round-trip semantics we couldn't diagnose; the hand-rolled version has obvious semantics by inspection.

The lesson recorded so future structural decisions hold the dimensions together: a wire that secures something but doesn't make tests reliable doesn't fully close the seam. Reliability is part of "convention to invariant" — flaky tests are a convention that something will work most of the time; deterministic tests are an invariant that it always will.

### Seam 12 — Configuration provenance

- **Intent.** Every config value (`ZP_HOME`, `ZP_PORT`, `ZP_BIND`, sovereignty mode, audit DB path, etc.) has one resolution function with a documented precedence (env var > config file > default), and every consumer goes through it.
- **Carrier.** A `zp-config::ConfigResolver` that exposes typed accessors. The harvest survey reports it exists but not all callers use it; `ZP_PORT`, `ZP_BIND`, `ZP_HOME` are read from three independent paths (zp-config, zp-server, security module) with subtly different fallback chains.
- **Status.** **Open** (or partial — the carrier exists but isn't authoritative).
- **Catalog rule.** Operational integrity.
- **Wire.** Make `zp-config::ConfigResolver` the only public API. Move all env-var reads into it. Fail loudly if a consumer outside `zp-config` calls `std::env::var` for a known config key.
- **Blast radius.** `zp-config/src/`, `zp-server/src/lib.rs` startup, `zp-cli/src/main.rs` startup, `zp-server/src/security.rs`.

### Seam 13 — Error-type boundary discipline

- **Intent.** Each crate exposes a typed error; consumers either propagate it (preserving structure) or convert it explicitly at the boundary (preserving information about *which* downstream error caused this).
- **Carrier.** Per-crate `Error` enums plus `From` impls at boundaries. Today the codebase mixes `KeyError`, `String`, `anyhow::Error`, `StoreError`, ad-hoc enums, and `format!("{}", e)` conversions that drop type information.
- **Status.** **Open**.
- **Catalog rule.** Not directly in the original catalog. This is a hygiene wire that supports M-rule integrity by making downstream forensics tractable.
- **Wire.** Each crate publishes one error enum. Boundary crossings either use the enum's variant or a typed `From` impl. `anyhow` is acceptable in CLI/server roots but not inside library crates. `format!("{}", e)` for error storage is forbidden.
- **Blast radius.** All ~22 crates. This is a long sweep but mostly mechanical.

### Seam 14 — Versioned-format dispatch (catalog-wide)

- **Intent.** Every persistent or wire format has a version byte/column/field. Every reader dispatches on it. Every writer emits the current version. The migration policy is the same for all.
- **Carrier.** A per-format dispatch function, plus a documented migration convention. Phase 1 + 2 closed two: audit DB schema (v=2 → v=3) and ciphertext blob (v0/v1 → v2). Receipts (`schema_version: "1.0.0"`) and operator blob (`OPERATOR_BLOB_VERSION = 0x01`) and certificates (no explicit version) are open.
- **Status.** **Partial**. Some formats have version dispatch; others don't.
- **Catalog rule.** Operational integrity; supports M3/M4 by making upgrade paths well-defined.
- **Wire.** Convention: every persistent format has a version byte/column. Reader = `match version { v1 => …, v2 => …, _ => Err(Unknown) }`. Writer emits one current version. Pre-version blobs are length-detected and treated as v0. Drop-and-recreate for incompatible upgrades is the documented policy when in-place migration is impractical.
- **Blast radius.** `zp-receipt` (Receipt schema versioning + verifier dispatch), `zp-keys/src/keyring.rs` (operator blob v2 with random nonce — likely needs the same v0/v1 lift as ciphertext), `zp-keys/src/certificate.rs` (certificate format), `zp-mesh/src/envelope.rs` (mesh envelope versioning).

### Seam 15 — Async cancellation and cleanup

- **Intent.** Tasks that own resources (audit store handles, mesh connections, file locks) clean up correctly when their parent future is dropped mid-flight.
- **Carrier.** Drop impls that release resources, plus structured concurrency around `tokio::spawn` so child tasks are cancelled when the parent scope ends.
- **Status.** **Open** (largely unsurveyed). Mesh connections, websocket handlers, and tool proxy spawns have not been audited for cancellation safety.
- **Catalog rule.** Operational integrity.
- **Wire.** Audit every `tokio::spawn` for whether it owns resources that need cleanup on cancel; convert standalone spawns into structured concurrency where possible (`JoinSet`, `tokio_util::task::TaskTracker`).
- **Blast radius.** TBD — needs survey before scope is known.

### Seam 16 — Receipt-actor key management

- **Intent.** Every Actor (Human/Codex/Agent) that signs a receipt has a registered key, and the verifier can look up "for this `actor_id`, what is the expected signing public key?"
- **Carrier.** An `ActorKeyRegistry` that maps `ActorId → VerifyingKey` plus a registration ceremony. Today the actor model has identity *intent* (`ActorId::User(String)`, `ActorId::System(String)`, etc.) but no per-actor signing-key wire. Receipts attribute to actors but the verifier has nowhere to look up an actor's key.
- **Status.** **Open**.
- **Catalog rule.** P2 (Delegation), M4 (signature integrity). Future work: this is the substrate for the GAR (Governed Agent Runtime) layer.
- **Wire.** Introduce an `ActorIdentity { id: ActorId, key: VerifyingKey, registered_at, registered_by }` record, persist it (signed by Operator), expose a registry API used during verification.
- **Blast radius.** `zp-core/src/audit.rs` (ActorId), new `zp-trust/src/actor_registry.rs`, `zp-receipt::Verifier` (lookup path), `zp-keys` (key derivation per actor).

### Seam 17 — Canonical JSON serialization

- **Intent.** Any JSON document that participates in a hash, signature, or wire-equality comparison is serialized canonically — same bytes for equal documents, regardless of who serialized.
- **Carrier.** A `canonical_json::to_bytes(&value) -> Vec<u8>` helper. Today the harvest reports 40+ sites doing canonical-ish serialization by hand: each domain (receipts, attestations, capability grants, mesh envelopes) builds its own preimage.
- **Status.** **Open**.
- **Catalog rule.** M3 (hash-chain continuity rests on this), M4 (signatures rest on this).
- **Wire.** Single canonical-JSON helper. Sort keys lexicographically; escape strings the same way; canonical number representation. Every preimage construction goes through it.
- **Blast radius.** ~40 call sites spread across `zp-receipt`, `zp-audit`, `zp-mesh`, `zp-core`. This is one of the highest-leverage wires because it touches every signing or hashing path.

### Seam 18 — String-typed identifiers

- **Intent.** Identifiers (node IDs, agent IDs, tool names, action types, capability IDs, key IDs, receipt IDs, scan paths) are typed handles whose construction either validates or restricts how they can be built. A bare `String` parameter that represents a typed concept is a wire waiting to happen.
- **Carrier.** Per-identifier newtype wrappers (`NodeId(String)`, `ToolName(String)`, etc.) with parse/validate constructors and `Display`/`AsRef<str>` for ergonomics.
- **Status.** **Partial**. Some identifiers are well-typed (`ConversationId(Uuid)`, `ActionType` enum). Others are bare strings. The harvest specifically calls out `tool_name`, which has 4 patched injection vulnerabilities (AUTHZ-VULN-08 through -11) — the patches are ad-hoc; the type remains untyped, so the next code path that accepts a tool name is one PR away from the fifth injection.
- **Catalog rule.** M1 (gate coverage applied to identifiers used in side effects).
- **Wire.** A newtype per concept with a `parse` function that bans the patterns that have ever been malicious (`..`, NUL, shell metacharacters, etc.). The bare `String` API is removed. Every consumer takes the typed handle.
- **Blast radius.** Wide — every site that takes a `tool_name`, `agent_id`, etc. needs the typed handle.

### Seam 19 — Home directory and path resolution

- **Intent.** "Where is `~/ZeroPoint`?" has one answer per process, resolved once at startup with a documented precedence (env var > config > default), and every component that needs it asks the same source.
- **Carrier.** `zp_core::paths::home()` and family, with `ZP_HOME` env var override.
- **Status.** **Partial**. The harvest reports the resolution chain is reimplemented across `zp-config`, `zp-core`, `zp-preflight`, `zp-cli` with subtly different fallback behavior. Sometimes `~` expands; sometimes `$HOME` is read directly; sometimes the default is `./data/zeropoint`.
- **Catalog rule.** Operational integrity.
- **Wire.** Single `zp_core::paths::home() -> PathBuf` (or `Result<PathBuf>`). All other path helpers (`keys_dir`, `data_dir`, etc.) build on it. Forbid duplicate resolution outside `zp-core::paths`.
- **Blast radius.** ~5 crates. Mechanical sweep once the canonical helper is identified.

### Seam 20 — Hash-then-sign discipline

- **Intent.** A signature is always produced *over* a well-defined hash of the unsigned canonical form, and the hash is well-defined before any signature exists. The signature field never feeds back into the hash.
- **Carrier.** A documented convention plus per-domain helpers. The audit chain enforces it (`compute_entry_hash` always sees `signatures: []`, signing happens in `append`); receipts enforce it (`canonical_hash(&receipt)` then `signer.sign(&mut receipt)`); but the harvest reports the convention is documented in many comments and the helpers are not unified.
- **Status.** **Partial**. Closed for the audit chain (Phase 1) and receipts (pre-existing); open for certificates, capability grants, anchor commitments, and any future signed structure.
- **Catalog rule.** M3, M4, X2.
- **Wire.** A `Signable` trait with `canonical_hash(&self) -> [u8; 32]` and a `sign_in_place(&mut self, signer)`. Everything signed in the substrate implements `Signable` and goes through the trait.
- **Blast radius.** `zp-core` (trait definition), `zp-receipt`, `zp-audit::chain`, `zp-keys::certificate`, anywhere else that signs.

---

## Part III — Wire Patterns

The seams above are not 20 independent fixes. They cluster into a smaller number of recurring **wire patterns** — architectural commitments that close many beads at once. Naming the patterns lets us deduplicate the work.

### Pattern A — Single-carrier discipline

*One function/middleware/type owns enforcement; no parallel paths exist.* Closes seams: 1 (AuditStore::append), 2 (evaluate), 3 (fleet_sig_middleware), 5 (verify_signature helper), 6 (encrypt_secret), 7 (write_atomic), 9 (ToolSpec), 11 (namespace functions), 12 (ConfigResolver), 17 (canonical_json), 19 (paths::home), 20 (Signable trait).

This is the dominant pattern. Most structural fixes in ZP are some variant of "introduce one carrier, sweep N call sites." The architectural commitment is the carrier; the sweep is the bead-stringing.

### Pattern B — Type-as-invariant

*Replace strings/primitive types with newtypes whose construction validates.* Closes seams: 18 (string-typed identifiers), 16 (ActorIdentity), and informs 4 (capability_id is a typed handle, not a string), 8 (signed announce payload is a typed struct, not a JSON value).

This pattern compounds with Pattern A — the typed handle's construction *is* the carrier.

### Pattern C — Versioned-format dispatch

*Every persistent format has a version byte/column. Reader dispatches; writer emits one current version; legacy versions are decode-only.* Closes seam: 14 (catalog-wide). Also the architectural template that Phase 1.B/1.C and Phase 2 CRIT-3 used (audit DB v=2/v=3, ciphertext v0/v1/v2).

The convention is now explicit: "if it lives on disk or on the wire, it has a version." Future formats inherit the discipline by default.

### Pattern D — Storage-layer enforcement

*Push the invariant into the layer below the language.* Closes seam: 1 (SQLite triggers reject UPDATE/DELETE), 7 (filesystem mode 0600 from creation, not after), and informs 3 (a NodeIdentity registered in the DB is bound to its public key by a foreign-key constraint).

This pattern is the strongest form of invariant: even raw SQL or `std::fs::write` can't violate it. Use when the language layer is too far from the persistence layer to be authoritative.

### Pattern E — Capability-bounded action

*Every signed action is verified to fit within a held capability.* Closes seam: 4 (receipt forgery), and is the substrate for Phase 4 (GAR).

This is the deepest pattern in ZP. It requires the capability/lease system to be the source of truth for what an actor can do — which is itself a wire that doesn't yet fully exist. Phase 4 territory.

### Pattern F — Test/production isolation by namespace + mock backend

*Tests run in a namespace that's structurally separate from production, with a mock backend for ambient resources (OS keychain, network, filesystem).* Closes seam: 11.

Combines two sub-wires: namespace function + env-var override (the structural answer) and mock backend installed at test startup (the operational answer). Together they make "test reaches production" impossible regardless of compile-time switches.

---

## Part IV — Status Against the Four Claims

The four claims (`ARCHITECTURE-2026-04.md` §2) are the substrate's acceptance criteria. Each is implemented by a set of wires.

### Claim 1 — Each step is conditioned on all prior context.

*Mechanism:* `pr` linkage + Blake3 transitivity.

*Wires required:* Seam 1 (audit chain write path), Seam 5 (verifier symmetry), Seam 17 (canonical JSON), Seam 20 (hash-then-sign).

*Status:* **Substantively true.** Phase 1 closed Seam 1 fully. Seam 5 is partially closed (call sites swept, single helper still missing). Seams 17 and 20 are partially closed (some helpers exist, not unified).

*To make fully true:* introduce the canonical-JSON helper (Seam 17) and the `Signable` trait (Seam 20), then sweep. After that the claim is structurally true, not just by-current-implementation true.

### Claim 2 — Present state compresses full history.

*Mechanism:* collective audit (`AuditChallenge → AuditResponse → PeerAuditAttestation`).

*Wires required:* Seam 1 (chain integrity), Seam 5 (verifier), Seam 14 (versioned formats so cross-version chains can be verified or rejected explicitly).

*Status:* **The mechanism exists; it has not been load-tested adversarially.** Phase 1 closed the chain-write side. The peer-audit verification path hasn't been exercised against an adversarial peer.

*To make fully true:* a dedicated test campaign with a malicious-peer harness. Not a code wire — a testing wire.

### Claim 3 — System-wide coherence from local evaluation.

*Mechanism:* PolicyEngine fixed evaluation order; constitutional rules first.

*Wires required:* Seam 2 (gate evaluation), Seam 9 (tool launch), Seam 18 (string-typed identifiers in side-effect paths).

*Status:* **Substantively true at the gate.** Phase 1 closed Seam 2. Seams 9 and 18 are open: `Command::new("sh").arg("-c")` and string `tool_name` parameters give attackers paths to side effects that don't go through the gate's structural enforcement. The pentest's central finding (gate coverage was disciplinary) hasn't been fully closed yet — Phase 1 closed the *classification* side; the *side-effect* side is still convention.

*To make fully true:* close Seam 9 (ToolSpec, postMessage tokens) and Seam 18 (typed `ToolName`).

### Claim 4 — Future actions narrowed by trajectory.

*Mechanism:* the eight delegation invariants.

*Wires required:* Seam 4 (receipt authority), Seam 16 (actor key registry), the GAR layer.

*Status:* **Believed-but-untested.** Implementation exists in `DelegationChain::verify()`. The pentest never exercised delegation paths because it didn't need to.

*To make fully true:* close Seam 4 (receipt forgery) and Seam 16 (actor identity). After Phase 4 lands the GAR, the delegation chain becomes the substrate for capability-bounded action.

---

## Part V — Status Against the Seven Principles

The principles (`ARCHITECTURE-2026-04.md` §V½) are the design philosophy made operational. Each is implemented by a set of wires.

| Principle | Wires | Status |
|---|---|---|
| **1. Signing is gravity** | Seams 1, 5, 17, 20 | Substantively true at the chain layer (1 closed). Open at receipt-auth (4) and verifier-symmetry (5) and canonical-form (17) levels. |
| **2. Identity is a key, not a location** | Seams 3, 16 | Open. Fleet heartbeat trusts location (3); receipts attribute to actors who have no registered key (16). Phase 3/4 territory. |
| **3. There is no center** | Seam 5 (verifier-as-re-deriver), Seam 14 (every node can verify a peer's chain regardless of version) | Partially closed. Verifier exists; symmetry across the codebase is incomplete. |
| **4. Every bit counts** | Seams 13, 17, 18 | Partial. Receipt schema is clean (Phase 6 stripped duplicate detail JSON). Error types and canonical JSON are still scattered. |
| **5. Store-and-forward primary** | Seam 1 (the chain is primary), Seam 8 (announce replay) | Seam 1 closed; Seam 8 open. Replay protection is a precondition for treating announces as substrate-level state. |
| **6. A tool is intent, crystallized** | Seams 2, 9 | Seam 2 (the classification side) closed. Seam 9 (the launch side) open. Until ToolSpec replaces `sh -c`, intent doesn't fully crystallize — there's a parallel path the gate doesn't see. |
| **7. Contact does not commit** | Seam 4 (receipts as the membrane), Seam 8 (rejecting replays before they become state), Seam 16 (actor identity binds events to commitments) | Open across all three. Phase 4 work. |

---

## Part VI — Prioritized Fix Order

The seams are not all equal. Some unlock others; some are mechanical sweeps of an existing pattern; some require new design work. Suggested order:

### Tier 1 — Highest leverage, lowest design cost

These close many beads with one wire and don't require new design.

1. **Seam 17 — Canonical JSON helper.** ~40 call sites consolidate. Closes a precondition for Seams 5, 14, 20.
2. **Seam 20 — `Signable` trait.** Builds on Seam 17. Unifies the hash-then-sign discipline across receipts, audit chain, certificates, future formats.
3. **Seam 5 — Single `verify_signature` helper.** ~138 call sites consolidate. Mechanical once the helper lands. Closes Claim 1 and Principle 1 structurally.
4. **Seam 19 — Path resolution unified.** Mechanical sweep, unblocks operational consistency.
5. **Seam 11 follow-up — Mock keyring backend.** Eliminates dev-loop friction, completes Seam 11.

### Tier 2 — Network identity (Phase 3)

Bigger architectural pieces. Identity-as-key story.

6. **Seam 3 — Fleet auth middleware.** Closes CRIT-5. Requires designing the node-identity registration ceremony.
7. **Seam 8 — Announce replay window.** Closes CRIT-7. Schema change to signed payload, receiver state, plus migration plan for existing announces.
8. **Seam 16 — Actor key registry.** Lays the substrate for receipt-actor binding. Useful before Seam 4.

### Tier 3 — Capability/lease layer (Phase 4)

The deepest piece. Requires significant design before implementation.

9. **Seam 4 — Receipt generation authority.** Depends on the lease/grant system being the source of truth for actor authority. Substantial.

### Tier 4 — Hygiene + perimeter

Mostly mechanical, low-design.

10. **Seam 14 — Versioned-format dispatch (catalog-wide).** Convention exists; sweep remaining formats.
11. **Seam 13 — Error-type discipline.** Long sweep, mostly mechanical.
12. **Seam 18 — String-typed identifier sweep.** Start with `tool_name` (4 patched vulns), then expand.
13. **Seam 9 — ToolSpec + postMessage.** Closes CRIT-6 (receipt forgery's near-cousin) and the side-effect half of Claim 3.
14. **Seam 12 — ConfigResolver authoritative.** Sweep three duplicate paths into one.
15. **Seam 10 — SRI on public pages.** CI lint + sweep.
16. **Seam 15 — Async cancellation.** Survey first; scope after.

---

## Part VII — Notes on Method

This document was produced by:

1. Re-reading `ARCHITECTURE-2026-04.md` for the operating spec's vocabulary.
2. Synthesizing seams from the Phase 1 and Phase 2 remediation work and the May 2026 keychain-bug discovery.
3. A harvest pass over the codebase looking for documented-but-unenforced disciplines (40+ canonical-JSON sites, 138+ unwrapped verifies, 4 untyped-identifier vulns, etc.).
4. Grouping the seams into wire patterns to deduplicate the work.

The document is a snapshot. Like the architecture record and the catalog, it has versions. The next version will be conditioned on what implementing the Tier 1 wires teaches us. Some seams may merge as the wire patterns become more concrete; others may split as the capability layer's structure becomes visible.

The substrate is autoregressive at the meta layer (`ARCHITECTURE-2026-04.md` §4a). This document is too.
