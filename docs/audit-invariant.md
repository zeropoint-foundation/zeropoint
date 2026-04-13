# The Audit Invariant

> This is the design note for the audit-subsystem recanonicalization. It is
> short on purpose. If you are about to add a second way to do any of the
> things below, read this first.

## The invariant

There is exactly one audit chain. It lives in exactly one place: a single
`audit_entries` table in a single SQLite database file, written by exactly one
writer API, `AuditStore::append`, which takes an `UnsealedEntry` and returns a
sealed `AuditEntry`. The writer is the only thing in the codebase that is
allowed to compute `prev_hash`, `entry_hash`, `id`, or `timestamp` for an
audit entry.

Formally, for every row `e` in `audit_entries`:

    e.prev_hash = (e_prev.entry_hash  if e_prev exists)
                  (genesis_hash()     otherwise)

    e.entry_hash = seal_entry(
        UnsealedEntry::from_sealed(&e),
        &e.prev_hash,
        e.id,
        e.timestamp,
    ).entry_hash

where `e_prev` is the row with the maximum `rowid` strictly less than `e.rowid`,
and `seal_entry` is `zp_audit::chain::seal_entry`.

The verifier (`zp_audit::catalog_verify`) enforces both clauses. When it does
not — and today the second clause is disabled for legacy-data reasons — the
subsystem is not coherent, and saying otherwise is a lie.

## Ownership

- **The chain itself** is owned by SQLite. The invariant is enforced by the
  schema (via a `UNIQUE(prev_hash)` partial index excluding genesis) and by
  `AuditStore::append` (via a `BEGIN IMMEDIATE` transaction around tip-read,
  seal, and insert).
- **`AuditStore`** is owned by one component per process. In `zp-server` that
  component is `AppState`. Every other in-process consumer (the pipeline, the
  tool-chain emitter, the proxy audit hook, any future writer) takes
  `Arc<Mutex<AuditStore>>` from that owner. `AuditStore::open` is called
  exactly once per process.
- **`UnsealedEntry`** is owned by its caller up until the moment it is passed
  to `append`. Callers populate application-level fields only (`actor`,
  `action`, `conversation_id`, `policy_decision`, `policy_module`, optional
  `receipt`, optional `signature`). Callers do not compute, supply, or read
  chain-position fields.

## Non-negotiables

1. **No second chain head.** Nothing in the tree may hold a `Mutex<String>`,
   `RefCell<String>`, `AtomicU64`-plus-a-hash, or any other in-memory chain
   cursor for audit entries. The only chain head is `MAX(rowid)` in the
   database. `zp_policy::Gate::audit_chain_head` (pre-recanonicalization) is
   exactly what this clause forbids.

2. **No second hash function.** Nothing in the tree may define a
   `compute_entry_hash` or `compute_hash` function that operates on
   `AuditEntry` or `UnsealedEntry` other than `zp_audit::chain::compute_entry_hash`
   (and its public wrapper `recompute_entry_hash`). `zp_policy::gate::compute_entry_hash`
   (pre-recanonicalization) is exactly what this clause forbids.

   Hash functions over *other* domain types (governance events, execution
   receipts, collective attestations) are permitted. They must be registered
   in `docs/audit-architecture.md`.

3. **No `format!("{:?}", ...)` as canonical identity.** Debug format is for
   humans. If a value is used as a map key, a hash input, a database column,
   a wire serialization, or an equality discriminator, it is serialized with
   `serde_json`, `Display`, or a purpose-built, versioned, round-trip-tested
   function. `ActorGuard`'s current `HashSet<String>` keyed on
   `format!("{:?}", actor)` is exactly what this clause forbids.

4. **No back-door writes.** `AuditStore::execute_raw` does not exist. Schema
   migrations go through an explicit migration API. The pentest tamper
   endpoints go through narrow, feature-gated methods
   (`tamper_entry_hash(id, new_hash)`, `restore_entry_hash(id, original_hash)`)
   that explicitly document that they violate the invariant and are only
   compiled in with the `pentest-demo` feature.

5. **One-writer transactional append.** `append` opens a
   `BEGIN IMMEDIATE` transaction, reads the tip with
   `SELECT entry_hash FROM audit_entries ORDER BY rowid DESC LIMIT 1`, assigns
   `id` and `timestamp`, calls `seal_entry`, inserts the row, and commits. Any
   deviation — non-transactional append, ordering by `timestamp`, caller-supplied
   `prev_hash`, tip caching across calls — is exactly the AUDIT-03 bug.

## Verifier obligations

`zp_audit::verifier::verify_chain` and `zp_audit::catalog_verify::verify_with_catalog`
together enforce:

- **P1 (linkage):** for every adjacent pair `(e_i, e_{i+1})` ordered by rowid,
  `e_{i+1}.prev_hash == e_i.entry_hash`, and `e_0.prev_hash == genesis_hash()`.
- **P2 (content hash):** for every row `e`,
  `recompute_entry_hash(&e) == e.entry_hash`.
- **P3 (uniqueness):** for every non-genesis `prev_hash` value, exactly one
  row has it. (Enforced by the schema; the verifier only confirms.)
- **P4 (monotonicity):** `rowid` is monotonically increasing with `timestamp`
  within wall-clock resolution, with tolerance for sub-millisecond ties
  resolved by `rowid` order.

As of AUDIT-03 recanonicalization (Stages 4–5, 2026-04-07), all four are
enforced: P1 and P4 strictly in the verifier, P2 strictly in the verifier via
`recompute_entry_hash(e) == e.entry_hash` (see
`crates/zp-audit/src/catalog_verify.rs`), and P3 at the storage layer via the
`idx_unique_prev_hash` partial unique index (see `crates/zp-audit/src/store.rs`),
surfaced as a verifier violation if ever bypassed. The subsystem is coherent on
an empty-then-populated schema-v2 database.

## What recanonicalization means

The database is dropped and recreated. Not migrated. The historical data is
forensically captured first (see
`security/pentest-2026-04-06/forensic-dump-audit-03.sh`) and then deleted.
The new schema is built from scratch with the invariants baked in, and the
first write through the new writer API produces row 1.

The historical forks at rowids 8214/8217/8223/8228 are not repaired. They are
preserved as evidence in the forensic TSV, and the rationale is recorded in
`REMEDIATION-NOTES.md`. Rewriting them would itself be a P1 integrity
violation, and they are the only concrete artifact proving AUDIT-03 existed
outside of our reasoning about the code.

## What to do if you disagree with any of this

Edit this file and open a PR. The invariant is the thing; the code exists to
serve it. If the invariant is wrong, fix the invariant first and the code
second. Do not add a second chain, a second hash function, a second writer,
or a second owner without changing this document in the same patch.
