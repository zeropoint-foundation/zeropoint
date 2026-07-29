# Discipline Pins Map

**Generated** by `tools/discipline-pins/discipline_pins.py` from commit `7a85056`. Derived, not authored — regenerate rather than edit.

19 pin files · 19 assertions · 43 forbidden patterns · 2,400 lines


These run under `cargo test --workspace`, which `.github/workflows/ci.yml` invokes on every push. A violation fails the build.


## Pins

| Pin | Forbids | Invariant cited | Allowlist | Rationale doc |
|---|---|---|---:|---|
| `adapters_must_be_documented` | every file that implements a known port trait must carry a module-level doc comment documenting the adapter it provides. | **hand-rolled** | 0 | `docs/ARCHITECTURE-2026-05.md` |
| `granted_tools_must_be_reachable` | the Regent's tool surface has exactly one source, and every capability in it is dispatchable. | **hand-rolled** | 0 | — |
| `no_build_time_paths_at_runtime` | runtime file resolution MUST NOT depend on build-time paths. | P2 (identity is a key, not a location) — C7 loaded-not-versioned | 3 | `docs/design/CONNECTION-INTEGRITY-PROGRAM-2026-07.md` |
| `no_cloudflare_imports_in_zp_crates` | Cloudflare-specific Rust types must stop at the `zp-cloudflare` adapter crate. | Stack-Cloudflare reference integration: port/adapter boundary | 1 | `docs/STACK-CLOUDFLARE-2026-05.md` |
| `no_direct_verify_strict_outside_helper` | `verify_strict(` MUST only appear inside the canonical verify primitive at `zp-receipt/src/verify.rs`. | Seam 5 (single verify primitive) | 1 | — |
| `no_external_script_without_integrity` | every external `<script>` and external `<link rel="stylesheet">` on the public site must carry an `integrity=` and `c… | **hand-rolled** | 0 | `docs/SUPPLY-CHAIN-MANIFEST.md` |
| `no_non_strict_ed25519_verify` | Ed25519 signature verification MUST go through `verify_strict`. | Seam 5 (verifier symmetry) / CRIT-4 (signature malleability) | 0 | — |
| `no_raw_artifact_creation_outside_zp_artifacts` | artifact creation must go through zp-artifacts. | **hand-rolled** | 0 | — |
| `no_raw_home_lookup` | raw home-directory lookups MUST go through the `zp_core::paths` carrier. | Seam 19 (path resolution carrier) | 3 | — |
| `no_raw_keychain_service_strings` | keyring `Entry::new` MUST go through the namespace functions. | Seam 11 (test/production identity isolation) | 0 | — |
| `no_raw_peer_url_outside_zp_net` | substrate-internal peer URLs MUST NOT be assembled by raw `format!()` / string concatenation of `http://localhost:<po… | Principle 8 (one canonical path) — singular loopback binding (client side) | 17 | `docs/design/SINGULAR-LOOPBACK-BINDING-2026-05.md` |
| `no_raw_provider_http_outside_canonical_layer` | substrate code MUST NOT post directly to cloud provider API endpoints. All inference must route through the ZP proxy … | Singular canonical inference surface — every inference call emits a signed receipt | 3 | `docs/design/INFERENCE-ARCHITECTURE-CONSOLIDATION-2026-05.md` |
| `no_raw_storage_calls_outside_zp_content` | raw filesystem writes for content purposes, and direct R2/D1/KV calls, must not appear outside `crates/zp-content/`. | Principle 8 (one canonical path) — singular content-addressed storage | 2 | `docs/design/STORAGE-ABSTRACTION-2026-05.md` |
| `no_raw_tcp_bind_outside_zp_net` | loopback servers MUST NOT call `TcpListener::bind` directly. All loopback server binds must route through `zp_net::bi… | Principle 8 (one canonical path) — singular loopback binding | 6 | `docs/design/SINGULAR-LOOPBACK-BINDING-2026-05.md` |
| `no_raw_tonic_serve_outside_zp_net` | tonic gRPC servers MUST NOT use the address-passing `.serve(<addr>)` form. All loopback gRPC binds must route through… | Principle 8 (one canonical path) — singular loopback binding | 1 | `docs/design/SINGULAR-LOOPBACK-BINDING-2026-05.md` |
| `no_serde_preserve_order` | `serde_json/preserve_order` MUST NOT be enabled. | Seam 17 (ZP-canonical-v1 determinism) | 0 | — |
| `no_sh_c_in_tool_launch` | tool-launch code MUST NOT use `Command::new("sh")` / `Command::new("bash")` patterns chained with `.arg("-c")`. | Seam 9a — argv-form tool launch (no sh -c) | 0 | — |
| `no_std_fs_write_in_keyring` | `std::fs::write` MUST NOT appear inside `zp-keys/keyring.rs`. | Seam 7 (atomic mode-0600 secret writes) | 0 | — |
| `verbs_must_match_schema` | every public function whose return type references a `zp_verbs` type must produce one of the verb-set's response cate… | **hand-rolled** | 0 | — |

## Inline pins (outside `zp-discipline`)

- `crates/zp-keys/src/sovereignty/mod.rs:991` — ── singular_sovereign_root discipline-pin tests ─────────────────

## Attention

- **Hand-rolled, no `Discipline` builder** (5): `adapters_must_be_documented`, `granted_tools_must_be_reachable`, `no_external_script_without_integrity`, `no_raw_artifact_creation_outside_zp_artifacts`, `verbs_must_match_schema` — these assert directly, so a failure prints a bare assertion rather than the cited invariant and rationale the builder emits. The pin still holds; the message does not explain itself.
- **No `cite_invariant`** (0): none — uses the builder but names no invariant, so the rule is enforced without a stated source.
- **No rationale document** (10): `granted_tools_must_be_reachable`, `no_direct_verify_strict_outside_helper`, `no_non_strict_ed25519_verify`, `no_raw_artifact_creation_outside_zp_artifacts`, `no_raw_home_lookup`, `no_raw_keychain_service_strings`, `no_serde_preserve_order`, `no_sh_c_in_tool_launch`, `no_std_fs_write_in_keyring`, `verbs_must_match_schema` — the `# Why` lives only in the pin's own header. Fine for a narrow rule; a gap for a broad one.
- **Rationale in an untracked file** (0): none — cites `docs/handoffs/`, which `.gitignore` excludes and the corpus convention classifies as local notes rather than corpus. The pin ships; its justification does not.
- **Widest allowlists** (2 with ≥5 exemptions): `no_raw_peer_url_outside_zp_net` (17), `no_raw_tcp_bind_outside_zp_net` (6) — each exemption is a place the rule does not hold. Worth re-reading when the count grows, since exemptions are added one at a time and never reviewed together.
- **Cited document does not resolve** (0): none
- **Promised but not landed** (2): `crates/zp-cli/src/commands.rs:49`; `crates/zp-keys/src/foundation_edge_signer.rs:91` — source comments announcing a pin that does not exist. These read as enforcement and enforce nothing (A11).
- **Described by `docs/DISCIPLINE-PINS.md`** (1 of 19): `no_raw_peer_url_outside_zp_net`
