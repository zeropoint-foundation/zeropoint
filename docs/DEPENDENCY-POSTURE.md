# ZeroPoint Dependency Posture

**Last reviewed: 2026-06-08**

This document catalogs ZeroPoint's third-party dependencies by strategic risk tier,
notes the structural reason for each assessment, and tracks mitigation status. It is
a living artifact — update it when dependencies are added, removed, or their risk
profile changes.

The framing question for each dependency: *if this library stagnates, gets acquired
by a company with misaligned interests, or is sunset, what breaks and how hard is
the recovery?*

---

## Tier 1 — Well-Insulated

Structural reasons for low risk, not just current reputation.

| Dependency | Role | Why insulated |
|---|---|---|
| `blake3`, `ed25519-dalek`, `chacha20poly1305`, `x25519-dalek`, `sha2`, `hkdf`, `aes`, `hmac`, `zeroize` | Cryptographic primitives | RustCrypto organization — community-governed, no single-company ownership, extensively audited, so widely deployed that abandonment would be an industry event |
| `rusqlite` + SQLite | Audit chain storage | SQLite is public domain; author has explicitly committed to maintenance in perpetuity. `rusqlite` bindings are thin and replaceable. |
| `tokio`, `axum`, `tower-http` | Async runtime + HTTP server | Maintained by the Tokio company; their commercial interests are structurally aligned with ecosystem health |
| `wasmtime` | WASM policy evaluation | Bytecode Alliance (Mozilla, Fastly, Intel, Microsoft); W3C standardization effort behind it; multiple corporate sponsors |
| `keyring`, `security-framework` | OS credential store | Thin Rust bindings over stable OS APIs (Keychain, Secret Service, Credential Manager); OS APIs are the stable surface |
| `clap`, `serde`, `anyhow`, `thiserror`, `chrono`, `regex` | Utility layer | Ubiquitous, community-maintained, no acquisition target value |

**Note on the JS toolchain risk (Bun/Astral):** ZeroPoint is Rust-native and uses
Cargo. The Rust Foundation has multi-corporate governance (AWS, Microsoft, Google,
Mozilla) that structurally resists single-entity capture. The specific acquisition
pattern described in the Bun/Astral context does not apply here.

---

## Tier 2 — Monitor

Real exposure but manageable; mitigation exists or is in progress.

### `libp2p` — Mesh networking

**Risk:** Protocol Labs (primary maintainer) has had funding uncertainty. The Rust
implementation specifically has gone through periods of reduced maintenance. The
project is widely deployed (Ethereum, IPFS) which provides some backstop, but
ZeroPoint is exposed if the Rust crate falls behind.

**Mitigation:** Architecture commits to Reticulum alongside libp2p as a parallel
mesh transport option (see `docs/ARCHITECTURE-2026-04.md` §II). This is the right
hedge — preserve it. Neither transport should become the only path.

**Status:** Hedged architecturally; not yet hedged in code.

---

### `ml-dsa` — Post-quantum signing (FIPS 204 / ML-DSA-65)

**Risk:** Still a release candidate (`0.1.0-rc`). API may have breaking changes
before stabilization. RUSTSEC-2025-0144 timing side-channel was patched in
`>=0.1.0-rc.3` — requires staying current.

**Mitigation:** Feature-gated (`pq-signing` feature flag in `zp-receipt`). The
hybrid signing path uses it; the primary Ed25519 path does not depend on it. If
`ml-dsa` breaks, the core signing path is unaffected.

**Status:** Appropriately gated. Pin to `>=0.1.0-rc.3` in Cargo.toml; audit on
each rc bump.

---

### `turbovec` — Vector similarity index

**Risk:** Smaller, less prominent library. Maintenance trajectory is unknown. No
corporate backer, limited contributor base.

**Mitigation:** `zp-memory-index` wraps `turbovec` behind the `MemoryIndex` trait.
`TurboVecIndex` is one implementation of that trait. Replacing the backend requires
a crate rewrite, not an architectural change. The trait is the stable surface;
`turbovec` is an implementation detail.

**Status:** Structurally hedged. If turbovec stagnates, the migration path is
clear.

---

### `trezor-client` — Hardware wallet signing

**Risk:** Thin crate maintained by SatoshiLabs. Low activity. Risk is not
abandonment but protocol drift — if Trezor firmware updates change the signing
protocol and `trezor-client` lags, the Trezor sovereignty provider breaks.

**Mitigation:** Hardware wallet integration is feature-gated and the sovereignty
provider interface abstracts over it. See `docs/design/quorum-sovereignty.md` for
the M-of-N direction which treats Trezor as one of several HW options.

**Status:** Gated and abstracted. Monitor SatoshiLabs release notes.

---

## Tier 3 — Active Exposure

These require deliberate mitigation work, not just monitoring.

### LLM API providers — Cognition layer

**Risk:** The highest strategic liability in the stack. `zp-llm` makes HTTP calls
to commercial LLM providers (OpenAI, Venice, configurable others). These are
companies with their own interests, pricing power, and API evolution timelines.
Any of the following would affect ZeroPoint's cognition layer:

- API deprecation or breaking changes
- Pricing changes that make the substrate uneconomical
- Acquisition or shutdown
- Policy changes that restrict agentic use cases

**Current hedges:**
- Venice (open-source model serving, sovereignty-aligned) is already a supported
  backend alongside OpenAI — this is the right instinct
- `zp-llm` abstracts provider calls; adding a backend is contained to that crate

**Gap:** Local inference (Ollama, llama.cpp server, any OpenAI-compatible local
endpoint) is not yet a first-class backend. A local inference path would make the
cognition layer fully sovereign — no external provider required for operators who
want it. This is consistent with the "no center" principle.

**Status:** Partially hedged. Priority: add a local-inference backend to `zp-llm`
that accepts any OpenAI-compatible base URL with no external dependency.

---

### Cloudflare platform — Reference deployment target

**Clarification:** Cloudflare is not integral to ZeroPoint. It is a practical
reference implementation of the edge tier. The substrate itself (audit chain,
receipts, gate, vault) runs entirely without CF — the self-hosted path is the
canonical path. `zp-cloudflare` is one implementation of the `EDGE-TIER-CONTRACT`;
other runtimes (Deno Deploy, Fastly Compute, raw VPS) are valid targets.

**Risk:** CF-specific APIs could leak through the abstraction boundary if
`zp-cloudflare` is developed carelessly, making the reference implementation harder
to port than it should be. This is a code hygiene concern, not a strategic
dependency.

**Mitigation:** `EDGE-TIER-CONTRACT-2026-06.md` defines required/optional/forbidden
affordances for the worker tier. Implementations must satisfy the contract; CF
conventions that don't correspond to contract affordances belong in
`zp-cloudflare` only, not in shared substrate code.

**Status:** Structurally sound. Monitor `zp-cloudflare` for contract boundary
violations during development.

---

## Review Cadence

This document should be revisited:
- When a new external dependency is added (add it to the appropriate tier)
- When an existing dependency has a significant event (acquisition, major version
  break, RUSTSEC advisory, maintainer departure)
- Quarterly as a routine hygiene pass

The goal is not zero external dependencies — that's impractical. The goal is that
every dependency is in the right tier, every Tier 3 exposure has a named mitigation
owner, and no surprises accumulate silently.


---

## Measured note (2026-07-22) — local inference backend: hedge → measured baseline

Promotes the held **E2** nomination from `AI-LANDSCAPE-SIGNAL-2026-07.md` §2 from assertion to measurement, updating the Tier-3 "LLM API providers" gap above. Benchmarked on APOLLO (M4 Pro, 64GB) via `tools/local-model-bench/`; selection rationale in `LOCAL-MODEL-SELECTION-2026-07.md`.

The Tier-3 gap noted local inference "is not yet a first-class backend" and treated it as a hedge. **Measurement closes the gap: a clear-license Apache-2.0 Qwen3-30B-A3B runs as an interactive sovereign Regent on APOLLO** — ~93 tok/s, 4/4 structured emission, int4-trustworthy grounded reasoning, 64k-corpus synthesis, resident in 16GB. The full local tier is clear-license and measured: reflection (Qwen3-30B-A3B), fast (Qwen3-4B, ~93 tok/s, 2.2GB), and routing classifier (Qwen3-1.7B, ~206 tok/s) — all Apache-2.0, no license-capture exposure.

**Reframe the Tier-3 posture accordingly:** local inference is no longer merely a strategic hedge against the cognition-layer liability — it is a demonstrated capable backend and should be the sovereign *default*, with cloud/rally reserved for realtime novelty. This does not remove the Tier-3 exposure for operators who choose cloud, but it converts "no sovereign fallback exists" into "the sovereign path is measured and works." Priority accordingly rises from "add a local backend" to "wire the measured local tier as the default; cloud is escalation."
