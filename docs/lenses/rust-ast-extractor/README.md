# rust-ast-extractor

AST-based extractor for `docs/lenses/source-manifest.json`. Companion to
`regenerate_source_manifest.py` (regex-based) — same output schema, more
accurate type-flow because it walks the actual Rust AST via `syn`.

## When to use which

Use whichever is at hand — both produce the same manifest schema so the
artifact reads either.

- **`regenerate_source_manifest.py`** — no build step, no Rust toolchain
  requirement. Regex-based, so it under-counts struct-field types, misses
  impl-block context, and mis-terminates on complex generics. Good enough
  for a quick refresh; ~5-10 second run.
- **`zp-lens-ast-extractor`** (this crate) — parses each `.rs` file with
  `syn`, so it catches struct/enum fields, impl-block methods with correct
  target attribution, complex generics with nested bounds, `pub use`
  re-exports, and unions. Requires `cargo`; sub-second run once built.

Snapshot comparison (2026-07-26 against the same tree):

| Metric | Regex | AST | Δ |
|---|---:|---:|---:|
| Type defs | 1191 | 1188 | -3 |
| Type-flow edges | 93 | 118 | **+25** |
| Type-flow signals | 3096 | 4996 | **+1900** |

The +1900 signals come from struct/enum fields and impl-block methods that
the regex extractor never saw. The +25 edges are cross-crate flows that
those field/method type refs surface.

## What still slips through

Even the AST pass has limits without a semantic layer:

- **Macro-generated types.** `syn` sees the macro call, not what it would
  emit. `#[derive(...)]`, `paste!`, `proptest!`, and hand-rolled derive-like
  macros drop those types on the floor. Rough estimate: ~5-8% of type
  references in the substrate.
- **Trait-associated types resolved through impls.** `T::Item` where `T:
  Iterator` requires trait resolution to attribute correctly. The AST pass
  records the reference but can't resolve which concrete type it is.
- **Glob re-exports** (`pub use foo::*`). Ambiguous without semantic
  analysis; skipped.

A full `rust-analyzer`-based pass would close these gaps. Not shipped here
because rust-analyzer as a library dependency is much heavier and the
current numbers are already a substantial improvement over regex.

## Usage

```bash
# From the repo root:
cargo run --release \
  --manifest-path docs/lenses/rust-ast-extractor/Cargo.toml \
  -- --repo-root . --out docs/lenses/source-manifest.json

# Or from within the extractor dir:
cd docs/lenses/rust-ast-extractor
cargo run --release -- --repo-root ../../.. --out ../source-manifest.json

# With tools scanned too:
cargo run --release -- --repo-root . --out docs/lenses/source-manifest.json --include-tools
```

Options:

- `--repo-root PATH` — repo to scan (default: current directory).
- `--out PATH` — output manifest path (default:
  `<repo-root>/docs/lenses/source-manifest.json`).
- `--include-tools` — also scan `tools/*/**/*.rs`.

## How it works

1. **Discover crates.** Walk `crates/` (and optionally `tools/`) for
   directories with a `Cargo.toml` and at least one `.rs` file.
2. **Parse each `.rs` file** with `syn::parse_file`. Files that fail to
   parse (macro-heavy, exotic syntax) contribute their signal counts
   scanned as text but no AST facts.
3. **Extract per-crate facts** via a visitor:
   - Type definitions: `struct`, `enum`, `type`, `union` — each `ident`.
   - Type references from fn signatures, impl-block methods, struct
     fields, enum variant fields, trait methods.
   - `pub use other_crate::TypeName` re-exports.
4. **Build ownership map.** Each type → its owning crate (first writer
   wins). Re-exports promote ownership to the true source crate.
5. **Attribute references.** Each type reference in a crate is attributed
   to its owner: same-crate refs count as `types_produced`; different-crate
   refs count as `types_consumed` and increment the `(owner→consumer)`
   edge weight.
6. **Same signal-count patterns** as the Python extractor — for schema
   parity, `.sign(`, `SigningKey`, `PolicyEngine`, `emit_receipt`, etc.
   Same receipt-slug regex too.

## Output

Writes to `--out` (default `docs/lenses/source-manifest.json`). Schema
identical to the Python extractor's output; the only addition is an
`extractor` field naming the producer for provenance.
