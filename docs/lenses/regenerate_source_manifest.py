#!/usr/bin/env python3
"""
Regenerates docs/lenses/source-manifest.json by walking the substrate's
Rust source under `crates/*/src/**/*.rs` (and optionally `tools/*/src/**/*.rs`).

Per crate, extracts:
- File and LOC counts
- Cross-crate dependencies (Cargo.toml [dependencies] + `use` statements)
- Info-flow signal counts (sign_count / gate_count / chain_count / verify_count)
- Receipt families and slugs (from string literals in source)
- Type definitions (regex-based; not a true AST parse)
- Type-flow signals (per-crate consumption of types defined in other crates,
  extracted from function signatures — returns + parameters)
- Type-flow edges (aggregated per producer→consumer crate pair with weight
  and top-type breakdown)

Also computes a `primary_role` per crate as argmax over the four base signal
counts (signing / gating / chain-emit / verifying), with `receipt-authoring`
tie-break for crates whose dominant activity is emitting receipts, and
`utility` fallback for crates with no strong signal.

Usage:
    cd <repo-root>
    python3 docs/lenses/regenerate_source_manifest.py [--out PATH] [--include-tools]

Output: writes JSON to <out> (default: docs/lenses/source-manifest.json).

NOTE on accuracy: The type-flow extraction is regex-based, not AST-based. It
will miscount macro-generated types, complex generics with nested bounds, and
`pub use` re-export chains. It's good enough to reveal the shape (which
crates produce vs consume, cross-crate channels including undeclared ones).
A `syn` or `rust-analyzer` pass would tighten the numbers — worth doing once
the crate structure stabilizes. This extractor prints per-crate stats and
totals so drift from a prior snapshot is legible.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable

# --- Regexes ---------------------------------------------------------------

# Type definitions: struct / enum / type alias (with optional pub visibility).
# Matches identifier that follows. Not tolerant of comments on the same line
# before the keyword; that's fine for typical Rust style.
TYPE_DEF_RE = re.compile(
    r'^\s*(?:pub(?:\s*\([^)]+\))?\s+)?'
    r'(?:struct|enum|type)\s+'
    r'([A-Z][A-Za-z0-9_]*)',
    re.MULTILINE,
)

# Function signatures: matches `fn name(params) -> RetType` across lines.
# We only need the params + return type to extract type references.
FN_SIG_RE = re.compile(
    r'\bfn\s+[A-Za-z_][A-Za-z0-9_]*\s*'
    r'(?:<[^>]*>)?\s*'          # generics on the fn itself (optional)
    r'\(([^)]*)\)'               # param list (naive: no nested parens)
    r'\s*(?:->\s*([^{;]+))?',   # return type up to body or `;`
    re.DOTALL,
)

# Extract capitalized identifiers (candidate type names) inside a snippet.
TYPE_REF_RE = re.compile(r'\b([A-Z][A-Za-z0-9_]*)\b')

# `use zp-something::...` and `use zp_something::...`
USE_RE = re.compile(
    r'^\s*(?:pub\s+)?use\s+((?:zp|mle|monte|trust|course|execution)[A-Za-z0-9_]*)::',
    re.MULTILINE,
)

# Cargo.toml dependency section entries: `zp-foo = ...` under [dependencies]
# / [dev-dependencies] / [build-dependencies].
CARGO_DEP_RE = re.compile(
    r'^\s*((?:zp-|mle-|monte-|trust-|course-|execution-)[A-Za-z0-9_-]+)\s*=',
    re.MULTILINE,
)
CARGO_SECTION_RE = re.compile(r'^\s*\[([^\]]+)\]', re.MULTILINE)

# Receipt slug extraction. Matches `"family:sub:leaf"` string literals whose
# first token is one of the canonical families.
RECEIPT_SLUG_RE = re.compile(
    r'"((?:regent|observation|embodiment|cognitive|coherence|officer|substrate|'
    r'chain|policy|delegation|governance|standing|kinship|artifact|hardening|'
    r'canonicalization|supersession|receipt|audit|content|gate|mesh|ceremony)'
    r'(?::[a-z0-9_]+){1,5})"'
)

# Info-flow signal patterns per class. Substring counts (via str.count), NOT
# regex word-boundary matches — many crypto identifiers appear with underscore
# or `::` suffixes (`ed25519_dalek`, `ed25519::PublicKey`), which \b treats as
# non-boundaries. Substring counting sidesteps that class of miss without
# adding false positives for these terms.
#
# Patterns are deliberately curated — narrow enough to reflect the
# substrate's identity/policy/chain/verify surfaces, wide enough to catch
# the vocabulary the crates actually use. Tune here when new patterns
# emerge; the totals in the manifest legibly show the drift.
SIGN_PATTERNS = [
    '.sign(',
    'SigningKey',
    'HKDF', 'hkdf', 'Hkdf',
    'ed25519',
    'Signer',
    'sign_receipt',
    'derive_key',
]
GATE_PATTERNS = [
    'gate.check',
    'PolicyEngine',
    'verify_delegation',
    'policy_check',
    'check_policy',
    'PolicyGate',
    'evaluate_policy',
    'gate_evaluate',
]
CHAIN_PATTERNS = [
    'chain.append',
    'AuditStore::write',
    'emit_receipt',
    'append_to_chain',
    'ChainEntry',
    'Chain::append',
    'audit_chain',
    'write_receipt',
]
VERIFY_PATTERNS = [
    '.verify(',
    'verify_chain',
    'verify_integrity',
    'verify_signature',
    'Verifier',
    'VerifyingKey',
    'verify_receipt',
]

# Types to skip from type-flow accounting (Rust std / prims / very common).
IGNORE_TYPES = {
    # Primitives / basic
    'String', 'Vec', 'Option', 'Result', 'Box', 'Arc', 'Rc', 'Mutex',
    'RwLock', 'Cell', 'RefCell', 'HashMap', 'HashSet', 'BTreeMap',
    'BTreeSet', 'VecDeque', 'BinaryHeap', 'LinkedList',
    # Common std lib
    'PathBuf', 'Path', 'OsString', 'OsStr', 'CString', 'CStr',
    'File', 'Duration', 'Instant', 'SystemTime',
    'Error', 'Ok', 'Err', 'Some', 'None', 'Send', 'Sync', 'Sized',
    # Serde-family
    'Serialize', 'Deserialize', 'Serializer', 'Deserializer',
    'Value', 'Map',
    # Common integer / float
    'u8', 'u16', 'u32', 'u64', 'u128', 'usize',
    'i8', 'i16', 'i32', 'i64', 'i128', 'isize',
    'f32', 'f64', 'bool', 'char', 'str',
    # Std traits
    'Debug', 'Display', 'Clone', 'Copy', 'Default', 'Hash', 'Eq', 'PartialEq',
    'Ord', 'PartialOrd', 'From', 'Into', 'TryFrom', 'TryInto', 'AsRef', 'AsMut',
    'Iterator', 'IntoIterator', 'Future', 'Fn', 'FnMut', 'FnOnce',
    # anyhow / tokio common
    'Sender', 'Receiver', 'JoinHandle', 'TaskLocal',
    # Common enum variants that are Capitalized
    'Self',
}


# --- Helpers ---------------------------------------------------------------


def crate_name_from_cargo(cargo_toml_path: Path) -> str | None:
    """Read the crate name from a Cargo.toml [package] name = "..." line."""
    try:
        text = cargo_toml_path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return None
    m = re.search(r'^\s*name\s*=\s*"([^"]+)"', text, re.MULTILINE)
    return m.group(1) if m else None


def cargo_deps(cargo_toml_path: Path, known_crates: set[str]) -> list[str]:
    """Return the subset of dependencies from Cargo.toml that name known crates."""
    try:
        text = cargo_toml_path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return []
    deps: set[str] = set()
    # Track which section we're in. Only accept deps in [dependencies],
    # [dev-dependencies], or [build-dependencies].
    accept_sections = {'dependencies', 'dev-dependencies', 'build-dependencies'}
    current: str | None = None
    lines = text.splitlines()
    for line in lines:
        sec = CARGO_SECTION_RE.match(line)
        if sec:
            current = sec.group(1).strip()
            continue
        if current in accept_sections:
            m = CARGO_DEP_RE.match(line)
            if m and m.group(1) in known_crates:
                deps.add(m.group(1))
    return sorted(deps)


def _snake_to_kebab(name: str) -> str:
    return name.replace('_', '-')


def use_deps(text: str, known_crates: set[str], self_name: str) -> set[str]:
    """Extract cross-crate references from `use` statements."""
    found: set[str] = set()
    for m in USE_RE.finditer(text):
        raw = m.group(1)
        # `use foo_bar::...` in Rust corresponds to crate `foo-bar` on disk.
        kebab = _snake_to_kebab(raw)
        if kebab in known_crates and kebab != self_name:
            found.add(kebab)
    return found


def count_signals(text: str, patterns: list[str]) -> int:
    """Substring-count each pattern in text and sum."""
    return sum(text.count(p) for p in patterns)


def extract_types_defined(text: str) -> list[str]:
    """Return type names defined in this source text."""
    return [m.group(1) for m in TYPE_DEF_RE.finditer(text)]


def extract_type_refs_in_fn_sigs(text: str) -> Counter[str]:
    """
    Walk each fn signature in the text and collect capitalized identifiers
    from its parameter list and return type. Multiple occurrences count.
    """
    refs: Counter[str] = Counter()
    for m in FN_SIG_RE.finditer(text):
        params = m.group(1) or ''
        ret = m.group(2) or ''
        chunk = params + ' | ' + ret
        for r in TYPE_REF_RE.finditer(chunk):
            name = r.group(1)
            if name in IGNORE_TYPES:
                continue
            refs[name] += 1
    return refs


def extract_receipt_slugs(text: str) -> list[str]:
    return [m.group(1) for m in RECEIPT_SLUG_RE.finditer(text)]


def primary_role(sign: int, gate: int, chain: int, verify: int,
                 receipt_slug_total: int) -> str:
    """Pick the crate's dominant info-flow role."""
    scores = {
        'signing': sign,
        'gating': gate,
        'chain-emit': chain,
        'verifying': verify,
    }
    top = max(scores.values())
    if top == 0:
        # No infrastructure signals — receipt authorship or utility.
        return 'receipt-authoring' if receipt_slug_total >= 5 else 'utility'
    # Argmax with deterministic tie-break by declaration order.
    for name, val in scores.items():
        if val == top:
            # But if receipt authorship dominates over the top signal, promote it.
            if receipt_slug_total > top:
                return 'receipt-authoring'
            return name
    return 'utility'


# --- Main extractor --------------------------------------------------------


def find_crate_dirs(repo_root: Path, include_tools: bool) -> list[Path]:
    """Return all crate directories that have a Cargo.toml and any .rs source.

    Accepts crates that have `src/`, `benches/`, or `examples/` — anything
    with a Cargo.toml and at least one Rust file counts.
    """
    roots = ['crates']
    if include_tools:
        roots.append('tools')
    crates: list[Path] = []
    for r in roots:
        base = repo_root / r
        if not base.is_dir():
            continue
        for child in sorted(base.iterdir()):
            if not child.is_dir():
                continue
            if not (child / 'Cargo.toml').is_file():
                continue
            # Check for any .rs file anywhere under the crate.
            if any(child.rglob('*.rs')):
                crates.append(child)
    return crates


def walk_rs_files(crate_dir: Path) -> Iterable[Path]:
    """All .rs files under the crate (src, benches, examples, tests)."""
    return sorted(crate_dir.rglob('*.rs'))


def build_manifest(repo_root: Path, include_tools: bool = False) -> dict:
    """Walk the source tree and produce the manifest dict."""

    crate_dirs = find_crate_dirs(repo_root, include_tools)
    # First pass: discover crate names, per-file contents, per-file type defs.
    crate_info: dict[str, dict] = {}
    all_type_definitions: dict[str, str] = {}  # type_name -> owning_crate

    for cdir in crate_dirs:
        name = crate_name_from_cargo(cdir / 'Cargo.toml')
        if not name:
            # Fall back to directory name if Cargo.toml has no package.name
            name = cdir.name
        # Prefer the on-disk directory name for cross-crate matching, since
        # Cargo.toml package names sometimes use `_` while dirs use `-`.
        # Convention: use directory name as the canonical crate identifier.
        name = cdir.name
        info = {
            'name': name,
            'dir': cdir,
            'files': 0,
            'loc': 0,
            'sign_count': 0,
            'gate_count': 0,
            'chain_count': 0,
            'verify_count': 0,
            'receipt_slugs': [],
            'type_defs': [],
            'text_bundle': [],  # concatenated source for later passes
        }
        for rs_path in walk_rs_files(cdir):
            try:
                text = rs_path.read_text(encoding='utf-8', errors='replace')
            except OSError:
                continue
            info['files'] += 1
            info['loc'] += text.count('\n')
            info['sign_count'] += count_signals(text, SIGN_PATTERNS)
            info['gate_count'] += count_signals(text, GATE_PATTERNS)
            info['chain_count'] += count_signals(text, CHAIN_PATTERNS)
            info['verify_count'] += count_signals(text, VERIFY_PATTERNS)
            info['receipt_slugs'].extend(extract_receipt_slugs(text))
            info['type_defs'].extend(extract_types_defined(text))
            info['text_bundle'].append(text)
        crate_info[name] = info

    known_crates = set(crate_info.keys())

    # Register every type definition under its owning crate.
    for cname, info in crate_info.items():
        for t in info['type_defs']:
            if t in IGNORE_TYPES:
                continue
            # First writer wins; if a type name is (re)defined in multiple crates,
            # attribute to the first alphabetical crate to keep deterministic.
            if t not in all_type_definitions:
                all_type_definitions[t] = cname

    # Second pass: dependencies + type-flow.
    # Per-crate: types_produced (owned defs referenced anywhere), types_consumed
    # (references to types owned by OTHER crates), edges aggregated per pair.

    edge_types: dict[tuple[str, str], Counter[str]] = defaultdict(Counter)
    per_crate_produced: dict[str, Counter[str]] = defaultdict(Counter)
    per_crate_consumed: dict[str, Counter[str]] = defaultdict(Counter)

    for cname, info in crate_info.items():
        full_text = '\n'.join(info['text_bundle'])
        refs = extract_type_refs_in_fn_sigs(full_text)
        for tname, count in refs.items():
            owner = all_type_definitions.get(tname)
            if not owner:
                continue  # Not an owned substrate type; skip.
            if owner == cname:
                per_crate_produced[cname][tname] += count
            else:
                per_crate_consumed[cname][tname] += count
                edge_types[(owner, cname)][tname] += count

        # Compute deps: Cargo.toml + use statements.
        deps_cargo = cargo_deps(info['dir'] / 'Cargo.toml', known_crates)
        deps_use = use_deps(full_text, known_crates, cname)
        deps = sorted(set(deps_cargo) | deps_use)
        info['deps'] = [d for d in deps if d != cname]

    # Build consumers (reverse dep map).
    consumers: dict[str, list[str]] = defaultdict(list)
    for cname, info in crate_info.items():
        for dep in info['deps']:
            consumers[dep].append(cname)

    # Assemble output records.
    crates_out: list[dict] = []
    total_sign = total_gate = total_chain = total_verify = 0
    total_receipts = total_deps = total_types = total_typeflow_sig = 0

    # Sort crates alphabetically for deterministic output.
    for cname in sorted(crate_info.keys()):
        info = crate_info[cname]
        receipt_slugs = info['receipt_slugs']
        slug_counter = Counter(receipt_slugs)
        # Receipt families: first token of the slug.
        families = Counter(s.split(':', 1)[0] for s in receipt_slugs)
        types_produced = per_crate_produced.get(cname, Counter())
        types_consumed = per_crate_consumed.get(cname, Counter())

        info_flow_signal = (
            info['sign_count'] + info['gate_count']
            + info['chain_count'] + info['verify_count']
        )
        role = primary_role(
            info['sign_count'], info['gate_count'],
            info['chain_count'], info['verify_count'],
            len(receipt_slugs),
        )

        crates_out.append({
            'name': cname,
            'files': info['files'],
            'loc': info['loc'],
            'deps': info['deps'],
            'sign_count': info['sign_count'],
            'gate_count': info['gate_count'],
            'chain_count': info['chain_count'],
            'verify_count': info['verify_count'],
            'receipt_families': dict(families.most_common()),
            'receipt_slugs_sample': [s for s, _ in slug_counter.most_common(12)],
            'receipt_slug_total': len(receipt_slugs),
            'info_flow_signal': info_flow_signal,
            'primary_role': role,
            'consumed_by': sorted(consumers.get(cname, [])),
            'type_defs': sorted(set(info['type_defs']) - IGNORE_TYPES),
            'type_defs_count': len(set(info['type_defs']) - IGNORE_TYPES),
            'types_produced': dict(types_produced.most_common()),
            'types_consumed': dict(types_consumed.most_common()),
            'type_flow_signal': sum(types_produced.values()) + sum(types_consumed.values()),
            'types_produced_total': sum(types_produced.values()),
            'types_consumed_total': sum(types_consumed.values()),
        })

        total_sign += info['sign_count']
        total_gate += info['gate_count']
        total_chain += info['chain_count']
        total_verify += info['verify_count']
        total_receipts += len(receipt_slugs)
        total_deps += len(info['deps'])
        total_types += len(set(info['type_defs']) - IGNORE_TYPES)
        total_typeflow_sig += sum(types_produced.values()) + sum(types_consumed.values())

    # Edges: sort by weight desc for stable ordering.
    edges_out: list[dict] = []
    for (src, dst), types in edge_types.items():
        edges_out.append({
            'from': src,
            'to': dst,
            'weight': sum(types.values()),
            'types': dict(types.most_common(12)),
        })
    edges_out.sort(key=lambda e: (-e['weight'], e['from'], e['to']))

    manifest = {
        'generated_at': int(time.time()),
        'crates': crates_out,
        'counts': {
            'total_crates': len(crates_out),
            'total_deps_edges': total_deps,
            'total_sign_sites': total_sign,
            'total_gate_crossings': total_gate,
            'total_chain_emits': total_chain,
            'total_verifications': total_verify,
            'total_receipt_slugs': total_receipts,
            'total_type_flow_signal': total_typeflow_sig,
            'total_type_defs': total_types,
            'total_type_flow_edges': len(edges_out),
        },
        'type_flow_edges': edges_out,
    }
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument(
        '--repo-root', default='.', type=Path,
        help='Repo root (default: current directory).',
    )
    parser.add_argument(
        '--out', default=None, type=Path,
        help='Output manifest path (default: <repo-root>/docs/lenses/source-manifest.json).',
    )
    parser.add_argument(
        '--include-tools', action='store_true',
        help='Also scan tools/*/src/**/*.rs (default: crates only).',
    )
    args = parser.parse_args()

    repo_root = args.repo_root.resolve()
    out_path = args.out or (repo_root / 'docs' / 'lenses' / 'source-manifest.json')
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if not (repo_root / 'crates').is_dir():
        print(f'error: no crates/ under {repo_root}', file=sys.stderr)
        return 1

    manifest = build_manifest(repo_root, include_tools=args.include_tools)
    out_path.write_text(json.dumps(manifest, indent=2), encoding='utf-8')

    c = manifest['counts']
    print(f'wrote {out_path}')
    print(f'  {c["total_crates"]} crates, '
          f'{c["total_deps_edges"]} deps, '
          f'{c["total_type_defs"]} type defs, '
          f'{c["total_type_flow_edges"]} type-flow edges, '
          f'{c["total_type_flow_signal"]} type-flow signals')
    print(f'  sign={c["total_sign_sites"]} '
          f'gate={c["total_gate_crossings"]} '
          f'chain={c["total_chain_emits"]} '
          f'verify={c["total_verifications"]} '
          f'receipts={c["total_receipt_slugs"]}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
