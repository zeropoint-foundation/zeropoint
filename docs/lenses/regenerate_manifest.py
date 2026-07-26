#!/usr/bin/env python3
"""
Regenerates docs/lenses/manifest.json — the corpus manifest that drives
`zeropoint-through-four-lenses.html`. Walks `docs/**/*.md` and produces one
record per document.

Per document, extracts:
- Filename, title (H1 or first non-empty heading), tier (1/2/3 based on
  declared markers), subdir (design/handoffs/root), mtime, word count.
- Declared date (`--- 2026-07-DD ---` in body, or `Date: 2026-07-DD` in
  front-matter-style, or `-2026-07-DD` suffix in filename as fallback).
- Author (from `**Author:**` line).
- Build state: `built | partial | scaffolded | candidate | unknown`
  (plus `keel` for the KEEL document itself), derived from:
    * Cross-referencing code mentions (`zp-*`, `mle-star-engine`,
      `tools/*` paths) against what actually exists in the repo tree.
    * Counting aspirational phrases ("not yet implemented",
      "blocked on", "immediate design work", "pending implementation").
- `cm` (code_mentions found AND existing in repo).
- `cx` (code_mentions found but NOT existing in repo — spec'd/candidate).
- `asp` (aspirational-phrase count).
- `cw` (composes-with — outgoing references to other docs).
- `cb` (composed-by — inbound reverse edges).

Compact field names (`f`, `t`, `tr`, `sd`, `mt`, `wc`, `au`, `dd`, `bs`,
`cm`, `cx`, `asp`, `cw`, `cb`) are used to keep the manifest small enough
to inline into the HTML artifact.

Usage:
    cd <repo-root>
    python3 docs/lenses/regenerate_manifest.py [--out PATH] [--root DOC]

Output: writes JSON to <out> (default: docs/lenses/manifest.json). The
`root` field identifies the corpus root (default: KEEL-2026-07.md); the
Weave and CodeFlow lenses use this as the center/left-edge anchor.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path


# --- Config ---------------------------------------------------------------

DEFAULT_ROOT = 'KEEL-2026-07.md'

# Directories under the repo root treated as "code" for cross-reference.
# Presence of a subdir under any of these = the code_mention exists.
CODE_ROOTS = ['crates', 'tools']

# Additional top-level repo directories to treat as code identifiers. Docs
# reference things like `clawd`, `dashboard`, `frameworks`, `core`, `cli`
# without a `crates/` or `tools/` prefix — those dirs live at the repo
# root, not inside crates/. Include them so cross-referencing resolves.
# The blocklist keeps documentation/data/config dirs out of the code set.
INCLUDE_TOPLEVEL = True
TOPLEVEL_BLOCKLIST = {
    'archive', 'assets', 'certs', 'config', 'data', 'deploy', 'docker',
    'docs', 'entitlements', 'governance', 'graph-viz-wasm', 'graphify-out',
    'graphiti', 'INPUT', 'logs', 'miniCPM-o-4_5', 'models', 'node_modules',
    'nomadnet-pages', 'policies', 'proto', 'release_pkg', 'reticulum-meshchat',
    'sandbox', 'sbom', 'scripts', 'security', 'services', 'sidecar', 'spec',
    'target', 'test-outputs', 'tests', 'third_party', 'video-assets',
    'wasm-modules', 'webui-next', 'ZeroPoint', 'zeropoint-py', 'zeropoint-server',
    'zeropoint.global', 'zeropointfoundation.org', 'zp-artemis-relay',
    'merlin-sentinel-deploy',
}

# Aspirational-phrase signals used to bump toward `candidate` / `scaffolded`
# build states even when code_mentions exist.
ASPIRATIONAL_PATTERNS = [
    re.compile(r'\bnot yet implemented\b', re.IGNORECASE),
    re.compile(r'\bblocked on\b', re.IGNORECASE),
    re.compile(r'\bimmediate design work\b', re.IGNORECASE),
    re.compile(r'\bpending implementation\b', re.IGNORECASE),
    re.compile(r'\bwill be implemented\b', re.IGNORECASE),
    re.compile(r'\bproposed:\b', re.IGNORECASE),
    re.compile(r'\bfollow[-\s]?up work\b', re.IGNORECASE),
    re.compile(r'\bnot yet built\b', re.IGNORECASE),
    re.compile(r'\bto be added\b', re.IGNORECASE),
    re.compile(r'\bpicked up (?:in|via) follow[-\s]?up\b', re.IGNORECASE),
    re.compile(r'\bfuture work\b', re.IGNORECASE),
    re.compile(r'\bstill to (?:build|implement)\b', re.IGNORECASE),
    re.compile(r'\bnot yet integrated\b', re.IGNORECASE),
    re.compile(r'\bcandidate\b(?!\s+lineup)', re.IGNORECASE),  # allow tenant-candidate-lineup
    re.compile(r'\bTBD\b'),
    re.compile(r'\bTODO\b'),
]

# Regex to extract crate/tool mentions from doc body.
# Matches: zp-foo, mle-star-engine, monte-carlo-engine, trust-triangle,
#          course-examples, execution-engine, tools/<name>, crates/<name>.
# The zp- variant requires at least 2 chars after the dash and disallows
# a trailing dash — otherwise `zp-` alone in prose ("the zp- prefix") and
# fragments like `zp-foo-` sweep in as false positives.
CODE_MENTION_RE = re.compile(
    r'\b('
    r'zp-[a-z][a-z0-9]+(?:-[a-z0-9]+)*'
    r'|mle-star-engine'
    r'|monte-carlo-engine'
    r'|trust-triangle'
    r'|course-examples'
    r'|execution-engine'
    r')\b'
)
# tools/foo, crates/foo — top-level path references only. Negative
# lookbehinds keep us from matching a nested `src/tools/wasm/...` (which
# is a submodule inside a crate, not the top-level tools/ tree).
# Require ≥3 char identifier (rejects `crates/zp` fragments that come from
# truncated `crates/zp-foo` matches in prose).
TOOL_PATH_RE = re.compile(r'(?<!/)(?<!\w)tools/([a-z][a-z0-9-]{2,}[a-z0-9])')
CRATE_PATH_RE = re.compile(r'(?<!/)(?<!\w)crates/([a-z][a-z0-9-]{2,}[a-z0-9])')

# Composes-with extraction. The composes-with relationship is a declared
# structural claim, not "any doc name that appears in body prose". Three
# channels contribute:
#   1. Explicit `composes with` / `composition` section body.
#   2. Front-matter-style `**Composes with:** ...` and `**Elaborates:** ...`
#      lines.
#   3. Backtick-wrapped `X.md` references anywhere in the body — these are
#      the substrate's convention for citing another doc (bare `X.md` in
#      prose without backticks is treated as incidental mention, not edge).
# A prose backtick reference is the substrate's structural citation
# gesture; matching every non-backtick .md mention would over-count.
DOC_REF_BACKTICK_RE = re.compile(
    r'`([A-Z][A-Za-z0-9_-]+(?:-\d{4}-\d{2})?\.md)`',
)
DOC_REF_ANY_RE = re.compile(
    r'\b([A-Z][A-Za-z0-9_-]+(?:-\d{4}-\d{2})?\.md)\b',
)
COMPOSES_SECTION_HEADING_RE = re.compile(
    r'(?im)^#+\s*(?:composes[-\s]?with|composition|composes\s+with\s*/\s*connects\s+to|what\s+composes\s+from\s+here|composes\s+with\s+/\s+connects\s+to)\b',
)
COMPOSES_INLINE_RE = re.compile(
    r'(?im)^\s*(?:\*\*)?(?:composes[-\s]?with|elaborates)(?:\*\*)?\s*:\s*(.+?)(?:\n\s*\n|$)',
    re.DOTALL,
)

# Explicit tier markers in doc body.
TIER_RE = re.compile(
    r'\*\*(?:Document\s+type|Tier)\s*:\*\*\s*Tier\s*(\d)',
    re.IGNORECASE,
)
TIER_ADJ_RE = re.compile(r'\*\*Tier\s*(\d)\s+canonical\s+elaboration\.?\*\*', re.IGNORECASE)

# Declared date extraction.
DATE_BODY_RE = re.compile(r'\*\*Date\s*:\*\*\s*(20\d{2}-\d{2}-\d{2})', re.IGNORECASE)
DATE_HEADING_RE = re.compile(r'^\s*(?:—|-|–)\s*(20\d{2}-\d{2}-\d{2})\s*—?\s*', re.MULTILINE)
DATE_FILENAME_RE = re.compile(r'-(20\d{2}-\d{2})(?:-\d{2})?\.md$')
AUTHOR_RE = re.compile(r'\*\*Author\s*:\*\*\s*([^\n\r]+?)(?:\.|$)', re.IGNORECASE)


# --- Helpers --------------------------------------------------------------


def extract_title(text: str, fallback_filename: str) -> str:
    """Return the first H1 heading; fall back to filename stem."""
    m = re.search(r'^#\s+([^\n]+)', text, re.MULTILINE)
    if m:
        return m.group(1).strip()
    return fallback_filename.replace('.md', '')


def extract_tier(text: str) -> int | None:
    """Detect tier from body markers. Returns 1/2/3 or None."""
    m = TIER_ADJ_RE.search(text)
    if m:
        return int(m.group(1))
    m = TIER_RE.search(text)
    if m:
        return int(m.group(1))
    return None


def extract_declared_date(text: str, filename: str) -> str | None:
    """Extract declared date — prefer body signal, fall back to filename."""
    m = DATE_BODY_RE.search(text)
    if m:
        return m.group(1)
    m = DATE_HEADING_RE.search(text)
    if m:
        return m.group(1)
    m = DATE_FILENAME_RE.search(filename)
    if m:
        return m.group(1) + '-01'  # first of month for month-only dates
    return None


def extract_author(text: str) -> str | None:
    m = AUTHOR_RE.search(text)
    if not m:
        return None
    val = m.group(1).strip().rstrip('.').strip()
    return val or None


def extract_code_mentions(text: str) -> set[str]:
    """Extract crate/tool identifiers referenced in the doc."""
    found: set[str] = set()
    for m in CODE_MENTION_RE.finditer(text):
        found.add(m.group(1))
    for m in TOOL_PATH_RE.finditer(text):
        found.add(m.group(1))
    for m in CRATE_PATH_RE.finditer(text):
        found.add(m.group(1))
    return found


def _harvest_doc_refs(
    chunk: str, doc_set: set[str], self_name: str,
    use_pattern: re.Pattern[str],
) -> set[str]:
    out: set[str] = set()
    for m in use_pattern.finditer(chunk):
        candidate = m.group(1)
        if candidate == self_name:
            continue
        if candidate in doc_set:
            out.add(candidate)
    return out


def extract_composes_with(text: str, doc_set: set[str], self_name: str) -> list[str]:
    """
    Extract outgoing composes-with edges. Three sources:
      1. Explicit `## Composes with` (or similar) section body — any doc
         reference within (backticks optional).
      2. Front-matter-style `**Composes with:** ...` / `**Elaborates:** ...`
         declarations (any doc reference within, backticks optional).
      3. Backtick-wrapped `X.md` references anywhere in the body —
         the substrate's structural citation convention. Bare `X.md` in
         prose without backticks is treated as incidental mention, not edge.
    """
    found: set[str] = set()

    # (1) Explicit section body — reference syntax is loose (backticks
    # optional, since composes-with sections list bare filenames too).
    for hm in COMPOSES_SECTION_HEADING_RE.finditer(text):
        start = hm.end()
        next_heading = re.search(r'^#{1,3}\s+', text[start:], re.MULTILINE)
        end = start + next_heading.start() if next_heading else len(text)
        section = text[start:end]
        found |= _harvest_doc_refs(section, doc_set, self_name, DOC_REF_ANY_RE)

    # (2) Inline front-matter-style declarations.
    for im in COMPOSES_INLINE_RE.finditer(text):
        chunk = im.group(1).split('\n\n', 1)[0]
        found |= _harvest_doc_refs(chunk, doc_set, self_name, DOC_REF_ANY_RE)

    # (3) Backtick-wrapped doc references in prose (structural citations).
    found |= _harvest_doc_refs(text, doc_set, self_name, DOC_REF_BACKTICK_RE)

    return sorted(found)


def count_aspirational(text: str) -> int:
    return sum(len(p.findall(text)) for p in ASPIRATIONAL_PATTERNS)


def classify_build_state(cm: set[str], cx: set[str], asp: int, filename: str) -> str:
    """
    Cross-reference code mentions and aspirational signals to classify.
    - keel: KEEL itself
    - built: has code mentions, all exist, low aspirational signal
    - partial: has code mentions with some missing OR moderate aspirational
    - scaffolded: has code mentions, most exist, high aspirational signal
    - candidate: mostly missing code mentions OR very high aspirational
    - unknown: no code mentions at all
    """
    if filename.startswith('KEEL-') and filename.endswith('.md'):
        return 'keel'
    total_mentions = len(cm) + len(cx)
    if total_mentions == 0:
        # No code mentions — classify by aspirational count alone
        if asp >= 3:
            return 'candidate'
        return 'unknown'
    missing_ratio = len(cx) / total_mentions if total_mentions else 0.0
    if missing_ratio >= 0.7:
        return 'candidate'
    if missing_ratio >= 0.4:
        return 'scaffolded' if asp >= 2 else 'partial'
    if asp >= 4:
        return 'scaffolded'
    if asp >= 2 or missing_ratio >= 0.15:
        return 'partial'
    return 'built'


def find_existing_code(repo_root: Path) -> set[str]:
    """Enumerate directories that a doc mention can resolve against.

    Includes: children of `crates/` and `tools/`, plus optionally top-level
    repo dirs that are code (excluding the documentation/data/config
    blocklist).
    """
    found: set[str] = set()
    for root in CODE_ROOTS:
        base = repo_root / root
        if not base.is_dir():
            continue
        for child in base.iterdir():
            if child.is_dir() and not child.name.startswith('.'):
                found.add(child.name)
    if INCLUDE_TOPLEVEL:
        for child in repo_root.iterdir():
            if not child.is_dir():
                continue
            if child.name.startswith('.'):
                continue
            if child.name in TOPLEVEL_BLOCKLIST:
                continue
            if child.name in CODE_ROOTS:
                continue  # already walked
            found.add(child.name)
    return found


def collect_docs(docs_root: Path, include_subdirs: set[str] | None) -> list[Path]:
    """
    All .md files under docs/, filtered to root + a subset of subdirs.

    - Root-level docs (immediate children of docs/) are always included.
    - Files under any subdir in `include_subdirs` are included.
    - _to_delete/ subtrees are always skipped.

    If `include_subdirs` is None, walks every subdir (exhaustive mode).
    """
    out: list[Path] = []
    for p in docs_root.rglob('*.md'):
        parts = p.parts
        # Skip trash / _to_delete/ subtrees.
        if any(part.startswith('_to_delete') for part in parts):
            continue
        rel = p.relative_to(docs_root).parts
        if len(rel) == 1:
            # Root-level doc under docs/
            out.append(p)
        else:
            top = rel[0]
            if include_subdirs is None or top in include_subdirs:
                out.append(p)
    return sorted(out)


# --- Main -----------------------------------------------------------------


# Which subdirs of docs/ the artifact renders. Docs outside these subdirs
# (course/, foundations/, sage-identity/, etc.) exist but wouldn't show up
# in the visualization, so the extractor excludes them by default.
DEFAULT_SUBDIRS = {'design', 'handoffs'}


def build_manifest(
    repo_root: Path, root_doc: str,
    include_subdirs: set[str] | None = None,
) -> dict:
    docs_root = repo_root / 'docs'
    if not docs_root.is_dir():
        raise FileNotFoundError(f'docs/ not found under {repo_root}')

    existing_code = find_existing_code(repo_root)

    scope = include_subdirs if include_subdirs is not None else DEFAULT_SUBDIRS
    # First pass: gather doc set (for composes-with resolution).
    all_paths = collect_docs(docs_root, scope)
    doc_set = {p.name for p in all_paths}

    docs_out: list[dict] = []
    forward_edges: dict[str, list[str]] = defaultdict(list)

    for path in all_paths:
        try:
            text = path.read_text(encoding='utf-8', errors='replace')
        except OSError:
            continue
        rel_parts = path.relative_to(docs_root).parts
        subdir = rel_parts[0] if len(rel_parts) > 1 else ''
        filename = path.name

        title = extract_title(text, filename)
        tier = extract_tier(text)
        # Defaults: root docs (KEEL, corpus-index) get tier 1; design/handoffs default 2/3.
        if tier is None:
            if filename == root_doc:
                tier = 1
            elif subdir == 'handoffs':
                tier = 3
            else:
                tier = 2

        declared_date = extract_declared_date(text, filename)
        author = extract_author(text)
        word_count = len(text.split())

        raw_mentions = extract_code_mentions(text)
        cm = sorted(raw_mentions & existing_code)
        cx = sorted(raw_mentions - existing_code)
        asp = count_aspirational(text)
        build_state = classify_build_state(set(cm), set(cx), asp, filename)

        composes = extract_composes_with(text, doc_set, filename)
        for ref in composes:
            forward_edges[filename].append(ref)

        docs_out.append({
            'f': filename,
            't': title,
            'tr': tier,
            'sd': subdir,
            'mt': int(path.stat().st_mtime),
            'wc': word_count,
            'au': author,
            'dd': declared_date,
            'bs': build_state,
            'cm': cm,
            'cx': cx,
            'asp': asp,
            'cw': composes,
        })

    # Second pass: build reverse edges (composed-by).
    reverse_edges: dict[str, list[str]] = defaultdict(list)
    for src, dsts in forward_edges.items():
        for dst in dsts:
            reverse_edges[dst].append(src)
    for d in docs_out:
        d['cb'] = sorted(reverse_edges.get(d['f'], []))

    # Sort docs alphabetically for deterministic output.
    docs_out.sort(key=lambda d: d['f'])

    # Counts / stats.
    total = len(docs_out)
    by_tier = Counter(d['tr'] for d in docs_out)
    by_bs = Counter(d['bs'] for d in docs_out)
    with_edges = sum(1 for d in docs_out if d['cw'])
    total_edges = sum(len(d['cw']) for d in docs_out)

    manifest = {
        'generated_at': int(time.time()),
        'docs': docs_out,
        'counts': {
            'total': total,
            'tier_1': by_tier.get(1, 0),
            'tier_2': by_tier.get(2, 0),
            'tier_3': by_tier.get(3, 0),
            'with_edges': with_edges,
            'total_edges': total_edges,
            'by_build_state': dict(by_bs),
        },
        'root': root_doc,
        'existing_code': sorted(existing_code),
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
        help='Output manifest path (default: <repo-root>/docs/lenses/manifest.json).',
    )
    parser.add_argument(
        '--root', default=DEFAULT_ROOT,
        help=f'Corpus root doc for lens anchoring (default: {DEFAULT_ROOT}).',
    )
    parser.add_argument(
        '--all-subdirs', action='store_true',
        help='Walk every subdir under docs/, not just design/ and handoffs/. '
             'Default scope matches what the artifact renders.',
    )
    args = parser.parse_args()

    repo_root = args.repo_root.resolve()
    out_path = args.out or (repo_root / 'docs' / 'lenses' / 'manifest.json')
    out_path.parent.mkdir(parents=True, exist_ok=True)

    include_subdirs = None if args.all_subdirs else DEFAULT_SUBDIRS
    manifest = build_manifest(repo_root, args.root, include_subdirs=include_subdirs)
    out_path.write_text(json.dumps(manifest, indent=2), encoding='utf-8')

    c = manifest['counts']
    print(f'wrote {out_path}')
    print(f'  {c["total"]} docs '
          f'(tier1={c["tier_1"]} tier2={c["tier_2"]} tier3={c["tier_3"]})')
    print(f'  {c["with_edges"]} docs with composes-with edges, '
          f'{c["total_edges"]} total edges')
    print(f'  build states: {c["by_build_state"]}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
