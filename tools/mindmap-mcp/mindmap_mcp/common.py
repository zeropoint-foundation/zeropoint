"""Shared schema, validation, and normalization for mindmap structures.

One canonical shape flows through the system regardless of which extraction
rung produced it or which theme is rendering it. Match the discipline used in
youtube-transcript-mcp/common.py — one normalized record, many producers.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, TypedDict


# ---------------------------------------------------------------------------
# Rung labels — the provenance recorded on every mindmap.
# ---------------------------------------------------------------------------
SOURCE_MANUAL = "manual"
SOURCE_OPENAI = "openai"
SOURCE_ANTHROPIC = "anthropic"
SOURCE_LOCAL = "local"
SOURCE_CACHE = "cache"


# ---------------------------------------------------------------------------
# Palette identifiers — resolved to colors in themes.py per active theme.
# ---------------------------------------------------------------------------
PALETTE_COLORS = ("teal", "coral", "lavender", "saffron", "sage", "rose")


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------
class RungDisabled(Exception):
    """A rung is intentionally not active (missing dependency or config)."""


class RungFailed(Exception):
    """A rung attempted the extraction and could not produce a mindmap."""


class MindmapUnavailable(Exception):
    """Every enabled rung failed. Carries per-rung reasons for diagnosis."""

    def __init__(self, reasons: Dict[str, str]):
        self.reasons = reasons
        detail = "; ".join(f"{rung}: {why}" for rung, why in reasons.items())
        super().__init__(f"No mindmap could be extracted. Rung results -> {detail}")


class MindmapInvalid(ValueError):
    """The mindmap dict does not match the schema."""


# ---------------------------------------------------------------------------
# Normalized shapes
# ---------------------------------------------------------------------------
class Leaf(TypedDict, total=False):
    label: str


class SubBranch(TypedDict, total=False):
    label: str
    children: List[Leaf]


class Branch(TypedDict, total=False):
    label: str
    emoji: str
    color: str
    children: List[SubBranch]


class Center(TypedDict, total=False):
    label: str
    emoji: str


class Mindmap(TypedDict, total=False):
    title: str
    subtitle: str
    center: Center
    branches: List[Branch]
    footnotes: List[str]
    # provenance
    source: str
    generated_at: str


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
def _clip(s: Any, limit: int = 200) -> str:
    text = str(s or "").strip()
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"


def validate_mindmap(data: Any) -> Mindmap:
    """Coerce and validate a mindmap dict into the canonical shape.

    Raises MindmapInvalid on structural problems. Silently trims oversized
    strings and clamps out-of-range palette identifiers to a valid default.
    """
    if not isinstance(data, dict):
        raise MindmapInvalid(f"Mindmap must be a dict, got {type(data).__name__}")

    title = _clip(data.get("title") or "Untitled Mindmap", 200)
    subtitle = _clip(data.get("subtitle") or "", 300)

    center_in = data.get("center") or {}
    if not isinstance(center_in, dict):
        raise MindmapInvalid("`center` must be an object")
    center: Center = {
        "label": _clip(center_in.get("label") or title, 80),
        "emoji": _clip(center_in.get("emoji") or "", 8),
    }

    branches_in = data.get("branches") or []
    if not isinstance(branches_in, list) or not branches_in:
        raise MindmapInvalid("`branches` must be a non-empty list")
    if len(branches_in) > 10:
        raise MindmapInvalid(f"`branches` capped at 10 (got {len(branches_in)})")

    branches: List[Branch] = []
    for i, b in enumerate(branches_in):
        if not isinstance(b, dict):
            raise MindmapInvalid(f"branch[{i}] must be a dict")
        color = str(b.get("color") or PALETTE_COLORS[i % len(PALETTE_COLORS)]).lower()
        if color not in PALETTE_COLORS:
            color = PALETTE_COLORS[i % len(PALETTE_COLORS)]
        children_in = b.get("children") or []
        if not isinstance(children_in, list):
            raise MindmapInvalid(f"branch[{i}].children must be a list")
        subs: List[SubBranch] = []
        for j, s in enumerate(children_in):
            if not isinstance(s, dict):
                raise MindmapInvalid(f"branch[{i}].children[{j}] must be a dict")
            leaves_in = s.get("children") or []
            if not isinstance(leaves_in, list):
                raise MindmapInvalid(
                    f"branch[{i}].children[{j}].children must be a list"
                )
            leaves: List[Leaf] = [
                {"label": _clip(l.get("label") or "", 80)}
                for l in leaves_in
                if isinstance(l, dict) and _clip(l.get("label") or "", 80)
            ]
            subs.append(
                {
                    "label": _clip(s.get("label") or "", 80),
                    "children": leaves,
                }
            )
        branches.append(
            {
                "label": _clip(b.get("label") or f"Branch {i+1}", 60),
                "emoji": _clip(b.get("emoji") or "", 8),
                "color": color,
                "children": subs,
            }
        )

    footnotes_in = data.get("footnotes") or []
    footnotes: List[str] = [
        _clip(f, 200) for f in footnotes_in if isinstance(f, str) and _clip(f, 200)
    ][:6]

    out: Mindmap = {
        "title": title,
        "subtitle": subtitle,
        "center": center,
        "branches": branches,
        "footnotes": footnotes,
        "source": _clip(data.get("source") or SOURCE_MANUAL, 40),
        "generated_at": _clip(data.get("generated_at") or now_iso(), 40),
    }
    return out


# ---------------------------------------------------------------------------
# Video-id parsing borrowed inline (kept tiny so this module has no import
# dependency on youtube-transcript-mcp — the two tools compose but don't
# hard-couple). Same regex as the transcript tool.
# ---------------------------------------------------------------------------
_YOUTUBE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{11}$")


def is_youtube_ref(value: str) -> bool:
    v = (value or "").strip().lower()
    return bool(v) and (
        _YOUTUBE_ID_RE.match(value.strip())
        or "youtube.com" in v
        or "youtu.be" in v
    )


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def summary(mindmap: Mindmap) -> Dict[str, Any]:
    """Compact metadata-only view for logging / markdown."""
    return {
        "title": mindmap.get("title"),
        "center": (mindmap.get("center") or {}).get("label"),
        "branches": len(mindmap.get("branches") or []),
        "leaf_count": sum(
            len(s.get("children") or [])
            for b in mindmap.get("branches") or []
            for s in b.get("children") or []
        ),
        "source": mindmap.get("source"),
        "generated_at": mindmap.get("generated_at"),
    }
