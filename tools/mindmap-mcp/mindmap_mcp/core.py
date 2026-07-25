"""Ladder orchestration for extraction + a stable public API.

Just like the transcript tool, this module is free of MCP concerns so that
ZeroPoint (or any Python caller) can consume it directly:

    from mindmap_mcp.core import extract_mindmap, render_mindmap
    mm = extract_mindmap(long_text, provider="auto")
    html = render_mindmap(mm, theme="mylens")

The extraction ladder is:

    cache  →  openai  →  anthropic  →  local  (any OpenAI-compatible endpoint)

Each rung is optional: RungDisabled if its config is missing, RungFailed if
it tried and could not deliver. The orchestration is identical to the
transcript tool's — the diagnostic UX is worth the copy-paste.
"""

from __future__ import annotations

import json
import logging
import os
import textwrap
from typing import Any, Callable, Dict, List, Optional

import requests

from .common import (
    Mindmap,
    MindmapUnavailable,
    RungDisabled,
    RungFailed,
    SOURCE_ANTHROPIC,
    SOURCE_LOCAL,
    SOURCE_OPENAI,
    now_iso,
    summary,
    validate_mindmap,
)
from .renderer import render_html, render_svg

logger = logging.getLogger("mindmap_mcp")


# ---------------------------------------------------------------------------
# Prompt — hand-crafted for the MyLens-style structural shape.
# ---------------------------------------------------------------------------
_SYSTEM_PROMPT = textwrap.dedent(
    """
    You extract mindmap structure from long-form text.

    Return a SINGLE JSON object matching this schema, and NOTHING ELSE. No
    prose, no fenced code block, no commentary. Start with `{` and end with `}`.

    Schema:
      {
        "title": string (short — the topic of the text),
        "subtitle": string (one sentence — what the text is about),
        "center": {"label": string (3-6 words — the thesis), "emoji": string (optional)},
        "branches": array of 4 to 6 objects, each:
          {
            "label": string (2-4 words — a top-level category),
            "emoji": string (one relevant emoji),
            "color": one of "teal" | "coral" | "lavender" | "saffron" | "sage" | "rose",
            "children": array of 2 to 5 objects, each:
              {
                "label": string (concise subcategory),
                "children": array (0, or 2-4) of {"label": short leaf string ≤40 chars}
              }
          },
        "footnotes": array (0-3) of short strings (key claims / themes)
      }

    Rules:
      - Ground every leaf in the actual text — no invented content.
      - Leaves are short and specific (fits on a small pill).
      - Emojis only on top-level branches, not on subs or leaves.
      - Assign a different color to each branch.
    """
).strip()


# ---------------------------------------------------------------------------
# Rungs — each returns a raw JSON dict or raises RungDisabled / RungFailed.
# ---------------------------------------------------------------------------
def _openai_call(text: str, model: str, base_url: str, api_key: str) -> Dict[str, Any]:
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": text},
        ],
        "temperature": 0.2,
        "response_format": {"type": "json_object"},
    }
    resp = requests.post(
        base_url.rstrip("/") + "/chat/completions",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json=body,
        timeout=180,
    )
    if resp.status_code >= 400:
        raise RungFailed(f"HTTP {resp.status_code}: {resp.text[:200]}")
    data = resp.json()
    try:
        content = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError) as exc:
        raise RungFailed(f"unexpected response shape: {exc}")
    try:
        return json.loads(content)
    except json.JSONDecodeError as exc:
        raise RungFailed(f"model returned non-JSON: {exc}")


def extract_via_openai(text: str) -> Mindmap:
    api_key = os.getenv("MMCP_OPENAI_API_KEY")
    if not api_key:
        raise RungDisabled("MMCP_OPENAI_API_KEY not set")
    model = os.getenv("MMCP_OPENAI_MODEL", "gpt-4o-mini")
    base_url = os.getenv("MMCP_OPENAI_BASE_URL", "https://api.openai.com/v1")
    raw = _openai_call(text, model, base_url, api_key)
    mm = validate_mindmap(raw)
    mm["source"] = SOURCE_OPENAI
    return mm


def extract_via_anthropic(text: str) -> Mindmap:
    api_key = os.getenv("MMCP_ANTHROPIC_API_KEY")
    if not api_key:
        raise RungDisabled("MMCP_ANTHROPIC_API_KEY not set")
    model = os.getenv("MMCP_ANTHROPIC_MODEL", "claude-opus-4-7")
    body = {
        "model": model,
        "max_tokens": 4096,
        "system": _SYSTEM_PROMPT,
        "messages": [{"role": "user", "content": text}],
    }
    resp = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        },
        json=body,
        timeout=180,
    )
    if resp.status_code >= 400:
        raise RungFailed(f"HTTP {resp.status_code}: {resp.text[:200]}")
    data = resp.json()
    try:
        content = data["content"][0]["text"]
    except (KeyError, IndexError) as exc:
        raise RungFailed(f"unexpected response shape: {exc}")
    # Claude typically obeys "start with {" but be defensive.
    content = content.strip()
    if content.startswith("```"):
        content = content.strip("`").split("\n", 1)[-1].rstrip("`")
    try:
        raw = json.loads(content)
    except json.JSONDecodeError as exc:
        raise RungFailed(f"model returned non-JSON: {exc}")
    mm = validate_mindmap(raw)
    mm["source"] = SOURCE_ANTHROPIC
    return mm


def extract_via_local(text: str) -> Mindmap:
    base_url = os.getenv("MMCP_LOCAL_BASE_URL")
    if not base_url:
        raise RungDisabled("MMCP_LOCAL_BASE_URL not set")
    api_key = os.getenv("MMCP_LOCAL_API_KEY", "local")
    model = os.getenv("MMCP_LOCAL_MODEL", "qwen3:8b")
    raw = _openai_call(text, model, base_url, api_key)
    mm = validate_mindmap(raw)
    mm["source"] = SOURCE_LOCAL
    return mm


# ---------------------------------------------------------------------------
# Ladder
# ---------------------------------------------------------------------------
_LADDER: List[tuple[str, Callable[[str], Mindmap]]] = [
    (SOURCE_OPENAI, extract_via_openai),
    (SOURCE_ANTHROPIC, extract_via_anthropic),
    (SOURCE_LOCAL, extract_via_local),
]


def extract_mindmap(
    text: str,
    provider: str = "auto",
) -> Mindmap:
    """Extract a mindmap from long text.

    Args:
        text: The source text (transcript, article, meeting notes, etc.).
        provider: 'auto' walks the ladder (openai → anthropic → local). Pass a
            specific rung name to force just that rung.

    Raises:
        ValueError: empty text or unknown provider.
        MindmapUnavailable: every enabled rung failed (carries per-rung reasons).
    """
    if not text or not text.strip():
        raise ValueError("Empty text — nothing to extract from.")

    if provider != "auto":
        chosen = [(name, fn) for name, fn in _LADDER if name == provider]
        if not chosen:
            raise ValueError(
                f"Unknown provider {provider!r}. Expected one of: "
                f"{['auto'] + [n for n, _ in _LADDER]}"
            )
        ladder = chosen
    else:
        ladder = _LADDER

    reasons: Dict[str, str] = {}
    for name, fn in ladder:
        try:
            mm = fn(text)
        except RungDisabled as exc:
            reasons[name] = f"disabled ({exc})"
            logger.debug("Rung %s disabled: %s", name, exc)
            continue
        except RungFailed as exc:
            reasons[name] = str(exc)
            logger.info("Rung %s failed: %s", name, exc)
            continue
        except Exception as exc:  # defensive: never let a rung crash the ladder
            reasons[name] = f"unexpected {type(exc).__name__}: {exc}"
            logger.warning("Rung %s crashed: %s", name, exc)
            continue
        mm["generated_at"] = now_iso()
        return mm

    raise MindmapUnavailable(reasons)


# ---------------------------------------------------------------------------
# Public thin wrappers around renderer + summary
# ---------------------------------------------------------------------------
def render_mindmap(
    mindmap: Dict[str, Any],
    theme: str = "mylens",
    show_editor: bool = True,
) -> str:
    """Return a self-contained HTML rendering of a mindmap dict."""
    return render_html(mindmap, theme_name=theme, show_editor=show_editor)


def render_mindmap_svg(
    mindmap: Dict[str, Any],
    theme: str = "mylens",
) -> str:
    """Return just the SVG element (no wrapping HTML)."""
    return render_svg(mindmap, theme_name=theme)


def mindmap_summary(mindmap: Dict[str, Any]) -> Dict[str, Any]:
    return summary(validate_mindmap(mindmap))
