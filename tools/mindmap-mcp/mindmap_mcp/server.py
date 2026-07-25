#!/usr/bin/env python3
"""MCP server exposing mindmap generation + rendering.

Tools:
    mindmap_render          — render a validated mindmap JSON as HTML or SVG.
    mindmap_extract         — extract a mindmap from long text via the LLM ladder.
    mindmap_themes          — list the built-in themes.

Runs over stdio for local use (Claude Desktop). All logging goes to stderr so
it never corrupts the stdio JSON-RPC stream — same discipline as
youtube-transcript-mcp.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from enum import Enum
from typing import Any, Dict, List, Optional

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, ConfigDict, Field, field_validator

from . import core
from .common import MindmapInvalid, MindmapUnavailable
from .themes import list_themes


logging.basicConfig(
    level=logging.INFO,
    stream=sys.stderr,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

mcp = FastMCP("mindmap_mcp")


class RenderFormat(str, Enum):
    HTML = "html"   # self-contained HTML document (default)
    SVG = "svg"     # just the SVG element (for embedding)


class ThemeName(str, Enum):
    MYLENS = "mylens"
    DARK = "dark"
    MONOCHROME = "monochrome"
    BRAND = "brand"


# ---------------------------------------------------------------------------
# Input models
# ---------------------------------------------------------------------------
class RenderInput(BaseModel):
    """Input for mindmap_render."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    mindmap: Dict[str, Any] = Field(
        ...,
        description=(
            "The mindmap JSON to render. Schema: {title, subtitle, center:{label,emoji}, "
            "branches:[{label, emoji, color, children:[{label, children:[{label}]}]}], "
            "footnotes:[str]}. Colors: teal|coral|lavender|saffron|sage|rose."
        ),
    )
    theme: ThemeName = Field(
        default=ThemeName.MYLENS,
        description="Visual theme. 'mylens' is a warm beige radial (default). "
        "'dark' matches ZP's dark palette. 'brand' tints for zeropoint.global. "
        "'monochrome' is print-safe.",
    )
    format: RenderFormat = Field(
        default=RenderFormat.HTML,
        description="'html' for a self-contained document (openable in a browser), "
        "'svg' for just the SVG element to embed elsewhere.",
    )
    show_editor: bool = Field(
        default=True,
        description="Only relevant when format='html'. Include a slide-out editor "
        "for live JSON tweaking. Set false when rendering into an artifact "
        "gallery or embedding read-only.",
    )


class ExtractInput(BaseModel):
    """Input for mindmap_extract."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    text: str = Field(
        ...,
        description="Long-form source text (transcript, article, notes). "
        "The tool extracts a 4-6 branch mindmap grounded in this text.",
        min_length=100,
    )
    provider: str = Field(
        default="auto",
        description="Extraction rung. 'auto' walks openai → anthropic → local, "
        "using whichever env vars are configured. Pass a specific rung to "
        "force it (see .env.example for keys).",
    )


class ThemesInput(BaseModel):
    """Input for mindmap_themes."""

    model_config = ConfigDict(extra="forbid")


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------
@mcp.tool(
    name="mindmap_render",
    annotations={
        "title": "Render Mindmap",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def mindmap_render(params: RenderInput) -> str:
    """Render a structured mindmap JSON as a self-contained HTML (or SVG).

    Use this when you have already produced a mindmap JSON — either by hand,
    by calling mindmap_extract, or by asking Claude to structure something for
    you — and want the visual artifact. The output is single-file, no CDN,
    no browser storage, safe to save and share.

    Args:
        params (RenderInput):
            - mindmap (dict): the mindmap structure (see schema in the field).
            - theme (str): 'mylens' | 'dark' | 'monochrome' | 'brand' (default 'mylens').
            - format (str): 'html' | 'svg' (default 'html').
            - show_editor (bool): live JSON editor in the HTML output (default True).

    Returns:
        str: The HTML document or SVG element. On invalid JSON: "Error: <reason>".

    Examples:
        - "Render this mindmap I drafted, dark theme" → theme='dark'.
        - "Give me just the SVG so I can embed it" → format='svg'.
        - "Render for the artifact gallery, no editor UI" → show_editor=False.
    """
    try:
        if params.format == RenderFormat.SVG:
            out = await asyncio.to_thread(
                core.render_mindmap_svg,
                params.mindmap,
                params.theme.value,
            )
        else:
            out = await asyncio.to_thread(
                core.render_mindmap,
                params.mindmap,
                params.theme.value,
                params.show_editor,
            )
    except MindmapInvalid as exc:
        return f"Error: invalid mindmap — {exc}"
    except Exception as exc:  # pragma: no cover
        return f"Error: unexpected {type(exc).__name__}: {exc}"
    return out


@mcp.tool(
    name="mindmap_extract",
    annotations={
        "title": "Extract Mindmap from Text",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": False,  # LLM output varies
        "openWorldHint": True,
    },
)
async def mindmap_extract(params: ExtractInput) -> str:
    """Extract a structured mindmap JSON from long-form text.

    Ladder: openai → anthropic → local. Uses whichever provider env vars
    are configured. Returns the normalized JSON structure ready to pass into
    mindmap_render.

    Args:
        params (ExtractInput):
            - text (str): the source text (transcript, article, notes; ≥100 chars).
            - provider (str): 'auto' | 'openai' | 'anthropic' | 'local'.

    Returns:
        str: JSON of the mindmap dict. On total failure: "Error: <per-rung reasons>".

    Examples:
        - "Extract a mindmap from this transcript" → text=<transcript>, provider='auto'.
        - "Use the local model" → provider='local'.
    """
    try:
        mm = await asyncio.to_thread(core.extract_mindmap, params.text, params.provider)
    except ValueError as exc:
        return f"Error: {exc}"
    except MindmapUnavailable as exc:
        return f"Error: {exc}"
    except Exception as exc:  # pragma: no cover
        return f"Error: unexpected {type(exc).__name__}: {exc}"
    return json.dumps(mm, ensure_ascii=False, indent=2)


@mcp.tool(
    name="mindmap_themes",
    annotations={
        "title": "List Themes",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def mindmap_themes(params: ThemesInput) -> str:
    """List the theme identifiers accepted by mindmap_render.

    Returns:
        str: JSON list of theme names, e.g. ["mylens","dark","monochrome","brand"].
    """
    return json.dumps(list_themes(), ensure_ascii=False)


def main() -> None:
    """Console-script entry point. Runs the stdio transport."""
    mcp.run()


if __name__ == "__main__":
    main()
