#!/usr/bin/env python3
"""MCP server exposing YouTube transcript retrieval with a resilient fallback ladder.

Tools:
    youtube_get_transcript   — fetch a transcript (cache -> api -> yt-dlp -> managed -> asr)
    youtube_list_transcripts — list available caption tracks for a video
    youtube_cache_info       — inspect / clear the local transcript cache

Runs over stdio for local use (Claude Desktop). All logging goes to stderr so it
never corrupts the stdio JSON-RPC stream.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from enum import Enum
from typing import List, Optional

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .common import TranscriptUnavailable, record_summary
from . import core

logging.basicConfig(
    level=logging.INFO,
    stream=sys.stderr,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

mcp = FastMCP("youtube_transcript_mcp")


class ResponseFormat(str, Enum):
    """Output format for the transcript tool."""

    JSON = "json"          # full normalized record with timestamped segments
    TEXT = "text"          # plain transcript text plus a short provenance header
    MARKDOWN = "markdown"  # human-readable summary + text


# ---------------------------------------------------------------------------
# Input models
# ---------------------------------------------------------------------------
class GetTranscriptInput(BaseModel):
    """Input for youtube_get_transcript."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    video: str = Field(
        ...,
        description="YouTube video id or any URL form "
        "(watch?v=, youtu.be/, /shorts/, /embed/, /live/).",
        min_length=1,
        max_length=500,
    )
    languages: List[str] = Field(
        default_factory=lambda: ["en"],
        description="Preferred language codes, highest priority first (e.g. ['en','es']). "
        "The first available match is returned.",
        max_length=20,
    )
    translate_to: Optional[str] = Field(
        default=None,
        description="If set, request YouTube's translation of the transcript into this "
        "language code (e.g. 'en'). Only the API rung supports translation.",
        max_length=10,
    )
    use_cache: bool = Field(
        default=True,
        description="Read from and write to the local SQLite cache. Set false to force a refetch.",
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.JSON,
        description="'json' for full timestamped segments, 'text' for plain transcript, "
        "'markdown' for a readable summary.",
    )

    @field_validator("languages")
    @classmethod
    def _clean_languages(cls, v: List[str]) -> List[str]:
        cleaned = [c.strip() for c in v if c and c.strip()]
        return cleaned or ["en"]


class ListTranscriptsInput(BaseModel):
    """Input for youtube_list_transcripts."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    video: str = Field(
        ...,
        description="YouTube video id or any URL form.",
        min_length=1,
        max_length=500,
    )


class CacheInfoInput(BaseModel):
    """Input for youtube_cache_info."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    clear: bool = Field(
        default=False,
        description="If true, delete cached transcripts (all, or just for `video` if given).",
    )
    video: Optional[str] = Field(
        default=None,
        description="Restrict a clear operation to a single video id/URL. Ignored unless clear=true.",
        max_length=500,
    )


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------
def _format_transcript(record: dict, fmt: ResponseFormat) -> str:
    if fmt == ResponseFormat.JSON:
        return json.dumps(record, ensure_ascii=False, indent=2)

    summary = record_summary(record)
    header_bits = [
        f"video: {summary['video_id']}",
        f"language: {summary['language']} ({summary['language_code']})",
        f"generated: {summary['is_generated']}",
        f"source: {summary['source']}"
        + (" (cache)" if summary["cache_hit"] else ""),
        f"segments: {summary['segment_count']}",
        f"chars: {summary['char_count']}",
    ]
    if summary.get("translated_to"):
        header_bits.insert(2, f"translated_to: {summary['translated_to']}")

    if fmt == ResponseFormat.TEXT:
        return "# " + " | ".join(header_bits) + "\n\n" + record.get("text", "")

    # MARKDOWN
    lines = [
        f"## Transcript — {summary['video_id']}",
        "",
        "| field | value |",
        "|---|---|",
    ]
    for bit in header_bits:
        key, _, val = bit.partition(": ")
        lines.append(f"| {key} | {val} |")
    lines += ["", "### Text", "", record.get("text", "")]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------
@mcp.tool(
    name="youtube_get_transcript",
    annotations={
        "title": "Get YouTube Transcript",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def youtube_get_transcript(params: GetTranscriptInput) -> str:
    """Retrieve a YouTube video transcript, resilient to YouTube's transcript blocking.

    Descends a fallback ladder and returns the first success:
      1. local cache  2. youtube-transcript-api  3. yt-dlp subtitles
      4. managed API (if configured)  5. local ASR (if enabled).
    All rungs normalize to one schema, so the caller never sees which path served it
    except via the `source` / `cache_hit` provenance fields.

    Args:
        params (GetTranscriptInput):
            - video (str): video id or any YouTube URL form.
            - languages (List[str]): preferred language codes, priority order (default ['en']).
            - translate_to (Optional[str]): request a translated transcript (API rung only).
            - use_cache (bool): use the persistent cache (default True).
            - response_format (ResponseFormat): 'json' | 'text' | 'markdown' (default 'json').

    Returns:
        str: For 'json', a normalized record:
            {
              "video_id": str, "language": str, "language_code": str,
              "is_generated": bool, "translated_to": str|null,
              "source": str,            # producing rung
              "cache_hit": bool,
              "segments": [{"start": float, "duration": float, "text": str}],
              "text": str,              # full plain transcript
              "duration_seconds": float|null, "fetched_at": str
            }
        For 'text'/'markdown', a human-readable rendering with a provenance header.
        On total failure: "Error: <reason>" listing why each rung could not deliver.

    Examples:
        - "Get the transcript of https://youtu.be/dQw4w9WgXcQ" -> video=that URL
        - "Spanish transcript, fall back to English" -> languages=['es','en']
        - "Translate this video's captions to English" -> translate_to='en'
        - Don't use to list which languages exist -> use youtube_list_transcripts.
    """
    try:
        record = await asyncio.to_thread(
            core.get_transcript,
            params.video,
            params.languages,
            params.translate_to,
            params.use_cache,
        )
    except ValueError as exc:
        return f"Error: {exc}"
    except TranscriptUnavailable as exc:
        return f"Error: {exc}"
    except Exception as exc:  # pragma: no cover
        return f"Error: unexpected {type(exc).__name__}: {exc}"

    return _format_transcript(record, params.response_format)


@mcp.tool(
    name="youtube_list_transcripts",
    annotations={
        "title": "List YouTube Caption Tracks",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def youtube_list_transcripts(params: ListTranscriptsInput) -> str:
    """List the caption tracks available for a YouTube video (metadata only).

    Use this to discover which languages exist and whether they are manually
    created, auto-generated, or translatable — before calling youtube_get_transcript.

    Args:
        params (ListTranscriptsInput):
            - video (str): video id or any YouTube URL form.

    Returns:
        str: JSON of the form:
            {
              "video_id": str,
              "tracks": [
                {"language": str, "language_code": str,
                 "is_generated": bool, "is_translatable": bool}
              ]
            }
        On failure: "Error: <reason>".
    """
    try:
        result = await asyncio.to_thread(core.list_transcripts, params.video)
    except ValueError as exc:
        return f"Error: {exc}"
    except TranscriptUnavailable as exc:
        return f"Error: {exc}"
    except Exception as exc:  # pragma: no cover
        return f"Error: unexpected {type(exc).__name__}: {exc}"
    return json.dumps(result, ensure_ascii=False, indent=2)


@mcp.tool(
    name="youtube_cache_info",
    annotations={
        "title": "Inspect/Clear Transcript Cache",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": False,
    },
)
async def youtube_cache_info(params: CacheInfoInput) -> str:
    """Report transcript cache statistics, or clear cached entries.

    Args:
        params (CacheInfoInput):
            - clear (bool): if true, delete cached transcripts.
            - video (Optional[str]): limit a clear to a single video (ignored unless clear=true).

    Returns:
        str: JSON with cache stats:
            {"db_path", "cached_requests", "distinct_videos", "by_source", "db_size_bytes"}
        When clearing, also includes {"cleared": <rows deleted>}.
    """
    try:
        if params.clear:
            deleted = await asyncio.to_thread(core.clear_cache, params.video)
            stats = await asyncio.to_thread(core.cache_info)
            stats["cleared"] = deleted
            return json.dumps(stats, ensure_ascii=False, indent=2)
        stats = await asyncio.to_thread(core.cache_info)
        return json.dumps(stats, ensure_ascii=False, indent=2)
    except Exception as exc:  # pragma: no cover
        return f"Error: unexpected {type(exc).__name__}: {exc}"


def main() -> None:
    """Console-script entry point. Runs the stdio transport."""
    mcp.run()


if __name__ == "__main__":
    main()
