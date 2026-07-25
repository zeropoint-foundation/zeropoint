"""Ladder orchestration: cache -> API -> yt-dlp -> managed -> ASR.

This module is deliberately free of any MCP concern so it can be reused
verbatim by ZeroPoint (phase 2) — imported directly, or ported to a Rust
subprocess boundary. The MCP server (server.py) is a thin wrapper over
`get_transcript` and `list_transcripts`.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, List, Optional

from .cache import TranscriptCache
from .common import (
    SOURCE_CACHE,
    RungDisabled,
    RungFailed,
    TranscriptRecord,
    TranscriptUnavailable,
    parse_video_id,
)
from .fetchers import (
    fetch_via_api,
    fetch_via_asr,
    fetch_via_managed,
    fetch_via_ytdlp,
    list_available_via_api,
)

logger = logging.getLogger("youtube_transcript_mcp")

# The ladder, in order. Each entry: (source_label, fetch_fn).
_LADDER: List[tuple[str, Callable[..., TranscriptRecord]]] = [
    ("youtube_transcript_api", fetch_via_api),
    ("yt_dlp", fetch_via_ytdlp),
    ("managed_api", fetch_via_managed),
    ("local_asr", fetch_via_asr),
]

# Single shared cache instance for the process.
_cache: Optional[TranscriptCache] = None


def get_cache() -> TranscriptCache:
    global _cache
    if _cache is None:
        _cache = TranscriptCache()
    return _cache


def get_transcript(
    video: str,
    languages: Optional[List[str]] = None,
    translate_to: Optional[str] = None,
    use_cache: bool = True,
) -> TranscriptRecord:
    """Fetch one transcript, descending the ladder until a rung succeeds.

    Args:
        video: A video id or any YouTube URL form.
        languages: Preferred language codes, highest priority first (default ['en']).
        translate_to: If set, request YouTube's translation into this code.
        use_cache: Read from (and write to) the persistent cache.

    Returns:
        A normalized TranscriptRecord. On a cache hit, record['cache_hit'] is True
        and record['source'] retains the original producing rung.

    Raises:
        ValueError: unparseable video reference.
        TranscriptUnavailable: every enabled rung failed (carries per-rung reasons).
    """
    video_id = parse_video_id(video)
    langs = languages or ["en"]

    cache = get_cache() if use_cache else None
    if cache is not None:
        cached = cache.get(video_id, langs, translate_to)
        if cached is not None:
            result = dict(cached)
            result["cache_hit"] = True
            return result  # type: ignore[return-value]

    reasons: Dict[str, str] = {}
    for source, fn in _LADDER:
        try:
            record = fn(video_id, langs, translate_to)
        except RungDisabled as exc:
            reasons[source] = f"disabled ({exc})"
            logger.debug("Rung %s disabled: %s", source, exc)
            continue
        except RungFailed as exc:
            reasons[source] = str(exc)
            logger.info("Rung %s failed: %s", source, exc)
            continue
        except Exception as exc:  # defensive: never let a rung crash the ladder
            reasons[source] = f"unexpected {type(exc).__name__}: {exc}"
            logger.warning("Rung %s crashed: %s", source, exc)
            continue

        record["cache_hit"] = False  # type: ignore[typeddict-unknown-key]
        if cache is not None:
            try:
                cache.put(video_id, langs, translate_to, record)
            except Exception as exc:  # cache write must never fail the fetch
                logger.warning("Cache write failed: %s", exc)
        return record

    raise TranscriptUnavailable(video_id, reasons)


def list_transcripts(video: str) -> Dict[str, Any]:
    """List available caption tracks for a video (metadata only).

    Returns a dict: {video_id, tracks:[{language, language_code, is_generated,
    is_translatable}]}. Raises ValueError / TranscriptUnavailable on failure.
    """
    video_id = parse_video_id(video)
    try:
        tracks = list_available_via_api(video_id)
    except RungDisabled as exc:
        raise TranscriptUnavailable(video_id, {"youtube_transcript_api": f"disabled ({exc})"})
    except RungFailed as exc:
        raise TranscriptUnavailable(video_id, {"youtube_transcript_api": str(exc)})
    return {"video_id": video_id, "tracks": tracks}


def cache_info() -> Dict[str, Any]:
    return get_cache().stats()


def clear_cache(video: Optional[str] = None) -> int:
    video_id = parse_video_id(video) if video else None
    return get_cache().clear(video_id)
