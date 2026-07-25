"""Shared types, video-id parsing, and normalization for the transcript ladder.

Everything the fetch rungs and the cache agree on lives here so there is exactly
one normalized transcript shape flowing through the system, regardless of which
rung produced it. (One canonical path per concern.)
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, TypedDict
from urllib.parse import parse_qs, urlparse

# ---------------------------------------------------------------------------
# Rung source labels — the provenance recorded on every record.
# ---------------------------------------------------------------------------
SOURCE_API = "youtube_transcript_api"
SOURCE_YTDLP = "yt_dlp"
SOURCE_MANAGED = "managed_api"
SOURCE_ASR = "local_asr"
SOURCE_CACHE = "cache"


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------
class RungDisabled(Exception):
    """A rung is intentionally not active (missing dependency or config).

    Distinct from RungFailed: a disabled rung is skipped quietly; a failed rung
    tried and could not deliver, and its reason is surfaced to the operator.
    """


class RungFailed(Exception):
    """A rung attempted the fetch and could not produce a transcript."""


class TranscriptUnavailable(Exception):
    """Every enabled rung failed. Carries the per-rung reasons for diagnosis."""

    def __init__(self, video_id: str, reasons: Dict[str, str]):
        self.video_id = video_id
        self.reasons = reasons
        detail = "; ".join(f"{rung}: {why}" for rung, why in reasons.items())
        super().__init__(
            f"No transcript could be retrieved for '{video_id}'. Rung results -> {detail}"
        )


# ---------------------------------------------------------------------------
# Normalized shapes
# ---------------------------------------------------------------------------
class Segment(TypedDict):
    start: float
    duration: float
    text: str


class TranscriptRecord(TypedDict):
    video_id: str
    language: str
    language_code: str
    is_generated: bool
    translated_to: Optional[str]
    source: str  # which rung produced it (SOURCE_* except SOURCE_CACHE)
    segments: List[Segment]
    text: str
    duration_seconds: Optional[float]
    fetched_at: str  # ISO-8601 UTC


_YOUTUBE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{11}$")
_ID_IN_PATH_RE = re.compile(r"([A-Za-z0-9_-]{11})")


def parse_video_id(value: str) -> str:
    """Extract an 11-character YouTube video id from a raw id or any URL form.

    Accepts bare ids, watch URLs (?v=), youtu.be short links, and
    /shorts/, /embed/, /live/, /v/ paths.

    Raises:
        ValueError: if no plausible video id can be found.
    """
    value = (value or "").strip()
    if not value:
        raise ValueError("Empty video reference.")

    if _YOUTUBE_ID_RE.match(value):
        return value

    parsed = urlparse(value if "//" in value else f"https://{value}")
    host = (parsed.hostname or "").lower().removeprefix("www.")

    if host == "youtu.be":
        candidate = parsed.path.lstrip("/").split("/")[0]
        if _YOUTUBE_ID_RE.match(candidate):
            return candidate

    if host in {"youtube.com", "m.youtube.com", "music.youtube.com"}:
        qs = parse_qs(parsed.query)
        if "v" in qs and _YOUTUBE_ID_RE.match(qs["v"][0]):
            return qs["v"][0]
        # /shorts/<id>, /embed/<id>, /live/<id>, /v/<id>
        parts = [p for p in parsed.path.split("/") if p]
        for i, part in enumerate(parts):
            if part in {"shorts", "embed", "live", "v"} and i + 1 < len(parts):
                if _YOUTUBE_ID_RE.match(parts[i + 1]):
                    return parts[i + 1]

    # Last resort: any 11-char token that looks like an id.
    match = _ID_IN_PATH_RE.search(value)
    if match:
        return match.group(1)

    raise ValueError(f"Could not extract a YouTube video id from: {value!r}")


def watch_url(video_id: str) -> str:
    return f"https://www.youtube.com/watch?v={video_id}"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def join_text(segments: List[Segment]) -> str:
    """Collapse segments into readable plain text (whitespace-normalized)."""
    joined = " ".join(seg["text"].strip() for seg in segments if seg["text"].strip())
    return re.sub(r"\s+", " ", joined).strip()


def build_record(
    *,
    video_id: str,
    language: str,
    language_code: str,
    is_generated: bool,
    source: str,
    segments: List[Segment],
    translated_to: Optional[str] = None,
) -> TranscriptRecord:
    """Assemble a normalized record from raw segments produced by any rung."""
    clean: List[Segment] = [
        {
            "start": round(float(s.get("start", 0.0)), 3),
            "duration": round(float(s.get("duration", 0.0)), 3),
            "text": str(s.get("text", "")).strip(),
        }
        for s in segments
        if str(s.get("text", "")).strip()
    ]
    duration = None
    if clean:
        last = clean[-1]
        duration = round(last["start"] + last["duration"], 3)
    return {
        "video_id": video_id,
        "language": language,
        "language_code": language_code,
        "is_generated": bool(is_generated),
        "translated_to": translated_to,
        "source": source,
        "segments": clean,
        "text": join_text(clean),
        "duration_seconds": duration,
        "fetched_at": now_iso(),
    }


def record_summary(record: Dict[str, Any]) -> Dict[str, Any]:
    """A compact, metadata-only view (no segment payload) for logging/markdown."""
    return {
        "video_id": record.get("video_id"),
        "language": record.get("language"),
        "language_code": record.get("language_code"),
        "is_generated": record.get("is_generated"),
        "translated_to": record.get("translated_to"),
        "source": record.get("source"),
        "cache_hit": record.get("cache_hit", False),
        "segment_count": len(record.get("segments", [])),
        "duration_seconds": record.get("duration_seconds"),
        "char_count": len(record.get("text", "")),
        "fetched_at": record.get("fetched_at"),
    }
