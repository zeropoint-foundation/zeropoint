"""The fetch rungs. Each rung is a pure function that either returns a
normalized TranscriptRecord or raises RungDisabled / RungFailed.

Rungs, in ladder order:
    1. youtube_transcript_api  — fast, structured, free (timedtext endpoint)
    2. yt-dlp subtitles        — different extraction path, catches API failures
    3. managed API             — paid backstop, off unless configured (stub-ready)
    4. local ASR (whisper)     — last resort for caption-less videos, off by default

Each rung fails independently and for different reasons, which is the whole
point of a ladder: the failure surface of rung N rarely overlaps rung N+1.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from .common import (
    SOURCE_API,
    SOURCE_ASR,
    SOURCE_MANAGED,
    SOURCE_YTDLP,
    RungDisabled,
    RungFailed,
    Segment,
    TranscriptRecord,
    build_record,
    watch_url,
)


# ---------------------------------------------------------------------------
# Proxy configuration (shared by the API rung). Read once from env.
# ---------------------------------------------------------------------------
def _build_proxy_config():
    """Return a youtube-transcript-api proxy config from env, or None.

    Only relevant when running from a datacenter/cloud IP (phase 2). When the
    server runs locally on a residential IP, no proxy is needed and this is None.
    """
    webshare_user = os.environ.get("YTMCP_WEBSHARE_USERNAME")
    webshare_pass = os.environ.get("YTMCP_WEBSHARE_PASSWORD")
    http_proxy = os.environ.get("YTMCP_HTTP_PROXY")
    https_proxy = os.environ.get("YTMCP_HTTPS_PROXY")

    if webshare_user and webshare_pass:
        from youtube_transcript_api.proxies import WebshareProxyConfig

        locations = os.environ.get("YTMCP_WEBSHARE_LOCATIONS", "")
        filter_ip_locations = [c.strip() for c in locations.split(",") if c.strip()]
        return WebshareProxyConfig(
            proxy_username=webshare_user,
            proxy_password=webshare_pass,
            filter_ip_locations=filter_ip_locations or None,
        )

    if http_proxy or https_proxy:
        from youtube_transcript_api.proxies import GenericProxyConfig

        return GenericProxyConfig(http_url=http_proxy, https_url=https_proxy)

    return None


# ---------------------------------------------------------------------------
# Rung 1: youtube-transcript-api
# ---------------------------------------------------------------------------
def _snippets_to_segments(snippets) -> List[Segment]:
    return [
        {"start": s.start, "duration": s.duration, "text": s.text} for s in snippets
    ]


def fetch_via_api(
    video_id: str, languages: List[str], translate_to: Optional[str]
) -> TranscriptRecord:
    try:
        from youtube_transcript_api import YouTubeTranscriptApi
        from youtube_transcript_api._errors import (  # noqa: F401
            CouldNotRetrieveTranscript,
        )
    except ImportError as exc:  # pragma: no cover
        raise RungDisabled(f"youtube-transcript-api not installed: {exc}") from exc

    from youtube_transcript_api import (
        NoTranscriptFound,
        TranscriptsDisabled,
        VideoUnavailable,
    )

    try:
        from youtube_transcript_api import IpBlocked, RequestBlocked  # type: ignore
    except ImportError:  # older builds
        IpBlocked = RequestBlocked = ()  # type: ignore

    ytt_api = YouTubeTranscriptApi(proxy_config=_build_proxy_config())

    try:
        if translate_to:
            transcript_list = ytt_api.list(video_id)
            base = transcript_list.find_transcript(languages)
            if not base.is_translatable:
                raise RungFailed(
                    f"Transcript '{base.language_code}' is not translatable to '{translate_to}'."
                )
            fetched = base.translate(translate_to).fetch()
        else:
            fetched = ytt_api.fetch(video_id, languages=languages)
    except (TranscriptsDisabled,) as exc:
        raise RungFailed("Transcripts are disabled for this video.") from exc
    except (NoTranscriptFound,) as exc:
        raise RungFailed(
            f"No transcript in {languages}"
            + (f" translatable to {translate_to}" if translate_to else "")
            + "."
        ) from exc
    except (VideoUnavailable,) as exc:
        raise RungFailed("Video is unavailable.") from exc
    except Exception as exc:
        name = type(exc).__name__
        if name in {"RequestBlocked", "IpBlocked"}:
            raise RungFailed(
                "YouTube blocked this request (datacenter IP). "
                "Configure YTMCP_WEBSHARE_* residential proxy, or run locally."
            ) from exc
        raise RungFailed(f"{name}: {exc}") from exc

    return build_record(
        video_id=video_id,
        language=fetched.language,
        language_code=fetched.language_code,
        is_generated=fetched.is_generated,
        source=SOURCE_API,
        segments=_snippets_to_segments(fetched.snippets),
        translated_to=translate_to,
    )


def list_available_via_api(video_id: str) -> List[Dict[str, Any]]:
    """List caption tracks for a video (used by the list tool). May raise RungFailed."""
    try:
        from youtube_transcript_api import YouTubeTranscriptApi
    except ImportError as exc:  # pragma: no cover
        raise RungDisabled(f"youtube-transcript-api not installed: {exc}") from exc

    ytt_api = YouTubeTranscriptApi(proxy_config=_build_proxy_config())
    try:
        transcript_list = ytt_api.list(video_id)
    except Exception as exc:
        raise RungFailed(f"{type(exc).__name__}: {exc}") from exc

    tracks: List[Dict[str, Any]] = []
    for t in transcript_list:
        tracks.append(
            {
                "language": t.language,
                "language_code": t.language_code,
                "is_generated": t.is_generated,
                "is_translatable": t.is_translatable,
            }
        )
    return tracks


# ---------------------------------------------------------------------------
# Rung 2: yt-dlp subtitle extraction
# ---------------------------------------------------------------------------
def _parse_json3(raw: str) -> List[Segment]:
    """Parse YouTube json3 timed-text into segments."""
    data = json.loads(raw)
    segments: List[Segment] = []
    for event in data.get("events", []):
        segs = event.get("segs")
        if not segs:
            continue
        text = "".join(s.get("utf8", "") for s in segs)
        if not text.strip():
            continue
        start = event.get("tStartMs", 0) / 1000.0
        dur = event.get("dDurationMs", 0) / 1000.0
        segments.append({"start": start, "duration": dur, "text": text})
    return segments


def fetch_via_ytdlp(
    video_id: str, languages: List[str], translate_to: Optional[str]
) -> TranscriptRecord:
    try:
        import yt_dlp  # noqa: F401
    except ImportError as exc:
        raise RungDisabled(f"yt-dlp not installed: {exc}") from exc

    from yt_dlp import YoutubeDL

    wanted = [translate_to] if translate_to else list(languages)
    with tempfile.TemporaryDirectory() as tmp:
        outtmpl = str(Path(tmp) / "%(id)s.%(ext)s")
        ydl_opts = {
            "skip_download": True,
            "writesubtitles": True,
            "writeautomaticsub": True,
            "subtitleslangs": wanted,
            "subtitlesformat": "json3",
            "outtmpl": outtmpl,
            "quiet": True,
            "no_warnings": True,
            "ignoreerrors": False,
        }
        try:
            with YoutubeDL(ydl_opts) as ydl:
                info = ydl.extract_info(watch_url(video_id), download=True)
        except Exception as exc:
            raise RungFailed(f"yt-dlp extraction failed: {type(exc).__name__}: {exc}") from exc

        # Find the downloaded json3 file for the best-matching language.
        files = sorted(Path(tmp).glob(f"{video_id}*.json3"))
        if not files:
            raise RungFailed("yt-dlp found no matching subtitle track.")

        chosen: Optional[Path] = None
        chosen_lang = wanted[0] if wanted else "unknown"
        for lang in wanted:
            for f in files:
                if f".{lang}." in f.name or f.stem.endswith(lang):
                    chosen, chosen_lang = f, lang
                    break
            if chosen:
                break
        if chosen is None:
            chosen = files[0]

        raw = chosen.read_text(encoding="utf-8", errors="replace")

    segments = _parse_json3(raw)
    if not segments:
        raise RungFailed("yt-dlp subtitle track was empty after parsing.")

    # Determine is_generated from info dict when available.
    is_generated = True
    if isinstance(info, dict):
        manual = info.get("subtitles") or {}
        if chosen_lang in manual:
            is_generated = False

    return build_record(
        video_id=video_id,
        language=chosen_lang,
        language_code=chosen_lang,
        is_generated=is_generated,
        source=SOURCE_YTDLP,
        segments=segments,
        translated_to=translate_to,
    )


# ---------------------------------------------------------------------------
# Rung 3: managed API (paid backstop) — STUB, off unless configured.
# ---------------------------------------------------------------------------
def fetch_via_managed(
    video_id: str, languages: List[str], translate_to: Optional[str]
) -> TranscriptRecord:
    """Call a managed transcript API as a last-mile backstop.

    Disabled unless YTMCP_MANAGED_API_KEY is set. The default wiring targets
    Supadata's shape; adapt _call_managed_provider() to whichever provider you
    contract with (TranscriptAPI, youtube-transcript.io, etc.). Kept behind an
    env flag so it costs nothing until you deliberately switch it on.
    """
    api_key = os.environ.get("YTMCP_MANAGED_API_KEY")
    if not api_key:
        raise RungDisabled("Managed API rung disabled (set YTMCP_MANAGED_API_KEY to enable).")

    provider = os.environ.get("YTMCP_MANAGED_PROVIDER", "supadata").lower()
    lang = (translate_to or (languages[0] if languages else "en"))

    try:
        segments, resolved_lang = _call_managed_provider(provider, api_key, video_id, lang)
    except Exception as exc:
        raise RungFailed(f"Managed API ({provider}) failed: {type(exc).__name__}: {exc}") from exc

    if not segments:
        raise RungFailed(f"Managed API ({provider}) returned no segments.")

    return build_record(
        video_id=video_id,
        language=resolved_lang,
        language_code=resolved_lang,
        is_generated=True,
        source=SOURCE_MANAGED,
        segments=segments,
        translated_to=translate_to,
    )


def _call_managed_provider(
    provider: str, api_key: str, video_id: str, lang: str
) -> tuple[List[Segment], str]:
    """Provider adapter. Returns (segments, resolved_language_code).

    NOTE: endpoint shapes change; verify the current request/response format
    against your provider's docs before relying on this in production. This is a
    deliberately thin, swappable adapter — the ladder treats any exception here
    as a normal rung failure and moves on.
    """
    import requests

    if provider == "supadata":
        resp = requests.get(
            "https://api.supadata.ai/v1/youtube/transcript",
            params={"videoId": video_id, "lang": lang, "text": "false"},
            headers={"x-api-key": api_key},
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        raw = data.get("content", data.get("transcript", []))
        segments: List[Segment] = []
        for item in raw:
            segments.append(
                {
                    "start": float(item.get("offset", item.get("start", 0))) / 1000.0
                    if item.get("offset") is not None
                    else float(item.get("start", 0)),
                    "duration": float(item.get("duration", 0)) / 1000.0
                    if item.get("duration", 0) > 1000
                    else float(item.get("duration", 0)),
                    "text": item.get("text", ""),
                }
            )
        return segments, data.get("lang", lang)

    # Generic JSON provider: expects {"segments":[{"start","duration","text"}], "lang"}
    base_url = os.environ.get("YTMCP_MANAGED_BASE_URL")
    if not base_url:
        raise RuntimeError(
            f"Unknown managed provider '{provider}' and no YTMCP_MANAGED_BASE_URL set."
        )
    resp = requests.get(
        base_url,
        params={"video_id": video_id, "lang": lang},
        headers={"Authorization": f"Bearer {api_key}"},
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()
    segs = [
        {
            "start": float(s.get("start", 0)),
            "duration": float(s.get("duration", 0)),
            "text": s.get("text", ""),
        }
        for s in data.get("segments", [])
    ]
    return segs, data.get("lang", lang)


# ---------------------------------------------------------------------------
# Rung 4: local ASR (yt-dlp audio + faster-whisper) — off by default.
# ---------------------------------------------------------------------------
def fetch_via_asr(
    video_id: str, languages: List[str], translate_to: Optional[str]
) -> TranscriptRecord:
    """Download audio and transcribe locally. Last resort for caption-less videos.

    Disabled unless YTMCP_ENABLE_ASR is truthy AND faster-whisper is importable.
    Model size via YTMCP_ASR_MODEL (default 'base'). translate_to is ignored here
    (ASR produces source-language text; translation would be a separate step).
    """
    if os.environ.get("YTMCP_ENABLE_ASR", "").lower() not in {"1", "true", "yes", "on"}:
        raise RungDisabled("Local ASR rung disabled (set YTMCP_ENABLE_ASR=1 to enable).")

    try:
        from faster_whisper import WhisperModel
    except ImportError as exc:
        raise RungDisabled(f"faster-whisper not installed: {exc}") from exc

    try:
        import yt_dlp  # noqa: F401
    except ImportError as exc:
        raise RungDisabled(f"yt-dlp not installed (needed for audio): {exc}") from exc

    from yt_dlp import YoutubeDL

    model_size = os.environ.get("YTMCP_ASR_MODEL", "base")
    with tempfile.TemporaryDirectory() as tmp:
        audio_path = Path(tmp) / f"{video_id}.m4a"
        ydl_opts = {
            "format": "bestaudio/best",
            "outtmpl": str(Path(tmp) / "%(id)s.%(ext)s"),
            "quiet": True,
            "no_warnings": True,
            "postprocessors": [
                {"key": "FFmpegExtractAudio", "preferredcodec": "m4a"}
            ],
        }
        try:
            with YoutubeDL(ydl_opts) as ydl:
                ydl.download([watch_url(video_id)])
        except Exception as exc:
            raise RungFailed(f"Audio download failed: {type(exc).__name__}: {exc}") from exc

        candidates = list(Path(tmp).glob(f"{video_id}.*"))
        audio = next((c for c in candidates if c.suffix in {".m4a", ".mp3", ".webm", ".opus"}), None)
        if audio is None:
            raise RungFailed("No audio file produced for ASR.")

        model = WhisperModel(model_size, device="auto", compute_type="int8")
        pref_lang = languages[0] if languages else None
        segments_iter, info = model.transcribe(str(audio), language=pref_lang)
        segments: List[Segment] = [
            {"start": s.start, "duration": max(0.0, s.end - s.start), "text": s.text}
            for s in segments_iter
        ]

    if not segments:
        raise RungFailed("ASR produced no segments.")

    return build_record(
        video_id=video_id,
        language=getattr(info, "language", pref_lang or "unknown"),
        language_code=getattr(info, "language", pref_lang or "unknown"),
        is_generated=True,
        source=SOURCE_ASR,
        segments=segments,
        translated_to=None,
    )
