#!/usr/bin/env python3
"""
ZeroPoint Kokoro Voice Tuner — TTS Preview Server

Lightweight backend for kokoro-tuner.html. Loads kokoro-onnx once,
accepts synthesis parameters, returns audio as WAV.

Mirrors voice-tuner-server.py (Piper) — same pattern, different engine.

Usage:
    python3 kokoro-tuner-server.py                 # port 8474
    python3 kokoro-tuner-server.py --port 9000     # custom port

API:
    GET    /                → serves kokoro-tuner.html
    GET    /voices          → { "voices": [{ id, lang, group, label }, ...] }
    GET    /health          → { "status": "ok", "model": "...", "voices_loaded": N }
    POST   /synthesize      →
        body: { "text": "...", "voice": "bm_george", "speed": 0.95 }
        → 200 audio/wav
        → 400/500 { "error": "..." }

    GET    /favorites       → { "favorites": [{ id, voice, speed, label, notes, saved_at }, ...] }
    POST   /favorites       →
        body: { "voice": "bm_george", "speed": 0.95, "label": "...", "notes": "..." }
        → 200 { "favorite": {...} }
    PATCH  /favorites/{id}  →
        body: { "label": "...", "notes": "..." }
        → 200 { "favorite": {...} }
    DELETE /favorites/{id}  → 204

Favorites are persisted to onboarding-voice-palette.json at the repo root.
"""

import argparse
import io
import json
import os
import sys
import wave
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

# ─── Defaults ────────────────────────────────────────────────────

REPO_ROOT = Path(__file__).resolve().parent
MODEL_PATH = REPO_ROOT / "models" / "kokoro" / "kokoro-v1.0.onnx"
VOICES_PATH = REPO_ROOT / "models" / "kokoro" / "voices-v1.0.bin"
HTML_PATH = REPO_ROOT / "kokoro-tuner.html"
FAVORITES_PATH = REPO_ROOT / "onboarding-voice-palette.json"
DEFAULT_PORT = 8474  # Piper uses 8473

# Voice catalog — must match generate-onboard-voice-samples.py
# Grouped for UI rendering.
VOICE_CATALOG = [
    # American Female
    {"id": "af_alloy",    "lang": "en-us", "group": "American Female", "label": "alloy"},
    {"id": "af_aoede",    "lang": "en-us", "group": "American Female", "label": "aoede"},
    {"id": "af_bella",    "lang": "en-us", "group": "American Female", "label": "bella"},
    {"id": "af_heart",    "lang": "en-us", "group": "American Female", "label": "heart"},
    {"id": "af_jessica",  "lang": "en-us", "group": "American Female", "label": "jessica"},
    {"id": "af_kore",     "lang": "en-us", "group": "American Female", "label": "kore"},
    {"id": "af_nicole",   "lang": "en-us", "group": "American Female", "label": "nicole"},
    {"id": "af_nova",     "lang": "en-us", "group": "American Female", "label": "nova"},
    {"id": "af_river",    "lang": "en-us", "group": "American Female", "label": "river"},
    {"id": "af_sarah",    "lang": "en-us", "group": "American Female", "label": "sarah"},
    {"id": "af_sky",      "lang": "en-us", "group": "American Female", "label": "sky"},
    # American Male
    {"id": "am_adam",     "lang": "en-us", "group": "American Male",   "label": "adam"},
    {"id": "am_echo",     "lang": "en-us", "group": "American Male",   "label": "echo"},
    {"id": "am_eric",     "lang": "en-us", "group": "American Male",   "label": "eric"},
    {"id": "am_fenrir",   "lang": "en-us", "group": "American Male",   "label": "fenrir"},
    {"id": "am_liam",     "lang": "en-us", "group": "American Male",   "label": "liam"},
    {"id": "am_michael",  "lang": "en-us", "group": "American Male",   "label": "michael"},
    {"id": "am_onyx",     "lang": "en-us", "group": "American Male",   "label": "onyx"},
    {"id": "am_puck",     "lang": "en-us", "group": "American Male",   "label": "puck"},
    {"id": "am_santa",    "lang": "en-us", "group": "American Male",   "label": "santa"},
    # British Female
    {"id": "bf_alice",    "lang": "en-gb", "group": "British Female",  "label": "alice"},
    {"id": "bf_emma",     "lang": "en-gb", "group": "British Female",  "label": "emma"},
    {"id": "bf_isabella", "lang": "en-gb", "group": "British Female",  "label": "isabella"},
    {"id": "bf_lily",     "lang": "en-gb", "group": "British Female",  "label": "lily"},
    # British Male
    {"id": "bm_daniel",   "lang": "en-gb", "group": "British Male",    "label": "daniel"},
    {"id": "bm_fable",    "lang": "en-gb", "group": "British Male",    "label": "fable"},
    {"id": "bm_george",   "lang": "en-gb", "group": "British Male",    "label": "george"},
    {"id": "bm_lewis",    "lang": "en-gb", "group": "British Male",    "label": "lewis"},
]

VOICE_LANG = {v["id"]: v["lang"] for v in VOICE_CATALOG}


# ─── Global kokoro instance (loaded once at startup) ────────────

KOKORO = None


def load_kokoro():
    """Load kokoro-onnx once. Cached in module globals."""
    global KOKORO
    if KOKORO is not None:
        return KOKORO

    if not MODEL_PATH.exists():
        raise FileNotFoundError(f"model not found: {MODEL_PATH}")
    if not VOICES_PATH.exists():
        raise FileNotFoundError(f"voices not found: {VOICES_PATH}")

    from kokoro_onnx import Kokoro
    print(f"Loading {MODEL_PATH.name} ...", file=sys.stderr)
    KOKORO = Kokoro(str(MODEL_PATH), str(VOICES_PATH))
    print("Ready.", file=sys.stderr)
    return KOKORO


def synthesize_wav(text: str, voice: str, speed: float) -> bytes:
    """Generate WAV bytes for given text + params."""
    import soundfile as sf

    kokoro = load_kokoro()
    lang = VOICE_LANG.get(voice, "en-us")
    samples, sample_rate = kokoro.create(text, voice=voice, speed=speed, lang=lang)

    buf = io.BytesIO()
    sf.write(buf, samples, sample_rate, format="WAV")
    return buf.getvalue()


# ─── Favorites (persisted to onboarding-voice-palette.json) ──────

def read_favorites() -> list:
    """Read favorites list from disk; return [] if file missing/empty."""
    if not FAVORITES_PATH.exists():
        return []
    try:
        data = json.loads(FAVORITES_PATH.read_text())
        return data.get("favorites", [])
    except (json.JSONDecodeError, OSError):
        return []


def write_favorites(favorites: list) -> None:
    """Persist favorites list to disk (atomic via temp + rename)."""
    payload = {
        "schema_version": 1,
        "comment": (
            "Sage voice palette — favorites curated via "
            "kokoro-tuner. The onboarding wizard reads from this file."
        ),
        "favorites": favorites,
    }
    tmp = FAVORITES_PATH.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(payload, indent=2) + "\n")
    tmp.replace(FAVORITES_PATH)


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _new_id() -> str:
    """Short, sortable, opaque id. Doesn't need crypto — these aren't keys."""
    import uuid
    return "fav-" + uuid.uuid4().hex[:8]


# ─── HTTP handler ───────────────────────────────────────────────

class TunerHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        # Compact, single-line log
        sys.stderr.write(f"[{self.log_date_time_string()}] {fmt % args}\n")

    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _send_bytes(self, status: int, ctype: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def _read_json_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def _favorite_id_from_path(self) -> str | None:
        # /favorites/{id}
        parts = self.path.strip("/").split("/")
        if len(parts) == 2 and parts[0] == "favorites":
            return parts[1]
        return None

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            try:
                html = HTML_PATH.read_bytes()
            except FileNotFoundError:
                self._send_json(500, {"error": f"{HTML_PATH.name} not found in {REPO_ROOT}"})
                return
            self._send_bytes(200, "text/html; charset=utf-8", html)
            return

        if self.path == "/voices":
            self._send_json(200, {"voices": VOICE_CATALOG})
            return

        if self.path == "/health":
            try:
                load_kokoro()
                self._send_json(200, {
                    "status": "ok",
                    "model": MODEL_PATH.name,
                    "voices_loaded": len(VOICE_CATALOG),
                })
            except Exception as e:
                self._send_json(503, {"status": "error", "error": str(e)})
            return

        if self.path == "/favorites":
            self._send_json(200, {"favorites": read_favorites()})
            return

        self._send_json(404, {"error": f"unknown path: {self.path}"})

    def do_POST(self):
        if self.path == "/synthesize":
            return self._handle_synthesize()
        if self.path == "/favorites":
            return self._handle_create_favorite()
        self._send_json(404, {"error": f"unknown path: {self.path}"})

    def do_PATCH(self):
        fav_id = self._favorite_id_from_path()
        if fav_id:
            return self._handle_update_favorite(fav_id)
        self._send_json(404, {"error": f"unknown path: {self.path}"})

    def do_DELETE(self):
        fav_id = self._favorite_id_from_path()
        if fav_id:
            return self._handle_delete_favorite(fav_id)
        self._send_json(404, {"error": f"unknown path: {self.path}"})

    # ─── Synthesis ─────────────────────────────────────────────

    def _handle_synthesize(self):
        try:
            payload = self._read_json_body()
        except Exception as e:
            return self._send_json(400, {"error": f"invalid JSON: {e}"})

        text = (payload.get("text") or "").strip()
        voice = (payload.get("voice") or "").strip()
        speed = payload.get("speed", 1.0)

        if not text:
            return self._send_json(400, {"error": "text is required"})
        if voice not in VOICE_LANG:
            return self._send_json(400, {"error": f"unknown voice: {voice}"})
        try:
            speed = float(speed)
        except (TypeError, ValueError):
            return self._send_json(400, {"error": "speed must be a number"})
        if not (0.3 <= speed <= 2.5):
            return self._send_json(400, {"error": "speed must be between 0.3 and 2.5"})

        try:
            wav = synthesize_wav(text, voice, speed)
        except Exception as e:
            return self._send_json(500, {"error": str(e)})

        self._send_bytes(200, "audio/wav", wav)

    # ─── Favorites ─────────────────────────────────────────────

    def _handle_create_favorite(self):
        try:
            payload = self._read_json_body()
        except Exception as e:
            return self._send_json(400, {"error": f"invalid JSON: {e}"})

        voice = (payload.get("voice") or "").strip()
        speed = payload.get("speed", 1.0)
        label = (payload.get("label") or "").strip()
        notes = (payload.get("notes") or "").strip()

        if voice not in VOICE_LANG:
            return self._send_json(400, {"error": f"unknown voice: {voice}"})
        try:
            speed = float(speed)
        except (TypeError, ValueError):
            return self._send_json(400, {"error": "speed must be a number"})
        if not (0.3 <= speed <= 2.5):
            return self._send_json(400, {"error": "speed must be between 0.3 and 2.5"})

        fav = {
            "id": _new_id(),
            "voice": voice,
            "speed": round(speed, 3),
            "label": label or f"{voice} @ {speed:.2f}x",
            "notes": notes,
            "saved_at": _now_iso(),
        }
        favorites = read_favorites()
        favorites.append(fav)
        write_favorites(favorites)
        self._send_json(200, {"favorite": fav})

    def _handle_update_favorite(self, fav_id: str):
        try:
            payload = self._read_json_body()
        except Exception as e:
            return self._send_json(400, {"error": f"invalid JSON: {e}"})

        favorites = read_favorites()
        for f in favorites:
            if f["id"] == fav_id:
                if "label" in payload:
                    f["label"] = (payload.get("label") or "").strip() or f["label"]
                if "notes" in payload:
                    f["notes"] = (payload.get("notes") or "").strip()
                write_favorites(favorites)
                return self._send_json(200, {"favorite": f})
        self._send_json(404, {"error": f"favorite not found: {fav_id}"})

    def _handle_delete_favorite(self, fav_id: str):
        favorites = read_favorites()
        new_list = [f for f in favorites if f["id"] != fav_id]
        if len(new_list) == len(favorites):
            return self._send_json(404, {"error": f"favorite not found: {fav_id}"})
        write_favorites(new_list)
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()


# ─── Entry ───────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Kokoro voice tuner server")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help=f"Port to listen on (default {DEFAULT_PORT})")
    parser.add_argument("--no-preload", action="store_true",
                        help="Skip preloading the model at startup")
    args = parser.parse_args()

    if not args.no_preload:
        load_kokoro()

    server = HTTPServer(("127.0.0.1", args.port), TunerHandler)
    url = f"http://127.0.0.1:{args.port}/"
    print(f"\nKokoro Voice Tuner — listening on {url}")
    print(f"Open in browser: {url}\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.server_close()


if __name__ == "__main__":
    main()
