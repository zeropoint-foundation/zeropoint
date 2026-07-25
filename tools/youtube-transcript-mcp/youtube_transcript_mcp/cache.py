"""Persistent SQLite cache for fetched transcripts.

Rationale: transcripts are immutable once published, and YouTube rate-limits
aggressively. Caching means we fetch any (video, language, translation) triple
at most once — cheaper, faster, and reproducible for research. The cache is the
first rung of the ladder and the only write path for successful fetches.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from pathlib import Path
from typing import List, Optional

from .common import TranscriptRecord, now_iso

_DEFAULT_DIR = Path(
    os.environ.get("YTMCP_CACHE_DIR", str(Path.home() / ".cache" / "youtube-transcript-mcp"))
)


def _request_key(video_id: str, languages: List[str], translate_to: Optional[str]) -> str:
    """One stable key per distinct request shape."""
    langs = ",".join(languages) if languages else ""
    return f"{video_id}|{langs}|{translate_to or ''}"


class TranscriptCache:
    """Thread-safe SQLite-backed transcript store.

    A single connection guarded by a lock is plenty for a personal-scale tool
    (hundreds of calls a month) and avoids per-call connection overhead.
    """

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = Path(db_path) if db_path else _DEFAULT_DIR / "transcripts.db"
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS transcripts (
                    request_key   TEXT PRIMARY KEY,
                    video_id      TEXT NOT NULL,
                    language_code TEXT,
                    translated_to TEXT,
                    source        TEXT,
                    record_json   TEXT NOT NULL,
                    cached_at     TEXT NOT NULL
                );
                """
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_video ON transcripts(video_id);"
            )
            self._conn.commit()

    def get(
        self, video_id: str, languages: List[str], translate_to: Optional[str]
    ) -> Optional[TranscriptRecord]:
        key = _request_key(video_id, languages, translate_to)
        with self._lock:
            row = self._conn.execute(
                "SELECT record_json FROM transcripts WHERE request_key = ?", (key,)
            ).fetchone()
        if not row:
            return None
        record: TranscriptRecord = json.loads(row[0])
        return record

    def put(
        self,
        video_id: str,
        languages: List[str],
        translate_to: Optional[str],
        record: TranscriptRecord,
    ) -> None:
        key = _request_key(video_id, languages, translate_to)
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO transcripts
                    (request_key, video_id, language_code, translated_to, source, record_json, cached_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(request_key) DO UPDATE SET
                    language_code=excluded.language_code,
                    translated_to=excluded.translated_to,
                    source=excluded.source,
                    record_json=excluded.record_json,
                    cached_at=excluded.cached_at
                """,
                (
                    key,
                    video_id,
                    record.get("language_code"),
                    translate_to,
                    record.get("source"),
                    json.dumps(record, ensure_ascii=False),
                    now_iso(),
                ),
            )
            self._conn.commit()

    def stats(self) -> dict:
        with self._lock:
            total = self._conn.execute("SELECT COUNT(*) FROM transcripts").fetchone()[0]
            distinct = self._conn.execute(
                "SELECT COUNT(DISTINCT video_id) FROM transcripts"
            ).fetchone()[0]
            by_source = dict(
                self._conn.execute(
                    "SELECT source, COUNT(*) FROM transcripts GROUP BY source"
                ).fetchall()
            )
        size_bytes = self.db_path.stat().st_size if self.db_path.exists() else 0
        return {
            "db_path": str(self.db_path),
            "cached_requests": total,
            "distinct_videos": distinct,
            "by_source": by_source,
            "db_size_bytes": size_bytes,
        }

    def clear(self, video_id: Optional[str] = None) -> int:
        with self._lock:
            if video_id:
                cur = self._conn.execute(
                    "DELETE FROM transcripts WHERE video_id = ?", (video_id,)
                )
            else:
                cur = self._conn.execute("DELETE FROM transcripts")
            self._conn.commit()
            return cur.rowcount

    def close(self) -> None:
        with self._lock:
            self._conn.close()
