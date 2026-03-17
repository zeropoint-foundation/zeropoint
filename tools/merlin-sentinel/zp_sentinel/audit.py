"""
Hash-chained audit trail implementation using Blake3.

Maps to ZeroPoint's AuditEntry and audit chain primitives.
Every policy decision is recorded with cryptographic linking to the previous entry.
"""

import logging
import sqlite3
import json
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from enum import Enum
from typing import Optional, List
from pathlib import Path

try:
    import blake3
except ImportError:
    blake3 = None
    logging.warning("blake3 not installed, using SHA256 fallback")
    import hashlib

logger = logging.getLogger(__name__)


class PolicyDecision(Enum):
    """
    Policy decision outcome.
    Maps to ZeroPoint Rust: enum PolicyDecision { Allow, Block, Warn, Review, Sanitize }
    """
    ALLOW = "allow"
    BLOCK = "block"
    WARN = "warn"
    REVIEW = "review"
    SANITIZE = "sanitize"

    def __str__(self):
        return self.value


@dataclass
class AuditEntry:
    """
    Audit trail entry with hash chain linking.
    Maps to ZeroPoint Rust AuditEntry struct.

    Fields:
    - id: Unique entry ID (sequential)
    - timestamp: ISO8601 UTC timestamp
    - prev_hash: Hash of previous entry (linking to chain)
    - entry_hash: Blake3 hash of this entry
    - actor: Who made the decision (DNS, DEVICE, ANOMALY, MANUAL, SYSTEM)
    - action: What was evaluated (domain query, MAC address, traffic pattern, etc)
    - policy_decision: The decision made (Allow/Block/Warn/Review/Sanitize)
    - risk_level: 0.0-1.0 risk assessment
    - trust_tier: Trust classification of the entity
    - details: JSON blob with additional context
    """
    id: int
    timestamp: str
    prev_hash: str
    entry_hash: str
    actor: str
    action: str
    policy_decision: str  # Stored as string in DB
    risk_level: float
    trust_tier: str
    details: str  # JSON string

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return asdict(self)

    @staticmethod
    def from_dict(data: dict) -> "AuditEntry":
        """Create from dictionary."""
        return AuditEntry(**data)


class AuditStore:
    """
    SQLite-backed hash-chained audit store.
    Provides persistent, cryptographically-linked audit trail.
    """

    def __init__(self, db_path: str):
        """Initialize audit store with SQLite database."""
        self.db_path = db_path
        self.conn = None
        self._last_entry_hash = None
        self._entry_counter = 0

        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self):
        """Initialize SQLite schema."""
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row

        cursor = self.conn.cursor()

        # Create audit table with hash chain fields
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL UNIQUE,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                policy_decision TEXT NOT NULL,
                risk_level REAL NOT NULL,
                trust_tier TEXT NOT NULL,
                details TEXT NOT NULL,
                created_at REAL NOT NULL
            )
        """
        )

        # Index for fast lookups
        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_timestamp
            ON audit_log(timestamp DESC)
        """
        )
        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_actor
            ON audit_log(actor)
        """
        )
        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_decision
            ON audit_log(policy_decision)
        """
        )

        self.conn.commit()

        # Load last entry hash for chain linking
        self._load_last_entry_hash()

        logger.info(f"Audit store initialized at {self.db_path}")

    def _load_last_entry_hash(self):
        """Load the last entry hash to continue the chain."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1")
        row = cursor.fetchone()
        if row:
            self._last_entry_hash = row[0]
            cursor.execute("SELECT MAX(id) FROM audit_log")
            self._entry_counter = cursor.fetchone()[0] or 0
        else:
            self._last_entry_hash = "genesis"  # First entry links to genesis
            self._entry_counter = 0

    def _hash_entry(self, entry_dict: dict) -> str:
        """Compute Blake3 hash of an audit entry."""
        entry_json = json.dumps(entry_dict, sort_keys=True, separators=(",", ":"))
        entry_bytes = entry_json.encode("utf-8")

        if blake3:
            return blake3.blake3(entry_bytes).hexdigest()
        else:
            # Fallback to SHA256 if blake3 not available
            import hashlib
            return hashlib.sha256(entry_bytes).hexdigest()

    def record(
        self,
        actor: str,
        action: str,
        policy_decision: PolicyDecision,
        risk_level: float = 0.0,
        trust_tier: str = "unknown",
        details: Optional[dict] = None,
    ) -> AuditEntry:
        """
        Record an audit entry in the hash chain.

        Args:
            actor: Source of decision (DNS, DEVICE, ANOMALY, MANUAL, SYSTEM)
            action: What was evaluated
            policy_decision: The decision made
            risk_level: Risk assessment 0.0-1.0
            trust_tier: Trust classification
            details: Additional context as dict

        Returns:
            AuditEntry: The recorded entry
        """
        if details is None:
            details = {}

        # Increment entry counter
        self._entry_counter += 1

        # Create entry record (without hash, will compute it)
        timestamp = datetime.now(timezone.utc).isoformat()

        entry_dict = {
            "id": self._entry_counter,
            "timestamp": timestamp,
            "prev_hash": self._last_entry_hash,
            "actor": actor,
            "action": action,
            "policy_decision": str(policy_decision),
            "risk_level": risk_level,
            "trust_tier": trust_tier,
            "details": details,
        }

        # Compute entry hash
        entry_hash = self._hash_entry(entry_dict)
        entry_dict["entry_hash"] = entry_hash

        # Create AuditEntry object
        audit_entry = AuditEntry(
            id=self._entry_counter,
            timestamp=timestamp,
            prev_hash=self._last_entry_hash,
            entry_hash=entry_hash,
            actor=actor,
            action=action,
            policy_decision=str(policy_decision),
            risk_level=risk_level,
            trust_tier=trust_tier,
            details=json.dumps(details),
        )

        # Persist to database
        cursor = self.conn.cursor()
        cursor.execute(
            """
            INSERT INTO audit_log
            (timestamp, prev_hash, entry_hash, actor, action,
             policy_decision, risk_level, trust_tier, details, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                audit_entry.timestamp,
                audit_entry.prev_hash,
                audit_entry.entry_hash,
                audit_entry.actor,
                audit_entry.action,
                audit_entry.policy_decision,
                audit_entry.risk_level,
                audit_entry.trust_tier,
                audit_entry.details,
                datetime.now().timestamp(),
            ),
        )
        self.conn.commit()

        # Update last hash for next entry
        self._last_entry_hash = entry_hash

        logger.debug(f"Audit entry recorded: {audit_entry.actor} → {audit_entry.policy_decision}")

        return audit_entry

    def get_recent(self, limit: int = 100) -> List[AuditEntry]:
        """Get recent audit entries."""
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT id, timestamp, prev_hash, entry_hash, actor, action,
                   policy_decision, risk_level, trust_tier, details
            FROM audit_log
            ORDER BY id DESC
            LIMIT ?
        """,
            (limit,),
        )

        entries = []
        for row in cursor.fetchall():
            entries.append(
                AuditEntry(
                    id=row[0],
                    timestamp=row[1],
                    prev_hash=row[2],
                    entry_hash=row[3],
                    actor=row[4],
                    action=row[5],
                    policy_decision=row[6],
                    risk_level=row[7],
                    trust_tier=row[8],
                    details=row[9],
                )
            )

        return entries

    def get_by_actor(self, actor: str, limit: int = 100) -> List[AuditEntry]:
        """Get audit entries by actor type."""
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT id, timestamp, prev_hash, entry_hash, actor, action,
                   policy_decision, risk_level, trust_tier, details
            FROM audit_log
            WHERE actor = ?
            ORDER BY id DESC
            LIMIT ?
        """,
            (actor, limit),
        )

        entries = []
        for row in cursor.fetchall():
            entries.append(
                AuditEntry(
                    id=row[0],
                    timestamp=row[1],
                    prev_hash=row[2],
                    entry_hash=row[3],
                    actor=row[4],
                    action=row[5],
                    policy_decision=row[6],
                    risk_level=row[7],
                    trust_tier=row[8],
                    details=row[9],
                )
            )

        return entries

    def get_by_decision(self, decision: PolicyDecision, limit: int = 100) -> List[AuditEntry]:
        """Get audit entries by decision type."""
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT id, timestamp, prev_hash, entry_hash, actor, action,
                   policy_decision, risk_level, trust_tier, details
            FROM audit_log
            WHERE policy_decision = ?
            ORDER BY id DESC
            LIMIT ?
        """,
            (str(decision), limit),
        )

        entries = []
        for row in cursor.fetchall():
            entries.append(
                AuditEntry(
                    id=row[0],
                    timestamp=row[1],
                    prev_hash=row[2],
                    entry_hash=row[3],
                    actor=row[4],
                    action=row[5],
                    policy_decision=row[6],
                    risk_level=row[7],
                    trust_tier=row[8],
                    details=row[9],
                )
            )

        return entries

    def verify_chain(self, start_id: int = 1, end_id: Optional[int] = None) -> bool:
        """
        Verify the integrity of the hash chain.
        Returns True if all hashes link correctly.
        """
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT id, timestamp, prev_hash, entry_hash, actor, action,
                   policy_decision, risk_level, trust_tier, details
            FROM audit_log
            WHERE id >= ?
            ORDER BY id ASC
        """,
            (start_id,),
        )

        prev_hash = "genesis"
        entry_count = 0

        for row in cursor.fetchall():
            entry_id = row[0]
            entry_hash = row[3]

            # Verify prev_hash links to previous entry
            if row[2] != prev_hash:
                logger.error(
                    f"Chain broken at entry {entry_id}: "
                    f"expected prev_hash {prev_hash}, got {row[2]}"
                )
                return False

            # Recompute entry hash and verify
            # Details is stored as JSON string in DB but hashed as dict during recording
            try:
                details_parsed = json.loads(row[9])
            except (json.JSONDecodeError, TypeError):
                details_parsed = row[9]

            entry_dict = {
                "id": row[0],
                "timestamp": row[1],
                "prev_hash": row[2],
                "actor": row[4],
                "action": row[5],
                "policy_decision": row[6],
                "risk_level": row[7],
                "trust_tier": row[8],
                "details": details_parsed,
            }

            computed_hash = self._hash_entry(entry_dict)
            if computed_hash != entry_hash:
                logger.error(
                    f"Hash mismatch at entry {entry_id}: "
                    f"expected {entry_hash}, computed {computed_hash}"
                )
                return False

            prev_hash = entry_hash
            entry_count += 1

        logger.info(f"Audit chain verified: {entry_count} entries")
        return True

    def get_stats(self) -> dict:
        """Get audit store statistics."""
        cursor = self.conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM audit_log")
        total_entries = cursor.fetchone()[0]

        cursor.execute(
            """
            SELECT policy_decision, COUNT(*) as count
            FROM audit_log
            GROUP BY policy_decision
        """
        )
        decisions = {row[0]: row[1] for row in cursor.fetchall()}

        cursor.execute(
            """
            SELECT actor, COUNT(*) as count
            FROM audit_log
            GROUP BY actor
        """
        )
        actors = {row[0]: row[1] for row in cursor.fetchall()}

        cursor.execute(
            """
            SELECT AVG(risk_level) as avg_risk
            FROM audit_log
        """
        )
        avg_risk = cursor.fetchone()[0] or 0.0

        return {
            "total_entries": total_entries,
            "decisions": decisions,
            "actors": actors,
            "average_risk_level": avg_risk,
            "last_hash": self._last_entry_hash,
        }

    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()
