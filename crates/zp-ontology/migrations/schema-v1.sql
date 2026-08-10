-- ZeroPoint ontology schema v1.
--
-- Cartographer-materialized derived object graph. All data here is
-- rebuildable from the receipt chain (`audit.db`) — this database is
-- explicitly disposable per KEEL §II.13 P5 (store-and-forward is primary).
--
-- Per CARTOGRAPHER-IMPLEMENTATION-DESIGN-2026-07.md §Section 2.

-- ── Meta / high-water mark ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
) WITHOUT ROWID;

-- ── Objects (Trajectory, Decision, Insight, Artifact, Friction) ───────────
--
-- Content-addressed IDs (16 bytes, first half of sha256).
-- payload is the full serde_json serialization of the typed object.
-- boundary_confidence is present only on trajectory rows; NULL otherwise.
CREATE TABLE IF NOT EXISTS objects (
    id BLOB PRIMARY KEY,
    object_type TEXT NOT NULL
        CHECK (object_type IN ('trajectory', 'decision', 'insight', 'artifact', 'friction')),
    trajectory_id BLOB,
    status TEXT NOT NULL,
    title TEXT NOT NULL,
    payload BLOB NOT NULL,
    boundary_confidence REAL,
    created_at TEXT NOT NULL,
    last_active TEXT NOT NULL,
    FOREIGN KEY (trajectory_id) REFERENCES objects(id)
);

CREATE INDEX IF NOT EXISTS idx_objects_type_status ON objects(object_type, status);
CREATE INDEX IF NOT EXISTS idx_objects_trajectory ON objects(trajectory_id)
    WHERE trajectory_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_objects_last_active ON objects(last_active);
CREATE INDEX IF NOT EXISTS idx_objects_type_active ON objects(object_type, last_active DESC);

-- ── Relationships (typed, directional) ────────────────────────────────────
CREATE TABLE IF NOT EXISTS relationships (
    id BLOB PRIMARY KEY,
    source_type TEXT NOT NULL,
    source_id BLOB NOT NULL,
    target_type TEXT NOT NULL,
    target_id BLOB NOT NULL,
    kind TEXT NOT NULL,
    created_at TEXT NOT NULL,
    payload BLOB NOT NULL,
    UNIQUE (source_type, source_id, target_type, target_id, kind)
);

CREATE INDEX IF NOT EXISTS idx_rel_source ON relationships(source_type, source_id);
CREATE INDEX IF NOT EXISTS idx_rel_target ON relationships(target_type, target_id);
CREATE INDEX IF NOT EXISTS idx_rel_kind ON relationships(kind);

-- ── Object-to-receipt linkage (many-to-many) ──────────────────────────────
--
-- Each object references the chain entries that produced or reinforce it.
-- audit_id matches the AuditId from the chain (16-byte UUIDv7).
-- role optionally distinguishes origin vs evidence vs update.
CREATE TABLE IF NOT EXISTS object_receipts (
    object_id BLOB NOT NULL,
    audit_id BLOB NOT NULL,
    role TEXT,
    PRIMARY KEY (object_id, audit_id)
);

CREATE INDEX IF NOT EXISTS idx_object_receipts_audit ON object_receipts(audit_id);

-- ── Relationship-to-receipt linkage ───────────────────────────────────────
CREATE TABLE IF NOT EXISTS relationship_receipts (
    relationship_id BLOB NOT NULL,
    audit_id BLOB NOT NULL,
    PRIMARY KEY (relationship_id, audit_id)
);
