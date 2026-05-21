-- Phase 1: cryptographically signed foundation chain.
-- Historical `receipts` rows are preserved read-only; this table holds
-- every new entry from genesis forward.

CREATE TABLE IF NOT EXISTS chain_entries (
  -- Identity & application content
  id              TEXT PRIMARY KEY,           -- ULID
  operator_id     TEXT NOT NULL,
  claim           TEXT NOT NULL,
  subject         TEXT NOT NULL DEFAULT '',
  capability_used TEXT NOT NULL DEFAULT '',
  metadata        TEXT NOT NULL DEFAULT '{}', -- JSON string
  created_at      TEXT NOT NULL,              -- ISO-8601, set by worker

  -- Chain linkage
  sequence        INTEGER NOT NULL,           -- monotonic, starts at 0 (genesis)
  prev_hash       TEXT NOT NULL,              -- hex; genesis_hash() for entry 0
  entry_hash      TEXT NOT NULL,              -- hex; blake3 over canonical preimage

  -- Attestation (JSON array of {alg, kid, value})
  signatures      TEXT NOT NULL DEFAULT '[]'
);

-- Storage-layer fork guard: no two entries may share the same prev_hash,
-- except the genesis sentinel (blake3(b"") hex) which is shared by nothing
-- else in practice — the WHERE excludes it so genesis can be inserted once.
CREATE UNIQUE INDEX idx_chain_entries_unique_prev_hash
  ON chain_entries(prev_hash)
  WHERE prev_hash != 'af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262';

-- Monotonic sequence guard: no two entries at the same position.
CREATE UNIQUE INDEX idx_chain_entries_sequence ON chain_entries(sequence);

-- Read indexes (mirror legacy receipts indexes).
CREATE INDEX idx_chain_entries_operator ON chain_entries(operator_id, created_at DESC);
CREATE INDEX idx_chain_entries_claim    ON chain_entries(claim,       created_at DESC);
CREATE INDEX idx_chain_entries_created  ON chain_entries(created_at DESC);
