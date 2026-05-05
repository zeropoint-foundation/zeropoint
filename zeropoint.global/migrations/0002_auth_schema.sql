-- ZeroPoint Workspace — Auth & Governance Schema
-- Operators, capabilities, and receipt audit trail

-- Operator registry — public keys and capability grants
CREATE TABLE IF NOT EXISTS operators (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  public_key_hex TEXT NOT NULL,
  capabilities TEXT NOT NULL DEFAULT '[]',
  role TEXT NOT NULL DEFAULT 'staff',
  active INTEGER NOT NULL DEFAULT 1,
  onboarded_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_operators_email
  ON operators(email);

-- Governance receipts — audit trail for every authenticated action
CREATE TABLE IF NOT EXISTS receipts (
  id TEXT PRIMARY KEY,
  operator_id TEXT NOT NULL,
  claim TEXT NOT NULL,
  subject TEXT,
  capability_used TEXT,
  metadata TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_receipts_operator
  ON receipts(operator_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_receipts_claim
  ON receipts(claim, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_receipts_created
  ON receipts(created_at DESC);

-- Succession events — auditable authority transfers
CREATE TABLE IF NOT EXISTS succession_events (
  id TEXT PRIMARY KEY,
  event_type TEXT NOT NULL,
  initiated_by TEXT NOT NULL,
  co_signer TEXT,
  reason TEXT,
  capabilities_granted TEXT,
  effective_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_succession_created
  ON succession_events(created_at DESC);
