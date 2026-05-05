-- ZeroPoint Workspace — Google Interop Schema
-- OAuth tokens and sync tracking

-- Per-operator Google OAuth2 tokens
CREATE TABLE IF NOT EXISTS google_tokens (
  operator_id TEXT PRIMARY KEY,
  access_token TEXT NOT NULL,
  refresh_token TEXT NOT NULL,
  token_type TEXT NOT NULL DEFAULT 'Bearer',
  scope TEXT,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Import/export audit log
CREATE TABLE IF NOT EXISTS google_sync_log (
  id TEXT PRIMARY KEY,
  operator_id TEXT NOT NULL,
  direction TEXT NOT NULL,            -- 'import' or 'export'
  drive_file_id TEXT NOT NULL,
  document_id TEXT,                   -- Sovereign document ID
  filename TEXT,
  content_hash TEXT,
  status TEXT NOT NULL DEFAULT 'success', -- 'success', 'error'
  error_message TEXT,
  receipt_id TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_google_sync_operator
  ON google_sync_log(operator_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_google_sync_document
  ON google_sync_log(document_id);
