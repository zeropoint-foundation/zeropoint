-- ZeroPoint Workspace — Document Store & Media Asset Schema
-- Documents, media assets, file transfer links, and access logging

-- ── Document Store ────────────────────────────────────────

CREATE TABLE IF NOT EXISTS documents (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  category TEXT NOT NULL,          -- 'legal', 'technical', 'media', 'correspondence', 'internal'
  content_type TEXT NOT NULL,      -- MIME type
  r2_key TEXT NOT NULL,            -- R2 object key
  content_hash TEXT NOT NULL,      -- Blake3 hash of file contents
  size_bytes INTEGER NOT NULL DEFAULT 0,
  version INTEGER NOT NULL DEFAULT 1,
  parent_version_id TEXT,          -- Previous version reference (version chain)
  uploaded_by TEXT NOT NULL,       -- Operator ID
  receipt_id TEXT,                 -- ZeroPoint receipt for the upload action
  tags TEXT NOT NULL DEFAULT '[]', -- JSON array of strings
  description TEXT,                -- Optional human-readable summary
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_documents_category
  ON documents(category, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_documents_hash
  ON documents(content_hash);
CREATE INDEX IF NOT EXISTS idx_documents_uploaded_by
  ON documents(uploaded_by, created_at DESC);

-- Document access log — every view, download, share is receipted
CREATE TABLE IF NOT EXISTS document_access (
  id TEXT PRIMARY KEY,
  document_id TEXT NOT NULL,
  accessor TEXT NOT NULL,          -- Operator ID or 'external:<token>'
  action TEXT NOT NULL,            -- 'view', 'download', 'share', 'edit', 'version'
  receipt_id TEXT,
  ip_address TEXT,
  accessed_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_doc_access_document
  ON document_access(document_id, accessed_at DESC);
CREATE INDEX IF NOT EXISTS idx_doc_access_accessor
  ON document_access(accessor, accessed_at DESC);

-- ── Media Assets ──────────────────────────────────────────

CREATE TABLE IF NOT EXISTS media_assets (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  asset_type TEXT NOT NULL,        -- 'image', 'video', 'audio', 'graphic', 'document'
  status TEXT NOT NULL DEFAULT 'raw',  -- 'raw', 'in_review', 'approved', 'published', 'archived'
  content_type TEXT NOT NULL,      -- MIME type
  r2_key TEXT NOT NULL,
  content_hash TEXT NOT NULL,
  size_bytes INTEGER NOT NULL DEFAULT 0,
  thumbnail_r2_key TEXT,           -- R2 key for thumbnail/preview
  dimensions TEXT,                 -- JSON: { "width": N, "height": N } for images/video
  duration_seconds REAL,           -- For audio/video
  uploaded_by TEXT NOT NULL,
  approved_by TEXT,                -- Operator who approved for publish
  approval_receipt_id TEXT,
  tags TEXT NOT NULL DEFAULT '[]', -- JSON array
  description TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  published_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_media_status
  ON media_assets(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_media_type
  ON media_assets(asset_type, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_media_uploaded_by
  ON media_assets(uploaded_by, created_at DESC);

-- ── File Transfer ─────────────────────────────────────────

-- Upload links — one-time, time-limited inbound file drops
CREATE TABLE IF NOT EXISTS upload_links (
  id TEXT PRIMARY KEY,             -- Short token for URL
  recipient_mailbox TEXT NOT NULL,
  created_by TEXT NOT NULL,        -- 'system' for bounce recovery, operator ID for manual
  original_sender TEXT,            -- Email that triggered bounce (if applicable)
  expires_at TEXT NOT NULL,
  consumed_at TEXT,                -- NULL until used
  r2_key TEXT,                     -- Populated after upload
  content_hash TEXT,
  filename TEXT,
  size_bytes INTEGER,
  receipt_id TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_upload_links_mailbox
  ON upload_links(recipient_mailbox, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_upload_links_expires
  ON upload_links(expires_at);

-- Download links — time-limited, access-capped outbound file shares
CREATE TABLE IF NOT EXISTS download_links (
  id TEXT PRIMARY KEY,             -- Short token for URL
  document_id TEXT,                -- Reference to documents table (optional)
  media_asset_id TEXT,             -- Reference to media_assets table (optional)
  r2_key TEXT NOT NULL,            -- Direct R2 key for the file
  filename TEXT NOT NULL,
  content_type TEXT NOT NULL,
  size_bytes INTEGER NOT NULL DEFAULT 0,
  created_by TEXT NOT NULL,        -- Operator ID
  expires_at TEXT NOT NULL,
  max_downloads INTEGER,           -- NULL = unlimited
  download_count INTEGER NOT NULL DEFAULT 0,
  revoked_at TEXT,                 -- NULL = active, timestamp = revoked
  revoked_by TEXT,
  receipt_id TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_download_links_expires
  ON download_links(expires_at);
CREATE INDEX IF NOT EXISTS idx_download_links_created_by
  ON download_links(created_by, created_at DESC);

-- Download access log — every download is logged
CREATE TABLE IF NOT EXISTS download_access (
  id TEXT PRIMARY KEY,
  download_link_id TEXT NOT NULL,
  ip_address TEXT,
  user_agent TEXT,
  receipt_id TEXT,
  accessed_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_download_access_link
  ON download_access(download_link_id, accessed_at DESC);
