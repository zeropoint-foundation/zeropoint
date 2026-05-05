-- ZeroPoint Workspace — Workflow Automation Schema
-- Tasks, inquiries, and publish queue

-- ── Tasks ─────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS tasks (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  description TEXT,
  status TEXT NOT NULL DEFAULT 'open',    -- 'open', 'in_progress', 'done', 'cancelled'
  priority TEXT NOT NULL DEFAULT 'normal', -- 'low', 'normal', 'high', 'urgent'
  assignee TEXT,                          -- Operator ID
  created_by TEXT NOT NULL,               -- Operator ID or 'system'
  due_date TEXT,
  source_message_id TEXT,                 -- Reference to email that created this task
  tags TEXT NOT NULL DEFAULT '[]',        -- JSON array
  receipt_id TEXT,
  completed_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_tasks_assignee
  ON tasks(assignee, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_tasks_status
  ON tasks(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_tasks_source
  ON tasks(source_message_id);

-- ── Publish Queue ─────────────────────────────────────────

CREATE TABLE IF NOT EXISTS publish_queue (
  id TEXT PRIMARY KEY,
  document_id TEXT,                       -- Reference to documents table
  media_asset_id TEXT,                    -- Reference to media_assets table
  title TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending', -- 'pending', 'approved', 'rejected', 'published'
  submitted_by TEXT NOT NULL,             -- Operator ID
  reviewed_by TEXT,                       -- Operator who approved/rejected
  review_note TEXT,
  source_message_id TEXT,                 -- Email that triggered the submission
  receipt_id TEXT,
  submitted_at TEXT NOT NULL DEFAULT (datetime('now')),
  reviewed_at TEXT,
  published_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_publish_status
  ON publish_queue(status, submitted_at DESC);
CREATE INDEX IF NOT EXISTS idx_publish_submitted_by
  ON publish_queue(submitted_by, submitted_at DESC);

-- ── Inquiries (info@ routing) ─────────────────────────────

CREATE TABLE IF NOT EXISTS inquiries (
  id TEXT PRIMARY KEY,
  category TEXT NOT NULL DEFAULT 'general', -- 'grant', 'technical', 'media', 'partnership', 'general'
  source_message_id TEXT NOT NULL,         -- Reference to the original email
  from_email TEXT NOT NULL,
  from_name TEXT,
  subject TEXT NOT NULL,
  summary TEXT,
  assigned_to TEXT,                        -- Operator ID
  status TEXT NOT NULL DEFAULT 'new',      -- 'new', 'assigned', 'responded', 'closed'
  response_deadline TEXT,
  receipt_id TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  responded_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_inquiries_status
  ON inquiries(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_inquiries_assigned
  ON inquiries(assigned_to, status, created_at DESC);

-- ── DMARC Reports ─────────────────────────────────────────

CREATE TABLE IF NOT EXISTS dmarc_reports (
  id TEXT PRIMARY KEY,
  source_message_id TEXT NOT NULL,
  reporter_org TEXT,
  reporter_email TEXT,
  report_id TEXT,
  date_begin TEXT,
  date_end TEXT,
  domain TEXT,
  policy TEXT,                             -- JSON: { p, sp, adkim, aspf }
  records_count INTEGER DEFAULT 0,
  pass_count INTEGER DEFAULT 0,
  fail_count INTEGER DEFAULT 0,
  raw_r2_key TEXT,                         -- R2 key for the raw XML report
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_dmarc_domain
  ON dmarc_reports(domain, created_at DESC);
