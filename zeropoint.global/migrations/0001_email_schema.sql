-- ZeroPoint Workspace — Email Schema
-- D1 (SQLite) storage for email metadata, contacts, and routing

-- Core email storage
CREATE TABLE IF NOT EXISTS messages (
  id TEXT PRIMARY KEY,
  mailbox TEXT NOT NULL,
  folder TEXT NOT NULL DEFAULT 'inbox',
  from_address TEXT NOT NULL,
  from_name TEXT,
  to_addresses TEXT NOT NULL,
  cc_addresses TEXT,
  bcc_addresses TEXT,
  subject TEXT,
  body_text TEXT,
  body_html TEXT,
  has_attachments INTEGER NOT NULL DEFAULT 0,
  is_read INTEGER NOT NULL DEFAULT 0,
  is_starred INTEGER NOT NULL DEFAULT 0,
  thread_id TEXT,
  in_reply_to TEXT,
  message_id_header TEXT,
  receipt_id TEXT,
  raw_size_bytes INTEGER,
  received_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_messages_mailbox
  ON messages(mailbox, folder, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_messages_thread
  ON messages(thread_id);
CREATE INDEX IF NOT EXISTS idx_messages_from
  ON messages(from_address);
CREATE INDEX IF NOT EXISTS idx_messages_received
  ON messages(received_at DESC);

-- Attachment metadata (blobs live in R2)
CREATE TABLE IF NOT EXISTS attachments (
  id TEXT PRIMARY KEY,
  message_id TEXT NOT NULL REFERENCES messages(id),
  filename TEXT NOT NULL,
  content_type TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  r2_key TEXT NOT NULL,
  content_hash TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_attachments_message
  ON attachments(message_id);

-- Contacts — built from email activity
CREATE TABLE IF NOT EXISTS contacts (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  name TEXT,
  organization TEXT,
  last_seen TEXT,
  interaction_count INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_contacts_email
  ON contacts(email);

-- Workflow routing rules
CREATE TABLE IF NOT EXISTS routing_rules (
  id TEXT PRIMARY KEY,
  address_pattern TEXT NOT NULL,
  handler TEXT NOT NULL,
  config TEXT,
  priority INTEGER NOT NULL DEFAULT 0,
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
