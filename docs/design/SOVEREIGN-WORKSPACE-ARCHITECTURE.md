# ZeroPoint Foundation — Sovereign Workspace Architecture

**Date:** 2026-05-02
**Status:** Design
**Purpose:** Operational workspace for ZeroPoint Foundation staff (Ken, Lorrie, Katie) that serves as both a functional tool and a proving ground for ZeroPoint's governance primitives.

---

## 1. Design Goals

### Operational
- Three staff members with @zeropoint.global email that works reliably
- Shared document repository with foundation legal docs pre-loaded
- Media asset management for raw and published content
- Zero-friction onboarding — if you can use email, you can use this

### Strategic
- **Proving ground:** Every workflow friction informs ZeroPoint's development
- **Dogfooding governance:** Receipts, capabilities, delegation chains — used for real work
- **Google interop without dependence:** Import/export seamlessly, store sovereignly
- **Exit ramp architecture:** Make it so easy to work outside Google that the switch is invisible

### Architectural
- Email as the universal automation trigger (N8N-style workflows, natively governed)
- Pixel-streaming UI renders server-side — client devices hold no data
- Every action receipted — who did what, when, with what authority
- Modular: email, documents, media, and workflows are independent planes that compose

---

## 2. Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    CLIENT DEVICES                            │
│         (browser — receives pixel stream only)               │
│    ┌──────────┐   ┌──────────┐   ┌──────────┐              │
│    │   Ken    │   │  Lorrie  │   │  Katie   │              │
│    └────┬─────┘   └────┬─────┘   └────┬─────┘              │
│         │              │              │                      │
│         └──────────────┼──────────────┘                      │
│                   WebRTC / WSS                               │
└────────────────────────┼────────────────────────────────────┘
                         │
┌────────────────────────┼────────────────────────────────────┐
│              SOVEREIGN RENDER NODE (APOLLO)                   │
│                        │                                     │
│    ┌───────────────────┴───────────────────┐                │
│    │         Headless Browser (Puppeteer)   │                │
│    │    ┌─────────┬──────────┬──────────┐  │                │
│    │    │  Email  │  Docs    │  Media   │  │                │
│    │    │  Client │  Viewer  │  Manager │  │                │
│    │    └────┬────┴────┬─────┴────┬─────┘  │                │
│    └─────────┼─────────┼──────────┼────────┘                │
│              │         │          │                           │
│    ┌─────────┴─────────┴──────────┴────────┐                │
│    │           Workspace API Layer          │                │
│    │  (email store, doc store, media store) │                │
│    └─────────┬─────────┬──────────┬────────┘                │
│              │         │          │                           │
│    ┌─────────┴─────────┴──────────┴────────┐                │
│    │         ZeroPoint Governance Gate       │                │
│    │   (capabilities, receipts, audit)       │                │
│    └───────────────────────────────────────┘                │
└─────────────────────────────────────────────────────────────┘
                         │
┌────────────────────────┼────────────────────────────────────┐
│              CLOUDFLARE EDGE                                 │
│                        │                                     │
│    ┌──────────────┐   ┌┴─────────────┐   ┌──────────────┐  │
│    │ Email Worker  │   │ SMTP Relay   │   │  D1 Database │  │
│    │ (inbound)     │   │ (outbound)   │   │  (metadata)  │  │
│    └──────┬───────┘   └──────────────┘   └──────────────┘  │
│           │                                                  │
│    ┌──────┴───────────────────────────────────────────────┐  │
│    │              Workflow Engine                          │  │
│    │  email-to-archive │ email-to-task │ email-to-publish  │  │
│    └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                         │
┌────────────────────────┼────────────────────────────────────┐
│              INTEROP LAYER                                   │
│    ┌──────────────┐   ┌──────────────┐   ┌──────────────┐  │
│    │ Google Docs   │   │ Google Drive │   │ Google Sheets│  │
│    │ Import/Export │   │ Sync Adapter │   │ Import/Export│  │
│    └──────────────┘   └──────────────┘   └──────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Email System

### 3.1 Inbound — Cloudflare Email Workers

Cloudflare Email Routing forwards all @zeropoint.global mail to an Email Worker. The worker:

1. **Verifies** DKIM/SPF/DMARC on the incoming message
2. **Parses** headers, body (text + HTML), and attachments
3. **Routes** based on recipient address:
   - `ken@`, `lorrie@`, `katie@` → personal mailbox (D1 + R2 storage)
   - `publish@` → publish workflow (attachment → approval gate → publication)
   - `archive@` → archive workflow (hash, store, receipt)
   - `task@` → task creation (parse subject line conventions)
   - `info@` → query routing (classify, delegate, notify)
4. **Stores** message metadata in D1, raw message + attachments in R2
5. **Emits** a receipt for every inbound message processed

```javascript
// Email Worker entry point
export default {
  async email(message, env, ctx) {
    const parsed = await parseMessage(message);
    const route = resolveRoute(parsed.to);
    
    // Store in D1 + R2
    const msgId = await storeMessage(env, parsed);
    
    // Dispatch to workflow
    await route.handler(env, msgId, parsed);
    
    // Emit governance receipt
    await emitReceipt(env, {
      claim: "email:received",
      subject: msgId,
      metadata: { from: parsed.from, to: parsed.to, route: route.name }
    });
  }
};
```

### 3.2 Outbound — SMTP Relay

Options ranked by practicality:

1. **Resend** — Free 100 emails/day (3k/month). Clean HTTP API, callable from Workers. Uses AWS SES under the hood. Best DX for low-volume.
2. **Amazon SES** — $0.10/1000 emails. Battle-tested deliverability. Direct API access from Workers.
3. **Cloudflare Email Workers (outbound)** — Native solution when it exits beta.
4. **Self-hosted Postfix on APOLLO** — Maximum sovereignty, but deliverability requires careful IP reputation management.

**Recommendation:** Start with Resend (option 1) — free tier covers foundation volume, excellent API, and provider is swappable via env config without code changes. The send module abstracts the relay behind a provider interface.

### 3.3 DNS Records Required

```
; MX — route inbound to Cloudflare Email Routing
zeropoint.global.  MX  10  route1.mx.cloudflare.net
zeropoint.global.  MX  20  route2.mx.cloudflare.net
zeropoint.global.  MX  30  route3.mx.cloudflare.net

; SPF — authorize outbound relay
zeropoint.global.  TXT  "v=spf1 include:resend.com ~all"

; DKIM — records provided by Resend during domain verification
; (typically 3 CNAME records pointing to Resend's DKIM infrastructure)

; DMARC — start with quarantine, move to reject after testing
_dmarc.zeropoint.global.  TXT  "v=DMARC1; p=quarantine; rua=mailto:dmarc@zeropoint.global"
```

### 3.4 Storage Schema (D1)

```sql
-- Core email storage
CREATE TABLE messages (
  id TEXT PRIMARY KEY,           -- ULID for sortable uniqueness
  mailbox TEXT NOT NULL,         -- 'ken', 'lorrie', 'katie', 'info', etc.
  folder TEXT DEFAULT 'inbox',   -- 'inbox', 'sent', 'archive', 'trash'
  from_address TEXT NOT NULL,
  from_name TEXT,
  to_addresses TEXT NOT NULL,    -- JSON array
  cc_addresses TEXT,             -- JSON array
  subject TEXT,
  body_text TEXT,
  body_html TEXT,
  has_attachments INTEGER DEFAULT 0,
  is_read INTEGER DEFAULT 0,
  is_starred INTEGER DEFAULT 0,
  thread_id TEXT,                -- for conversation threading
  in_reply_to TEXT,              -- Message-ID reference
  receipt_id TEXT,               -- ZeroPoint receipt reference
  received_at TEXT NOT NULL,     -- ISO 8601
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX idx_messages_mailbox ON messages(mailbox, folder, received_at DESC);
CREATE INDEX idx_messages_thread ON messages(thread_id);
CREATE INDEX idx_messages_from ON messages(from_address);

-- Attachments metadata (blobs in R2)
CREATE TABLE attachments (
  id TEXT PRIMARY KEY,
  message_id TEXT NOT NULL REFERENCES messages(id),
  filename TEXT NOT NULL,
  content_type TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  r2_key TEXT NOT NULL,          -- R2 object key
  content_hash TEXT,             -- Blake3 hash for integrity
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX idx_attachments_message ON attachments(message_id);

-- Contacts (built from email activity)
CREATE TABLE contacts (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  name TEXT,
  organization TEXT,
  last_seen TEXT,
  interaction_count INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now'))
);

-- Workflow routing rules
CREATE TABLE routing_rules (
  id TEXT PRIMARY KEY,
  address_pattern TEXT NOT NULL,  -- glob: 'publish@*', 'task@*'
  handler TEXT NOT NULL,          -- 'publish', 'archive', 'task', 'route'
  config TEXT,                    -- JSON handler config
  priority INTEGER DEFAULT 0,
  active INTEGER DEFAULT 1,
  created_at TEXT DEFAULT (datetime('now'))
);
```

---

## 4. Secure Channel — Internal Encrypted Communications

Email is the public-facing channel. The secure channel is the internal nervous system — a completely separate communication layer where messages never leave sovereign infrastructure. No SMTP, no federation, no third-party relay, no DNS resolution. Messages are born on the render node and stay there.

### 4.1 Architecture: Two Channels, Two Trust Models

| Property | Email (Public Channel) | Secure Channel (Internal) |
|----------|----------------------|--------------------------|
| Scope | External + internal | Internal only |
| Transport | SMTP (federated, multi-hop) | Direct WebSocket on render node (zero-hop) |
| Encryption in transit | TLS (opportunistic, relay-dependent) | Always encrypted — ChaCha20-Poly1305, end-to-end |
| Encryption at rest | R2 (Cloudflare-managed encryption) | R2 + vault-layer encryption (sovereign keys) |
| Third-party exposure | Yes — SMTP relays, recipient mail servers | None — never leaves your infrastructure |
| Metadata exposure | Headers visible to every relay | No external metadata — sender, recipient, timestamp all internal |
| Deliverability concerns | SPF/DKIM/DMARC, spam filters, bounces | None — delivery is local function call |
| Message size limit | ~25MB (relay-dependent) | Unlimited — R2-backed, same as file transfer |
| Participants | Anyone with an email address | Foundation staff + workspace agent only |
| Governance | Receipted | Receipted + capability-scoped |

### 4.2 Secure Channel Capabilities

**Real-time messaging.** Instant delivery — no store-and-forward delay. Messages appear as they're sent, with typing indicators, read receipts, and presence (who's online, who's in a call).

**Threads.** Conversations are threaded by default. Start a thread from any message — discussions stay organized without inbox clutter. Threads can be linked to documents, tasks, or media assets.

**Voice notes.** Hold-to-record, Whisper transcribes on the render node, both audio and transcript stored. Same as email voice messages but delivered instantly, never touching external infrastructure.

**File sharing.** Drop any file into the channel — it goes to R2, hashed with Blake3, receipted. No size limit. The file never traverses email infrastructure.

**Reactions and annotations.** Quick acknowledgment without generating a new message. Useful for approval flows: Ken posts a draft, Lorrie reacts with a checkmark. The reaction is receipted.

**Agent participation.** The workspace agent has a presence in the secure channel. It can be @mentioned to trigger workflows, answer questions about documents, summarize threads, or surface relevant context. Its messages are visually distinct and its capabilities are scoped — it can read and respond but can't initiate conversations or modify documents without human authorization.

### 4.3 Encryption Model

```
Sender (staff member on render node)
    │
    ▼
┌─────────────────────────────────────┐
│  Message plaintext                  │
│  + Blake3 content hash              │
│  + Ed25519 signature (sender key)   │
│  + ChaCha20-Poly1305 encryption     │
│    (per-channel symmetric key,      │
│     derived from members' keypairs) │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│  D1: message metadata (encrypted)   │
│  R2: message body + attachments     │
│       (encrypted at rest)           │
│  Receipt chain: message:sent claim  │
└─────────────────────────────────────┘
               │
               ▼
  Recipients' render sessions decrypt
  and display in real time via WebSocket
```

Messages are encrypted with a per-channel symmetric key derived from the participants' Ed25519 keypairs. Even if D1 or R2 were compromised, the messages are ciphertext without the members' private keys. The render node holds the decryption keys in memory during active sessions only — they're never written to disk.

### 4.4 Channel Types

**#general** — All staff. Foundation-wide announcements, daily coordination, casual conversation. The workspace agent monitors this channel for actionable items.

**#decisions** — All staff. Formal decisions that need to be recorded. Every message in this channel gets an enhanced receipt with `decision:recorded` claim type. This channel becomes the foundation's decision log — auditable, tamper-evident, legally meaningful.

**#private (1:1)** — Direct messages between any two participants. Same encryption model, scoped to two keypairs.

**#with-agent** — Ken's direct channel with the workspace agent for administrative commands, workflow configuration, and system status. Agent has elevated capabilities here (can modify workflows, run reports) that it doesn't have in other channels.

### 4.5 Relationship to Email

The two channels complement, not compete:

- **External inquiry arrives via email** → agent routes it → posts a summary in #general → staff discuss in secure channel → response drafted in secure channel → sent via email
- **Internal decision made in #decisions** → needs external communication → staff drafts in secure channel → sends via email to external parties
- **Document shared externally via email** → secure channel notification: "Articles_v3.docx shared with counsel@lawfirm.com" with receipt link

The secure channel is where the thinking happens. Email is where the output goes.

### 4.6 Schema

```sql
-- Secure channel messages
CREATE TABLE secure_messages (
  id TEXT PRIMARY KEY,              -- ULID
  channel_id TEXT NOT NULL,
  sender TEXT NOT NULL,             -- staff member or 'agent'
  thread_id TEXT,                   -- NULL for top-level, parent msg ID for replies
  content_encrypted BLOB NOT NULL,  -- ChaCha20-Poly1305 ciphertext
  content_hash TEXT NOT NULL,       -- Blake3 hash of plaintext (for integrity)
  signature TEXT NOT NULL,          -- Ed25519 signature
  has_attachments INTEGER DEFAULT 0,
  receipt_id TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  edited_at TEXT                    -- NULL if never edited; edits are receipted
);

CREATE INDEX idx_secure_channel ON secure_messages(channel_id, created_at);
CREATE INDEX idx_secure_thread ON secure_messages(thread_id);

-- Channels
CREATE TABLE secure_channels (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,               -- '#general', '#decisions', etc.
  channel_type TEXT NOT NULL,       -- 'group', 'direct', 'agent'
  encryption_key_id TEXT NOT NULL,  -- reference to channel key in vault
  created_by TEXT NOT NULL,
  created_at TEXT DEFAULT (datetime('now'))
);

-- Channel membership
CREATE TABLE channel_members (
  channel_id TEXT NOT NULL REFERENCES secure_channels(id),
  user_id TEXT NOT NULL,
  role TEXT DEFAULT 'member',       -- 'admin', 'member'
  joined_at TEXT DEFAULT (datetime('now')),
  PRIMARY KEY (channel_id, user_id)
);

-- Read state (for unread indicators)
CREATE TABLE channel_read_state (
  channel_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  last_read_message_id TEXT,
  updated_at TEXT DEFAULT (datetime('now')),
  PRIMARY KEY (channel_id, user_id)
);

-- Reactions
CREATE TABLE message_reactions (
  id TEXT PRIMARY KEY,
  message_id TEXT NOT NULL REFERENCES secure_messages(id),
  user_id TEXT NOT NULL,
  reaction TEXT NOT NULL,           -- emoji or ':approve:', ':reject:'
  receipt_id TEXT,                  -- approval reactions are receipted
  created_at TEXT DEFAULT (datetime('now'))
);
```

### 4.7 Why Two Channels Matters

This isn't paranoia — it's operational hygiene. Email is structurally incapable of confidentiality: headers are plaintext, content traverses infrastructure you don't control, and metadata (who emailed whom, when, how often) is visible to every relay in the chain. Even with TLS everywhere, the receiving mail server sees everything.

The secure channel gives the foundation a space where:
- Attorney-client privileged discussions stay privileged
- Financial planning conversations don't transit third-party servers
- Board deliberations are recorded with cryptographic integrity
- The agent can participate without external exposure
- Internal disagreements stay internal

When regulators, auditors, or opposing counsel ask for communications, the email archive contains the external-facing record. The secure channel contains the deliberation. Both are auditable via the receipt chain — but only to parties with the decryption keys.

---

## 5. Document Store

### 4.1 Foundation Documents (Pre-loaded)

| Document | Status | Source |
|----------|--------|--------|
| Articles of Incorporation | Final | Wyoming filing |
| Bylaws | Final | Board-approved |
| Conflict of Interest Policy | Final | Board-approved |
| Whitepaper v2 | Published | zeropoint.global |
| Architecture Specification | Published | zeropoint.global |
| Formal Primitives | Published | zeropoint.global |
| Falsification Guide | Published | zeropoint.global |
| Hedera Grant Application | Draft | Pending submission |

### 4.2 Document Schema (D1)

```sql
CREATE TABLE documents (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  category TEXT NOT NULL,        -- 'legal', 'technical', 'media', 'correspondence'
  content_type TEXT NOT NULL,    -- 'application/pdf', 'application/vnd.openxmlformats...'
  r2_key TEXT NOT NULL,          -- R2 object key for the file
  content_hash TEXT NOT NULL,    -- Blake3 hash
  version INTEGER DEFAULT 1,
  parent_version_id TEXT,        -- Previous version reference
  uploaded_by TEXT NOT NULL,     -- Staff member
  receipt_id TEXT,               -- ZeroPoint receipt reference
  tags TEXT,                     -- JSON array
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX idx_documents_category ON documents(category);
CREATE INDEX idx_documents_hash ON documents(content_hash);

-- Document access log (every view, download, share is receipted)
CREATE TABLE document_access (
  id TEXT PRIMARY KEY,
  document_id TEXT NOT NULL REFERENCES documents(id),
  accessor TEXT NOT NULL,        -- Staff member or external
  action TEXT NOT NULL,          -- 'view', 'download', 'share', 'edit'
  receipt_id TEXT,
  accessed_at TEXT DEFAULT (datetime('now'))
);
```

### 4.3 Media Asset Management

```sql
CREATE TABLE media_assets (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  asset_type TEXT NOT NULL,      -- 'image', 'video', 'audio', 'graphic'
  status TEXT DEFAULT 'raw',     -- 'raw', 'in_review', 'approved', 'published'
  content_type TEXT NOT NULL,
  r2_key TEXT NOT NULL,
  content_hash TEXT NOT NULL,
  thumbnail_r2_key TEXT,
  dimensions TEXT,               -- JSON: { width, height } for images/video
  duration_seconds REAL,         -- For audio/video
  uploaded_by TEXT NOT NULL,
  approved_by TEXT,
  approval_receipt_id TEXT,
  tags TEXT,                     -- JSON array
  created_at TEXT DEFAULT (datetime('now')),
  published_at TEXT
);

CREATE INDEX idx_media_status ON media_assets(status);
CREATE INDEX idx_media_type ON media_assets(asset_type);
```

---

## 6. File Transfer — Upload Portal + Secure Links

Email's biggest limitation is attachment size — 25MB on most relays, often less. The workspace solves this by separating the control plane (email) from the data plane (R2).

### 5.1 Inbound: Upload Portal

Every staff member gets a personal upload endpoint:

```
https://upload.zeropoint.global/ken
https://upload.zeropoint.global/lorrie
https://upload.zeropoint.global/katie
```

**Public dropzone (for external senders):**
- Drag-and-drop UI — no account required
- Files go straight to R2, hashed with Blake3
- Uploader gets a confirmation with content hash
- Staff member gets an inbox notification with the file linked
- Receipt emitted: `file:received` with sender metadata and hash

**One-time upload links (for bounce recovery):**
When an inbound email bounces due to attachment size, the bounce handler auto-replies:

```
Your file was too large for email delivery.
Drop it here instead: https://upload.zeropoint.global/katie/a8f3c1
This link expires in 72 hours and accepts one upload.
```

The link is:
- Time-limited (configurable, default 72h)
- Single-use (consumed after one upload)
- Authenticated by token (no account needed)
- Receipted (proves when the link was issued and when it was used)

**Internal uploads:**
Staff upload directly from the workspace UI — no size limit, resumable for large files (tus protocol), progress tracking, immediate hash + receipt on completion.

### 5.2 Outbound: Secure Download Links

Instead of attaching large files to outgoing email, the workspace generates secure download links:

```
https://files.zeropoint.global/d/7b2e9f4a
```

**Link properties:**
- **Time-limited:** Expires after configurable window (default 7 days)
- **Access-limited:** Optional download count cap (e.g., 3 downloads max)
- **Authenticated:** One-time token, no account required for recipient
- **Receipted:** Every download emits `file:accessed` with accessor IP, timestamp, user-agent
- **Revocable:** Ken can kill any link immediately via the workspace

**Compose integration:**
When composing an email with a large attachment, the UI automatically:
1. Uploads the file to R2
2. Replaces the attachment with a secure download link
3. Adds a footer: "This file is hosted securely by ZeroPoint Foundation"

The recipient experience is identical to Dropbox or Google Drive links — click to download — but the file lives on sovereign infrastructure.

### 5.3 Schema Additions

```sql
-- Upload links (one-time, time-limited)
CREATE TABLE upload_links (
  id TEXT PRIMARY KEY,           -- short token for URL
  recipient_mailbox TEXT NOT NULL,
  created_by TEXT,               -- 'system' for bounce recovery, staff name for manual
  original_sender TEXT,          -- who triggered the bounce
  expires_at TEXT NOT NULL,
  consumed_at TEXT,              -- NULL until used
  r2_key TEXT,                   -- populated after upload
  content_hash TEXT,
  receipt_id TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

-- Download links (secure file sharing)
CREATE TABLE download_links (
  id TEXT PRIMARY KEY,           -- short token for URL
  document_id TEXT,              -- references documents or media_assets
  r2_key TEXT NOT NULL,
  filename TEXT NOT NULL,
  created_by TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  max_downloads INTEGER,         -- NULL = unlimited
  download_count INTEGER DEFAULT 0,
  revoked INTEGER DEFAULT 0,
  receipt_id TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE download_access_log (
  id TEXT PRIMARY KEY,
  link_id TEXT NOT NULL REFERENCES download_links(id),
  accessor_ip TEXT,
  user_agent TEXT,
  receipt_id TEXT,
  accessed_at TEXT DEFAULT (datetime('now'))
);
```

### 5.4 Size Tiers

| Channel | Max Size | Use Case |
|---------|----------|----------|
| Email attachment (inbound) | ~25 MB | Small docs, images — processed normally |
| Email attachment (outbound) | ~10 MB | Small files attached directly |
| Upload portal | 10 GB | Raw video, large media, bulk docs |
| Secure download link | 10 GB | Sharing large files externally |
| R2 storage | Unlimited | Archive, media library, backups |

The Email Worker detects large inbound attachments and automatically strips + stores them in R2, replacing inline with a workspace link. The staff member sees the attachment in their inbox as if it arrived normally — the workspace abstracts the size limit away.

---

## 7. Video/Audio Conferencing

The workspace already pixel-streams a UI over WebRTC. Conferencing is the same primitive — WebRTC media streams between participants — rendered inside the same sovereign workspace.

### 6.1 Architecture

```
┌──────────────┐     WebRTC      ┌──────────────────────────┐
│  Ken's       │◄───audio/video──►│                          │
│  thin client │                  │    APOLLO Render Node     │
└──────────────┘                  │                          │
                                  │  ┌────────────────────┐  │
┌──────────────┐     WebRTC      │  │  Conference Room    │  │
│  Lorrie's    │◄───audio/video──►│  │                    │  │
│  thin client │                  │  │  ┌────┐ ┌────┐     │  │
└──────────────┘                  │  │  │Ken │ │Lor.│     │  │
                                  │  │  └────┘ └────┘     │  │
┌──────────────┐     WebRTC      │  │  ┌────┐            │  │
│  Katie's     │◄───audio/video──►│  │  │Kat.│ [Share]    │  │
│  thin client │                  │  │  └────┘            │  │
└──────────────┘                  │  └────────────────────┘  │
                                  └──────────────────────────┘
```

Key insight: **the render node is already a WebRTC endpoint for pixel streaming.** Adding voice/video conferencing means adding media tracks to the existing connection — not building a separate system.

Each participant's thin client already has:
- A WebRTC connection to APOLLO (for the pixel stream)
- A WebSocket for input events
- MediaStream access (camera/mic permissions in the browser)

Conferencing adds:
- Upstream audio/video tracks from each participant's camera and mic
- Mixing/compositing on APOLLO (or SFU-style selective forwarding)
- Conference UI rendered inside the workspace — same pixel stream, same security model

### 6.2 Conference Modes

**Quick call:** Click a staff member's name → instant audio call. No scheduling, no meeting link, no lobby. Like picking up a phone on someone's desk.

**Team standup:** All three participants, video on, rendered as a panel inside the workspace. Screen sharing is native — the workspace is already rendering the shared content on the same render node.

**Screen sharing (sovereign):** Unlike Zoom or Meet, screen sharing doesn't stream the presenter's actual screen. Instead, the render node shows the document/email/media that's being discussed — all participants see the same pixel-streamed view of the same server-side content. No screen capture, no local data exposure.

**External guest:** Time-limited join link for outside participants (counsel, grant reviewers). Guest connects via WebRTC to APOLLO, sees only the pixel stream of what's been shared — never gets direct access to the workspace. Receipt emitted for guest join/leave.

### 6.3 Conference UI

```
┌──────────────────────────────────────────────────────┐
│  ZP Foundation          🔍 Search          Ken ▾     │
├──────────┬───────────────────────────────────────────┤
│          │  ┌─────────────────────────────────────┐  │
│ ▸ Inbox  │  │          Team Standup               │  │
│   Sent   │  │  ┌──────┐  ┌──────┐  ┌──────┐     │  │
│   Archive│  │  │ Ken  │  │Lorrie│  │Katie │     │  │
│   Trash  │  │  │  🎥  │  │  🎥  │  │  🎥  │     │  │
│          │  │  └──────┘  └──────┘  └──────┘     │  │
│ ─────── │  │                                     │  │
│ Docs     │  │  🔇 Mute  📹 Camera  📎 Share Doc  │  │
│ Media    │  └─────────────────────────────────────┘  │
│ Tasks    │                                           │
│ ─────── │  Shared: Articles_v3.docx                 │
│ 📞 Call  │  ┌─────────────────────────────────────┐  │
│          │  │  [Document content rendered here]    │  │
│          │  │  [All participants see same view]    │  │
│          │  └─────────────────────────────────────┘  │
└──────────┴───────────────────────────────────────────┘
```

### 6.4 Why This Is Better Than Zoom/Meet

| Feature | Zoom/Meet | ZP Workspace |
|---------|-----------|--------------|
| Screen sharing | Streams presenter's actual screen | Renders shared content server-side — no screen capture |
| Meeting data | Stored on Zoom/Google servers | Stays on APOLLO, receipted |
| Recording | Cloud recording on vendor infrastructure | Local recording on sovereign node, if enabled |
| Guest access | Full app install or web client with broad permissions | Time-limited WebRTC link, pixel stream only |
| Chat during call | Stored on vendor servers, often mined | Same workspace chat, same governance |
| File sharing during call | Upload to vendor cloud | Already in the document store — just share the view |
| Calendar integration | Requires Google/Microsoft calendar | email-to-meeting: send to `meet@zeropoint.global` |
| Transcript | Vendor AI transcription (data leaves your control) | On-node transcription (Whisper), sovereign storage |

### 6.5 Meeting Automation

**email-to-meeting:** Send to `meet@zeropoint.global` with subject line:
```
[MEET] Weekly standup — Lorrie, Katie — Friday 10am
```
The workflow parses participants, time, creates the meeting, sends calendar-compatible .ics attachments to all participants. Receipt emitted.

**Auto-transcript:** If enabled, APOLLO runs Whisper locally on the audio stream. Transcript is hashed, stored, receipted. Never leaves sovereign infrastructure. Searchable in the workspace.

**Action items from meetings:** Post-meeting, the transcript can be processed to extract action items → automatically create tasks via the task workflow. Each task traces its provenance back to the meeting transcript, back to the meeting receipt.

### 6.6 Technical Stack

| Component | Technology | Why |
|-----------|------------|-----|
| Signaling | WebSocket on APOLLO | Already exists for input events |
| Media transport | WebRTC (DTLS-SRTP) | Already exists for pixel streaming |
| Audio mixing | mediasoup or Pion SFU | Selective forwarding, low latency |
| Video layout | Server-side compositing | Rendered into the workspace pixel stream |
| Transcription | Whisper (local) | Sovereign, no external API |
| Recording | FFmpeg on APOLLO | Direct capture of media streams |

### 6.7 Schema Additions

```sql
CREATE TABLE conferences (
  id TEXT PRIMARY KEY,
  title TEXT,
  started_by TEXT NOT NULL,
  status TEXT DEFAULT 'active',   -- 'active', 'ended'
  recording_r2_key TEXT,          -- NULL if not recorded
  transcript_r2_key TEXT,         -- NULL if not transcribed
  receipt_id TEXT,
  started_at TEXT DEFAULT (datetime('now')),
  ended_at TEXT
);

CREATE TABLE conference_participants (
  id TEXT PRIMARY KEY,
  conference_id TEXT NOT NULL REFERENCES conferences(id),
  participant TEXT NOT NULL,      -- staff name or 'guest:token'
  role TEXT DEFAULT 'participant', -- 'host', 'participant', 'guest'
  joined_at TEXT DEFAULT (datetime('now')),
  left_at TEXT
);

-- Guest access links (time-limited, single-conference)
CREATE TABLE conference_guest_links (
  id TEXT PRIMARY KEY,
  conference_id TEXT NOT NULL REFERENCES conferences(id),
  guest_name TEXT,
  expires_at TEXT NOT NULL,
  max_uses INTEGER DEFAULT 1,
  use_count INTEGER DEFAULT 0,
  created_by TEXT NOT NULL,
  receipt_id TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);
```

---

## 8. Email-to-Workflow Automation

### 5.1 Pattern: email-to-archive

**Trigger:** Forward any email to `archive@zeropoint.global`
**Action:**
1. Hash the message body and all attachments (Blake3)
2. Store in R2 with content-addressed key
3. Create document record with provenance metadata
4. Emit `document:archived` receipt with hash chain
5. Reply to sender confirming archive with receipt ID

**Use case:** Katie receives a letter from counsel. Forwards to archive@. It's hashed, stored, receipted. Provenance is permanent.

### 5.2 Pattern: email-to-task

**Trigger:** Send email to `task@zeropoint.global` with subject convention
**Subject format:** `[TASK] <description>` or `[TASK:assignee] <description>`
**Action:**
1. Parse subject for task description and optional assignee
2. Create task record in D1
3. Notify assignee (if specified)
4. Emit `task:created` receipt

**Use case:** Ken sends `[TASK:lorrie] Review updated bylaws by Friday` to task@. Lorrie gets notified, task is tracked, receipt proves when it was assigned.

### 5.3 Pattern: email-to-publish

**Trigger:** Send document to `publish@zeropoint.global`
**Action:**
1. Extract attachment
2. Hash and store as draft
3. Route to approval workflow:
   - If sender has `publish` capability → auto-approve, emit receipt
   - If not → queue for Ken's approval, notify him
4. On approval: move to published state, update site if applicable
5. Emit `document:published` receipt with approval chain

**Use case:** Lorrie drafts a blog post, sends it to publish@. Ken gets a notification. He replies "approved" and it goes live. Full audit trail.

### 5.4 Pattern: query-routing

**Trigger:** External email to `info@zeropoint.global`
**Action:**
1. Classify the inquiry (grant-related, technical, media, general)
2. Route to appropriate staff member based on classification
3. Create a tracked inquiry with response deadline
4. Emit `inquiry:received` receipt

---

## 9. Google Interop Layer

### 6.1 Import Adapters

| Google Format | Internal Format | Method |
|---------------|-----------------|--------|
| Google Docs | .docx + .md | Google Drive API export |
| Google Sheets | .xlsx + .csv | Google Drive API export |
| Google Slides | .pptx | Google Drive API export |
| Gmail messages | Standard MIME | IMAP or Gmail API |
| Drive files | Original format | Google Drive API download |

### 6.2 Export Adapters

| Internal Format | Google Format | Method |
|-----------------|---------------|--------|
| .docx | Google Docs | Google Drive API import |
| .md | Google Docs | Convert → upload |
| .xlsx | Google Sheets | Google Drive API import |
| .pdf | Google Drive file | Direct upload |

### 6.3 Sync Strategy

- **Pull on demand:** Staff clicks "Import from Google Drive" → picks files → they're hashed, stored, receipted
- **Push on demand:** Staff clicks "Share via Google" → document exported to Google format → shared link generated
- **No continuous sync:** Sovereign store is the source of truth. Google is the delivery mechanism.

---

## 10. Email Client UI

### 7.1 Design Principles

- **Less is more:** Inbox, compose, reply, search, folders, attachments. Nothing else.
- **Fast:** Sub-second render. No loading spinners for basic operations.
- **Keyboard-first:** Power users (Ken) navigate entirely by keyboard.
- **Mobile-capable:** Pixel stream adapts to viewport. Same app, any device.
- **No dark patterns:** No promotions tab, no social tab, no smart categories that hide mail.

### 7.2 Layout

```
┌──────────────────────────────────────────────────────┐
│  ZP Foundation          🔍 Search          Ken ▾     │
├──────────┬───────────────────────────────────────────┤
│          │                                           │
│ ▸ Inbox  │  From: counsel@lawfirm.com               │
│   Sent   │  Subject: Updated Articles — Final       │
│   Archive│  Date: May 2, 2026                        │
│   Trash  │                                           │
│          │  Hi Ken,                                  │
│ ─────── │                                           │
│ Docs     │  Please find attached the final           │
│ Media    │  Articles of Incorporation...             │
│ Tasks    │                                           │
│          │  📎 Articles_Final.docx (42 KB)           │
│          │                                           │
│          │  [Reply]  [Archive]  [→Publish]            │
│          │                                           │
└──────────┴───────────────────────────────────────────┘
```

### 7.3 Unique Features (vs Gmail)

- **[→Publish] button:** One click sends an attachment to the publish workflow
- **[→Archive] button:** One click hashes and stores with provenance
- **Receipt sidebar:** Shows the governance receipt for any message or action
- **Document pane:** Switch from email to document store without leaving the workspace
- **Media pane:** Browse, upload, and manage media assets inline
- **Task pane:** View and manage tasks created from email workflows

---

## 11. Pixel Streaming Deployment

### 8.1 Render Node (APOLLO)

The workspace UI runs inside a headless Chromium instance on APOLLO, managed by Puppeteer:

- **One session per user** — process-isolated page contexts
- **WebRTC stream** — DTLS-SRTP encrypted video to client
- **Input channel** — authenticated WebSocket for mouse/keyboard events
- **No data on client** — the browser tab is a `<canvas>` receiving pixels

### 8.2 Thin Client

```html
<!DOCTYPE html>
<html>
<head><title>ZeroPoint Workspace</title></head>
<body style="margin:0; overflow:hidden;">
  <canvas id="viewport" style="width:100vw; height:100vh;"></canvas>
  <script>
    // Connect to render node, receive video stream, send input events
    // That's it. The entire client.
  </script>
</body>
</html>
```

### 10.3 Device-Aware Adaptive Layout

The render node knows each client's viewport dimensions — the thin client reports screen size and pixel density on connect and on resize. The headless browser renders at the client's native resolution, so the UI adapts exactly like a responsive web app — but the adaptation happens server-side.

**Layout tiers:**

| Viewport | Layout | Behavior |
|----------|--------|----------|
| Desktop (≥1200px) | Three-column: sidebar + list + detail | Full workspace with all panes visible |
| Tablet (768–1199px) | Two-column: collapsible sidebar + main | Sidebar slides in/out, conference goes picture-in-picture |
| Phone (< 768px) | Single-column: stack navigation | Swipe between inbox → message → docs. Conference is full-screen with overlay controls |

**Why this is better than native responsive design:**

In a traditional web app, responsive layout is a CSS concern — media queries, flexbox, viewport units. The client does the work. With pixel streaming, the render node sets the headless browser's viewport to match the client device, and the React app's responsive breakpoints fire server-side. The result is:

- **Identical rendering across devices** — no CSS quirks, no browser-specific layout bugs
- **DPI-aware** — render at 2x for Retina, 1x for standard, matched to actual device pixel ratio
- **Bandwidth-adaptive** — smaller viewports produce smaller video frames, naturally reducing bandwidth for mobile connections
- **Orientation-aware** — phone rotates landscape, render node resizes the headless viewport, layout reflows server-side instantly

**Connection quality adaptation:**

The thin client also reports connection quality (RTT, packet loss, bandwidth estimate). The render node adjusts:

| Quality | Resolution | FPS | Strategy |
|---------|-----------|-----|----------|
| High | Native | 60 | Full fidelity, crisp text |
| Medium | 75% | 30 | Slight downscale, text still sharp |
| Low | 50% | 15 | Aggressive compression, grayscale backgrounds, color text |
| Offline | — | — | Last frame frozen, "Reconnecting..." overlay. Session state safe on server |

```javascript
// Thin client reports viewport on connect and resize
const reportViewport = () => ws.send(JSON.stringify({
  type: 'viewport',
  width: window.innerWidth,
  height: window.innerHeight,
  dpr: window.devicePixelRatio,
  orientation: screen.orientation?.type || 'landscape-primary'
}));

window.addEventListener('resize', reportViewport);
screen.orientation?.addEventListener('change', reportViewport);
```

### 10.4 Voice Interface — TTS/STT

Every interaction in the workspace has a voice-capable surface. The intent isn't a novelty feature — it's a first-class input/output mode that makes the workspace usable hands-free, eyes-free, or as a natural complement to visual interaction.

**Core primitives:**

| Primitive | Technology | Where It Runs | Why |
|-----------|------------|---------------|-----|
| Speech-to-Text | Whisper (local) | APOLLO render node | Sovereign — audio never leaves the server |
| Text-to-Speech | Piper TTS (local) | APOLLO render node | Sovereign — no external API, no cloud dependency |
| Voice Activity Detection | Silero VAD | APOLLO render node | Detects speech boundaries for natural turn-taking |
| Wake word (optional) | OpenWakeWord | APOLLO render node | Hands-free activation without always-on streaming |

All processing happens on the render node. The thin client captures microphone audio and streams it to APOLLO over the existing WebRTC connection (adding an audio track). Synthesized speech comes back as audio on the same connection. No audio data touches external servers.

**Voice surfaces:**

**Dictate anywhere.** Every text input — compose email, document annotation, task description, search — has a microphone button. Tap it, speak, Whisper transcribes, text appears. No mode switching, no separate dictation app. On mobile (single-column layout), the mic button is persistent and prominent — voice becomes the primary input method when a keyboard is inconvenient.

**Voice messages.** Instead of typing a reply, hold the mic button to record a voice message. The workspace stores the audio in R2 (hashed, receipted), transcribes it with Whisper, and sends the email with both: the transcript as body text and the audio as an attachment. The recipient gets a readable email; the archive has the original voice.

**Read it to me.** Any email, document, or notification can be read aloud via Piper TTS. On mobile, this turns the workspace into a podcast-like experience — listen to your inbox while walking. The TTS button appears contextually: next to email bodies, document previews, task descriptions.

**Agent conversation.** The workspace agent (for query routing, task management, document search) is voice-accessible. Speak a request ("File that attachment from counsel under legal docs"), Whisper transcribes, the agent processes, and Piper speaks the confirmation. This is the natural evolution of the email-to-workflow pattern — voice-to-workflow.

**Conference transcription.** During video/audio calls (§6), Whisper runs on the mixed audio stream in real time. Live captions render inside the conference panel. Post-meeting, the full transcript is available for search, action item extraction, and archive.

**Interaction model:**

```
┌─ Thin Client ─────────────────────────────────────────┐
│  Microphone → WebRTC audio track → ─┐                 │
│                                      │                 │
│  Speaker ← WebRTC audio track ← ────┤                 │
└──────────────────────────────────────┼─────────────────┘
                                       │
┌─ APOLLO Render Node ─────────────────┼─────────────────┐
│                                      ▼                 │
│  ┌──────────────┐    ┌──────────────────────────┐      │
│  │ Silero VAD   │───►│ Whisper (speech-to-text)  │      │
│  │ (detect      │    │ - dictation → text field  │      │
│  │  speech)     │    │ - voice msg → R2 + email  │      │
│  └──────────────┘    │ - agent cmd → workflow    │      │
│                      │ - conference → captions    │      │
│                      └──────────────────────────┘      │
│                                                        │
│  ┌──────────────────────────────┐                      │
│  │ Piper TTS (text-to-speech)   │                      │
│  │ - read email body            │                      │
│  │ - agent response             │                      │
│  │ - notification readout       │                      │
│  │ - document narration         │                      │
│  └──────────┬───────────────────┘                      │
│             │ audio frames                             │
│             ▼ → WebRTC audio track → thin client       │
└────────────────────────────────────────────────────────┘
```

### 10.5 Display Heuristics — Viewport Utilization Engine

The workspace doesn't just respond to viewport size — it actively optimizes how content fills the available space based on device characteristics, user behavior, and stated preferences.

**Heuristic inputs:**

| Signal | Source | What It Tells Us |
|--------|--------|-----------------|
| Viewport dimensions | Thin client | Physical screen real estate |
| Device pixel ratio | Thin client | Retina vs standard — affects text sizing and density |
| Orientation | Thin client | Portrait favors vertical scroll; landscape favors columns |
| Input method | Thin client | Touch (larger tap targets, swipe gestures) vs pointer (dense UI, hover states) |
| Connection quality | Thin client | Bandwidth budget for rendering complexity |
| Time of day | Server clock | Auto dark-mode, reduced brightness late at night |
| Active pane history | Session state | Which panes the user actually uses — hide what they don't |
| Explicit preferences | User profile | Stored in D1: font size, density, color scheme, default pane, voice mode |

**Heuristic outputs:**

**Information density.** Desktop with a mouse gets compact rows, hover tooltips, dense sidebars. Tablet with touch gets larger tap targets, more whitespace, swipe affordances. Phone gets card-based layouts with generous touch areas.

**Pane prioritization.** If Lorrie only ever uses Email and Docs, the sidebar collapses Media and Tasks into a "More" menu on her sessions. Ken uses everything — his sidebar stays full. This adapts over time from usage patterns, not configuration.

**Content reflow.** A long email on desktop renders inline with the message list visible. On phone, the message takes the full screen — the list is a back-swipe away. A document preview on desktop shows side-by-side with its metadata. On phone, metadata is a pull-down sheet.

**Conference layout adaptation.** Three-person call on desktop: video tiles + shared document side by side. Same call on tablet: video tiles stacked above document. On phone: active speaker full-screen with swipe to document, small floating self-view.

**Voice mode.** On phone with low bandwidth or during motion (accelerometer data from thin client), the workspace can suggest or auto-enter voice mode: TTS reads incoming notifications, STT handles replies, the visual display becomes a minimal status dashboard rather than a full email client.

**Preference storage:**

```sql
CREATE TABLE user_preferences (
  user_id TEXT PRIMARY KEY,
  theme TEXT DEFAULT 'system',       -- 'light', 'dark', 'system'
  font_scale REAL DEFAULT 1.0,       -- 0.8 (compact) to 1.5 (large)
  density TEXT DEFAULT 'adaptive',   -- 'compact', 'comfortable', 'adaptive'
  default_pane TEXT DEFAULT 'inbox',  -- initial view on login
  voice_input_enabled INTEGER DEFAULT 1,
  voice_output_enabled INTEGER DEFAULT 1,
  voice_speed REAL DEFAULT 1.0,      -- TTS playback speed
  auto_voice_mode INTEGER DEFAULT 0, -- auto-enter voice mode on mobile
  sidebar_collapsed TEXT,            -- JSON array of collapsed sections
  pane_order TEXT,                   -- JSON array of pane display order
  notification_sound INTEGER DEFAULT 1,
  notification_voice INTEGER DEFAULT 0, -- read notifications aloud
  updated_at TEXT DEFAULT (datetime('now'))
);

-- Usage patterns for adaptive heuristics
CREATE TABLE usage_patterns (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  pane TEXT NOT NULL,                -- 'inbox', 'docs', 'media', 'tasks', 'conference'
  device_class TEXT NOT NULL,        -- 'desktop', 'tablet', 'phone'
  interaction_count INTEGER DEFAULT 0,
  last_used TEXT,
  avg_session_seconds REAL,
  updated_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX idx_usage_user ON usage_patterns(user_id, device_class);
```

**The principle:** The workspace should feel like it was designed specifically for whatever device you're holding, not like a desktop app squeezed into a phone screen. Every pixel of viewport real estate earns its place — if a UI element isn't serving the user in their current context, it steps aside.

### 10.6 Why This Matters for the Foundation

A compromised staff laptop yields a video feed of the last frame they saw — not the foundation's legal documents, email history, grant applications, or financial records. The workspace is sovereign by architecture, not by policy.

---

## 12. Operator Model & Succession

### 12.1 Authority Tiers

| Role | Holder | Authority | Key Hierarchy |
|------|--------|-----------|---------------|
| **Genesis** | Ken | Root of trust. Issues all operator keys. Full authority over every workspace surface. | Self-signed Ed25519 — secret in OS credential store |
| **Successor** | Kalyn | Complete succession authority. Holds genesis recovery mnemonic. Can independently reconstitute genesis and assume full control. | Operator key (genesis-signed) + `workspace:admin` + mnemonic access |
| **Officer** | Lorrie, Katie | Operational authority. Own mailbox, shared resources, secure channel. Co-signed escalation path to admin if Ken and Kalyn are both unreachable. | Operator key (genesis-signed) + staff capabilities |

### 12.2 Succession Protocol

**Normal operations:** Ken holds genesis. Kalyn's key is live with `workspace:admin` but she may not be active daily. Lorrie and Katie operate with staff capabilities.

**Ken incapacitated, Kalyn available:** Kalyn uses the genesis recovery mnemonic to reconstitute the root key. She can issue new operator keys, rotate compromised keys, grant or revoke capabilities, and sustain all operations. A `succession:invoked` receipt is emitted to the chain — this is a designed, auditable transfer of authority, not a backdoor.

**Ken and Kalyn both unreachable:** Lorrie and Katie co-sign an escalation request. Both officer keys must sign. After a configurable delay (default: 72 hours with no Ken or Kalyn activity), their capabilities elevate to `workspace:admin`. A `succession:escalation` receipt is emitted. This is the backstop — it ensures operations can continue even in the worst case.

**Recovery mnemonic distribution:**
- Ken: full mnemonic (OS credential store + memory)
- Kalyn: full mnemonic (physical custody — sealed, secure location)
- Lorrie + Katie: no mnemonic access (escalation path only)

### 12.3 Operator Onboarding Flow

```
zp operator create --name lorrie --email lorrie@zeropoint.global --role staff
zp operator create --name katie  --email katie@zeropoint.global  --role staff
zp operator create --name kalyn  --email kalyn@zeropoint.global  --role successor
zp operator register --name lorrie --endpoint https://zeropoint.global
zp operator register --name katie  --endpoint https://zeropoint.global
zp operator register --name kalyn  --endpoint https://zeropoint.global
```

Each `create` generates an Ed25519 keypair, stores the private key in the vault, signs the operator certificate with genesis, and emits an `operator:created` receipt. Each `register` pushes the public key and capabilities to the workspace D1 database via the governed API.

### 12.4 Staff Capabilities

| Capability | Ken | Kalyn | Lorrie | Katie |
|-----------|-----|-------|--------|-------|
| Send email (own address) | ✓ | ✓ | ✓ | ✓ |
| View all mailboxes | ✓ | ✓ | ✗ | ✗ |
| Secure channel messaging | ✓ | ✓ | ✓ | ✓ |
| Create secure channels | ✓ | ✓ | ✗ | ✗ |
| Access #decisions channel | ✓ | ✓ | ✓ | ✓ |
| Agent direct channel | ✓ | ✓ | ✗ | ✗ |
| Upload documents | ✓ | ✓ | ✓ | ✓ |
| Upload via portal (unlimited size) | ✓ | ✓ | ✓ | ✓ |
| Create secure download links | ✓ | ✓ | ✓ | ✓ |
| Revoke download links | ✓ | ✓ | ✗ | ✗ |
| Approve publications | ✓ | ✓ | ✗ | ✗ |
| Manage media assets | ✓ | ✓ | ✓ | ✓ |
| Create tasks | ✓ | ✓ | ✓ | ✓ |
| Assign tasks | ✓ | ✓ | ✗ | ✗ |
| Start conference call | ✓ | ✓ | ✓ | ✓ |
| Invite external guests | ✓ | ✓ | ✗ | ✗ |
| Enable meeting recording | ✓ | ✓ | ✗ | ✗ |
| Voice dictation (STT) | ✓ | ✓ | ✓ | ✓ |
| Voice playback (TTS) | ✓ | ✓ | ✓ | ✓ |
| Agent voice interaction | ✓ | ✓ | ✓ | ✓ |
| Configure workflows | ✓ | ✓ | ✗ | ✗ |
| Configure display preferences | ✓ | ✓ | ✓ | ✓ |
| View audit trail | ✓ | ✓ | ✓ | ✓ |
| Export to Google | ✓ | ✓ | ✓ | ✓ |
| Issue/revoke operator keys | ✓ | ✓ | ✗ | ✗ |
| Invoke succession protocol | — | ✓ | co-sign | co-sign |

Capabilities are granted via ZeroPoint's operator system — scoped, receipted, and delegation-chain aware.

---

## 13. Implementation Phases

### Phase 1: Email (W2 + W3) — Get mail flowing
- Cloudflare Email Worker for inbound
- SMTP relay for outbound
- D1 schema deployed
- R2 bucket for attachments
- Basic routing: personal mailboxes + info@

### Phase 2: Email Client UI (W4) — Make it usable
- React email client rendering on APOLLO
- Inbox, compose, reply, search, folders
- Pixel streaming to client devices

### Phase 3: Secure Channel — Internal encrypted comms
- WebSocket relay on APOLLO (zero-hop, never leaves sovereign infra)
- E2E ChaCha20-Poly1305 encryption, Ed25519 signatures
- Channel provisioning: #general, #decisions, #private DMs, #with-agent
- D1 schema: secure_messages, secure_channels, channel_members, channel_read_state, message_reactions
- Minimal chat UI rendered server-side via pixel streaming

### Phase 4: Document & Media Store (W5) — Organize the files
- Pre-load foundation documents
- Upload, version, hash, receipt
- Media asset pipeline (raw → review → publish)

### Phase 5: Workflow Automation (W6) — Make email smart
- email-to-archive
- email-to-task
- email-to-publish
- Query routing for info@

### Phase 6: Conferencing — Sovereign video/audio
- WebRTC media tracks on existing connections
- SFU (mediasoup or Pion) for multi-party
- Quick call, team standup, guest access modes
- Screen sharing via server-side content rendering
- Whisper STT + Piper TTS on APOLLO for voice interface

### Phase 7: Google Interop (W7) — Bridge the gap
- Import from Google Drive
- Export to Google formats
- No continuous sync — sovereign store is canonical

### Phase 8: Hetzner Migration (W9) — Move to Ashburn
- Provision new CX22 in Ashburn, VA (us-east)
- Snapshot Helsinki node, restore to Ashburn
- Update Cloudflare DNS + tunnel endpoints
- Validate latency: Katie ~5ms, Lorrie ~30ms, Ken ~65ms

### Phase 9: Staff Onboarding (W8) — Go live
- Create accounts, grant capabilities
- Load documents, test workflows
- Verify deliverability end-to-end

---

## 14. Design Feedback Loop

Every friction point in this workspace becomes a ZeroPoint development signal:

| Workspace Problem | ZeroPoint Insight |
|-------------------|-------------------|
| "Email workflow was too slow" | Governance gate latency needs optimization |
| "I couldn't share a doc externally" | Interop adapter gap — new adapter needed |
| "Who approved this?" | Audit trail UX needs work |
| "Lorrie needs temporary publish rights" | Delegation depth and time-scoping matter |
| "The video stream lagged" | Pixel streaming needs adaptive bitrate |
| "Search couldn't find that email" | Full-text indexing strategy for D1/R2 |
| "Secure channel felt clunky" | E2E UX must be invisible — encryption can't mean friction |
| "Agent missed context from email" | Cross-channel context bridging needed |
| "Latency spike during standup" | Ashburn proximity validated; adaptive bitrate tuning |

This workspace isn't just infrastructure. It's the instrument panel for ZeroPoint's own development.
