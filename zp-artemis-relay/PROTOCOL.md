# ARTEMIS Relay Protocol

Two agents, one shared filesystem. No human telephone required.

## Paths

From APOLLO (this repo):
  `zp-artemis-relay/`

From ARTEMIS (SMB mount):
  `/Volumes/APOLLO/Projects/zeropoint/zp-artemis-relay/`
  (adjust if the Projects path differs on the APOLLO share)

## Message Queue

All async communication goes through `messages/`. Each message is a
single file named `{timestamp}-{from}-{seq}.md` — e.g.:

  `20260419T0830Z-apollo-001.md`
  `20260419T0835Z-artemis-001.md`

### Message format

```
from: apollo | artemis
to: artemis | apollo
type: request | response | status | ack
ref: (optional — filename of message this responds to)
---

Body in plain text or markdown. Be direct.
```

### Flow

1. Apollo writes a message to `messages/`.
2. ARTEMIS checks `messages/` for unacked messages from apollo.
3. ARTEMIS does the work, writes a response to `messages/`.
4. Apollo checks `messages/` for unacked messages from artemis.

No polling loops. Each side checks when prompted or when starting work.

## Commands (legacy, still valid)

`commands/*.sh` — executable scripts ARTEMIS can run directly.
`results/*.txt` — ARTEMIS writes structured output here.

These still work. The message queue adds conversational back-and-forth
on top of the batch command model.

## Bundles

`zp-artemis.bundle` — full repo bundle, updated by post-commit hook.
`manifest.json` — HEAD state.
`dispatch.log` — append-only commit log.

## Rules

- No secrets in messages. Ever.
- Keep messages short. If you need to send code, reference a file path or commit.
- Both sides: read all unread messages before writing new ones.
- If something is broken, say so directly. Don't wait to be asked.
