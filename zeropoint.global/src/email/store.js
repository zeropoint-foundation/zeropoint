/**
 * Email storage — persists messages to D1 and attachments to R2.
 */

import { ulid } from "./ulid.js";

/**
 * Store a parsed email in D1 (metadata) and R2 (attachments).
 *
 * @param {Object} env     - Worker environment bindings (DB, STORAGE)
 * @param {import('./parser.js').ParsedEmail} email - Parsed email
 * @param {import('./router.js').Route} route - Resolved route
 * @returns {Promise<{messageId: string, attachmentIds: string[]}>}
 */
export async function storeMessage(env, email, route) {
  const messageId = ulid();
  const now = new Date().toISOString();

  // Derive thread_id from In-Reply-To or generate new
  const threadId = email.inReplyTo
    ? await findThreadId(env, email.inReplyTo)
    : messageId;

  // Store message metadata in D1
  await env.DB.prepare(
    `INSERT INTO messages (
      id, mailbox, folder, from_address, from_name,
      to_addresses, cc_addresses, subject,
      body_text, body_html, has_attachments,
      thread_id, in_reply_to, message_id_header,
      raw_size_bytes, received_at, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(
      messageId,
      route.mailbox,
      route.folder,
      email.from,
      email.fromName || null,
      JSON.stringify(email.toAll),
      email.cc.length ? JSON.stringify(email.cc) : null,
      email.subject,
      email.textBody || null,
      email.htmlBody || null,
      email.attachments.length > 0 ? 1 : 0,
      threadId,
      email.inReplyTo || null,
      email.messageId || null,
      email.rawSize,
      email.date,
      now
    )
    .run();

  // Store attachments in R2
  const attachmentIds = [];
  for (const att of email.attachments) {
    const attId = ulid();
    const r2Key = `mail/${route.mailbox}/${messageId}/${att.filename}`;

    // Upload to R2
    await env.STORAGE.put(r2Key, att.content, {
      httpMetadata: { contentType: att.contentType },
      customMetadata: {
        messageId,
        filename: att.filename,
        originalSize: String(att.size),
      },
    });

    // Record metadata in D1
    await env.DB.prepare(
      `INSERT INTO attachments (
        id, message_id, filename, content_type,
        size_bytes, r2_key, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(attId, messageId, att.filename, att.contentType, att.size, r2Key, now)
      .run();

    attachmentIds.push(attId);
  }

  // Upsert contact
  await upsertContact(env, email.from, email.fromName);

  return { messageId, attachmentIds, threadId };
}

/**
 * Look up a thread ID from a Message-ID reference.
 * Falls back to the Message-ID itself if no prior message found.
 */
async function findThreadId(env, inReplyTo) {
  const result = await env.DB.prepare(
    `SELECT thread_id FROM messages WHERE message_id_header = ? LIMIT 1`
  )
    .bind(inReplyTo)
    .first();

  return result?.thread_id || inReplyTo;
}

/**
 * Create or update a contact from email activity.
 */
async function upsertContact(env, email, name) {
  const now = new Date().toISOString();
  const existing = await env.DB.prepare(
    `SELECT id, interaction_count FROM contacts WHERE email = ?`
  )
    .bind(email)
    .first();

  if (existing) {
    await env.DB.prepare(
      `UPDATE contacts SET
        name = COALESCE(?, name),
        last_seen = ?,
        interaction_count = ?
      WHERE id = ?`
    )
      .bind(name || null, now, existing.interaction_count + 1, existing.id)
      .run();
  } else {
    await env.DB.prepare(
      `INSERT INTO contacts (id, email, name, last_seen, interaction_count, created_at)
      VALUES (?, ?, ?, ?, 1, ?)`
    )
      .bind(ulid(), email, name || null, now, now)
      .run();
  }
}

/**
 * Query messages for a mailbox.
 *
 * @param {Object} env
 * @param {string} mailbox
 * @param {Object} opts
 * @param {string} [opts.folder='inbox']
 * @param {number} [opts.limit=50]
 * @param {number} [opts.offset=0]
 */
export async function queryMessages(env, mailbox, opts = {}) {
  const folder = opts.folder || "inbox";
  const limit = opts.limit || 50;
  const offset = opts.offset || 0;

  const { results } = await env.DB.prepare(
    `SELECT * FROM messages
     WHERE mailbox = ? AND folder = ?
     ORDER BY received_at DESC
     LIMIT ? OFFSET ?`
  )
    .bind(mailbox, folder, limit, offset)
    .all();

  return results;
}

/**
 * Get a single message by ID, including its attachments.
 */
export async function getMessage(env, messageId) {
  const message = await env.DB.prepare(
    `SELECT * FROM messages WHERE id = ?`
  )
    .bind(messageId)
    .first();

  if (!message) return null;

  const { results: attachments } = await env.DB.prepare(
    `SELECT id, filename, content_type, size_bytes, r2_key
     FROM attachments WHERE message_id = ?`
  )
    .bind(messageId)
    .all();

  return { ...message, attachments };
}

/**
 * Mark a message as read.
 */
export async function markRead(env, messageId) {
  await env.DB.prepare(
    `UPDATE messages SET is_read = 1 WHERE id = ?`
  )
    .bind(messageId)
    .run();
}

/**
 * Move a message to a different folder.
 */
export async function moveMessage(env, messageId, folder) {
  await env.DB.prepare(
    `UPDATE messages SET folder = ? WHERE id = ?`
  )
    .bind(folder, messageId)
    .run();
}

/**
 * Star/unstar a message.
 */
export async function toggleStar(env, messageId) {
  await env.DB.prepare(
    `UPDATE messages SET is_starred = 1 - is_starred WHERE id = ?`
  )
    .bind(messageId)
    .run();
}
