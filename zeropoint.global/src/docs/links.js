/**
 * File transfer links — upload portals and secure download links.
 *
 * Upload links: one-time, time-limited inbound file drops.
 * Download links: time-limited, access-capped outbound shares.
 * Every link creation, use, and revocation is receipted.
 */

import { ulid } from "../email/ulid.js";

// ─── Upload Links ─────────────────────────────────────────

/**
 * Create an upload link.
 *
 * @param {Object} env
 * @param {Object} opts
 * @param {string} opts.recipientMailbox  - Which mailbox receives the upload
 * @param {string} opts.createdBy         - 'system' for bounce recovery, operator ID otherwise
 * @param {string} [opts.originalSender]  - Email address that triggered a bounce
 * @param {number} [opts.expiresInHours]  - Hours until expiry (default 72)
 * @returns {Promise<{id: string, url: string, expiresAt: string}>}
 */
export async function createUploadLink(env, opts) {
  const id = generateShortToken();
  const expiresAt = new Date(
    Date.now() + (opts.expiresInHours || 72) * 60 * 60 * 1000
  ).toISOString();

  await env.DB.prepare(
    `INSERT INTO upload_links (id, recipient_mailbox, created_by, original_sender, expires_at)
     VALUES (?, ?, ?, ?, ?)`
  )
    .bind(id, opts.recipientMailbox, opts.createdBy, opts.originalSender || null, expiresAt)
    .run();

  return {
    id,
    url: `https://upload.zeropoint.global/${opts.recipientMailbox}/${id}`,
    expiresAt,
  };
}

/**
 * Consume an upload link — called when a file is uploaded through it.
 */
export async function consumeUploadLink(env, linkId, file) {
  const link = await env.DB.prepare(
    `SELECT * FROM upload_links WHERE id = ? AND consumed_at IS NULL`
  )
    .bind(linkId)
    .first();

  if (!link) return { ok: false, error: "link not found or already used" };

  if (new Date(link.expires_at) < new Date()) {
    return { ok: false, error: "link expired" };
  }

  const r2Key = `uploads/${link.recipient_mailbox}/${linkId}/${file.filename}`;

  // Hash contents
  const hashBuffer = await crypto.subtle.digest("SHA-256", file.data);
  const contentHash = Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  // Store in R2
  await env.STORAGE.put(r2Key, file.data, {
    httpMetadata: { contentType: file.contentType },
    customMetadata: { uploadLinkId: linkId, hash: contentHash },
  });

  // Mark consumed
  await env.DB.prepare(
    `UPDATE upload_links SET consumed_at = ?, r2_key = ?, content_hash = ?, filename = ?, size_bytes = ?
     WHERE id = ?`
  )
    .bind(new Date().toISOString(), r2Key, contentHash, file.filename, file.data.byteLength, linkId)
    .run();

  return { ok: true, r2Key, contentHash, recipientMailbox: link.recipient_mailbox };
}

/**
 * List upload links for a mailbox.
 */
export async function queryUploadLinks(env, mailbox, opts = {}) {
  const { includeConsumed = false, limit = 50 } = opts;

  let sql = `SELECT * FROM upload_links WHERE recipient_mailbox = ?`;
  const params = [mailbox];

  if (!includeConsumed) {
    sql += ` AND consumed_at IS NULL AND expires_at > ?`;
    params.push(new Date().toISOString());
  }

  sql += ` ORDER BY created_at DESC LIMIT ?`;
  params.push(limit);

  const { results } = await env.DB.prepare(sql).bind(...params).all();
  return results;
}

// ─── Download Links ───────────────────────────────────────

/**
 * Create a secure download link.
 *
 * @param {Object} env
 * @param {Object} opts
 * @param {string} opts.r2Key           - R2 key for the file
 * @param {string} opts.filename        - Display filename
 * @param {string} opts.contentType     - MIME type
 * @param {number} opts.sizeBytes       - File size
 * @param {string} opts.createdBy       - Operator ID
 * @param {string} [opts.documentId]    - Link to documents table
 * @param {string} [opts.mediaAssetId]  - Link to media_assets table
 * @param {number} [opts.expiresInDays] - Days until expiry (default 7)
 * @param {number} [opts.maxDownloads]  - Max download count (null = unlimited)
 * @returns {Promise<{id: string, url: string, expiresAt: string}>}
 */
export async function createDownloadLink(env, opts) {
  const id = generateShortToken();
  const expiresAt = new Date(
    Date.now() + (opts.expiresInDays || 7) * 24 * 60 * 60 * 1000
  ).toISOString();

  await env.DB.prepare(
    `INSERT INTO download_links (id, document_id, media_asset_id, r2_key, filename, content_type, size_bytes, created_by, expires_at, max_downloads)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(
      id,
      opts.documentId || null,
      opts.mediaAssetId || null,
      opts.r2Key,
      opts.filename,
      opts.contentType,
      opts.sizeBytes,
      opts.createdBy,
      expiresAt,
      opts.maxDownloads || null
    )
    .run();

  return {
    id,
    url: `https://files.zeropoint.global/d/${id}`,
    expiresAt,
  };
}

/**
 * Serve a download link — validates expiry, download cap, revocation.
 *
 * @returns {{ ok: boolean, link?: Object, body?: ReadableStream, error?: string }}
 */
export async function serveDownloadLink(env, linkId, accessInfo) {
  const link = await env.DB.prepare(
    `SELECT * FROM download_links WHERE id = ?`
  )
    .bind(linkId)
    .first();

  if (!link) return { ok: false, error: "not found", status: 404 };

  if (link.revoked_at) {
    return { ok: false, error: "link has been revoked", status: 410 };
  }

  if (new Date(link.expires_at) < new Date()) {
    return { ok: false, error: "link expired", status: 410 };
  }

  if (link.max_downloads && link.download_count >= link.max_downloads) {
    return { ok: false, error: "download limit reached", status: 410 };
  }

  // Fetch from R2
  const object = await env.STORAGE.get(link.r2_key);
  if (!object) return { ok: false, error: "file not found in storage", status: 404 };

  // Increment counter
  await env.DB.prepare(
    `UPDATE download_links SET download_count = download_count + 1 WHERE id = ?`
  )
    .bind(linkId)
    .run();

  // Log access
  const accessId = ulid();
  await env.DB.prepare(
    `INSERT INTO download_access (id, download_link_id, ip_address, user_agent)
     VALUES (?, ?, ?, ?)`
  )
    .bind(accessId, linkId, accessInfo.ip || null, accessInfo.userAgent || null)
    .run();

  return {
    ok: true,
    link,
    body: object.body,
    contentType: link.content_type,
    filename: link.filename,
  };
}

/**
 * Revoke a download link.
 */
export async function revokeDownloadLink(env, linkId, revokedBy) {
  await env.DB.prepare(
    `UPDATE download_links SET revoked_at = ?, revoked_by = ? WHERE id = ?`
  )
    .bind(new Date().toISOString(), revokedBy, linkId)
    .run();
}

/**
 * List download links created by an operator.
 */
export async function queryDownloadLinks(env, createdBy, opts = {}) {
  const { includeExpired = false, limit = 50 } = opts;

  let sql = `SELECT * FROM download_links WHERE created_by = ?`;
  const params = [createdBy];

  if (!includeExpired) {
    sql += ` AND revoked_at IS NULL AND expires_at > ?`;
    params.push(new Date().toISOString());
  }

  sql += ` ORDER BY created_at DESC LIMIT ?`;
  params.push(limit);

  const { results } = await env.DB.prepare(sql).bind(...params).all();
  return results;
}

// ─── Helpers ──────────────────────────────────────────────

/**
 * Generate a short URL-safe token (8 chars).
 */
function generateShortToken() {
  const chars = "23456789abcdefghjkmnpqrstvwxyz"; // no ambiguous chars
  const bytes = crypto.getRandomValues(new Uint8Array(8));
  return Array.from(bytes)
    .map((b) => chars[b % chars.length])
    .join("");
}
