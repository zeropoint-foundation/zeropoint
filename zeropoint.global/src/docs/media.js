/**
 * Media asset management — raw → review → approved → published pipeline.
 *
 * Media assets are stored in R2 with metadata in D1.
 * The status lifecycle is enforced: raw → in_review → approved → published.
 * Each status transition is receipted.
 */

import { ulid } from "../email/ulid.js";

/**
 * Upload a new media asset.
 *
 * @param {Object} env
 * @param {Object} opts
 * @param {string} opts.title
 * @param {string} opts.assetType     - 'image', 'video', 'audio', 'graphic'
 * @param {string} opts.contentType   - MIME type
 * @param {ArrayBuffer} opts.data     - File contents
 * @param {string} opts.uploadedBy    - Operator ID
 * @param {string[]} [opts.tags]
 * @param {string} [opts.description]
 * @param {Object} [opts.dimensions]  - { width, height } for images/video
 * @param {number} [opts.duration]    - Duration in seconds for audio/video
 * @returns {Promise<{id: string, r2Key: string, contentHash: string}>}
 */
export async function uploadAsset(env, opts) {
  const id = ulid();
  const ext = mimeToExt(opts.contentType);
  const safeName = opts.title.replace(/[^a-zA-Z0-9._-]/g, "_");
  const r2Key = `media/${opts.assetType}/${id}/${safeName}${ext ? "." + ext : ""}`;

  // Hash contents
  const hashBuffer = await crypto.subtle.digest("SHA-256", opts.data);
  const contentHash = Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  // Store blob
  await env.STORAGE.put(r2Key, opts.data, {
    httpMetadata: { contentType: opts.contentType },
    customMetadata: { assetId: id, hash: contentHash },
  });

  // Store metadata
  await env.DB.prepare(
    `INSERT INTO media_assets (id, title, asset_type, status, content_type, r2_key, content_hash, size_bytes, dimensions, duration_seconds, uploaded_by, tags, description)
     VALUES (?, ?, ?, 'raw', ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(
      id,
      opts.title,
      opts.assetType,
      opts.contentType,
      r2Key,
      contentHash,
      opts.data.byteLength,
      opts.dimensions ? JSON.stringify(opts.dimensions) : null,
      opts.duration || null,
      opts.uploadedBy,
      JSON.stringify(opts.tags || []),
      opts.description || null
    )
    .run();

  return { id, r2Key, contentHash };
}

/**
 * Query media assets with filtering.
 */
export async function queryAssets(env, opts = {}) {
  const { assetType, status, uploadedBy, tag, limit = 50, offset = 0 } = opts;

  let sql = `SELECT id, title, asset_type, status, content_type, content_hash, size_bytes, thumbnail_r2_key, dimensions, duration_seconds, uploaded_by, approved_by, tags, description, created_at, published_at FROM media_assets WHERE 1=1`;
  const params = [];

  if (assetType) {
    sql += ` AND asset_type = ?`;
    params.push(assetType);
  }
  if (status) {
    sql += ` AND status = ?`;
    params.push(status);
  }
  if (uploadedBy) {
    sql += ` AND uploaded_by = ?`;
    params.push(uploadedBy);
  }
  if (tag) {
    sql += ` AND tags LIKE ?`;
    params.push(`%"${tag}"%`);
  }

  sql += ` ORDER BY created_at DESC LIMIT ? OFFSET ?`;
  params.push(limit, offset);

  const { results } = await env.DB.prepare(sql).bind(...params).all();

  return results.map((r) => ({
    ...r,
    tags: JSON.parse(r.tags || "[]"),
    dimensions: r.dimensions ? JSON.parse(r.dimensions) : null,
  }));
}

/**
 * Get a single media asset by ID.
 */
export async function getAsset(env, id) {
  const asset = await env.DB.prepare(
    `SELECT * FROM media_assets WHERE id = ?`
  )
    .bind(id)
    .first();

  if (!asset) return null;

  return {
    ...asset,
    tags: JSON.parse(asset.tags || "[]"),
    dimensions: asset.dimensions ? JSON.parse(asset.dimensions) : null,
  };
}

/**
 * Transition asset status through the pipeline.
 *
 * Valid transitions:
 *   raw → in_review
 *   in_review → approved | raw (reject)
 *   approved → published | archived
 *   published → archived
 *   archived → raw (re-activate)
 *
 * @param {Object} env
 * @param {string} id          - Asset ID
 * @param {string} newStatus   - Target status
 * @param {string} operatorId  - Who is making the transition
 * @returns {Promise<boolean>} - Whether the transition was valid
 */
export async function transitionAsset(env, id, newStatus, operatorId) {
  const asset = await getAsset(env, id);
  if (!asset) return false;

  const valid = VALID_TRANSITIONS[asset.status];
  if (!valid || !valid.includes(newStatus)) return false;

  const updates = { status: newStatus };

  if (newStatus === "approved") {
    updates.approved_by = operatorId;
  }
  if (newStatus === "published") {
    updates.published_at = new Date().toISOString();
  }

  const fields = Object.entries(updates)
    .map(([k]) => `${k} = ?`)
    .join(", ");
  const values = Object.values(updates);

  await env.DB.prepare(
    `UPDATE media_assets SET ${fields} WHERE id = ?`
  )
    .bind(...values, id)
    .run();

  return true;
}

const VALID_TRANSITIONS = {
  raw: ["in_review"],
  in_review: ["approved", "raw"],
  approved: ["published", "archived"],
  published: ["archived"],
  archived: ["raw"],
};

/**
 * Update asset metadata.
 */
export async function updateAsset(env, id, updates) {
  const fields = [];
  const params = [];

  if (updates.title !== undefined) {
    fields.push("title = ?");
    params.push(updates.title);
  }
  if (updates.tags !== undefined) {
    fields.push("tags = ?");
    params.push(JSON.stringify(updates.tags));
  }
  if (updates.description !== undefined) {
    fields.push("description = ?");
    params.push(updates.description);
  }

  if (fields.length === 0) return;
  params.push(id);

  await env.DB.prepare(
    `UPDATE media_assets SET ${fields.join(", ")} WHERE id = ?`
  )
    .bind(...params)
    .run();
}

/**
 * Delete a media asset (R2 + D1).
 */
export async function deleteAsset(env, id) {
  const asset = await getAsset(env, id);
  if (!asset) return false;

  await env.STORAGE.delete(asset.r2_key);
  if (asset.thumbnail_r2_key) {
    await env.STORAGE.delete(asset.thumbnail_r2_key);
  }
  await env.DB.prepare(`DELETE FROM media_assets WHERE id = ?`).bind(id).run();
  return true;
}

/**
 * Set thumbnail for an asset.
 */
export async function setThumbnail(env, id, thumbnailData, contentType) {
  const asset = await getAsset(env, id);
  if (!asset) return false;

  const thumbKey = `media/thumbs/${id}.${mimeToExt(contentType) || "jpg"}`;

  await env.STORAGE.put(thumbKey, thumbnailData, {
    httpMetadata: { contentType },
  });

  await env.DB.prepare(
    `UPDATE media_assets SET thumbnail_r2_key = ? WHERE id = ?`
  )
    .bind(thumbKey, id)
    .run();

  return thumbKey;
}

// ── Helpers ───────────────────────────────────────────────

function mimeToExt(mime) {
  const map = {
    "image/jpeg": "jpg",
    "image/png": "png",
    "image/gif": "gif",
    "image/webp": "webp",
    "image/svg+xml": "svg",
    "video/mp4": "mp4",
    "video/webm": "webm",
    "audio/mpeg": "mp3",
    "audio/wav": "wav",
    "audio/ogg": "ogg",
    "application/pdf": "pdf",
  };
  return map[mime] || null;
}
