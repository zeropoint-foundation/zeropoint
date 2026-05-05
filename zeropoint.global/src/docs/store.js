/**
 * Document store — CRUD for documents and versioning.
 *
 * Documents live in R2, metadata in D1.
 * Every upload hashes the content for integrity verification.
 * Version chains link parent→child for full history.
 */

import { ulid } from "../email/ulid.js";

/**
 * Store a new document (or a new version of an existing one).
 *
 * @param {Object} env        - Cloudflare bindings (DB, STORAGE)
 * @param {Object} opts
 * @param {string} opts.title
 * @param {string} opts.category      - 'legal', 'technical', 'media', 'correspondence', 'internal'
 * @param {string} opts.contentType   - MIME type
 * @param {ArrayBuffer} opts.data     - File contents
 * @param {string} opts.uploadedBy    - Operator ID
 * @param {string[]} [opts.tags]
 * @param {string} [opts.description]
 * @param {string} [opts.parentVersionId] - ID of previous version (for versioning)
 * @returns {Promise<{id: string, r2Key: string, contentHash: string, version: number}>}
 */
export async function storeDocument(env, opts) {
  const id = ulid();
  const r2Key = `docs/${opts.category}/${id}/${opts.title.replace(/[^a-zA-Z0-9._-]/g, "_")}`;

  // Hash contents
  const hashBuffer = await crypto.subtle.digest("SHA-256", opts.data);
  const contentHash = Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  // Store blob in R2
  await env.STORAGE.put(r2Key, opts.data, {
    httpMetadata: { contentType: opts.contentType },
    customMetadata: { documentId: id, hash: contentHash },
  });

  // Determine version number
  let version = 1;
  if (opts.parentVersionId) {
    const parent = await env.DB.prepare(
      `SELECT version FROM documents WHERE id = ?`
    )
      .bind(opts.parentVersionId)
      .first();
    if (parent) version = parent.version + 1;
  }

  // Store metadata in D1
  await env.DB.prepare(
    `INSERT INTO documents (id, title, category, content_type, r2_key, content_hash, size_bytes, version, parent_version_id, uploaded_by, tags, description)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(
      id,
      opts.title,
      opts.category,
      opts.contentType,
      r2Key,
      contentHash,
      opts.data.byteLength,
      version,
      opts.parentVersionId || null,
      opts.uploadedBy,
      JSON.stringify(opts.tags || []),
      opts.description || null
    )
    .run();

  return { id, r2Key, contentHash, version };
}

/**
 * Query documents with filtering.
 */
export async function queryDocuments(env, opts = {}) {
  const { category, uploadedBy, tag, limit = 50, offset = 0 } = opts;

  let sql = `SELECT id, title, category, content_type, content_hash, size_bytes, version, uploaded_by, tags, description, created_at, updated_at FROM documents WHERE 1=1`;
  const params = [];

  if (category) {
    sql += ` AND category = ?`;
    params.push(category);
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

  const stmt = env.DB.prepare(sql);
  const { results } = await stmt.bind(...params).all();

  return results.map((r) => ({
    ...r,
    tags: JSON.parse(r.tags || "[]"),
  }));
}

/**
 * Get a single document by ID.
 */
export async function getDocument(env, id) {
  const doc = await env.DB.prepare(
    `SELECT * FROM documents WHERE id = ?`
  )
    .bind(id)
    .first();

  if (!doc) return null;

  return {
    ...doc,
    tags: JSON.parse(doc.tags || "[]"),
  };
}

/**
 * Get the version history of a document (follows parent chain).
 */
export async function getDocumentVersions(env, id) {
  // Walk back through parent chain
  const versions = [];
  let currentId = id;

  // First get the doc and walk up to the root
  const doc = await getDocument(env, currentId);
  if (!doc) return [];

  // Get all versions that share the same root
  // Find root by walking up
  let rootId = id;
  let current = doc;
  while (current.parent_version_id) {
    rootId = current.parent_version_id;
    current = await getDocument(env, rootId);
    if (!current) break;
  }

  // Now get all documents that trace back to this root
  const { results } = await env.DB.prepare(
    `SELECT id, title, version, content_hash, size_bytes, uploaded_by, created_at
     FROM documents
     WHERE id = ? OR parent_version_id = ?
     ORDER BY version DESC`
  )
    .bind(rootId, rootId)
    .all();

  // For deeper chains, also get docs whose parent is in results
  // (Simple approach — works for typical 2-3 level version chains)
  if (results.length > 0) {
    const ids = results.map((r) => r.id);
    const { results: children } = await env.DB.prepare(
      `SELECT id, title, version, content_hash, size_bytes, uploaded_by, created_at
       FROM documents
       WHERE parent_version_id IN (${ids.map(() => "?").join(",")})
       ORDER BY version DESC`
    )
      .bind(...ids)
      .all();

    const allVersions = [...results, ...children];
    // Deduplicate
    const seen = new Set();
    return allVersions.filter((v) => {
      if (seen.has(v.id)) return false;
      seen.add(v.id);
      return true;
    });
  }

  return results;
}

/**
 * Download document blob from R2.
 */
export async function downloadDocument(env, id) {
  const doc = await getDocument(env, id);
  if (!doc) return null;

  const object = await env.STORAGE.get(doc.r2_key);
  if (!object) return null;

  return {
    doc,
    body: object.body,
    contentType: doc.content_type,
  };
}

/**
 * Update document metadata (title, tags, description, category).
 */
export async function updateDocument(env, id, updates) {
  const fields = [];
  const params = [];

  if (updates.title !== undefined) {
    fields.push("title = ?");
    params.push(updates.title);
  }
  if (updates.category !== undefined) {
    fields.push("category = ?");
    params.push(updates.category);
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

  fields.push("updated_at = ?");
  params.push(new Date().toISOString());
  params.push(id);

  await env.DB.prepare(
    `UPDATE documents SET ${fields.join(", ")} WHERE id = ?`
  )
    .bind(...params)
    .run();
}

/**
 * Log a document access event.
 */
export async function logDocumentAccess(env, opts) {
  const id = ulid();
  await env.DB.prepare(
    `INSERT INTO document_access (id, document_id, accessor, action, receipt_id, ip_address)
     VALUES (?, ?, ?, ?, ?, ?)`
  )
    .bind(id, opts.documentId, opts.accessor, opts.action, opts.receiptId || null, opts.ip || null)
    .run();
  return id;
}

/**
 * Delete a document (removes from D1 and R2).
 */
export async function deleteDocument(env, id) {
  const doc = await getDocument(env, id);
  if (!doc) return false;

  await env.STORAGE.delete(doc.r2_key);
  await env.DB.prepare(`DELETE FROM documents WHERE id = ?`).bind(id).run();
  return true;
}
