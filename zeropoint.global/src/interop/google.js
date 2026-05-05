/**
 * Google interop layer — import/export adapter.
 *
 * Strategy: Pull on demand, push on demand. No continuous sync.
 * The sovereign store is the source of truth. Google is the delivery mechanism.
 *
 * Import: Google Drive → sovereign store (hashed, receipted)
 * Export: sovereign store → Google Drive (shared, tracked)
 *
 * Requires:
 *   - Google OAuth2 credentials (stored as secrets)
 *   - Google Drive API access
 *   - Per-operator OAuth tokens (stored in D1)
 */

import { storeDocument } from "../docs/store.js";
import { ulid } from "../email/ulid.js";

// ─── Google Drive API Client ──────────────────────────────

/**
 * Minimal Google Drive API client for Cloudflare Workers.
 * Uses OAuth2 bearer tokens — token refresh is handled separately.
 */
class DriveClient {
  constructor(accessToken) {
    this.accessToken = accessToken;
    this.baseUrl = "https://www.googleapis.com/drive/v3";
    this.uploadUrl = "https://www.googleapis.com/upload/drive/v3";
  }

  async request(path, opts = {}) {
    const url = `${this.baseUrl}${path}`;
    const response = await fetch(url, {
      ...opts,
      headers: {
        Authorization: `Bearer ${this.accessToken}`,
        ...opts.headers,
      },
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Drive API error ${response.status}: ${error}`);
    }

    return response.json();
  }

  /**
   * List files in Drive with optional query filter.
   */
  async listFiles(opts = {}) {
    const params = new URLSearchParams();
    if (opts.query) params.set("q", opts.query);
    if (opts.pageSize) params.set("pageSize", String(opts.pageSize));
    if (opts.pageToken) params.set("pageToken", opts.pageToken);
    params.set("fields", "nextPageToken,files(id,name,mimeType,size,modifiedTime,parents)");

    return this.request(`/files?${params}`);
  }

  /**
   * Get file metadata.
   */
  async getFile(fileId) {
    return this.request(`/files/${fileId}?fields=id,name,mimeType,size,modifiedTime,parents`);
  }

  /**
   * Download file content.
   */
  async downloadFile(fileId) {
    const url = `${this.baseUrl}/files/${fileId}?alt=media`;
    const response = await fetch(url, {
      headers: { Authorization: `Bearer ${this.accessToken}` },
    });

    if (!response.ok) {
      throw new Error(`Download failed: ${response.status}`);
    }

    return {
      data: await response.arrayBuffer(),
      contentType: response.headers.get("Content-Type") || "application/octet-stream",
    };
  }

  /**
   * Export a Google Workspace file (Docs, Sheets, Slides) to a specified format.
   */
  async exportFile(fileId, mimeType) {
    const url = `${this.baseUrl}/files/${fileId}/export?mimeType=${encodeURIComponent(mimeType)}`;
    const response = await fetch(url, {
      headers: { Authorization: `Bearer ${this.accessToken}` },
    });

    if (!response.ok) {
      throw new Error(`Export failed: ${response.status}`);
    }

    return {
      data: await response.arrayBuffer(),
      contentType: mimeType,
    };
  }

  /**
   * Upload a file to Drive.
   */
  async uploadFile(name, mimeType, data, folderId) {
    const metadata = { name, mimeType };
    if (folderId) metadata.parents = [folderId];

    // Simple upload for files under 5MB
    if (data.byteLength < 5 * 1024 * 1024) {
      const boundary = "zpboundary" + Date.now();
      const metadataStr = JSON.stringify(metadata);

      const body = new Blob([
        `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${metadataStr}\r\n`,
        `--${boundary}\r\nContent-Type: ${mimeType}\r\n\r\n`,
        data,
        `\r\n--${boundary}--`,
      ]);

      const response = await fetch(
        `${this.uploadUrl}/files?uploadType=multipart&fields=id,name,mimeType,size`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${this.accessToken}`,
            "Content-Type": `multipart/related; boundary=${boundary}`,
          },
          body,
        }
      );

      if (!response.ok) {
        throw new Error(`Upload failed: ${response.status}`);
      }

      return response.json();
    }

    // Resumable upload for larger files
    const initResponse = await fetch(
      `${this.uploadUrl}/files?uploadType=resumable`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${this.accessToken}`,
          "Content-Type": "application/json",
          "X-Upload-Content-Type": mimeType,
          "X-Upload-Content-Length": String(data.byteLength),
        },
        body: JSON.stringify(metadata),
      }
    );

    if (!initResponse.ok) {
      throw new Error(`Upload init failed: ${initResponse.status}`);
    }

    const uploadUri = initResponse.headers.get("Location");
    const uploadResponse = await fetch(uploadUri, {
      method: "PUT",
      headers: {
        "Content-Type": mimeType,
        "Content-Length": String(data.byteLength),
      },
      body: data,
    });

    if (!uploadResponse.ok) {
      throw new Error(`Upload failed: ${uploadResponse.status}`);
    }

    return uploadResponse.json();
  }
}

// ─── Import Adapters ──────────────────────────────────────

/** Google MIME type → export format mapping */
const EXPORT_FORMATS = {
  "application/vnd.google-apps.document": {
    mimeType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ext: "docx",
  },
  "application/vnd.google-apps.spreadsheet": {
    mimeType: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ext: "xlsx",
  },
  "application/vnd.google-apps.presentation": {
    mimeType: "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ext: "pptx",
  },
};

/**
 * Import a file from Google Drive into the sovereign store.
 *
 * @param {Object} env
 * @param {string} accessToken  - Google OAuth2 access token
 * @param {string} fileId       - Google Drive file ID
 * @param {string} operatorId   - Who is importing
 * @returns {Promise<{ok: boolean, documentId?: string, error?: string}>}
 */
export async function importFromDrive(env, accessToken, fileId, operatorId) {
  const drive = new DriveClient(accessToken);
  const meta = await drive.getFile(fileId);

  let downloaded;
  const exportFormat = EXPORT_FORMATS[meta.mimeType];

  if (exportFormat) {
    // Google Workspace file — export to Office format
    downloaded = await drive.exportFile(fileId, exportFormat.mimeType);
    meta.name = meta.name.replace(/\.[^.]+$/, "") + "." + exportFormat.ext;
  } else {
    // Regular file — download as-is
    downloaded = await drive.downloadFile(fileId);
  }

  const doc = await storeDocument(env, {
    title: meta.name,
    category: "internal",
    contentType: downloaded.contentType,
    data: downloaded.data,
    uploadedBy: operatorId,
    tags: ["imported", "google-drive"],
    description: `Imported from Google Drive (file ID: ${fileId})`,
  });

  return {
    ok: true,
    documentId: doc.id,
    contentHash: doc.contentHash,
    filename: meta.name,
    sizeBytes: downloaded.data.byteLength,
    source: { driveFileId: fileId, originalMimeType: meta.mimeType },
  };
}

/**
 * List files available for import from Google Drive.
 */
export async function listDriveFiles(accessToken, opts = {}) {
  const drive = new DriveClient(accessToken);
  const result = await drive.listFiles({
    query: opts.query || "trashed = false",
    pageSize: opts.limit || 50,
    pageToken: opts.pageToken,
  });

  return {
    files: result.files.map((f) => ({
      id: f.id,
      name: f.name,
      mimeType: f.mimeType,
      size: f.size ? parseInt(f.size, 10) : null,
      modifiedTime: f.modifiedTime,
      isGoogleWorkspace: !!EXPORT_FORMATS[f.mimeType],
      exportFormat: EXPORT_FORMATS[f.mimeType]?.ext || null,
    })),
    nextPageToken: result.nextPageToken,
  };
}

// ─── Export Adapters ──────────────────────────────────────

/**
 * Export a document from the sovereign store to Google Drive.
 *
 * @param {Object} env
 * @param {string} accessToken  - Google OAuth2 access token
 * @param {string} documentId   - Sovereign document ID
 * @param {string} [folderId]   - Target Google Drive folder
 * @returns {Promise<{ok: boolean, driveFileId?: string, error?: string}>}
 */
export async function exportToDrive(env, accessToken, documentId, folderId) {
  const { downloadDocument } = await import("../docs/store.js");
  const result = await downloadDocument(env, documentId);
  if (!result) return { ok: false, error: "document not found" };

  const drive = new DriveClient(accessToken);

  // Read the stream into an ArrayBuffer
  const chunks = [];
  const reader = result.body.getReader();
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
  }
  const data = concatArrayBuffers(chunks);

  const uploaded = await drive.uploadFile(
    result.doc.title,
    result.contentType,
    data,
    folderId
  );

  return {
    ok: true,
    driveFileId: uploaded.id,
    name: uploaded.name,
    mimeType: uploaded.mimeType,
    source: { documentId, contentHash: result.doc.content_hash },
  };
}

// ─── OAuth2 Token Management ──────────────────────────────

/**
 * Refresh an OAuth2 access token using a refresh token.
 */
export async function refreshAccessToken(env, operatorId) {
  const tokenRecord = await env.DB.prepare(
    `SELECT * FROM google_tokens WHERE operator_id = ?`
  )
    .bind(operatorId)
    .first();

  if (!tokenRecord) return null;

  const response = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      refresh_token: tokenRecord.refresh_token,
      grant_type: "refresh_token",
    }),
  });

  if (!response.ok) return null;

  const data = await response.json();

  // Update stored access token
  await env.DB.prepare(
    `UPDATE google_tokens SET access_token = ?, expires_at = ?, updated_at = ? WHERE operator_id = ?`
  )
    .bind(
      data.access_token,
      new Date(Date.now() + data.expires_in * 1000).toISOString(),
      new Date().toISOString(),
      operatorId
    )
    .run();

  return data.access_token;
}

// ─── Helpers ──────────────────────────────────────────────

function concatArrayBuffers(chunks) {
  const totalLength = chunks.reduce((sum, chunk) => sum + chunk.byteLength, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(new Uint8Array(chunk.buffer || chunk), offset);
    offset += chunk.byteLength;
  }
  return result.buffer;
}
