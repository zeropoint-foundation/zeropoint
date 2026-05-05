/**
 * email-to-publish workflow handler.
 *
 * Trigger: Send document to publish@zeropoint.global
 * Action:
 *   1. Extract attachment
 *   2. Hash and store as draft document
 *   3. Create publish queue entry:
 *      - If sender has publish capability → auto-approve
 *      - If not → queue for admin approval
 *   4. Emit document:submitted or document:published receipt
 */

import { storeDocument } from "../docs/store.js";
import { uploadAsset, transitionAsset } from "../docs/media.js";
import { ulid } from "../email/ulid.js";

/**
 * @param {Object} env
 * @param {Object} parsed    - Parsed email
 * @param {string} messageId - Stored message ID
 * @returns {Promise<{type: string, id: string}>}
 */
export async function handlePublish(env, parsed, messageId) {
  const submittedBy = extractOperatorFromEmail(parsed.from) || "unknown";
  const results = [];

  for (const att of parsed.attachments) {
    if (!att.content) continue;

    const isMedia = isMediaType(att.mimeType);

    let docOrAssetId;

    if (isMedia) {
      // Store as media asset in "in_review" state
      const asset = await uploadAsset(env, {
        title: att.filename || `publish-${ulid()}`,
        assetType: inferAssetType(att.mimeType),
        contentType: att.mimeType || "application/octet-stream",
        data: att.content,
        uploadedBy: submittedBy,
        tags: ["publish-queue"],
        description: `Submitted via publish@ by ${parsed.from}`,
      });
      // Move directly to in_review
      await transitionAsset(env, asset.id, "in_review", submittedBy);
      docOrAssetId = asset.id;
    } else {
      // Store as document
      const doc = await storeDocument(env, {
        title: att.filename || `publish-${ulid()}`,
        category: "media",
        contentType: att.mimeType || "application/octet-stream",
        data: att.content,
        uploadedBy: submittedBy,
        tags: ["publish-queue"],
        description: `Submitted via publish@ by ${parsed.from}`,
      });
      docOrAssetId = doc.id;
    }

    // Create publish queue entry
    const queueId = ulid();
    const now = new Date().toISOString();

    // Check if sender is admin (auto-approve)
    const isAdmin = await checkPublishCapability(env, submittedBy);
    const status = isAdmin ? "approved" : "pending";

    await env.DB.prepare(
      `INSERT INTO publish_queue (id, document_id, media_asset_id, title, status, submitted_by, reviewed_by, source_message_id, submitted_at, reviewed_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(
        queueId,
        isMedia ? null : docOrAssetId,
        isMedia ? docOrAssetId : null,
        att.filename || parsed.subject,
        status,
        submittedBy,
        isAdmin ? submittedBy : null,
        messageId,
        now,
        isAdmin ? now : null
      )
      .run();

    results.push({
      queueId,
      assetId: docOrAssetId,
      filename: att.filename,
      status,
      autoApproved: isAdmin,
    });
  }

  // If no attachments, treat the email body itself as content to publish
  if (parsed.attachments.length === 0 && (parsed.textBody || parsed.htmlBody)) {
    const content = parsed.htmlBody || parsed.textBody;
    const contentType = parsed.htmlBody ? "text/html" : "text/plain";
    const data = new TextEncoder().encode(content);

    const doc = await storeDocument(env, {
      title: parsed.subject || "Untitled",
      category: "media",
      contentType,
      data: data.buffer,
      uploadedBy: submittedBy,
      tags: ["publish-queue"],
      description: `Submitted via publish@ by ${parsed.from}`,
    });

    const queueId = ulid();
    const isAdmin = await checkPublishCapability(env, submittedBy);

    await env.DB.prepare(
      `INSERT INTO publish_queue (id, document_id, title, status, submitted_by, reviewed_by, source_message_id, submitted_at, reviewed_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(
        queueId,
        doc.id,
        parsed.subject || "Untitled",
        isAdmin ? "approved" : "pending",
        submittedBy,
        isAdmin ? submittedBy : null,
        messageId,
        new Date().toISOString(),
        isAdmin ? new Date().toISOString() : null
      )
      .run();

    results.push({
      queueId,
      documentId: doc.id,
      status: isAdmin ? "approved" : "pending",
      autoApproved: isAdmin,
    });
  }

  return {
    type: "publish",
    id: results[0]?.queueId || messageId,
    items: results,
  };
}

async function checkPublishCapability(env, operatorId) {
  if (!operatorId || operatorId === "unknown" || operatorId === "system") return false;

  const op = await env.DB.prepare(
    `SELECT capabilities FROM operators WHERE id = ? AND active = 1`
  )
    .bind(operatorId)
    .first();

  if (!op) return false;

  const caps = JSON.parse(op.capabilities || "[]");
  return caps.includes("workspace:admin");
}

function extractOperatorFromEmail(email) {
  const local = email.split("@")[0].toLowerCase();
  const operators = new Set(["ken", "kalyn", "lorrie", "katie"]);
  return operators.has(local) ? local : null;
}

function isMediaType(mime) {
  if (!mime) return false;
  return mime.startsWith("image/") || mime.startsWith("video/") || mime.startsWith("audio/");
}

function inferAssetType(mime) {
  if (mime.startsWith("image/")) return "image";
  if (mime.startsWith("video/")) return "video";
  if (mime.startsWith("audio/")) return "audio";
  return "graphic";
}
