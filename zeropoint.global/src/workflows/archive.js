/**
 * email-to-archive workflow handler.
 *
 * Trigger: Forward any email to archive@zeropoint.global
 * Action:
 *   1. Hash the message body and all attachments (SHA-256)
 *   2. Store in R2 with content-addressed key
 *   3. Create document record with provenance metadata
 *   4. Emit document:archived receipt
 */

import { storeDocument } from "../docs/store.js";

/**
 * @param {Object} env
 * @param {Object} parsed   - Parsed email
 * @param {string} messageId - Stored message ID
 * @returns {Promise<{type: string, id: string}>}
 */
export async function handleArchive(env, parsed, messageId) {
  const docs = [];

  // Archive the email body as a document
  const bodyContent = parsed.htmlBody || parsed.textBody || "";
  if (bodyContent) {
    const bodyData = new TextEncoder().encode(bodyContent);
    const bodyDoc = await storeDocument(env, {
      title: `Archive: ${parsed.subject}`,
      category: "correspondence",
      contentType: parsed.htmlBody ? "text/html" : "text/plain",
      data: bodyData.buffer,
      uploadedBy: "system",
      tags: ["archived", "email"],
      description: `Archived from ${parsed.from} on ${new Date().toISOString()}. Original subject: "${parsed.subject}"`,
    });
    docs.push(bodyDoc.id);
  }

  // Archive each attachment as a separate document
  for (const att of parsed.attachments) {
    if (att.content) {
      const attDoc = await storeDocument(env, {
        title: att.filename || `attachment-${att.contentId || "unknown"}`,
        category: "correspondence",
        contentType: att.mimeType || "application/octet-stream",
        data: att.content,
        uploadedBy: "system",
        tags: ["archived", "email-attachment"],
        description: `Attachment from ${parsed.from}, email subject: "${parsed.subject}"`,
      });
      docs.push(attDoc.id);
    }
  }

  return {
    type: "archive",
    id: docs[0] || messageId,
    documentIds: docs,
    attachmentCount: parsed.attachments.length,
  };
}
