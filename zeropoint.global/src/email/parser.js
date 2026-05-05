/**
 * Email parser — extracts structured data from raw email messages.
 * Uses postal-mime for RFC 2822 / MIME parsing.
 */

import PostalMime from "postal-mime";

/**
 * Parse a raw email stream into a structured object.
 *
 * @param {ForwardableEmailMessage} message - Cloudflare Email Worker message
 * @returns {Promise<ParsedEmail>}
 *
 * @typedef {Object} ParsedEmail
 * @property {string} from        - Sender email address
 * @property {string} fromName    - Sender display name
 * @property {string} to          - Primary recipient address
 * @property {string[]} toAll     - All To: addresses
 * @property {string[]} cc        - CC addresses
 * @property {string[]} bcc       - BCC addresses (if visible)
 * @property {string} subject     - Subject line
 * @property {string} textBody    - Plain text body
 * @property {string} htmlBody    - HTML body
 * @property {string} messageId   - Message-ID header
 * @property {string} inReplyTo   - In-Reply-To header (for threading)
 * @property {string} date        - Date header
 * @property {Attachment[]} attachments - Parsed attachments
 * @property {number} rawSize     - Original message size in bytes
 * @property {Object} authResults - DKIM/SPF/DMARC results from headers
 */
export async function parseEmail(message) {
  // Read the raw email stream
  const rawEmail = await streamToArrayBuffer(message.raw);

  // Parse with postal-mime
  const parser = new PostalMime();
  const parsed = await parser.parse(rawEmail);

  // Extract authentication results from headers
  const authResults = extractAuthResults(message.headers);

  return {
    from: message.from,
    fromName: parsed.from?.name || "",
    to: message.to,
    toAll: parsed.to?.map((a) => a.address) || [message.to],
    cc: parsed.cc?.map((a) => a.address) || [],
    bcc: parsed.bcc?.map((a) => a.address) || [],
    subject: parsed.subject || "(no subject)",
    textBody: parsed.text || "",
    htmlBody: parsed.html || "",
    messageId: parsed.messageId || "",
    inReplyTo: parsed.inReplyTo || "",
    date: parsed.date || new Date().toISOString(),
    attachments: (parsed.attachments || []).map((att) => ({
      filename: att.filename || "unnamed",
      contentType: att.mimeType || "application/octet-stream",
      content: att.content, // ArrayBuffer
      size: att.content?.byteLength || 0,
    })),
    rawSize: message.rawSize,
    authResults,
  };
}

/**
 * Read a ReadableStream into an ArrayBuffer.
 */
async function streamToArrayBuffer(stream) {
  const reader = stream.getReader();
  const chunks = [];
  let totalLength = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    totalLength += value.length;
  }

  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }

  return result.buffer;
}

/**
 * Extract DKIM/SPF/DMARC authentication results from email headers.
 */
function extractAuthResults(headers) {
  const results = {
    spf: "none",
    dkim: "none",
    dmarc: "none",
  };

  const authHeader = headers.get("authentication-results");
  if (!authHeader) return results;

  if (authHeader.includes("spf=pass")) results.spf = "pass";
  else if (authHeader.includes("spf=fail")) results.spf = "fail";
  else if (authHeader.includes("spf=softfail")) results.spf = "softfail";

  if (authHeader.includes("dkim=pass")) results.dkim = "pass";
  else if (authHeader.includes("dkim=fail")) results.dkim = "fail";

  if (authHeader.includes("dmarc=pass")) results.dmarc = "pass";
  else if (authHeader.includes("dmarc=fail")) results.dmarc = "fail";

  return results;
}
