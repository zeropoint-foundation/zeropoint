/**
 * Outbound email — provider-abstracted SMTP relay.
 *
 * Sends mail via an HTTP API relay (Resend, SES, etc.).
 * The provider is swappable without changing calling code.
 *
 * Provider selection:
 *   - Resend: Free 100/day (3k/month). Clean API. Good for low-volume.
 *   - Amazon SES: $0.10/1000. Battle-tested. Best at scale.
 *   - Cloudflare: When native outbound exits beta.
 *
 * All providers are called via fetch() — no SMTP sockets needed.
 */

import { ulid } from "./ulid.js";

/**
 * Send an email through the configured relay.
 *
 * @param {Object} env       - Worker environment bindings
 * @param {OutboundEmail} email - Email to send
 * @returns {Promise<SendResult>}
 *
 * @typedef {Object} OutboundEmail
 * @property {string} from       - Sender (e.g., "ken@zeropoint.global")
 * @property {string} fromName   - Sender display name
 * @property {string[]} to       - Recipient addresses
 * @property {string[]} [cc]     - CC addresses
 * @property {string[]} [bcc]    - BCC addresses
 * @property {string} subject    - Subject line
 * @property {string} [text]     - Plain text body
 * @property {string} [html]     - HTML body
 * @property {string} [inReplyTo] - Message-ID for threading
 * @property {string} [replyTo]  - Reply-To address
 * @property {OutboundAttachment[]} [attachments] - File attachments
 *
 * @typedef {Object} OutboundAttachment
 * @property {string} filename
 * @property {string} contentType
 * @property {ArrayBuffer|string} content - Binary content or base64 string
 *
 * @typedef {Object} SendResult
 * @property {boolean} ok
 * @property {string} messageId   - Our internal message ID
 * @property {string} [relayId]   - Provider's message ID
 * @property {string} [error]     - Error message if failed
 */
export async function sendEmail(env, email) {
  const messageId = ulid();

  // Determine provider from env
  const provider = env.EMAIL_PROVIDER || "resend";

  let result;
  switch (provider) {
    case "resend":
      result = await sendViaResend(env, email);
      break;
    case "ses":
      result = await sendViaSES(env, email);
      break;
    default:
      return { ok: false, messageId, error: `Unknown provider: ${provider}` };
  }

  if (result.ok) {
    // Store sent message in D1
    await storeSentMessage(env, email, messageId, result.relayId);

    console.log(
      JSON.stringify({
        event: "email:sent",
        messageId,
        relayId: result.relayId,
        provider,
        from: email.from,
        to: email.to,
        subject: email.subject,
      })
    );
  } else {
    console.error(
      JSON.stringify({
        event: "email:send_failed",
        messageId,
        provider,
        from: email.from,
        to: email.to,
        error: result.error,
      })
    );
  }

  return { ...result, messageId };
}

// ─── Resend Provider ───────────────────────────────────────

async function sendViaResend(env, email) {
  const apiKey = env.RESEND_API_KEY;
  if (!apiKey) {
    return { ok: false, error: "RESEND_API_KEY not configured" };
  }

  const fromField = email.fromName
    ? `${email.fromName} <${email.from}>`
    : email.from;

  const payload = {
    from: fromField,
    to: email.to,
    subject: email.subject,
  };

  if (email.cc?.length) payload.cc = email.cc;
  if (email.bcc?.length) payload.bcc = email.bcc;
  if (email.text) payload.text = email.text;
  if (email.html) payload.html = email.html;
  if (email.replyTo) payload.reply_to = email.replyTo;

  // Threading headers
  if (email.inReplyTo) {
    payload.headers = {
      "In-Reply-To": email.inReplyTo,
      References: email.inReplyTo,
    };
  }

  // Attachments
  if (email.attachments?.length) {
    payload.attachments = email.attachments.map((att) => ({
      filename: att.filename,
      content:
        typeof att.content === "string"
          ? att.content
          : arrayBufferToBase64(att.content),
      content_type: att.contentType,
    }));
  }

  try {
    const response = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });

    const data = await response.json();

    if (!response.ok) {
      return {
        ok: false,
        error: data.message || `Resend API error: ${response.status}`,
      };
    }

    return { ok: true, relayId: data.id };
  } catch (err) {
    return { ok: false, error: `Resend request failed: ${err.message}` };
  }
}

// ─── Amazon SES Provider (v2 API) ──────────────────────────

async function sendViaSES(env, email) {
  const accessKeyId = env.AWS_ACCESS_KEY_ID;
  const secretAccessKey = env.AWS_SECRET_ACCESS_KEY;
  const region = env.AWS_SES_REGION || "us-east-1";

  if (!accessKeyId || !secretAccessKey) {
    return { ok: false, error: "AWS SES credentials not configured" };
  }

  // SES v2 SendEmail API via raw HTTPS
  // For MVP, use the simple email format (not raw MIME)
  const payload = {
    Content: {
      Simple: {
        Subject: { Data: email.subject, Charset: "UTF-8" },
        Body: {},
      },
    },
    Destination: {
      ToAddresses: email.to,
    },
    FromEmailAddress: email.fromName
      ? `${email.fromName} <${email.from}>`
      : email.from,
  };

  if (email.text) {
    payload.Content.Simple.Body.Text = {
      Data: email.text,
      Charset: "UTF-8",
    };
  }
  if (email.html) {
    payload.Content.Simple.Body.Html = {
      Data: email.html,
      Charset: "UTF-8",
    };
  }
  if (email.cc?.length) payload.Destination.CcAddresses = email.cc;
  if (email.bcc?.length) payload.Destination.BccAddresses = email.bcc;
  if (email.replyTo) payload.ReplyToAddresses = [email.replyTo];

  try {
    // Sign and send using AWS Signature V4
    const response = await awsFetch(
      `https://email.${region}.amazonaws.com/v2/email/outbound-emails`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      },
      { accessKeyId, secretAccessKey, region, service: "ses" }
    );

    const data = await response.json();

    if (!response.ok) {
      return {
        ok: false,
        error: data.message || `SES error: ${response.status}`,
      };
    }

    return { ok: true, relayId: data.MessageId };
  } catch (err) {
    return { ok: false, error: `SES request failed: ${err.message}` };
  }
}

/**
 * Minimal AWS Signature V4 fetch.
 * Enough for SES v2 — not a general-purpose AWS client.
 */
async function awsFetch(url, init, credentials) {
  const { accessKeyId, secretAccessKey, region, service } = credentials;
  const parsedUrl = new URL(url);
  const now = new Date();
  const dateStamp = now.toISOString().replace(/[-:]/g, "").split(".")[0] + "Z";
  const dateOnly = dateStamp.slice(0, 8);

  const headers = new Headers(init.headers);
  headers.set("host", parsedUrl.host);
  headers.set("x-amz-date", dateStamp);

  const body = init.body || "";
  const bodyHash = await sha256Hex(body);
  headers.set("x-amz-content-sha256", bodyHash);

  // Canonical request
  const signedHeadersList = [...headers.keys()].sort();
  const signedHeaders = signedHeadersList.join(";");
  const canonicalHeaders = signedHeadersList
    .map((k) => `${k}:${headers.get(k)}\n`)
    .join("");

  const canonicalRequest = [
    init.method || "GET",
    parsedUrl.pathname,
    parsedUrl.search.slice(1),
    canonicalHeaders,
    signedHeaders,
    bodyHash,
  ].join("\n");

  // String to sign
  const scope = `${dateOnly}/${region}/${service}/aws4_request`;
  const stringToSign = [
    "AWS4-HMAC-SHA256",
    dateStamp,
    scope,
    await sha256Hex(canonicalRequest),
  ].join("\n");

  // Signing key
  const kDate = await hmacSha256(
    new TextEncoder().encode(`AWS4${secretAccessKey}`),
    dateOnly
  );
  const kRegion = await hmacSha256(kDate, region);
  const kService = await hmacSha256(kRegion, service);
  const kSigning = await hmacSha256(kService, "aws4_request");

  // Signature
  const signatureBytes = await hmacSha256(kSigning, stringToSign);
  const signature = bufToHex(signatureBytes);

  headers.set(
    "authorization",
    `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`
  );

  return fetch(url, { ...init, headers });
}

async function sha256Hex(data) {
  const encoded =
    typeof data === "string" ? new TextEncoder().encode(data) : data;
  const hash = await crypto.subtle.digest("SHA-256", encoded);
  return bufToHex(new Uint8Array(hash));
}

async function hmacSha256(key, data) {
  const keyData = key instanceof Uint8Array ? key : new TextEncoder().encode(key);
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyData,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const encoded =
    typeof data === "string" ? new TextEncoder().encode(data) : data;
  const sig = await crypto.subtle.sign("HMAC", cryptoKey, encoded);
  return new Uint8Array(sig);
}

function bufToHex(buf) {
  return [...buf].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// ─── Storage ───────────────────────────────────────────────

/**
 * Store a sent message in D1 for the sender's "sent" folder.
 */
async function storeSentMessage(env, email, messageId, relayId) {
  const now = new Date().toISOString();
  const senderMailbox = email.from.split("@")[0].toLowerCase();

  await env.DB.prepare(
    `INSERT INTO messages (
      id, mailbox, folder, from_address, from_name,
      to_addresses, cc_addresses, subject,
      body_text, body_html, has_attachments,
      is_read, message_id_header,
      received_at, created_at
    ) VALUES (?, ?, 'sent', ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)`
  )
    .bind(
      messageId,
      senderMailbox,
      email.from,
      email.fromName || null,
      JSON.stringify(email.to),
      email.cc?.length ? JSON.stringify(email.cc) : null,
      email.subject,
      email.text || null,
      email.html || null,
      email.attachments?.length ? 1 : 0,
      relayId || null,
      now,
      now
    )
    .run();
}

// ─── Utilities ─────────────────────────────────────────────

function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}
