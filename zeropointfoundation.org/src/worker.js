/**
 * ZeroPoint Global — Worker
 *
 * Handles:
 *  1. Static asset serving with legacy redirects
 *  2. Inbound email processing (Cloudflare Email Workers)
 *  3. Governed REST API for email client (/api/mail/*)
 *  4. Governed REST API for documents & media (/api/docs/*, /api/media/*)
 *  5. File transfer links (/api/links/*)
 *
 * Every API call passes through the ZeroPoint governance gate:
 *   - Ed25519 signature verification
 *   - Capability-based authorization
 *   - Receipt emission for every action
 */

import { parseEmail } from "./email/parser.js";
import { resolveRoute } from "./email/router.js";
import { storeMessage, queryMessages, getMessage, markRead, moveMessage, toggleStar } from "./email/store.js";
import { sendEmail } from "./email/send.js";
import { verifyRequest } from "./auth/verify.js";
import { hasCapability, mailCapability } from "./auth/capabilities.js";
import { emitReceipt, emitAuthFailure } from "./auth/receipts.js";
import { storeDocument, queryDocuments, getDocument, getDocumentVersions, downloadDocument, updateDocument, deleteDocument, logDocumentAccess } from "./docs/store.js";
import { uploadAsset, queryAssets, getAsset, transitionAsset, updateAsset, deleteAsset } from "./docs/media.js";
import { createDownloadLink, serveDownloadLink, revokeDownloadLink, queryDownloadLinks, createUploadLink, consumeUploadLink } from "./docs/links.js";
import { createSession } from "./auth/session.js";
import {
  RP_ID, RP_NAME,
  generateChallenge, base64urlEncode, base64urlDecode,
  verifyRegistration, verifyAuthentication,
} from "./auth/webauthn.js";
import { dispatchWorkflow } from "./workflows/dispatch.js";
import { queryTasks, updateTaskStatus } from "./workflows/task.js";
import { queryInquiries } from "./workflows/inquiry.js";
import { importFromDrive, exportToDrive, listDriveFiles, refreshAccessToken } from "./interop/google.js";
import { ulid } from "./email/ulid.js";

// ─── Static Asset Redirects ────────────────────────────────

const REDIRECTS = {
  "/playground.html": "/lab/sim01.html",
  "/playground": "/lab/",
};

/**
 * Variant domains that should 301 redirect to the canonical domain.
 * All paths and query strings are preserved.
 */
const CANONICAL_HOST = "zeropointfoundation.org";
const VARIANT_HOSTS = new Set([
  "www.zeropointfoundation.org",
  "zeropoint.global",
  "www.zeropoint.global",
  "zeropointfoundation.com",
  "www.zeropointfoundation.com",
  "zeropointfoundation.net",
  "www.zeropointfoundation.net",
  "zeropoint.foundation",
  "www.zeropoint.foundation",
]);

// ─── Email Handler (inbound — no auth needed) ─────────────

async function handleEmail(message, env, ctx) {
  const startTime = Date.now();

  try {
    const parsed = await parseEmail(message);
    const route = resolveRoute(parsed.to);
    const result = await storeMessage(env, parsed, route);

    console.log(
      JSON.stringify({
        event: "email:received",
        messageId: result.messageId,
        from: parsed.from,
        to: parsed.to,
        subject: parsed.subject,
        route: route.type,
        mailbox: route.mailbox,
        attachments: parsed.attachments.length,
        authResults: parsed.authResults,
        durationMs: Date.now() - startTime,
      })
    );

    if (route.type === "workflow") {
      // Dispatch to workflow handler (fire-and-forget via waitUntil)
      ctx.waitUntil(
        dispatchWorkflow(env, parsed, route, result.messageId)
      );
    }
  } catch (err) {
    console.error(
      JSON.stringify({
        event: "email:error",
        from: message.from,
        to: message.to,
        error: err.message,
        stack: err.stack,
        durationMs: Date.now() - startTime,
      })
    );
  }
}

// ─── Governance Gate ───────────────────────────────────────

/**
 * Authenticate and authorize an API request.
 * Returns the operator context or an error Response.
 */
async function governanceGate(request, env, requiredCapability) {
  const auth = await verifyRequest(request, env);

  if (!auth.ok) {
    // Emit denial receipt
    const url = new URL(request.url);
    try {
      await emitAuthFailure(env, {
        operatorId: auth.operatorId,
        reason: auth.error,
        path: url.pathname,
        method: request.method,
        ip: request.headers.get("CF-Connecting-IP") || "unknown",
      });
    } catch (e) {
      // Don't let receipt emission failure block the auth response
      console.error("Receipt emission failed:", e.message);
    }

    return {
      ok: false,
      response: new Response(
        JSON.stringify({ error: auth.error }),
        {
          status: auth.status || 401,
          headers: { "Content-Type": "application/json", ...corsHeaders() },
        }
      ),
    };
  }

  // Check capability
  if (requiredCapability && !hasCapability(auth.capabilities, requiredCapability)) {
    try {
      await emitAuthFailure(env, {
        operatorId: auth.operatorId,
        reason: `Missing capability: ${requiredCapability}`,
        path: new URL(request.url).pathname,
        method: request.method,
        ip: request.headers.get("CF-Connecting-IP") || "unknown",
      });
    } catch (e) {
      console.error("Receipt emission failed:", e.message);
    }

    return {
      ok: false,
      response: new Response(
        JSON.stringify({
          error: "Insufficient capability",
          required: requiredCapability,
        }),
        {
          status: 403,
          headers: { "Content-Type": "application/json", ...corsHeaders() },
        }
      ),
    };
  }

  return { ok: true, operator: auth };
}

// ─── CORS ──────────────────────────────────────────────────

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
  };
}

// ─── API Router ────────────────────────────────────────────

async function handleApi(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  if (method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders() });
  }

  const json = (data, status = 200) =>
    new Response(JSON.stringify(data), {
      status,
      headers: { "Content-Type": "application/json", ...corsHeaders() },
    });

  try {
    // ── Unauthenticated endpoints ──

    // GET /api/health
    if (path === "/api/health" && method === "GET") {
      return json({
        status: "ok",
        service: "zeropoint-global",
        governance: "enabled",
        timestamp: new Date().toISOString(),
      });
    }

    // POST /api/auth/session — create session token (pre-auth)
    if (path === "/api/auth/session" && method === "POST") {
      const body = await request.json();
      if (!body.operatorId) {
        return json({ error: "operatorId required" }, 400);
      }
      const result = await createSession(env, body.operatorId);
      if (!result) {
        return json({ error: "Unknown or inactive operator" }, 401);
      }
      return json(result);
    }

    // GET /api/operators/active — list active operators (pre-auth, for login screen).
    // Renamed from /api/operators to free that path for the admin-gated full listing
    // at line ~454 below. Returns only id + name; no role, email, or onboarded_at.
    if (path === "/api/operators/active" && method === "GET") {
      const rows = await env.DB.prepare(
        `SELECT id, name FROM operators WHERE active = 1 ORDER BY name`
      ).all();
      return json({ operators: rows.results });
    }

    // ── WebAuthn (passkey) ceremonies ─────────────────────────
    //
    // Four endpoints implement the W3C WebAuthn registration and authentication
    // flows. The browser handles the platform's secure unlock (Face ID, Touch
    // ID, Windows Hello, fingerprint, PIN, hardware key). We verify what comes
    // back. Every successful ceremony emits a receipt into the audit chain.

    // POST /api/auth/webauthn/register/options — start a registration ceremony.
    // Authenticated: only the logged-in operator can register a passkey for
    // themselves.
    if (path === "/api/auth/webauthn/register/options" && method === "POST") {
      const gate = await governanceGate(request, env, null);
      if (!gate.ok) return gate.response;

      const operatorId = gate.operator.operatorId;
      const op = await env.DB.prepare(
        `SELECT id, name, email FROM operators WHERE id = ?`
      ).bind(operatorId).first();
      if (!op) return json({ error: "operator not found" }, 404);

      const challenge = generateChallenge();
      await env.DB.prepare(
        `INSERT INTO webauthn_challenges (challenge, operator_id, ceremony, created_at)
         VALUES (?, ?, 'register', datetime('now'))`
      ).bind(challenge, operatorId).run();

      // Existing credentials → exclude so the same authenticator isn't double-registered
      const existing = await env.DB.prepare(
        `SELECT credential_id, transports FROM webauthn_credentials WHERE operator_id = ?`
      ).bind(operatorId).all();

      const userIdBytes = new TextEncoder().encode(operatorId);

      return json({
        rp: { id: RP_ID, name: RP_NAME },
        user: {
          id: base64urlEncode(userIdBytes),
          name: op.email,
          displayName: op.name,
        },
        challenge,
        pubKeyCredParams: [
          { type: "public-key", alg: -7  }, // ES256 — Windows Hello, most platforms
          { type: "public-key", alg: -8  }, // EdDSA — some Android, hardware keys
        ],
        authenticatorSelection: {
          residentKey: "preferred",
          userVerification: "preferred",
        },
        attestation: "none",
        excludeCredentials: existing.results.map(r => ({
          type: "public-key",
          id: r.credential_id,
          transports: JSON.parse(r.transports || "[]"),
        })),
        timeout: 120000,
      });
    }

    // POST /api/auth/webauthn/register/verify — finish a registration ceremony.
    if (path === "/api/auth/webauthn/register/verify" && method === "POST") {
      const gate = await governanceGate(request, env, null);
      if (!gate.ok) return gate.response;
      const operatorId = gate.operator.operatorId;

      const body = await request.json();
      const credential = body.credential;
      const deviceName = (body.deviceName || "").toString().slice(0, 80) || null;
      if (!credential || !credential.response) {
        return json({ error: "credential missing" }, 400);
      }

      // Pull the matching pending challenge (must exist and belong to this op)
      const ceremony = await env.DB.prepare(
        `SELECT challenge FROM webauthn_challenges
         WHERE operator_id = ? AND ceremony = 'register'
         ORDER BY created_at DESC LIMIT 1`
      ).bind(operatorId).first();
      if (!ceremony) return json({ error: "no pending registration" }, 400);
      const expectedChallenge = ceremony.challenge;

      // One-shot: delete the challenge whether verification succeeds or fails
      await env.DB.prepare(
        `DELETE FROM webauthn_challenges WHERE challenge = ?`
      ).bind(expectedChallenge).run();

      let verified;
      try {
        verified = await verifyRegistration({ credential, expectedChallenge });
      } catch (err) {
        await emitReceipt(env, {
          operatorId,
          claim: "webauthn:register:failed",
          subject: operatorId,
          capability: "self",
          metadata: { error: err.message },
        });
        return json({ error: `registration failed: ${err.message}` }, 400);
      }

      const id = ulid();
      await env.DB.prepare(
        `INSERT INTO webauthn_credentials
           (id, operator_id, credential_id, public_key_jwk, sign_count, transports, device_name, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))`
      ).bind(
        id,
        operatorId,
        verified.credentialId,
        JSON.stringify(verified.publicKeyJwk),
        verified.signCount,
        JSON.stringify(credential.response.transports || []),
        deviceName,
      ).run();

      const receiptId = await emitReceipt(env, {
        operatorId,
        claim: "webauthn:register",
        subject: operatorId,
        capability: "self",
        metadata: {
          credentialId: verified.credentialId,
          alg: verified.publicKeyJwk.alg,
          deviceName,
          userVerified: verified.userVerified,
        },
      });

      return json({ ok: true, credentialId: verified.credentialId, receiptId });
    }

    // POST /api/auth/webauthn/auth/options — start an authentication ceremony.
    // Pre-auth: a director who hasn't logged in yet can request a challenge
    // for their registered credentials.
    if (path === "/api/auth/webauthn/auth/options" && method === "POST") {
      const body = await request.json().catch(() => ({}));
      const operatorId = body.operatorId;
      if (!operatorId) return json({ error: "operatorId required" }, 400);

      const op = await env.DB.prepare(
        `SELECT id FROM operators WHERE id = ? AND active = 1`
      ).bind(operatorId).first();
      if (!op) return json({ error: "Unknown or inactive operator" }, 404);

      const creds = await env.DB.prepare(
        `SELECT credential_id, transports FROM webauthn_credentials WHERE operator_id = ?`
      ).bind(operatorId).all();
      if (!creds.results.length) {
        return json({ error: "No passkey registered for this operator" }, 404);
      }

      const challenge = generateChallenge();
      await env.DB.prepare(
        `INSERT INTO webauthn_challenges (challenge, operator_id, ceremony, created_at)
         VALUES (?, ?, 'authenticate', datetime('now'))`
      ).bind(challenge, operatorId).run();

      return json({
        challenge,
        rpId: RP_ID,
        timeout: 120000,
        userVerification: "preferred",
        allowCredentials: creds.results.map(r => ({
          type: "public-key",
          id: r.credential_id,
          transports: JSON.parse(r.transports || "[]"),
        })),
      });
    }

    // POST /api/auth/webauthn/auth/verify — finish authentication, issue session.
    if (path === "/api/auth/webauthn/auth/verify" && method === "POST") {
      const body = await request.json().catch(() => ({}));
      const operatorId = body.operatorId;
      const credential = body.credential;
      if (!operatorId || !credential || !credential.response) {
        return json({ error: "operatorId and credential required" }, 400);
      }

      const ceremony = await env.DB.prepare(
        `SELECT challenge FROM webauthn_challenges
         WHERE operator_id = ? AND ceremony = 'authenticate'
         ORDER BY created_at DESC LIMIT 1`
      ).bind(operatorId).first();
      if (!ceremony) return json({ error: "no pending authentication" }, 400);
      const expectedChallenge = ceremony.challenge;
      await env.DB.prepare(
        `DELETE FROM webauthn_challenges WHERE challenge = ?`
      ).bind(expectedChallenge).run();

      // Look up the stored credential
      const credentialId = credential.id;
      const stored = await env.DB.prepare(
        `SELECT public_key_jwk, sign_count FROM webauthn_credentials
         WHERE operator_id = ? AND credential_id = ?`
      ).bind(operatorId, credentialId).first();
      if (!stored) return json({ error: "credential not registered" }, 404);

      let result;
      try {
        result = await verifyAuthentication({
          credential,
          expectedChallenge,
          storedPublicKeyJwk: JSON.parse(stored.public_key_jwk),
          storedSignCount: stored.sign_count,
        });
      } catch (err) {
        await emitAuthFailure(env, {
          operatorId,
          reason: `webauthn: ${err.message}`,
          path: "/api/auth/webauthn/auth/verify",
          method: "POST",
          ip: request.headers.get("CF-Connecting-IP") || "unknown",
        });
        return json({ error: `authentication failed: ${err.message}` }, 401);
      }

      // Bump sign count, update last-used
      await env.DB.prepare(
        `UPDATE webauthn_credentials
         SET sign_count = ?, last_used_at = datetime('now')
         WHERE operator_id = ? AND credential_id = ?`
      ).bind(result.newSignCount, operatorId, credentialId).run();

      // Issue a session token using the existing flow
      const session = await createSession(env, operatorId);
      if (!session) return json({ error: "Session creation failed" }, 500);

      await emitReceipt(env, {
        operatorId,
        claim: "webauthn:authenticate",
        subject: operatorId,
        capability: "self",
        metadata: {
          credentialId,
          userVerified: result.userVerified,
        },
      });

      return json(session);
    }

    // GET /api/auth/webauthn/has-passkey?operatorId=<id> — pre-auth probe so the
    // login UI can decide whether to offer the passkey path. Returns just a
    // boolean; doesn't leak any of the credential.
    if (path === "/api/auth/webauthn/has-passkey" && method === "GET") {
      const operatorId = url.searchParams.get("operatorId");
      if (!operatorId) return json({ error: "operatorId required" }, 400);
      const row = await env.DB.prepare(
        `SELECT 1 AS one FROM webauthn_credentials WHERE operator_id = ? LIMIT 1`
      ).bind(operatorId).first();
      return json({ hasPasskey: !!row });
    }

    // ── Governed endpoints ──

    // GET /api/mail/:mailbox — list messages
    const listMatch = path.match(/^\/api\/mail\/([a-z]+)\/?$/);
    if (listMatch && method === "GET") {
      const mailbox = listMatch[1];
      const gate = await governanceGate(request, env, mailCapability("read", mailbox));
      if (!gate.ok) return gate.response;

      const folder = url.searchParams.get("folder") || "inbox";
      const limit = parseInt(url.searchParams.get("limit") || "50", 10);
      const offset = parseInt(url.searchParams.get("offset") || "0", 10);
      const messages = await queryMessages(env, mailbox, { folder, limit, offset });

      await emitReceipt(env, {
        operatorId: gate.operator.operatorId,
        claim: "mail:list",
        subject: mailbox,
        capability: mailCapability("read", mailbox),
        metadata: { folder, count: messages.length },
      });

      return json({ mailbox, folder, count: messages.length, messages });
    }

    // GET /api/mail/:mailbox/:id — get single message
    const msgMatch = path.match(/^\/api\/mail\/([a-z]+)\/([A-Z0-9]+)\/?$/);
    if (msgMatch && method === "GET") {
      const mailbox = msgMatch[1];
      const gate = await governanceGate(request, env, mailCapability("read", mailbox));
      if (!gate.ok) return gate.response;

      const message = await getMessage(env, msgMatch[2]);
      if (!message) return json({ error: "not found" }, 404);

      await emitReceipt(env, {
        operatorId: gate.operator.operatorId,
        claim: "mail:read",
        subject: msgMatch[2],
        capability: mailCapability("read", mailbox),
      });

      return json(message);
    }

    // POST /api/mail/:mailbox/:id/read — mark as read
    const readMatch = path.match(/^\/api\/mail\/([a-z]+)\/([A-Z0-9]+)\/read\/?$/);
    if (readMatch && method === "POST") {
      const mailbox = readMatch[1];
      const gate = await governanceGate(request, env, mailCapability("manage", mailbox));
      if (!gate.ok) return gate.response;

      await markRead(env, readMatch[2]);

      await emitReceipt(env, {
        operatorId: gate.operator.operatorId,
        claim: "mail:mark_read",
        subject: readMatch[2],
        capability: mailCapability("manage", mailbox),
      });

      return json({ ok: true });
    }

    // POST /api/mail/:mailbox/:id/move — move to folder
    const moveMatch = path.match(/^\/api\/mail\/([a-z]+)\/([A-Z0-9]+)\/move\/?$/);
    if (moveMatch && method === "POST") {
      const mailbox = moveMatch[1];
      const gate = await governanceGate(request, env, mailCapability("manage", mailbox));
      if (!gate.ok) return gate.response;

      const body = await request.json();

      await moveMessage(env, moveMatch[2], body.folder);

      await emitReceipt(env, {
        operatorId: gate.operator.operatorId,
        claim: "mail:move",
        subject: moveMatch[2],
        capability: mailCapability("manage", mailbox),
        metadata: { folder: body.folder },
      });

      return json({ ok: true });
    }

    // POST /api/mail/:mailbox/:id/star — toggle star
    const starMatch = path.match(/^\/api\/mail\/([a-z]+)\/([A-Z0-9]+)\/star\/?$/);
    if (starMatch && method === "POST") {
      const mailbox = starMatch[1];
      const gate = await governanceGate(request, env, mailCapability("manage", mailbox));
      if (!gate.ok) return gate.response;

      await toggleStar(env, starMatch[2]);

      await emitReceipt(env, {
        operatorId: gate.operator.operatorId,
        claim: "mail:star",
        subject: starMatch[2],
        capability: mailCapability("manage", mailbox),
      });

      return json({ ok: true });
    }

    // GET /api/mail/:mailbox/:msgId/attachments/:attId — download
    const attMatch = path.match(
      /^\/api\/mail\/([a-z]+)\/([A-Z0-9]+)\/attachments\/([A-Z0-9]+)\/?$/
    );
    if (attMatch && method === "GET") {
      const mailbox = attMatch[1];
      const gate = await governanceGate(request, env, mailCapability("read", mailbox));
      if (!gate.ok) return gate.response;

      const att = await env.DB.prepare(
        `SELECT * FROM attachments WHERE id = ? AND message_id = ?`
      )
        .bind(attMatch[3], attMatch[2])
        .first();

      if (!att) return json({ error: "attachment not found" }, 404);

      const object = await env.STORAGE.get(att.r2_key);
      if (!object) return json({ error: "blob not found" }, 404);

      await emitReceipt(env, {
        operatorId: gate.operator.operatorId,
        claim: "mail:download_attachment",
        subject: attMatch[3],
        capability: mailCapability("read", mailbox),
        metadata: { filename: att.filename, messageId: attMatch[2] },
      });

      return new Response(object.body, {
        headers: {
          "Content-Type": att.content_type,
          "Content-Disposition": `attachment; filename="${att.filename}"`,
          ...corsHeaders(),
        },
      });
    }

    // POST /api/mail/:mailbox/send — compose and send
    const sendMatch = path.match(/^\/api\/mail\/([a-z]+)\/send\/?$/);
    if (sendMatch && method === "POST") {
      const mailbox = sendMatch[1];
      const gate = await governanceGate(request, env, mailCapability("send", mailbox));
      if (!gate.ok) return gate.response;

      const body = await request.json();

      if (!body.to?.length || !body.subject) {
        return json({ error: "to and subject are required" }, 400);
      }

      const result = await sendEmail(env, {
        from: `${mailbox}@zeropoint.global`,
        fromName: body.fromName || gate.operator.operatorName,
        to: Array.isArray(body.to) ? body.to : [body.to],
        cc: body.cc || [],
        bcc: body.bcc || [],
        subject: body.subject,
        text: body.text || "",
        html: body.html || "",
        inReplyTo: body.inReplyTo || "",
        replyTo: body.replyTo || "",
      });

      if (!result.ok) {
        return json({ error: result.error }, 502);
      }

      await emitReceipt(env, {
        operatorId: gate.operator.operatorId,
        claim: "mail:send",
        subject: result.messageId,
        capability: mailCapability("send", mailbox),
        metadata: { to: body.to, relayId: result.relayId },
      });

      return json({
        ok: true,
        messageId: result.messageId,
        relayId: result.relayId,
      });
    }

    // POST /api/operators — register a new operator (admin only)
    if (path === "/api/operators" && method === "POST") {
      const gate = await governanceGate(request, env, "workspace:admin");
      if (!gate.ok) return gate.response;

      const body = await request.json();
      if (!body.id || !body.name || !body.email || !body.public_key_hex) {
        return json({ error: "id, name, email, and public_key_hex required" }, 400);
      }

      const capabilities = JSON.stringify(body.capabilities || []);
      const role = body.role || "officer";
      const now = new Date().toISOString();

      await env.DB.prepare(
        `INSERT INTO operators (id, name, email, public_key_hex, capabilities, role, active, onboarded_at, created_at)
         VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)`
      )
        .bind(body.id, body.name, body.email, body.public_key_hex, capabilities, role, now, now)
        .run();

      await emitReceipt(env, {
        operatorId: gate.operator.operatorId,
        claim: "operator:registered",
        subject: body.id,
        capability: "workspace:admin",
        metadata: { name: body.name, email: body.email, role },
      });

      return json({ ok: true, operatorId: body.id, role });
    }

    // GET /api/operators — list operators (admin only)
    if (path === "/api/operators" && method === "GET") {
      const gate = await governanceGate(request, env, "workspace:admin");
      if (!gate.ok) return gate.response;

      const { results } = await env.DB.prepare(
        `SELECT id, name, email, role, active, onboarded_at FROM operators`
      ).all();

      return json({ count: results.length, operators: results });
    }

    // DELETE /api/operators/:id — deactivate operator (admin only)
    const deactivateMatch = path.match(/^\/api\/operators\/([a-z0-9-]+)\/?$/);
    if (deactivateMatch && method === "DELETE") {
      const gate = await governanceGate(request, env, "workspace:admin");
      if (!gate.ok) return gate.response;

      await env.DB.prepare(
        `UPDATE operators SET active = 0 WHERE id = ?`
      )
        .bind(deactivateMatch[1])
        .run();

      await emitReceipt(env, {
        operatorId: gate.operator.operatorId,
        claim: "operator:deactivated",
        subject: deactivateMatch[1],
        capability: "workspace:admin",
      });

      return json({ ok: true });
    }

    // GET /api/receipts — query audit trail (admin only)
    // Optional query params: subject, claim, claim_prefix, since (ISO ts), limit
    if (path === "/api/receipts" && method === "GET") {
      const gate = await governanceGate(request, env, "workspace:admin");
      if (!gate.ok) return gate.response;

      const limit = parseInt(url.searchParams.get("limit") || "100", 10);
      const subject = url.searchParams.get("subject");
      const claim = url.searchParams.get("claim");
      const claimPrefix = url.searchParams.get("claim_prefix");
      const since = url.searchParams.get("since");

      let query = `SELECT * FROM receipts WHERE 1=1`;
      const binds = [];
      if (subject) { query += ` AND subject = ?`; binds.push(subject); }
      if (claim) { query += ` AND claim = ?`; binds.push(claim); }
      if (claimPrefix) { query += ` AND claim LIKE ?`; binds.push(claimPrefix + "%"); }
      if (since) { query += ` AND created_at > ?`; binds.push(since); }
      query += ` ORDER BY created_at DESC LIMIT ?`;
      binds.push(limit);

      const { results } = await env.DB.prepare(query).bind(...binds).all();
      return json({ count: results.length, receipts: results });
    }

    // GET /api/me — return the authenticated operator's full record.
    // Used by the director wizard to detect when their public key has been
    // registered (polling: public_key_hex transitions from zero to real).
    if (path === "/api/me" && method === "GET") {
      const gate = await governanceGate(request, env, null);
      if (!gate.ok) return gate.response;

      const op = await env.DB.prepare(
        `SELECT id, name, email, role, public_key_hex, capabilities, active, onboarded_at
         FROM operators WHERE id = ?`
      )
        .bind(gate.operator.operatorId)
        .first();

      if (!op) return json({ error: "operator not found" }, 404);

      // Detect placeholder vs real key without leaking the placeholder pattern
      const ZERO_KEY = "0".repeat(64);
      const registered = op.public_key_hex && op.public_key_hex !== ZERO_KEY;

      return json({
        id: op.id,
        name: op.name,
        email: op.email,
        role: op.role,
        registered,
        publicKeyFingerprint: op.public_key_hex
          ? op.public_key_hex.slice(0, 16)
          : null,
        capabilities: JSON.parse(op.capabilities || "[]"),
        active: !!op.active,
        onboardedAt: op.onboarded_at,
      });
    }

    // POST /api/onboard/register-identity — one-shot self-registration of the
    // director's Ed25519 public key. Succeeds only while the operator's row
    // still has the all-zero placeholder. Once a real key is in place, this
    // endpoint refuses (key rotation is a separate, sovereignty-gated path).
    if (path === "/api/onboard/register-identity" && method === "POST") {
      const gate = await governanceGate(request, env, null);
      if (!gate.ok) return gate.response;

      const body = await request.json().catch(() => ({}));
      const newKeyHex = (body.publicKeyHex || "").toLowerCase();
      if (!/^[0-9a-f]{64}$/.test(newKeyHex)) {
        return json({ error: "publicKeyHex must be 64 hex characters" }, 400);
      }

      const operatorId = gate.operator.operatorId;
      const op = await env.DB.prepare(
        `SELECT public_key_hex FROM operators WHERE id = ?`
      ).bind(operatorId).first();
      if (!op) return json({ error: "operator not found" }, 404);

      const ZERO_KEY = "0".repeat(64);
      if (op.public_key_hex && op.public_key_hex !== ZERO_KEY) {
        return json({ error: "identity already registered" }, 409);
      }

      await env.DB.prepare(
        `UPDATE operators SET public_key_hex = ?, onboarded_at = datetime('now')
         WHERE id = ? AND (public_key_hex IS NULL OR public_key_hex = ?)`
      ).bind(newKeyHex, operatorId, ZERO_KEY).run();

      const receiptId = await emitReceipt(env, {
        operatorId,
        claim: "onboard:identity:registered",
        subject: operatorId,
        capability: "self",
        metadata: { fingerprint: newKeyHex.slice(0, 16) },
      });
      return json({ ok: true, receiptId });
    }

    // POST /api/onboard/progress — record an onboarding wizard step.
    // Self-scoped: the operator can only post progress for themselves.
    // The receipt subject is always the authenticated operator's id.
    // Used by /onboard/ to drive the director's wizard, and by /onboard/host
    // to mirror their state in real time.
    if (path === "/api/onboard/progress" && method === "POST") {
      const gate = await governanceGate(request, env, null);
      if (!gate.ok) return gate.response;

      const body = await request.json();
      const step = parseInt(body.step, 10);
      if (!Number.isInteger(step) || step < 1 || step > 10) {
        return json({ error: "step must be an integer 1-10" }, 400);
      }
      if (!["started", "completed", "skipped", "failed"].includes(body.status)) {
        return json({ error: "status must be started, completed, skipped, or failed" }, 400);
      }
      // Allow caller to supply a specific claim name (e.g. "onboard:voice:selected").
      // Falls back to the generic positional form for backward-compat.
      const claim = (typeof body.claim === "string" && body.claim.startsWith("onboard:"))
        ? body.claim
        : `onboard:wizard:step:${step}`;

      const receiptId = await emitReceipt(env, {
        operatorId: gate.operator.operatorId,
        claim,
        subject: gate.operator.operatorId,
        capability: "self",
        metadata: {
          step,
          status: body.status,
          ...(body.metadata || {}),
        },
      });

      return json({ ok: true, receiptId, step, claim, status: body.status });
    }

    // ── Document API (/api/docs/*) ──

    // GET /api/docs — list documents
    if (path === "/api/docs" && method === "GET") {
      const gate = await governanceGate(request, env, "docs:read:*");
      if (!gate.ok) return gate.response;

      const category = url.searchParams.get("category");
      const tag = url.searchParams.get("tag");
      const limit = parseInt(url.searchParams.get("limit") || "50", 10);
      const offset = parseInt(url.searchParams.get("offset") || "0", 10);

      const docs = await queryDocuments(env, { category, tag, limit, offset });

      await emitReceipt(env, {
        operatorId: gate.operator.operatorId,
        claim: "docs:list",
        capability: "docs:read:*",
        metadata: { category, count: docs.length },
      });

      return json({ count: docs.length, documents: docs });
    }

    // POST /api/docs — upload document
    if (path === "/api/docs" && method === "POST") {
      const gate = await governanceGate(request, env, "docs:write:*");
      if (!gate.ok) return gate.response;

      const formData = await request.formData();
      const file = formData.get("file");
      if (!file) return json({ error: "file required" }, 400);

      const title = formData.get("title") || file.name;
      const category = formData.get("category") || "internal";
      const tags = formData.get("tags") ? JSON.parse(formData.get("tags")) : [];
      const description = formData.get("description") || "";
      const parentVersionId = formData.get("parentVersionId") || null;

      const data = await file.arrayBuffer();
      const result = await storeDocument(env, {
        title,
        category,
        contentType: file.type || "application/octet-stream",
        data,
        uploadedBy: gate.operator.operatorId,
        tags,
        description,
        parentVersionId,
      });

      await emitReceipt(env, {
        operatorId: gate.operator.operatorId,
        claim: "docs:upload",
        subject: result.id,
        capability: "docs:write:*",
        metadata: { title, category, contentHash: result.contentHash, version: result.version },
      });

      return json({ ok: true, ...result });
    }

    // GET /api/docs/:id — get document metadata
    const docGetMatch = path.match(/^\/api\/docs\/([A-Z0-9]+)\/?$/);
    if (docGetMatch && method === "GET") {
      const gate = await governanceGate(request, env, "docs:read:*");
      if (!gate.ok) return gate.response;

      const doc = await getDocument(env, docGetMatch[1]);
      if (!doc) return json({ error: "not found" }, 404);

      await logDocumentAccess(env, {
        documentId: docGetMatch[1],
        accessor: gate.operator.operatorId,
        action: "view",
        ip: request.headers.get("CF-Connecting-IP"),
      });

      await emitReceipt(env, {
        operatorId: gate.operator.operatorId,
        claim: "docs:read",
        subject: docGetMatch[1],
        capability: "docs:read:*",
      });

      return json(doc);
    }

    // GET /api/docs/:id/download — download document file
    const docDownloadMatch = path.match(/^\/api\/docs\/([A-Z0-9]+)\/download\/?$/);
    if (docDownloadMatch && method === "GET") {
      const gate = await governanceGate(request, env, "docs:read:*");
      if (!gate.ok) return gate.response;

      const result = await downloadDocument(env, docDownloadMatch[1]);
      if (!result) return json({ error: "not found" }, 404);

      await logDocumentAccess(env, {
        documentId: docDownloadMatch[1],
        accessor: gate.operator.operatorId,
        action: "download",
        ip: request.headers.get("CF-Connecting-IP"),
      });

      await emitReceipt(env, {
        operatorId: gate.operator.operatorId,
        claim: "docs:download",
        subject: docDownloadMatch[1],
        capability: "docs:read:*",
        metadata: { title: result.doc.title },
      });

      return new Response(result.body, {
        headers: {
          "Content-Type": result.contentType,
          "Content-Disposition": `attachment; filename="${result.doc.title}"`,
          ...corsHeaders(),
        },
      });
    }

    // GET /api/docs/:id/versions — get version history
    const docVersionsMatch = path.match(/^\/api\/docs\/([A-Z0-9]+)\/versions\/?$/);
    if (docVersionsMatch && method === "GET") {
      const gate = await governanceGate(request, env, "docs:read:*");
      if (!gate.ok) return gate.response;

      const versions = await getDocumentVersions(env, docVersionsMatch[1]);
      return json({ versions });
    }

    // PUT /api/docs/:id — update document metadata
    const docUpdateMatch = path.match(/^\/api\/docs\/([A-Z0-9]+)\/?$/);
    if (docUpdateMatch && method === "PUT") {
      const gate = await governanceGate(request, env, "docs:write:*");
      if (!gate.ok) return gate.response;

      const body = await request.json();
      await updateDocument(env, docUpdateMatch[1], body);

      await emitReceipt(env, {
        operatorId: gate.operator.operatorId,
        claim: "docs:update",
        subject: docUpdateMatch[1],
        capability: "docs:write:*",
        metadata: { fields: Object.keys(body) },
      });

      return json({ ok: true });
    }

    // DELETE /api/docs/:id — delete document (admin only)
    const docDeleteMatch = path.match(/^\/api\/docs\/([A-Z0-9]+)\/?$/);
    if (docDeleteMatch && method === "DELETE") {
      const gate = await governanceGate(request, env, "workspace:admin");
      if (!gate.ok) return gate.response;

      const deleted = await deleteDocument(env, docDeleteMatch[1]);
      if (!deleted) return json({ error: "not found" }, 404);

      await emitReceipt(env, {
        operatorId: gate.operator.operatorId,
        claim: "docs:delete",
        subject: docDeleteMatch[1],
        capability: "workspace:admin",
      });

      return json({ ok: true });
    }

    // ── Media API (/api/media/*) ──

    // GET /api/media — list assets
    if (path === "/api/media" && method === "GET") {
      const gate = await governanceGate(request, env, "docs:read:*");
      if (!gate.ok) return gate.response;

      const assetType = url.searchParams.get("type");
      const status = url.searchParams.get("status");
      const tag = url.searchParams.get("tag");
      const limit = parseInt(url.searchParams.get("limit") || "50", 10);
      const offset = parseInt(url.searchParams.get("offset") || "0", 10);

      const assets = await queryAssets(env, { assetType, status, tag, limit, offset });

      await emitReceipt(env, {
        operatorId: gate.operator.operatorId,
        claim: "media:list",
        capability: "docs:read:*",
        metadata: { assetType, status, count: assets.length },
      });

      return json({ count: assets.length, assets });
    }

    // POST /api/media — upload asset
    if (path === "/api/media" && method === "POST") {
      const gate = await governanceGate(request, env, "docs:write:*");
      if (!gate.ok) return gate.response;

      const formData = await request.formData();
      const file = formData.get("file");
      if (!file) return json({ error: "file required" }, 400);

      const title = formData.get("title") || file.name;
      const assetType = formData.get("assetType") || inferAssetType(file.type);
      const tags = formData.get("tags") ? JSON.parse(formData.get("tags")) : [];
      const description = formData.get("description") || "";
      const dimensions = formData.get("dimensions") ? JSON.parse(formData.get("dimensions")) : null;
      const duration = formData.get("duration") ? parseFloat(formData.get("duration")) : null;

      const data = await file.arrayBuffer();
      const result = await uploadAsset(env, {
        title,
        assetType,
        contentType: file.type || "application/octet-stream",
        data,
        uploadedBy: gate.operator.operatorId,
        tags,
        description,
        dimensions,
        duration,
      });

      await emitReceipt(env, {
        operatorId: gate.operator.operatorId,
        claim: "media:upload",
        subject: result.id,
        capability: "docs:write:*",
        metadata: { title, assetType, contentHash: result.contentHash },
      });

      return json({ ok: true, ...result });
    }

    // GET /api/media/:id — get asset metadata
    const mediaGetMatch = path.match(/^\/api\/media\/([A-Z0-9]+)\/?$/);
    if (mediaGetMatch && method === "GET") {
      const gate = await governanceGate(request, env, "docs:read:*");
      if (!gate.ok) return gate.response;

      const asset = await getAsset(env, mediaGetMatch[1]);
      if (!asset) return json({ error: "not found" }, 404);

      return json(asset);
    }

    // POST /api/media/:id/transition — change asset status
    const mediaTransitionMatch = path.match(/^\/api\/media\/([A-Z0-9]+)\/transition\/?$/);
    if (mediaTransitionMatch && method === "POST") {
      // Approve/publish requires admin; submit for review requires write
      const body = await request.json();
      const requiredCap = (body.status === "approved" || body.status === "published")
        ? "workspace:admin"
        : "docs:write:*";

      const gate = await governanceGate(request, env, requiredCap);
      if (!gate.ok) return gate.response;

      const ok = await transitionAsset(env, mediaTransitionMatch[1], body.status, gate.operator.operatorId);
      if (!ok) return json({ error: "invalid transition" }, 400);

      await emitReceipt(env, {
        operatorId: gate.operator.operatorId,
        claim: `media:${body.status}`,
        subject: mediaTransitionMatch[1],
        capability: requiredCap,
        metadata: { newStatus: body.status },
      });

      return json({ ok: true });
    }

    // PUT /api/media/:id — update asset metadata
    const mediaUpdateMatch = path.match(/^\/api\/media\/([A-Z0-9]+)\/?$/);
    if (mediaUpdateMatch && method === "PUT") {
      const gate = await governanceGate(request, env, "docs:write:*");
      if (!gate.ok) return gate.response;

      const body = await request.json();
      await updateAsset(env, mediaUpdateMatch[1], body);

      await emitReceipt(env, {
        operatorId: gate.operator.operatorId,
        claim: "media:update",
        subject: mediaUpdateMatch[1],
        capability: "docs:write:*",
      });

      return json({ ok: true });
    }

    // DELETE /api/media/:id — delete asset (admin only)
    const mediaDeleteMatch = path.match(/^\/api\/media\/([A-Z0-9]+)\/?$/);
    if (mediaDeleteMatch && method === "DELETE") {
      const gate = await governanceGate(request, env, "workspace:admin");
      if (!gate.ok) return gate.response;

      const deleted = await deleteAsset(env, mediaDeleteMatch[1]);
      if (!deleted) return json({ error: "not found" }, 404);

      await emitReceipt(env, {
        operatorId: gate.operator.operatorId,
        claim: "media:delete",
        subject: mediaDeleteMatch[1],
        capability: "workspace:admin",
      });

      return json({ ok: true });
    }

    // ── File Transfer Links API (/api/links/*) ──

    // POST /api/links/download — create a download link
    if (path === "/api/links/download" && method === "POST") {
      const gate = await governanceGate(request, env, "docs:read:*");
      if (!gate.ok) return gate.response;

      const body = await request.json();
      if (!body.r2Key || !body.filename) {
        return json({ error: "r2Key and filename required" }, 400);
      }

      const link = await createDownloadLink(env, {
        r2Key: body.r2Key,
        filename: body.filename,
        contentType: body.contentType || "application/octet-stream",
        sizeBytes: body.sizeBytes || 0,
        createdBy: gate.operator.operatorId,
        documentId: body.documentId || null,
        mediaAssetId: body.mediaAssetId || null,
        expiresInDays: body.expiresInDays,
        maxDownloads: body.maxDownloads,
      });

      await emitReceipt(env, {
        operatorId: gate.operator.operatorId,
        claim: "link:created",
        subject: link.id,
        capability: "docs:read:*",
        metadata: { url: link.url, filename: body.filename, expiresAt: link.expiresAt },
      });

      return json({ ok: true, ...link });
    }

    // GET /api/links/download — list download links
    if (path === "/api/links/download" && method === "GET") {
      const gate = await governanceGate(request, env, "docs:read:*");
      if (!gate.ok) return gate.response;

      const links = await queryDownloadLinks(env, gate.operator.operatorId, {
        includeExpired: url.searchParams.get("includeExpired") === "true",
      });

      return json({ count: links.length, links });
    }

    // DELETE /api/links/download/:id — revoke a download link
    const linkRevokeMatch = path.match(/^\/api\/links\/download\/([a-z0-9]+)\/?$/);
    if (linkRevokeMatch && method === "DELETE") {
      const gate = await governanceGate(request, env, "docs:read:*");
      if (!gate.ok) return gate.response;

      await revokeDownloadLink(env, linkRevokeMatch[1], gate.operator.operatorId);

      await emitReceipt(env, {
        operatorId: gate.operator.operatorId,
        claim: "link:revoked",
        subject: linkRevokeMatch[1],
        capability: "docs:read:*",
      });

      return json({ ok: true });
    }

    // ── Task API (/api/tasks/*) ──

    // GET /api/tasks — list tasks
    if (path === "/api/tasks" && method === "GET") {
      const gate = await governanceGate(request, env, "docs:read:*");
      if (!gate.ok) return gate.response;

      const assignee = url.searchParams.get("assignee");
      const status = url.searchParams.get("status");
      const limit = parseInt(url.searchParams.get("limit") || "50", 10);

      const tasks = await queryTasks(env, { assignee, status, limit });

      return json({ count: tasks.length, tasks });
    }

    // POST /api/tasks/:id/status — update task status
    const taskStatusMatch = path.match(/^\/api\/tasks\/([A-Z0-9]+)\/status\/?$/);
    if (taskStatusMatch && method === "POST") {
      const gate = await governanceGate(request, env, "docs:write:*");
      if (!gate.ok) return gate.response;

      const body = await request.json();
      if (!body.status) return json({ error: "status required" }, 400);

      await updateTaskStatus(env, taskStatusMatch[1], body.status, gate.operator.operatorId);

      await emitReceipt(env, {
        operatorId: gate.operator.operatorId,
        claim: "task:status_change",
        subject: taskStatusMatch[1],
        capability: "docs:write:*",
        metadata: { newStatus: body.status },
      });

      return json({ ok: true });
    }

    // ── Inquiry API (/api/inquiries/*) ──

    // GET /api/inquiries — list inquiries
    if (path === "/api/inquiries" && method === "GET") {
      const gate = await governanceGate(request, env, "docs:read:*");
      if (!gate.ok) return gate.response;

      const assignedTo = url.searchParams.get("assignedTo");
      const status = url.searchParams.get("status");
      const category = url.searchParams.get("category");

      const inquiries = await queryInquiries(env, { assignedTo, status, category });

      return json({ count: inquiries.length, inquiries });
    }

    // ── Google Interop API (/api/google/*) ──

    // GET /api/google/files — list Google Drive files
    if (path === "/api/google/files" && method === "GET") {
      const gate = await governanceGate(request, env, "docs:read:*");
      if (!gate.ok) return gate.response;

      const token = await refreshAccessToken(env, gate.operator.operatorId);
      if (!token) return json({ error: "Google account not connected" }, 401);

      const query = url.searchParams.get("q") || undefined;
      const limit = parseInt(url.searchParams.get("limit") || "50", 10);
      const pageToken = url.searchParams.get("pageToken") || undefined;

      const result = await listDriveFiles(token, { query, limit, pageToken });
      return json(result);
    }

    // POST /api/google/import — import file from Google Drive
    if (path === "/api/google/import" && method === "POST") {
      const gate = await governanceGate(request, env, "docs:write:*");
      if (!gate.ok) return gate.response;

      const body = await request.json();
      if (!body.fileId) return json({ error: "fileId required" }, 400);

      const token = await refreshAccessToken(env, gate.operator.operatorId);
      if (!token) return json({ error: "Google account not connected" }, 401);

      const result = await importFromDrive(env, token, body.fileId, gate.operator.operatorId);

      // Log sync
      const logId = ulid();
      await env.DB.prepare(
        `INSERT INTO google_sync_log (id, operator_id, direction, drive_file_id, document_id, filename, content_hash, status)
         VALUES (?, ?, 'import', ?, ?, ?, ?, ?)`
      )
        .bind(logId, gate.operator.operatorId, body.fileId, result.documentId, result.filename, result.contentHash, "success")
        .run();

      await emitReceipt(env, {
        operatorId: gate.operator.operatorId,
        claim: "google:import",
        subject: result.documentId,
        capability: "docs:write:*",
        metadata: { driveFileId: body.fileId, filename: result.filename },
      });

      return json({ ok: true, ...result });
    }

    // POST /api/google/export — export document to Google Drive
    if (path === "/api/google/export" && method === "POST") {
      const gate = await governanceGate(request, env, "docs:read:*");
      if (!gate.ok) return gate.response;

      const body = await request.json();
      if (!body.documentId) return json({ error: "documentId required" }, 400);

      const token = await refreshAccessToken(env, gate.operator.operatorId);
      if (!token) return json({ error: "Google account not connected" }, 401);

      const result = await exportToDrive(env, token, body.documentId, body.folderId);
      if (!result.ok) return json({ error: result.error }, 404);

      // Log sync
      const logId = ulid();
      await env.DB.prepare(
        `INSERT INTO google_sync_log (id, operator_id, direction, drive_file_id, document_id, filename, status)
         VALUES (?, ?, 'export', ?, ?, ?, ?)`
      )
        .bind(logId, gate.operator.operatorId, result.driveFileId, body.documentId, result.name, "success")
        .run();

      await emitReceipt(env, {
        operatorId: gate.operator.operatorId,
        claim: "google:export",
        subject: body.documentId,
        capability: "docs:read:*",
        metadata: { driveFileId: result.driveFileId, name: result.name },
      });

      return json({ ok: true, ...result });
    }

    // ── File Transfer Links API (/api/links/*) ──

    // POST /api/links/upload — create an upload link
    if (path === "/api/links/upload" && method === "POST") {
      const gate = await governanceGate(request, env, "docs:write:*");
      if (!gate.ok) return gate.response;

      const body = await request.json();
      if (!body.recipientMailbox) {
        return json({ error: "recipientMailbox required" }, 400);
      }

      const link = await createUploadLink(env, {
        recipientMailbox: body.recipientMailbox,
        createdBy: gate.operator.operatorId,
        originalSender: body.originalSender,
        expiresInHours: body.expiresInHours,
      });

      await emitReceipt(env, {
        operatorId: gate.operator.operatorId,
        claim: "upload_link:created",
        subject: link.id,
        capability: "docs:write:*",
        metadata: { url: link.url, recipientMailbox: body.recipientMailbox, expiresAt: link.expiresAt },
      });

      return json({ ok: true, ...link });
    }

    return json({ error: "not found" }, 404);
  } catch (err) {
    console.error("API error:", err.message, err.stack);
    return json({ error: "internal error" }, 500);
  }
}

// ─── Helpers ──────────────────────────────────────────────

function inferAssetType(mimeType) {
  if (!mimeType) return "document";
  if (mimeType.startsWith("image/")) return "image";
  if (mimeType.startsWith("video/")) return "video";
  if (mimeType.startsWith("audio/")) return "audio";
  return "document";
}

// ─── Fetch Handler (static + API) ─────────────────────────

async function handleFetch(request, env) {
  const url = new URL(request.url);

  // Redirect variant domains to canonical
  if (VARIANT_HOSTS.has(url.hostname)) {
    const canonical = new URL(url);
    canonical.hostname = CANONICAL_HOST;
    return Response.redirect(canonical.href, 301);
  }

  const dest = REDIRECTS[url.pathname];
  if (dest) {
    return Response.redirect(new URL(dest, url.origin).href, 301);
  }

  if (url.pathname.startsWith("/api/")) {
    return handleApi(request, env);
  }

  // Public download links — /d/:token (no auth, token IS the credential)
  const dlMatch = url.pathname.match(/^\/d\/([a-z0-9]+)\/?$/);
  if (dlMatch && request.method === "GET") {
    const result = await serveDownloadLink(env, dlMatch[1], {
      ip: request.headers.get("CF-Connecting-IP"),
      userAgent: request.headers.get("User-Agent"),
    });

    if (!result.ok) {
      return new Response(JSON.stringify({ error: result.error }), {
        status: result.status || 404,
        headers: { "Content-Type": "application/json" },
      });
    }

    return new Response(result.body, {
      headers: {
        "Content-Type": result.contentType,
        "Content-Disposition": `attachment; filename="${result.filename}"`,
      },
    });
  }

  return env.ASSETS.fetch(request);
}

// ─── Export ────────────────────────────────────────────────

export default {
  fetch: handleFetch,
  email: handleEmail,
};
