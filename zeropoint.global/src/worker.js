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
    if (path === "/api/receipts" && method === "GET") {
      const gate = await governanceGate(request, env, "workspace:admin");
      if (!gate.ok) return gate.response;

      const limit = parseInt(url.searchParams.get("limit") || "100", 10);
      const { results } = await env.DB.prepare(
        `SELECT * FROM receipts ORDER BY created_at DESC LIMIT ?`
      )
        .bind(limit)
        .all();

      return json({ count: results.length, receipts: results });
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
