/**
 * Foundation Edge — receipt-intent forwarding client.
 *
 * Forwards receipt-intents from the Cloudflare worker to the operator's
 * `zp-server` for canonical signing and chain-append. Returns the signed
 * receipt JSON to the caller. The worker holds no signing key for
 * receipts — only its envelope key (FOUNDATION_EDGE_SIGNING_KEY) which
 * authenticates the worker as the legitimate sender, separate from
 * receipt authority.
 *
 * Network reachability is via a stable hostname (Cloudflare Tunnel
 * terminating at the operator host); the endpoint per operator is
 * stored in D1.operators.zp_server_endpoint.
 */

import * as ed from "@noble/ed25519";
import { ulid } from "../email/ulid.js";

// ── Canonical JSON ────────────────────────────────────────────────────────────

/**
 * Deterministic JSON serialization. Sorted keys, no whitespace, recursive.
 * The bytes this produces are exactly what the operator's zp-server
 * verifies the envelope signature against.
 */
export function canonicalJSON(value) {
  if (value === null || value === undefined) return "null";
  if (typeof value === "number") {
    return Number.isFinite(value) ? JSON.stringify(value) : "null";
  }
  if (typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return "[" + value.map(canonicalJSON).join(",") + "]";
  }
  if (typeof value === "object") {
    const keys = Object.keys(value).sort();
    return (
      "{" +
      keys
        .map((k) => JSON.stringify(k) + ":" + canonicalJSON(value[k]))
        .join(",") +
      "}"
    );
  }
  return "null";
}

// ── Base64 ────────────────────────────────────────────────────────────────────

function base64Encode(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

function base64Decode(str) {
  const s = atob(str);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

// ── Envelope signing ──────────────────────────────────────────────────────────

/**
 * Sign body bytes with the worker's Ed25519 envelope key.
 * Returns base64-encoded 64-byte signature.
 *
 * @param {string} secretB64 — the FOUNDATION_EDGE_SIGNING_KEY secret
 *   (raw 32-byte seed, base64).
 * @param {Uint8Array} bodyBytes — exact body bytes to sign.
 * @returns {Promise<string>} base64 signature.
 */
async function edSign(secretB64, bodyBytes) {
  const seed = base64Decode(secretB64);
  if (seed.length !== 32) {
    throw new Error(
      `FOUNDATION_EDGE_SIGNING_KEY must decode to 32 bytes; got ${seed.length}`,
    );
  }
  const sig = await ed.signAsync(bodyBytes, seed);
  return base64Encode(sig);
}

// ── Operator endpoint lookup ──────────────────────────────────────────────────

/**
 * Resolve which `zp-server` endpoint serves the given operator. Reads
 * D1.operators.zp_server_endpoint.
 *
 * @returns {Promise<string>} endpoint URL (e.g. https://relay.example.org)
 * @throws if operator unknown or endpoint not configured
 */
async function lookupOperatorEndpoint(env, operatorId) {
  const row = await env.DB.prepare(
    "SELECT zp_server_endpoint FROM operators WHERE id = ? LIMIT 1",
  )
    .bind(operatorId)
    .first();
  if (!row) {
    throw new ForwardError(404, `unknown operator: ${operatorId}`);
  }
  if (!row.zp_server_endpoint) {
    throw new ForwardError(
      503,
      `operator ${operatorId} has no zp_server_endpoint configured`,
    );
  }
  return row.zp_server_endpoint;
}

// ── Errors ────────────────────────────────────────────────────────────────────

export class ForwardError extends Error {
  constructor(status, message, body) {
    super(message);
    this.name = "ForwardError";
    this.status = status;
    this.body = body;
  }
}

// ── Build envelope headers ────────────────────────────────────────────────────

async function envelopeHeaders(env, bodyBytes) {
  if (!env.FOUNDATION_EDGE_SIGNING_KEY) {
    throw new ForwardError(503, "FOUNDATION_EDGE_SIGNING_KEY not configured");
  }
  if (!env.FOUNDATION_EDGE_PUBKEY_ID) {
    throw new ForwardError(503, "FOUNDATION_EDGE_PUBKEY_ID not configured");
  }
  const sig = await edSign(env.FOUNDATION_EDGE_SIGNING_KEY, bodyBytes);
  return {
    "X-Foundation-Worker-Pubkey-Id": env.FOUNDATION_EDGE_PUBKEY_ID,
    "X-Foundation-Worker-Signature": sig,
  };
}

// ── POST forwardReceipt ───────────────────────────────────────────────────────

/**
 * Forward a receipt-intent to the operator's zp-server. Operator signs
 * canonical receipt, appends to chain, returns signed receipt JSON.
 *
 * @param {Object} env — Worker env (DB binding + secrets).
 * @param {string} operatorId — which operator this action is on behalf of.
 * @param {Object} intentInput — partial intent: { claim, subject?,
 *   capability_used?, metadata? }. intent_id and requested_at are filled
 *   here.
 * @returns {Promise<Object>} the signed receipt JSON.
 */
export async function forwardReceipt(env, operatorId, intentInput) {
  const endpoint = await lookupOperatorEndpoint(env, operatorId);

  const intent = {
    intent_id: `intn-${ulid()}`,
    operator_id: operatorId,
    claim: intentInput.claim,
    subject: intentInput.subject ?? null,
    capability_used: intentInput.capability_used ?? null,
    metadata: intentInput.metadata ?? null,
    requested_at: new Date().toISOString(),
  };

  const bodyBytes = new TextEncoder().encode(canonicalJSON(intent));
  const headers = await envelopeHeaders(env, bodyBytes);
  headers["Content-Type"] = "application/json";

  let res;
  try {
    res = await fetch(`${endpoint}/v1/foundation-receipts`, {
      method: "POST",
      headers,
      body: bodyBytes,
      signal: AbortSignal.timeout(2000),
    });
  } catch (e) {
    // Network error or timeout — operator unreachable.
    const status = e?.name === "TimeoutError" ? 504 : 503;
    throw new ForwardError(status, `forward fetch failed: ${e?.message ?? e}`);
  }

  if (!res.ok) {
    let body = null;
    try {
      body = await res.json();
    } catch {
      // Fall through with null body.
    }
    // Map operator response shape to worker-side response status.
    // Operator 5xx → bubble up; operator 4xx → worker 502 (worker built
    // a bad intent or auth failed); operator 503 → 503 (offline pass-through).
    let status = 502;
    if (res.status === 503) status = 503;
    else if (res.status >= 500) status = 502;
    throw new ForwardError(status, `operator returned ${res.status}`, body);
  }

  return await res.json();
}

// ── GET fetchReceipts ─────────────────────────────────────────────────────────

/**
 * Query the operator's chain for foundation-relayed receipts.
 *
 * @param {Object} env
 * @param {string} operatorId
 * @param {Object} query — { limit?, after?, before?, claim? }
 * @returns {Promise<{receipts: Array, count: number}>}
 */
export async function fetchReceipts(env, operatorId, query = {}) {
  const endpoint = await lookupOperatorEndpoint(env, operatorId);

  const params = new URLSearchParams();
  params.set("operator_id", operatorId);
  if (query.limit) params.set("limit", String(query.limit));
  if (query.after) params.set("after", query.after);
  if (query.before) params.set("before", query.before);
  if (query.claim) params.set("claim", query.claim);

  // The envelope signature covers the (empty) request body. Worker and
  // operator agree on signing an empty Uint8Array; both sides do the
  // same thing.
  const bodyBytes = new Uint8Array(0);
  const headers = await envelopeHeaders(env, bodyBytes);

  let res;
  try {
    res = await fetch(
      `${endpoint}/v1/foundation-receipts?${params.toString()}`,
      {
        method: "GET",
        headers,
        signal: AbortSignal.timeout(2000),
      },
    );
  } catch (e) {
    const status = e?.name === "TimeoutError" ? 504 : 503;
    throw new ForwardError(status, `fetch failed: ${e?.message ?? e}`);
  }

  if (!res.ok) {
    let body = null;
    try {
      body = await res.json();
    } catch {
      // Fall through.
    }
    let status = 502;
    if (res.status === 503) status = 503;
    else if (res.status >= 500) status = 502;
    throw new ForwardError(status, `operator returned ${res.status}`, body);
  }

  return await res.json();
}
