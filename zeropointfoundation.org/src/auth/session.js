/**
 * Session-based authentication for the browser workspace client.
 *
 * Flow:
 *   1. POST /api/auth/session { operatorId } → returns { token, expiresAt }
 *   2. Client sends Authorization: Bearer <token> on subsequent requests
 *   3. Worker verifies HMAC-signed token and extracts operator context
 *
 * Token format: base64url(JSON.stringify({ sub, iat, exp })) + "." + base64url(HMAC-SHA256)
 *
 * This is a temporary pre-auth mechanism. Production will use Ed25519
 * challenge-response from the client's WebCrypto-generated keypair.
 */

const SESSION_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

/** Name of the session cookie. Read by the worker (this file) and by
 *  IronClaw's gateway middleware downstream — must stay in sync. */
export const SESSION_COOKIE_NAME = "zp_session";

/**
 * Build a Set-Cookie value carrying the session token.
 *
 * Production: scopes to `.FOUNDATION_DOMAIN` so the cookie travels to
 * any subdomain (notably `app.zeropointfoundation.org` for the wizard
 * handoff). HttpOnly + Secure + SameSite=Lax.
 *
 * Localhost dev: host-scoped (no Domain attribute), no Secure (HTTP
 * is fine), so the cookie still works during local pilot runs.
 *
 * @param {Request} request - The incoming HTTP request
 * @param {Object}  env     - Worker env (uses FOUNDATION_DOMAIN)
 * @param {string}  token   - The session token to embed
 * @returns {string} Set-Cookie header value
 */
export function buildSessionCookie(request, env, token) {
  const url = new URL(request.url);
  const isLocalhost =
    url.hostname === "localhost" ||
    url.hostname === "127.0.0.1" ||
    url.hostname.endsWith(".localhost");

  const maxAge = Math.floor(SESSION_TTL_MS / 1000); // seconds

  let cookie = `${SESSION_COOKIE_NAME}=${token}; Path=/; Max-Age=${maxAge}; HttpOnly; SameSite=None; Secure`;

  if (!isLocalhost) {
    if (env.FOUNDATION_DOMAIN) {
      cookie += `; Domain=.${env.FOUNDATION_DOMAIN}`;
    }
  }

  return cookie;
}

/**
 * Build a Set-Cookie value that clears the session cookie (logout).
 * Mirrors the scope rules of buildSessionCookie so the right cookie
 * gets cleared.
 */
export function clearSessionCookie(request, env) {
  const url = new URL(request.url);
  const isLocalhost =
    url.hostname === "localhost" ||
    url.hostname === "127.0.0.1" ||
    url.hostname.endsWith(".localhost");

  let cookie = `${SESSION_COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; SameSite=None; Secure`;
  if (!isLocalhost) {
    if (env.FOUNDATION_DOMAIN) {
      cookie += `; Domain=.${env.FOUNDATION_DOMAIN}`;
    }
  }
  return cookie;
}

/**
 * Create a signed session token for an operator.
 *
 * @param {Object} env        - Worker env (SESSION_SIGNING_KEY, DB)
 * @param {string} operatorId - Operator ID to create session for
 * @returns {Promise<{ token: string, expiresAt: string } | null>}
 */
export async function createSession(env, operatorId) {
  // Verify operator exists and is active
  const operator = await env.DB.prepare(
    `SELECT id, name, capabilities, active FROM operators WHERE id = ?`
  )
    .bind(operatorId)
    .first();

  if (!operator || !operator.active) {
    return null;
  }

  const now = Date.now();
  const exp = now + SESSION_TTL_MS;

  const payload = {
    sub: operatorId,
    name: operator.name,
    cap: operator.capabilities,
    iat: now,
    exp,
  };

  const payloadB64 = base64url(JSON.stringify(payload));
  const sig = await hmacSign(env.SESSION_SIGNING_KEY, payloadB64);
  const token = `${payloadB64}.${sig}`;

  return {
    token,
    expiresAt: new Date(exp).toISOString(),
    operator: {
      id: operator.id,
      name: operator.name,
    },
  };
}

/**
 * Verify a session token and return the operator context.
 *
 * @param {Object} env    - Worker env (SESSION_SIGNING_KEY)
 * @param {string} token  - Session token from Authorization header
 * @returns {Promise<{ ok: boolean, operatorId?: string, operatorName?: string, capabilities?: string[], error?: string, status?: number }>}
 */
export async function verifySession(env, token) {
  const dotIdx = token.indexOf(".");
  if (dotIdx < 0) {
    return { ok: false, error: "Malformed session token", status: 401 };
  }

  const payloadB64 = token.slice(0, dotIdx);
  const sig = token.slice(dotIdx + 1);

  // Verify HMAC
  const expectedSig = await hmacSign(env.SESSION_SIGNING_KEY, payloadB64);
  if (sig !== expectedSig) {
    return { ok: false, error: "Invalid session signature", status: 401 };
  }

  // Decode payload
  let payload;
  try {
    payload = JSON.parse(base64urlDecode(payloadB64));
  } catch {
    return { ok: false, error: "Invalid session payload", status: 401 };
  }

  // Check expiry
  if (Date.now() > payload.exp) {
    return { ok: false, error: "Session expired", status: 401 };
  }

  const capabilities = typeof payload.cap === "string"
    ? JSON.parse(payload.cap)
    : (payload.cap || []);

  return {
    ok: true,
    operatorId: payload.sub,
    operatorName: payload.name,
    capabilities,
  };
}

// ── Helpers ─────────────────────────────────────────────────────

async function hmacSign(secret, data) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  return base64url(new Uint8Array(sig));
}

function base64url(input) {
  let str;
  if (typeof input === "string") {
    str = btoa(input);
  } else {
    // Uint8Array
    str = btoa(String.fromCharCode(...input));
  }
  return str.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64urlDecode(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  return atob(str);
}
