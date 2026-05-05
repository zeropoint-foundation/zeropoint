/**
 * ZeroPoint operator authentication for Cloudflare Workers.
 *
 * Every API request is signed with the operator's Ed25519 private key.
 * The worker verifies against known public keys stored in D1.
 *
 * Request signing scheme:
 *   Authorization: ZP <operator_id>:<timestamp_ms>:<signature_hex>
 *
 * Signature covers (canonical string):
 *   METHOD\nPATH\nTIMESTAMP\nBODY_HASH
 *
 * Where BODY_HASH = hex(SHA-256(body)) or "e3b0c44..." (empty hash) for GET.
 *
 * Replay protection: timestamp must be within TIMESTAMP_WINDOW_MS.
 */

/** Maximum age of a signed request (5 minutes) */
const TIMESTAMP_WINDOW_MS = 5 * 60 * 1000;

/** SHA-256 of empty string — used for GET requests */
const EMPTY_HASH =
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/**
 * Verify a signed request and return the authenticated operator.
 *
 * @param {Request} request   - The incoming request
 * @param {Object} env        - Worker environment (DB binding)
 * @returns {Promise<AuthResult>}
 *
 * @typedef {Object} AuthResult
 * @property {boolean} ok
 * @property {string} [operatorId]    - Operator ID if authenticated
 * @property {string} [operatorName]  - Human-readable name
 * @property {string[]} [capabilities] - Granted capabilities
 * @property {string} [error]         - Error message if failed
 * @property {number} [status]        - HTTP status code for errors
 */
export async function verifyRequest(request, env) {
  const authHeader = request.headers.get("Authorization");
  if (!authHeader) {
    return { ok: false, error: "Missing Authorization header", status: 401 };
  }

  if (!authHeader.startsWith("ZP ")) {
    return { ok: false, error: "Invalid auth scheme (expected ZP)", status: 401 };
  }

  const parts = authHeader.slice(3).split(":");
  if (parts.length !== 3) {
    return {
      ok: false,
      error: "Malformed auth header (expected id:timestamp:signature)",
      status: 401,
    };
  }

  const [operatorId, timestampStr, signatureHex] = parts;
  const timestamp = parseInt(timestampStr, 10);

  // Replay protection
  const now = Date.now();
  if (Math.abs(now - timestamp) > TIMESTAMP_WINDOW_MS) {
    return {
      ok: false,
      error: "Request timestamp outside window",
      status: 401,
    };
  }

  // Look up operator
  const operator = await env.DB.prepare(
    `SELECT id, name, public_key_hex, capabilities, active
     FROM operators WHERE id = ?`
  )
    .bind(operatorId)
    .first();

  if (!operator) {
    return { ok: false, error: "Unknown operator", status: 401 };
  }

  if (!operator.active) {
    return { ok: false, error: "Operator deactivated", status: 403 };
  }

  // Build canonical string
  const url = new URL(request.url);
  const method = request.method;
  const path = url.pathname + url.search;

  let bodyHash = EMPTY_HASH;
  if (method !== "GET" && method !== "HEAD") {
    const body = await request.clone().arrayBuffer();
    bodyHash = await sha256Hex(new Uint8Array(body));
  }

  const canonical = `${method}\n${path}\n${timestampStr}\n${bodyHash}`;

  // Verify Ed25519 signature
  const valid = await verifyEd25519(
    operator.public_key_hex,
    signatureHex,
    canonical
  );

  if (!valid) {
    return { ok: false, error: "Invalid signature", status: 401 };
  }

  // Parse capabilities
  const capabilities = JSON.parse(operator.capabilities || "[]");

  return {
    ok: true,
    operatorId: operator.id,
    operatorName: operator.name,
    capabilities,
  };
}

/**
 * Verify an Ed25519 signature using Web Crypto API.
 *
 * @param {string} publicKeyHex  - 32-byte public key as hex
 * @param {string} signatureHex  - 64-byte signature as hex
 * @param {string} message       - Message that was signed
 * @returns {Promise<boolean>}
 */
async function verifyEd25519(publicKeyHex, signatureHex, message) {
  try {
    const publicKeyBytes = hexToBytes(publicKeyHex);
    const signatureBytes = hexToBytes(signatureHex);
    const messageBytes = new TextEncoder().encode(message);

    // Import the public key
    const key = await crypto.subtle.importKey(
      "raw",
      publicKeyBytes,
      { name: "Ed25519" },
      false,
      ["verify"]
    );

    // Verify the signature
    return await crypto.subtle.verify("Ed25519", key, signatureBytes, messageBytes);
  } catch (err) {
    console.error("Ed25519 verification error:", err.message);
    return false;
  }
}

/**
 * SHA-256 hash as hex string.
 */
async function sha256Hex(data) {
  const hash = await crypto.subtle.digest("SHA-256", data);
  return bytesToHex(new Uint8Array(hash));
}

/**
 * Convert hex string to Uint8Array.
 */
function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Convert Uint8Array to hex string.
 */
function bytesToHex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}
