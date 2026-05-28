/**
 * Receipt emission for authenticated workspace actions.
 *
 * Every successful API call through the governance gate emits a
 * signed receipt-intent to the operator's zp-server, which signs the
 * canonical receipt and appends it to the operator's audit chain.
 * The worker holds no chain and no receipt-signing key — its envelope
 * key (FOUNDATION_EDGE_SIGNING_KEY) only authenticates this worker as
 * the legitimate sender.
 *
 * The (env, opts) => receiptId caller API is preserved so existing
 * call sites in worker.js don't need to change.
 */

import { forwardReceipt, ForwardError } from "./forward.js";

/**
 * Emit a governance receipt for an authenticated action.
 *
 * @param {Object} env        - Worker environment (DB binding + secrets)
 * @param {Object} opts
 * @param {string} opts.operatorId   - Who performed the action
 * @param {string} opts.claim        - What happened (e.g., "mail:read")
 * @param {string} [opts.subject]    - What it was performed on
 * @param {string} [opts.capability] - Which capability authorized it
 * @param {Object} [opts.metadata]   - Additional context
 * @returns {Promise<string>} the signed receipt id, or empty string on
 *   forward failure (caller continues; emission is best-effort from the
 *   caller's perspective, but the worker should surface forward errors
 *   via the standard HTTP path when receipts are essential).
 */
export async function emitReceipt(env, opts) {
  try {
    const signedReceipt = await forwardReceipt(env, opts.operatorId, {
      claim: opts.claim,
      subject: opts.subject || null,
      capability_used: opts.capability || null,
      metadata: opts.metadata ?? null,
    });

    console.log(
      JSON.stringify({
        event: "receipt:emitted",
        receiptId: signedReceipt.id,
        operatorId: opts.operatorId,
        claim: opts.claim,
        subject: opts.subject,
      }),
    );

    return signedReceipt.id;
  } catch (e) {
    // Forward failed: operator offline, envelope auth misconfigured, etc.
    // Log loudly — this is a signing-is-gravity gap (P1).
    console.error(
      JSON.stringify({
        event: "receipt:forward_failed",
        operatorId: opts.operatorId,
        claim: opts.claim,
        status: e instanceof ForwardError ? e.status : 500,
        reason: e?.message ?? String(e),
      }),
    );
    // Re-throw so the calling route can map to an honest HTTP status.
    // Per the architecture: if there is no canonical place to record a
    // receipt, the action does not happen.
    throw e;
  }
}

/**
 * Emit a receipt for a failed authentication attempt.
 * Security-relevant events; same forwarding path as success.
 */
export async function emitAuthFailure(env, opts) {
  try {
    const signedReceipt = await forwardReceipt(
      env,
      opts.operatorId || "unknown",
      {
        claim: "auth:denied",
        subject: opts.path || "",
        capability_used: null,
        metadata: {
          reason: opts.reason,
          ip: opts.ip,
          method: opts.method,
        },
      },
    );

    console.log(
      JSON.stringify({
        event: "receipt:auth_denied",
        receiptId: signedReceipt.id,
        reason: opts.reason,
        path: opts.path,
      }),
    );

    return signedReceipt.id;
  } catch (e) {
    // Auth-failure receipts that fail to forward are doubly bad: the
    // worker can't tell the operator someone tried to do something
    // they shouldn't have. Log and surface; caller decides whether to
    // still reject the original request (it usually should).
    console.error(
      JSON.stringify({
        event: "receipt:auth_denied_forward_failed",
        operatorId: opts.operatorId,
        reason: opts.reason,
        forward_status: e instanceof ForwardError ? e.status : 500,
        forward_reason: e?.message ?? String(e),
      }),
    );
    // Don't re-throw on auth-failure emission — the underlying auth
    // failure response should still go to the caller. The operator
    // learns about the gap from the error log.
    return "";
  }
}
