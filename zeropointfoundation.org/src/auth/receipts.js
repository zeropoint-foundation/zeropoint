/**
 * Receipt emission for authenticated workspace actions.
 *
 * Every receipt-emitting action is forwarded as a signed intent to the
 * relevant operator's zp-server, which signs the canonical receipt with
 * the operator's Genesis-derived audit signer and appends it to the
 * operator's audit chain. The foundation worker holds no chain and no
 * receipt-signing key — only its envelope key (FOUNDATION_EDGE_SIGNING_KEY)
 * which authenticates this worker as the legitimate sender, distinct from
 * receipt authority.
 *
 * The (env, opts) => Promise<receiptId> caller API is preserved so the
 * 18+ call sites in worker.js don't need to change.
 *
 * See docs/handoffs/foundation-worker-chain-relocation-2026-06.md for the
 * architectural rationale: chains live with their sovereign; edge-stored
 * chains violate P3.
 */

import { forwardReceipt, ForwardError } from "./forward.js";

/**
 * Emit a governance receipt for an authenticated action.
 *
 * Forwards an intent to the operator's zp-server, which signs the
 * canonical receipt and appends to the operator's audit chain. Returns
 * the signed receipt's id on success.
 *
 * If the forward fails (operator unreachable, envelope auth rejected,
 * etc.) the error propagates to the caller — honest failure, no
 * fabrication. Per the architecture: if there is no canonical place to
 * record a receipt, the action does not happen.
 *
 * @param {Object} env        - Worker environment (DB binding + secrets)
 * @param {Object} opts
 * @param {string} opts.operatorId   - Who performed the action
 * @param {string} opts.claim        - What happened (e.g., "mail:read")
 * @param {string} [opts.subject]    - What it was performed on
 * @param {string} [opts.capability] - Which capability authorized it
 * @param {Object} [opts.metadata]   - Additional context
 * @returns {Promise<string>} the signed receipt id
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
    console.error(
      JSON.stringify({
        event: "receipt:forward_failed",
        operatorId: opts.operatorId,
        claim: opts.claim,
        status: e instanceof ForwardError ? e.status : 500,
        reason: e?.message ?? String(e),
      }),
    );
    // Re-throw so the calling route maps to an honest HTTP status.
    // The action did not get a canonical record; the caller should
    // surface that to the requester.
    throw e;
  }
}

/**
 * Emit a receipt for a failed authentication attempt.
 *
 * Forwards the same intent shape as emitReceipt with claim="auth:denied".
 * Auth-failure receipts that fail to forward are LOGGED but do NOT
 * re-throw — the underlying auth-failure response should still reach the
 * caller. The operator learns about the forward gap from the error log.
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
    // failure response should still go to the caller.
    return "";
  }
}
