/**
 * Receipt emission for authenticated workspace actions.
 *
 * Every successful API call through the governance gate
 * emits a structured receipt to D1. This creates a complete
 * audit trail: who did what, when, with what authority.
 */

import { ulid } from "../email/ulid.js";

/**
 * Emit a governance receipt for an authenticated action.
 *
 * @param {Object} env        - Worker environment (DB binding)
 * @param {Object} opts
 * @param {string} opts.operatorId   - Who performed the action
 * @param {string} opts.claim        - What happened (e.g., "mail:read")
 * @param {string} opts.subject      - What it was performed on
 * @param {string} opts.capability   - Which capability authorized it
 * @param {Object} [opts.metadata]   - Additional context
 */
export async function emitReceipt(env, opts) {
  const id = ulid();
  const now = new Date().toISOString();

  await env.DB.prepare(
    `INSERT INTO receipts (
      id, operator_id, claim, subject,
      capability_used, metadata, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(
      id,
      opts.operatorId,
      opts.claim,
      opts.subject || "",
      opts.capability || "",
      opts.metadata ? JSON.stringify(opts.metadata) : null,
      now
    )
    .run();

  console.log(
    JSON.stringify({
      event: "receipt:emitted",
      receiptId: id,
      operatorId: opts.operatorId,
      claim: opts.claim,
      subject: opts.subject,
    })
  );

  return id;
}

/**
 * Emit a receipt for a failed authentication attempt.
 * These are always logged — they're security-relevant events.
 */
export async function emitAuthFailure(env, opts) {
  const id = ulid();
  const now = new Date().toISOString();

  await env.DB.prepare(
    `INSERT INTO receipts (
      id, operator_id, claim, subject,
      capability_used, metadata, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(
      id,
      opts.operatorId || "unknown",
      "auth:denied",
      opts.path || "",
      "",
      JSON.stringify({
        reason: opts.reason,
        ip: opts.ip,
        method: opts.method,
      }),
      now
    )
    .run();

  console.log(
    JSON.stringify({
      event: "receipt:auth_denied",
      receiptId: id,
      reason: opts.reason,
      path: opts.path,
    })
  );

  return id;
}
