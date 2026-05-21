/**
 * Receipt emission — foundation-canonical-v1.
 *
 * Every write goes through emitReceipt, which appends a signed, hash-linked
 * entry to `chain_entries`. If FOUNDATION_SIGNING_KEY_PKCS8_B64 is not set
 * (e.g., during staged rollout), the function falls back to the legacy
 * `receipts` table so no call site breaks.
 *
 * The retry loop handles the storage-layer fork guard: the UNIQUE INDEX on
 * prev_hash causes a constraint violation if two concurrent invocations read
 * the same tip and both attempt to insert. Up to 4 retries are attempted;
 * in practice CF Workers see at most one writer per isolate.
 */

import { ulid } from "../email/ulid.js";
import { canonicalString, canonicalHashHex } from "../chain/canonical.js";
import {
  getFoundationKeypair,
  getChainId,
  readChainTip,
  writeGenesis,
  isUniqueConstraintViolation,
  base64Encode,
} from "../chain/chain.js";

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Emit a governance receipt for an authenticated action.
 *
 * @param {Object} env        - Worker environment (DB binding)
 * @param {Object} opts
 * @param {string} opts.operatorId   - Who performed the action
 * @param {string} opts.claim        - What happened (e.g., "mail:read")
 * @param {string} [opts.subject]    - What it was performed on
 * @param {string} [opts.capability] - Which capability authorized it
 * @param {Object} [opts.metadata]   - Additional context
 * @returns {Promise<string>} The ULID receipt id
 */
export async function emitReceipt(env, opts) {
  if (!env.FOUNDATION_SIGNING_KEY_PKCS8_B64) {
    return _legacyEmitReceipt(env, opts);
  }
  return _signedEmitReceipt(env, opts);
}

/**
 * Emit a receipt for a failed authentication attempt.
 * Thin wrapper around emitReceipt — same chain, same signing.
 */
export async function emitAuthFailure(env, opts) {
  return emitReceipt(env, {
    operatorId: opts.operatorId || "unknown",
    claim: "auth:denied",
    subject: opts.path || "",
    capability: "",
    metadata: {
      reason: opts.reason,
      ip: opts.ip,
      method: opts.method,
    },
  });
}

// ── Signed path (foundation-canonical-v1) ────────────────────────────────────

async function _signedEmitReceipt(env, opts) {
  const { priv, pubKid } = await getFoundationKeypair(env);
  const id = ulid();
  const now = new Date().toISOString();

  for (let attempt = 0; attempt < 4; attempt++) {
    let tip = await readChainTip(env);
    let sequence, prevHash;

    if (tip.empty) {
      await writeGenesis(env, priv, pubKid);
      tip = await readChainTip(env);
      sequence = 1;
      prevHash = tip.entry_hash;
    } else {
      sequence = tip.sequence + 1;
      prevHash = tip.entry_hash;
    }

    const chainId = await getChainId(env);

    const preimage = {
      capability_used: opts.capability || "",
      chain: { chain_id: chainId, prev_hash: prevHash, sequence },
      claim: opts.claim,
      created_at: now,
      id,
      metadata: opts.metadata || {},
      operator_id: opts.operatorId,
      subject: opts.subject || "",
    };

    const entryHash = canonicalHashHex(preimage);
    const rawSig = await crypto.subtle.sign(
      "Ed25519",
      priv,
      new TextEncoder().encode(canonicalString(preimage))
    );
    const signatures = [
      { alg: "Ed25519", kid: pubKid, value: base64Encode(new Uint8Array(rawSig)) },
    ];

    try {
      await env.DB.prepare(
        `INSERT INTO chain_entries
           (id, operator_id, claim, subject, capability_used, metadata,
            created_at, sequence, prev_hash, entry_hash, signatures)
         VALUES (?,?,?,?,?,?,?,?,?,?,?)`
      )
        .bind(
          id,
          opts.operatorId,
          opts.claim,
          opts.subject || "",
          opts.capability || "",
          JSON.stringify(opts.metadata || {}),
          now,
          sequence,
          prevHash,
          entryHash,
          JSON.stringify(signatures)
        )
        .run();

      console.log(
        JSON.stringify({
          event: "receipt:emitted",
          receiptId: id,
          operatorId: opts.operatorId,
          claim: opts.claim,
          subject: opts.subject,
          sequence,
        })
      );

      return id;
    } catch (e) {
      if (isUniqueConstraintViolation(e)) continue;
      throw e;
    }
  }

  throw new Error("emitReceipt: chain contention, retries exhausted");
}

// ── Legacy fallback (no signing key configured) ───────────────────────────────

async function _legacyEmitReceipt(env, opts) {
  const id = ulid();
  const now = new Date().toISOString();

  await env.DB.prepare(
    `INSERT INTO receipts
       (id, operator_id, claim, subject, capability_used, metadata, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
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
      legacy: true,
    })
  );

  return id;
}
