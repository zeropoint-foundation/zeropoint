/**
 * Foundation chain management: keypair caching, chain-tip reads, genesis write.
 *
 * All state that must survive across receipt emissions within one isolate
 * lifetime is cached here at module scope. Cold starts re-derive everything.
 */

import { ulid } from "../email/ulid.js";
import { canonicalString, canonicalHashHex, GENESIS_HASH } from "./canonical.js";

// ── Module-level caches (per-isolate lifetime) ──────────────────────────────

let cachedKeyPair = null; // { priv: CryptoKey, pubKid: string }
let cachedChainId = null; // "foundation:<deploy_id>"

// ── Keypair ──────────────────────────────────────────────────────────────────

/**
 * Load and cache the foundation Ed25519 keypair from env.
 * Requires FOUNDATION_SIGNING_KEY_PKCS8_B64 to be set as a Worker secret.
 */
export async function getFoundationKeypair(env) {
  if (cachedKeyPair) return cachedKeyPair;
  const pkcs8 = _base64ToArrayBuffer(env.FOUNDATION_SIGNING_KEY_PKCS8_B64);
  const priv = await crypto.subtle.importKey(
    "pkcs8",
    pkcs8,
    { name: "Ed25519" },
    false,
    ["sign"]
  );
  cachedKeyPair = { priv, pubKid: "foundation-root-v1" };
  return cachedKeyPair;
}

// ── Chain ID ─────────────────────────────────────────────────────────────────

/**
 * Return the chain_id string ("foundation:<deploy_id>"), reading it from the
 * genesis entry on first call and caching thereafter. Returns null if the
 * chain table is empty (genesis not yet written).
 */
export async function getChainId(env) {
  if (cachedChainId) return cachedChainId;
  const row = await env.DB.prepare(
    "SELECT metadata FROM chain_entries WHERE sequence = 0"
  ).first();
  if (!row) return null;
  const meta = JSON.parse(row.metadata);
  cachedChainId = `foundation:${meta.deploy_id}`;
  return cachedChainId;
}

// ── Chain tip ────────────────────────────────────────────────────────────────

/**
 * Read the current chain tip.
 * @returns {{ empty: boolean, sequence: number, entry_hash: string|null }}
 */
export async function readChainTip(env) {
  const row = await env.DB.prepare(
    "SELECT sequence, entry_hash FROM chain_entries ORDER BY sequence DESC LIMIT 1"
  ).first();
  if (!row) return { empty: true, sequence: -1, entry_hash: null };
  return { empty: false, sequence: row.sequence, entry_hash: row.entry_hash };
}

// ── Genesis ───────────────────────────────────────────────────────────────────

/**
 * Write the genesis entry (sequence = 0) for a fresh chain.
 * The genesis receipt is self-describing: it embeds deploy_id, pubkey_hex,
 * and schema_version so verifiers are fully bootstrapped from the chain alone.
 *
 * Returns the new chain_id string.
 */
export async function writeGenesis(env, priv, pubKid) {
  const deployId = ulid();
  const chainId = `foundation:${deployId}`;
  const pubkeyHex = env.FOUNDATION_SIGNING_KEY_PUB_HEX || "";
  const id = ulid();
  const now = new Date().toISOString();

  const metadata = {
    deploy_id: deployId,
    pubkey_hex: pubkeyHex,
    schema_version: "foundation-canonical-v1",
  };

  const preimage = {
    capability_used: "",
    chain: {
      chain_id: chainId,
      prev_hash: GENESIS_HASH,
      sequence: 0,
    },
    claim: "foundation:chain:genesis",
    created_at: now,
    id,
    metadata,
    operator_id: "",
    subject: "",
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

  await env.DB.prepare(
    `INSERT INTO chain_entries
       (id, operator_id, claim, subject, capability_used, metadata,
        created_at, sequence, prev_hash, entry_hash, signatures)
     VALUES (?,?,?,?,?,?,?,?,?,?,?)`
  )
    .bind(
      id,
      "",
      "foundation:chain:genesis",
      "",
      "",
      JSON.stringify(metadata),
      now,
      0,
      GENESIS_HASH,
      entryHash,
      JSON.stringify(signatures)
    )
    .run();

  cachedChainId = chainId;
  return chainId;
}

// ── Utilities ────────────────────────────────────────────────────────────────

/**
 * Return true if the D1 error is a UNIQUE constraint violation.
 * Used by emitReceipt's retry loop.
 */
export function isUniqueConstraintViolation(e) {
  const msg = (e?.message || "").toLowerCase();
  return msg.includes("unique") || msg.includes("constraint");
}

/**
 * Base64-encode a Uint8Array (standard alphabet, padded).
 */
export function base64Encode(bytes) {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

function _base64ToArrayBuffer(b64) {
  const binary = atob(b64);
  const buf = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) buf[i] = binary.charCodeAt(i);
  return buf.buffer;
}
