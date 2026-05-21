/**
 * foundation-canonical-v1: deterministic JSON serialization for receipt
 * preimages and chain entry hashes.
 *
 * Mirrors crates/zp-receipt/src/canonical.rs (ZP-canonical-v1) for the fields
 * enumerated in the preimage spec. A conformance test fixture lives at
 * crates/zp-verify/tests/foundation-canonical-fixtures.json; both this
 * implementation and the Rust verifier must hash to the same bytes for every
 * fixture row.
 *
 * Rules (foundation-canonical-v1):
 *   1. Object keys at every depth sorted in UTF-16 code-unit order (Object.keys().sort()).
 *   2. No whitespace between tokens (JSON.stringify with no second arg).
 *   3. No trailing newline.
 *   4. UTF-8 encoding of the JSON string.
 *   5. Numbers are integers — no floats in receipt fields.
 *   6. metadata is the parsed JSON object, not the wire string.
 *   7. Exactly the fields named in the preimage spec — no extras.
 */

import { blake3 } from "@noble/hashes/blake3";

/** blake3(b"") — sentinel prev_hash for every chain's genesis entry. */
export const GENESIS_HASH =
  "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";

/**
 * Serialize an object to canonical JSON (deep key-sorted, no whitespace).
 * @param {unknown} obj
 * @returns {string}
 */
export function canonicalString(obj) {
  return JSON.stringify(sortDeep(obj));
}

/**
 * Encode an object as canonical UTF-8 bytes.
 * @param {unknown} obj
 * @returns {Uint8Array}
 */
export function canonicalBytes(obj) {
  return new TextEncoder().encode(canonicalString(obj));
}

/**
 * BLAKE3 hash of the canonical bytes, returned as a hex string.
 * @param {unknown} obj
 * @returns {string} 64-character hex string
 */
export function canonicalHashHex(obj) {
  return bytesToHex(blake3(canonicalBytes(obj)));
}

// ── Internal helpers ────────────────────────────────────────────────────────

function sortDeep(v) {
  if (v === null || typeof v !== "object") return v;
  if (Array.isArray(v)) return v.map(sortDeep);
  const out = {};
  for (const k of Object.keys(v).sort()) {
    out[k] = sortDeep(v[k]);
  }
  return out;
}

function bytesToHex(b) {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}
