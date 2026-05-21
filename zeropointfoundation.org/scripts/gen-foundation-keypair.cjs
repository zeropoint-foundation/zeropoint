#!/usr/bin/env node
/**
 * Generate the foundation Ed25519 signing keypair.
 *
 * Usage:
 *   node scripts/gen-foundation-keypair.js
 *
 * Outputs two lines:
 *   FOUNDATION_SIGNING_KEY_PKCS8_B64=<base64>   → paste into: wrangler secret put FOUNDATION_SIGNING_KEY_PKCS8_B64
 *   FOUNDATION_SIGNING_KEY_PUB_HEX=<hex>         → paste into wrangler.toml [vars]
 *
 * Run once per chain lifetime. Rotation requires a new genesis (new chain_id).
 */

const { webcrypto } = require("crypto");

(async () => {
  const kp = await webcrypto.subtle.generateKey(
    { name: "Ed25519" },
    true,
    ["sign", "verify"]
  );

  const [privPkcs8, pubRaw] = await Promise.all([
    webcrypto.subtle.exportKey("pkcs8", kp.privateKey),
    webcrypto.subtle.exportKey("raw", kp.publicKey),
  ]);

  const privB64 = Buffer.from(privPkcs8).toString("base64");
  const pubHex = Buffer.from(pubRaw).toString("hex");

  console.log();
  console.log("── Foundation signing keypair ──────────────────────────────");
  console.log();
  console.log("1. Store the private key as a Worker secret:");
  console.log("   wrangler secret put FOUNDATION_SIGNING_KEY_PKCS8_B64");
  console.log("   (paste the value below when prompted)");
  console.log();
  console.log(`FOUNDATION_SIGNING_KEY_PKCS8_B64=${privB64}`);
  console.log();
  console.log("2. Add the public key to wrangler.toml [vars]:");
  console.log();
  console.log(`FOUNDATION_SIGNING_KEY_PUB_HEX = "${pubHex}"`);
  console.log();
  console.log("── Keep the PKCS8 value secret. The hex pubkey is public. ──");
  console.log();
})();
