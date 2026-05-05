/**
 * Minimal ULID generator for Cloudflare Workers.
 * Crockford Base32, timestamp + 80 bits of randomness.
 */

const ENCODING = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

function encodeTime(now, len) {
  let str = "";
  for (let i = len; i > 0; i--) {
    const mod = now % 32;
    str = ENCODING[mod] + str;
    now = (now - mod) / 32;
  }
  return str;
}

function encodeRandom(len) {
  const arr = crypto.getRandomValues(new Uint8Array(len));
  let str = "";
  for (const byte of arr) {
    str += ENCODING[byte % 32];
  }
  return str;
}

export function ulid() {
  const time = encodeTime(Date.now(), 10);
  const rand = encodeRandom(16);
  return time + rand;
}
