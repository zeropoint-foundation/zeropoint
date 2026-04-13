// crates/zp-keys/src/recovery.rs
//
// Recovery kit: BIP-39 mnemonic encoding of the Genesis secret.
//
// The mnemonic IS the Genesis secret in human-readable form — not a
// separate key. 256 bits of entropy → 24 words (BIP-39 standard).
//
// This module provides:
// 1. Encode a 32-byte secret into a 24-word mnemonic
// 2. Decode a 24-word mnemonic back to a 32-byte secret
// 3. Verify a mnemonic matches a known Genesis public key
//
// The mnemonic is displayed exactly once during the Genesis ceremony
// (when biometric sovereignty is selected) and never stored digitally.

use crate::error::KeyError;

// ---------------------------------------------------------------------------
// BIP-39 English wordlist (2048 words)
// ---------------------------------------------------------------------------

// The standard BIP-39 English wordlist, embedded at compile time.
// Source: https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt
//
// We embed this rather than depending on an external crate to keep the
// dependency tree minimal and auditable.
const BIP39_WORDLIST: &str = include_str!("bip39_english.txt");

/// Get the BIP-39 wordlist as a Vec of &str.
fn wordlist() -> Vec<&'static str> {
    BIP39_WORDLIST.lines().collect()
}

// ---------------------------------------------------------------------------
// Encode: 32 bytes → 24 words
// ---------------------------------------------------------------------------

/// Encode a 32-byte (256-bit) secret as a 24-word BIP-39 mnemonic.
///
/// BIP-39 encoding for 256 bits:
/// 1. Compute SHA-256 hash of the entropy
/// 2. Take first 8 bits of hash as checksum (256 / 32 = 8)
/// 3. Concatenate entropy + checksum = 264 bits
/// 4. Split into 24 groups of 11 bits
/// 5. Each 11-bit value indexes into the 2048-word wordlist
///
/// The checksum ensures that typos in the mnemonic are detected.
pub fn encode_mnemonic(secret: &[u8; 32]) -> Result<Vec<String>, KeyError> {
    let words = wordlist();
    if words.len() != 2048 {
        return Err(KeyError::InvalidKeyMaterial(format!(
            "BIP-39 wordlist has {} words, expected 2048",
            words.len()
        )));
    }

    // Step 1: SHA-256 hash of entropy
    let hash = sha256(secret);

    // Step 2: Take first 8 bits as checksum (for 256-bit entropy)
    let checksum_byte = hash[0];

    // Step 3: Build 264-bit bitstream (256 entropy + 8 checksum)
    // We work with a Vec<bool> for clarity
    let mut bits: Vec<bool> = Vec::with_capacity(264);
    for byte in secret.iter() {
        for i in (0..8).rev() {
            bits.push((byte >> i) & 1 == 1);
        }
    }
    for i in (0..8).rev() {
        bits.push((checksum_byte >> i) & 1 == 1);
    }

    assert_eq!(bits.len(), 264, "expected 264 bits (256 + 8 checksum)");

    // Step 4-5: Split into 24 groups of 11 bits, index into wordlist
    let mut mnemonic = Vec::with_capacity(24);
    for chunk in bits.chunks(11) {
        let mut index: usize = 0;
        for (j, &bit) in chunk.iter().enumerate() {
            if bit {
                index |= 1 << (10 - j);
            }
        }
        if index >= 2048 {
            return Err(KeyError::InvalidKeyMaterial(format!(
                "BIP-39 index out of range: {}",
                index
            )));
        }
        mnemonic.push(words[index].to_string());
    }

    assert_eq!(mnemonic.len(), 24, "expected 24 words");
    Ok(mnemonic)
}

// ---------------------------------------------------------------------------
// Decode: 24 words → 32 bytes
// ---------------------------------------------------------------------------

/// Decode a 24-word BIP-39 mnemonic back to the original 32-byte secret.
///
/// Validates the checksum to detect typos.
pub fn decode_mnemonic(mnemonic: &[String]) -> Result<[u8; 32], KeyError> {
    if mnemonic.len() != 24 {
        return Err(KeyError::InvalidKeyMaterial(format!(
            "Recovery mnemonic must be exactly 24 words, got {}",
            mnemonic.len()
        )));
    }

    let words = wordlist();
    if words.len() != 2048 {
        return Err(KeyError::InvalidKeyMaterial(
            "BIP-39 wordlist corrupt".into(),
        ));
    }

    // Convert words to 11-bit indices
    let mut bits: Vec<bool> = Vec::with_capacity(264);
    for word in mnemonic {
        let word_lower = word.trim().to_lowercase();
        let index = words.iter().position(|&w| w == word_lower).ok_or_else(|| {
            KeyError::InvalidKeyMaterial(format!("\"{}\" is not a valid BIP-39 word", word_lower))
        })?;

        for i in (0..11).rev() {
            bits.push((index >> i) & 1 == 1);
        }
    }

    assert_eq!(bits.len(), 264);

    // First 256 bits are the entropy
    let mut secret = [0u8; 32];
    for (i, byte) in secret.iter_mut().enumerate() {
        for j in 0..8 {
            if bits[i * 8 + j] {
                *byte |= 1 << (7 - j);
            }
        }
    }

    // Last 8 bits are the checksum
    let mut checksum_received: u8 = 0;
    for j in 0..8 {
        if bits[256 + j] {
            checksum_received |= 1 << (7 - j);
        }
    }

    // Verify checksum
    let hash = sha256(&secret);
    let checksum_expected = hash[0];

    if checksum_received != checksum_expected {
        return Err(KeyError::InvalidKeyMaterial(
            "Recovery mnemonic checksum failed — check for typos".into(),
        ));
    }

    Ok(secret)
}

// ---------------------------------------------------------------------------
// Verify against known Genesis public key
// ---------------------------------------------------------------------------

/// Verify that a decoded mnemonic produces the expected Genesis public key.
///
/// This is the final sanity check during recovery: the user enters their
/// 24 words, we decode to a secret, derive the Ed25519 keypair, and check
/// that the public key matches the one in genesis.json.
pub fn verify_recovery(
    mnemonic: &[String],
    expected_public_key: &ed25519_dalek::VerifyingKey,
) -> Result<[u8; 32], KeyError> {
    let secret = decode_mnemonic(mnemonic)?;

    // Derive the signing key from the secret
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret);
    let derived_public = signing_key.verifying_key();

    if derived_public != *expected_public_key {
        return Err(KeyError::InvalidKeyMaterial(
            "Recovery mnemonic does not match the Genesis public key in genesis.json. \
             This mnemonic may belong to a different identity."
                .into(),
        ));
    }

    Ok(secret)
}

// ---------------------------------------------------------------------------
// SHA-256 (minimal, no external dependency)
// ---------------------------------------------------------------------------

/// Compute SHA-256 hash of input bytes.
///
/// We implement SHA-256 here rather than adding a dependency because:
/// 1. It's only used for BIP-39 checksum (8 bits)
/// 2. The implementation is straightforward and auditable
/// 3. It keeps the dependency tree clean
///
/// If we already have `sha2` in the workspace, this should be swapped.
fn sha256(input: &[u8]) -> [u8; 32] {
    // SHA-256 constants
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    // Pre-processing: pad message
    let bit_len = (input.len() as u64) * 8;
    let mut data = input.to_vec();
    data.push(0x80);
    while (data.len() % 64) != 56 {
        data.push(0x00);
    }
    data.extend_from_slice(&bit_len.to_be_bytes());

    // Process each 512-bit (64-byte) block
    for chunk in data.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut result = [0u8; 32];
    for (i, val) in h.iter().enumerate() {
        result[i * 4..i * 4 + 4].copy_from_slice(&val.to_be_bytes());
    }
    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_empty() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let hash = sha256(b"");
        assert_eq!(
            hex::encode(hash),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_sha256_abc() {
        // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let hash = sha256(b"abc");
        assert_eq!(
            hex::encode(hash),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_mnemonic_roundtrip() {
        // Generate a deterministic 32-byte secret
        let secret: [u8; 32] = [
            0x7e, 0xb8, 0xda, 0x3f, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc,
            0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xaa, 0xbb, 0xcc,
        ];

        let mnemonic = encode_mnemonic(&secret).expect("encode should succeed");
        assert_eq!(mnemonic.len(), 24, "mnemonic should be 24 words");

        // Each word should be in the wordlist
        let words = wordlist();
        for word in &mnemonic {
            assert!(
                words.contains(&word.as_str()),
                "word '{}' not in BIP-39 wordlist",
                word
            );
        }

        // Decode back to secret
        let recovered = decode_mnemonic(&mnemonic).expect("decode should succeed");
        assert_eq!(
            recovered, secret,
            "roundtrip should recover original secret"
        );
    }

    #[test]
    fn test_mnemonic_checksum_detects_typo() {
        let secret = [0u8; 32];
        let mut mnemonic = encode_mnemonic(&secret).expect("encode should succeed");

        // Corrupt one word
        mnemonic[0] = "abandon".to_string(); // probably not the correct first word for all-zeros

        // This should either succeed (if "abandon" happens to be correct) or fail checksum
        // For all-zeros entropy, the first word IS "abandon" (index 0), so corrupt differently
        mnemonic[12] = "zoo".to_string();

        let result = decode_mnemonic(&mnemonic);
        // Should fail with checksum error (unless we got astronomically lucky)
        assert!(
            result.is_err(),
            "corrupted mnemonic should fail checksum validation"
        );
    }

    #[test]
    fn test_mnemonic_wrong_length() {
        let too_short = vec!["abandon".to_string(); 12];
        assert!(decode_mnemonic(&too_short).is_err());

        let too_long = vec!["abandon".to_string(); 25];
        assert!(decode_mnemonic(&too_long).is_err());
    }

    #[test]
    fn test_mnemonic_invalid_word() {
        let mut mnemonic = vec!["abandon".to_string(); 24];
        mnemonic[5] = "zeropoint".to_string(); // not a BIP-39 word

        assert!(decode_mnemonic(&mnemonic).is_err());
    }

    #[test]
    fn test_verify_recovery_with_correct_key() {
        use ed25519_dalek::SigningKey;

        let secret = [42u8; 32];
        let signing_key = SigningKey::from_bytes(&secret);
        let public_key = signing_key.verifying_key();

        let mnemonic = encode_mnemonic(&secret).expect("encode should succeed");
        let recovered = verify_recovery(&mnemonic, &public_key).expect("verify should succeed");
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_verify_recovery_with_wrong_key() {
        use ed25519_dalek::SigningKey;

        let secret = [42u8; 32];
        let wrong_secret = [99u8; 32];
        let wrong_key = SigningKey::from_bytes(&wrong_secret).verifying_key();

        let mnemonic = encode_mnemonic(&secret).expect("encode should succeed");
        let result = verify_recovery(&mnemonic, &wrong_key);
        assert!(result.is_err(), "wrong public key should fail verification");
    }
}
