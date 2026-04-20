//! Genesis v2 ceremony — Shamir secret sharing for key escrow and scheduled rotation.
//!
//! Extends the original Genesis ceremony with:
//!
//! 1. **Key escrow via Shamir's Secret Sharing (SSS)**: The genesis secret is split
//!    into N shares with a threshold of K required for reconstruction. This enables
//!    organizational recovery without any single custodian holding the full key.
//!
//! 2. **Rotation scheduling**: The ceremony records a rotation schedule — how
//!    frequently the genesis key should be rotated — and tracks the current
//!    rotation epoch.
//!
//! ## Shamir Secret Sharing
//!
//! SSS operates over GF(256) — each byte of the 32-byte secret is shared
//! independently using polynomial evaluation modulo an irreducible polynomial.
//! This implementation uses the standard AES irreducible polynomial x^8 + x^4 + x^3 + x + 1.
//!
//! ## Design
//!
//! ```text
//! ┌──────────────────────────────────────────────────┐
//! │  Genesis v2 Ceremony                              │
//! │                                                   │
//! │  1. Generate or import 32-byte genesis secret     │
//! │  2. Split into N shares (threshold K)             │
//! │  3. Distribute shares to custodians               │
//! │  4. Record rotation schedule                      │
//! │  5. Produce GenesisV2Record (auditable)           │
//! │                                                   │
//! │  Recovery: K of N custodians → reconstruct secret │
//! └──────────────────────────────────────────────────┘
//! ```

use chrono::{DateTime, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::error::KeyError;

// ============================================================================
// GF(256) arithmetic for Shamir's Secret Sharing
// ============================================================================

/// AES irreducible polynomial for GF(256): x^8 + x^4 + x^3 + x + 1 = 0x11B
const GF256_MODULUS: u16 = 0x11B;

/// Multiply two elements in GF(256).
fn gf256_mul(a: u8, b: u8) -> u8 {
    let mut result: u16 = 0;
    let mut a = a as u16;
    let mut b = b as u16;

    while b > 0 {
        if b & 1 != 0 {
            result ^= a;
        }
        a <<= 1;
        if a & 0x100 != 0 {
            a ^= GF256_MODULUS;
        }
        b >>= 1;
    }

    result as u8
}

/// Multiplicative inverse in GF(256) via exponentiation: a^(-1) = a^254.
fn gf256_inv(a: u8) -> u8 {
    if a == 0 {
        panic!("cannot invert zero in GF(256)");
    }
    // Compute a^254 by repeated squaring
    // 254 = 11111110 in binary
    let mut result = 1u8;
    let mut base = a;
    let mut exp = 254u8;
    while exp > 0 {
        if exp & 1 != 0 {
            result = gf256_mul(result, base);
        }
        base = gf256_mul(base, base);
        exp >>= 1;
    }
    result
}

// ============================================================================
// Shamir Secret Sharing
// ============================================================================

/// A single share from Shamir's Secret Sharing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShamirShare {
    /// Share index (1-based, never 0). This is the x-coordinate.
    pub index: u8,
    /// Share data — same length as the original secret (32 bytes).
    pub data: Vec<u8>,
}

/// Configuration for secret sharing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharingConfig {
    /// Total number of shares to generate.
    pub total_shares: u8,
    /// Minimum shares required for reconstruction.
    pub threshold: u8,
}

impl SharingConfig {
    pub fn new(total_shares: u8, threshold: u8) -> Result<Self, KeyError> {
        if threshold < 2 {
            return Err(KeyError::InvalidKeyMaterial(
                "threshold must be at least 2".to_string(),
            ));
        }
        if total_shares < threshold {
            return Err(KeyError::InvalidKeyMaterial(
                "total_shares must be >= threshold".to_string(),
            ));
        }
        // total_shares is u8, so max is 255 — no need for upper bound check
        Ok(Self {
            total_shares,
            threshold,
        })
    }
}

/// Split a secret into shares using Shamir's Secret Sharing over GF(256).
///
/// Each byte of the secret is shared independently using a random polynomial
/// of degree (threshold - 1). The secret is the constant term (evaluation at x=0).
pub fn split_secret(
    secret: &[u8; 32],
    config: &SharingConfig,
) -> Result<Vec<ShamirShare>, KeyError> {
    let mut rng = rand::thread_rng();
    let threshold = config.threshold as usize;

    // Initialize shares
    let mut shares: Vec<ShamirShare> = (1..=config.total_shares)
        .map(|i| ShamirShare {
            index: i,
            data: vec![0u8; 32],
        })
        .collect();

    // For each byte of the secret, create a random polynomial and evaluate
    for byte_idx in 0..32 {
        // Coefficients: a[0] = secret byte, a[1..threshold-1] = random
        let mut coeffs = vec![0u8; threshold];
        coeffs[0] = secret[byte_idx];
        let mut random_bytes = vec![0u8; threshold - 1];
        rng.fill_bytes(&mut random_bytes);
        coeffs[1..].copy_from_slice(&random_bytes);

        // Evaluate polynomial at each share's x-coordinate
        for share in &mut shares {
            let x = share.index;
            let mut y = 0u8;
            let mut x_power = 1u8; // x^0 = 1

            for coeff in &coeffs {
                y ^= gf256_mul(*coeff, x_power);
                x_power = gf256_mul(x_power, x);
            }

            share.data[byte_idx] = y;
        }
    }

    Ok(shares)
}

/// Reconstruct a secret from K or more shares using Lagrange interpolation over GF(256).
pub fn reconstruct_secret(shares: &[ShamirShare]) -> Result<[u8; 32], KeyError> {
    if shares.is_empty() {
        return Err(KeyError::InvalidKeyMaterial(
            "need at least one share".to_string(),
        ));
    }

    let k = shares.len();
    let secret_len = shares[0].data.len();
    if secret_len != 32 {
        return Err(KeyError::InvalidKeyMaterial(format!(
            "share data length {} != 32",
            secret_len
        )));
    }

    // Check for duplicate indices
    let mut seen = std::collections::HashSet::new();
    for share in shares {
        if !seen.insert(share.index) {
            return Err(KeyError::InvalidKeyMaterial(format!(
                "duplicate share index {}",
                share.index
            )));
        }
        if share.index == 0 {
            return Err(KeyError::InvalidKeyMaterial(
                "share index cannot be 0".to_string(),
            ));
        }
    }

    let mut secret = [0u8; 32];

    // Lagrange interpolation at x=0 for each byte position
    for byte_idx in 0..32 {
        let mut result = 0u8;

        for i in 0..k {
            let xi = shares[i].index;
            let yi = shares[i].data[byte_idx];

            // Compute Lagrange basis polynomial L_i(0)
            let mut basis = 1u8;
            for j in 0..k {
                if i == j {
                    continue;
                }
                let xj = shares[j].index;
                // L_i(0) *= (0 - xj) / (xi - xj) = xj / (xi ^ xj) in GF(256)
                // Note: subtraction = XOR in GF(256), and -xj = xj
                let num = xj;
                let den = xi ^ xj;
                basis = gf256_mul(basis, gf256_mul(num, gf256_inv(den)));
            }

            result ^= gf256_mul(yi, basis);
        }

        secret[byte_idx] = result;
    }

    Ok(secret)
}

// ============================================================================
// Genesis v2 ceremony record
// ============================================================================

/// Rotation schedule for the genesis key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationSchedule {
    /// How often the key should be rotated (in days).
    pub rotation_interval_days: u32,
    /// When the next rotation is due.
    pub next_rotation: DateTime<Utc>,
    /// Current rotation epoch (increments on each rotation).
    pub epoch: u32,
}

/// The auditable record produced by a Genesis v2 ceremony.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisV2Record {
    /// Version marker.
    pub version: String,
    /// Public key of the genesis keypair (hex-encoded Ed25519).
    pub public_key: String,
    /// Blake3 hash of the genesis public key (for quick lookup).
    pub public_key_hash: String,
    /// Sharing configuration used.
    pub sharing_config: SharingConfig,
    /// Blake3 hashes of each share (for verification without revealing shares).
    pub share_hashes: Vec<String>,
    /// When the ceremony was performed.
    pub ceremony_timestamp: DateTime<Utc>,
    /// Rotation schedule.
    pub rotation_schedule: RotationSchedule,
    /// Ed25519 signature over the canonical JSON of this record (excluding this field).
    pub ceremony_signature: String,
}

/// Perform a Genesis v2 ceremony.
///
/// 1. Takes a 32-byte genesis secret (typically from key generation).
/// 2. Splits it into shares via Shamir SSS.
/// 3. Produces an auditable ceremony record.
/// 4. Returns the shares (to be distributed to custodians out-of-band).
pub fn perform_genesis_v2(
    genesis_secret: &[u8; 32],
    public_key_hex: &str,
    sharing_config: SharingConfig,
    rotation_interval_days: u32,
) -> Result<(GenesisV2Record, Vec<ShamirShare>), KeyError> {
    // Split the secret
    let shares = split_secret(genesis_secret, &sharing_config)?;

    // Hash each share for the ceremony record
    let share_hashes: Vec<String> = shares
        .iter()
        .map(|s| {
            let hash = blake3::hash(&s.data);
            hash.to_hex().to_string()
        })
        .collect();

    let now = Utc::now();
    let next_rotation = now + chrono::Duration::days(rotation_interval_days as i64);

    let public_key_hash = blake3::hash(public_key_hex.as_bytes())
        .to_hex()
        .to_string();

    let record = GenesisV2Record {
        version: "2.0".to_string(),
        public_key: public_key_hex.to_string(),
        public_key_hash,
        sharing_config: sharing_config.clone(),
        share_hashes,
        ceremony_timestamp: now,
        rotation_schedule: RotationSchedule {
            rotation_interval_days,
            next_rotation,
            epoch: 0,
        },
        ceremony_signature: String::new(), // Placeholder — signed by caller
    };

    info!(
        shares = sharing_config.total_shares,
        threshold = sharing_config.threshold,
        rotation_days = rotation_interval_days,
        "genesis v2 ceremony completed"
    );

    Ok((record, shares))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gf256_multiply_identity() {
        for a in 0..=255u8 {
            assert_eq!(gf256_mul(a, 1), a);
            assert_eq!(gf256_mul(1, a), a);
            assert_eq!(gf256_mul(a, 0), 0);
        }
    }

    #[test]
    fn gf256_inverse_roundtrip() {
        for a in 1..=255u8 {
            let inv = gf256_inv(a);
            assert_eq!(gf256_mul(a, inv), 1, "a={} inv={}", a, inv);
        }
    }

    #[test]
    fn split_and_reconstruct_exact_threshold() {
        let secret: [u8; 32] = [
            0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
            0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1A, 0x1B, 0x1C,
        ];
        let config = SharingConfig::new(5, 3).unwrap();
        let shares = split_secret(&secret, &config).unwrap();
        assert_eq!(shares.len(), 5);

        // Reconstruct with exactly 3 shares (threshold)
        let reconstructed = reconstruct_secret(&shares[0..3]).unwrap();
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn split_and_reconstruct_all_shares() {
        let secret = [0x42u8; 32];
        let config = SharingConfig::new(5, 3).unwrap();
        let shares = split_secret(&secret, &config).unwrap();

        // Reconstruct with all 5 shares
        let reconstructed = reconstruct_secret(&shares).unwrap();
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn reconstruct_with_different_share_subsets() {
        let secret = [0xABu8; 32];
        let config = SharingConfig::new(5, 3).unwrap();
        let shares = split_secret(&secret, &config).unwrap();

        // Try various 3-share combinations
        let combos: Vec<Vec<usize>> = vec![
            vec![0, 1, 2],
            vec![0, 2, 4],
            vec![1, 3, 4],
            vec![2, 3, 4],
            vec![0, 1, 4],
        ];

        for combo in combos {
            let subset: Vec<ShamirShare> = combo.iter().map(|&i| shares[i].clone()).collect();
            let reconstructed = reconstruct_secret(&subset).unwrap();
            assert_eq!(reconstructed, secret, "failed with combo {:?}", combo);
        }
    }

    #[test]
    fn insufficient_shares_gives_wrong_result() {
        let secret = [0xFFu8; 32];
        let config = SharingConfig::new(5, 3).unwrap();
        let shares = split_secret(&secret, &config).unwrap();

        // Only 2 shares — below threshold, should give wrong result
        let reconstructed = reconstruct_secret(&shares[0..2]).unwrap();
        // With overwhelming probability, this won't match the original
        // (probability of accidental match: 1/256^32 ≈ 0)
        assert_ne!(reconstructed, secret);
    }

    #[test]
    fn invalid_config_rejected() {
        assert!(SharingConfig::new(5, 1).is_err()); // threshold too low
        assert!(SharingConfig::new(2, 5).is_err()); // total < threshold
    }

    #[test]
    fn duplicate_share_index_rejected() {
        let share = ShamirShare {
            index: 1,
            data: vec![0u8; 32],
        };
        let result = reconstruct_secret(&[share.clone(), share]);
        assert!(result.is_err());
    }

    #[test]
    fn zero_index_rejected() {
        let share = ShamirShare {
            index: 0,
            data: vec![0u8; 32],
        };
        let result = reconstruct_secret(&[share]);
        assert!(result.is_err());
    }

    #[test]
    fn genesis_v2_ceremony_produces_valid_record() {
        let secret = [0x42u8; 32];
        let config = SharingConfig::new(3, 2).unwrap();
        let (record, shares) = perform_genesis_v2(&secret, "abcdef1234", config, 90).unwrap();

        assert_eq!(record.version, "2.0");
        assert_eq!(record.sharing_config.total_shares, 3);
        assert_eq!(record.sharing_config.threshold, 2);
        assert_eq!(record.share_hashes.len(), 3);
        assert_eq!(record.rotation_schedule.rotation_interval_days, 90);
        assert_eq!(record.rotation_schedule.epoch, 0);
        assert_eq!(shares.len(), 3);

        // Verify shares reconstruct correctly
        let reconstructed = reconstruct_secret(&shares[0..2]).unwrap();
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn share_hashes_are_unique() {
        let secret = [0x42u8; 32];
        let config = SharingConfig::new(5, 3).unwrap();
        let (record, _) = perform_genesis_v2(&secret, "pubkey123", config, 30).unwrap();

        let unique: std::collections::HashSet<_> = record.share_hashes.iter().collect();
        assert_eq!(unique.len(), record.share_hashes.len());
    }
}
