//! Epoch compaction — Merkle tree sealing for receipt chains.
//!
//! When a receipt chain grows beyond a threshold, a range of entries can be
//! "compacted" into an epoch. The epoch seals the entries into a Merkle tree,
//! producing a root hash that proves integrity without keeping every entry.
//!
//! ## Design
//!
//! ```text
//! Epoch 0: [receipt_0 .. receipt_99]  → merkle_root_0
//! Epoch 1: [receipt_100 .. receipt_199] → merkle_root_1
//! Active:  [receipt_200 .. receipt_N]   → live chain
//! ```
//!
//! Each epoch contains:
//! - The Merkle root of all entry hashes in the epoch
//! - The first and last sequence numbers
//! - The hash of the previous epoch (forming an epoch chain)
//! - A timestamp for when compaction occurred

use crate::chain::ReceiptChainEntry;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A single node in the Merkle tree.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct MerkleNode {
    hash: String,
    left: Option<Box<MerkleNode>>,
    right: Option<Box<MerkleNode>>,
}

/// A sealed epoch — a compacted range of receipt chain entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Epoch {
    /// Epoch number (0-indexed, monotonically increasing).
    pub epoch_number: u64,
    /// Merkle root hash of all entries in this epoch.
    pub merkle_root: String,
    /// Hash of the previous epoch's merkle root (or "genesis" for epoch 0).
    pub prev_epoch_hash: String,
    /// First sequence number in this epoch.
    pub first_sequence: u64,
    /// Last sequence number in this epoch (inclusive).
    pub last_sequence: u64,
    /// Number of entries compacted.
    pub entry_count: usize,
    /// When this epoch was sealed.
    pub sealed_at: DateTime<Utc>,
    /// The chain ID this epoch belongs to.
    pub chain_id: String,
}

/// A Merkle proof that a specific entry exists in an epoch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    /// The hash of the entry being proved.
    pub leaf_hash: String,
    /// The index of the leaf in the tree.
    pub leaf_index: usize,
    /// Sibling hashes from leaf to root, with direction (left/right).
    pub path: Vec<ProofStep>,
    /// The expected Merkle root.
    pub root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofStep {
    pub hash: String,
    pub direction: Direction,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Direction {
    Left,
    Right,
}

/// Errors from epoch operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EpochError {
    /// Not enough entries to form an epoch.
    InsufficientEntries { required: usize, available: usize },
    /// The entries are not contiguous.
    NonContiguousEntries,
    /// Merkle proof verification failed.
    ProofVerificationFailed,
    /// Invalid epoch chain (prev_epoch_hash mismatch).
    EpochChainBroken {
        epoch: u64,
        expected: String,
        actual: String,
    },
}

impl std::fmt::Display for EpochError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EpochError::InsufficientEntries {
                required,
                available,
            } => {
                write!(
                    f,
                    "Insufficient entries: need {}, have {}",
                    required, available
                )
            }
            EpochError::NonContiguousEntries => {
                write!(f, "Entries are not contiguous")
            }
            EpochError::ProofVerificationFailed => {
                write!(f, "Merkle proof verification failed")
            }
            EpochError::EpochChainBroken {
                epoch,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "Epoch chain broken at epoch {}: expected {}, got {}",
                    epoch, expected, actual
                )
            }
        }
    }
}

impl std::error::Error for EpochError {}

/// Internal Merkle tree structure.
#[allow(dead_code)]
struct MerkleTree {
    root_node: MerkleNode,
    leaves: Vec<String>,
}

impl MerkleTree {
    /// Build a balanced binary Merkle tree from entry hashes.
    ///
    /// If the number of entries is odd, the last leaf is duplicated
    /// to form a balanced tree.
    fn from_hashes(hashes: &[String]) -> Self {
        if hashes.is_empty() {
            panic!("Cannot build Merkle tree from empty hashes");
        }

        let mut leaves = hashes.to_vec();

        // If odd number of leaves, duplicate the last one
        if !leaves.len().is_multiple_of(2) {
            leaves.push(leaves[leaves.len() - 1].clone());
        }

        // Build tree from leaves upward
        let mut current_level: Vec<MerkleNode> = leaves
            .iter()
            .map(|hash| MerkleNode {
                hash: hash.clone(),
                left: None,
                right: None,
            })
            .collect();

        while current_level.len() > 1 {
            // Pad odd-length levels by duplicating the last node
            if !current_level.len().is_multiple_of(2) {
                current_level.push(current_level[current_level.len() - 1].clone());
            }

            let mut next_level = Vec::new();

            for i in (0..current_level.len()).step_by(2) {
                let left = current_level[i].clone();
                let right = current_level[i + 1].clone();

                let combined = format!("{}:{}", left.hash, right.hash);
                let parent_hash = blake3::hash(combined.as_bytes()).to_hex().to_string();

                let parent = MerkleNode {
                    hash: parent_hash,
                    left: Some(Box::new(left)),
                    right: Some(Box::new(right)),
                };

                next_level.push(parent);
            }

            current_level = next_level;
        }

        let root_node = current_level.into_iter().next().unwrap();

        MerkleTree {
            root_node,
            leaves: hashes.to_vec(),
        }
    }

    /// Get the root hash.
    fn root(&self) -> &str {
        &self.root_node.hash
    }

    /// Generate a Merkle proof for the leaf at the given index.
    #[allow(dead_code)]
    fn proof(&self, index: usize) -> Option<MerkleProof> {
        if index >= self.leaves.len() {
            return None;
        }

        let leaf_hash = self.leaves[index].clone();
        let mut path = Vec::new();

        // Handle odd-numbered leaves case
        let mut adjusted_leaves = self.leaves.clone();
        if !adjusted_leaves.len().is_multiple_of(2) {
            adjusted_leaves.push(adjusted_leaves[adjusted_leaves.len() - 1].clone());
        }

        let current_index = index;

        // Walk up the tree to collect sibling hashes
        Self::collect_proof_path(&self.root_node, current_index, &adjusted_leaves, &mut path);

        Some(MerkleProof {
            leaf_hash,
            leaf_index: index,
            path,
            root: self.root_node.hash.clone(),
        })
    }

    /// Helper to collect proof path by traversing the tree.
    /// Path is built bottom-up: leaf siblings first, root siblings last.
    #[allow(clippy::only_used_in_recursion)]
    fn collect_proof_path(
        node: &MerkleNode,
        target_index: usize,
        leaves: &[String],
        path: &mut Vec<ProofStep>,
    ) -> bool {
        // If this is a leaf, check if it matches
        if node.left.is_none() && node.right.is_none() {
            return target_index == 0;
        }

        // Calculate how many leaves are in the left subtree
        let left_size = Self::leaf_count(node.left.as_deref());
        let target_is_in_left = target_index < left_size;

        if target_is_in_left {
            if let Some(left) = &node.left {
                if Self::collect_proof_path(left, target_index, leaves, path) {
                    // Add right sibling AFTER recursion (bottom-up order)
                    if let Some(right) = &node.right {
                        path.push(ProofStep {
                            hash: right.hash.clone(),
                            direction: Direction::Right,
                        });
                    }
                    return true;
                }
            }
        } else if let Some(right) = &node.right {
            let right_index = target_index - left_size;
            if Self::collect_proof_path(right, right_index, leaves, path) {
                // Add left sibling AFTER recursion (bottom-up order)
                if let Some(left) = &node.left {
                    path.push(ProofStep {
                        hash: left.hash.clone(),
                        direction: Direction::Left,
                    });
                }
                return true;
            }
        }

        false
    }

    /// Count leaves in a subtree.
    fn leaf_count(node: Option<&MerkleNode>) -> usize {
        match node {
            None => 0,
            Some(n) => {
                if n.left.is_none() && n.right.is_none() {
                    1
                } else {
                    Self::leaf_count(n.left.as_deref()) + Self::leaf_count(n.right.as_deref())
                }
            }
        }
    }
}

impl MerkleProof {
    /// Verify the proof by recomputing the root hash from leaf to root.
    pub fn verify(&self) -> bool {
        let mut current_hash = self.leaf_hash.clone();

        for step in &self.path {
            let combined = match step.direction {
                Direction::Left => format!("{}:{}", step.hash, current_hash),
                Direction::Right => format!("{}:{}", current_hash, step.hash),
            };
            current_hash = blake3::hash(combined.as_bytes()).to_hex().to_string();
        }

        current_hash == self.root
    }
}

/// Compacts receipt chains into sealed epochs.
pub struct EpochCompactor {
    entries_per_epoch: usize,
}

impl EpochCompactor {
    /// Create a new compactor with configurable epoch size.
    ///
    /// # Arguments
    /// * `entries_per_epoch` - How many entries to include in each epoch (default: 100)
    pub fn new(entries_per_epoch: usize) -> Self {
        Self { entries_per_epoch }
    }

    /// Determine if a chain has enough uncompacted entries to warrant compaction.
    pub fn should_compact(&self, chain_len: usize, epochs: &[Epoch]) -> bool {
        let compacted_count = epochs.iter().map(|e| e.entry_count).sum::<usize>();
        let uncompacted_count = chain_len - compacted_count;
        uncompacted_count >= self.entries_per_epoch
    }

    /// Compact a range of entries into a single epoch.
    ///
    /// Returns an error if:
    /// - Fewer than `entries_per_epoch` entries are provided
    /// - Entries are not contiguous
    /// - The previous epoch hash doesn't match (if prev_epoch is Some)
    pub fn compact(
        &self,
        chain_id: &str,
        entries: &[ReceiptChainEntry],
        prev_epoch: Option<&Epoch>,
    ) -> Result<Epoch, EpochError> {
        // Check sufficient entries
        if entries.len() < self.entries_per_epoch {
            return Err(EpochError::InsufficientEntries {
                required: self.entries_per_epoch,
                available: entries.len(),
            });
        }

        // Check contiguity: sequences should be [first, first+1, ..., last]
        if !entries.is_empty() {
            let first_seq = entries[0].sequence;
            for (i, entry) in entries.iter().enumerate() {
                if entry.sequence != first_seq + i as u64 {
                    return Err(EpochError::NonContiguousEntries);
                }
            }
        }

        // Collect hashes from entries
        let hashes: Vec<String> = entries.iter().map(|e| e.content_hash.clone()).collect();

        // Build Merkle tree and get root
        let merkle_root = compute_merkle_root(&hashes);

        // Determine prev_epoch_hash
        let prev_epoch_hash = match prev_epoch {
            None => "genesis".to_string(),
            Some(epoch) => epoch.merkle_root.clone(),
        };

        // Determine epoch number
        let epoch_number = match prev_epoch {
            None => 0,
            Some(epoch) => epoch.epoch_number + 1,
        };

        Ok(Epoch {
            epoch_number,
            merkle_root,
            prev_epoch_hash,
            first_sequence: entries[0].sequence,
            last_sequence: entries[entries.len() - 1].sequence,
            entry_count: entries.len(),
            sealed_at: Utc::now(),
            chain_id: chain_id.to_string(),
        })
    }

    /// Verify that an epoch's Merkle root matches the given entries.
    pub fn verify_epoch(&self, epoch: &Epoch, entries: &[ReceiptChainEntry]) -> Result<(), EpochError> {
        // Check that entries match the epoch's sequence range
        if entries.is_empty() {
            return Err(EpochError::NonContiguousEntries);
        }

        if entries[0].sequence != epoch.first_sequence
            || entries[entries.len() - 1].sequence != epoch.last_sequence
        {
            return Err(EpochError::NonContiguousEntries);
        }

        // Compute Merkle root from entries
        let hashes: Vec<String> = entries.iter().map(|e| e.content_hash.clone()).collect();
        let computed_root = compute_merkle_root(&hashes);

        if computed_root == epoch.merkle_root {
            Ok(())
        } else {
            Err(EpochError::ProofVerificationFailed)
        }
    }

    /// Verify that a chain of epochs is intact.
    ///
    /// Checks that:
    /// - Epoch numbers are monotonically increasing
    /// - Each epoch's prev_epoch_hash matches the previous epoch's merkle_root
    /// - The first epoch's prev_epoch_hash is "genesis"
    pub fn verify_epoch_chain(&self, epochs: &[Epoch]) -> Result<(), EpochError> {
        if epochs.is_empty() {
            return Ok(());
        }

        // Check first epoch
        if epochs[0].prev_epoch_hash != "genesis" {
            return Err(EpochError::EpochChainBroken {
                epoch: 0,
                expected: "genesis".to_string(),
                actual: epochs[0].prev_epoch_hash.clone(),
            });
        }

        // Check epoch numbers and chain linkage
        for (i, epoch) in epochs.iter().enumerate() {
            if epoch.epoch_number != i as u64 {
                return Err(EpochError::EpochChainBroken {
                    epoch: i as u64,
                    expected: i.to_string(),
                    actual: epoch.epoch_number.to_string(),
                });
            }

            if i > 0 {
                let prev_epoch = &epochs[i - 1];
                if epoch.prev_epoch_hash != prev_epoch.merkle_root {
                    return Err(EpochError::EpochChainBroken {
                        epoch: i as u64,
                        expected: prev_epoch.merkle_root.clone(),
                        actual: epoch.prev_epoch_hash.clone(),
                    });
                }
            }
        }

        Ok(())
    }
}

/// Compute the Merkle root from a list of hashes.
///
/// Uses blake3 for hashing. The root is computed by building a balanced
/// binary Merkle tree where internal node hashes are computed as:
/// `blake3(left_hash + ":" + right_hash)`
pub fn compute_merkle_root(hashes: &[String]) -> String {
    if hashes.is_empty() {
        return String::new();
    }

    if hashes.len() == 1 {
        return hashes[0].clone();
    }

    let tree = MerkleTree::from_hashes(hashes);
    tree.root().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_chain_entry(sequence: u64, content_hash: &str) -> ReceiptChainEntry {
        ReceiptChainEntry {
            sequence,
            content_hash: content_hash.to_string(),
            prev_hash: format!("prev_{}", sequence),
            receipt_id: format!("rcpt_{}", sequence),
        }
    }

    #[test]
    fn test_merkle_tree_single_hash() {
        let hashes = vec!["hash1".to_string()];
        let root = compute_merkle_root(&hashes);
        assert_eq!(root, "hash1");
    }

    #[test]
    fn test_merkle_tree_two_hashes() {
        let hashes = vec!["hash1".to_string(), "hash2".to_string()];
        let root = compute_merkle_root(&hashes);
        let expected = blake3::hash(b"hash1:hash2").to_hex().to_string();
        assert_eq!(root, expected);
    }

    #[test]
    fn test_merkle_tree_three_hashes() {
        let hashes = vec![
            "hash1".to_string(),
            "hash2".to_string(),
            "hash3".to_string(),
        ];
        let root = compute_merkle_root(&hashes);

        // With 3 hashes (odd), last hash is duplicated
        // Level 1: [hash1, hash2, hash3, hash3]
        // Level 2: [blake3(hash1:hash2), blake3(hash3:hash3)]
        // Level 3: [blake3(blake3(hash1:hash2):blake3(hash3:hash3))]

        let combined12 = blake3::hash(b"hash1:hash2").to_hex().to_string();
        let combined33 = blake3::hash(b"hash3:hash3").to_hex().to_string();
        let expected = blake3::hash(format!("{}:{}", combined12, combined33).as_bytes())
            .to_hex()
            .to_string();

        assert_eq!(root, expected);
    }

    #[test]
    fn test_merkle_tree_determinism() {
        let hashes = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let root1 = compute_merkle_root(&hashes);
        let root2 = compute_merkle_root(&hashes);
        assert_eq!(root1, root2);
    }

    #[test]
    fn test_merkle_proof_two_hashes() {
        let hashes = vec!["hash1".to_string(), "hash2".to_string()];
        let tree = MerkleTree::from_hashes(&hashes);

        let proof = tree.proof(0).expect("Proof for hash1");
        assert!(proof.verify());

        let proof = tree.proof(1).expect("Proof for hash2");
        assert!(proof.verify());
    }

    #[test]
    fn test_merkle_proof_four_hashes() {
        let hashes = vec![
            "hash1".to_string(),
            "hash2".to_string(),
            "hash3".to_string(),
            "hash4".to_string(),
        ];
        let tree = MerkleTree::from_hashes(&hashes);

        for i in 0..4 {
            let proof = tree.proof(i).expect(&format!("Proof for index {}", i));
            assert!(proof.verify(), "Proof verification failed for index {}", i);
        }
    }

    #[test]
    fn test_merkle_proof_wrong_leaf_fails() {
        let hashes = vec!["hash1".to_string(), "hash2".to_string()];
        let tree = MerkleTree::from_hashes(&hashes);

        let mut proof = tree.proof(0).expect("Proof for hash1");
        proof.leaf_hash = "wrong_hash".to_string();

        assert!(!proof.verify());
    }

    #[test]
    fn test_merkle_proof_tampered_path_fails() {
        let hashes = vec!["hash1".to_string(), "hash2".to_string()];
        let tree = MerkleTree::from_hashes(&hashes);

        let mut proof = tree.proof(0).expect("Proof for hash1");
        if !proof.path.is_empty() {
            proof.path[0].hash = "tampered".to_string();
        }

        assert!(!proof.verify());
    }

    #[test]
    fn test_compact_insufficient_entries() {
        let compactor = EpochCompactor::new(10);
        let entries = vec![make_chain_entry(0, "hash0")];

        let result = compactor.compact("test-chain", &entries, None);
        assert!(matches!(
            result,
            Err(EpochError::InsufficientEntries { .. })
        ));
    }

    #[test]
    fn test_compact_non_contiguous_entries() {
        let compactor = EpochCompactor::new(2);
        let entries = vec![
            make_chain_entry(0, "hash0"),
            make_chain_entry(2, "hash2"), // Gap in sequence
        ];

        let result = compactor.compact("test-chain", &entries, None);
        assert!(matches!(result, Err(EpochError::NonContiguousEntries)));
    }

    #[test]
    fn test_compact_simple() {
        let compactor = EpochCompactor::new(3);
        let entries = vec![
            make_chain_entry(0, "hash0"),
            make_chain_entry(1, "hash1"),
            make_chain_entry(2, "hash2"),
        ];

        let epoch = compactor.compact("test-chain", &entries, None).unwrap();
        assert_eq!(epoch.epoch_number, 0);
        assert_eq!(epoch.first_sequence, 0);
        assert_eq!(epoch.last_sequence, 2);
        assert_eq!(epoch.entry_count, 3);
        assert_eq!(epoch.prev_epoch_hash, "genesis");
        assert_eq!(epoch.chain_id, "test-chain");
        assert!(!epoch.merkle_root.is_empty());
    }

    #[test]
    fn test_compact_100_entries() {
        let compactor = EpochCompactor::new(100);
        let entries: Vec<ReceiptChainEntry> = (0..100)
            .map(|i| make_chain_entry(i, &format!("hash_{}", i)))
            .collect();

        let epoch = compactor.compact("test-chain", &entries, None).unwrap();
        assert_eq!(epoch.epoch_number, 0);
        assert_eq!(epoch.entry_count, 100);
    }

    #[test]
    fn test_compact_chain_linkage() {
        let compactor = EpochCompactor::new(3);

        // First epoch
        let entries1 = vec![
            make_chain_entry(0, "hash0"),
            make_chain_entry(1, "hash1"),
            make_chain_entry(2, "hash2"),
        ];
        let epoch1 = compactor.compact("test-chain", &entries1, None).unwrap();

        // Second epoch
        let entries2 = vec![
            make_chain_entry(3, "hash3"),
            make_chain_entry(4, "hash4"),
            make_chain_entry(5, "hash5"),
        ];
        let epoch2 = compactor
            .compact("test-chain", &entries2, Some(&epoch1))
            .unwrap();

        assert_eq!(epoch2.epoch_number, 1);
        assert_eq!(epoch2.prev_epoch_hash, epoch1.merkle_root);
    }

    #[test]
    fn test_verify_epoch_correct() {
        let compactor = EpochCompactor::new(3);
        let entries = vec![
            make_chain_entry(0, "hash0"),
            make_chain_entry(1, "hash1"),
            make_chain_entry(2, "hash2"),
        ];

        let epoch = compactor.compact("test-chain", &entries, None).unwrap();
        assert!(compactor.verify_epoch(&epoch, &entries).is_ok());
    }

    #[test]
    fn test_verify_epoch_wrong_entries() {
        let compactor = EpochCompactor::new(3);
        let entries = vec![
            make_chain_entry(0, "hash0"),
            make_chain_entry(1, "hash1"),
            make_chain_entry(2, "hash2"),
        ];

        let epoch = compactor.compact("test-chain", &entries, None).unwrap();

        let wrong_entries = vec![
            make_chain_entry(0, "wrong0"),
            make_chain_entry(1, "wrong1"),
            make_chain_entry(2, "wrong2"),
        ];

        assert!(compactor.verify_epoch(&epoch, &wrong_entries).is_err());
    }

    #[test]
    fn test_verify_epoch_chain_valid() {
        let compactor = EpochCompactor::new(3);

        let entries1 = vec![
            make_chain_entry(0, "hash0"),
            make_chain_entry(1, "hash1"),
            make_chain_entry(2, "hash2"),
        ];
        let epoch1 = compactor.compact("test-chain", &entries1, None).unwrap();

        let entries2 = vec![
            make_chain_entry(3, "hash3"),
            make_chain_entry(4, "hash4"),
            make_chain_entry(5, "hash5"),
        ];
        let epoch2 = compactor
            .compact("test-chain", &entries2, Some(&epoch1))
            .unwrap();

        let epochs = vec![epoch1, epoch2];
        assert!(compactor.verify_epoch_chain(&epochs).is_ok());
    }

    #[test]
    fn test_verify_epoch_chain_broken_linkage() {
        let compactor = EpochCompactor::new(3);

        let entries1 = vec![
            make_chain_entry(0, "hash0"),
            make_chain_entry(1, "hash1"),
            make_chain_entry(2, "hash2"),
        ];
        let epoch1 = compactor.compact("test-chain", &entries1, None).unwrap();

        let entries2 = vec![
            make_chain_entry(3, "hash3"),
            make_chain_entry(4, "hash4"),
            make_chain_entry(5, "hash5"),
        ];
        let mut epoch2 = compactor
            .compact("test-chain", &entries2, Some(&epoch1))
            .unwrap();

        // Tamper with linkage
        epoch2.prev_epoch_hash = "tampered".to_string();

        let epochs = vec![epoch1, epoch2];
        assert!(compactor.verify_epoch_chain(&epochs).is_err());
    }

    #[test]
    fn test_verify_epoch_chain_wrong_genesis() {
        let compactor = EpochCompactor::new(3);

        let entries1 = vec![
            make_chain_entry(0, "hash0"),
            make_chain_entry(1, "hash1"),
            make_chain_entry(2, "hash2"),
        ];
        let mut epoch1 = compactor.compact("test-chain", &entries1, None).unwrap();

        // Tamper with genesis
        epoch1.prev_epoch_hash = "not-genesis".to_string();

        let epochs = vec![epoch1];
        assert!(compactor.verify_epoch_chain(&epochs).is_err());
    }

    #[test]
    fn test_should_compact_false() {
        let compactor = EpochCompactor::new(100);
        let epochs = vec![];
        assert!(!compactor.should_compact(50, &epochs));
    }

    #[test]
    fn test_should_compact_true() {
        let compactor = EpochCompactor::new(100);
        let epochs = vec![];
        assert!(compactor.should_compact(150, &epochs));
    }

    #[test]
    fn test_should_compact_with_existing_epochs() {
        let compactor = EpochCompactor::new(100);

        // One epoch with 100 entries
        let epoch1 = Epoch {
            epoch_number: 0,
            merkle_root: "root1".to_string(),
            prev_epoch_hash: "genesis".to_string(),
            first_sequence: 0,
            last_sequence: 99,
            entry_count: 100,
            sealed_at: Utc::now(),
            chain_id: "test".to_string(),
        };

        // 150 total entries means 50 uncompacted, not enough
        assert!(!compactor.should_compact(150, &[epoch1.clone()]));

        // 250 total entries means 150 uncompacted, enough
        assert!(compactor.should_compact(250, &[epoch1]));
    }

    #[test]
    fn test_epoch_serialization() {
        let epoch = Epoch {
            epoch_number: 42,
            merkle_root: "abc123".to_string(),
            prev_epoch_hash: "prev123".to_string(),
            first_sequence: 0,
            last_sequence: 99,
            entry_count: 100,
            sealed_at: Utc::now(),
            chain_id: "test-chain".to_string(),
        };

        let json = serde_json::to_string(&epoch).unwrap();
        let deserialized: Epoch = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.epoch_number, 42);
        assert_eq!(deserialized.entry_count, 100);
    }

    #[test]
    fn test_merkle_proof_serialization() {
        let proof = MerkleProof {
            leaf_hash: "leaf".to_string(),
            leaf_index: 0,
            path: vec![
                ProofStep {
                    hash: "hash1".to_string(),
                    direction: Direction::Right,
                },
                ProofStep {
                    hash: "hash2".to_string(),
                    direction: Direction::Left,
                },
            ],
            root: "root".to_string(),
        };

        let json = serde_json::to_string(&proof).unwrap();
        let deserialized: MerkleProof = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.leaf_hash, "leaf");
        assert_eq!(deserialized.path.len(), 2);
    }
}
