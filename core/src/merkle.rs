use blake3::Hasher;
use serde::{Deserialize, Serialize};
use crate::note::commit;

const MERKLE_NODE_DOMAIN: &[u8] = b"MERKLE_NODE_v1";

/// A simple Merkle tree that stores leaf hashes and computes roots.
///
/// # Design Notes
/// - Leaves are note commitments (32-byte hashes)
/// - Uses a simple, unbalanced tree structure for Phase 1
/// - Duplicates last node if odd number at any level (Bitcoin-style)
///
/// # Security Properties
/// - Domain separation prevents second-preimage attacks
/// - Deterministic root computation ensures consensus
///
/// HIGH-LEVEL: Models the "global state commitment" on Ethereum (currentRoot).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MerkleTree {
    leaves: Vec<[u8; 32]>,
}

/// A Merkle proof proves a leaf exists at a given index.
///
/// # Structure
/// - `leaf_index`: Position of the leaf in the tree
/// - `siblings`: Hashes needed to compute path from leaf to root
///
/// # Verification
/// Start with the leaf, hash with each sibling moving up the tree,
/// final result should equal the root.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    pub leaf_index: u64,
    pub siblings: Vec<[u8; 32]>,
}

impl MerkleTree {
    /// Create a new empty Merkle tree.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a Merkle tree with initial leaves.
    pub fn with_leaves(leaves: Vec<[u8; 32]>) -> Self {
        Self { leaves }
    }

    /// Add a new leaf hash (a commitment) to the tree.
    ///
    /// Returns the index where the leaf was inserted.
    pub fn push_leaf(&mut self, leaf: [u8; 32]) -> u64 {
        let index = self.leaves.len() as u64;
        self.leaves.push(leaf);
        index
    }

    /// Convenience helper: push a commitment for a note.
    ///
    /// Returns the leaf index where the note commitment was inserted.
    pub fn push_note(&mut self, note: &crate::note::Note) -> u64 {
        self.push_leaf(commit(note))
    }

    /// Get the number of leaves in the tree.
    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
    }

    /// Get a leaf at a specific index.
    pub fn get_leaf(&self, index: usize) -> Option<[u8; 32]> {
        self.leaves.get(index).copied()
    }

    /// Get all leaves (useful for debugging or snapshots).
    pub fn leaves(&self) -> &[[u8; 32]] {
        &self.leaves
    }

    /// Compute the Merkle root of the current leaves.
    ///
    /// # Empty Tree
    /// Returns 32 zero bytes if the tree is empty.
    ///
    /// # Algorithm
    /// Standard Merkle tree construction:
    /// 1. Start with leaves as the bottom level
    /// 2. Hash pairs of nodes to create next level
    /// 3. If odd number, duplicate last node
    /// 4. Repeat until one node remains (the root)
    pub fn root(&self) -> [u8; 32] {
        if self.leaves.is_empty() {
            return [0u8; 32];
        }

        if self.leaves.len() == 1 {
            return self.leaves[0];
        }

        // Work on a local buffer of hashes we reduce level by level.
        let mut level = self.leaves.clone();

        while level.len() > 1 {
            level = Self::compute_next_level(&level);
        }

        // Now level has exactly one element: the root.
        level[0]
    }

    /// Compute the next level of the tree from the current level.
    fn compute_next_level(level: &[[u8; 32]]) -> Vec<[u8; 32]> {
        let mut next_level = Vec::with_capacity((level.len() + 1) / 2);

        for chunk in level.chunks(2) {
            let left = chunk[0];
            let right = chunk.get(1).copied().unwrap_or(left); // Duplicate last if odd
            next_level.push(hash_internal_node(left, right));
        }

        next_level
    }

    /// Generate a Merkle proof for a leaf at the given index.
    ///
    /// # Returns
    /// - `Some(MerkleProof)` if the index is valid
    /// - `None` if the index is out of bounds
    ///
    /// # Usage
    /// The proof allows anyone to verify that a leaf exists in the tree
    /// without needing all the leaves. This is what SP1 will use.
    pub fn prove(&self, leaf_index: usize) -> Option<MerkleProof> {
        if leaf_index >= self.leaves.len() {
            return None;
        }

        let mut siblings = Vec::new();
        let mut level = self.leaves.clone();
        let mut index = leaf_index;

        while level.len() > 1 {
            // Determine sibling index
            let sibling_index = if index % 2 == 0 {
                // We're on the left, sibling is on the right
                if index + 1 < level.len() {
                    index + 1
                } else {
                    index // Duplicate if we're the last odd node
                }
            } else {
                // We're on the right, sibling is on the left
                index - 1
            };

            siblings.push(level[sibling_index]);

            // Move to next level
            level = Self::compute_next_level(&level);
            index /= 2;
        }

        Some(MerkleProof {
            leaf_index: leaf_index as u64,
            siblings,
        })
    }

    /// Verify a Merkle proof against a given root.
    ///
    /// # Parameters
    /// - `leaf`: The leaf hash to verify
    /// - `proof`: The Merkle proof
    /// - `expected_root`: The root to verify against
    ///
    /// # Returns
    /// `true` if the proof is valid, `false` otherwise
    pub fn verify_proof(
        leaf: [u8; 32],
        proof: &MerkleProof,
        expected_root: [u8; 32],
    ) -> bool {
        let mut current = leaf;
        let mut index = proof.leaf_index;

        for sibling in &proof.siblings {
            current = if index % 2 == 0 {
                // We're on the left
                hash_internal_node(current, *sibling)
            } else {
                // We're on the right
                hash_internal_node(*sibling, current)
            };
            index /= 2;
        }

        current == expected_root
    }
}

/// Hash two child nodes into a parent node.
///
/// # Domain Separation
/// Uses "MERKLE_NODE_v1" prefix to prevent hash collisions with other
/// protocol components (commitments, nullifiers, etc.).
///
/// HIGH-LEVEL: This is the hash rule for the Merkle tree. Both SP1 and
/// any indexers must follow the exact same rule for consensus.
fn hash_internal_node(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(MERKLE_NODE_DOMAIN);
    hasher.update(&left);
    hasher.update(&right);
    let hash = hasher.finalize();
    *hash.as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_tree_root() {
        let tree = MerkleTree::new();
        assert_eq!(tree.root(), [0u8; 32]);
    }

    #[test]
    fn test_single_leaf_root() {
        let mut tree = MerkleTree::new();
        let leaf = [1u8; 32];
        tree.push_leaf(leaf);
        assert_eq!(tree.root(), leaf);
    }

    #[test]
    fn test_two_leaves() {
        let mut tree = MerkleTree::new();
        let leaf1 = [1u8; 32];
        let leaf2 = [2u8; 32];
        tree.push_leaf(leaf1);
        tree.push_leaf(leaf2);

        let expected_root = hash_internal_node(leaf1, leaf2);
        assert_eq!(tree.root(), expected_root);
    }

    #[test]
    fn test_odd_number_of_leaves() {
        let mut tree = MerkleTree::new();
        let leaf1 = [1u8; 32];
        let leaf2 = [2u8; 32];
        let leaf3 = [3u8; 32];
        
        tree.push_leaf(leaf1);
        tree.push_leaf(leaf2);
        tree.push_leaf(leaf3);

        // Should duplicate leaf3 when computing the level
        let root = tree.root();
        assert_ne!(root, [0u8; 32], "Root should be non-zero");
    }

    #[test]
    fn test_proof_generation_and_verification() {
        let mut tree = MerkleTree::new();
        let leaves = [[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
        
        for leaf in leaves {
            tree.push_leaf(leaf);
        }

        let root = tree.root();

        // Test proof for each leaf
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.prove(i).expect("Should generate proof");
            assert!(
                MerkleTree::verify_proof(*leaf, &proof, root),
                "Proof for leaf {} should verify",
                i
            );
        }
    }

    #[test]
    fn test_invalid_proof_fails() {
        let mut tree = MerkleTree::new();
        tree.push_leaf([1u8; 32]);
        tree.push_leaf([2u8; 32]);

        let root = tree.root();
        let proof = tree.prove(0).unwrap();

        // Try to verify with wrong leaf
        let wrong_leaf = [99u8; 32];
        assert!(
            !MerkleTree::verify_proof(wrong_leaf, &proof, root),
            "Proof with wrong leaf should fail"
        );
    }

    #[test]
    fn test_leaf_index_tracking() {
        let mut tree = MerkleTree::new();
        
        let index1 = tree.push_leaf([1u8; 32]);
        let index2 = tree.push_leaf([2u8; 32]);
        let index3 = tree.push_leaf([3u8; 32]);

        assert_eq!(index1, 0);
        assert_eq!(index2, 1);
        assert_eq!(index3, 2);
    }

    #[test]
    fn test_get_leaf() {
        let mut tree = MerkleTree::new();
        let leaf = [42u8; 32];
        tree.push_leaf(leaf);

        assert_eq!(tree.get_leaf(0), Some(leaf));
        assert_eq!(tree.get_leaf(1), None);
    }
}