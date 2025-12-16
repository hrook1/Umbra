use serde::{Deserialize, Serialize};
use crate::merkle::MerkleProof;
use crate::note::Note;

/// Public inputs that the chain/host provides to the SP1 program.
///
/// # Purpose
/// These inputs are known to both the prover and verifier (Ethereum).
/// They represent the state that must be validated by the proof.
///
/// # Security Properties
/// - `old_root`: Must match the current state root on-chain
/// - Acts as a commitment to the pre-transaction state
/// - Prevents transaction replay by anchoring to specific tree state
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicInputs {
    /// Merkle root before applying this transaction.
    ///
    /// This must match `currentRoot` on the Ethereum contract.
    /// Ensures the transaction is built against the correct state.
    pub old_root: [u8; 32],
}

impl PublicInputs {
    /// Create new public inputs with the given old root.
    pub fn new(old_root: [u8; 32]) -> Self {
        Self { old_root }
    }

    /// Check if this represents an empty tree state.
    pub fn is_empty_tree(&self) -> bool {
        self.old_root == [0u8; 32]
    }
}

/// Private witness that only the prover (SP1) sees.
///
/// # Privacy Model
/// - Input notes: Revealed to prover, hidden from verifier
/// - Output notes: Commitments published, full notes remain private
/// - Merkle proofs: Private, used only to generate the proof
///
/// # Validation Requirements
/// The SP1 program must verify:
/// 1. Each input_index corresponds to a valid leaf in the tree
/// 2. Each input_proof correctly proves inclusion
/// 3. Prover knows the spend_secret for each input note
/// 4. Output notes are well-formed
/// 5. Value is conserved (sum of inputs ≥ sum of outputs)
///
/// # Performance Optimization
/// Expensive operations (ECDSA, nullifier computation) are precomputed on the host
/// and passed in the witness. The zkVM only verifies these against recomputed hashes.
///
/// In Phase 1, we keep this simple. In production, additional checks include:
/// - Signature verification
/// - Range proofs for amounts
/// - Fee computation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Witness {
    /// The actual input notes being spent.
    ///
    /// These are private to the prover. Only their nullifiers
    /// will be revealed in the public outputs.
    pub input_notes: Vec<Note>,

    /// Indices where each input note lives in the Merkle tree.
    ///
    /// Used to:
    /// - Compute nullifiers (nullifier = hash(spend_secret, index))
    /// - Verify Merkle proofs
    pub input_indices: Vec<usize>,

    /// Merkle proofs proving each input note exists in the tree.
    ///
    /// Must correspond 1:1 with input_notes and input_indices.
    /// In Phase 1, these may be empty if we're not yet validating proofs.
    pub input_proofs: Vec<MerkleProof>,

    /// Signatures used to derive the nullifier (Privacy).
    ///
    /// Signs the input note commitment.
    /// Format: 65 bytes [r (32), s (32), v (1)]
    pub nullifier_signatures: Vec<Vec<u8>>,

    /// Signatures used to authorize the transaction (Anti-Theft).
    ///
    /// Signs the transaction hash (nullifier + outputs).
    /// Format: 65 bytes [r (32), s (32), v (1)]
    pub tx_signatures: Vec<Vec<u8>>,

    /// New notes being created by this transaction.
    ///
    /// Only their commitments will be published. The full note data
    /// (including blinding) remains private.
    pub output_notes: Vec<Note>,

    // =========================================================================
    // PRECOMPUTED VALUES (Performance Optimization)
    // These are computed on the host to avoid expensive operations inside zkVM.
    // The zkVM verifies these match what it can recompute using fast hashing.
    // =========================================================================

    /// Precomputed nullifiers for each input note.
    ///
    /// Computed on host as: hash(NULLIFIER_DOMAIN || owner_privkey || commitment)
    /// The zkVM recomputes and verifies these match.
    #[serde(default)]
    pub precomputed_nullifiers: Vec<[u8; 32]>,

    /// Precomputed commitments for each input note.
    ///
    /// Computed on host as: hash(NOTE_COMMITMENT_DOMAIN || amount || owner_pubkey || blinding)
    /// The zkVM verifies these match note.commitment().
    #[serde(default)]
    pub precomputed_input_commitments: Vec<[u8; 32]>,

    /// Precomputed commitments for each output note.
    ///
    /// Computed on host to avoid redundant hashing inside zkVM.
    #[serde(default)]
    pub precomputed_output_commitments: Vec<[u8; 32]>,
}

impl Witness {
    /// Create a new witness with the given inputs and outputs.
    ///
    /// # Parameters
    /// - `input_notes`: Notes being spent
    /// - `input_indices`: Tree positions of input notes
    /// - `input_proofs`: Merkle proofs for each input
    /// - `nullifier_signatures`: Signatures for nullifier derivation
    /// - `tx_signatures`: Signatures for transaction authorization
    /// - `output_notes`: New notes being created
    pub fn new(
        input_notes: Vec<Note>,
        input_indices: Vec<usize>,
        input_proofs: Vec<MerkleProof>,
        nullifier_signatures: Vec<Vec<u8>>,
        tx_signatures: Vec<Vec<u8>>,
        output_notes: Vec<Note>,
    ) -> Self {
        Self {
            input_notes,
            input_indices,
            input_proofs,
            nullifier_signatures,
            tx_signatures,
            output_notes,
            precomputed_nullifiers: Vec::new(),
            precomputed_input_commitments: Vec::new(),
            precomputed_output_commitments: Vec::new(),
        }
    }

    /// Create a simple witness without Merkle proofs (Phase 1).
    pub fn new_without_proofs(
        input_notes: Vec<Note>,
        input_indices: Vec<usize>,
        nullifier_signatures: Vec<Vec<u8>>,
        tx_signatures: Vec<Vec<u8>>,
        output_notes: Vec<Note>,
    ) -> Self {
        Self {
            input_notes,
            input_indices,
            input_proofs: Vec::new(),
            nullifier_signatures,
            tx_signatures,
            output_notes,
            precomputed_nullifiers: Vec::new(),
            precomputed_input_commitments: Vec::new(),
            precomputed_output_commitments: Vec::new(),
        }
    }

    /// Create a witness with precomputed values.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_precomputed(
        input_notes: Vec<Note>,
        input_indices: Vec<usize>,
        input_proofs: Vec<MerkleProof>,
        nullifier_signatures: Vec<Vec<u8>>,
        tx_signatures: Vec<Vec<u8>>,
        output_notes: Vec<Note>,
        precomputed_nullifiers: Vec<[u8; 32]>,
        precomputed_input_commitments: Vec<[u8; 32]>,
        precomputed_output_commitments: Vec<[u8; 32]>,
    ) -> Self {
        Self {
            input_notes,
            input_indices,
            input_proofs,
            nullifier_signatures,
            tx_signatures,
            output_notes,
            precomputed_nullifiers,
            precomputed_input_commitments,
            precomputed_output_commitments,
        }
    }

    /// Check if this witness has precomputed values.
    ///
    /// Returns true if precomputed nullifiers and commitments are provided.
    pub fn has_precomputed_values(&self) -> bool {
        !self.precomputed_nullifiers.is_empty()
            && self.precomputed_nullifiers.len() == self.input_notes.len()
            && self.precomputed_input_commitments.len() == self.input_notes.len()
            && self.precomputed_output_commitments.len() == self.output_notes.len()
    }

    /// Validate the witness structure (not cryptographic validation).
    ///
    /// Checks:
    /// - Input notes, indices, and proofs have matching lengths (if proofs provided)
    /// - No empty inputs or outputs (unless explicitly allowed)
    ///
    /// # Returns
    /// `Ok(())` if structure is valid, `Err` with description otherwise.
    pub fn validate_structure(&self) -> Result<(), String> {
        // Check inputs match
        if self.input_notes.len() != self.input_indices.len() {
            return Err(format!(
                "Mismatched input lengths: {} notes vs {} indices",
                self.input_notes.len(),
                self.input_indices.len()
            ));
        }

        // Check nullifier signatures match inputs
        if self.input_notes.len() != self.nullifier_signatures.len() {
            return Err(format!(
                "Mismatched nullifier signature count: {} signatures for {} inputs",
                self.nullifier_signatures.len(),
                self.input_notes.len()
            ));
        }

        // Check tx signatures match inputs
        if self.input_notes.len() != self.tx_signatures.len() {
            return Err(format!(
                "Mismatched tx signature count: {} signatures for {} inputs",
                self.tx_signatures.len(),
                self.input_notes.len()
            ));
        }

        // If proofs are provided, they must match input count
        if !self.input_proofs.is_empty() && self.input_proofs.len() != self.input_notes.len() {
            return Err(format!(
                "Mismatched proof count: {} proofs for {} inputs",
                self.input_proofs.len(),
                self.input_notes.len()
            ));
        }

        // Transactions should have at least one input or output
        if self.input_notes.is_empty() && self.output_notes.is_empty() {
            return Err("Transaction must have at least one input or output".to_string());
        }

        Ok(())
    }

    /// Get the number of inputs being spent.
    pub fn input_count(&self) -> usize {
        self.input_notes.len()
    }

    /// Get the number of outputs being created.
    pub fn output_count(&self) -> usize {
        self.output_notes.len()
    }

    /// Calculate total input value.
    pub fn total_input_value(&self) -> u64 {
        self.input_notes.iter().map(|n| n.amount).sum()
    }

    /// Calculate total output value.
    pub fn total_output_value(&self) -> u64 {
        self.output_notes.iter().map(|n| n.amount).sum()
    }

    /// Check if this is a mint transaction (no inputs).
    pub fn is_mint(&self) -> bool {
        self.input_notes.is_empty()
    }

    /// Check if this is a burn transaction (no outputs).
    pub fn is_burn(&self) -> bool {
        self.output_notes.is_empty()
    }

    /// Validate value conservation.
    ///
    /// In a real system, you'd allow inputs > outputs (the difference is a fee).
    /// For Phase 1, we can enforce exact balance.
    pub fn validate_value_conservation(&self) -> Result<(), String> {
        let input_total = self.total_input_value();
        let output_total = self.total_output_value();

        if input_total < output_total {
            return Err(format!(
                "Insufficient input value: {} < {} outputs",
                input_total, output_total
            ));
        }

        Ok(())
    }

    /// Compute and populate precomputed values for optimized proving.
    ///
    /// This method should be called on the HOST before passing the witness
    /// to the SP1 prover. It precomputes:
    /// - Input commitments (from note data)
    /// - Nullifiers (from private keys + commitments)
    /// - Output commitments (from note data)
    ///
    /// This allows the zkVM to verify precomputed values using fast Blake3
    /// hashing instead of expensive ECDSA operations.
    ///
    /// # Returns
    /// A new Witness with precomputed values populated.
    pub fn with_precomputed_values(mut self) -> Self {
        use crate::note::commit;

        // Compute input commitments
        self.precomputed_input_commitments = self
            .input_notes
            .iter()
            .map(|note| commit(note))
            .collect();

        // Compute nullifiers (Airtight: Hash(Sig))
        // We use the provided nullifier signatures.
        self.precomputed_nullifiers = self
            .nullifier_signatures
            .iter()
            .map(|sig| crate::note::compute_nullifier(sig))
            .collect();

        // Compute output commitments
        self.precomputed_output_commitments = self
            .output_notes
            .iter()
            .map(|note| commit(note))
            .collect();

        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "encryption")]
    use crate::encryption::generate_keypair;

    fn dummy_note(amount: u64) -> (Note, [u8; 32]) {
        #[cfg(feature = "encryption")]
        let (key, pubkey) = generate_keypair();
        #[cfg(not(feature = "encryption"))]
        let (key, pubkey) = ([1u8; 32], [2u8; 32]);

        let mut owner_pubkey = [0u8; 32];
        owner_pubkey.copy_from_slice(&pubkey[1..]);

        (Note::new(amount, owner_pubkey, [2; 32]), key)
    }

    #[test]
    fn test_public_inputs_creation() {
        let root = [42u8; 32];
        let inputs = PublicInputs::new(root);
        assert_eq!(inputs.old_root, root);
        assert!(!inputs.is_empty_tree());
    }

    #[test]
    fn test_empty_tree_detection() {
        let empty = PublicInputs::new([0u8; 32]);
        assert!(empty.is_empty_tree());
    }

    #[test]
    fn test_witness_without_proofs() {
        let (input, _key) = dummy_note(100);
        let (out1, _) = dummy_note(60);
        let (out2, _) = dummy_note(40);
        let sigs = vec![vec![0u8; 65]];
        
        let witness = Witness::new_without_proofs(
            vec![input],
            vec![0],
            sigs.clone(), // nullifier_signatures
            sigs,         // tx_signatures
            vec![out1, out2]
        );
        
        assert_eq!(witness.input_count(), 1);
        assert_eq!(witness.output_count(), 2);
        assert_eq!(witness.total_input_value(), 100);
        assert_eq!(witness.total_output_value(), 100);
    }

    #[test]
    fn test_witness_validation() {
        let (input, _key) = dummy_note(100);
        let (out, _) = dummy_note(100);
        let sigs = vec![vec![0u8; 65]];

        let witness = Witness::new_without_proofs(
            vec![input],
            vec![0],
            sigs.clone(),
            sigs,
            vec![out],
        );
        
        assert!(witness.validate_structure().is_ok());
        assert!(witness.validate_value_conservation().is_ok());
    }

    #[test]
    fn test_mismatched_input_lengths() {
        let (input, _key) = dummy_note(100);
        let (out, _) = dummy_note(100);
        let sigs = vec![vec![0u8; 65]];

        let witness = Witness::new_without_proofs(
            vec![input],
            vec![0, 1], // Too many indices
            sigs.clone(),
            sigs,
            vec![out],
        );
        
        assert!(witness.validate_structure().is_err());
    }

    #[test]
    fn test_insufficient_value() {
        let (input, _key) = dummy_note(50);
        let (out, _) = dummy_note(100);
        let sigs = vec![vec![0u8; 65]];

        let witness = Witness::new_without_proofs(
            vec![input], // Only 50 input
            vec![0],
            sigs.clone(),
            sigs,
            vec![out], // Trying to create 100 output
        );
        
        assert!(witness.validate_value_conservation().is_err());
    }

    #[test]
    fn test_mint_transaction() {
        let (out, _) = dummy_note(100);

        let witness = Witness::new_without_proofs(
            vec![], // No inputs
            vec![],
            vec![],
            vec![],
            vec![out],
        );
        
        assert!(witness.is_mint());
        assert!(!witness.is_burn());
    }
    
    #[test]
    fn test_burn_transaction() {
        let (input, _key) = dummy_note(100);
        let sigs = vec![vec![0u8; 65]];

        let witness = Witness::new_without_proofs(
            vec![input],
            vec![0],
            sigs.clone(),
            sigs,
            vec![], // No outputs
        );

        assert!(witness.is_burn());
        assert!(!witness.is_mint());
    }

    #[test]
    fn test_with_precomputed_values() {
        use crate::note::commit;

        let (input, key) = dummy_note(100);
        let (out1, _) = dummy_note(60);
        let (out2, _) = dummy_note(40);
        let sigs = vec![vec![1u8; 65]]; // Dummy signature

        let witness = Witness::new_without_proofs(
            vec![input.clone()],
            vec![0],
            sigs.clone(),
            sigs.clone(),
            vec![out1.clone(), out2.clone()],
        );

        // Before: no precomputed values
        assert!(!witness.has_precomputed_values());

        // After: has precomputed values
        let witness = witness.with_precomputed_values();
        assert!(witness.has_precomputed_values());

        // Verify precomputed values are correct
        let expected_input_commitment = commit(&input);
        // compute_nullifier now uses signature (sigs[0])
        let expected_nullifier = crate::note::compute_nullifier(&sigs[0]);
        let expected_out1_commitment = commit(&out1);
        let expected_out2_commitment = commit(&out2);

        assert_eq!(witness.precomputed_input_commitments.len(), 1);
        assert_eq!(witness.precomputed_input_commitments[0], expected_input_commitment);

        assert_eq!(witness.precomputed_nullifiers.len(), 1);
        assert_eq!(witness.precomputed_nullifiers[0], expected_nullifier);

        assert_eq!(witness.precomputed_output_commitments.len(), 2);
        assert_eq!(witness.precomputed_output_commitments[0], expected_out1_commitment);
        assert_eq!(witness.precomputed_output_commitments[1], expected_out2_commitment);
    }
}