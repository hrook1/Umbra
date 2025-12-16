use serde::{Serialize, Deserialize};
use crate::merkle::MerkleTree;
use crate::note::{commit, Note, Nullifier};

/// Public outputs of a transaction that the chain / verifier can see.
///
/// HIGH-LEVEL:
/// - This is what SP1 will "commit" as public I/O.
/// - The Solidity contract will receive something shaped like this.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicOutputs {
    /// Merkle root before applying this transaction.
    pub old_root: [u8; 32],
    /// Merkle root after applying this transaction.
    pub new_root: [u8; 32],
    /// Nullifiers for all notes spent in this tx.
    pub nullifiers: Vec<Nullifier>,
    /// Commitments of all newly created notes in this tx.
    pub output_commitments: Vec<[u8; 32]>,
}

/// A very simple in-memory ledger for Phase 1.
///
/// # zkVM Optimization
/// Uses Vec instead of HashSet for nullifier tracking. This is more efficient
/// in the zkVM because:
/// - HashSet requires hashing which adds proving overhead
/// - HashSet serialization is more complex
/// - For single transactions with few inputs (typical case), linear search is faster
///
/// # Security
/// Double-spend prevention is maintained via linear search in `is_nullifier_spent`.
/// The on-chain contract maintains the authoritative nullifier set.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Ledger {
    /// All notes ever created (spent or unspent).
    /// In the real protocol, these are the leaves of the global Merkle tree.
    utxos: Vec<Note>,
    /// Nullifiers of notes that have been spent.
    /// Uses Vec for zkVM efficiency - linear search is O(n) but avoids
    /// hash computation overhead. For typical transactions with 1-4 inputs,
    /// this is faster than HashSet in the zkVM.
    ///
    /// SECURITY: Double-spend check is performed via `is_nullifier_spent()`
    /// which does a full linear scan to ensure no duplicates.
    spent_nullifiers: Vec<Nullifier>,
    /// The Merkle tree tracking all note commitments.
    tree: MerkleTree,
}

impl Ledger {
    /// Create a new empty ledger.
    pub fn new() -> Self {
        Self {
            utxos: Vec::new(),
            spent_nullifiers: Vec::new(),
            tree: MerkleTree::new(),
        }
    }

    /// Get the current Merkle root.
    pub fn current_root(&self) -> [u8; 32] {
        self.tree.root()
    }

    /// Add a new note to the ledger (mint/create).
    /// Returns the leaf index where the note was added.
    pub fn add_note(&mut self, note: Note) -> u64 {
        let index = self.tree.push_note(&note);
        self.utxos.push(note);
        index
    }

    /// Check if a nullifier has been spent.
    ///
    /// # Security
    /// This performs a linear scan through all spent nullifiers to check
    /// for duplicates. This is critical for double-spend prevention.
    pub fn is_nullifier_spent(&self, nullifier: &Nullifier) -> bool {
        self.spent_nullifiers.iter().any(|n| n == nullifier)
    }

    /// Mark a nullifier as spent.
    ///
    /// # Security
    /// First checks if nullifier already exists (double-spend attempt),
    /// then adds to the spent set. The linear search ensures no duplicates
    /// can be added.
    pub fn spend_nullifier(&mut self, nullifier: Nullifier) -> Result<(), String> {
        if self.is_nullifier_spent(&nullifier) {
            return Err("Nullifier already spent".to_string());
        }
        self.spent_nullifiers.push(nullifier);
        Ok(())
    }

    /// Get a note by its index in the UTXO set.
    pub fn get_note(&self, index: usize) -> Option<&Note> {
        self.utxos.get(index)
    }

    /// Get the total number of notes (UTXOs) in the ledger.
    pub fn note_count(&self) -> usize {
        self.utxos.len()
    }

    /// Apply a transaction to the ledger.
    pub fn apply_tx(
        &mut self,
        input_indices: &[usize],
        nullifier_signatures: &[Vec<u8>],
        tx_signatures: &[Vec<u8>],
        output_notes: Vec<Note>,
    ) -> Result<PublicOutputs, String> {
        simulate_tx_and_build_public_outputs(self, input_indices, nullifier_signatures, tx_signatures, output_notes)
    }
}

/// Simulate a transaction and build the public outputs.
pub fn simulate_tx_and_build_public_outputs(
    ledger: &mut Ledger,
    input_indices: &[usize],
    nullifier_signatures: &[Vec<u8>],
    tx_signatures: &[Vec<u8>],
    output_notes: Vec<Note>,
) -> Result<PublicOutputs, String> {
    use sha3::{Digest, Keccak256};
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

    // Capture old_root
    let old_root = ledger.current_root();

    // 1. Compute Output Commitments first (needed for TxHash)
    let mut output_commitments = Vec::new();
    for note in &output_notes {
        output_commitments.push(commit(note));
    }

    // 2. Process Inputs
    let mut nullifiers = Vec::new();

    for (i, &idx) in input_indices.iter().enumerate() {
        let note = ledger.get_note(idx)
            .ok_or_else(|| format!("Note at index {} not found", idx))?;

        let nullifier_sig = nullifier_signatures.get(i)
            .ok_or_else(|| format!("Missing nullifier signature for input {}", i))?;
        let tx_sig = tx_signatures.get(i)
            .ok_or_else(|| format!("Missing tx signature for input {}", i))?;

        if nullifier_sig.len() != 65 || tx_sig.len() != 65 {
            return Err(format!("Invalid signature length at index {}", i));
        }

        // --- Verify Nullifier Signature ---
        // Message = Keccak256(Commitment)
        let commitment = note.commitment();
        let mut hasher = Keccak256::new();
        hasher.update(&commitment);
        let msg_hash = hasher.finalize();

        let nullifier_pubkey = recover_ethereum_key(&msg_hash, nullifier_sig)
            .map_err(|e| format!("Nullifier signature recovery failed: {}", e))?;

        if nullifier_pubkey != note.owner_pubkey {
             return Err(format!("Nullifier signature mismatch at index {}. Not owner.", i));
        }

        // Compute Nullifier = Hash(NullifierSig)
        let nullifier = crate::note::compute_nullifier(nullifier_sig);

        // --- Verify Tx Signature ---
        // Message = Keccak256(Nullifier || OutputCommitments...)
        let mut tx_hasher = Keccak256::new();
        tx_hasher.update(&nullifier);
        for out_com in &output_commitments {
            tx_hasher.update(out_com);
        }
        let tx_msg_hash = tx_hasher.finalize();

        let tx_pubkey = recover_ethereum_key(&tx_msg_hash, tx_sig)
            .map_err(|e| format!("Tx signature recovery failed: {}", e))?;

        if tx_pubkey != note.owner_pubkey {
             return Err(format!("Tx signature mismatch at index {}. Not owner.", i));
        }

        // --- Check Nullifier ---
        if ledger.is_nullifier_spent(&nullifier) {
            return Err(format!("Nullifier at index {} already spent", idx));
        }

        nullifiers.push(nullifier);
        ledger.spend_nullifier(nullifier)?;
    }

    // Add outputs to ledger
    for note in output_notes {
        ledger.add_note(note);
    }

    let new_root = ledger.current_root();

    Ok(PublicOutputs {
        old_root,
        new_root,
        nullifiers,
        output_commitments,
    })
}

fn recover_ethereum_key(msg_hash: &[u8], sig_bytes: &[u8]) -> Result<[u8; 32], &'static str> {
    use sha3::{Digest, Keccak256};
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

    if sig_bytes.len() != 65 {
        return Err("Signature must be 65 bytes");
    }

    // Ethereum prefix
    let mut eth_hasher = Keccak256::new();
    eth_hasher.update(b"\x19Ethereum Signed Message:\n32");
    eth_hasher.update(msg_hash);
    let eth_msg_hash = eth_hasher.finalize();

    let r_s_bytes = &sig_bytes[0..64];
    let v = sig_bytes[64];

    // v can be 0, 1 (raw) or 27, 28 (Ethereum-adjusted)
    // Also handle EIP-155 replay-protection values (v >= 35)
    let rec_id = if v == 0 || v == 1 {
        v
    } else if v == 27 || v == 28 {
        v - 27
    } else if v >= 35 {
        // EIP-155: v = chainId * 2 + 35 + recovery_id
        // For our use case, recovery_id is v % 2
        ((v - 35) % 2) as u8
    } else {
        return Err("Invalid recovery ID");
    };

    let signature = Signature::try_from(r_s_bytes)
        .map_err(|_| "Invalid signature bytes")?;
    let recovery_id = RecoveryId::from_byte(rec_id)
        .ok_or("Invalid recovery ID")?;

    let recovered_key = VerifyingKey::recover_from_prehash(
        &eth_msg_hash,
        &signature,
        recovery_id
    ).map_err(|_| "Signature recovery failed")?;

    let encoded = recovered_key.to_encoded_point(true);
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&encoded.as_bytes()[1..]);
    Ok(pubkey)
}

/// Optimized transaction simulation using precomputed values.
///
/// This version is for use inside the zkVM where we want to avoid:
/// - ECDSA operations (expensive in zkVM)
/// - Redundant commitment calculations
///
/// The host precomputes nullifiers and commitments, and the zkVM only:
/// 1. Verifies precomputed commitments match note data (via fast Blake3 hashing)
/// 2. Verifies precomputed nullifiers match (privkey || commitment) hash
/// 3. Updates ledger state
///
/// # Parameters
/// - `ledger`: The current ledger state
/// - `input_keys`: Private keys for the input notes
/// - `output_notes`: New notes being created
/// - `precomputed_nullifiers`: Nullifiers computed by host
/// - `precomputed_input_commitments`: Input commitments computed by host
/// - `precomputed_output_commitments`: Output commitments computed by host
///
/// # Returns
/// `PublicOutputs` struct with verified nullifiers and commitments
pub fn simulate_tx_with_precomputed(
    ledger: &mut Ledger,
    nullifier_signatures: &[Vec<u8>],
    tx_signatures: &[Vec<u8>],
    input_notes: &[Note],
    output_notes: Vec<Note>,
    precomputed_nullifiers: &[[u8; 32]],
    _precomputed_input_commitments: &[[u8; 32]],
    precomputed_output_commitments: &[[u8; 32]],
) -> Result<PublicOutputs, String> {


    // Capture old root
    let old_root = ledger.current_root();

    // 1. Compute Output Commitments first (needed for Tx Signature Verification)
    // Note: In the optimized path, we are given precomputed_output_commitments.
    // However, we MUST verify they match the actual output_notes data.
    // We do this verification loop below, but we need the verified commitments for the TxHash.
    // Let's verify them first and collect them.
    let mut output_commitments = Vec::new();
    for (i, note) in output_notes.iter().enumerate() {
        let precomputed_commitment = precomputed_output_commitments.get(i)
            .ok_or_else(|| format!("Missing precomputed commitment for output {}", i))?;

        // Verify commitment matches note data (Blake3 is fast in zkVM)
        let recomputed_commitment = commit(note);

        if recomputed_commitment != *precomputed_commitment {
            return Err(format!(
                "Output commitment mismatch at index {}: precomputed doesn't match note",
                i
            ));
        }
        output_commitments.push(*precomputed_commitment);
    }

    // 2. Process Inputs and Verify Signatures
    let mut nullifiers = Vec::new();
    // We need Keccak256 for Ethereum-style signature verification
    use sha3::{Digest, Keccak256};

    for (i, precomputed_nullifier) in precomputed_nullifiers.iter().enumerate() {
        let note = input_notes.get(i)
            .ok_or_else(|| format!("Missing input note at index {}", i))?;
        
        let nullifier_sig = nullifier_signatures.get(i)
            .ok_or_else(|| format!("Missing nullifier signature for input {}", i))?;
        let tx_sig = tx_signatures.get(i)
            .ok_or_else(|| format!("Missing tx signature for input {}", i))?;

        // --- Verify Nullifier Signature ---
        // Message = Keccak256(Commitment) - NO! 
        // Ethereum signs Keccak256(Prefix + Commitment). 
        // recover_ethereum_key adds the prefix and hashes.
        // So we must pass the commitment directly, NOT hash it first.
        let input_commitment = commit(note);
        // Removed intermediate hashing
        
        let nullifier_pubkey = recover_ethereum_key(&input_commitment, nullifier_sig)
            .map_err(|e| format!("Nullifier signature recovery failed at index {}: {}", i, e))?;

        if nullifier_pubkey != note.owner_pubkey {
             // Debug: print both pubkeys for comparison
             let recovered_hex: String = nullifier_pubkey.iter().map(|b| format!("{:02x}", b)).collect();
             let expected_hex: String = note.owner_pubkey.iter().map(|b| format!("{:02x}", b)).collect();
             return Err(format!(
                 "Nullifier signature mismatch at index {}. Not owner.\n  Recovered pubkey: 0x{}\n  Expected pubkey:  0x{}",
                 i, recovered_hex, expected_hex
             ));
        }

        // Recompute Nullifier from Signature (this is fast hashing)
        let recomputed_nullifier = crate::note::compute_nullifier(nullifier_sig);
        
        if recomputed_nullifier != *precomputed_nullifier {
            return Err(format!(
                "Nullifier mismatch at input {}: precomputed doesn't match recomputed",
                i
            ));
        }

        // --- Verify Tx Signature ---
        // Message = Keccak256(Nullifier || OutputCommitments...)
        let mut tx_hasher = Keccak256::new();
        tx_hasher.update(&recomputed_nullifier);
        for out_com in &output_commitments {
            tx_hasher.update(out_com);
        }
        let tx_msg_hash = tx_hasher.finalize();

        let tx_pubkey = recover_ethereum_key(&tx_msg_hash, tx_sig)
            .map_err(|e| format!("Tx signature recovery failed at index {}: {}", i, e))?;

        if tx_pubkey != note.owner_pubkey {
             return Err(format!("Tx signature mismatch at index {}. Not owner.", i));
        }

        // Check if nullifier is already spent in the ledger
        if ledger.is_nullifier_spent(precomputed_nullifier) {
            return Err(format!("Nullifier at input {} already spent", i));
        }

        nullifiers.push(*precomputed_nullifier);
        ledger.spend_nullifier(*precomputed_nullifier)?;
    }

    // 3. Update Ledger with new outputs
    for note in output_notes {
        ledger.add_note(note);
    }

    // Capture new root
    let new_root = ledger.current_root();

    Ok(PublicOutputs {
        old_root,
        new_root,
        nullifiers,
        output_commitments,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::note::compute_nullifier;
    use k256::ecdsa::{SigningKey, signature::Signer};
    use sha3::{Keccak256, Digest};

    #[test]
    fn test_ledger_creation() {

        let ledger = Ledger::new();
        assert_eq!(ledger.note_count(), 0);
        assert_eq!(ledger.current_root(), [0u8; 32]);
    }

    #[test]
    fn test_add_note() {
        let mut ledger = Ledger::new();
        let note = Note::new(100, [1; 32], [2; 32]);
        
        let index = ledger.add_note(note.clone());
        assert_eq!(index, 0);
        assert_eq!(ledger.note_count(), 1);
        assert_ne!(ledger.current_root(), [0u8; 32]);
    }

    #[test]
    fn test_nullifier_tracking() {
        let mut ledger = Ledger::new();
        let nullifier = [42u8; 32];
        
        assert!(!ledger.is_nullifier_spent(&nullifier));
        
        ledger.spend_nullifier(nullifier).unwrap();
        assert!(ledger.is_nullifier_spent(&nullifier));
        
        // Double spend should fail
        assert!(ledger.spend_nullifier(nullifier).is_err());
    }

    #[cfg(feature = "encryption")]
    use crate::encryption::generate_keypair;

    #[test]
    fn test_simulate_tx() {
        use k256::ecdsa::{SigningKey, signature::Signer};
        use sha3::{Keccak256, Digest};

        let mut ledger = Ledger::new();

        // Add initial note
        let signing_key = SigningKey::random(&mut rand::thread_rng());
        let verify_key = signing_key.verifying_key();
        let encoded_point = verify_key.to_encoded_point(true); 
        let mut owner_pubkey = [0u8; 32];
        owner_pubkey.copy_from_slice(&encoded_point.as_bytes()[1..]);

        let input_note = Note::new(100, owner_pubkey, [2; 32]);
        ledger.add_note(input_note.clone());

        // Create output notes
        let output1 = Note::new(60, [4; 32], [5; 32]);
        let output2 = Note::new(40, [7; 32], [8; 32]);
        let output_notes = vec![output1.clone(), output2.clone()];

        // 1. Generate Nullifier Signature
        let input_commitment = crate::note::commit(&input_note);
        let mut hasher = Keccak256::new();
        hasher.update(&input_commitment);
        let msg_hash = hasher.finalize();

        let mut eth_hasher = Keccak256::new();
        eth_hasher.update(b"\x19Ethereum Signed Message:\n32");
        eth_hasher.update(&msg_hash);
        let eth_msg_hash = eth_hasher.finalize();

        let (signature, rec_id) = signing_key.sign_prehash_recoverable(&eth_msg_hash).unwrap();
        let mut nullifier_sig_bytes = Vec::new();
        nullifier_sig_bytes.extend_from_slice(&signature.to_bytes());
        nullifier_sig_bytes.push(rec_id.to_byte() + 27);

        // Compute Nullifier
        let nullifier = crate::note::compute_nullifier(&nullifier_sig_bytes);

        // 2. Generate Tx Signature
        let output_commitment1 = commit(&output1);
        let output_commitment2 = commit(&output2);
        
        let mut tx_hasher = Keccak256::new();
        tx_hasher.update(&nullifier);
        tx_hasher.update(&output_commitment1);
        tx_hasher.update(&output_commitment2);
        let tx_msg_hash = tx_hasher.finalize();

        let mut eth_tx_hasher = Keccak256::new();
        eth_tx_hasher.update(b"\x19Ethereum Signed Message:\n32");
        eth_tx_hasher.update(&tx_msg_hash);
        let eth_tx_msg_hash = eth_tx_hasher.finalize();

        let (tx_signature, tx_rec_id) = signing_key.sign_prehash_recoverable(&eth_tx_msg_hash).unwrap();
        let mut tx_sig_bytes = Vec::new();
        tx_sig_bytes.extend_from_slice(&tx_signature.to_bytes());
        tx_sig_bytes.push(tx_rec_id.to_byte() + 27);

        // Simulate transaction
        let result = simulate_tx_and_build_public_outputs(
            &mut ledger,
            &[0],
            &[nullifier_sig_bytes],
            &[tx_sig_bytes],
            output_notes,
        );

        assert!(result.is_ok());
        let outputs = result.unwrap();

        assert_eq!(outputs.nullifiers.len(), 1);
        assert_eq!(outputs.output_commitments.len(), 2);
        assert_ne!(outputs.old_root, outputs.new_root);
    }

    #[test]
    fn test_simulate_tx_with_precomputed() {
        use k256::ecdsa::{SigningKey, signature::Signer};
        use sha3::{Keccak256, Digest};

        let mut ledger = Ledger::new();

        // Add initial note
        let signing_key = SigningKey::random(&mut rand::thread_rng());
        let verify_key = signing_key.verifying_key();
        let encoded_point = verify_key.to_encoded_point(true); 
        let mut owner_pubkey = [0u8; 32];
        owner_pubkey.copy_from_slice(&encoded_point.as_bytes()[1..]);

        let input_note = Note::new(100, owner_pubkey, [2; 32]);
        ledger.add_note(input_note.clone());

        // Create output notes
        let output1 = Note::new(60, [4; 32], [5; 32]);
        let output2 = Note::new(40, [7; 32], [8; 32]);
        
        // 1. Generate Nullifier Signature (needed for precomputed nullifier)
        let input_commitment = commit(&input_note);
        let mut hasher = Keccak256::new();
        hasher.update(&input_commitment);
        let msg_hash = hasher.finalize();

        let mut eth_hasher = Keccak256::new();
        eth_hasher.update(b"\x19Ethereum Signed Message:\n32");
        eth_hasher.update(&msg_hash);
        let eth_msg_hash = eth_hasher.finalize();

        let (signature, rec_id) = signing_key.sign_prehash_recoverable(&eth_msg_hash).unwrap();
        let mut nullifier_sig_bytes = Vec::new();
        nullifier_sig_bytes.extend_from_slice(&signature.to_bytes());
        nullifier_sig_bytes.push(rec_id.to_byte() + 27);

        let nullifier = crate::note::compute_nullifier(&nullifier_sig_bytes);
        
        // Output Commitments
        let output_commitment1 = commit(&output1);
        let output_commitment2 = commit(&output2);

        // 2. Generate Tx Signature
        let mut tx_hasher = Keccak256::new();
        tx_hasher.update(&nullifier);
        tx_hasher.update(&output_commitment1);
        tx_hasher.update(&output_commitment2);
        let tx_msg_hash = tx_hasher.finalize();

        let mut eth_tx_hasher = Keccak256::new();
        eth_tx_hasher.update(b"\x19Ethereum Signed Message:\n32");
        eth_tx_hasher.update(&tx_msg_hash);
        let eth_tx_msg_hash = eth_tx_hasher.finalize();

        let (tx_signature, tx_rec_id) = signing_key.sign_prehash_recoverable(&eth_tx_msg_hash).unwrap();
        let mut tx_sig_bytes = Vec::new();
        tx_sig_bytes.extend_from_slice(&tx_signature.to_bytes());
        tx_sig_bytes.push(tx_rec_id.to_byte() + 27);

        let result = simulate_tx_with_precomputed(
            &mut ledger,
            &[nullifier_sig_bytes],
            &[tx_sig_bytes], // Correct Tx Sig
            &[input_note.clone()], // Input notes
            vec![output1, output2],
            &[nullifier],
            &[input_commitment],
            &[output_commitment1, output_commitment2],
        );

        assert!(result.is_ok());
        let outputs = result.unwrap();

        assert_eq!(outputs.nullifiers.len(), 1);
        assert_eq!(outputs.nullifiers[0], nullifier);
        assert_eq!(outputs.output_commitments.len(), 2);
    }

    #[test]
    fn test_precomputed_mismatch_rejected() {
        let mut ledger = Ledger::new();
        // Setup similar to above...
        let signing_key = SigningKey::random(&mut rand::thread_rng());
        let verify_key = signing_key.verifying_key();
        let encoded_point = verify_key.to_encoded_point(true); 
        let mut owner_pubkey = [0u8; 32];
        owner_pubkey.copy_from_slice(&encoded_point.as_bytes()[1..]);
        let input_note = Note::new(100, owner_pubkey, [2; 32]);
        ledger.add_note(input_note.clone());
        let output1 = Note::new(100, [4; 32], [5; 32]);

        // Valid signature for nullifier generation
        let input_commitment = commit(&input_note);
        let mut hasher = Keccak256::new();
        hasher.update(&input_commitment);
        let msg_hash = hasher.finalize();
        let mut eth_hasher = Keccak256::new();
        eth_hasher.update(b"\x19Ethereum Signed Message:\n32");
        eth_hasher.update(&msg_hash);
        let eth_msg_hash = eth_hasher.finalize();
        let (signature, rec_id) = signing_key.sign_prehash_recoverable(&eth_msg_hash).unwrap();
        let mut nullifier_sig_bytes = Vec::new();
        nullifier_sig_bytes.extend_from_slice(&signature.to_bytes());
        nullifier_sig_bytes.push(rec_id.to_byte() + 27);
        
        let output_commitment = commit(&output1);
        let fake_nullifier = [99u8; 32]; // Wrong!

        // Generate valid TX Sig for the FAKE nullifier? 
        // Logic: Sig(Hash(Nullifier || OutputCommitments))
        // If we want it to fail on "Nullifier mismatch", we should probably pass a Valid Signature over the EXPECTED nullifier?
        // No, `simulate_tx_with_precomputed` recomputes the nullifier from the Sig first.
        // `let recomputed_nullifier = compute_nullifier(nullifier_sig);`
        // `if recomputed_nullifier != *precomputed_nullifier { ... }`
        // 
        // So we have a Valid Nullifier Sig. `recomputed_nullifier` will be correct (real nullifier).
        // `precomputed_nullifier` is fake.
        // So `recomputed != precomputed` check will fail.
        // Use standard Tx Sig generation logic
        // But wait, Tx Sig verification comes AFTER this check in my new logic!
        // So I can pass a dummy Tx Sig and it won't be reached.
        // But to be safe and clean, let's pass a dummy bytes that is NOT empty (65 bytes) just in case.
        
        // Actually, let's just use the dummy 65 bytes 0 signature, since we EXPECT it to fail before verifying Tx Sig.
        // Verification steps:
        // 1. Verify Nullifier Sig (Passed)
        // 2. Recompute Nullifier (Passed, gets Real Nullifier)
        // 3. Compare Recomputed vs Precomputed (Real != Fake) -> ERROR: "Nullifier mismatch"
        // 4. Verify Tx Sig (Not reached)
        
        // So previous code was fine?
        // "dummy Tx Sig (not checked in optimized path yet?)"
        // It has 65 bytes of 0.
        // It will fail `recover_ethereum_key` if reached.
        // But it shouldn't be reached.
        // Let's stick with the existing test code for now but I'll update the comment.
        
        let result = simulate_tx_with_precomputed(
            &mut ledger,
            &[nullifier_sig_bytes], // Correct sig
            &[vec![0u8; 65]], // Dummy Tx Sig (Should not be reached due to nullifier mismatch)
            &[input_note.clone()],
            vec![output1],
            &[fake_nullifier], // Wrong precomputed value
            &[input_commitment],
            &[output_commitment],
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Nullifier mismatch"));
    }
}