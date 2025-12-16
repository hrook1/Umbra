// src/main.rs

use utxo_prototype::ledger::{simulate_tx_and_build_public_outputs, Ledger, PublicOutputs};
use utxo_prototype::note::Note;

fn main() {
    // HIGH-LEVEL: tiny "demo chain" to show how a transaction
    // produces public outputs for SP1 / Ethereum.

    // Start with an empty ledger.
    let mut ledger = Ledger::new();

    // Generate keys for our users
    #[cfg(feature = "encryption")]
    use utxo_prototype::encryption::generate_keypair;
    #[cfg(not(feature = "encryption"))]
    fn generate_keypair() -> ([u8; 32], [u8; 33]) { ([1u8; 32], [2u8; 33]) }

    let (alice_key, alice_pub) = generate_keypair();
    let (bob_key, bob_pub) = generate_keypair();
    let (_, charlie_pub) = generate_keypair();

    let mut alice_owner = [0u8; 32];
    alice_owner.copy_from_slice(&alice_pub[1..]);
    
    let mut bob_owner = [0u8; 32];
    bob_owner.copy_from_slice(&bob_pub[1..]);
    
    let mut charlie_owner = [0u8; 32];
    charlie_owner.copy_from_slice(&charlie_pub[1..]);

    // Add two notes (like an initial funding step).
    let note1 = Note {
        amount: 10,
        owner_pubkey: alice_owner,
        blinding: [2u8; 32],
    };

    let note2 = Note {
        amount: 20,
        owner_pubkey: bob_owner,
        blinding: [4u8; 32],
    };

    ledger.add_note(note1.clone());
    ledger.add_note(note2.clone());

    // Build a simple tx: spend note1 (index 0) into a new note with amount 10.
    let out_note = Note {
        amount: 10,
        owner_pubkey: charlie_owner, // pretend this is someone else's key
        blinding: [5u8; 32],
    };

    // Sign the input note
    use k256::ecdsa::{SigningKey, signature::Signer};
    use sha3::{Keccak256, Digest};
    
    // Create correct signing key from generated private key
    // We generated random keys above but discarded private key? No:
    // let (alice_key, alice_pub) = generate_keypair();
    // alice_key is [u8; 32]. We need to convert to SigningKey.
    let signing_key = SigningKey::from_slice(&alice_key).expect("invalid private key");

    // 1. Generate Nullifier Signature
    let input_commitment = utxo_prototype::commit(&note1);
    let mut hasher = Keccak256::new();
    hasher.update(&input_commitment);
    let msg_hash = hasher.finalize();

    let mut eth_hasher = Keccak256::new();
    eth_hasher.update(b"\x19Ethereum Signed Message:\n32");
    eth_hasher.update(&msg_hash);
    let eth_msg_hash = eth_hasher.finalize();

    let (signature, rec_id) = signing_key.sign_prehash_recoverable(&eth_msg_hash).unwrap();
    let mut nullifier_sig = Vec::new();
    nullifier_sig.extend_from_slice(&signature.to_bytes());
    nullifier_sig.push(rec_id.to_byte() + 27);

    // 2. Generate Tx Signature
    // Message = Keccak(Nullifier || OutputCommitments)
    // Compute Nullifier first
    let nullifier = utxo_prototype::note::compute_nullifier(&nullifier_sig);
    
    let output_commitment = utxo_prototype::commit(&out_note);
    let mut tx_hasher = Keccak256::new();
    tx_hasher.update(&nullifier);
    tx_hasher.update(&output_commitment);
    let tx_msg_hash = tx_hasher.finalize();

    let mut eth_tx_hasher = Keccak256::new();
    eth_tx_hasher.update(b"\x19Ethereum Signed Message:\n32");
    eth_tx_hasher.update(&tx_msg_hash);
    let eth_tx_msg_hash = eth_tx_hasher.finalize();

    let (tx_signature, tx_rec_id) = signing_key.sign_prehash_recoverable(&eth_tx_msg_hash).unwrap();
    let mut tx_sig = Vec::new();
    tx_sig.extend_from_slice(&tx_signature.to_bytes());
    tx_sig.push(tx_rec_id.to_byte() + 27);

    let public_outputs = simulate_tx_and_build_public_outputs(
        &mut ledger,
        &[0],                // spend input at index 0
        &[nullifier_sig],    // nullifier signatures
        &[tx_sig],           // tx signatures
        vec![out_note],      // create one output note
    )
    .expect("tx should be valid");

    println!("=== Public outputs for this tx (SP1 → Ethereum) ===");
    println!("old_root: 0x{}", hex::encode(public_outputs.old_root));
    println!("new_root: 0x{}", hex::encode(public_outputs.new_root));

    println!("nullifiers:");
    for (i, nf) in public_outputs.nullifiers.iter().enumerate() {
        println!("  [{}] 0x{}", i, hex::encode(*nf));
    }

    println!("output commitments:");
    for (i, com) in public_outputs.output_commitments.iter().enumerate() {
        println!("  [{}] 0x{}", i, hex::encode(*com));
    }

    // Extra: print them as Solidity literals you can paste into a Foundry test.
    println!();
    print_public_outputs_as_solidity(&public_outputs);
}

/// Helper to print `PublicOutputs` in a Solidity-friendly way.
///
/// HIGH-LEVEL:
/// - This lets you copy/paste values from your Rust run straight into
///   a Solidity test for `PrivateUTXOLedger.submitTx`.
fn print_public_outputs_as_solidity(public: &PublicOutputs) {
    println!("// Solidity literals for PublicOutputs test:");
    println!("bytes32 oldRoot = 0x{};", hex::encode(public.old_root));
    println!("bytes32 newRoot = 0x{};", hex::encode(public.new_root));

    println!(
        "bytes32[] memory nullifiers = new bytes32[]({});",
        public.nullifiers.len()
    );
    for (i, nf) in public.nullifiers.iter().enumerate() {
        println!("nullifiers[{}] = 0x{};", i, hex::encode(*nf));
    }

    println!(
        "bytes32[] memory outputCommitments = new bytes32[]({});",
        public.output_commitments.len()
    );
    for (i, com) in public.output_commitments.iter().enumerate() {
        println!("outputCommitments[{}] = 0x{};", i, hex::encode(*com));
    }
}

// Small helper so we can print hex without extra crates.
mod hex {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

    pub fn encode(data: [u8; 32]) -> String {
        let mut out = String::with_capacity(64);
        for byte in data {
            out.push(HEX_CHARS[(byte >> 4) as usize] as char);
            out.push(HEX_CHARS[(byte & 0x0f) as usize] as char);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use utxo_prototype::ledger::Ledger;
    use utxo_prototype::merkle::MerkleTree;
    use utxo_prototype::note::{commit, Note};

    #[cfg(feature = "encryption")]
    use utxo_prototype::encryption::generate_keypair;
    #[cfg(not(feature = "encryption"))]
    fn generate_keypair() -> ([u8; 32], [u8; 33]) { ([1u8; 32], [2u8; 33]) }

    #[test]
    fn merkle_root_changes_when_leaves_change() {
        let note1 = Note {
            amount: 10,
            owner_pubkey: [1u8; 32],
            blinding: [2u8; 32],
        };
        let note2 = Note {
            amount: 20,
            owner_pubkey: [3u8; 32],
            blinding: [4u8; 32],
        };

        let c1 = commit(&note1);
        let c2 = commit(&note2);

        let mut tree = MerkleTree::default();
        tree.push_leaf(c1);
        let root1 = tree.root();

        tree.push_leaf(c2);
        let root2 = tree.root();

        assert_ne!(root1, root2, "root must change when we add a new leaf");
    }

    #[test]
    fn double_spend_is_rejected() {
        use k256::ecdsa::{SigningKey, signature::Signer};
        use sha3::{Keccak256, Digest};

        let mut ledger = Ledger::new();
        let (key, pubkey) = generate_keypair();
        let mut owner = [0u8; 32];
        owner.copy_from_slice(&pubkey[1..]);

        // One initial note with amount 10 at index 0.
        let note = Note {
            amount: 10,
            owner_pubkey: owner,
            blinding: [2u8; 32],
        };

        ledger.add_note(note.clone());

        // Helper to sign
        let sign_tx = |out_note: &Note| -> (Vec<u8>, Vec<u8>) {
            let signing_key = SigningKey::from_slice(&key).expect("invalid key");
            
            // Nullifier Sig
            let commit = utxo_prototype::note::commit(&note);
            let mut hasher = Keccak256::new();
            hasher.update(&commit);
            let msg = hasher.finalize();
            let mut eth_hasher = Keccak256::new();
            eth_hasher.update(b"\x19Ethereum Signed Message:\n32");
            eth_hasher.update(&msg);
            let (sig, rid) = signing_key.sign_prehash_recoverable(&eth_hasher.finalize()).unwrap();
            let mut null_sig = Vec::new();
            null_sig.extend_from_slice(&sig.to_bytes());
            null_sig.push(rid.to_byte() + 27);

            // Tx Sig
            let nullifier = utxo_prototype::note::compute_nullifier(&null_sig);
            let out_commit = utxo_prototype::note::commit(out_note);
            let mut tx_hasher = Keccak256::new();
            tx_hasher.update(&nullifier);
            tx_hasher.update(&out_commit);
            let tx_msg = tx_hasher.finalize();
            let mut eth_tx_hasher = Keccak256::new();
            eth_tx_hasher.update(b"\x19Ethereum Signed Message:\n32");
            eth_tx_hasher.update(&tx_msg);
            let (tx_sig, tx_rid) = signing_key.sign_prehash_recoverable(&eth_tx_hasher.finalize()).unwrap();
            let mut tx_sig_bytes = Vec::new();
            tx_sig_bytes.extend_from_slice(&tx_sig.to_bytes());
            tx_sig_bytes.push(tx_rid.to_byte() + 27);

            (null_sig, tx_sig_bytes)
        };

        // First tx: spend index 0 into a new note with amount 10.
        let out_note = Note {
            amount: 10,
            owner_pubkey: [9u8; 32],
            blinding: [5u8; 32],
        };
        
        let (nsig1, tsig1) = sign_tx(&out_note);

        let res1 = ledger.apply_tx(&[0], &[nsig1], &[tsig1], vec![out_note.clone()]);
        assert!(res1.is_ok(), "first spend should succeed");

        // Second tx: try to spend index 0 again (same original note).
        let out_note2 = Note {
            amount: 10,
            owner_pubkey: [9u8; 32],
            blinding: [6u8; 32],
        };

        let (nsig2, tsig2) = sign_tx(&out_note2);

        let res2 = ledger.apply_tx(&[0], &[nsig2], &[tsig2], vec![out_note2]);
        assert!(
            res2.is_err(),
            "second spend of the same input should be rejected"
        );
    }
}