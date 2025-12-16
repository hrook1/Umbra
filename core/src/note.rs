use blake3::Hasher;
use serde::{Deserialize, Serialize};

// Domain separators as constants for better maintainability
const NOTE_COMMITMENT_DOMAIN: &[u8] = b"NOTE_COMMITMENT_v1";
const NULLIFIER_DOMAIN: &[u8] = b"NULLIFIER_v1";

/// A simple UTXO note in our prototype.
///
/// # Privacy Model
/// - `owner_pubkey`: Public - identifies who can spend this note
/// - `amount`: Public in commitment, hidden in witness
/// - `blinding`: Private - adds entropy to prevent commitment analysis
///
/// # Security Properties
/// - Commitment hiding: `blinding` ensures same amount/owner produce different commitments
/// - Spending authority: Only holder of `owner_privkey` can sign for this note
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Note {
    pub amount: u64,
    pub owner_pubkey: [u8; 32],
    pub blinding: [u8; 32],
}

impl Note {
    /// Create a new note with the given parameters.
    pub fn new(
        amount: u64,
        owner_pubkey: [u8; 32],
        blinding: [u8; 32],
    ) -> Self {
        Self {
            amount,
            owner_pubkey,
            blinding,
        }
    }

    /// Compute the commitment for this note.
    ///
    /// This is a convenience method that calls the top-level `commit` function.
    pub fn commitment(&self) -> [u8; 32] {
        commit(self)
    }
}

/// A nullifier is a 32-byte tag indicating "this note has been spent".
///
/// # Protocol Design
/// - Posted publicly on Ethereum when a note is spent
/// - Tracked in the `nullifierUsed` mapping to prevent double-spending
/// - Unlinkable to the original note commitment (privacy property)
pub type Nullifier = [u8; 32];

/// Compute a 32-byte commitment hash for a Note.
///
/// # Commitment Scheme
/// The commitment binds to:
/// - `amount`: The value of the note
/// - `owner_pubkey`: Who can spend it
/// - `blinding`: Random entropy for hiding
///
/// # Security Properties
/// - **Hiding**: Same amount/owner with different blinding produce different commitments
/// - **Binding**: Computationally infeasible to find two notes with same commitment
///
/// # Output
/// This 32-byte hash becomes a leaf in the global Merkle tree on Ethereum.
pub fn commit(note: &Note) -> [u8; 32] {
    let mut hasher = Hasher::new();

    // Domain separator prevents hash collisions with other protocol components
    hasher.update(NOTE_COMMITMENT_DOMAIN);

    // Hash all public and semi-public components
    hasher.update(&note.amount.to_le_bytes());
    hasher.update(&note.owner_pubkey);
    hasher.update(&note.blinding);

    let hash = hasher.finalize();
    *hash.as_bytes()
}

/// Compute a nullifier for a note (with ECDSA ownership verification).
///
/// # Nullifier Construction
/// The nullifier binds to:
/// - `owner_privkey`: Proves ownership (only note owner knows this)
/// - `commitment`: The note's unique identity

/// Compute a nullifier from a signature.
///
/// # Logic
/// Nullifier = Hash(NULLIFIER_DOMAIN || signature)
///
/// # Privacy
/// - The signature should be over the note commitment.
/// - Since the signature is deterministic (RFC 6979), the nullifier is stable.
/// - Observers see Hash(Sig), which they cannot link to the user/pubkey.
pub fn compute_nullifier(signature: &[u8]) -> Nullifier {
    let mut hasher = Hasher::new();
    hasher.update(NULLIFIER_DOMAIN);
    hasher.update(signature);
    let hash = hasher.finalize();
    *hash.as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_produces_consistent_nullifier() {
        let signature = [7u8; 65];
        let nullifier1 = compute_nullifier(&signature);
        let nullifier2 = compute_nullifier(&signature);
        assert_eq!(nullifier1, nullifier2);
    }

    #[test]
    fn test_different_signature_produces_different_nullifier() {
        let sig1 = [7u8; 65];
        let mut sig2 = [7u8; 65];
        sig2[0] = 8;
        
        let nullifier1 = compute_nullifier(&sig1);
        let nullifier2 = compute_nullifier(&sig2);
        assert_ne!(nullifier1, nullifier2);
    }

    #[test]
    fn test_commitment_and_nullifier_are_different() {
        let note = Note::new(100, [1; 32], [2; 32]);
        let commitment = commit(&note);
        let signature = [7u8; 65];
        let nullifier = compute_nullifier(&signature);
        
        assert_ne!(commitment, nullifier);
    }
}
