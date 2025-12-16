#[cfg(feature = "encryption")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "encryption")]
use crate::note::Note;
#[cfg(feature = "encryption")]
use crate::encryption::{encrypt_note, decrypt_note, EncryptedNote, ViewPublicKey, ViewSecretKey};

/// Plaintext payload that gets encrypted
#[cfg(feature = "encryption")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotePlaintext {
    pub note: Note,
    /// Optional: leaf index hint for faster Merkle path lookup
    pub leaf_index_hint: Option<u64>,
}

#[cfg(feature = "encryption")]
impl NotePlaintext {
    pub fn new(note: Note, leaf_index_hint: Option<u64>) -> Self {
        Self {
            note,
            leaf_index_hint,
        }
    }
    
    /// Serialize to bytes for encryption
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("Serialization should not fail")
    }
    
    /// Deserialize from decrypted bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        bincode::deserialize(data).map_err(|e| format!("Deserialization failed: {}", e))
    }
    
    /// Encrypt this note for a recipient
    pub fn encrypt(&self, recipient_pubkey: &ViewPublicKey) -> Result<EncryptedNote, String> {
        let plaintext = self.to_bytes();
        encrypt_note(&plaintext, recipient_pubkey)
    }
    
    /// Try to decrypt an encrypted note
    pub fn decrypt(encrypted: &EncryptedNote, secret_key: &ViewSecretKey) -> Option<Self> {
        let plaintext = decrypt_note(encrypted, secret_key)?;
        Self::from_bytes(&plaintext).ok()
    }
}

#[cfg(all(test, feature = "encryption"))]
mod tests {
    use super::*;
    use crate::encryption::generate_keypair;

    #[test]
    fn test_note_plaintext_encrypt_decrypt() {
        let (secret, public) = generate_keypair();
        
        let note = Note::new(100, [1; 32], [2; 32]);
        let plaintext = NotePlaintext::new(note.clone(), Some(42));
        
        // Encrypt
        let encrypted = plaintext.encrypt(&public).unwrap();
        
        // Decrypt
        let decrypted = NotePlaintext::decrypt(&encrypted, &secret).unwrap();
        
        assert_eq!(decrypted.note.amount, note.amount);
        assert_eq!(decrypted.note.owner_pubkey, note.owner_pubkey);
        assert_eq!(decrypted.leaf_index_hint, Some(42));
    }
    
    #[test]
    fn test_decrypt_with_wrong_key_returns_none() {
        let (_, public1) = generate_keypair();
        let (secret2, _) = generate_keypair();
        
        let note = Note::new(50, [4; 32], [5; 32]);
        let plaintext = NotePlaintext::new(note, None);
        
        let encrypted = plaintext.encrypt(&public1).unwrap();
        let result = NotePlaintext::decrypt(&encrypted, &secret2);
        
        assert!(result.is_none());
    }
}