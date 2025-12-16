use serde::{Deserialize, Serialize, Deserializer, Serializer};
use crate::encryption::{ViewPublicKey, ViewSecretKey, encrypt_note, decrypt_note, EncryptedNote};

// Custom serialization for [u8; 33]
fn serialize_pubkey<S>(key: &ViewPublicKey, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_bytes(key)
}

fn deserialize_pubkey<'de, D>(deserializer: D) -> Result<ViewPublicKey, D::Error>
where
    D: Deserializer<'de>,
{
    let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
    if bytes.len() != 33 {
        return Err(serde::de::Error::custom("Invalid pubkey length"));
    }
    let mut array = [0u8; 33];
    array.copy_from_slice(&bytes);
    Ok(array)
}

fn serialize_optional_pubkey<S>(key: &Option<ViewPublicKey>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match key {
        Some(k) => serializer.serialize_some(&k.to_vec()),
        None => serializer.serialize_none(),
    }
}

fn deserialize_optional_pubkey<'de, D>(deserializer: D) -> Result<Option<ViewPublicKey>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt: Option<Vec<u8>> = Deserialize::deserialize(deserializer)?;
    match opt {
        Some(bytes) => {
            if bytes.len() != 33 {
                return Err(serde::de::Error::custom("Invalid pubkey length"));
            }
            let mut array = [0u8; 33];
            array.copy_from_slice(&bytes);
            Ok(Some(array))
        }
        None => Ok(None),
    }
}

/// Metadata that sender sees about their transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SenderMetadata {
    /// Who they sent to
    #[serde(serialize_with = "serialize_pubkey", deserialize_with = "deserialize_pubkey")]
    pub recipient_pubkey: ViewPublicKey,
    /// Amount they sent
    pub amount: u64,
    /// Optional memo
    pub memo: Option<String>,
    /// Timestamp
    pub timestamp: u64,
    /// Which output index is for recipient (vs change)
    pub recipient_output_index: usize,
}

/// Metadata that recipient sees about the transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipientMetadata {
    /// Who sent it (if sender chooses to reveal)
    #[serde(serialize_with = "serialize_optional_pubkey", deserialize_with = "deserialize_optional_pubkey")]
    pub sender_pubkey: Option<ViewPublicKey>,
    /// Optional memo from sender
    pub memo: Option<String>,
    /// Timestamp
    pub timestamp: u64,
}

/// Combined metadata for a single output commitment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CommitmentMetadata {
    /// This output is for the sender (change)
    SenderChange {
        original_amount: u64,
        sent_amount: u64,
        #[serde(serialize_with = "serialize_pubkey", deserialize_with = "deserialize_pubkey")]
        recipient_pubkey: ViewPublicKey,
        memo: Option<String>,
        timestamp: u64,
        blinding: [u8; 32],
    },
    /// This output is for a recipient
    ReceivedFunds {
        #[serde(serialize_with = "serialize_optional_pubkey", deserialize_with = "deserialize_optional_pubkey")]
        sender_pubkey: Option<ViewPublicKey>,
        memo: Option<String>,
        timestamp: u64,
        blinding: [u8; 32],
    },
    /// This is a deposit
    Deposit {
        amount: u64,
        timestamp: u64,
        blinding: [u8; 32],
    },
}

impl CommitmentMetadata {
    /// Encrypt metadata with the output's recipient public key
    pub fn encrypt(&self, recipient_pubkey: &ViewPublicKey) -> Result<Vec<u8>, String> {
        let plaintext = bincode::serialize(self)
            .map_err(|e| format!("Serialize failed: {}", e))?;
        
        // Use existing encrypt_note function
        let encrypted = encrypt_note(&plaintext, recipient_pubkey)?;
        
        // Serialize the EncryptedNote to bytes
        bincode::serialize(&encrypted)
            .map_err(|e| format!("Failed to serialize encrypted metadata: {}", e))
    }

    /// Decrypt metadata with your secret key
    pub fn decrypt(encrypted: &[u8], secret_key: &ViewSecretKey) -> Result<Self, String> {
        // Deserialize EncryptedNote
        let encrypted_note: EncryptedNote = bincode::deserialize(encrypted)
            .map_err(|e| format!("Failed to deserialize: {}", e))?;
        
        // Decrypt using existing function
        let plaintext = decrypt_note(&encrypted_note, secret_key)
            .ok_or("Failed to decrypt metadata")?;
        
        // Deserialize metadata
        bincode::deserialize(&plaintext)
            .map_err(|e| format!("Deserialize failed: {}", e))
    }

    /// Create metadata for sender's change output
    pub fn for_sender_change(
        original_amount: u64,
        sent_amount: u64,
        recipient_pubkey: ViewPublicKey,
        memo: Option<String>,
        blinding: [u8; 32],
    ) -> Self {
        Self::SenderChange {
            original_amount,
            sent_amount,
            recipient_pubkey,
            memo,
            timestamp: current_timestamp(),
            blinding,
        }
    }

    /// Create metadata for recipient's output
    pub fn for_recipient(
        sender_pubkey: Option<ViewPublicKey>,
        memo: Option<String>,
        blinding: [u8; 32],
    ) -> Self {
        Self::ReceivedFunds {
            sender_pubkey,
            memo,
            timestamp: current_timestamp(),
            blinding,
        }
    }

    /// Create metadata for deposit
    pub fn for_deposit(amount: u64, blinding: [u8; 32]) -> Self {
        Self::Deposit {
            amount,
            timestamp: current_timestamp(),
            blinding,
        }
    }
}

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::generate_keypair;

    #[test]
    fn test_metadata_encryption() {
        let (secret, pubkey) = generate_keypair(); // Note: returns (secret, public)
        
        let metadata = CommitmentMetadata::for_recipient(
            Some(pubkey),
            Some("Hello!".to_string()),
            [7u8; 32], // blinding
        );
        
        let encrypted = metadata.encrypt(&pubkey).unwrap();
        let decrypted = CommitmentMetadata::decrypt(&encrypted, &secret).unwrap();
        
        match decrypted {
            CommitmentMetadata::ReceivedFunds { memo, blinding, .. } => {
                assert_eq!(memo, Some("Hello!".to_string()));
                assert_eq!(blinding, [7u8; 32]);
            }
            _ => panic!("Wrong type"),
        }
    }
    
    #[test]
    fn test_sender_change_metadata() {
        let (alice_secret, alice_pub) = generate_keypair();
        let (_bob_secret, bob_pub) = generate_keypair();
        
        let metadata = CommitmentMetadata::for_sender_change(
            1_000_000_000_000_000_000u64,
            600_000_000_000_000_000u64,
            bob_pub,
            Some("Payment for services".to_string()),
            [8u8; 32], // blinding
        );
        
        let encrypted = metadata.encrypt(&alice_pub).unwrap();
        let decrypted = CommitmentMetadata::decrypt(&encrypted, &alice_secret).unwrap();
        
        match decrypted {
            CommitmentMetadata::SenderChange { 
                original_amount, 
                sent_amount, 
                memo, 
                blinding,
                .. 
            } => {
                assert_eq!(original_amount, 1_000_000_000_000_000_000u64);
                assert_eq!(sent_amount, 600_000_000_000_000_000u64);
                assert_eq!(memo, Some("Payment for services".to_string()));
                assert_eq!(blinding, [8u8; 32]);
            }
            _ => panic!("Wrong type"),
        }
    }
}