#[cfg(feature = "encryption")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "encryption")]
use crate::note::{Note, commit};
#[cfg(feature = "encryption")]
use crate::encryption::EncryptedNote;

/// Data for a deposit transaction (ETH → Private Note)
#[cfg(feature = "encryption")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositData {
    /// Amount in wei being deposited
    pub amount_wei: u64,
    /// The note being created
    pub output_note: Note,
    /// Encrypted note data for the recipient
    pub encrypted_output: EncryptedNote,
}

#[cfg(feature = "encryption")]
impl DepositData {
    /// Create a new deposit
    pub fn new(
        amount_wei: u64,
        output_note: Note,
        encrypted_output: EncryptedNote,
    ) -> Self {
        Self {
            amount_wei,
            output_note,
            encrypted_output,
        }
    }

    /// Get the commitment for this deposit
    pub fn commitment(&self) -> [u8; 32] {
        commit(&self.output_note)
    }

    /// Validate that the note amount matches the deposit amount
    pub fn validate(&self) -> Result<(), String> {
        // In a real system, you'd have a conversion rate
        // For simplicity, 1 wei = 1 note unit
        if self.output_note.amount != self.amount_wei {
            return Err(format!(
                "Note amount {} doesn't match deposit {}",
                self.output_note.amount, self.amount_wei
            ));
        }
        Ok(())
    }
}

/// Data for a withdraw transaction (Private Note → ETH)
#[cfg(feature = "encryption")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawData {
    /// Amount in wei being withdrawn
    pub amount_wei: u64,
    /// Ethereum address to receive the ETH
    pub recipient: [u8; 20], // Ethereum address
}

#[cfg(feature = "encryption")]
impl WithdrawData {
    /// Create a new withdraw
    pub fn new(amount_wei: u64, recipient: [u8; 20]) -> Self {
        Self {
            amount_wei,
            recipient,
        }
    }

    /// Convert recipient to hex string for display
    pub fn recipient_hex(&self) -> String {
        format!("0x{}", hex::encode(&self.recipient))
    }
}

#[cfg(feature = "encryption")]
mod hex {
    pub fn encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(all(test, feature = "encryption"))]
mod tests {
    use super::*;
    use crate::encryption::generate_keypair;
    use crate::encrypted_note::NotePlaintext;

    #[test]
    fn test_deposit_data_validation() {
        let (_, public_key) = generate_keypair();
        
        let note = Note::new(100, [1; 32], [2; 32]);
        let plaintext = NotePlaintext::new(note.clone(), None);
        let encrypted = plaintext.encrypt(&public_key).unwrap();
        
        let deposit = DepositData::new(100, note, encrypted);
        
        assert!(deposit.validate().is_ok());
        assert_eq!(deposit.amount_wei, 100);
    }

    #[test]
    fn test_deposit_validation_fails_on_mismatch() {
        let (_, public_key) = generate_keypair();
        
        let note = Note::new(100, [1; 32], [2; 32]);
        let plaintext = NotePlaintext::new(note.clone(), None);
        let encrypted = plaintext.encrypt(&public_key).unwrap();
        
        // Amount mismatch: depositing 200 but note is for 100
        let deposit = DepositData::new(200, note, encrypted);
        
        assert!(deposit.validate().is_err());
    }

    #[test]
    fn test_withdraw_data() {
        let recipient = [0x12u8; 20];
        let withdraw = WithdrawData::new(50, recipient);
        
        assert_eq!(withdraw.amount_wei, 50);
        assert_eq!(withdraw.recipient, recipient);
        assert!(withdraw.recipient_hex().starts_with("0x"));
    }
}