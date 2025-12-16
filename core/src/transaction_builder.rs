use crate::tx_metadata::CommitmentMetadata;
use crate::note::Note;
use crate::encryption::ViewPublicKey;

pub struct TransactionBuilder {
    pub inputs: Vec<Note>,
    pub input_indices: Vec<usize>,
    pub outputs: Vec<Note>,
    pub metadata: Vec<CommitmentMetadata>,
}

impl TransactionBuilder {
    /// Build a P2P transfer transaction with metadata
    pub fn build_transfer(
        sender_note: Note,
        sender_note_index: usize,
        recipient_pubkey: ViewPublicKey,
        amount: u64,
        memo: Option<String>,
        sender_pubkey: ViewPublicKey,
    ) -> Result<Self, String> {
        let sender_value = sender_note.amount;
        
        if amount > sender_value {
            return Err("Insufficient funds".into());
        }

        // Extract owner pubkey (x-coordinate from compressed key)
        let mut recipient_owner = [0u8; 32];
        recipient_owner.copy_from_slice(&recipient_pubkey[1..]);
        
        let mut sender_owner = [0u8; 32];
        sender_owner.copy_from_slice(&sender_pubkey[1..]);
        
        // Create output for recipient
        let recipient_blinding = rand::random();
        let recipient_note = Note::new(
            amount,
            recipient_owner,
            recipient_blinding,
        );
        
        // Create change output for sender
        let change_amount = sender_value - amount;
        let change_blinding = rand::random();
        let change_note = Note::new(
            change_amount,
            sender_owner,
            change_blinding,
        );
        
        // Create metadata for both outputs
        let recipient_metadata = CommitmentMetadata::for_recipient(
            Some(sender_pubkey),
            memo.clone(),
            recipient_blinding,
        );
        
        let sender_metadata = CommitmentMetadata::for_sender_change(
            sender_value,
            amount,
            recipient_pubkey,
            memo,
            change_blinding,
        );
        
        Ok(Self {
            inputs: vec![sender_note],
            input_indices: vec![sender_note_index],
            outputs: vec![recipient_note, change_note],
            metadata: vec![recipient_metadata, sender_metadata],
        })
    }
    
    /// Encrypt all metadata
    pub fn encrypt_metadata(&self) -> Result<Vec<Vec<u8>>, String> {
        let mut encrypted = Vec::new();
        
        for (i, metadata) in self.metadata.iter().enumerate() {
            // Extract view pubkey from note's owner (add 0x02 prefix for compressed key)
            let mut view_pubkey = [0u8; 33];
            view_pubkey[0] = 0x02; // Compressed public key prefix
            view_pubkey[1..].copy_from_slice(&self.outputs[i].owner_pubkey);
            
            let encrypted_meta = metadata.encrypt(&view_pubkey)?;
            encrypted.push(encrypted_meta);
        }
        
        Ok(encrypted)
    }
}
