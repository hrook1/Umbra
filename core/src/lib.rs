pub mod ledger;
pub mod merkle;
pub mod note;
pub mod sp1_types;

#[cfg(feature = "encryption")]
pub mod transaction_builder;

#[cfg(feature = "encryption")]
pub mod encryption;

#[cfg(feature = "encryption")]
pub mod encrypted_note;

#[cfg(feature = "encryption")]
pub mod deposit_withdraw;

#[cfg(feature = "encryption")]
pub mod tx_metadata;

// Re-exports for convenience
pub use crate::note::{commit, compute_nullifier, Note, Nullifier};
pub use merkle::MerkleTree;
pub use ledger::{Ledger, PublicOutputs, simulate_tx_with_precomputed};
pub use sp1_types::{PublicInputs, Witness};

#[cfg(feature = "encryption")]
pub use encryption::{generate_keypair, encrypt_note, decrypt_note, EncryptedNote, ViewPublicKey, ViewSecretKey, KeyType};

#[cfg(feature = "encryption")]
pub use encrypted_note::NotePlaintext;

#[cfg(feature = "encryption")]
pub use deposit_withdraw::{DepositData, WithdrawData};

#[cfg(feature = "encryption")]
pub use transaction_builder::TransactionBuilder;
