#[cfg(feature = "encryption")]
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
#[cfg(feature = "encryption")]
use secp256k1::{PublicKey, SecretKey, Secp256k1, ecdh::SharedSecret};
#[cfg(feature = "encryption")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "encryption")]
use hkdf::Hkdf;
#[cfg(feature = "encryption")]
use sha2::Sha256;

/// Key type for future-proofing (RIP-7212 support)
#[cfg(feature = "encryption")]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum KeyType {
    Secp256k1 = 0,
    Secp256r1 = 1, // For future RIP-7212 support
}

/// View public key (33 bytes compressed)
#[cfg(feature = "encryption")]
pub type ViewPublicKey = [u8; 33];

/// View secret key (32 bytes)
#[cfg(feature = "encryption")]
pub type ViewSecretKey = [u8; 32];

/// Encrypted note payload
#[cfg(feature = "encryption")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedNote {
    /// Curve type used
    pub key_type: KeyType,
    /// Ephemeral public key (compressed, 33 bytes)
    #[serde(with = "serde_big_array::BigArray")]
    pub ephemeral_pubkey: [u8; 33],
    /// Nonce for AES-GCM
    pub nonce: [u8; 12],
    /// Encrypted data with auth tag
    pub ciphertext: Vec<u8>,
}

/// Generate a new secp256k1 keypair
#[cfg(feature = "encryption")]
pub fn generate_keypair() -> (ViewSecretKey, ViewPublicKey) {
    let secp = Secp256k1::new();
    let (secret_key, public_key) = secp.generate_keypair(&mut rand::thread_rng());
    
    (secret_key.secret_bytes(), public_key.serialize())
}

/// Encrypt data for a recipient using ECIES-like scheme
///
/// # Process
/// 1. Generate ephemeral keypair
/// 2. Perform ECDH with recipient's public key
/// 3. Derive AES key using HKDF-SHA256
/// 4. Encrypt plaintext with AES-256-GCM
#[cfg(feature = "encryption")]
pub fn encrypt_note(
    plaintext: &[u8],
    recipient_pubkey: &ViewPublicKey,
) -> Result<EncryptedNote, String> {
    let secp = Secp256k1::new();
    
    // Parse recipient's public key
    let recipient_pk = PublicKey::from_slice(recipient_pubkey)
        .map_err(|e| format!("Invalid public key: {}", e))?;
    
    // Generate ephemeral keypair
    let (ephemeral_sk, ephemeral_pk) = secp.generate_keypair(&mut rand::thread_rng());
    
    // Perform ECDH: shared_secret = recipient_pk * ephemeral_sk
    let shared_secret = SharedSecret::new(&recipient_pk, &ephemeral_sk);
    
    // Derive AES key: HKDF(shared_secret)
    let aes_key = kdf(shared_secret.as_ref());
    
    // Encrypt with AES-256-GCM
    let cipher = Aes256Gcm::new_from_slice(&aes_key)
        .map_err(|e| format!("Failed to create cipher: {}", e))?;
    
    let nonce_bytes: [u8; 12] = rand::random();
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| format!("Encryption failed: {}", e))?;
    
    Ok(EncryptedNote {
        key_type: KeyType::Secp256k1,
        ephemeral_pubkey: ephemeral_pk.serialize(),
        nonce: nonce_bytes,
        ciphertext,
    })
}

/// Decrypt an encrypted note
///
/// Returns None if:
/// - Wrong key (ECDH produces different shared secret)
/// - Corrupted ciphertext (GCM auth fails)
/// - Wrong curve type
#[cfg(feature = "encryption")]
pub fn decrypt_note(
    encrypted: &EncryptedNote,
    secret_key: &ViewSecretKey,
) -> Option<Vec<u8>> {
    // Only support secp256k1 for now
    if encrypted.key_type != KeyType::Secp256k1 {
        return None;
    }
    
    // Parse keys
    let recipient_sk = SecretKey::from_slice(secret_key).ok()?;
    let ephemeral_pk = PublicKey::from_slice(&encrypted.ephemeral_pubkey).ok()?;
    
    // Perform ECDH: shared_secret = ephemeral_pk * recipient_sk
    let shared_secret = SharedSecret::new(&ephemeral_pk, &recipient_sk);
    
    // Derive same AES key
    let aes_key = kdf(shared_secret.as_ref());
    
    // Decrypt
    let cipher = Aes256Gcm::new_from_slice(&aes_key).ok()?;
    let nonce = Nonce::from_slice(&encrypted.nonce);
    
    cipher.decrypt(nonce, encrypted.ciphertext.as_ref()).ok()
}

/// Key derivation function: HKDF-SHA256(shared_secret)
#[cfg(feature = "encryption")]
fn kdf(shared_secret: &[u8]) -> [u8; 32] {
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret);
    let mut okm = [0u8; 32];
    // We can use a context string for info to bind it to this specific protocol
    let info = b"utxo-prototype-v1-encryption";
    hkdf.expand(info, &mut okm).expect("HKDF expand failed");
    okm
}

#[cfg(all(test, feature = "encryption"))]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let (secret_key, public_key) = generate_keypair();
        let plaintext = b"Hello, private UTXO with secp256k1!";
        
        let encrypted = encrypt_note(plaintext, &public_key)
            .expect("Encryption should succeed");
        
        assert_eq!(encrypted.key_type, KeyType::Secp256k1);
        assert_eq!(encrypted.ephemeral_pubkey.len(), 33);
        assert_eq!(encrypted.nonce.len(), 12);
        
        let decrypted = decrypt_note(&encrypted, &secret_key)
            .expect("Decryption should succeed");
        
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }
    
    #[test]
    fn test_decrypt_with_wrong_key() {
        let (_, public_key1) = generate_keypair();
        let (secret_key2, _) = generate_keypair();
        
        let encrypted = encrypt_note(b"secret", &public_key1).unwrap();
        let result = decrypt_note(&encrypted, &secret_key2);
        
        assert!(result.is_none(), "Wrong key should fail to decrypt");
    }
    
    #[test]
    fn test_key_format() {
        let (secret, public) = generate_keypair();
        
        // Public key should be 33 bytes (compressed)
        assert_eq!(public.len(), 33);
        assert!(public[0] == 0x02 || public[0] == 0x03, "Should be compressed format");
        
        // Secret key should be 32 bytes
        assert_eq!(secret.len(), 32);
    }
    
    #[test]
    fn test_ciphertext_has_auth_tag() {
        let (_, public_key) = generate_keypair();
        let plaintext = b"test";
        
        let encrypted = encrypt_note(plaintext, &public_key).unwrap();
        
        // AES-GCM adds 16-byte auth tag
        assert_eq!(encrypted.ciphertext.len(), plaintext.len() + 16);
    }
}