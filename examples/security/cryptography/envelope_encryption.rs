//! Envelope Encryption Example
//!
//! Demonstrates envelope encryption pattern used by AWS KMS, GCP KMS, etc.

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};

/// Data Encryption Key (DEK) - encrypts actual data
#[derive(Clone)]
pub struct DataKey {
    key: [u8; 32],
}

impl DataKey {
    pub fn generate() -> Self {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        Self { key }
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self { key: *bytes }
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.key));
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher.encrypt(nonce, plaintext).expect("encryption failed");

        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend(ciphertext);
        result
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        if ciphertext.len() < 28 {
            return None;
        }

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.key));
        let nonce = Nonce::from_slice(&ciphertext[..12]);
        cipher.decrypt(nonce, &ciphertext[12..]).ok()
    }
}

impl Drop for DataKey {
    fn drop(&mut self) {
        // Zeroize key material
        self.key.iter_mut().for_each(|b| *b = 0);
    }
}

/// Key Encryption Key (KEK) - encrypts DEKs
pub struct MasterKey {
    key: [u8; 32],
    key_id: String,
}

impl MasterKey {
    pub fn new(key_id: &str) -> Self {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        Self {
            key,
            key_id: key_id.to_string(),
        }
    }

    pub fn from_bytes(key_id: &str, bytes: &[u8; 32]) -> Self {
        Self {
            key: *bytes,
            key_id: key_id.to_string(),
        }
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Encrypt a DEK with this master key
    pub fn wrap_key(&self, dek: &DataKey) -> WrappedKey {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.key));
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let encrypted = cipher
            .encrypt(nonce, dek.as_bytes().as_slice())
            .expect("key wrapping failed");

        let mut ciphertext = Vec::with_capacity(12 + encrypted.len());
        ciphertext.extend_from_slice(&nonce_bytes);
        ciphertext.extend(encrypted);

        WrappedKey {
            key_id: self.key_id.clone(),
            ciphertext,
        }
    }

    /// Decrypt a wrapped DEK
    pub fn unwrap_key(&self, wrapped: &WrappedKey) -> Option<DataKey> {
        if wrapped.key_id != self.key_id {
            return None;
        }
        if wrapped.ciphertext.len() < 28 {
            return None;
        }

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.key));
        let nonce = Nonce::from_slice(&wrapped.ciphertext[..12]);

        let decrypted = cipher.decrypt(nonce, &wrapped.ciphertext[12..]).ok()?;
        if decrypted.len() != 32 {
            return None;
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&decrypted);
        Some(DataKey::from_bytes(&key))
    }
}

/// A wrapped (encrypted) data key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedKey {
    pub key_id: String,
    pub ciphertext: Vec<u8>,
}

/// Encrypted data with its wrapped key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedEnvelope {
    pub wrapped_key: WrappedKey,
    pub ciphertext: Vec<u8>,
}

impl EncryptedEnvelope {
    /// Encrypt data using envelope encryption
    pub fn encrypt(master_key: &MasterKey, plaintext: &[u8]) -> Self {
        let dek = DataKey::generate();
        let ciphertext = dek.encrypt(plaintext);
        let wrapped_key = master_key.wrap_key(&dek);
        Self {
            wrapped_key,
            ciphertext,
        }
    }

    /// Decrypt envelope-encrypted data
    pub fn decrypt(&self, master_key: &MasterKey) -> Option<Vec<u8>> {
        let dek = master_key.unwrap_key(&self.wrapped_key)?;
        dek.decrypt(&self.ciphertext)
    }
}

/// Key rotation support
pub struct KeyManager {
    current_key: MasterKey,
    previous_keys: Vec<MasterKey>,
}

impl KeyManager {
    pub fn new(initial_key_id: &str) -> Self {
        Self {
            current_key: MasterKey::new(initial_key_id),
            previous_keys: Vec::new(),
        }
    }

    pub fn rotate(&mut self, new_key_id: &str) {
        let old_key = std::mem::replace(&mut self.current_key, MasterKey::new(new_key_id));
        self.previous_keys.push(old_key);
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> EncryptedEnvelope {
        EncryptedEnvelope::encrypt(&self.current_key, plaintext)
    }

    pub fn decrypt(&self, envelope: &EncryptedEnvelope) -> Option<Vec<u8>> {
        // Try current key first
        if let Some(data) = envelope.decrypt(&self.current_key) {
            return Some(data);
        }
        // Try previous keys
        for key in &self.previous_keys {
            if let Some(data) = envelope.decrypt(key) {
                return Some(data);
            }
        }
        None
    }

    /// Re-encrypt with current key
    pub fn reencrypt(&self, envelope: &EncryptedEnvelope) -> Option<EncryptedEnvelope> {
        let plaintext = self.decrypt(envelope)?;
        Some(self.encrypt(&plaintext))
    }
}

fn main() {
    println!("=== Envelope Encryption ===\n");

    // Create master key
    let master_key = MasterKey::new("master-key-001");
    println!("Master Key ID: {}", master_key.key_id());

    // Encrypt data
    let plaintext = b"Sensitive data that needs protection";
    let envelope = EncryptedEnvelope::encrypt(&master_key, plaintext);

    println!("Plaintext size: {} bytes", plaintext.len());
    println!(
        "Wrapped key size: {} bytes",
        envelope.wrapped_key.ciphertext.len()
    );
    println!("Ciphertext size: {} bytes", envelope.ciphertext.len());

    // Decrypt
    let decrypted = envelope.decrypt(&master_key).expect("decryption failed");
    assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    println!("Decryption successful!");

    // Key rotation
    println!("\n--- Key Rotation ---");
    let mut km = KeyManager::new("key-v1");

    let data1 = km.encrypt(b"Data encrypted with v1");
    println!("Encrypted with key-v1");

    km.rotate("key-v2");
    println!("Rotated to key-v2");

    let data2 = km.encrypt(b"Data encrypted with v2");
    println!("Encrypted new data with key-v2");

    // Both can still be decrypted
    assert!(km.decrypt(&data1).is_some());
    assert!(km.decrypt(&data2).is_some());
    println!("Both old and new data decryptable!");

    // Re-encrypt old data with new key
    let data1_reencrypted = km.reencrypt(&data1).expect("reencrypt failed");
    println!(
        "Re-encrypted old data with new key: {}",
        data1_reencrypted.wrapped_key.key_id
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_envelope_encryption() {
        let master = MasterKey::new("test-key");
        let plaintext = b"test data";

        let envelope = EncryptedEnvelope::encrypt(&master, plaintext);
        let decrypted = envelope.decrypt(&master).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_key_rotation() {
        let mut km = KeyManager::new("v1");
        let data = km.encrypt(b"original");

        km.rotate("v2");

        // Old data still decryptable
        assert!(km.decrypt(&data).is_some());

        // New encryption uses new key
        let new_data = km.encrypt(b"new");
        assert_eq!(new_data.wrapped_key.key_id, "v2");
    }
}
