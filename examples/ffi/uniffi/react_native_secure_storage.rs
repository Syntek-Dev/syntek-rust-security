//! React Native Secure Storage via UniFFI
//!
//! Rust secure storage exposed to React Native applications,
//! providing encrypted key-value storage with platform integration.

use std::collections::HashMap;

/// Storage configuration
#[derive(Debug, Clone)]
pub struct StorageConfig {
    /// Enable encryption at rest
    pub encryption_enabled: bool,
    /// Key derivation iterations
    pub kdf_iterations: u32,
    /// Enable biometric unlock (requires platform support)
    pub biometric_enabled: bool,
    /// Auto-lock timeout in seconds (0 = disabled)
    pub auto_lock_timeout: u32,
    /// Maximum value size in bytes
    pub max_value_size: usize,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            encryption_enabled: true,
            kdf_iterations: 100_000,
            biometric_enabled: false,
            auto_lock_timeout: 300,      // 5 minutes
            max_value_size: 1024 * 1024, // 1 MB
        }
    }
}

/// Storage errors
#[derive(Debug, Clone)]
pub enum StorageError {
    NotInitialized,
    Locked,
    KeyNotFound(String),
    EncryptionError(String),
    DecryptionError(String),
    InvalidPassword,
    ValueTooLarge,
    StorageCorrupted,
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageError::NotInitialized => write!(f, "Storage not initialized"),
            StorageError::Locked => write!(f, "Storage is locked"),
            StorageError::KeyNotFound(key) => write!(f, "Key not found: {}", key),
            StorageError::EncryptionError(msg) => write!(f, "Encryption error: {}", msg),
            StorageError::DecryptionError(msg) => write!(f, "Decryption error: {}", msg),
            StorageError::InvalidPassword => write!(f, "Invalid password"),
            StorageError::ValueTooLarge => write!(f, "Value too large"),
            StorageError::StorageCorrupted => write!(f, "Storage corrupted"),
        }
    }
}

impl std::error::Error for StorageError {}

/// Secure storage item
#[derive(Debug, Clone)]
pub struct StorageItem {
    pub key: String,
    pub value: Vec<u8>,
    pub created_at: u64,
    pub updated_at: u64,
    pub metadata: HashMap<String, String>,
}

/// Main secure storage for React Native
///
/// Usage in React Native (TypeScript):
/// ```typescript
/// import { SecureStorage } from 'rust-secure-storage';
///
/// const storage = new SecureStorage();
/// await storage.initialize('user_password');
/// await storage.setItem('api_key', 'secret_value');
/// const value = await storage.getItem('api_key');
/// ```
#[derive(Debug)]
pub struct SecureStorage {
    config: StorageConfig,
    master_key: Option<Vec<u8>>,
    storage: HashMap<String, EncryptedItem>,
    is_locked: bool,
    last_access: u64,
}

#[derive(Debug, Clone)]
struct EncryptedItem {
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
    tag: Vec<u8>,
    created_at: u64,
    updated_at: u64,
    metadata: HashMap<String, String>,
}

impl SecureStorage {
    /// Create new secure storage instance
    pub fn new() -> Self {
        Self::with_config(StorageConfig::default())
    }

    /// Create with custom configuration
    pub fn with_config(config: StorageConfig) -> Self {
        Self {
            config,
            master_key: None,
            storage: HashMap::new(),
            is_locked: true,
            last_access: 0,
        }
    }

    /// Initialize storage with password
    pub fn initialize(&mut self, password: &str) -> Result<(), StorageError> {
        if password.len() < 8 {
            return Err(StorageError::InvalidPassword);
        }

        // Derive master key from password
        let salt = self.get_or_create_salt();
        let master_key = derive_key(password.as_bytes(), &salt, self.config.kdf_iterations, 32);

        self.master_key = Some(master_key);
        self.is_locked = false;
        self.update_last_access();

        Ok(())
    }

    /// Lock the storage
    pub fn lock(&mut self) {
        if let Some(ref mut key) = self.master_key {
            // Zeroize master key
            key.iter_mut().for_each(|b| *b = 0);
        }
        self.master_key = None;
        self.is_locked = true;
    }

    /// Unlock the storage
    pub fn unlock(&mut self, password: &str) -> Result<(), StorageError> {
        self.initialize(password)
    }

    /// Check if storage is locked
    pub fn is_locked(&self) -> bool {
        self.is_locked
    }

    /// Store an item
    pub fn set_item(&mut self, key: &str, value: &[u8]) -> Result<(), StorageError> {
        self.check_unlocked()?;

        if value.len() > self.config.max_value_size {
            return Err(StorageError::ValueTooLarge);
        }

        let master_key = self.master_key.as_ref().unwrap();
        let now = current_timestamp();

        // Generate nonce
        let mut nonce = vec![0u8; 12];
        fill_random(&mut nonce);

        // Encrypt value
        let (ciphertext, tag) = encrypt_aead(value, master_key, &nonce)?;

        let item = EncryptedItem {
            ciphertext,
            nonce,
            tag,
            created_at: self.storage.get(key).map(|i| i.created_at).unwrap_or(now),
            updated_at: now,
            metadata: HashMap::new(),
        };

        self.storage.insert(key.to_string(), item);
        self.update_last_access();

        Ok(())
    }

    /// Store an item with metadata
    pub fn set_item_with_metadata(
        &mut self,
        key: &str,
        value: &[u8],
        metadata: HashMap<String, String>,
    ) -> Result<(), StorageError> {
        self.set_item(key, value)?;

        if let Some(item) = self.storage.get_mut(key) {
            item.metadata = metadata;
        }

        Ok(())
    }

    /// Get an item
    pub fn get_item(&mut self, key: &str) -> Result<Vec<u8>, StorageError> {
        self.check_unlocked()?;

        let item = self
            .storage
            .get(key)
            .ok_or_else(|| StorageError::KeyNotFound(key.to_string()))?;

        let master_key = self.master_key.as_ref().unwrap();
        let plaintext = decrypt_aead(&item.ciphertext, master_key, &item.nonce, &item.tag)?;

        self.update_last_access();
        Ok(plaintext)
    }

    /// Get item as string
    pub fn get_string(&mut self, key: &str) -> Result<String, StorageError> {
        let bytes = self.get_item(key)?;
        String::from_utf8(bytes)
            .map_err(|_| StorageError::DecryptionError("Invalid UTF-8".to_string()))
    }

    /// Store a string
    pub fn set_string(&mut self, key: &str, value: &str) -> Result<(), StorageError> {
        self.set_item(key, value.as_bytes())
    }

    /// Check if key exists
    pub fn has_key(&self, key: &str) -> bool {
        self.storage.contains_key(key)
    }

    /// Remove an item
    pub fn remove_item(&mut self, key: &str) -> Result<(), StorageError> {
        self.check_unlocked()?;

        if let Some(mut item) = self.storage.remove(key) {
            // Zeroize ciphertext
            item.ciphertext.iter_mut().for_each(|b| *b = 0);
        }

        self.update_last_access();
        Ok(())
    }

    /// Get all keys
    pub fn get_all_keys(&self) -> Result<Vec<String>, StorageError> {
        self.check_unlocked()?;
        Ok(self.storage.keys().cloned().collect())
    }

    /// Get item metadata
    pub fn get_metadata(&self, key: &str) -> Result<HashMap<String, String>, StorageError> {
        self.check_unlocked()?;

        let item = self
            .storage
            .get(key)
            .ok_or_else(|| StorageError::KeyNotFound(key.to_string()))?;

        Ok(item.metadata.clone())
    }

    /// Get item info (without decrypting)
    pub fn get_item_info(&self, key: &str) -> Result<ItemInfo, StorageError> {
        self.check_unlocked()?;

        let item = self
            .storage
            .get(key)
            .ok_or_else(|| StorageError::KeyNotFound(key.to_string()))?;

        Ok(ItemInfo {
            key: key.to_string(),
            size: item.ciphertext.len(),
            created_at: item.created_at,
            updated_at: item.updated_at,
            metadata: item.metadata.clone(),
        })
    }

    /// Clear all items
    pub fn clear(&mut self) -> Result<(), StorageError> {
        self.check_unlocked()?;

        // Zeroize all ciphertexts
        for (_, mut item) in self.storage.drain() {
            item.ciphertext.iter_mut().for_each(|b| *b = 0);
        }

        Ok(())
    }

    /// Change password
    pub fn change_password(
        &mut self,
        old_password: &str,
        new_password: &str,
    ) -> Result<(), StorageError> {
        // Verify old password
        let salt = self.get_or_create_salt();
        let old_key = derive_key(
            old_password.as_bytes(),
            &salt,
            self.config.kdf_iterations,
            32,
        );

        if self.master_key.as_ref() != Some(&old_key) {
            return Err(StorageError::InvalidPassword);
        }

        // Derive new key
        let new_salt = generate_salt();
        let new_key = derive_key(
            new_password.as_bytes(),
            &new_salt,
            self.config.kdf_iterations,
            32,
        );

        // Re-encrypt all items with new key
        let mut new_storage = HashMap::new();

        for (key, item) in &self.storage {
            // Decrypt with old key
            let plaintext = decrypt_aead(&item.ciphertext, &old_key, &item.nonce, &item.tag)?;

            // Encrypt with new key
            let mut nonce = vec![0u8; 12];
            fill_random(&mut nonce);
            let (ciphertext, tag) = encrypt_aead(&plaintext, &new_key, &nonce)?;

            new_storage.insert(
                key.clone(),
                EncryptedItem {
                    ciphertext,
                    nonce,
                    tag,
                    created_at: item.created_at,
                    updated_at: current_timestamp(),
                    metadata: item.metadata.clone(),
                },
            );
        }

        self.storage = new_storage;
        self.master_key = Some(new_key);

        Ok(())
    }

    /// Export encrypted backup
    pub fn export_backup(&self) -> Result<Vec<u8>, StorageError> {
        self.check_unlocked()?;

        // Serialize storage (simplified)
        let mut backup = Vec::new();

        for (key, item) in &self.storage {
            backup.extend((key.len() as u32).to_le_bytes());
            backup.extend(key.as_bytes());
            backup.extend((item.ciphertext.len() as u32).to_le_bytes());
            backup.extend(&item.ciphertext);
            backup.extend(&item.nonce);
            backup.extend(&item.tag);
        }

        Ok(backup)
    }

    /// Get storage statistics
    pub fn get_stats(&self) -> StorageStats {
        let total_size: usize = self
            .storage
            .values()
            .map(|item| item.ciphertext.len())
            .sum();

        StorageStats {
            item_count: self.storage.len(),
            total_size,
            is_locked: self.is_locked,
            encryption_enabled: self.config.encryption_enabled,
        }
    }

    fn check_unlocked(&self) -> Result<(), StorageError> {
        if self.is_locked {
            return Err(StorageError::Locked);
        }

        // Check auto-lock timeout
        if self.config.auto_lock_timeout > 0 {
            let elapsed = current_timestamp() - self.last_access;
            if elapsed > self.config.auto_lock_timeout as u64 {
                return Err(StorageError::Locked);
            }
        }

        Ok(())
    }

    fn update_last_access(&mut self) {
        self.last_access = current_timestamp();
    }

    fn get_or_create_salt(&self) -> Vec<u8> {
        // In production, this would be stored persistently
        generate_salt()
    }
}

impl Default for SecureStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for SecureStorage {
    fn drop(&mut self) {
        self.lock();
        self.clear().ok();
    }
}

/// Item information
#[derive(Debug, Clone)]
pub struct ItemInfo {
    pub key: String,
    pub size: usize,
    pub created_at: u64,
    pub updated_at: u64,
    pub metadata: HashMap<String, String>,
}

/// Storage statistics
#[derive(Debug, Clone)]
pub struct StorageStats {
    pub item_count: usize,
    pub total_size: usize,
    pub is_locked: bool,
    pub encryption_enabled: bool,
}

/// Keychain integration (platform-specific)
#[derive(Debug)]
pub struct KeychainBridge {
    service_name: String,
}

impl KeychainBridge {
    pub fn new(service_name: &str) -> Self {
        Self {
            service_name: service_name.to_string(),
        }
    }

    /// Store in keychain (simulated)
    pub fn store(&self, key: &str, value: &[u8]) -> Result<(), StorageError> {
        // In production, this would use platform keychain APIs
        println!(
            "Keychain store: {}:{} ({} bytes)",
            self.service_name,
            key,
            value.len()
        );
        Ok(())
    }

    /// Retrieve from keychain (simulated)
    pub fn retrieve(&self, key: &str) -> Result<Vec<u8>, StorageError> {
        // In production, this would use platform keychain APIs
        println!("Keychain retrieve: {}:{}", self.service_name, key);
        Err(StorageError::KeyNotFound(key.to_string()))
    }

    /// Delete from keychain (simulated)
    pub fn delete(&self, key: &str) -> Result<(), StorageError> {
        println!("Keychain delete: {}:{}", self.service_name, key);
        Ok(())
    }
}

// Helper functions

fn current_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn fill_random(buf: &mut [u8]) {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::time::{SystemTime, UNIX_EPOCH};

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    for (i, byte) in buf.iter_mut().enumerate() {
        let mut hasher = DefaultHasher::new();
        timestamp.hash(&mut hasher);
        i.hash(&mut hasher);
        std::process::id().hash(&mut hasher);
        *byte = (hasher.finish() & 0xFF) as u8;
    }
}

fn generate_salt() -> Vec<u8> {
    let mut salt = vec![0u8; 32];
    fill_random(&mut salt);
    salt
}

fn derive_key(password: &[u8], salt: &[u8], iterations: u32, length: usize) -> Vec<u8> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut key = Vec::with_capacity(length);
    let mut state = 0u64;

    for (i, &byte) in password.iter().chain(salt.iter()).enumerate() {
        let mut hasher = DefaultHasher::new();
        state.hash(&mut hasher);
        (byte as u64).hash(&mut hasher);
        i.hash(&mut hasher);
        state = hasher.finish();
    }

    for _ in 0..iterations {
        let mut hasher = DefaultHasher::new();
        state.hash(&mut hasher);
        state = hasher.finish();
    }

    for i in 0..length {
        let mut hasher = DefaultHasher::new();
        state.hash(&mut hasher);
        i.hash(&mut hasher);
        key.push((hasher.finish() & 0xFF) as u8);
    }

    key
}

fn encrypt_aead(
    plaintext: &[u8],
    key: &[u8],
    nonce: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), StorageError> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    // Generate keystream
    let mut keystream = Vec::with_capacity(plaintext.len());
    let mut state = 0u64;

    for &b in key.iter().chain(nonce.iter()) {
        let mut hasher = DefaultHasher::new();
        state.hash(&mut hasher);
        (b as u64).hash(&mut hasher);
        state = hasher.finish();
    }

    for i in 0..plaintext.len() {
        let mut hasher = DefaultHasher::new();
        state.hash(&mut hasher);
        i.hash(&mut hasher);
        state = hasher.finish();
        keystream.push((state & 0xFF) as u8);
    }

    // Encrypt
    let ciphertext: Vec<u8> = plaintext
        .iter()
        .zip(keystream.iter())
        .map(|(p, k)| p ^ k)
        .collect();

    // Generate tag
    let mut hasher = DefaultHasher::new();
    key.hash(&mut hasher);
    nonce.hash(&mut hasher);
    ciphertext.hash(&mut hasher);
    let hash1 = hasher.finish();

    let mut hasher2 = DefaultHasher::new();
    hash1.hash(&mut hasher2);
    key.hash(&mut hasher2);
    let hash2 = hasher2.finish();

    let mut tag = Vec::with_capacity(16);
    tag.extend(&hash1.to_le_bytes());
    tag.extend(&hash2.to_le_bytes());

    Ok((ciphertext, tag))
}

fn decrypt_aead(
    ciphertext: &[u8],
    key: &[u8],
    nonce: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>, StorageError> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    // Verify tag first
    let mut hasher = DefaultHasher::new();
    key.hash(&mut hasher);
    nonce.hash(&mut hasher);
    ciphertext.hash(&mut hasher);
    let hash1 = hasher.finish();

    let mut hasher2 = DefaultHasher::new();
    hash1.hash(&mut hasher2);
    key.hash(&mut hasher2);
    let hash2 = hasher2.finish();

    let mut expected_tag = Vec::with_capacity(16);
    expected_tag.extend(&hash1.to_le_bytes());
    expected_tag.extend(&hash2.to_le_bytes());

    if !constant_time_eq(&expected_tag, tag) {
        return Err(StorageError::DecryptionError(
            "Authentication failed".to_string(),
        ));
    }

    // Generate keystream
    let mut keystream = Vec::with_capacity(ciphertext.len());
    let mut state = 0u64;

    for &b in key.iter().chain(nonce.iter()) {
        let mut hasher = DefaultHasher::new();
        state.hash(&mut hasher);
        (b as u64).hash(&mut hasher);
        state = hasher.finish();
    }

    for i in 0..ciphertext.len() {
        let mut hasher = DefaultHasher::new();
        state.hash(&mut hasher);
        i.hash(&mut hasher);
        state = hasher.finish();
        keystream.push((state & 0xFF) as u8);
    }

    // Decrypt
    let plaintext: Vec<u8> = ciphertext
        .iter()
        .zip(keystream.iter())
        .map(|(c, k)| c ^ k)
        .collect();

    Ok(plaintext)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

fn main() {
    println!("=== React Native Secure Storage Demo ===\n");

    let mut storage = SecureStorage::new();

    // Initialize with password
    println!("--- Initialization ---\n");
    storage.initialize("my_secure_password_123").unwrap();
    println!("Storage initialized");
    println!("Is locked: {}", storage.is_locked());

    // Store items
    println!("\n--- Storing Items ---\n");
    storage.set_string("api_key", "sk_live_abc123xyz").unwrap();
    storage
        .set_string("user_token", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
        .unwrap();
    storage
        .set_item("binary_data", &[0x01, 0x02, 0x03, 0x04])
        .unwrap();

    let mut metadata = HashMap::new();
    metadata.insert("type".to_string(), "oauth_token".to_string());
    metadata.insert("expires".to_string(), "2024-12-31".to_string());
    storage
        .set_item_with_metadata("oauth_token", b"oauth_secret_value", metadata)
        .unwrap();

    println!("Stored 4 items");

    // Retrieve items
    println!("\n--- Retrieving Items ---\n");
    let api_key = storage.get_string("api_key").unwrap();
    println!("API Key: {}...", &api_key[..api_key.len().min(20)]);

    let binary = storage.get_item("binary_data").unwrap();
    println!("Binary data: {:?}", binary);

    // Get metadata
    let meta = storage.get_metadata("oauth_token").unwrap();
    println!("OAuth token metadata: {:?}", meta);

    // Get item info
    let info = storage.get_item_info("api_key").unwrap();
    println!(
        "API Key info: size={}, created={}",
        info.size, info.created_at
    );

    // List all keys
    println!("\n--- All Keys ---\n");
    let keys = storage.get_all_keys().unwrap();
    for key in &keys {
        println!("  - {}", key);
    }

    // Storage statistics
    println!("\n--- Statistics ---\n");
    let stats = storage.get_stats();
    println!("Item count: {}", stats.item_count);
    println!("Total size: {} bytes", stats.total_size);
    println!("Encryption enabled: {}", stats.encryption_enabled);

    // Lock and unlock
    println!("\n--- Lock/Unlock ---\n");
    storage.lock();
    println!("Storage locked: {}", storage.is_locked());

    match storage.get_string("api_key") {
        Ok(_) => println!("ERROR: Should not be able to read when locked"),
        Err(e) => println!("Expected error: {}", e),
    }

    storage.unlock("my_secure_password_123").unwrap();
    println!("Storage unlocked: {}", !storage.is_locked());

    // Remove item
    println!("\n--- Remove Item ---\n");
    storage.remove_item("binary_data").unwrap();
    println!("Removed binary_data");
    println!("Has key 'binary_data': {}", storage.has_key("binary_data"));

    // Export backup
    println!("\n--- Backup ---\n");
    let backup = storage.export_backup().unwrap();
    println!("Backup size: {} bytes", backup.len());

    // Keychain bridge
    println!("\n--- Keychain Bridge ---\n");
    let keychain = KeychainBridge::new("com.myapp.secure");
    keychain.store("master_key", b"encrypted_key_data").unwrap();

    // Clear storage
    println!("\n--- Clear Storage ---\n");
    storage.clear().unwrap();
    println!("Storage cleared");
    println!("Item count: {}", storage.get_stats().item_count);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initialization() {
        let mut storage = SecureStorage::new();
        storage.initialize("test_password_123").unwrap();
        assert!(!storage.is_locked());
    }

    #[test]
    fn test_short_password_rejected() {
        let mut storage = SecureStorage::new();
        let result = storage.initialize("short");
        assert!(matches!(result, Err(StorageError::InvalidPassword)));
    }

    #[test]
    fn test_set_get_item() {
        let mut storage = SecureStorage::new();
        storage.initialize("test_password_123").unwrap();

        storage.set_item("key1", b"value1").unwrap();
        let value = storage.get_item("key1").unwrap();

        assert_eq!(value, b"value1");
    }

    #[test]
    fn test_set_get_string() {
        let mut storage = SecureStorage::new();
        storage.initialize("test_password_123").unwrap();

        storage.set_string("key1", "Hello, World!").unwrap();
        let value = storage.get_string("key1").unwrap();

        assert_eq!(value, "Hello, World!");
    }

    #[test]
    fn test_key_not_found() {
        let mut storage = SecureStorage::new();
        storage.initialize("test_password_123").unwrap();

        let result = storage.get_item("nonexistent");
        assert!(matches!(result, Err(StorageError::KeyNotFound(_))));
    }

    #[test]
    fn test_has_key() {
        let mut storage = SecureStorage::new();
        storage.initialize("test_password_123").unwrap();

        storage.set_item("existing", b"value").unwrap();

        assert!(storage.has_key("existing"));
        assert!(!storage.has_key("nonexistent"));
    }

    #[test]
    fn test_remove_item() {
        let mut storage = SecureStorage::new();
        storage.initialize("test_password_123").unwrap();

        storage.set_item("key1", b"value1").unwrap();
        assert!(storage.has_key("key1"));

        storage.remove_item("key1").unwrap();
        assert!(!storage.has_key("key1"));
    }

    #[test]
    fn test_lock_unlock() {
        let mut storage = SecureStorage::new();
        storage.initialize("test_password_123").unwrap();

        storage.set_item("key1", b"value1").unwrap();
        storage.lock();

        assert!(storage.is_locked());
        assert!(storage.get_item("key1").is_err());

        storage.unlock("test_password_123").unwrap();
        assert!(!storage.is_locked());
        assert!(storage.get_item("key1").is_ok());
    }

    #[test]
    fn test_metadata() {
        let mut storage = SecureStorage::new();
        storage.initialize("test_password_123").unwrap();

        let mut metadata = HashMap::new();
        metadata.insert("type".to_string(), "token".to_string());

        storage
            .set_item_with_metadata("key1", b"value1", metadata.clone())
            .unwrap();

        let retrieved_meta = storage.get_metadata("key1").unwrap();
        assert_eq!(retrieved_meta.get("type"), Some(&"token".to_string()));
    }

    #[test]
    fn test_get_all_keys() {
        let mut storage = SecureStorage::new();
        storage.initialize("test_password_123").unwrap();

        storage.set_item("key1", b"value1").unwrap();
        storage.set_item("key2", b"value2").unwrap();
        storage.set_item("key3", b"value3").unwrap();

        let keys = storage.get_all_keys().unwrap();
        assert_eq!(keys.len(), 3);
    }

    #[test]
    fn test_clear() {
        let mut storage = SecureStorage::new();
        storage.initialize("test_password_123").unwrap();

        storage.set_item("key1", b"value1").unwrap();
        storage.set_item("key2", b"value2").unwrap();

        storage.clear().unwrap();

        let keys = storage.get_all_keys().unwrap();
        assert!(keys.is_empty());
    }

    #[test]
    fn test_statistics() {
        let mut storage = SecureStorage::new();
        storage.initialize("test_password_123").unwrap();

        storage.set_item("key1", b"value1").unwrap();
        storage.set_item("key2", b"longer_value_here").unwrap();

        let stats = storage.get_stats();
        assert_eq!(stats.item_count, 2);
        assert!(stats.total_size > 0);
        assert!(stats.encryption_enabled);
    }

    #[test]
    fn test_value_too_large() {
        let config = StorageConfig {
            max_value_size: 10,
            ..Default::default()
        };
        let mut storage = SecureStorage::with_config(config);
        storage.initialize("test_password_123").unwrap();

        let large_value = vec![0u8; 100];
        let result = storage.set_item("key1", &large_value);

        assert!(matches!(result, Err(StorageError::ValueTooLarge)));
    }

    #[test]
    fn test_item_info() {
        let mut storage = SecureStorage::new();
        storage.initialize("test_password_123").unwrap();

        storage.set_item("key1", b"value1").unwrap();

        let info = storage.get_item_info("key1").unwrap();
        assert_eq!(info.key, "key1");
        assert!(info.size > 0);
        assert!(info.created_at > 0);
    }

    #[test]
    fn test_export_backup() {
        let mut storage = SecureStorage::new();
        storage.initialize("test_password_123").unwrap();

        storage.set_item("key1", b"value1").unwrap();

        let backup = storage.export_backup().unwrap();
        assert!(!backup.is_empty());
    }
}
