# Rust Backup Client Template

## Overview

This template provides an encrypted backup client for Backblaze B2 with
client-side encryption, chunked uploads, deduplication, and integrity
verification.

**Target Use Cases:**

- Encrypted cloud backups
- Incremental backup systems
- Disaster recovery
- Secure file synchronization

## Project Structure

```
my-backup-client/
├── Cargo.toml
├── src/
│   ├── main.rs
│   ├── lib.rs
│   ├── b2/
│   │   ├── mod.rs
│   │   ├── client.rs
│   │   └── upload.rs
│   ├── crypto/
│   │   ├── mod.rs
│   │   ├── encrypt.rs
│   │   └── keys.rs
│   ├── backup/
│   │   ├── mod.rs
│   │   ├── chunker.rs
│   │   ├── manifest.rs
│   │   └── restore.rs
│   └── error.rs
└── README.md
```

## Cargo.toml

```toml
[package]
name = "my-backup-client"
version = "0.1.0"
edition = "2021"
rust-version = "1.92.0"

[dependencies]
tokio = { version = "1.40", features = ["full"] }
reqwest = { version = "0.12", features = ["json", "rustls-tls", "stream"], default-features = false }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
aes-gcm = "0.10"
argon2 = "0.5"
sha2 = "0.10"
rand = "0.8"
secrecy = { version = "0.10", features = ["serde"] }
zeroize = { version = "1.8", features = ["derive"] }
base64 = "0.22"
thiserror = "2.0"
tracing = "0.1"
clap = { version = "4.5", features = ["derive"] }
walkdir = "2.5"
indicatif = "0.17"
```

## Core Implementation

### src/crypto/encrypt.rs

```rust
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use secrecy::{ExposeSecret, Secret};
use sha2::{Sha256, Digest};
use zeroize::Zeroize;
use crate::error::BackupError;

pub struct Encryptor {
    cipher: Aes256Gcm,
}

impl Encryptor {
    pub fn new(key: &[u8]) -> Result<Self, BackupError> {
        if key.len() != 32 {
            return Err(BackupError::CryptoError("Key must be 32 bytes".into()));
        }
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|_| BackupError::CryptoError("Invalid key".into()))?;
        Ok(Self { cipher })
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, BackupError> {
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self.cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| BackupError::CryptoError("Encryption failed".into()))?;

        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, BackupError> {
        if ciphertext.len() < 28 {
            return Err(BackupError::CryptoError("Ciphertext too short".into()));
        }

        let (nonce_bytes, encrypted) = ciphertext.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        self.cipher
            .decrypt(nonce, encrypted)
            .map_err(|_| BackupError::CryptoError("Decryption failed".into()))
    }
}

pub fn derive_key(password: &str, salt: &[u8]) -> Result<Secret<Vec<u8>>, BackupError> {
    use argon2::Argon2;

    let params = argon2::Params::new(65536, 3, 4, Some(32))
        .map_err(|e| BackupError::CryptoError(e.to_string()))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut key = vec![0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| BackupError::CryptoError(e.to_string()))?;

    Ok(Secret::new(key))
}

pub fn hash_chunk(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}
```

### src/backup/chunker.rs

```rust
use sha2::{Sha256, Digest};
use std::io::Read;
use crate::error::BackupError;

const MIN_CHUNK_SIZE: usize = 256 * 1024;      // 256KB
const MAX_CHUNK_SIZE: usize = 4 * 1024 * 1024; // 4MB
const TARGET_CHUNK_SIZE: usize = 1024 * 1024;  // 1MB

pub struct Chunk {
    pub data: Vec<u8>,
    pub hash: String,
    pub offset: u64,
    pub size: usize,
}

pub struct Chunker {
    min_size: usize,
    max_size: usize,
}

impl Chunker {
    pub fn new() -> Self {
        Self {
            min_size: MIN_CHUNK_SIZE,
            max_size: MAX_CHUNK_SIZE,
        }
    }

    pub fn chunk_file<R: Read>(&self, reader: &mut R) -> Result<Vec<Chunk>, BackupError> {
        let mut chunks = Vec::new();
        let mut offset = 0u64;
        let mut buffer = vec![0u8; self.max_size];

        loop {
            let bytes_read = reader.read(&mut buffer)
                .map_err(|e| BackupError::IoError(e.to_string()))?;

            if bytes_read == 0 {
                break;
            }

            let data = buffer[..bytes_read].to_vec();
            let hash = self.hash_chunk(&data);

            chunks.push(Chunk {
                data,
                hash,
                offset,
                size: bytes_read,
            });

            offset += bytes_read as u64;
        }

        Ok(chunks)
    }

    fn hash_chunk(&self, data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }
}

impl Default for Chunker {
    fn default() -> Self {
        Self::new()
    }
}
```

### src/b2/client.rs

```rust
use reqwest::Client;
use secrecy::{ExposeSecret, Secret};
use serde::{Deserialize, Serialize};
use crate::error::BackupError;

const B2_API_URL: &str = "https://api.backblazeb2.com/b2api/v2";

#[derive(Debug, Deserialize)]
struct AuthResponse {
    #[serde(rename = "authorizationToken")]
    auth_token: String,
    #[serde(rename = "apiUrl")]
    api_url: String,
    #[serde(rename = "downloadUrl")]
    download_url: String,
}

#[derive(Debug, Deserialize)]
struct UploadUrlResponse {
    #[serde(rename = "uploadUrl")]
    upload_url: String,
    #[serde(rename = "authorizationToken")]
    auth_token: String,
}

pub struct B2Client {
    client: Client,
    key_id: String,
    app_key: Secret<String>,
    auth_token: Option<String>,
    api_url: Option<String>,
    download_url: Option<String>,
}

impl B2Client {
    pub fn new(key_id: &str, app_key: Secret<String>) -> Self {
        Self {
            client: Client::new(),
            key_id: key_id.to_string(),
            app_key,
            auth_token: None,
            api_url: None,
            download_url: None,
        }
    }

    pub async fn authorize(&mut self) -> Result<(), BackupError> {
        let credentials = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            format!("{}:{}", self.key_id, self.app_key.expose_secret()),
        );

        let response: AuthResponse = self.client
            .get(format!("{}/b2_authorize_account", B2_API_URL))
            .header("Authorization", format!("Basic {}", credentials))
            .send()
            .await?
            .json()
            .await?;

        self.auth_token = Some(response.auth_token);
        self.api_url = Some(response.api_url);
        self.download_url = Some(response.download_url);

        Ok(())
    }

    pub async fn upload_file(
        &self,
        bucket_id: &str,
        file_name: &str,
        data: &[u8],
        content_sha1: &str,
    ) -> Result<String, BackupError> {
        let auth_token = self.auth_token.as_ref()
            .ok_or_else(|| BackupError::NotAuthorized)?;
        let api_url = self.api_url.as_ref()
            .ok_or_else(|| BackupError::NotAuthorized)?;

        // Get upload URL
        let upload_url_response: UploadUrlResponse = self.client
            .post(format!("{}/b2api/v2/b2_get_upload_url", api_url))
            .header("Authorization", auth_token)
            .json(&serde_json::json!({ "bucketId": bucket_id }))
            .send()
            .await?
            .json()
            .await?;

        // Upload file
        let response = self.client
            .post(&upload_url_response.upload_url)
            .header("Authorization", &upload_url_response.auth_token)
            .header("X-Bz-File-Name", urlencoding::encode(file_name).as_ref())
            .header("Content-Type", "application/octet-stream")
            .header("X-Bz-Content-Sha1", content_sha1)
            .body(data.to_vec())
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(BackupError::UploadFailed(response.status().to_string()));
        }

        #[derive(Deserialize)]
        struct UploadResponse {
            #[serde(rename = "fileId")]
            file_id: String,
        }

        let upload_response: UploadResponse = response.json().await?;
        Ok(upload_response.file_id)
    }

    pub async fn download_file(&self, file_id: &str) -> Result<Vec<u8>, BackupError> {
        let auth_token = self.auth_token.as_ref()
            .ok_or_else(|| BackupError::NotAuthorized)?;
        let download_url = self.download_url.as_ref()
            .ok_or_else(|| BackupError::NotAuthorized)?;

        let response = self.client
            .get(format!("{}/b2api/v2/b2_download_file_by_id", download_url))
            .query(&[("fileId", file_id)])
            .header("Authorization", auth_token)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(BackupError::DownloadFailed(response.status().to_string()));
        }

        Ok(response.bytes().await?.to_vec())
    }
}
```

### src/backup/manifest.rs

```rust
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupManifest {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub files: Vec<FileEntry>,
    pub chunks: HashMap<String, ChunkInfo>,
    pub total_size: u64,
    pub encrypted_size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub path: String,
    pub size: u64,
    pub modified: DateTime<Utc>,
    pub chunks: Vec<String>, // Chunk hashes
    pub permissions: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkInfo {
    pub hash: String,
    pub size: usize,
    pub encrypted_size: usize,
    pub file_id: String, // B2 file ID
}

impl BackupManifest {
    pub fn new() -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            created_at: Utc::now(),
            files: Vec::new(),
            chunks: HashMap::new(),
            total_size: 0,
            encrypted_size: 0,
        }
    }

    pub fn add_file(&mut self, entry: FileEntry) {
        self.total_size += entry.size;
        self.files.push(entry);
    }

    pub fn add_chunk(&mut self, info: ChunkInfo) {
        self.encrypted_size += info.encrypted_size as u64;
        self.chunks.insert(info.hash.clone(), info);
    }

    pub fn chunk_exists(&self, hash: &str) -> bool {
        self.chunks.contains_key(hash)
    }
}
```

## Security Checklist

- [ ] Encryption key derived with strong KDF
- [ ] All data encrypted before upload
- [ ] Chunk hashes verified on download
- [ ] API keys stored securely
- [ ] Manifest encrypted separately
- [ ] No plaintext data in logs
- [ ] Key rotation supported
- [ ] Integrity verification on restore
