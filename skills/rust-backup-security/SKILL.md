# Rust Backup Security Skills

This skill provides patterns for implementing secure backup systems in Rust,
with a focus on Backblaze B2 integration, client-side encryption, and backup
integrity verification.

## Overview

Secure backup encompasses:

- **Client-Side Encryption**: Encrypt before upload
- **Backblaze B2 Integration**: S3-compatible object storage
- **Integrity Verification**: Hash chains and checksums
- **Key Management**: Vault integration for encryption keys
- **Incremental Backups**: Efficient delta synchronization
- **Disaster Recovery**: Secure restore procedures

## /backup-setup

Set up encrypted backup infrastructure.

### Usage

```bash
/backup-setup
```

### What It Does

1. Creates backup client configuration
2. Sets up client-side encryption
3. Configures Backblaze B2 integration
4. Implements backup scheduling
5. Creates integrity verification

---

## Backblaze B2 Client

### Basic Client Setup

```rust
use aws_sdk_s3::{Client as S3Client, Config};
use aws_credential_types::Credentials;

pub struct B2Client {
    client: S3Client,
    bucket: String,
    key_id: String,
}

impl B2Client {
    pub fn new(
        application_key_id: &str,
        application_key: &str,
        bucket: &str,
        endpoint: &str,  // e.g., "s3.us-west-004.backblazeb2.com"
    ) -> Self {
        let credentials = Credentials::new(
            application_key_id,
            application_key,
            None,
            None,
            "b2",
        );

        let config = Config::builder()
            .endpoint_url(format!("https://{}", endpoint))
            .credentials_provider(credentials)
            .region(aws_sdk_s3::config::Region::new("us-west-004"))
            .force_path_style(true)  // B2 requires path-style URLs
            .build();

        Self {
            client: S3Client::from_conf(config),
            bucket: bucket.to_string(),
            key_id: application_key_id.to_string(),
        }
    }

    pub async fn upload(&self, key: &str, data: Vec<u8>) -> Result<String, Error> {
        let response = self.client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(data.into())
            .send()
            .await
            .map_err(Error::B2Upload)?;

        Ok(response.e_tag().unwrap_or_default().to_string())
    }

    pub async fn download(&self, key: &str) -> Result<Vec<u8>, Error> {
        let response = self.client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(Error::B2Download)?;

        let data = response.body
            .collect()
            .await
            .map_err(Error::B2StreamRead)?
            .into_bytes()
            .to_vec();

        Ok(data)
    }

    pub async fn delete(&self, key: &str) -> Result<(), Error> {
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(Error::B2Delete)?;

        Ok(())
    }

    pub async fn list(&self, prefix: &str) -> Result<Vec<BackupFile>, Error> {
        let mut files = Vec::new();
        let mut continuation_token = None;

        loop {
            let mut request = self.client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(prefix);

            if let Some(token) = continuation_token {
                request = request.continuation_token(token);
            }

            let response = request.send().await.map_err(Error::B2List)?;

            for obj in response.contents() {
                files.push(BackupFile {
                    key: obj.key().unwrap_or_default().to_string(),
                    size: obj.size().unwrap_or(0) as u64,
                    last_modified: obj.last_modified()
                        .map(|t| chrono::DateTime::from_timestamp(t.secs(), 0).unwrap())
                        .unwrap_or_else(chrono::Utc::now),
                    etag: obj.e_tag().unwrap_or_default().to_string(),
                });
            }

            if response.is_truncated().unwrap_or(false) {
                continuation_token = response.next_continuation_token().map(String::from);
            } else {
                break;
            }
        }

        Ok(files)
    }
}

#[derive(Debug)]
pub struct BackupFile {
    pub key: String,
    pub size: u64,
    pub last_modified: chrono::DateTime<chrono::Utc>,
    pub etag: String,
}
```

---

## Client-Side Encryption

### Encrypted Backup Manager

```rust
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use zeroize::{Zeroize, ZeroizeOnDrop};
use argon2::Argon2;

#[derive(ZeroizeOnDrop)]
pub struct EncryptedBackupManager {
    b2_client: B2Client,
    #[zeroize(skip)]
    encryption_key: chacha20poly1305::Key,
}

impl EncryptedBackupManager {
    pub fn new(b2_client: B2Client, master_key: &[u8; 32]) -> Self {
        Self {
            b2_client,
            encryption_key: *chacha20poly1305::Key::from_slice(master_key),
        }
    }

    pub fn from_password(b2_client: B2Client, password: &str, salt: &[u8; 16]) -> Result<Self, Error> {
        let mut key = [0u8; 32];

        Argon2::default()
            .hash_password_into(password.as_bytes(), salt, &mut key)
            .map_err(|_| Error::KeyDerivation)?;

        Ok(Self {
            b2_client,
            encryption_key: *chacha20poly1305::Key::from_slice(&key),
        })
    }

    pub async fn backup_file(&self, local_path: &std::path::Path, remote_key: &str) -> Result<BackupMetadata, Error> {
        // Read file
        let plaintext = tokio::fs::read(local_path).await.map_err(Error::FileRead)?;

        // Calculate plaintext hash
        let plaintext_hash = blake3::hash(&plaintext);

        // Generate nonce
        let mut nonce_bytes = [0u8; 12];
        getrandom::getrandom(&mut nonce_bytes).map_err(|_| Error::RandomGeneration)?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt
        let cipher = ChaCha20Poly1305::new(&self.encryption_key);
        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|_| Error::Encryption)?;

        // Build encrypted payload with metadata
        let payload = EncryptedPayload {
            version: 1,
            nonce: nonce_bytes,
            ciphertext,
        };

        let payload_bytes = bincode::serialize(&payload).map_err(Error::Serialize)?;

        // Upload
        let etag = self.b2_client.upload(remote_key, payload_bytes).await?;

        Ok(BackupMetadata {
            local_path: local_path.to_path_buf(),
            remote_key: remote_key.to_string(),
            plaintext_hash: hex::encode(plaintext_hash.as_bytes()),
            size: plaintext.len() as u64,
            encrypted_size: payload.ciphertext.len() as u64 + 12 + 1,  // nonce + version
            timestamp: chrono::Utc::now(),
            etag,
        })
    }

    pub async fn restore_file(&self, remote_key: &str, local_path: &std::path::Path) -> Result<(), Error> {
        // Download
        let payload_bytes = self.b2_client.download(remote_key).await?;

        // Deserialize
        let payload: EncryptedPayload = bincode::deserialize(&payload_bytes)
            .map_err(Error::Deserialize)?;

        // Decrypt
        let cipher = ChaCha20Poly1305::new(&self.encryption_key);
        let nonce = Nonce::from_slice(&payload.nonce);
        let plaintext = cipher
            .decrypt(nonce, payload.ciphertext.as_ref())
            .map_err(|_| Error::Decryption)?;

        // Write file
        tokio::fs::write(local_path, &plaintext).await.map_err(Error::FileWrite)?;

        Ok(())
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct EncryptedPayload {
    version: u8,
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct BackupMetadata {
    pub local_path: std::path::PathBuf,
    pub remote_key: String,
    pub plaintext_hash: String,
    pub size: u64,
    pub encrypted_size: u64,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub etag: String,
}
```

### Chunked Backup for Large Files

```rust
const CHUNK_SIZE: usize = 64 * 1024 * 1024;  // 64MB chunks

pub struct ChunkedBackupManager {
    backup_manager: EncryptedBackupManager,
}

impl ChunkedBackupManager {
    pub async fn backup_large_file(
        &self,
        local_path: &std::path::Path,
        remote_prefix: &str,
    ) -> Result<ChunkedBackupMetadata, Error> {
        let file = tokio::fs::File::open(local_path).await.map_err(Error::FileRead)?;
        let file_size = file.metadata().await?.len();

        let mut reader = tokio::io::BufReader::new(file);
        let mut chunk_index = 0;
        let mut chunks = Vec::new();
        let mut overall_hasher = blake3::Hasher::new();

        loop {
            let mut chunk = vec![0u8; CHUNK_SIZE];
            let bytes_read = tokio::io::AsyncReadExt::read(&mut reader, &mut chunk).await?;

            if bytes_read == 0 {
                break;
            }

            chunk.truncate(bytes_read);
            overall_hasher.update(&chunk);

            let chunk_key = format!("{}/chunk_{:08}", remote_prefix, chunk_index);

            // Calculate chunk hash
            let chunk_hash = blake3::hash(&chunk);

            // Encrypt and upload chunk
            let nonce = generate_nonce()?;
            let cipher = ChaCha20Poly1305::new(&self.backup_manager.encryption_key);
            let encrypted_chunk = cipher
                .encrypt(Nonce::from_slice(&nonce), chunk.as_ref())
                .map_err(|_| Error::Encryption)?;

            let payload = EncryptedPayload {
                version: 1,
                nonce,
                ciphertext: encrypted_chunk,
            };

            let payload_bytes = bincode::serialize(&payload)?;
            let etag = self.backup_manager.b2_client.upload(&chunk_key, payload_bytes).await?;

            chunks.push(ChunkMetadata {
                index: chunk_index,
                key: chunk_key,
                hash: hex::encode(chunk_hash.as_bytes()),
                size: bytes_read as u64,
                etag,
            });

            chunk_index += 1;
        }

        let overall_hash = hex::encode(overall_hasher.finalize().as_bytes());

        // Upload manifest
        let manifest = ChunkedBackupMetadata {
            local_path: local_path.to_path_buf(),
            remote_prefix: remote_prefix.to_string(),
            total_size: file_size,
            chunk_count: chunks.len(),
            chunks: chunks.clone(),
            overall_hash: overall_hash.clone(),
            timestamp: chrono::Utc::now(),
        };

        let manifest_key = format!("{}/manifest.json", remote_prefix);
        let manifest_bytes = serde_json::to_vec(&manifest)?;

        // Encrypt and upload manifest
        let nonce = generate_nonce()?;
        let cipher = ChaCha20Poly1305::new(&self.backup_manager.encryption_key);
        let encrypted_manifest = cipher
            .encrypt(Nonce::from_slice(&nonce), manifest_bytes.as_ref())
            .map_err(|_| Error::Encryption)?;

        let manifest_payload = EncryptedPayload {
            version: 1,
            nonce,
            ciphertext: encrypted_manifest,
        };

        self.backup_manager.b2_client
            .upload(&manifest_key, bincode::serialize(&manifest_payload)?)
            .await?;

        Ok(manifest)
    }

    pub async fn restore_large_file(
        &self,
        remote_prefix: &str,
        local_path: &std::path::Path,
    ) -> Result<(), Error> {
        // Download and decrypt manifest
        let manifest_key = format!("{}/manifest.json", remote_prefix);
        let manifest_payload_bytes = self.backup_manager.b2_client.download(&manifest_key).await?;
        let manifest_payload: EncryptedPayload = bincode::deserialize(&manifest_payload_bytes)?;

        let cipher = ChaCha20Poly1305::new(&self.backup_manager.encryption_key);
        let manifest_bytes = cipher
            .decrypt(Nonce::from_slice(&manifest_payload.nonce), manifest_payload.ciphertext.as_ref())
            .map_err(|_| Error::Decryption)?;

        let manifest: ChunkedBackupMetadata = serde_json::from_slice(&manifest_bytes)?;

        // Create output file
        let file = tokio::fs::File::create(local_path).await?;
        let mut writer = tokio::io::BufWriter::new(file);
        let mut overall_hasher = blake3::Hasher::new();

        // Download and decrypt each chunk
        for chunk in &manifest.chunks {
            let chunk_payload_bytes = self.backup_manager.b2_client.download(&chunk.key).await?;
            let chunk_payload: EncryptedPayload = bincode::deserialize(&chunk_payload_bytes)?;

            let plaintext = cipher
                .decrypt(Nonce::from_slice(&chunk_payload.nonce), chunk_payload.ciphertext.as_ref())
                .map_err(|_| Error::Decryption)?;

            // Verify chunk hash
            let chunk_hash = hex::encode(blake3::hash(&plaintext).as_bytes());
            if chunk_hash != chunk.hash {
                return Err(Error::HashMismatch {
                    chunk: chunk.index,
                    expected: chunk.hash.clone(),
                    actual: chunk_hash,
                });
            }

            overall_hasher.update(&plaintext);
            tokio::io::AsyncWriteExt::write_all(&mut writer, &plaintext).await?;
        }

        tokio::io::AsyncWriteExt::flush(&mut writer).await?;

        // Verify overall hash
        let overall_hash = hex::encode(overall_hasher.finalize().as_bytes());
        if overall_hash != manifest.overall_hash {
            return Err(Error::OverallHashMismatch {
                expected: manifest.overall_hash,
                actual: overall_hash,
            });
        }

        Ok(())
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
pub struct ChunkedBackupMetadata {
    pub local_path: std::path::PathBuf,
    pub remote_prefix: String,
    pub total_size: u64,
    pub chunk_count: usize,
    pub chunks: Vec<ChunkMetadata>,
    pub overall_hash: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
pub struct ChunkMetadata {
    pub index: usize,
    pub key: String,
    pub hash: String,
    pub size: u64,
    pub etag: String,
}

fn generate_nonce() -> Result<[u8; 12], Error> {
    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut nonce).map_err(|_| Error::RandomGeneration)?;
    Ok(nonce)
}
```

---

## Vault Integration for Keys

```rust
use vaultrs::kv2;

pub struct VaultBackupKeyManager {
    vault_client: vaultrs::client::VaultClient,
    vault_mount: String,
    key_path: String,
}

impl VaultBackupKeyManager {
    pub async fn get_backup_key(&self) -> Result<[u8; 32], Error> {
        #[derive(serde::Deserialize)]
        struct BackupKeySecret {
            key: String,  // Base64 encoded
        }

        let secret: BackupKeySecret = kv2::read(&self.vault_client, &self.vault_mount, &self.key_path)
            .await
            .map_err(Error::VaultRead)?;

        let key_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &secret.key,
        ).map_err(|_| Error::InvalidKey)?;

        if key_bytes.len() != 32 {
            return Err(Error::InvalidKeyLength(key_bytes.len()));
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&key_bytes);
        Ok(key)
    }

    pub async fn rotate_backup_key(&self) -> Result<[u8; 32], Error> {
        // Generate new key
        let mut new_key = [0u8; 32];
        getrandom::getrandom(&mut new_key).map_err(|_| Error::RandomGeneration)?;

        // Store in Vault
        #[derive(serde::Serialize)]
        struct BackupKeySecret {
            key: String,
        }

        let secret = BackupKeySecret {
            key: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &new_key),
        };

        kv2::set(&self.vault_client, &self.vault_mount, &self.key_path, &secret)
            .await
            .map_err(Error::VaultWrite)?;

        Ok(new_key)
    }
}
```

---

## Backup Integrity Verification

```rust
pub struct BackupVerifier {
    b2_client: B2Client,
    encryption_key: chacha20poly1305::Key,
}

impl BackupVerifier {
    pub async fn verify_backup(&self, remote_key: &str, expected_hash: &str) -> Result<VerificationResult, Error> {
        // Download
        let payload_bytes = self.b2_client.download(remote_key).await?;
        let payload: EncryptedPayload = bincode::deserialize(&payload_bytes)
            .map_err(Error::Deserialize)?;

        // Decrypt
        let cipher = ChaCha20Poly1305::new(&self.encryption_key);
        let nonce = Nonce::from_slice(&payload.nonce);
        let plaintext = cipher
            .decrypt(nonce, payload.ciphertext.as_ref())
            .map_err(|_| Error::Decryption)?;

        // Verify hash
        let actual_hash = hex::encode(blake3::hash(&plaintext).as_bytes());
        let hash_valid = actual_hash == expected_hash;

        Ok(VerificationResult {
            remote_key: remote_key.to_string(),
            expected_hash: expected_hash.to_string(),
            actual_hash,
            hash_valid,
            size: plaintext.len() as u64,
        })
    }

    pub async fn verify_all_backups(&self, manifest_path: &str) -> Result<Vec<VerificationResult>, Error> {
        let manifest_bytes = tokio::fs::read(manifest_path).await?;
        let manifest: BackupManifest = serde_json::from_slice(&manifest_bytes)?;

        let mut results = Vec::new();

        for entry in &manifest.entries {
            let result = self.verify_backup(&entry.remote_key, &entry.hash).await?;
            results.push(result);
        }

        Ok(results)
    }
}

#[derive(Debug)]
pub struct VerificationResult {
    pub remote_key: String,
    pub expected_hash: String,
    pub actual_hash: String,
    pub hash_valid: bool,
    pub size: u64,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct BackupManifest {
    pub entries: Vec<BackupEntry>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub total_size: u64,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct BackupEntry {
    pub local_path: std::path::PathBuf,
    pub remote_key: String,
    pub hash: String,
    pub size: u64,
}
```

---

## Incremental Backups

```rust
use std::collections::HashMap;

pub struct IncrementalBackupManager {
    backup_manager: EncryptedBackupManager,
    state_path: std::path::PathBuf,
}

impl IncrementalBackupManager {
    pub async fn run_incremental_backup(
        &self,
        source_dir: &std::path::Path,
        remote_prefix: &str,
    ) -> Result<IncrementalBackupReport, Error> {
        // Load previous state
        let previous_state = self.load_state().await.unwrap_or_default();

        // Scan current files
        let current_files = self.scan_directory(source_dir).await?;

        let mut uploaded = Vec::new();
        let mut unchanged = Vec::new();
        let mut deleted = Vec::new();

        // Find files to upload (new or changed)
        for (path, current_hash) in &current_files {
            let needs_upload = match previous_state.files.get(path) {
                Some(prev_hash) => prev_hash != current_hash,
                None => true,
            };

            if needs_upload {
                let remote_key = format!("{}/{}", remote_prefix, path.display());
                let metadata = self.backup_manager
                    .backup_file(path, &remote_key)
                    .await?;
                uploaded.push(metadata);
            } else {
                unchanged.push(path.clone());
            }
        }

        // Find deleted files
        for path in previous_state.files.keys() {
            if !current_files.contains_key(path) {
                let remote_key = format!("{}/{}", remote_prefix, path.display());
                self.backup_manager.b2_client.delete(&remote_key).await?;
                deleted.push(path.clone());
            }
        }

        // Save new state
        let new_state = BackupState {
            files: current_files,
            timestamp: chrono::Utc::now(),
        };
        self.save_state(&new_state).await?;

        Ok(IncrementalBackupReport {
            uploaded,
            unchanged,
            deleted,
            timestamp: chrono::Utc::now(),
        })
    }

    async fn scan_directory(&self, dir: &std::path::Path) -> Result<HashMap<std::path::PathBuf, String>, Error> {
        let mut files = HashMap::new();

        let mut entries = tokio::fs::read_dir(dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            let metadata = entry.metadata().await?;

            if metadata.is_file() {
                let content = tokio::fs::read(&path).await?;
                let hash = hex::encode(blake3::hash(&content).as_bytes());
                files.insert(path, hash);
            } else if metadata.is_dir() {
                let sub_files = Box::pin(self.scan_directory(&path)).await?;
                files.extend(sub_files);
            }
        }

        Ok(files)
    }

    async fn load_state(&self) -> Result<BackupState, Error> {
        let content = tokio::fs::read_to_string(&self.state_path).await?;
        serde_json::from_str(&content).map_err(Error::StateParse)
    }

    async fn save_state(&self, state: &BackupState) -> Result<(), Error> {
        let content = serde_json::to_string_pretty(state)?;
        tokio::fs::write(&self.state_path, content).await?;
        Ok(())
    }
}

#[derive(Default, serde::Serialize, serde::Deserialize)]
struct BackupState {
    files: HashMap<std::path::PathBuf, String>,
    timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug)]
pub struct IncrementalBackupReport {
    pub uploaded: Vec<BackupMetadata>,
    pub unchanged: Vec<std::path::PathBuf>,
    pub deleted: Vec<std::path::PathBuf>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}
```

---

## Backup Security Checklist

### Encryption

- [ ] Client-side encryption before upload
- [ ] Strong encryption algorithm (ChaCha20-Poly1305 or AES-256-GCM)
- [ ] Unique nonce for each encryption
- [ ] Keys stored in Vault
- [ ] Key rotation implemented

### Integrity

- [ ] Hash verification for all backups
- [ ] Chain hashing for sequential backups
- [ ] Manifest files encrypted and signed
- [ ] Regular integrity verification

### Access Control

- [ ] B2 application keys with minimum permissions
- [ ] Separate keys for read and write operations
- [ ] Key rotation policy
- [ ] Audit logging

### Disaster Recovery

- [ ] Tested restore procedures
- [ ] Off-site key backup (securely)
- [ ] Documentation for recovery
- [ ] Regular restore testing

## Recommended Crates

- **aws-sdk-s3**: S3-compatible API (B2)
- **chacha20poly1305**: Encryption
- **blake3**: Hashing
- **argon2**: Key derivation
- **zeroize**: Secure memory clearing
- **vaultrs**: HashiCorp Vault
- **bincode/serde**: Serialization

## Best Practices

1. **Always encrypt locally** - Never send plaintext to cloud
2. **Verify integrity** - Check hashes after upload and before restore
3. **Rotate keys** - Regular key rotation with re-encryption
4. **Test restores** - Regularly verify backup restorability
5. **Monitor storage** - Track backup sizes and costs
6. **Version backups** - Keep multiple versions for point-in-time recovery
7. **Secure key storage** - Use Vault, never store keys in code

## Integration Points

This skill works well with:

- `/vault-setup` - Key management
- `/token-rotate` - Credential rotation
