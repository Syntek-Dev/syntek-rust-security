# Rust File Scanning Skills

This skill provides patterns for building file scanning systems in Rust with
ClamAV integration, file type detection, and quarantine management.

## Overview

File scanning encompasses:

- **ClamAV Integration**: Virus signature scanning
- **File Type Detection**: Magic byte analysis
- **Real-time Monitoring**: inotify/kqueue integration
- **Quarantine System**: Isolated storage for threats
- **Scan Scheduling**: Periodic full scans

## /malware-scanner-setup

Initialize a file scanning engine.

### Usage

```bash
/malware-scanner-setup
```

## /quarantine-setup

Configure file quarantine system.

### Usage

```bash
/quarantine-setup
```

---

## ClamAV Integration

### ClamAV Client

```rust
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;

pub struct ClamAvClient {
    socket_path: String,
    timeout: std::time::Duration,
}

#[derive(Debug, Clone)]
pub enum ScanResult {
    Clean,
    Infected { virus_name: String },
    Error { message: String },
}

impl ClamAvClient {
    pub fn new_unix(socket_path: &str) -> Self {
        Self {
            socket_path: socket_path.to_string(),
            timeout: std::time::Duration::from_secs(30),
        }
    }

    pub fn new_tcp(host: &str, port: u16) -> Self {
        Self {
            socket_path: format!("{}:{}", host, port),
            timeout: std::time::Duration::from_secs(30),
        }
    }

    /// Scan a file by path
    pub fn scan_file(&self, path: &Path) -> Result<ScanResult, Error> {
        let mut conn = self.connect()?;

        // Use SCAN command (single file)
        let command = format!("SCAN {}\n", path.display());
        conn.write_all(command.as_bytes())?;
        conn.flush()?;

        // Read response
        let mut response = String::new();
        conn.read_to_string(&mut response)?;

        Self::parse_response(&response)
    }

    /// Scan bytes directly (using INSTREAM)
    pub fn scan_bytes(&self, data: &[u8]) -> Result<ScanResult, Error> {
        let mut conn = self.connect()?;

        // Send INSTREAM command
        conn.write_all(b"zINSTREAM\0")?;

        // Send data in chunks with length prefix
        for chunk in data.chunks(2048) {
            let len = (chunk.len() as u32).to_be_bytes();
            conn.write_all(&len)?;
            conn.write_all(chunk)?;
        }

        // Send zero-length chunk to signal end
        conn.write_all(&[0, 0, 0, 0])?;
        conn.flush()?;

        // Read response
        let mut response = Vec::new();
        conn.read_to_end(&mut response)?;

        // Parse null-terminated response
        let response = String::from_utf8_lossy(&response);
        let response = response.trim_end_matches('\0');

        Self::parse_response(response)
    }

    /// Ping the ClamAV daemon
    pub fn ping(&self) -> Result<bool, Error> {
        let mut conn = self.connect()?;

        conn.write_all(b"PING\n")?;
        conn.flush()?;

        let mut response = String::new();
        conn.read_to_string(&mut response)?;

        Ok(response.trim() == "PONG")
    }

    /// Reload virus database
    pub fn reload(&self) -> Result<(), Error> {
        let mut conn = self.connect()?;

        conn.write_all(b"RELOAD\n")?;
        conn.flush()?;

        let mut response = String::new();
        conn.read_to_string(&mut response)?;

        if response.trim() == "RELOADING" {
            Ok(())
        } else {
            Err(Error::ReloadFailed(response))
        }
    }

    /// Get ClamAV version
    pub fn version(&self) -> Result<String, Error> {
        let mut conn = self.connect()?;

        conn.write_all(b"VERSION\n")?;
        conn.flush()?;

        let mut response = String::new();
        conn.read_to_string(&mut response)?;

        Ok(response.trim().to_string())
    }

    fn connect(&self) -> Result<Box<dyn Read + Write>, Error> {
        if self.socket_path.contains(':') {
            // TCP connection
            let stream = TcpStream::connect(&self.socket_path)?;
            stream.set_read_timeout(Some(self.timeout))?;
            stream.set_write_timeout(Some(self.timeout))?;
            Ok(Box::new(stream))
        } else {
            // Unix socket
            #[cfg(unix)]
            {
                use std::os::unix::net::UnixStream;
                let stream = UnixStream::connect(&self.socket_path)?;
                stream.set_read_timeout(Some(self.timeout))?;
                stream.set_write_timeout(Some(self.timeout))?;
                Ok(Box::new(stream))
            }
            #[cfg(not(unix))]
            {
                Err(Error::UnixSocketNotSupported)
            }
        }
    }

    fn parse_response(response: &str) -> Result<ScanResult, Error> {
        let response = response.trim();

        if response.ends_with("OK") {
            return Ok(ScanResult::Clean);
        }

        if response.contains("FOUND") {
            // Format: "path: VirusName FOUND"
            if let Some(virus) = response.split(':').nth(1) {
                let virus = virus.trim().trim_end_matches(" FOUND").to_string();
                return Ok(ScanResult::Infected { virus_name: virus });
            }
        }

        if response.contains("ERROR") {
            return Ok(ScanResult::Error {
                message: response.to_string(),
            });
        }

        Err(Error::UnknownResponse(response.to_string()))
    }
}
```

---

## File Type Detection

```rust
pub struct FileTypeDetector {
    magic_bytes: Vec<MagicSignature>,
}

#[derive(Debug, Clone)]
pub struct MagicSignature {
    pub offset: usize,
    pub bytes: Vec<u8>,
    pub file_type: FileType,
    pub mime_type: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    // Executables
    PeExecutable,
    ElfExecutable,
    MachO,
    Script,

    // Archives
    Zip,
    Gzip,
    Tar,
    Rar,
    SevenZip,

    // Documents
    Pdf,
    MsWord,
    MsExcel,
    OpenDocument,

    // Images
    Jpeg,
    Png,
    Gif,
    Bmp,

    // Other
    Unknown,
}

impl FileTypeDetector {
    pub fn new() -> Self {
        let magic_bytes = vec![
            // Executables
            MagicSignature {
                offset: 0,
                bytes: vec![0x4D, 0x5A],  // MZ
                file_type: FileType::PeExecutable,
                mime_type: "application/x-dosexec".to_string(),
            },
            MagicSignature {
                offset: 0,
                bytes: vec![0x7F, 0x45, 0x4C, 0x46],  // ELF
                file_type: FileType::ElfExecutable,
                mime_type: "application/x-executable".to_string(),
            },
            MagicSignature {
                offset: 0,
                bytes: vec![0xCF, 0xFA, 0xED, 0xFE],  // Mach-O 64-bit
                file_type: FileType::MachO,
                mime_type: "application/x-mach-binary".to_string(),
            },
            MagicSignature {
                offset: 0,
                bytes: vec![0x23, 0x21],  // #!
                file_type: FileType::Script,
                mime_type: "text/x-script".to_string(),
            },

            // Archives
            MagicSignature {
                offset: 0,
                bytes: vec![0x50, 0x4B, 0x03, 0x04],  // PK
                file_type: FileType::Zip,
                mime_type: "application/zip".to_string(),
            },
            MagicSignature {
                offset: 0,
                bytes: vec![0x1F, 0x8B],  // Gzip
                file_type: FileType::Gzip,
                mime_type: "application/gzip".to_string(),
            },
            MagicSignature {
                offset: 0,
                bytes: vec![0x52, 0x61, 0x72, 0x21],  // Rar!
                file_type: FileType::Rar,
                mime_type: "application/vnd.rar".to_string(),
            },
            MagicSignature {
                offset: 0,
                bytes: vec![0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C],  // 7z
                file_type: FileType::SevenZip,
                mime_type: "application/x-7z-compressed".to_string(),
            },

            // Documents
            MagicSignature {
                offset: 0,
                bytes: vec![0x25, 0x50, 0x44, 0x46],  // %PDF
                file_type: FileType::Pdf,
                mime_type: "application/pdf".to_string(),
            },
            MagicSignature {
                offset: 0,
                bytes: vec![0xD0, 0xCF, 0x11, 0xE0],  // MS Office
                file_type: FileType::MsWord,
                mime_type: "application/msword".to_string(),
            },

            // Images
            MagicSignature {
                offset: 0,
                bytes: vec![0xFF, 0xD8, 0xFF],  // JPEG
                file_type: FileType::Jpeg,
                mime_type: "image/jpeg".to_string(),
            },
            MagicSignature {
                offset: 0,
                bytes: vec![0x89, 0x50, 0x4E, 0x47],  // PNG
                file_type: FileType::Png,
                mime_type: "image/png".to_string(),
            },
            MagicSignature {
                offset: 0,
                bytes: vec![0x47, 0x49, 0x46],  // GIF
                file_type: FileType::Gif,
                mime_type: "image/gif".to_string(),
            },
        ];

        Self { magic_bytes }
    }

    pub fn detect(&self, data: &[u8]) -> FileTypeInfo {
        for sig in &self.magic_bytes {
            if data.len() >= sig.offset + sig.bytes.len() {
                let slice = &data[sig.offset..sig.offset + sig.bytes.len()];
                if slice == sig.bytes.as_slice() {
                    return FileTypeInfo {
                        file_type: sig.file_type,
                        mime_type: sig.mime_type.clone(),
                        is_executable: matches!(
                            sig.file_type,
                            FileType::PeExecutable | FileType::ElfExecutable | FileType::MachO | FileType::Script
                        ),
                        is_archive: matches!(
                            sig.file_type,
                            FileType::Zip | FileType::Gzip | FileType::Tar | FileType::Rar | FileType::SevenZip
                        ),
                    };
                }
            }
        }

        FileTypeInfo {
            file_type: FileType::Unknown,
            mime_type: "application/octet-stream".to_string(),
            is_executable: false,
            is_archive: false,
        }
    }

    pub fn detect_file(&self, path: &std::path::Path) -> Result<FileTypeInfo, Error> {
        let mut file = std::fs::File::open(path)?;
        let mut buffer = vec![0u8; 256];
        std::io::Read::read(&mut file, &mut buffer)?;
        Ok(self.detect(&buffer))
    }
}

#[derive(Debug, Clone)]
pub struct FileTypeInfo {
    pub file_type: FileType,
    pub mime_type: String,
    pub is_executable: bool,
    pub is_archive: bool,
}
```

---

## Real-time File Monitoring

```rust
use notify::{Watcher, RecursiveMode, Config};
use std::path::PathBuf;
use tokio::sync::mpsc;

pub struct FileMonitor {
    paths: Vec<PathBuf>,
    scanner: ClamAvClient,
    quarantine: QuarantineManager,
}

#[derive(Debug)]
pub enum FileEvent {
    Created(PathBuf),
    Modified(PathBuf),
    Deleted(PathBuf),
}

impl FileMonitor {
    pub fn new(scanner: ClamAvClient, quarantine: QuarantineManager) -> Self {
        Self {
            paths: Vec::new(),
            scanner,
            quarantine,
        }
    }

    pub fn add_watch_path(&mut self, path: PathBuf) {
        self.paths.push(path);
    }

    pub async fn run(self) -> Result<(), Error> {
        let (tx, mut rx) = mpsc::channel(100);

        let mut watcher = notify::recommended_watcher(move |res: Result<notify::Event, _>| {
            if let Ok(event) = res {
                for path in event.paths {
                    let file_event = match event.kind {
                        notify::EventKind::Create(_) => Some(FileEvent::Created(path)),
                        notify::EventKind::Modify(_) => Some(FileEvent::Modified(path)),
                        notify::EventKind::Remove(_) => Some(FileEvent::Deleted(path)),
                        _ => None,
                    };

                    if let Some(fe) = file_event {
                        let _ = tx.blocking_send(fe);
                    }
                }
            }
        })?;

        for path in &self.paths {
            watcher.watch(path, RecursiveMode::Recursive)?;
        }

        tracing::info!("File monitor started, watching {} paths", self.paths.len());

        while let Some(event) = rx.recv().await {
            match event {
                FileEvent::Created(path) | FileEvent::Modified(path) => {
                    // Scan new/modified files
                    if path.is_file() {
                        self.scan_file(&path).await;
                    }
                }
                FileEvent::Deleted(_) => {
                    // No action needed for deleted files
                }
            }
        }

        Ok(())
    }

    async fn scan_file(&self, path: &PathBuf) {
        tracing::debug!("Scanning file: {}", path.display());

        match self.scanner.scan_file(path) {
            Ok(ScanResult::Clean) => {
                tracing::debug!("File clean: {}", path.display());
            }
            Ok(ScanResult::Infected { virus_name }) => {
                tracing::warn!(
                    "Infected file detected: {} - {}",
                    path.display(),
                    virus_name
                );

                // Quarantine the file
                if let Err(e) = self.quarantine.quarantine(path, &virus_name).await {
                    tracing::error!("Failed to quarantine file: {}", e);
                }
            }
            Ok(ScanResult::Error { message }) => {
                tracing::error!("Scan error for {}: {}", path.display(), message);
            }
            Err(e) => {
                tracing::error!("Failed to scan {}: {}", path.display(), e);
            }
        }
    }
}
```

---

## Quarantine System

```rust
use std::path::{Path, PathBuf};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub struct QuarantineManager {
    quarantine_dir: PathBuf,
    metadata_file: PathBuf,
    encryption_key: Option<[u8; 32]>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QuarantinedFile {
    pub id: String,
    pub original_path: PathBuf,
    pub quarantine_path: PathBuf,
    pub threat_name: String,
    pub quarantine_time: DateTime<Utc>,
    pub file_hash: String,
    pub file_size: u64,
    pub encrypted: bool,
}

impl QuarantineManager {
    pub fn new(quarantine_dir: PathBuf) -> Result<Self, Error> {
        std::fs::create_dir_all(&quarantine_dir)?;

        // Set restrictive permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&quarantine_dir, std::fs::Permissions::from_mode(0o700))?;
        }

        let metadata_file = quarantine_dir.join("quarantine.json");

        Ok(Self {
            quarantine_dir,
            metadata_file,
            encryption_key: None,
        })
    }

    pub fn with_encryption(mut self, key: [u8; 32]) -> Self {
        self.encryption_key = Some(key);
        self
    }

    pub async fn quarantine(&self, path: &Path, threat_name: &str) -> Result<QuarantinedFile, Error> {
        // Generate unique ID
        let id = uuid::Uuid::new_v4().to_string();

        // Read file content
        let content = tokio::fs::read(path).await?;

        // Calculate hash
        let hash = hex::encode(ring::digest::digest(&ring::digest::SHA256, &content));

        // Determine quarantine path
        let quarantine_path = self.quarantine_dir.join(&id);

        // Encrypt if key is available
        let (stored_content, encrypted) = if let Some(key) = &self.encryption_key {
            let encrypted = self.encrypt_file(&content, key)?;
            (encrypted, true)
        } else {
            (content.clone(), false)
        };

        // Write to quarantine
        tokio::fs::write(&quarantine_path, &stored_content).await?;

        // Set restrictive permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(&quarantine_path, std::fs::Permissions::from_mode(0o600)).await?;
        }

        // Remove original file
        tokio::fs::remove_file(path).await?;

        // Create metadata entry
        let entry = QuarantinedFile {
            id,
            original_path: path.to_path_buf(),
            quarantine_path,
            threat_name: threat_name.to_string(),
            quarantine_time: Utc::now(),
            file_hash: hash,
            file_size: content.len() as u64,
            encrypted,
        };

        // Save metadata
        self.save_entry(&entry).await?;

        tracing::info!(
            "Quarantined file: {} -> {} (threat: {})",
            path.display(),
            entry.quarantine_path.display(),
            threat_name
        );

        Ok(entry)
    }

    pub async fn restore(&self, id: &str, restore_path: Option<&Path>) -> Result<PathBuf, Error> {
        let entries = self.load_entries().await?;
        let entry = entries.iter()
            .find(|e| e.id == id)
            .ok_or(Error::NotFound(id.to_string()))?;

        // Read quarantined content
        let content = tokio::fs::read(&entry.quarantine_path).await?;

        // Decrypt if necessary
        let decrypted = if entry.encrypted {
            let key = self.encryption_key.as_ref()
                .ok_or(Error::NoEncryptionKey)?;
            self.decrypt_file(&content, key)?
        } else {
            content
        };

        // Determine restore path
        let restore_path = restore_path
            .map(PathBuf::from)
            .unwrap_or_else(|| entry.original_path.clone());

        // Write restored file
        tokio::fs::write(&restore_path, &decrypted).await?;

        tracing::info!("Restored file: {} -> {}", id, restore_path.display());

        Ok(restore_path)
    }

    pub async fn delete(&self, id: &str) -> Result<(), Error> {
        let mut entries = self.load_entries().await?;

        let idx = entries.iter()
            .position(|e| e.id == id)
            .ok_or(Error::NotFound(id.to_string()))?;

        let entry = entries.remove(idx);

        // Delete quarantined file
        tokio::fs::remove_file(&entry.quarantine_path).await?;

        // Update metadata
        self.save_entries(&entries).await?;

        tracing::info!("Deleted quarantined file: {}", id);

        Ok(())
    }

    pub async fn list(&self) -> Result<Vec<QuarantinedFile>, Error> {
        self.load_entries().await
    }

    async fn load_entries(&self) -> Result<Vec<QuarantinedFile>, Error> {
        if !self.metadata_file.exists() {
            return Ok(Vec::new());
        }

        let content = tokio::fs::read_to_string(&self.metadata_file).await?;
        serde_json::from_str(&content).map_err(Error::MetadataParse)
    }

    async fn save_entries(&self, entries: &[QuarantinedFile]) -> Result<(), Error> {
        let content = serde_json::to_string_pretty(entries)?;
        tokio::fs::write(&self.metadata_file, content).await?;
        Ok(())
    }

    async fn save_entry(&self, entry: &QuarantinedFile) -> Result<(), Error> {
        let mut entries = self.load_entries().await?;
        entries.push(entry.clone());
        self.save_entries(&entries).await
    }

    fn encrypt_file(&self, data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, Error> {
        use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, aead::{Aead, KeyInit}};

        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));

        let mut nonce_bytes = [0u8; 12];
        getrandom::getrandom(&mut nonce_bytes).map_err(|_| Error::RandomGeneration)?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher.encrypt(nonce, data)
            .map_err(|_| Error::Encryption)?;

        // Prepend nonce to ciphertext
        let mut result = nonce_bytes.to_vec();
        result.extend(ciphertext);
        Ok(result)
    }

    fn decrypt_file(&self, data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, Error> {
        use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, aead::{Aead, KeyInit}};

        if data.len() < 12 {
            return Err(Error::InvalidCiphertext);
        }

        let (nonce_bytes, ciphertext) = data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));

        cipher.decrypt(nonce, ciphertext)
            .map_err(|_| Error::Decryption)
    }
}
```

---

## File Scanner Service

```rust
pub struct FileScannerService {
    clamav: ClamAvClient,
    type_detector: FileTypeDetector,
    quarantine: QuarantineManager,
    config: ScanConfig,
}

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub scan_archives: bool,
    pub max_file_size: u64,
    pub excluded_extensions: Vec<String>,
    pub excluded_paths: Vec<PathBuf>,
}

impl FileScannerService {
    pub async fn scan_directory(&self, path: &Path) -> Result<ScanReport, Error> {
        let mut report = ScanReport::new(path.to_path_buf());

        for entry in walkdir::WalkDir::new(path)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();

            if !path.is_file() {
                continue;
            }

            // Check exclusions
            if self.should_skip(path) {
                report.skipped += 1;
                continue;
            }

            // Scan file
            report.scanned += 1;
            match self.scan_file(path).await {
                Ok(ScanResult::Clean) => {
                    report.clean += 1;
                }
                Ok(ScanResult::Infected { virus_name }) => {
                    report.infected.push(InfectedFile {
                        path: path.to_path_buf(),
                        threat: virus_name.clone(),
                    });

                    // Quarantine
                    if let Err(e) = self.quarantine.quarantine(path, &virus_name).await {
                        tracing::error!("Failed to quarantine {}: {}", path.display(), e);
                    }
                }
                Ok(ScanResult::Error { message }) => {
                    report.errors.push((path.to_path_buf(), message));
                }
                Err(e) => {
                    report.errors.push((path.to_path_buf(), e.to_string()));
                }
            }
        }

        Ok(report)
    }

    async fn scan_file(&self, path: &Path) -> Result<ScanResult, Error> {
        self.clamav.scan_file(path)
    }

    fn should_skip(&self, path: &Path) -> bool {
        // Check file size
        if let Ok(metadata) = path.metadata() {
            if metadata.len() > self.config.max_file_size {
                return true;
            }
        }

        // Check extension
        if let Some(ext) = path.extension() {
            let ext = ext.to_string_lossy().to_lowercase();
            if self.config.excluded_extensions.contains(&ext) {
                return true;
            }
        }

        // Check path
        for excluded in &self.config.excluded_paths {
            if path.starts_with(excluded) {
                return true;
            }
        }

        false
    }
}

#[derive(Debug)]
pub struct ScanReport {
    pub path: PathBuf,
    pub scanned: usize,
    pub clean: usize,
    pub skipped: usize,
    pub infected: Vec<InfectedFile>,
    pub errors: Vec<(PathBuf, String)>,
    pub duration: std::time::Duration,
}

#[derive(Debug)]
pub struct InfectedFile {
    pub path: PathBuf,
    pub threat: String,
}
```

---

## Security Checklist

- [ ] ClamAV database regularly updated
- [ ] Quarantine directory secured
- [ ] File permissions restrictive
- [ ] Encryption key stored securely
- [ ] Scan logs retained appropriately
- [ ] Real-time monitoring enabled

## Recommended Crates

- **notify**: File system events
- **walkdir**: Directory traversal
- **chacha20poly1305**: Encryption
- **ring**: Hashing

## Integration Points

This skill works well with:

- `/threat-detection` - Additional scanning
- `/vault-setup` - Encryption key storage
