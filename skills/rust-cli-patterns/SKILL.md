# Rust CLI Security Patterns Skills

This skill provides security patterns for building command-line interface (CLI)
tools in Rust with secure argument handling, configuration management, and
secret protection.

## Overview

CLI security encompasses:

- **Argument Security**: Safe handling of sensitive arguments
- **Configuration Files**: Secure config file parsing
- **Environment Variables**: Safe secret injection
- **Output Handling**: Preventing information leakage
- **Signal Handling**: Graceful cleanup on termination
- **Privilege Management**: Dropping privileges safely

---

## Secure Argument Handling with Clap

### Basic Secure CLI Structure

```rust
use clap::{Parser, Subcommand};
use secrecy::{Secret, SecretString};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "secure-cli")]
#[command(about = "A security-focused CLI tool")]
pub struct Cli {
    /// Configuration file path
    #[arg(short, long, default_value = "config.toml")]
    pub config: PathBuf,

    /// Verbosity level
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Encrypt a file
    Encrypt {
        /// Input file
        #[arg(short, long)]
        input: PathBuf,

        /// Output file
        #[arg(short, long)]
        output: PathBuf,

        /// Encryption key (prefer env var ENCRYPTION_KEY)
        #[arg(long, env = "ENCRYPTION_KEY", hide_env_values = true)]
        key: Option<SecretString>,
    },

    /// Decrypt a file
    Decrypt {
        #[arg(short, long)]
        input: PathBuf,

        #[arg(short, long)]
        output: PathBuf,

        #[arg(long, env = "ENCRYPTION_KEY", hide_env_values = true)]
        key: Option<SecretString>,
    },
}
```

### Hiding Sensitive Values

```rust
use clap::Parser;

#[derive(Parser)]
pub struct AuthArgs {
    /// API endpoint
    #[arg(long)]
    pub endpoint: String,

    /// API key (NEVER shown in --help or error messages)
    #[arg(
        long,
        env = "API_KEY",
        hide_env_values = true,    // Don't show env value in help
        hide_default_value = true, // Don't show default in help
    )]
    pub api_key: Option<String>,

    /// Password (prompted if not provided)
    #[arg(long, hide = true)]  // Hidden from --help entirely
    pub password: Option<String>,
}

impl AuthArgs {
    pub fn get_api_key(&self) -> Result<SecretString, Error> {
        match &self.api_key {
            Some(key) => Ok(SecretString::new(key.clone())),
            None => self.prompt_for_key(),
        }
    }

    fn prompt_for_key(&self) -> Result<SecretString, Error> {
        let key = rpassword::prompt_password("Enter API key: ")
            .map_err(|_| Error::PromptFailed)?;
        Ok(SecretString::new(key))
    }
}
```

---

## Secure Configuration Management

### Secure Config File Format

```rust
use serde::{Deserialize, Serialize};
use secrecy::{Secret, ExposeSecret};
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub secrets: SecretsConfig,
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub tls_cert: PathBuf,
    pub tls_key: PathBuf,
}

#[derive(Debug, Deserialize)]
pub struct DatabaseConfig {
    pub host: String,
    pub port: u16,
    pub name: String,
    pub user: String,
    // Password should come from env or Vault, not config file
    #[serde(skip)]
    pub password: Option<Secret<String>>,
}

#[derive(Debug, Deserialize)]
pub struct SecretsConfig {
    /// Vault address for secrets
    pub vault_addr: Option<String>,
    /// Vault token path
    pub vault_token_path: Option<PathBuf>,
    /// Environment variable prefix for secrets
    pub env_prefix: Option<String>,
}

impl Config {
    pub fn load(path: &std::path::Path) -> Result<Self, Error> {
        // Check file permissions first
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = std::fs::metadata(path)?;
            let mode = metadata.permissions().mode();

            // Config should not be world-readable
            if mode & 0o044 != 0 {
                return Err(Error::InsecurePermissions(path.to_path_buf()));
            }
        }

        let content = std::fs::read_to_string(path)?;
        let mut config: Config = toml::from_str(&content)?;

        // Load password from environment
        if let Some(prefix) = &config.secrets.env_prefix {
            let env_key = format!("{}_DB_PASSWORD", prefix.to_uppercase());
            if let Ok(password) = std::env::var(&env_key) {
                config.database.password = Some(Secret::new(password));
            }
        }

        Ok(config)
    }
}
```

### Config File Validation

```rust
use std::fs;
use std::path::Path;

pub struct ConfigValidator;

impl ConfigValidator {
    pub fn validate_config_file(path: &Path) -> Result<Vec<Warning>, Error> {
        let mut warnings = Vec::new();

        // Check file exists
        if !path.exists() {
            return Err(Error::ConfigNotFound(path.to_path_buf()));
        }

        // Check permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = fs::metadata(path)?;
            let mode = metadata.permissions().mode();

            if mode & 0o077 != 0 {
                warnings.push(Warning::InsecurePermissions {
                    path: path.to_path_buf(),
                    mode,
                    recommended: 0o600,
                });
            }
        }

        // Parse and check for secrets in config
        let content = fs::read_to_string(path)?;
        let value: toml::Value = toml::from_str(&content)?;

        Self::check_for_secrets(&value, "", &mut warnings);

        Ok(warnings)
    }

    fn check_for_secrets(value: &toml::Value, path: &str, warnings: &mut Vec<Warning>) {
        match value {
            toml::Value::Table(table) => {
                for (key, val) in table {
                    let new_path = if path.is_empty() {
                        key.clone()
                    } else {
                        format!("{}.{}", path, key)
                    };

                    // Check if key name suggests a secret
                    let key_lower = key.to_lowercase();
                    if key_lower.contains("password")
                        || key_lower.contains("secret")
                        || key_lower.contains("key")
                        || key_lower.contains("token")
                    {
                        if let toml::Value::String(s) = val {
                            if !s.starts_with("${") && !s.starts_with("env:") {
                                warnings.push(Warning::PotentialSecret {
                                    path: new_path.clone(),
                                    suggestion: "Use environment variable or Vault reference".to_string(),
                                });
                            }
                        }
                    }

                    Self::check_for_secrets(val, &new_path, warnings);
                }
            }
            toml::Value::Array(arr) => {
                for (i, val) in arr.iter().enumerate() {
                    Self::check_for_secrets(val, &format!("{}[{}]", path, i), warnings);
                }
            }
            _ => {}
        }
    }
}

#[derive(Debug)]
pub enum Warning {
    InsecurePermissions {
        path: std::path::PathBuf,
        mode: u32,
        recommended: u32,
    },
    PotentialSecret {
        path: String,
        suggestion: String,
    },
}
```

---

## Secure Environment Variable Handling

### Environment Variable Manager

```rust
use secrecy::{Secret, SecretString};
use std::collections::HashMap;

pub struct SecureEnv {
    prefix: String,
    loaded: HashMap<String, SecretString>,
}

impl SecureEnv {
    pub fn new(prefix: &str) -> Self {
        Self {
            prefix: prefix.to_uppercase(),
            loaded: HashMap::new(),
        }
    }

    pub fn get(&mut self, name: &str) -> Option<&SecretString> {
        let full_name = format!("{}_{}", self.prefix, name.to_uppercase());

        if !self.loaded.contains_key(&full_name) {
            if let Ok(value) = std::env::var(&full_name) {
                // Clear from environment after reading
                std::env::remove_var(&full_name);
                self.loaded.insert(full_name.clone(), SecretString::new(value));
            }
        }

        self.loaded.get(&full_name)
    }

    pub fn require(&mut self, name: &str) -> Result<&SecretString, Error> {
        self.get(name)
            .ok_or_else(|| Error::MissingEnvVar(format!("{}_{}", self.prefix, name.to_uppercase())))
    }

    /// Load all secrets at startup, then clear from environment
    pub fn preload(&mut self, names: &[&str]) -> Result<(), Error> {
        for name in names {
            self.require(name)?;
        }
        Ok(())
    }
}

impl Drop for SecureEnv {
    fn drop(&mut self) {
        // SecretString handles zeroization
        self.loaded.clear();
    }
}
```

### Environment Sanitization

```rust
/// Remove sensitive environment variables from process
pub fn sanitize_environment(keep_vars: &[&str]) {
    let sensitive_patterns = [
        "PASSWORD",
        "SECRET",
        "KEY",
        "TOKEN",
        "CREDENTIAL",
        "API_KEY",
        "PRIVATE",
    ];

    let vars_to_remove: Vec<String> = std::env::vars()
        .filter_map(|(key, _)| {
            let key_upper = key.to_uppercase();

            // Keep explicitly allowed vars
            if keep_vars.iter().any(|k| k.to_uppercase() == key_upper) {
                return None;
            }

            // Remove sensitive vars
            if sensitive_patterns.iter().any(|p| key_upper.contains(p)) {
                Some(key)
            } else {
                None
            }
        })
        .collect();

    for var in vars_to_remove {
        std::env::remove_var(&var);
    }
}
```

---

## Secure Password Prompting

### Interactive Password Input

```rust
use rpassword::prompt_password;
use secrecy::SecretString;

pub struct PasswordPrompt;

impl PasswordPrompt {
    pub fn prompt(message: &str) -> Result<SecretString, Error> {
        let password = prompt_password(message)
            .map_err(|_| Error::PromptFailed)?;

        if password.is_empty() {
            return Err(Error::EmptyPassword);
        }

        Ok(SecretString::new(password))
    }

    pub fn prompt_with_confirmation(message: &str) -> Result<SecretString, Error> {
        let password1 = prompt_password(message)
            .map_err(|_| Error::PromptFailed)?;

        let password2 = prompt_password("Confirm password: ")
            .map_err(|_| Error::PromptFailed)?;

        if password1 != password2 {
            return Err(Error::PasswordMismatch);
        }

        if password1.is_empty() {
            return Err(Error::EmptyPassword);
        }

        Ok(SecretString::new(password1))
    }

    pub fn prompt_with_validation<F>(
        message: &str,
        validator: F,
    ) -> Result<SecretString, Error>
    where
        F: Fn(&str) -> Result<(), String>,
    {
        loop {
            let password = prompt_password(message)
                .map_err(|_| Error::PromptFailed)?;

            match validator(&password) {
                Ok(()) => return Ok(SecretString::new(password)),
                Err(msg) => {
                    eprintln!("Invalid password: {}", msg);
                    continue;
                }
            }
        }
    }
}

/// Password strength validation
pub fn validate_password_strength(password: &str) -> Result<(), String> {
    if password.len() < 12 {
        return Err("Password must be at least 12 characters".to_string());
    }

    let has_upper = password.chars().any(|c| c.is_uppercase());
    let has_lower = password.chars().any(|c| c.is_lowercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_special = password.chars().any(|c| !c.is_alphanumeric());

    if !has_upper || !has_lower || !has_digit || !has_special {
        return Err("Password must contain uppercase, lowercase, digit, and special character".to_string());
    }

    Ok(())
}
```

---

## Secure Output Handling

### Redacted Output

```rust
use std::fmt;

/// Wrapper that redacts value in Display/Debug
pub struct Redacted<T>(pub T);

impl<T> fmt::Display for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}

impl<T> fmt::Debug for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}

/// Secure output writer that filters sensitive data
pub struct SecureWriter<W: std::io::Write> {
    inner: W,
    patterns: Vec<regex::Regex>,
}

impl<W: std::io::Write> SecureWriter<W> {
    pub fn new(writer: W) -> Self {
        let patterns = vec![
            regex::Regex::new(r"(?i)(password|secret|key|token)\s*[=:]\s*\S+").unwrap(),
            regex::Regex::new(r"(?i)bearer\s+\S+").unwrap(),
            regex::Regex::new(r"(?i)api[_-]?key\s*[=:]\s*\S+").unwrap(),
        ];

        Self {
            inner: writer,
            patterns,
        }
    }

    pub fn with_pattern(mut self, pattern: &str) -> Result<Self, regex::Error> {
        self.patterns.push(regex::Regex::new(pattern)?);
        Ok(self)
    }
}

impl<W: std::io::Write> std::io::Write for SecureWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let text = String::from_utf8_lossy(buf);
        let mut redacted = text.to_string();

        for pattern in &self.patterns {
            redacted = pattern.replace_all(&redacted, "[REDACTED]").to_string();
        }

        self.inner.write_all(redacted.as_bytes())?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}
```

### Secure Logging

```rust
use tracing_subscriber::fmt::format::FmtSpan;

pub fn init_secure_logging(verbose: u8) {
    let level = match verbose {
        0 => tracing::Level::WARN,
        1 => tracing::Level::INFO,
        2 => tracing::Level::DEBUG,
        _ => tracing::Level::TRACE,
    };

    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_target(false)
        .with_span_events(FmtSpan::CLOSE)
        // Don't log to file by default (could contain secrets)
        .with_writer(std::io::stderr)
        .init();
}

/// Macro for logging with automatic secret redaction
#[macro_export]
macro_rules! secure_info {
    ($($arg:tt)*) => {
        tracing::info!(target: "secure", $($arg)*);
    };
}
```

---

## Signal Handling and Cleanup

### Graceful Shutdown with Cleanup

```rust
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use zeroize::Zeroize;

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

pub fn setup_signal_handlers() {
    ctrlc::set_handler(move || {
        if SHUTDOWN.load(Ordering::SeqCst) {
            // Force exit on second signal
            std::process::exit(1);
        }
        SHUTDOWN.store(true, Ordering::SeqCst);
        eprintln!("\nShutting down gracefully...");
    })
    .expect("Failed to set signal handler");
}

pub fn should_shutdown() -> bool {
    SHUTDOWN.load(Ordering::SeqCst)
}

/// RAII guard for cleanup on exit
pub struct CleanupGuard<F: FnOnce()> {
    cleanup: Option<F>,
}

impl<F: FnOnce()> CleanupGuard<F> {
    pub fn new(cleanup: F) -> Self {
        Self {
            cleanup: Some(cleanup),
        }
    }
}

impl<F: FnOnce()> Drop for CleanupGuard<F> {
    fn drop(&mut self) {
        if let Some(cleanup) = self.cleanup.take() {
            cleanup();
        }
    }
}

// Usage
fn main() {
    setup_signal_handlers();

    let mut sensitive_data = vec![0u8; 1024];
    let _guard = CleanupGuard::new(|| {
        sensitive_data.zeroize();
    });

    // Main application logic...
}
```

---

## Privilege Management

### Dropping Privileges

```rust
#[cfg(unix)]
pub fn drop_privileges(user: &str, group: &str) -> Result<(), Error> {
    use nix::unistd::{setuid, setgid, Uid, Gid, User, Group};

    let user = User::from_name(user)?
        .ok_or(Error::UserNotFound(user.to_string()))?;

    let group = Group::from_name(group)?
        .ok_or(Error::GroupNotFound(group.to_string()))?;

    // Set supplementary groups
    nix::unistd::setgroups(&[group.gid])?;

    // Set GID first
    setgid(group.gid)?;

    // Then set UID
    setuid(user.uid)?;

    // Verify we can't get root back
    if nix::unistd::setuid(Uid::from_raw(0)).is_ok() {
        return Err(Error::PrivilegeDropFailed);
    }

    Ok(())
}

/// Execute privileged operation then drop privileges
pub fn with_elevated_privileges<T, F>(operation: F) -> Result<T, Error>
where
    F: FnOnce() -> Result<T, Error>,
{
    // Perform privileged operation
    let result = operation()?;

    // Drop privileges
    drop_privileges("nobody", "nogroup")?;

    Ok(result)
}
```

---

## CLI Security Checklist

### Arguments

- [ ] Sensitive args use `hide_env_values = true`
- [ ] Passwords prompted, not passed as args
- [ ] No secrets in default values
- [ ] Secrets read from env vars

### Configuration

- [ ] Config files have restricted permissions
- [ ] No plaintext secrets in config
- [ ] Secrets loaded from env/Vault
- [ ] Config validation warns about issues

### Output

- [ ] Secrets redacted in logs
- [ ] Error messages don't leak secrets
- [ ] Debug output sanitized
- [ ] Core dumps disabled

### Process

- [ ] Signal handlers for cleanup
- [ ] Secrets zeroized on exit
- [ ] Privileges dropped when possible
- [ ] Environment sanitized

## Recommended Crates

- **clap**: Argument parsing
- **secrecy**: Secret wrapping
- **rpassword**: Secure password input
- **toml/serde**: Configuration
- **tracing**: Logging
- **ctrlc**: Signal handling
- **nix**: Unix APIs

## Best Practices

1. **Never accept secrets as arguments** - Use env vars or prompts
2. **Clear environment after reading** - Prevent child process leakage
3. **Validate config permissions** - Warn about insecure files
4. **Implement graceful shutdown** - Clean up secrets properly
5. **Drop privileges early** - Run with minimum required permissions
6. **Sanitize all output** - Filter secrets from logs and errors

## Integration Points

This skill works well with:

- `/vault-setup` - Secret management
- `/zeroize-audit` - Memory safety
