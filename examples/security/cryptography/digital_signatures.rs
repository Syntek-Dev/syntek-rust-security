//! Digital Signatures Example
//!
//! Demonstrates Ed25519 and ECDSA digital signatures for authentication.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SignatureError {
    #[error("Signing failed")]
    SigningFailed,
    #[error("Verification failed")]
    VerificationFailed,
    #[error("Invalid key")]
    InvalidKey,
}

/// Ed25519 digital signatures (recommended)
pub mod ed25519 {
    use super::*;

    /// Generate a new Ed25519 key pair
    pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key)
    }

    /// Sign a message
    pub fn sign(signing_key: &SigningKey, message: &[u8]) -> Signature {
        signing_key.sign(message)
    }

    /// Verify a signature
    pub fn verify(
        verifying_key: &VerifyingKey,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), SignatureError> {
        verifying_key
            .verify(message, signature)
            .map_err(|_| SignatureError::VerificationFailed)
    }

    /// Export signing key to bytes
    pub fn export_signing_key(key: &SigningKey) -> [u8; 32] {
        key.to_bytes()
    }

    /// Import signing key from bytes
    pub fn import_signing_key(bytes: &[u8; 32]) -> SigningKey {
        SigningKey::from_bytes(bytes)
    }

    /// Export verifying key to bytes
    pub fn export_verifying_key(key: &VerifyingKey) -> [u8; 32] {
        key.to_bytes()
    }

    /// Import verifying key from bytes
    pub fn import_verifying_key(bytes: &[u8; 32]) -> Result<VerifyingKey, SignatureError> {
        VerifyingKey::from_bytes(bytes).map_err(|_| SignatureError::InvalidKey)
    }
}

/// Message signing with context (domain separation)
pub struct ContextualSigner {
    signing_key: SigningKey,
    context: String,
}

impl ContextualSigner {
    pub fn new(signing_key: SigningKey, context: &str) -> Self {
        Self {
            signing_key,
            context: context.to_string(),
        }
    }

    /// Sign with context prefix for domain separation
    pub fn sign(&self, message: &[u8]) -> Signature {
        let mut data = Vec::with_capacity(self.context.len() + 1 + message.len());
        data.extend_from_slice(self.context.as_bytes());
        data.push(0x00); // Separator
        data.extend_from_slice(message);
        self.signing_key.sign(&data)
    }
}

pub struct ContextualVerifier {
    verifying_key: VerifyingKey,
    context: String,
}

impl ContextualVerifier {
    pub fn new(verifying_key: VerifyingKey, context: &str) -> Self {
        Self {
            verifying_key,
            context: context.to_string(),
        }
    }

    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), SignatureError> {
        let mut data = Vec::with_capacity(self.context.len() + 1 + message.len());
        data.extend_from_slice(self.context.as_bytes());
        data.push(0x00);
        data.extend_from_slice(message);
        self.verifying_key
            .verify(&data, signature)
            .map_err(|_| SignatureError::VerificationFailed)
    }
}

/// Batch signature verification
pub fn verify_batch(
    messages: &[&[u8]],
    signatures: &[Signature],
    verifying_keys: &[VerifyingKey],
) -> Result<(), SignatureError> {
    if messages.len() != signatures.len() || messages.len() != verifying_keys.len() {
        return Err(SignatureError::VerificationFailed);
    }

    for ((message, signature), key) in messages.iter().zip(signatures).zip(verifying_keys) {
        key.verify(message, signature)
            .map_err(|_| SignatureError::VerificationFailed)?;
    }

    Ok(())
}

/// Signed message container
#[derive(Debug, Clone)]
pub struct SignedMessage {
    pub message: Vec<u8>,
    pub signature: [u8; 64],
    pub public_key: [u8; 32],
}

impl SignedMessage {
    pub fn new(signing_key: &SigningKey, message: Vec<u8>) -> Self {
        let signature = signing_key.sign(&message);
        Self {
            message,
            signature: signature.to_bytes(),
            public_key: signing_key.verifying_key().to_bytes(),
        }
    }

    pub fn verify(&self) -> Result<(), SignatureError> {
        let verifying_key =
            VerifyingKey::from_bytes(&self.public_key).map_err(|_| SignatureError::InvalidKey)?;
        let signature = Signature::from_bytes(&self.signature);

        verifying_key
            .verify(&self.message, &signature)
            .map_err(|_| SignatureError::VerificationFailed)
    }

    /// Serialize to bytes: pubkey || signature || message
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32 + 64 + self.message.len());
        bytes.extend_from_slice(&self.public_key);
        bytes.extend_from_slice(&self.signature);
        bytes.extend_from_slice(&self.message);
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        if bytes.len() < 96 {
            return Err(SignatureError::InvalidKey);
        }

        let mut public_key = [0u8; 32];
        let mut signature = [0u8; 64];
        public_key.copy_from_slice(&bytes[..32]);
        signature.copy_from_slice(&bytes[32..96]);
        let message = bytes[96..].to_vec();

        Ok(Self {
            message,
            signature,
            public_key,
        })
    }
}

fn main() {
    println!("=== Digital Signatures with Ed25519 ===\n");

    // Generate key pair
    let (signing_key, verifying_key) = ed25519::generate_keypair();
    println!("Generated Ed25519 key pair");
    println!(
        "Public key: {}...",
        hex::encode(&verifying_key.to_bytes()[..8])
    );

    // Sign a message
    let message = b"This is an important document.";
    let signature = ed25519::sign(&signing_key, message);
    println!("\nMessage: {:?}", String::from_utf8_lossy(message));
    println!("Signature: {}...", hex::encode(&signature.to_bytes()[..16]));

    // Verify signature
    match ed25519::verify(&verifying_key, message, &signature) {
        Ok(()) => println!("Signature verified successfully!"),
        Err(e) => println!("Verification failed: {}", e),
    }

    // Tampered message fails verification
    let tampered = b"This is a modified document.";
    match ed25519::verify(&verifying_key, tampered, &signature) {
        Ok(()) => println!("ERROR: Tampered message accepted!"),
        Err(_) => println!("Tampered message rejected (expected)"),
    }

    // Domain separation with context
    println!("\n--- Contextual Signing (Domain Separation) ---");

    let (sk, vk) = ed25519::generate_keypair();
    let signer = ContextualSigner::new(sk.clone(), "my-app:v1:login");
    let verifier = ContextualVerifier::new(vk, "my-app:v1:login");

    let token = b"user:12345:timestamp:1234567890";
    let sig = signer.sign(token);

    verifier.verify(token, &sig).expect("Valid signature");
    println!("Contextual signature verified!");

    // Wrong context fails
    let wrong_verifier = ContextualVerifier::new(
        ed25519::import_verifying_key(&ed25519::export_verifying_key(&sk.verifying_key())).unwrap(),
        "my-app:v1:payment",
    );
    assert!(wrong_verifier.verify(token, &sig).is_err());
    println!("Wrong context rejected (expected)");

    // Signed message container
    println!("\n--- Signed Message Container ---");

    let (sk, _vk) = ed25519::generate_keypair();
    let signed = SignedMessage::new(&sk, b"Hello, World!".to_vec());

    // Serialize and deserialize
    let bytes = signed.to_bytes();
    println!("Serialized size: {} bytes", bytes.len());

    let restored = SignedMessage::from_bytes(&bytes).unwrap();
    restored.verify().expect("Restored signature valid");
    println!("Deserialized and verified!");

    // Key export/import
    println!("\n--- Key Export/Import ---");

    let (sk, vk) = ed25519::generate_keypair();

    // Export
    let sk_bytes = ed25519::export_signing_key(&sk);
    let vk_bytes = ed25519::export_verifying_key(&vk);

    // Import
    let sk_restored = ed25519::import_signing_key(&sk_bytes);
    let vk_restored = ed25519::import_verifying_key(&vk_bytes).unwrap();

    // Verify they work
    let msg = b"test";
    let sig = ed25519::sign(&sk_restored, msg);
    ed25519::verify(&vk_restored, msg, &sig).expect("Imported keys work");
    println!("Key export/import successful!");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify() {
        let (sk, vk) = ed25519::generate_keypair();
        let message = b"test message";

        let signature = ed25519::sign(&sk, message);
        assert!(ed25519::verify(&vk, message, &signature).is_ok());
    }

    #[test]
    fn test_tampered_message() {
        let (sk, vk) = ed25519::generate_keypair();
        let message = b"original";
        let tampered = b"modified";

        let signature = ed25519::sign(&sk, message);
        assert!(ed25519::verify(&vk, tampered, &signature).is_err());
    }

    #[test]
    fn test_wrong_key() {
        let (sk, _vk) = ed25519::generate_keypair();
        let (_sk2, vk2) = ed25519::generate_keypair();
        let message = b"test";

        let signature = ed25519::sign(&sk, message);
        assert!(ed25519::verify(&vk2, message, &signature).is_err());
    }

    #[test]
    fn test_key_export_import() {
        let (sk, vk) = ed25519::generate_keypair();

        let sk_bytes = ed25519::export_signing_key(&sk);
        let vk_bytes = ed25519::export_verifying_key(&vk);

        let sk_restored = ed25519::import_signing_key(&sk_bytes);
        let vk_restored = ed25519::import_verifying_key(&vk_bytes).unwrap();

        let message = b"test";
        let sig = ed25519::sign(&sk_restored, message);
        assert!(ed25519::verify(&vk_restored, message, &sig).is_ok());
    }

    #[test]
    fn test_signed_message() {
        let (sk, _) = ed25519::generate_keypair();
        let message = b"important data".to_vec();

        let signed = SignedMessage::new(&sk, message.clone());
        assert!(signed.verify().is_ok());

        let bytes = signed.to_bytes();
        let restored = SignedMessage::from_bytes(&bytes).unwrap();
        assert!(restored.verify().is_ok());
        assert_eq!(restored.message, message);
    }

    #[test]
    fn test_contextual_signing() {
        let (sk, vk) = ed25519::generate_keypair();

        let signer = ContextualSigner::new(sk.clone(), "context-a");
        let verifier_a = ContextualVerifier::new(vk.clone(), "context-a");
        let verifier_b = ContextualVerifier::new(vk, "context-b");

        let message = b"test";
        let signature = signer.sign(message);

        assert!(verifier_a.verify(message, &signature).is_ok());
        assert!(verifier_b.verify(message, &signature).is_err());
    }
}
