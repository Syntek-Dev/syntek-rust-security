//! AFL++ Fuzzing Harness Example
//!
//! Demonstrates setting up AFL++ (American Fuzzy Lop) for Rust security testing.
//! AFL++ uses instrumentation-guided fuzzing for discovering security vulnerabilities.

use std::io::{self, Read};

/// AFL harness configuration
#[derive(Debug, Clone)]
pub struct AflConfig {
    pub input_dir: String,
    pub output_dir: String,
    pub dictionary: Option<String>,
    pub timeout_ms: u64,
    pub memory_limit_mb: usize,
    pub parallel_instances: usize,
}

impl Default for AflConfig {
    fn default() -> Self {
        Self {
            input_dir: "afl_input".to_string(),
            output_dir: "afl_output".to_string(),
            dictionary: None,
            timeout_ms: 1000,
            memory_limit_mb: 256,
            parallel_instances: 1,
        }
    }
}

impl AflConfig {
    pub fn new(input: &str, output: &str) -> Self {
        Self {
            input_dir: input.to_string(),
            output_dir: output.to_string(),
            ..Default::default()
        }
    }

    pub fn with_dictionary(mut self, dict_path: &str) -> Self {
        self.dictionary = Some(dict_path.to_string());
        self
    }

    pub fn with_timeout(mut self, ms: u64) -> Self {
        self.timeout_ms = ms;
        self
    }

    pub fn with_memory_limit(mut self, mb: usize) -> Self {
        self.memory_limit_mb = mb;
        self
    }

    pub fn generate_command(&self, target: &str) -> String {
        let mut cmd = format!(
            "AFL_SKIP_CPUFREQ=1 afl-fuzz -i {} -o {} -t {} -m {}",
            self.input_dir, self.output_dir, self.timeout_ms, self.memory_limit_mb
        );

        if let Some(ref dict) = self.dictionary {
            cmd.push_str(&format!(" -x {}", dict));
        }

        cmd.push_str(&format!(" -- ./{}", target));
        cmd
    }
}

/// Protocol parser for AFL fuzzing demonstration
pub mod protocol_parser {
    use std::convert::TryInto;

    /// Simple binary protocol header
    #[derive(Debug, Clone, PartialEq)]
    pub struct ProtocolHeader {
        pub magic: u32,
        pub version: u16,
        pub flags: u16,
        pub payload_len: u32,
        pub checksum: u32,
    }

    const MAGIC: u32 = 0x53454355; // "SECU" in hex

    impl ProtocolHeader {
        pub fn parse(data: &[u8]) -> Result<Self, ProtocolError> {
            if data.len() < 16 {
                return Err(ProtocolError::HeaderTooShort);
            }

            let magic = u32::from_le_bytes(data[0..4].try_into().unwrap());
            if magic != MAGIC {
                return Err(ProtocolError::InvalidMagic(magic));
            }

            let version = u16::from_le_bytes(data[4..6].try_into().unwrap());
            if version > 10 {
                return Err(ProtocolError::UnsupportedVersion(version));
            }

            let flags = u16::from_le_bytes(data[6..8].try_into().unwrap());
            let payload_len = u32::from_le_bytes(data[8..12].try_into().unwrap());
            let checksum = u32::from_le_bytes(data[12..16].try_into().unwrap());

            // Security check: prevent excessive allocation
            if payload_len > 10 * 1024 * 1024 {
                return Err(ProtocolError::PayloadTooLarge(payload_len));
            }

            Ok(Self {
                magic,
                version,
                flags,
                payload_len,
                checksum,
            })
        }

        pub fn validate_checksum(&self, payload: &[u8]) -> bool {
            compute_checksum(payload) == self.checksum
        }
    }

    /// Compute simple checksum
    fn compute_checksum(data: &[u8]) -> u32 {
        data.iter().fold(0u32, |acc, &b| acc.wrapping_add(b as u32))
    }

    /// Parse complete message
    pub fn parse_message(data: &[u8]) -> Result<(ProtocolHeader, Vec<u8>), ProtocolError> {
        let header = ProtocolHeader::parse(data)?;

        let expected_total = 16 + header.payload_len as usize;
        if data.len() < expected_total {
            return Err(ProtocolError::IncompletePayload);
        }

        let payload = data[16..expected_total].to_vec();

        if !header.validate_checksum(&payload) {
            return Err(ProtocolError::ChecksumMismatch);
        }

        Ok((header, payload))
    }

    #[derive(Debug, PartialEq)]
    pub enum ProtocolError {
        HeaderTooShort,
        InvalidMagic(u32),
        UnsupportedVersion(u16),
        PayloadTooLarge(u32),
        IncompletePayload,
        ChecksumMismatch,
    }
}

/// Image format parser for AFL fuzzing
pub mod image_parser {
    use std::convert::TryInto;

    #[derive(Debug, Clone)]
    pub struct ImageHeader {
        pub width: u32,
        pub height: u32,
        pub bit_depth: u8,
        pub color_type: ColorType,
    }

    #[derive(Debug, Clone, Copy, PartialEq)]
    pub enum ColorType {
        Grayscale,
        Rgb,
        Rgba,
        Indexed,
    }

    impl ImageHeader {
        pub fn parse_png_header(data: &[u8]) -> Result<Self, ImageError> {
            // PNG signature: 89 50 4E 47 0D 0A 1A 0A
            const PNG_SIG: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

            if data.len() < 24 {
                return Err(ImageError::TooShort);
            }

            if &data[0..8] != &PNG_SIG {
                return Err(ImageError::InvalidSignature);
            }

            // IHDR chunk starts at offset 8
            let chunk_len = u32::from_be_bytes(data[8..12].try_into().unwrap());
            if chunk_len != 13 {
                return Err(ImageError::InvalidIhdr);
            }

            // Check "IHDR" chunk type
            if &data[12..16] != b"IHDR" {
                return Err(ImageError::MissingIhdr);
            }

            let width = u32::from_be_bytes(data[16..20].try_into().unwrap());
            let height = u32::from_be_bytes(data[20..24].try_into().unwrap());

            // Security: prevent decompression bombs
            if width > 65535 || height > 65535 {
                return Err(ImageError::DimensionsTooLarge);
            }

            let total_pixels = (width as u64) * (height as u64);
            if total_pixels > 100_000_000 {
                return Err(ImageError::TooManyPixels);
            }

            let bit_depth = if data.len() > 24 { data[24] } else { 8 };
            let color_type_byte = if data.len() > 25 { data[25] } else { 2 };

            let color_type = match color_type_byte {
                0 => ColorType::Grayscale,
                2 => ColorType::Rgb,
                3 => ColorType::Indexed,
                6 => ColorType::Rgba,
                _ => return Err(ImageError::InvalidColorType),
            };

            Ok(Self {
                width,
                height,
                bit_depth,
                color_type,
            })
        }

        pub fn estimated_size(&self) -> usize {
            let bytes_per_pixel = match self.color_type {
                ColorType::Grayscale => 1,
                ColorType::Rgb => 3,
                ColorType::Rgba => 4,
                ColorType::Indexed => 1,
            };
            (self.width as usize) * (self.height as usize) * bytes_per_pixel
        }
    }

    #[derive(Debug, PartialEq)]
    pub enum ImageError {
        TooShort,
        InvalidSignature,
        InvalidIhdr,
        MissingIhdr,
        DimensionsTooLarge,
        TooManyPixels,
        InvalidColorType,
    }
}

/// AFL harness entry point - reads from stdin
pub fn afl_harness_main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;

    // Test protocol parser
    let _ = protocol_parser::parse_message(&input);

    // Test image parser
    let _ = image_parser::ImageHeader::parse_png_header(&input);

    Ok(())
}

/// Generate seed corpus for protocol fuzzing
pub fn generate_protocol_seeds() -> Vec<Vec<u8>> {
    let mut seeds = Vec::new();

    // Valid minimal message
    let mut valid = Vec::new();
    valid.extend_from_slice(&0x53454355u32.to_le_bytes()); // magic
    valid.extend_from_slice(&1u16.to_le_bytes()); // version
    valid.extend_from_slice(&0u16.to_le_bytes()); // flags
    valid.extend_from_slice(&4u32.to_le_bytes()); // payload_len
    valid.extend_from_slice(&(b't' as u32 + b'e' as u32 + b's' as u32 + b't' as u32).to_le_bytes()); // checksum
    valid.extend_from_slice(b"test"); // payload
    seeds.push(valid);

    // Empty payload
    let mut empty = Vec::new();
    empty.extend_from_slice(&0x53454355u32.to_le_bytes());
    empty.extend_from_slice(&1u16.to_le_bytes());
    empty.extend_from_slice(&0u16.to_le_bytes());
    empty.extend_from_slice(&0u32.to_le_bytes());
    empty.extend_from_slice(&0u32.to_le_bytes());
    seeds.push(empty);

    // Invalid magic
    let mut bad_magic = Vec::new();
    bad_magic.extend_from_slice(&0xDEADBEEFu32.to_le_bytes());
    bad_magic.extend_from_slice(&[0u8; 12]);
    seeds.push(bad_magic);

    seeds
}

fn main() {
    println!("AFL++ Fuzzing Harness Example");
    println!("==============================\n");

    // Configure AFL
    let config = AflConfig::new("corpus/protocol", "findings/protocol")
        .with_dictionary("dictionaries/protocol.dict")
        .with_timeout(500)
        .with_memory_limit(512);

    println!("AFL Command:");
    println!(
        "  {}\n",
        config.generate_command("target/release/protocol_fuzz")
    );

    // Generate seed corpus
    println!("Generating seed corpus...");
    let seeds = generate_protocol_seeds();
    for (i, seed) in seeds.iter().enumerate() {
        println!("  Seed {}: {} bytes", i, seed.len());
    }

    // Test protocol parser with seeds
    println!("\nTesting protocol parser with seeds:");
    for (i, seed) in seeds.iter().enumerate() {
        match protocol_parser::parse_message(seed) {
            Ok((header, payload)) => {
                println!(
                    "  Seed {}: Success - version={}, payload={} bytes",
                    i,
                    header.version,
                    payload.len()
                );
            }
            Err(e) => {
                println!("  Seed {}: Error - {:?}", i, e);
            }
        }
    }

    // Test image parser
    println!("\nTesting image parser:");
    let fake_png = [
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
        0x00, 0x00, 0x00, 0x0D, // IHDR length
        0x49, 0x48, 0x44, 0x52, // "IHDR"
        0x00, 0x00, 0x00, 0x10, // width = 16
        0x00, 0x00, 0x00, 0x10, // height = 16
        0x08, 0x02, // bit depth = 8, color type = RGB
    ];

    match image_parser::ImageHeader::parse_png_header(&fake_png) {
        Ok(header) => {
            println!(
                "  Valid PNG: {}x{}, estimated size: {} bytes",
                header.width,
                header.height,
                header.estimated_size()
            );
        }
        Err(e) => {
            println!("  Parse error: {:?}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_afl_config() {
        let config = AflConfig::new("input", "output")
            .with_timeout(2000)
            .with_memory_limit(1024);

        assert_eq!(config.input_dir, "input");
        assert_eq!(config.output_dir, "output");
        assert_eq!(config.timeout_ms, 2000);
        assert_eq!(config.memory_limit_mb, 1024);
    }

    #[test]
    fn test_protocol_header_parse() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x53454355u32.to_le_bytes());
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());

        let header = protocol_parser::ProtocolHeader::parse(&data).unwrap();
        assert_eq!(header.version, 1);
        assert_eq!(header.payload_len, 0);
    }

    #[test]
    fn test_protocol_invalid_magic() {
        let data = [0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let result = protocol_parser::ProtocolHeader::parse(&data);
        assert!(matches!(
            result,
            Err(protocol_parser::ProtocolError::InvalidMagic(_))
        ));
    }

    #[test]
    fn test_protocol_payload_too_large() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x53454355u32.to_le_bytes());
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes()); // 4GB payload
        data.extend_from_slice(&0u32.to_le_bytes());

        let result = protocol_parser::ProtocolHeader::parse(&data);
        assert!(matches!(
            result,
            Err(protocol_parser::ProtocolError::PayloadTooLarge(_))
        ));
    }

    #[test]
    fn test_image_png_header() {
        let fake_png = [
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48,
            0x44, 0x52, 0x00, 0x00, 0x00, 0x20, // width = 32
            0x00, 0x00, 0x00, 0x20, // height = 32
            0x08, 0x06, // RGBA
        ];

        let header = image_parser::ImageHeader::parse_png_header(&fake_png).unwrap();
        assert_eq!(header.width, 32);
        assert_eq!(header.height, 32);
        assert_eq!(header.color_type, image_parser::ColorType::Rgba);
        assert_eq!(header.estimated_size(), 32 * 32 * 4);
    }

    #[test]
    fn test_image_dimensions_limit() {
        let mut fake_png = vec![
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48,
            0x44, 0x52,
        ];
        fake_png.extend_from_slice(&0x00FFFFFFu32.to_be_bytes()); // huge width
        fake_png.extend_from_slice(&0x00000001u32.to_be_bytes());

        let result = image_parser::ImageHeader::parse_png_header(&fake_png);
        assert!(matches!(
            result,
            Err(image_parser::ImageError::DimensionsTooLarge)
        ));
    }

    #[test]
    fn test_seed_generation() {
        let seeds = generate_protocol_seeds();
        assert!(!seeds.is_empty());

        // First seed should be valid
        let result = protocol_parser::parse_message(&seeds[0]);
        assert!(result.is_ok());
    }
}
