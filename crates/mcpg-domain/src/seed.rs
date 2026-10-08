//! Seed type and entropy abstraction for deterministic runs.
//!
//! SPEC 3.2.4 (REQ-SEED-001, REQ-SEED-003):
//! Every run uses a 32-byte seed. Without `--seed`, it is drawn from OS entropy.
//! With `--seed <hex>`, the run replays deterministically.

use std::fmt;
use std::io;
use std::str::FromStr;

/// Source of random bytes for seed generation.
pub trait EntropySource {
    /// Fill the destination buffer with entropy.
    fn fill_bytes(&self, dest: &mut [u8]) -> io::Result<()>;
}

/// Errors that can occur when parsing a hex seed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeedError {
    /// Seed string has invalid length.
    InvalidLength(usize),
    /// Seed string contains a non-hex character.
    InvalidHex(char),
}

impl fmt::Display for SeedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength(len) => {
                write!(
                    f,
                    "Invalid seed length: expected 64 hex characters, got {len}"
                )
            }
            Self::InvalidHex(ch) => {
                write!(f, "Invalid hex character in seed: '{ch}'")
            }
        }
    }
}

impl std::error::Error for SeedError {}

/// A 32-byte seed for deterministic canary generation and replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Seed([u8; 32]);

impl Seed {
    /// Create a seed directly from raw bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Return a reference to the raw 32 bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Consume the seed and return its raw 32 bytes.
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Generate a fresh seed from an entropy source.
    pub fn random(entropy: &dyn EntropySource) -> io::Result<Self> {
        let mut bytes = [0u8; 32];
        entropy.fill_bytes(&mut bytes)?;
        Ok(Self(bytes))
    }
}

fn decode_hex_nibble(byte: u8) -> Result<u8, SeedError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(SeedError::InvalidHex(byte as char)),
    }
}

impl FromStr for Seed {
    type Err = SeedError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 64 {
            return Err(SeedError::InvalidLength(s.len()));
        }
        let mut bytes = [0u8; 32];
        let raw = s.as_bytes();
        for (i, byte) in bytes.iter_mut().enumerate() {
            let hi = decode_hex_nibble(raw[i * 2])?;
            let lo = decode_hex_nibble(raw[i * 2 + 1])?;
            *byte = (hi << 4) | lo;
        }
        Ok(Self(bytes))
    }
}

impl fmt::Display for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}
