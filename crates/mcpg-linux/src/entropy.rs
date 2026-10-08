//! OS entropy source using getrandom.

use std::io;

use mcpg_app::ports::EntropySource;

/// Entropy source using the operating system CSPRNG via getrandom.
#[derive(Debug, Clone, Copy, Default)]
pub struct OsEntropy;

impl EntropySource for OsEntropy {
    fn fill_bytes(&self, dest: &mut [u8]) -> io::Result<()> {
        getrandom::fill(dest).map_err(|e| io::Error::other(e.to_string()))
    }
}
