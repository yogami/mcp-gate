//! In-memory fake entropy source for testing.

use std::cell::RefCell;
use std::io;

use mcpg_domain::seed::EntropySource;

/// A fake entropy source that yields predetermined blocks of bytes.
#[derive(Debug, Default)]
pub struct FakeEntropy {
    blocks: RefCell<Vec<[u8; 32]>>,
}

impl FakeEntropy {
    /// Create a fake entropy source with a list of 32-byte blocks.
    pub fn new(blocks: Vec<[u8; 32]>) -> Self {
        Self {
            blocks: RefCell::new(blocks),
        }
    }
}

impl EntropySource for FakeEntropy {
    fn fill_bytes(&self, dest: &mut [u8]) -> io::Result<()> {
        let mut blocks = self.blocks.borrow_mut();
        if blocks.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "no more fake entropy blocks available",
            ));
        }
        let block = blocks.remove(0);
        let copy_len = dest.len().min(block.len());
        dest[..copy_len].copy_from_slice(&block[..copy_len]);
        Ok(())
    }
}
