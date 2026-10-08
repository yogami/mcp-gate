//! HKDF-SHA256 key derivation for deterministic canaries.
//!
//! SPEC 3.2.4:
//! Per-canary key material: HKDF-SHA256(seed, info = "mcp-gate/v1/" || kind || "/" || field),
//! expanded through ChaCha20 for longer values.

use hkdf::Hkdf;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use sha2::Sha256;

use crate::seed::Seed;

/// Derive deterministic bytes for a canary field using HKDF-SHA256 and ChaCha20.
pub fn derive(seed: &Seed, kind: &str, field: &str, len: usize) -> Vec<u8> {
    if len == 0 {
        return Vec::new();
    }

    let info = format!("mcp-gate/v1/{kind}/{field}");
    let hk = Hkdf::<Sha256>::new(None, seed.as_bytes());

    let mut okm = [0u8; 32];
    hk.expand(info.as_bytes(), &mut okm)
        .expect("32 bytes is within HKDF-SHA256 limit");

    if len <= 32 {
        return okm[..len].to_vec();
    }

    let mut rng = ChaCha20Rng::from_seed(okm);
    let mut out = vec![0u8; len];
    rng.fill_bytes(&mut out);
    out
}
