//! Deterministic OpenSSH ed25519 key pair generator.
//!
//! SPEC 3.2.2 (REQ-SEED-003, P1-CAN-03):
//! Generates OpenSSH v1 format ed25519 key pair derived from seed.
//! The 32-bit checkint pair is derived from the seed for strict reproducibility.

use ed25519_dalek::SigningKey;

use crate::canary::derive::derive;
use crate::seed::Seed;

fn write_string(buf: &mut Vec<u8>, s: &[u8]) {
    buf.extend_from_slice(&(s.len() as u32).to_be_bytes());
    buf.extend_from_slice(s);
}


/// Generated SSH key pair in OpenSSH format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshKeyPair {
    /// Private key in OpenSSH v1 PEM format.
    pub private_key: Vec<u8>,
    /// Public key in standard single-line format (`ssh-ed25519 <b64> <comment>\n`).
    pub public_key: Vec<u8>,
    /// Raw private key bytes (64 bytes: 32 bytes seed + 32 bytes public) for secret detection.
    pub secret_raw: Vec<u8>,
}

/// Generate a deterministic OpenSSH ed25519 key pair from seed.
pub fn generate_ssh_key(seed: &Seed) -> SshKeyPair {
    let raw_seed = derive(seed, "ssh", "key", 32);
    let mut seed_bytes = [0u8; 32];
    seed_bytes.copy_from_slice(&raw_seed[..32]);

    let signing_key = SigningKey::from_bytes(&seed_bytes);
    let verifying_key = signing_key.verifying_key();
    let public_bytes = verifying_key.to_bytes();

    let checkint_bytes = derive(seed, "ssh", "checkint", 4);
    let mut checkint_arr = [0u8; 4];
    checkint_arr.copy_from_slice(&checkint_bytes[..4]);
    let checkint = u32::from_be_bytes(checkint_arr);

    let comment = "user@ssh.invalid";

    // 1. Build public key wire blob: string "ssh-ed25519", string public_bytes
    let mut pub_blob = Vec::new();
    write_string(&mut pub_blob, b"ssh-ed25519");
    write_string(&mut pub_blob, &public_bytes);

    let pub_b64 = crate::util::to_base64(&pub_blob);
    let public_key = format!("ssh-ed25519 {pub_b64} {comment}\n").into_bytes();

    // 2. Build private key block (unencrypted)
    let mut priv_block = Vec::new();
    priv_block.extend_from_slice(&checkint.to_be_bytes());
    priv_block.extend_from_slice(&checkint.to_be_bytes());
    write_string(&mut priv_block, b"ssh-ed25519");
    write_string(&mut priv_block, &public_bytes);

    // In OpenSSH ed25519, the private key string field is 64 bytes: 32 bytes seed + 32 bytes pub
    let mut full_priv = Vec::with_capacity(64);
    full_priv.extend_from_slice(&seed_bytes);
    full_priv.extend_from_slice(&public_bytes);
    write_string(&mut priv_block, &full_priv);
    write_string(&mut priv_block, comment.as_bytes());

    // Padding: multiple of 8
    let pad_len = 8 - (priv_block.len() % 8);
    for i in 1..=pad_len {
        priv_block.push(i as u8);
    }

    // 3. Assemble full OpenSSH v1 binary container
    let mut container = Vec::new();
    container.extend_from_slice(b"openssh-key-v1\0");
    write_string(&mut container, b"none"); // cipher
    write_string(&mut container, b"none"); // kdf
    write_string(&mut container, b""); // kdf options
    container.extend_from_slice(&1u32.to_be_bytes()); // num_keys
    write_string(&mut container, &pub_blob);
    write_string(&mut container, &priv_block);

    // 4. Wrap with PEM header and footer with 70-character line breaks
    let b64_container = crate::util::to_base64(&container);
    let mut pem = String::from("-----BEGIN OPENSSH PRIVATE KEY-----\n");
    for chunk in b64_container.as_bytes().chunks(70) {
        pem.push_str(std::str::from_utf8(chunk).expect("valid utf-8 b64"));
        pem.push('\n');
    }
    pem.push_str("-----END OPENSSH PRIVATE KEY-----\n");

    SshKeyPair {
        private_key: pem.into_bytes(),
        public_key,
        secret_raw: full_priv,
    }
}
