use mcpg_domain::canary::catalogue::{CanaryKind, CanaryTier};
use mcpg_domain::canary::registry::{CanaryRecord, CanaryRegistry};
use mcpg_domain::canary::render::Secret;
use mcpg_domain::leak::{LeakEncoding, LeakScanner};
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::path::PathBuf;

fn sample_registry() -> (CanaryRegistry, String) {
    let mut reg = CanaryRegistry::new();
    let raw_secret = "AKIAEXAMPLESECRET1234567890EXTRA".to_string();
    reg.add(CanaryRecord {
        id: "aws-test".to_string(),
        kind: CanaryKind::Aws,
        tier: CanaryTier::A,
        path: PathBuf::from("/capsule/home/.aws/credentials"),
        dev: 1,
        ino: 100,
        fp: "awsfp1234567".to_string(),
        secrets: vec![Secret {
            field: "aws_secret_access_key".to_string(),
            value: raw_secret.clone(),
            kind: CanaryKind::Aws,
        }],
    });
    (reg, raw_secret)
}

#[test]
fn p1_leak_01_raw_in_json() {
    let (reg, secret) = sample_registry();
    let scanner = LeakScanner::from_registry(&reg);

    let json_payload = format!(r#"{{"jsonrpc":"2.0","result":{{"token":"{secret}"}}}}"#);
    let matches = scanner.scan_bytes(json_payload.as_bytes(), "stdout");
    assert!(!matches.is_empty(), "expected match in json string");
    assert_eq!(matches[0].canary_kind, CanaryKind::Aws);
    assert_eq!(matches[0].encoding, LeakEncoding::Raw);

    let val: serde_json::Value = serde_json::from_str(&json_payload).expect("valid json");
    let json_matches = scanner.scan_json(&val, "stdout");
    assert!(!json_matches.is_empty(), "expected match via scan_json");
    assert_eq!(json_matches[0].canary_kind, CanaryKind::Aws);

    let empty_reg = CanaryRegistry::new();
    let empty_scanner = LeakScanner::from_registry(&empty_reg);
    assert!(empty_scanner.scan_bytes(b"test", "stdout").is_empty());
    assert!(empty_scanner.scan_json(&val, "stdout").is_empty());
}

#[test]
fn p1_leak_02_base64_alignments() {
    let (reg, secret) = sample_registry();
    let scanner = LeakScanner::from_registry(&reg);

    // Alignment 0
    let b64_align0 = simple_base64(secret.as_bytes());
    let m0 = scanner.scan_bytes(b64_align0.as_bytes(), "stdout");
    assert!(!m0.is_empty(), "expected match for alignment 0");
    assert_eq!(m0[0].encoding, LeakEncoding::Base64);

    // Alignment 1: prefix with one dummy byte
    let mut with_prefix1 = vec![b'x'];
    with_prefix1.extend_from_slice(secret.as_bytes());
    let b64_align1 = simple_base64(&with_prefix1);
    let m1 = scanner.scan_bytes(b64_align1.as_bytes(), "stdout");
    assert!(!m1.is_empty(), "expected match for alignment 1");
    assert_eq!(m1[0].encoding, LeakEncoding::Base64);

    // Alignment 2: prefix with two dummy bytes ("xx" + secret as specified in SPEC)
    let mut with_prefix2 = vec![b'x', b'x'];
    with_prefix2.extend_from_slice(secret.as_bytes());
    let b64_align2 = simple_base64(&with_prefix2);
    let m2 = scanner.scan_bytes(b64_align2.as_bytes(), "stdout");
    assert!(!m2.is_empty(), "expected match for alignment 2");
    assert_eq!(m2[0].encoding, LeakEncoding::Base64);
}

#[test]
fn p1_leak_03_hex_and_percent() {
    let (reg, secret) = sample_registry();
    let scanner = LeakScanner::from_registry(&reg);

    // Hex lower
    let hex_lower: String = secret.bytes().map(|b| format!("{b:02x}")).collect();
    let m_hex_l = scanner.scan_bytes(hex_lower.as_bytes(), "stderr");
    assert!(!m_hex_l.is_empty(), "expected match for hex lower");
    assert_eq!(m_hex_l[0].encoding, LeakEncoding::HexLower);

    // Hex upper
    let hex_upper: String = secret.bytes().map(|b| format!("{b:02X}")).collect();
    let m_hex_u = scanner.scan_bytes(hex_upper.as_bytes(), "stderr");
    assert!(!m_hex_u.is_empty(), "expected match for hex upper");
    assert_eq!(m_hex_u[0].encoding, LeakEncoding::HexUpper);

    // Percent encoded
    let percent: String = secret.bytes().map(|b| format!("%{b:02X}")).collect();
    let m_pct = scanner.scan_bytes(percent.as_bytes(), "argv");
    assert!(!m_pct.is_empty(), "expected match for percent encoded");
    assert_eq!(m_pct[0].encoding, LeakEncoding::Percent);
}

#[test]
fn p1_leak_04_random_bytes_zero_false_positives() {
    let (reg, _) = sample_registry();
    let scanner = LeakScanner::from_registry(&reg);

    // 10 MB pseudo-random stream using ChaCha20 with fixed seed
    let mut rng = ChaCha20Rng::seed_from_u64(0xdeadbeefcafebabe);
    let chunk_size = 1024 * 1024;
    let mut chunk = vec![0u8; chunk_size];

    for _ in 0..10 {
        rng.fill_bytes(&mut chunk);
        let matches = scanner.scan_bytes(&chunk, "stdout");
        assert!(
            matches.is_empty(),
            "false positive match detected in pseudo-random data: {matches:?}"
        );
    }
}

fn simple_base64(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((triple >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((triple >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((triple >> 6) & 0x3f) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(triple & 0x3f) as usize] as char);
        }
    }
    out
}
