//! Stream leak scanner for detecting canary secrets in outputs.
//!
//! SPEC 3.2.5:
//! Builds an Aho-Corasick automaton over secret substrings across encodings:
//! raw, base64 (alignments 0, 1, 2 for standard and URL-safe),
//! lowercase hex, uppercase hex, and percent-encoding.
//! Scans stdout, stderr, argv, network payloads, and mutated files.

use aho_corasick::{AhoCorasick, Match};
use serde::{Deserialize, Serialize};

use crate::canary::catalogue::CanaryKind;
use crate::canary::registry::CanaryRegistry;

const MIN_PATTERN_LEN: usize = 8;
const B64_STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64_URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// The detected representation format of a leaked secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LeakEncoding {
    Raw,
    Base64,
    HexLower,
    HexUpper,
    Percent,
}

/// A matched leak occurrence in scanned content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeakMatch {
    pub canary_kind: CanaryKind,
    pub field: String,
    pub canary_fp: String,
    pub encoding: LeakEncoding,
    pub offset: usize,
    pub channel: String,
}

#[derive(Clone)]
struct PatternMeta {
    canary_kind: CanaryKind,
    field: String,
    canary_fp: String,
    encoding: LeakEncoding,
}

/// High-performance multi-pattern scanner for canary values.
pub struct LeakScanner {
    aut: Option<AhoCorasick>,
    metas: Vec<PatternMeta>,
}

impl LeakScanner {
    /// Build a scanner from a planted canary registry.
    pub fn from_registry(registry: &CanaryRegistry) -> Self {
        let mut patterns = Vec::new();
        let mut metas = Vec::new();

        for record in &registry.records {
            for secret in &record.secrets {
                let meta = PatternMeta {
                    canary_kind: record.kind,
                    field: secret.field.clone(),
                    canary_fp: record.fp.clone(),
                    encoding: LeakEncoding::Raw,
                };
                collect_all_patterns(meta, secret.value.as_bytes(), &mut patterns, &mut metas);
            }
        }

        let aut = if patterns.is_empty() {
            None
        } else {
            AhoCorasick::new(&patterns).ok()
        };

        Self { aut, metas }
    }

    /// Scan arbitrary bytes on a specified reporting channel.
    pub fn scan_bytes(&self, data: &[u8], channel: &str) -> Vec<LeakMatch> {
        let Some(aut) = &self.aut else {
            return Vec::new();
        };

        aut.find_iter(data)
            .map(|m| self.build_match(&m, channel))
            .collect()
    }

    /// Recursively scan all string values in a JSON tree.
    pub fn scan_json(&self, val: &serde_json::Value, channel: &str) -> Vec<LeakMatch> {
        let mut matches = Vec::new();
        scan_json_recursive(self, val, channel, &mut matches);
        matches
    }

    fn build_match(&self, m: &Match, channel: &str) -> LeakMatch {
        let meta = &self.metas[m.pattern().as_usize()];
        LeakMatch {
            canary_kind: meta.canary_kind,
            field: meta.field.clone(),
            canary_fp: meta.canary_fp.clone(),
            encoding: meta.encoding,
            offset: m.start(),
            channel: channel.to_string(),
        }
    }
}

fn scan_json_recursive(
    scanner: &LeakScanner,
    val: &serde_json::Value,
    channel: &str,
    out: &mut Vec<LeakMatch>,
) {
    match val {
        serde_json::Value::String(s) => {
            out.extend(scanner.scan_bytes(s.as_bytes(), channel));
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                scan_json_recursive(scanner, item, channel, out);
            }
        }
        serde_json::Value::Object(map) => {
            for v in map.values() {
                scan_json_recursive(scanner, v, channel, out);
            }
        }
        _ => {}
    }
}

fn collect_all_patterns(
    base_meta: PatternMeta,
    secret: &[u8],
    patterns: &mut Vec<Vec<u8>>,
    metas: &mut Vec<PatternMeta>,
) {
    if secret.len() < MIN_PATTERN_LEN {
        return;
    }

    add_pattern(
        secret.to_vec(),
        LeakEncoding::Raw,
        &base_meta,
        patterns,
        metas,
    );
    collect_b64_variants(&base_meta, secret, patterns, metas);
    collect_hex_variants(&base_meta, secret, patterns, metas);
    collect_percent_variants(&base_meta, secret, patterns, metas);
}

fn collect_b64_variants(
    meta: &PatternMeta,
    secret: &[u8],
    patterns: &mut Vec<Vec<u8>>,
    metas: &mut Vec<PatternMeta>,
) {
    for align in 0..=2 {
        if let Some(pat) = derive_b64_slice(secret, align, B64_STD) {
            add_pattern(pat, LeakEncoding::Base64, meta, patterns, metas);
        }
        if let Some(pat) = derive_b64_slice(secret, align, B64_URL) {
            add_pattern(pat, LeakEncoding::Base64, meta, patterns, metas);
        }
    }
}

fn collect_hex_variants(
    meta: &PatternMeta,
    secret: &[u8],
    patterns: &mut Vec<Vec<u8>>,
    metas: &mut Vec<PatternMeta>,
) {
    let lower = encode_hex(secret, false);
    add_pattern(lower, LeakEncoding::HexLower, meta, patterns, metas);

    let upper = encode_hex(secret, true);
    add_pattern(upper, LeakEncoding::HexUpper, meta, patterns, metas);
}

fn collect_percent_variants(
    meta: &PatternMeta,
    secret: &[u8],
    patterns: &mut Vec<Vec<u8>>,
    metas: &mut Vec<PatternMeta>,
) {
    let pct_upper = encode_percent(secret, true);
    add_pattern(pct_upper, LeakEncoding::Percent, meta, patterns, metas);

    let pct_lower = encode_percent(secret, false);
    add_pattern(pct_lower, LeakEncoding::Percent, meta, patterns, metas);
}

fn add_pattern(
    pat: Vec<u8>,
    encoding: LeakEncoding,
    meta: &PatternMeta,
    patterns: &mut Vec<Vec<u8>>,
    metas: &mut Vec<PatternMeta>,
) {
    if pat.len() < MIN_PATTERN_LEN {
        return;
    }
    let mut m = meta.clone();
    m.encoding = encoding;
    patterns.push(pat);
    metas.push(m);
}

fn derive_b64_slice(secret: &[u8], align: usize, alphabet: &[u8; 64]) -> Option<Vec<u8>> {
    let mut buffer = vec![0u8; align];
    buffer.extend_from_slice(secret);

    let full_triples = buffer.len() / 3;
    let end_char = full_triples * 4;
    let start_char = if align == 0 { 0 } else { align + 1 };

    if start_char >= end_char {
        return None;
    }

    let encoded = raw_b64(&buffer, alphabet);
    Some(encoded[start_char..end_char].to_vec())
}

fn raw_b64(data: &[u8], alphabet: &[u8; 64]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;

        out.push(alphabet[((triple >> 18) & 0x3f) as usize]);
        out.push(alphabet[((triple >> 12) & 0x3f) as usize]);
        if chunk.len() > 1 {
            out.push(alphabet[((triple >> 6) & 0x3f) as usize]);
        }
        if chunk.len() > 2 {
            out.push(alphabet[(triple & 0x3f) as usize]);
        }
    }
    out
}

fn encode_hex(data: &[u8], upper: bool) -> Vec<u8> {
    const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";
    const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";
    let alphabet = if upper { HEX_UPPER } else { HEX_LOWER };

    let mut out = Vec::with_capacity(data.len() * 2);
    for &b in data {
        out.push(alphabet[(b >> 4) as usize]);
        out.push(alphabet[(b & 0x0f) as usize]);
    }
    out
}

fn encode_percent(data: &[u8], upper: bool) -> Vec<u8> {
    const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";
    const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";
    let alphabet = if upper { HEX_UPPER } else { HEX_LOWER };

    let mut out = Vec::with_capacity(data.len() * 3);
    for &b in data {
        out.push(b'%');
        out.push(alphabet[(b >> 4) as usize]);
        out.push(alphabet[(b & 0x0f) as usize]);
    }
    out
}
