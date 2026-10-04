//! Canary planning and content rendering.
//!
//! SPEC 3.2.2:
//! Pure functions to plan file and environment canaries from a seed.

use std::ffi::OsString;
use std::path::PathBuf;

use crate::canary::catalogue::{entry_for_kind, CanaryKind, CanaryTier};
use crate::canary::derive::derive;
use crate::seed::Seed;

const B32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/+";
const B62_ALPHABET: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

fn encode_b32(raw: &[u8]) -> String {
    raw.iter()
        .map(|&b| B32_ALPHABET[(b % 32) as usize] as char)
        .collect()
}

fn encode_b64(raw: &[u8]) -> String {
    raw.iter()
        .map(|&b| B64_ALPHABET[(b % 64) as usize] as char)
        .collect()
}

fn encode_b62(raw: &[u8]) -> String {
    raw.iter()
        .map(|&b| B62_ALPHABET[(b % 62) as usize] as char)
        .collect()
}

/// A planned canary file to be planted in the capsule or run directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedFile {
    pub path: PathBuf,
    pub content: Vec<u8>,
    pub mode: u32,
    pub kind: CanaryKind,
    pub tier: CanaryTier,
}

/// A secret value contained in a planted canary file or environment variable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Secret {
    pub field: String,
    pub value: String,
    pub kind: CanaryKind,
}

/// The pure execution plan for all requested canaries.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CanaryPlan {
    pub files: Vec<PlannedFile>,
    pub env: Vec<(OsString, OsString)>,
    pub secrets: Vec<Secret>,
}

fn render_aws(seed: &Seed, files: &mut Vec<PlannedFile>, secrets: &mut Vec<Secret>) {
    let entry = entry_for_kind(CanaryKind::Aws);
    let key_suffix = encode_b32(&derive(seed, "aws", "access_key_id", 16));
    let access_key = format!("AKIA{key_suffix}");
    let secret_key = encode_b64(&derive(seed, "aws", "secret_access_key", 40));

    secrets.push(Secret {
        field: "aws_access_key_id".to_string(),
        value: access_key.clone(),
        kind: CanaryKind::Aws,
    });
    secrets.push(Secret {
        field: "aws_secret_access_key".to_string(),
        value: secret_key.clone(),
        kind: CanaryKind::Aws,
    });

    let creds_content = format!(
        "[default]\naws_access_key_id = {access_key}\naws_secret_access_key = {secret_key}\n"
    );
    files.push(PlannedFile {
        path: PathBuf::from(".aws/credentials"),
        content: creds_content.into_bytes(),
        mode: entry.file_mode,
        kind: CanaryKind::Aws,
        tier: entry.tier,
    });

    let config_content = "[default]\nregion = us-east-1\noutput = json\n";
    files.push(PlannedFile {
        path: PathBuf::from(".aws/config"),
        content: config_content.as_bytes().to_vec(),
        mode: entry.file_mode,
        kind: CanaryKind::Aws,
        tier: entry.tier,
    });
}

fn render_env(seed: &Seed, env: &mut Vec<(OsString, OsString)>, secrets: &mut Vec<Secret>) {
    let key_suffix = encode_b32(&derive(seed, "aws", "access_key_id", 16));
    let aws_key = format!("AKIA{key_suffix}");
    let aws_sec = encode_b64(&derive(seed, "aws", "secret_access_key", 40));

    let gh_token = format!(
        "ghp_{}",
        encode_b62(&derive(seed, "env", "github_token", 36))
    );
    let oai_token = format!(
        "sk-proj-{}",
        encode_b62(&derive(seed, "env", "openai_api_key", 48))
    );
    let ant_token = format!(
        "sk-ant-{}",
        encode_b62(&derive(seed, "env", "anthropic_api_key", 48))
    );

    let vars = [
        ("AWS_ACCESS_KEY_ID", aws_key),
        ("AWS_SECRET_ACCESS_KEY", aws_sec),
        ("GITHUB_TOKEN", gh_token),
        ("OPENAI_API_KEY", oai_token),
        ("ANTHROPIC_API_KEY", ant_token),
    ];

    for (name, val) in vars {
        secrets.push(Secret {
            field: name.to_lowercase(),
            value: val.clone(),
            kind: CanaryKind::Env,
        });
        env.push((OsString::from(name), OsString::from(val)));
    }
}

/// Plan canaries for the given seed and set of canary kinds.
pub fn plan(seed: &Seed, kinds: &[CanaryKind]) -> CanaryPlan {
    let mut plan = CanaryPlan::default();
    for &kind in kinds {
        match kind {
            CanaryKind::Aws => render_aws(seed, &mut plan.files, &mut plan.secrets),
            CanaryKind::Env => render_env(seed, &mut plan.env, &mut plan.secrets),
            _ => {}
        }
    }
    plan
}
