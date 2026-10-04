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

fn to_base64(data: &[u8]) -> String {
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;

        out.push(B64_ALPHABET[((triple >> 18) & 0x3f) as usize] as char);
        out.push(B64_ALPHABET[((triple >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64_ALPHABET[((triple >> 6) & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(B64_ALPHABET[(triple & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
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

fn render_gcloud(seed: &Seed, files: &mut Vec<PlannedFile>, secrets: &mut Vec<Secret>) {
    let entry = entry_for_kind(CanaryKind::Gcloud);
    let client_secret = encode_b62(&derive(seed, "gcloud", "client_secret", 24));
    let refresh_token = format!(
        "1//{}",
        encode_b62(&derive(seed, "gcloud", "refresh_token", 32))
    );
    let client_id = format!(
        "{}.apps.googleusercontent.invalid",
        encode_b62(&derive(seed, "gcloud", "client_id", 24))
    );

    secrets.push(Secret {
        field: "gcloud_client_secret".to_string(),
        value: client_secret.clone(),
        kind: CanaryKind::Gcloud,
    });
    secrets.push(Secret {
        field: "gcloud_refresh_token".to_string(),
        value: refresh_token.clone(),
        kind: CanaryKind::Gcloud,
    });

    let content = format!(
        "{{\n  \"account\": \"\",\n  \"client_id\": \"{client_id}\",\n  \"client_secret\": \"{client_secret}\",\n  \"quota_project_id\": \"project-default\",\n  \"refresh_token\": \"{refresh_token}\",\n  \"type\": \"authorized_user\"\n}}\n"
    );

    files.push(PlannedFile {
        path: PathBuf::from(".config/gcloud/application_default_credentials.json"),
        content: content.into_bytes(),
        mode: entry.file_mode,
        kind: CanaryKind::Gcloud,
        tier: entry.tier,
    });
}

fn render_kube(seed: &Seed, files: &mut Vec<PlannedFile>, secrets: &mut Vec<Secret>) {
    let entry = entry_for_kind(CanaryKind::Kube);
    let token = encode_b62(&derive(seed, "kube", "token", 32));

    secrets.push(Secret {
        field: "kube_token".to_string(),
        value: token.clone(),
        kind: CanaryKind::Kube,
    });

    let content = format!(
        "apiVersion: v1\nkind: Config\npreferences: {{}}\nclusters:\n- cluster:\n    server: https://k8s.invalid\n  name: default-cluster\ncontexts:\n- context:\n    cluster: default-cluster\n    user: default-user\n  name: default-context\ncurrent-context: default-context\nusers:\n- name: default-user\n  user:\n    token: {token}\n"
    );

    files.push(PlannedFile {
        path: PathBuf::from(".kube/config"),
        content: content.into_bytes(),
        mode: entry.file_mode,
        kind: CanaryKind::Kube,
        tier: entry.tier,
    });
}

fn render_docker(seed: &Seed, files: &mut Vec<PlannedFile>, secrets: &mut Vec<Secret>) {
    let entry = entry_for_kind(CanaryKind::Docker);
    let token = encode_b62(&derive(seed, "docker", "token", 32));
    let raw_auth = format!("agent:{token}");
    let auth = to_base64(raw_auth.as_bytes());

    secrets.push(Secret {
        field: "docker_token".to_string(),
        value: token,
        kind: CanaryKind::Docker,
    });

    let content = format!(
        "{{\n  \"auths\": {{\n    \"registry.invalid\": {{\n      \"auth\": \"{auth}\"\n    }}\n  }}\n}}\n"
    );

    files.push(PlannedFile {
        path: PathBuf::from(".docker/config.json"),
        content: content.into_bytes(),
        mode: entry.file_mode,
        kind: CanaryKind::Docker,
        tier: entry.tier,
    });
}

fn render_git_credentials(seed: &Seed, files: &mut Vec<PlannedFile>, secrets: &mut Vec<Secret>) {
    let entry = entry_for_kind(CanaryKind::GitCredentials);
    let token = encode_b62(&derive(seed, "git_credentials", "token", 32));

    secrets.push(Secret {
        field: "git_token".to_string(),
        value: token.clone(),
        kind: CanaryKind::GitCredentials,
    });

    let content = format!("https://user:{token}@git.invalid\n");

    files.push(PlannedFile {
        path: PathBuf::from(".git-credentials"),
        content: content.into_bytes(),
        mode: entry.file_mode,
        kind: CanaryKind::GitCredentials,
        tier: entry.tier,
    });
}

fn render_gh_cli(seed: &Seed, files: &mut Vec<PlannedFile>, secrets: &mut Vec<Secret>) {
    let entry = entry_for_kind(CanaryKind::GhCli);
    let token = format!(
        "gho_{}",
        encode_b62(&derive(seed, "gh_cli", "oauth_token", 36))
    );

    secrets.push(Secret {
        field: "gh_oauth_token".to_string(),
        value: token.clone(),
        kind: CanaryKind::GhCli,
    });

    let content =
        format!("github.invalid:\n  user: octo\n  oauth_token: {token}\n  git_protocol: https\n");

    files.push(PlannedFile {
        path: PathBuf::from(".config/gh/hosts.yml"),
        content: content.into_bytes(),
        mode: entry.file_mode,
        kind: CanaryKind::GhCli,
        tier: entry.tier,
    });
}

fn render_netrc(seed: &Seed, files: &mut Vec<PlannedFile>, secrets: &mut Vec<Secret>) {
    let entry = entry_for_kind(CanaryKind::Netrc);
    let password = encode_b62(&derive(seed, "netrc", "password", 24));

    secrets.push(Secret {
        field: "netrc_password".to_string(),
        value: password.clone(),
        kind: CanaryKind::Netrc,
    });

    let content = format!("machine api.invalid login user password {password}\n");

    files.push(PlannedFile {
        path: PathBuf::from(".netrc"),
        content: content.into_bytes(),
        mode: entry.file_mode,
        kind: CanaryKind::Netrc,
        tier: entry.tier,
    });
}

fn render_npmrc(seed: &Seed, files: &mut Vec<PlannedFile>, secrets: &mut Vec<Secret>) {
    let entry = entry_for_kind(CanaryKind::Npmrc);
    let token = encode_b62(&derive(seed, "npmrc", "token", 36));

    secrets.push(Secret {
        field: "npmrc_token".to_string(),
        value: token.clone(),
        kind: CanaryKind::Npmrc,
    });

    let content = format!("//registry.invalid/:_authToken={token}\n");

    files.push(PlannedFile {
        path: PathBuf::from(".npmrc"),
        content: content.into_bytes(),
        mode: entry.file_mode,
        kind: CanaryKind::Npmrc,
        tier: entry.tier,
    });
}

fn render_pypirc(seed: &Seed, files: &mut Vec<PlannedFile>, secrets: &mut Vec<Secret>) {
    let entry = entry_for_kind(CanaryKind::Pypirc);
    let token = format!("pypi-{}", encode_b62(&derive(seed, "pypirc", "token", 36)));

    secrets.push(Secret {
        field: "pypirc_token".to_string(),
        value: token.clone(),
        kind: CanaryKind::Pypirc,
    });

    let content = format!(
        "[distutils]\nindex-servers = pypi\n\n[pypi]\nrepository = https://upload.pypi.invalid/legacy/\nusername = __token__\npassword = {token}\n"
    );

    files.push(PlannedFile {
        path: PathBuf::from(".pypirc"),
        content: content.into_bytes(),
        mode: entry.file_mode,
        kind: CanaryKind::Pypirc,
        tier: entry.tier,
    });
}

fn render_dotenv(seed: &Seed, files: &mut Vec<PlannedFile>, secrets: &mut Vec<Secret>) {
    let entry = entry_for_kind(CanaryKind::Dotenv);
    let db_pass = encode_b62(&derive(seed, "dotenv", "db_pass", 24));
    let stripe_key = format!(
        "sk_live_{}",
        encode_b62(&derive(seed, "dotenv", "stripe_key", 24))
    );

    secrets.push(Secret {
        field: "dotenv_db_pass".to_string(),
        value: db_pass.clone(),
        kind: CanaryKind::Dotenv,
    });
    secrets.push(Secret {
        field: "dotenv_stripe_key".to_string(),
        value: stripe_key.clone(),
        kind: CanaryKind::Dotenv,
    });

    let content = format!(
        "DATABASE_URL=postgres://app_user:{db_pass}@db.invalid:5432/app_production\nSTRIPE_SECRET_KEY={stripe_key}\n"
    );

    files.push(PlannedFile {
        path: PathBuf::from(".env"),
        content: content.into_bytes(),
        mode: entry.file_mode,
        kind: CanaryKind::Dotenv,
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
            CanaryKind::Gcloud => render_gcloud(seed, &mut plan.files, &mut plan.secrets),
            CanaryKind::Kube => render_kube(seed, &mut plan.files, &mut plan.secrets),
            CanaryKind::Docker => render_docker(seed, &mut plan.files, &mut plan.secrets),
            CanaryKind::GitCredentials => {
                render_git_credentials(seed, &mut plan.files, &mut plan.secrets)
            }
            CanaryKind::GhCli => render_gh_cli(seed, &mut plan.files, &mut plan.secrets),
            CanaryKind::Netrc => render_netrc(seed, &mut plan.files, &mut plan.secrets),
            CanaryKind::Npmrc => render_npmrc(seed, &mut plan.files, &mut plan.secrets),
            CanaryKind::Pypirc => render_pypirc(seed, &mut plan.files, &mut plan.secrets),
            CanaryKind::Dotenv => render_dotenv(seed, &mut plan.files, &mut plan.secrets),
            CanaryKind::Ssh => {} // Ssh canary rendered in TASK-1.32
        }
    }
    plan
}
