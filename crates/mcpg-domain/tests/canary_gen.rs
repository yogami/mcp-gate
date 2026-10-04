use mcpg_domain::canary::derive::derive;
use mcpg_domain::seed::Seed;

#[test]
fn derive_same_seed_same_bytes() {
    let seed = Seed::from_bytes([42u8; 32]);
    let out1 = derive(&seed, "aws", "secret_key", 40);
    let out2 = derive(&seed, "aws", "secret_key", 40);
    assert_eq!(out1, out2);
    assert_eq!(out1.len(), 40);

    // Also verify short outputs (<= 32 bytes)
    let short1 = derive(&seed, "aws", "key_id", 16);
    let short2 = derive(&seed, "aws", "key_id", 16);
    assert_eq!(short1, short2);
    assert_eq!(short1.len(), 16);
}

#[test]
fn derive_different_info_differs() {
    let seed = Seed::from_bytes([7u8; 32]);
    let out_aws = derive(&seed, "aws", "key", 32);
    let out_gcloud = derive(&seed, "gcloud", "key", 32);
    let out_aws_field2 = derive(&seed, "aws", "other_field", 32);

    assert_ne!(out_aws, out_gcloud);
    assert_ne!(out_aws, out_aws_field2);
    assert_ne!(out_gcloud, out_aws_field2);
}

#[test]
fn derive_known_answer() {
    let seed = Seed::from_bytes([1u8; 32]);
    let out = derive(&seed, "aws", "access_key_id", 32);
    // Known test vector computed with HKDF-SHA256(ikm=[1;32], salt=None, info="mcp-gate/v1/aws/access_key_id")
    let hex_out = out
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join("");
    // We will verify the exact committed vector once derive is implemented
    assert_eq!(out.len(), 32);
    assert_eq!(
        hex_out,
        "4c44a9b7c9045fad5ef33aa52fcbe99bff6939d2920bf608324c584906d875da"
    );
}

#[test]
fn catalogue_matches_spec_table() {
    use mcpg_domain::canary::catalogue::{all_catalogue_entries, CanaryKind, CanaryTier};

    let entries = all_catalogue_entries();
    assert_eq!(entries.len(), 12);

    let find = |k: CanaryKind| entries.iter().find(|e| e.kind == k).expect("entry exists");

    let ssh = find(CanaryKind::Ssh);
    assert_eq!(ssh.tier, CanaryTier::A);
    assert_eq!(
        ssh.relative_paths,
        &[".ssh/id_ed25519", ".ssh/id_ed25519.pub"]
    );

    let aws = find(CanaryKind::Aws);
    assert_eq!(aws.tier, CanaryTier::A);
    assert_eq!(aws.relative_paths, &[".aws/credentials", ".aws/config"]);

    let gcloud = find(CanaryKind::Gcloud);
    assert_eq!(gcloud.tier, CanaryTier::A);
    assert_eq!(
        gcloud.relative_paths,
        &[".config/gcloud/application_default_credentials.json"]
    );

    let kube = find(CanaryKind::Kube);
    assert_eq!(kube.tier, CanaryTier::A);
    assert_eq!(kube.relative_paths, &[".kube/config"]);

    let docker = find(CanaryKind::Docker);
    assert_eq!(docker.tier, CanaryTier::A);
    assert_eq!(docker.relative_paths, &[".docker/config.json"]);

    let git_creds = find(CanaryKind::GitCredentials);
    assert_eq!(git_creds.tier, CanaryTier::A);
    assert_eq!(git_creds.relative_paths, &[".git-credentials"]);

    let gh = find(CanaryKind::GhCli);
    assert_eq!(gh.tier, CanaryTier::A);
    assert_eq!(gh.relative_paths, &[".config/gh/hosts.yml"]);

    let netrc = find(CanaryKind::Netrc);
    assert_eq!(netrc.tier, CanaryTier::B);
    assert_eq!(netrc.relative_paths, &[".netrc"]);

    let npmrc = find(CanaryKind::Npmrc);
    assert_eq!(npmrc.tier, CanaryTier::B);
    assert_eq!(npmrc.relative_paths, &[".npmrc"]);

    let pypirc = find(CanaryKind::Pypirc);
    assert_eq!(pypirc.tier, CanaryTier::B);
    assert_eq!(pypirc.relative_paths, &[".pypirc"]);

    let dotenv = find(CanaryKind::Dotenv);
    assert_eq!(dotenv.tier, CanaryTier::A);
    assert_eq!(dotenv.relative_paths, &[".env"]);

    let env = find(CanaryKind::Env);
    assert_eq!(env.tier, CanaryTier::EgressOnly);
    assert!(env.relative_paths.is_empty());
}

#[test]
fn p1_can_04_aws_shapes() {
    use mcpg_domain::canary::catalogue::CanaryKind;
    use mcpg_domain::canary::render::plan;

    let seed = Seed::from_bytes([99u8; 32]);
    let canary_plan = plan(&seed, &[CanaryKind::Aws]);

    let creds_file = canary_plan
        .files
        .iter()
        .find(|f| f.path.to_str() == Some(".aws/credentials"))
        .expect(".aws/credentials must exist in plan");

    let content = String::from_utf8(creds_file.content.clone()).expect("valid utf8");
    assert!(content.contains("[default]"));
    assert!(content.contains("aws_access_key_id = "));
    assert!(content.contains("aws_secret_access_key = "));

    // Extract access key id and secret access key from secrets list
    let key_id_secret = canary_plan
        .secrets
        .iter()
        .find(|s| s.field == "aws_access_key_id")
        .expect("access key secret recorded");
    let secret_key_secret = canary_plan
        .secrets
        .iter()
        .find(|s| s.field == "aws_secret_access_key")
        .expect("secret key secret recorded");

    // Key format: ^AKIA[A-Z2-7]{16}$
    let key_id = &key_id_secret.value;
    assert_eq!(key_id.len(), 20);
    assert!(key_id.starts_with("AKIA"));
    for ch in key_id[4..].chars() {
        assert!(
            matches!(ch, 'A'..='Z' | '2'..='7'),
            "char '{ch}' not in [A-Z2-7]"
        );
    }

    // Secret format: 40 chars of [A-Za-z0-9/+]
    let secret = &secret_key_secret.value;
    assert_eq!(secret.len(), 40);
    for ch in secret.chars() {
        assert!(
            matches!(ch, 'A'..='Z' | 'a'..='z' | '0'..='9' | '/' | '+'),
            "char '{ch}' not in [A-Za-z0-9/+]"
        );
    }
}

#[test]
fn env_decoys_cover_five_names() {
    use mcpg_domain::canary::catalogue::CanaryKind;
    use mcpg_domain::canary::render::plan;

    let seed = Seed::from_bytes([88u8; 32]);
    let canary_plan = plan(&seed, &[CanaryKind::Env]);

    let keys: Vec<String> = canary_plan
        .env
        .iter()
        .map(|(k, _)| k.to_string_lossy().into_owned())
        .collect();

    assert!(keys.contains(&"AWS_ACCESS_KEY_ID".to_string()));
    assert!(keys.contains(&"AWS_SECRET_ACCESS_KEY".to_string()));
    assert!(keys.contains(&"GITHUB_TOKEN".to_string()));
    assert!(keys.contains(&"OPENAI_API_KEY".to_string()));
    assert!(keys.contains(&"ANTHROPIC_API_KEY".to_string()));

    for (k, v) in &canary_plan.env {
        let val_str = v.to_string_lossy();
        assert!(
            !val_str.is_empty(),
            "decoy value for {k:?} must not be empty"
        );
    }
}

#[test]
fn gcloud_is_valid_json() {
    use mcpg_domain::canary::catalogue::CanaryKind;
    use mcpg_domain::canary::render::plan;

    let seed = Seed::from_bytes([12u8; 32]);
    let canary_plan = plan(&seed, &[CanaryKind::Gcloud]);

    let file = canary_plan
        .files
        .iter()
        .find(|f| f.path.to_str() == Some(".config/gcloud/application_default_credentials.json"))
        .expect("gcloud credentials file planned");

    let parsed: serde_json::Value =
        serde_json::from_slice(&file.content).expect("gcloud credentials must be valid json");

    assert_eq!(parsed["type"], "authorized_user");
    assert!(parsed["client_secret"].as_str().is_some());
    assert!(parsed["refresh_token"].as_str().is_some());
}

#[test]
fn kube_is_valid_yaml() {
    use mcpg_domain::canary::catalogue::CanaryKind;
    use mcpg_domain::canary::render::plan;

    let seed = Seed::from_bytes([13u8; 32]);
    let canary_plan = plan(&seed, &[CanaryKind::Kube]);

    let file = canary_plan
        .files
        .iter()
        .find(|f| f.path.to_str() == Some(".kube/config"))
        .expect("kubeconfig file planned");

    let text = std::str::from_utf8(&file.content).expect("valid utf-8");
    let parsed: serde_yml::Value =
        serde_yml::from_str(text).expect("kubeconfig must be valid yaml");

    assert_eq!(parsed["kind"].as_str(), Some("Config"));
    assert_eq!(parsed["apiVersion"].as_str(), Some("v1"));
}

#[test]
fn docker_auth_is_base64_user_token() {
    use mcpg_domain::canary::catalogue::CanaryKind;
    use mcpg_domain::canary::render::plan;

    let seed = Seed::from_bytes([14u8; 32]);
    let canary_plan = plan(&seed, &[CanaryKind::Docker]);

    let file = canary_plan
        .files
        .iter()
        .find(|f| f.path.to_str() == Some(".docker/config.json"))
        .expect("docker config file planned");

    let parsed: serde_json::Value =
        serde_json::from_slice(&file.content).expect("docker config must be valid json");

    let auth_str = parsed["auths"]["registry.invalid"]["auth"]
        .as_str()
        .expect("auth field must be string");

    // Decode base64
    let decoded_bytes = decode_test_base64(auth_str);
    let decoded_str = String::from_utf8(decoded_bytes).expect("decoded auth is utf-8");
    let parts: Vec<&str> = decoded_str.split(':').collect();
    assert_eq!(parts.len(), 2, "docker auth must decode to user:token");
    assert!(!parts[0].is_empty());
    assert!(!parts[1].is_empty());
}

fn decode_test_base64(input: &str) -> Vec<u8> {
    const B64_CHARS: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0;
    for &byte in input.as_bytes() {
        if byte == b'=' {
            break;
        }
        if let Some(pos) = B64_CHARS.iter().position(|&c| c == byte) {
            buf = (buf << 6) | (pos as u32);
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((buf >> bits) as u8);
            }
        }
    }
    out
}

#[test]
fn hosts_use_invalid_tld() {
    use mcpg_domain::canary::catalogue::{all_catalogue_entries, CanaryKind};
    use mcpg_domain::canary::render::plan;

    let seed = Seed::from_bytes([15u8; 32]);
    let all_kinds: Vec<CanaryKind> = all_catalogue_entries().iter().map(|e| e.kind).collect();
    let canary_plan = plan(&seed, &all_kinds);

    // Collect all text from planned files and secrets
    let mut corpus = String::new();
    for f in &canary_plan.files {
        corpus.push_str(&String::from_utf8_lossy(&f.content));
        corpus.push('\n');
    }
    for s in &canary_plan.secrets {
        corpus.push_str(&s.value);
        corpus.push('\n');
    }

    // Check for common hosts and ensure any detected domain ends with .invalid
    for token in corpus.split_whitespace() {
        let cleaned = token.trim_matches(|c: char| {
            c == '"'
                || c == '\''
                || c == ','
                || c == ':'
                || c == '{'
                || c == '}'
                || c == '['
                || c == ']'
                || c == '('
                || c == ')'
                || c == ';'
        });
        let host = if let Some(stripped) = cleaned.strip_prefix("https://") {
            stripped.split('/').next().unwrap_or(stripped)
        } else if let Some(stripped) = cleaned.strip_prefix("//") {
            stripped.split('/').next().unwrap_or(stripped)
        } else if let Some(stripped) = cleaned.strip_prefix("machine ") {
            stripped
        } else {
            cleaned
        };

        let host = host.split(':').next().unwrap_or(host);
        let host = host.split('@').next_back().unwrap_or(host);
        let host = host.split('/').next().unwrap_or(host);
        let host = host.trim_matches(|c: char| !c.is_alphanumeric() && c != '.' && c != '-');

        if host.contains('.')
            && !host.chars().any(|c| c.is_ascii_digit())
            && !host.ends_with(".json")
            && !host.ends_with(".yml")
            && !host.ends_with(".pub")
        {
            assert!(
                host.ends_with(".invalid"),
                "detected host '{host}' does not end in .invalid"
            );
        }
    }
}

#[test]
fn no_fixed_marker_strings() {
    use mcpg_domain::canary::catalogue::{all_catalogue_entries, CanaryKind};
    use mcpg_domain::canary::render::plan;

    let seed = Seed::from_bytes([16u8; 32]);
    let all_kinds: Vec<CanaryKind> = all_catalogue_entries().iter().map(|e| e.kind).collect();
    let canary_plan = plan(&seed, &all_kinds);

    let forbidden = ["mcpg", "canary", "MCPG", "EXAMPLE"];

    for f in &canary_plan.files {
        let text = String::from_utf8_lossy(&f.content);
        for marker in forbidden {
            assert!(
                !text.contains(marker),
                "planned file {:?} contains forbidden marker '{marker}'",
                f.path
            );
        }
    }

    for s in &canary_plan.secrets {
        for marker in forbidden {
            assert!(
                !s.value.contains(marker),
                "secret {} contains forbidden marker '{marker}'",
                s.field
            );
        }
    }
}

#[test]
fn p1_can_02_different_seeds_all_secrets_differ() {
    use mcpg_domain::canary::catalogue::{all_catalogue_entries, CanaryKind};
    use mcpg_domain::canary::render::plan;

    let seed1 = Seed::from_bytes([101u8; 32]);
    let seed2 = Seed::from_bytes([202u8; 32]);

    let kinds: Vec<CanaryKind> = all_catalogue_entries()
        .iter()
        .map(|e| e.kind)
        .filter(|&k| k != CanaryKind::Ssh) // Ssh is TASK-1.32
        .collect();

    let plan1 = plan(&seed1, &kinds);
    let plan2 = plan(&seed2, &kinds);

    assert_eq!(plan1.secrets.len(), plan2.secrets.len());
    assert!(!plan1.secrets.is_empty(), "must have secrets to compare");

    for (s1, s2) in plan1.secrets.iter().zip(plan2.secrets.iter()) {
        assert_eq!(s1.field, s2.field);
        assert_eq!(s1.kind, s2.kind);
        assert_ne!(
            s1.value, s2.value,
            "secret for {:?}/{} was identical across two seeds",
            s1.kind, s1.field
        );
    }
}
