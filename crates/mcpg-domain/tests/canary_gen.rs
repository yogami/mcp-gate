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
