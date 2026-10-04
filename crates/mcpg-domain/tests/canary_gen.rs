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
