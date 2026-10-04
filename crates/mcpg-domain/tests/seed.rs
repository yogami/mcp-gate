use std::str::FromStr;

use mcpg_domain::seed::{Seed, SeedError};
use mcpg_domain::testing::FakeEntropy;

#[test]
fn p1_seed_01_fresh_seeds_differ() {
    let block1 = [1u8; 32];
    let block2 = [2u8; 32];
    let entropy = FakeEntropy::new(vec![block1, block2]);

    let seed1 = Seed::random(&entropy).expect("generate seed 1");
    let seed2 = Seed::random(&entropy).expect("generate seed 2");

    assert_ne!(seed1, seed2);
    assert_eq!(seed1.as_bytes(), &block1);
    assert_eq!(seed2.as_bytes(), &block2);
}

#[test]
fn p1_seed_04_bad_hex_rejected() {
    // 63 characters: too short
    let too_short = "a".repeat(63);
    let err_short = Seed::from_str(&too_short).expect_err("63 chars must fail");
    assert!(matches!(err_short, SeedError::InvalidLength(63)));

    // 65 characters: too long
    let too_long = "b".repeat(65);
    let err_long = Seed::from_str(&too_long).expect_err("65 chars must fail");
    assert!(matches!(err_long, SeedError::InvalidLength(65)));

    // 64 characters with non-hex character
    let non_hex = "g".repeat(64);
    let err_hex = Seed::from_str(&non_hex).expect_err("non-hex must fail");
    assert!(matches!(err_hex, SeedError::InvalidHex('g')));
}
