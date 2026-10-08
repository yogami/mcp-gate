use std::str::FromStr;

use mcpg_domain::canary::catalogue::all_catalogue_entries;
use mcpg_domain::canary::registry::{CanaryRecord, CanaryRegistry};
use mcpg_domain::canary::render::{plan, Secret};
use mcpg_domain::seed::Seed;
use mcpg_domain::verdict::Verdict;
use mcpg_report::{all_writers, ReportWriter, RunRecord, CLAIM_SENTENCE};

fn sample_run_record() -> RunRecord {
    let seed = Seed::from_str("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        .expect("valid seed");
    let kinds: Vec<_> = all_catalogue_entries().iter().map(|e| e.kind).collect();
    let planned = plan(&seed, &kinds);

    let mut registry = CanaryRegistry::new();
    for (i, file) in planned.files.iter().enumerate() {
        let file_secrets: Vec<Secret> = planned
            .secrets
            .iter()
            .filter(|s| s.kind == file.kind)
            .cloned()
            .collect();

        registry.add(CanaryRecord {
            id: format!("canary-{}", i + 1),
            kind: file.kind,
            tier: file.tier,
            path: file.path.clone(),
            dev: 1,
            ino: (i + 1) as u64,
            fp: format!("fp{:010x}", i),
            secrets: file_secrets,
        });
    }

    RunRecord::new(seed, Verdict::Pass, registry, vec![])
}

#[test]
fn p1_can_06_no_raw_canary_in_any_writer() {
    let record = sample_run_record();
    let writers = all_writers();
    assert!(!writers.is_empty(), "expected registered writers");

    for writer in &writers {
        let mut buf = Vec::new();
        writer.write(&record, &mut buf).expect("write failed");
        let output = String::from_utf8(buf).expect("utf8 report");

        for rec in &record.registry.records {
            for secret in &rec.secrets {
                assert!(
                    !output.contains(&secret.value),
                    "writer '{}' leaked raw canary secret '{}':\n{}",
                    writer.name(),
                    secret.value,
                    output
                );
            }
        }
    }
}

#[test]
fn p1_seed_03_seed_in_every_writer() {
    let record = sample_run_record();
    let seed_hex = record.seed.to_string();
    let writers: Vec<_> = all_writers().into_iter().filter(|w| w.name() != "github").collect();
    assert!(!writers.is_empty(), "expected registered writers");

    for writer in &writers {
        let mut buf = Vec::new();
        writer.write(&record, &mut buf).expect("write failed");
        let output = String::from_utf8(buf).expect("utf8 report");

        assert!(
            output.contains(&seed_hex),
            "writer '{}' missing seed hex {}",
            writer.name(),
            seed_hex
        );

        if writer.name() == "console" {
            let expected_line =
                format!("mcp-gate: seed {seed_hex} (replay with --seed {seed_hex})");
            let line_found = output.lines().any(|l| l.trim() == expected_line);
            assert!(
                line_found,
                "console output must match expected seed replay line, got:\n{output}"
            );
        }
    }
}

#[test]
fn claim_sentence_in_every_writer() {
    let record = sample_run_record();
    let writers: Vec<_> = all_writers().into_iter().filter(|w| w.name() != "github").collect();
    assert!(!writers.is_empty(), "expected registered writers");

    for writer in &writers {
        let mut buf = Vec::new();
        writer.write(&record, &mut buf).expect("write failed");
        let output = String::from_utf8(buf).expect("utf8 report");

        assert!(
            output.contains(CLAIM_SENTENCE),
            "writer '{}' missing claim sentence:\n{}",
            writer.name(),
            output
        );
    }
}

#[test]
fn p1_seed_05_same_findings_rendered_with_two_different_seeds() {
    let seed1: Seed = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        .parse()
        .unwrap();
    let seed2: Seed = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        .parse()
        .unwrap();

    let violations = vec![(
        "MCPG005".to_string(),
        "Tool call resolved path outside policy: /etc/passwd".to_string(),
    )];

    let reg1 = CanaryRegistry::new();
    let reg2 = CanaryRegistry::new();

    let run1 = RunRecord::new(seed1, Verdict::FailSecurity, reg1, violations.clone());
    let run2 = RunRecord::new(seed2, Verdict::FailSecurity, reg2, violations);

    let writer = mcpg_report::SarifWriter;
    let mut out1 = Vec::new();
    let mut out2 = Vec::new();

    writer.write(&run1, &mut out1).expect("write run1");
    writer.write(&run2, &mut out2).expect("write run2");

    let j1: serde_json::Value = serde_json::from_slice(&out1).expect("valid sarif 1");
    let j2: serde_json::Value = serde_json::from_slice(&out2).expect("valid sarif 2");

    assert_eq!(
        j1["runs"][0]["results"][0]["message"]["text"],
        j2["runs"][0]["results"][0]["message"]["text"]
    );
    assert_eq!(
        j1["runs"][0]["results"][0]["partialFingerprints"],
        j2["runs"][0]["results"][0]["partialFingerprints"]
    );
    assert_ne!(
        j1["runs"][0]["invocations"][0]["properties"]["seed"],
        j2["runs"][0]["invocations"][0]["properties"]["seed"]
    );
}
