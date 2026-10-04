use std::str::FromStr;

use mcpg_domain::canary::catalogue::all_catalogue_entries;
use mcpg_domain::canary::registry::{CanaryRecord, CanaryRegistry};
use mcpg_domain::canary::render::{plan, Secret};
use mcpg_domain::seed::Seed;
use mcpg_domain::verdict::Verdict;
use mcpg_report::{all_writers, RunRecord, CLAIM_SENTENCE};

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

    RunRecord::new(seed, Verdict::Pass, registry)
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
    let writers = all_writers();
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
    let writers = all_writers();
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
