use mcpg_domain::canary::registry::CanaryRegistry;
use mcpg_domain::seed::Seed;
use mcpg_domain::verdict::Verdict;
use mcpg_report::{all_writers, JunitWriter, ReportWriter, RunRecord, SarifWriter};

#[test]
fn sarif_writer_renders_valid_json_structure() {
    let seed: Seed = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        .parse()
        .unwrap();
    let registry = CanaryRegistry::new();
    let violations = vec![(
        "MCPG005".to_string(),
        "Tool call resolved path outside policy: /etc/passwd".to_string(),
    )];

    let run = RunRecord::new(seed, Verdict::FailSecurity, registry, violations);
    let writer = SarifWriter;
    let mut out = Vec::new();
    writer.write(&run, &mut out).expect("write sarif");

    let text = String::from_utf8(out).expect("utf8");
    let json: serde_json::Value = serde_json::from_str(&text).expect("valid json sarif");

    assert_eq!(json["version"], "2.1.0");
    assert_eq!(json["runs"][0]["tool"]["driver"]["name"], "mcp-gate");
    assert_eq!(
        json["runs"][0]["invocations"][0]["properties"]["verdict"],
        "FAIL_SECURITY"
    );
    assert_eq!(json["runs"][0]["results"][0]["ruleId"], "MCPG005");
}

#[test]
fn junit_writer_renders_valid_xml_structure() {
    let seed: Seed = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        .parse()
        .unwrap();
    let registry = CanaryRegistry::new();
    let violations = vec![(
        "MCPG001".to_string(),
        "Canary secret accessed in decoy zone".to_string(),
    )];

    let run = RunRecord::new(seed, Verdict::FailSecurity, registry, violations);
    let writer = JunitWriter;
    let mut out = Vec::new();
    writer.write(&run, &mut out).expect("write junit");

    let text = String::from_utf8(out).expect("utf8");
    assert!(text.contains("<testsuites name=\"mcp-gate\""));
    assert!(text.contains("<property name=\"verdict\" value=\"FAIL_SECURITY\"/>"));
    assert!(text.contains("type=\"MCPG001\""));
}

#[test]
fn all_writers_includes_all_five_writers() {
    let writers = all_writers();
    let names: Vec<&str> = writers.iter().map(|w| w.name()).collect();
    assert!(names.contains(&"console"));
    assert!(names.contains(&"evidence"));
    assert!(names.contains(&"sarif"));
    assert!(names.contains(&"junit"));
    assert!(names.contains(&"github"));
}

#[test]
fn github_writer_renders_annotations_and_summary() {
    let seed: mcpg_domain::seed::Seed =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
            .parse()
            .unwrap();
    let registry = mcpg_domain::canary::registry::CanaryRegistry::new();
    let violations = vec![(
        "MCPG005".to_string(),
        "Tool call resolved path outside policy: /etc/passwd".to_string(),
    )];

    let run = mcpg_report::RunRecord::new(
        seed,
        mcpg_domain::verdict::Verdict::FailSecurity,
        registry,
        violations,
    );

    // We set a fake GITHUB_STEP_SUMMARY path
    let summary_dir = std::env::temp_dir();
    let summary_path = summary_dir.join(format!("step_summary_{}.md", std::process::id()));
    std::env::set_var("GITHUB_STEP_SUMMARY", &summary_path);
    std::env::set_var("GITHUB_ACTIONS", "true");

    let writer = mcpg_report::github::GithubWriter;
    let mut out = Vec::new();
    writer
        .write(&run, &mut out)
        .expect("write github annotations");

    let text = String::from_utf8(out).expect("utf8");
    assert!(text.contains("::error file=mcp-gate.yaml,title=MCPG005::Tool call resolved path outside policy: /etc/passwd"));

    let summary = std::fs::read_to_string(&summary_path).expect("read summary");
    assert!(summary.contains("mcp-gate: FAIL_SECURITY"));
    assert!(summary.contains("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));

    std::fs::remove_file(summary_path).ok();
    std::env::remove_var("GITHUB_STEP_SUMMARY");
    std::env::remove_var("GITHUB_ACTIONS");
}
