use mcpg_domain::canary::registry::CanaryRegistry;
use mcpg_domain::seed::Seed;
use mcpg_domain::verdict::Verdict;
use mcpg_report::{ReportWriter, RunRecord, SarifWriter};

fn test_record(violations: Vec<(String, String)>) -> RunRecord {
    let seed: Seed = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        .parse()
        .unwrap();
    RunRecord::new(
        seed,
        Verdict::FailSecurity,
        CanaryRegistry::new(),
        violations,
    )
}

fn render_sarif(record: &RunRecord) -> serde_json::Value {
    let mut out = Vec::new();
    SarifWriter.write(record, &mut out).expect("write sarif");
    serde_json::from_slice(&out).expect("valid json")
}

#[test]
fn p4_sarif_01_output_validates_sarif_structure() {
    let rec = test_record(vec![("MCPG005".to_string(), "Escape".to_string())]);
    let doc = render_sarif(&rec);

    assert_eq!(doc["version"], "2.1.0");
    assert_eq!(
        doc["$schema"],
        "https://json.schemastore.org/sarif-2.1.0.json"
    );
    assert_eq!(doc["runs"][0]["tool"]["driver"]["name"], "mcp-gate");
    assert_eq!(doc["runs"][0]["tool"]["driver"]["semanticVersion"], "1.0.0");
}

#[test]
fn p4_sarif_02_sarif_multitool_compliance() {
    let rec = test_record(vec![("MCPG001".to_string(), "Canary access".to_string())]);
    let doc = render_sarif(&rec);

    let run = &doc["runs"][0];
    assert!(run["invocations"].is_array());
    assert!(run["results"].is_array());
    assert!(run["tool"]["driver"]["rules"].is_array());
}

#[test]
fn p4_sarif_03_physical_location_srcroot() {
    let rec = test_record(vec![("MCPG003".to_string(), "Read outside".to_string())]);
    let doc = render_sarif(&rec);

    let res = &doc["runs"][0]["results"][0];
    let loc = &res["locations"][0]["physicalLocation"];
    assert_eq!(loc["artifactLocation"]["uri"], "mcp-gate.yaml");
    assert_eq!(loc["artifactLocation"]["uriBaseId"], "SRCROOT");
}

#[test]
fn p4_sarif_04_rule_id_exists_in_driver_rules_and_rule_index() {
    let rec = test_record(vec![
        ("MCPG001".to_string(), "Canary".to_string()),
        ("MCPG005".to_string(), "Escape".to_string()),
    ]);
    let doc = render_sarif(&rec);

    let rules = doc["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .unwrap();
    let results = doc["runs"][0]["results"].as_array().unwrap();

    for res in results {
        let rule_id = res["ruleId"].as_str().unwrap();
        let rule_idx = res["ruleIndex"].as_u64().unwrap() as usize;

        assert_eq!(rules[rule_idx]["id"], rule_id);
    }
}

#[test]
fn p4_sarif_05_security_severity_numeric_string() {
    let rec = test_record(vec![]);
    let doc = render_sarif(&rec);

    let rules = doc["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .unwrap();
    for rule in rules {
        let sev_val = &rule["properties"]["security-severity"];
        assert!(
            sev_val.is_string(),
            "rule {} missing security-severity string",
            rule["id"]
        );
        let sev: f64 = sev_val.as_str().unwrap().parse().expect("valid float");
        assert!((0.0..=10.0).contains(&sev));
    }
}

#[test]
fn p4_sarif_06_region_start_line_points_to_config() {
    let rec = test_record(vec![("MCPG006".to_string(), "Subprocess".to_string())]);
    let doc = render_sarif(&rec);

    let res = &doc["runs"][0]["results"][0];
    let line = res["locations"][0]["physicalLocation"]["region"]["startLine"]
        .as_u64()
        .unwrap();
    assert!(line >= 1);
}

#[test]
fn p4_sarif_07_result_truncation_limits() {
    let mut violations = Vec::new();
    for i in 0..6000 {
        violations.push(("MCPG001".to_string(), format!("Violation {i}")));
    }
    let rec = test_record(violations);
    let doc = render_sarif(&rec);

    let results = doc["runs"][0]["results"].as_array().unwrap();
    assert_eq!(results.len(), 5000);

    let notifs = doc["runs"][0]["invocations"][0]["toolExecutionNotifications"]
        .as_array()
        .unwrap();
    assert_eq!(notifs.len(), 1);
    assert!(notifs[0]["message"]["text"]
        .as_str()
        .unwrap()
        .contains("truncated"));
}

#[test]
fn p4_sarif_08_byte_identical_with_source_date_epoch_and_seed() {
    let rec1 = test_record(vec![("MCPG005".to_string(), "Escape".to_string())]);
    let rec2 = test_record(vec![("MCPG005".to_string(), "Escape".to_string())]);

    let mut out1 = Vec::new();
    let mut out2 = Vec::new();

    SarifWriter.write(&rec1, &mut out1).unwrap();
    SarifWriter.write(&rec2, &mut out2).unwrap();

    assert_eq!(out1, out2);
}

#[test]
fn p4_sarif_09_zero_findings_valid_empty_results() {
    let seed: Seed = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        .parse()
        .unwrap();
    let rec = RunRecord::new(seed, Verdict::Pass, CanaryRegistry::new(), vec![]);
    let doc = render_sarif(&rec);

    let results = doc["runs"][0]["results"].as_array().unwrap();
    assert!(results.is_empty());
}
