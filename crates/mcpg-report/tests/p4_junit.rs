use mcpg_domain::canary::registry::CanaryRegistry;
use mcpg_domain::seed::Seed;
use mcpg_domain::verdict::Verdict;
use mcpg_report::{JunitWriter, ReportWriter, RunRecord};
use proptest::prelude::*;

fn make_record(violations: Vec<(String, String)>) -> RunRecord {
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

fn render_junit(record: &RunRecord) -> String {
    let mut out = Vec::new();
    JunitWriter.write(record, &mut out).expect("write junit");
    String::from_utf8(out).expect("utf8")
}

#[test]
fn p4_junit_01_valid_xml_structure() {
    let rec = make_record(vec![("MCPG001".to_string(), "Canary access".to_string())]);
    let xml = render_junit(&rec);

    assert!(xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
    assert!(xml.contains("<testsuites name=\"mcp-gate\""));
    assert!(xml.contains("<testsuite name=\"mcp-gate\""));
    assert!(xml.contains("</testsuite>"));
    assert!(xml.ends_with("</testsuites>\n") || xml.ends_with("</testsuites>"));
}

#[test]
fn p4_junit_02_counts_match_child_elements() {
    let violations = vec![
        ("MCPG001".to_string(), "v1".to_string()),
        ("MCPG005".to_string(), "v2".to_string()),
        ("MCPG007".to_string(), "v3".to_string()),
    ];
    let rec = make_record(violations);
    let xml = render_junit(&rec);

    let testcase_count = xml.matches("<testcase ").count();
    let failure_count = xml.matches("<failure ").count();

    // In JunitWriter: tests = 1 (lifecycle) + failures_count
    assert_eq!(testcase_count, 4);
    assert_eq!(failure_count, 3);

    assert!(xml.contains("tests=\"4\""));
    assert!(xml.contains("failures=\"3\""));
}

#[test]
fn p4_junit_03_xml_special_characters_escaped() {
    let weird_detail = "Special chars: <script> alert(\"xss\" & 'foo'); </script>";
    let rec = make_record(vec![("MCPG005".to_string(), weird_detail.to_string())]);
    let xml = render_junit(&rec);

    assert!(!xml.contains("<script>"));
    assert!(xml.contains("&lt;script&gt;"));
    assert!(xml.contains("&amp;"));
    assert!(xml.contains("&quot;xss&quot;"));
    assert!(xml.contains("&apos;foo&apos;"));
}

proptest! {
    #[test]
    fn p4_junit_03_proptest_escaping(s in "\\PC*") {
        let rec = make_record(vec![("MCPG001".to_string(), s)]);
        let xml = render_junit(&rec);

        // Ensure closing and opening tags are balanced and standard XML header exists
        prop_assert!(xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
        prop_assert_eq!(xml.matches("<testsuites").count(), 1);
        prop_assert_eq!(xml.matches("</testsuites>").count(), 1);
    }
}
