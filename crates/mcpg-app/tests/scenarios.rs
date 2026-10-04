use mcpg_app::scenario::{check, CallOutcome, Expect, OutcomeKind};
use mcpg_domain::verdict::ExitCode;

#[test]
fn success_outcome_matches() {
    let expect = Expect {
        outcome: Some("success".to_string()),
        content_contains: vec![],
        content_not_contains: vec![],
    };
    let outcome = CallOutcome::success("operation completed");
    let res = check(&expect, &outcome);

    assert!(res.passed);
    assert_eq!(res.exit_code, ExitCode::Pass);
    assert!(res.reason.is_none());
}

#[test]
fn is_error_true_maps_to_tool_error() {
    let outcome = CallOutcome::from_tool_result(true, "file not found error");
    assert_eq!(outcome.kind, OutcomeKind::ToolError);

    let expect = Expect {
        outcome: Some("tool_error".to_string()),
        content_contains: vec!["not found".to_string()],
        content_not_contains: vec![],
    };
    let res = check(&expect, &outcome);
    assert!(res.passed);
    assert_eq!(res.exit_code, ExitCode::Pass);
}

#[test]
fn jsonrpc_error_maps_to_protocol_error() {
    let outcome = CallOutcome::from_jsonrpc_error("Internal JSON-RPC error -32603");
    assert_eq!(outcome.kind, OutcomeKind::ProtocolError);

    let expect = Expect {
        outcome: Some("protocol_error".to_string()),
        content_contains: vec!["-32603".to_string()],
        content_not_contains: vec![],
    };
    let res = check(&expect, &outcome);
    assert!(res.passed);
    assert_eq!(res.exit_code, ExitCode::Pass);
}

#[test]
fn content_contains_and_not_contains() {
    let outcome = CallOutcome::success("welcome user: alice; status: active");

    // Both pass
    let expect_ok = Expect {
        outcome: Some("success".to_string()),
        content_contains: vec!["alice".to_string(), "active".to_string()],
        content_not_contains: vec!["password".to_string(), "token".to_string()],
    };
    let res_ok = check(&expect_ok, &outcome);
    assert!(res_ok.passed);

    // Missing substring in contains fails
    let expect_missing = Expect {
        outcome: Some("success".to_string()),
        content_contains: vec!["bob".to_string()],
        content_not_contains: vec![],
    };
    let res_missing = check(&expect_missing, &outcome);
    assert!(!res_missing.passed);
    assert_eq!(res_missing.exit_code, ExitCode::FailFunctional);

    // Forbidden substring present in not_contains fails
    let expect_forbidden = Expect {
        outcome: Some("success".to_string()),
        content_contains: vec![],
        content_not_contains: vec!["alice".to_string()],
    };
    let res_forbidden = check(&expect_forbidden, &outcome);
    assert!(!res_forbidden.passed);
    assert_eq!(res_forbidden.exit_code, ExitCode::FailFunctional);
}

#[test]
fn failed_expectation_yields_fail_functional() {
    let expect = Expect {
        outcome: Some("success".to_string()),
        content_contains: vec![],
        content_not_contains: vec![],
    };
    let outcome = CallOutcome::tool_error("disk full");
    let res = check(&expect, &outcome);

    assert!(!res.passed);
    assert_eq!(res.exit_code, ExitCode::FailFunctional);
    assert_eq!(res.exit_code.as_i32(), 2);
    let reason = res.reason.expect("failure reason must be recorded");
    assert!(reason.contains("outcome mismatch"));
}
