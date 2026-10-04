use mcpg_app::phase::{Phase, PhaseCursor, PhaseError};

#[test]
fn phases_advance_in_order() {
    let cursor = PhaseCursor::new();
    assert_eq!(cursor.current(), Phase::Startup);
    assert_eq!(cursor.current().to_string(), "startup");

    cursor
        .advance_to_handshake()
        .expect("advance to handshake should succeed");
    assert_eq!(cursor.current(), Phase::Handshake);
    assert_eq!(cursor.current().to_string(), "handshake");

    cursor
        .start_scenario("read-note")
        .expect("start scenario 1 should succeed");
    assert_eq!(cursor.current(), Phase::Scenario("read-note".to_string()));
    assert_eq!(cursor.current().to_string(), "scenario:read-note");

    cursor
        .end_scenario()
        .expect("end scenario 1 should succeed");

    cursor
        .start_scenario("write-note")
        .expect("start scenario 2 should succeed");
    assert_eq!(cursor.current(), Phase::Scenario("write-note".to_string()));
    assert_eq!(cursor.current().to_string(), "scenario:write-note");

    cursor
        .end_scenario()
        .expect("end scenario 2 should succeed");

    cursor
        .advance_to_shutdown()
        .expect("advance to shutdown should succeed");
    assert_eq!(cursor.current(), Phase::Shutdown);
    assert_eq!(cursor.current().to_string(), "shutdown");
}

#[test]
fn event_tagged_with_active_phase() {
    let cursor = PhaseCursor::new();

    let event1 = cursor.tag("disk-write-event");
    assert_eq!(event1.phase, Phase::Startup);
    assert_eq!(event1.event, "disk-write-event");

    cursor.advance_to_handshake().unwrap();
    let event2 = cursor.tag("packet-received");
    assert_eq!(event2.phase, Phase::Handshake);
    assert_eq!(event2.event, "packet-received");

    cursor.start_scenario("audit-log").unwrap();
    let event3 = cursor.tag("secret-canary-access");
    assert_eq!(event3.phase, Phase::Scenario("audit-log".to_string()));
    assert_eq!(event3.event, "secret-canary-access");
}

#[test]
fn scenarios_never_overlap() {
    let cursor = PhaseCursor::new();
    cursor
        .start_scenario("scenario-first")
        .expect("first scenario starts cleanly");

    let err = cursor
        .start_scenario("scenario-second")
        .expect_err("nested or overlapping scenario start must be rejected");

    match err {
        PhaseError::ScenarioOverlap(msg) => {
            assert!(msg.contains("scenario-second"));
            assert!(msg.contains("scenario-first"));
        }
        other => panic!("expected ScenarioOverlap, got: {other:?}"),
    }

    // After finishing the first scenario, a new scenario can start
    cursor.end_scenario().expect("first scenario ends cleanly");
    cursor
        .start_scenario("scenario-second")
        .expect("second scenario starts cleanly");
}
