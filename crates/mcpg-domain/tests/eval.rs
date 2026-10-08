use mcpg_domain::canary::catalogue::CanaryKind;
use mcpg_domain::canary::registry::{CanaryRecord, CanaryRegistry};
use mcpg_domain::evaluator::{evaluate, EvalContext, FindingLevel};
use mcpg_domain::event::{AccessKind, Event, EventKind};
use mcpg_domain::policy::resolve::ResolvedPolicy;
use std::path::PathBuf;

fn dummy_policy() -> ResolvedPolicy {
    ResolvedPolicy {
        read_paths: vec![mcpg_domain::policy::resolve::PathEntry::Dir(PathBuf::from(
            "/workspace",
        ))],
        write_paths: vec![mcpg_domain::policy::resolve::PathEntry::Dir(PathBuf::from(
            "/workspace/out",
        ))],
        allowed_child_binaries: vec![PathBuf::from("/usr/bin/git")],
        baseline_paths: vec![],
        capsule_tmp: PathBuf::from("/tmp/mcpg-1234/tmp"),
        allow_network: false,
        allowed_unix_sockets: vec!["/tmp/allowed.sock".to_string()],
        to_create: vec![],
    }
}

fn dummy_context() -> EvalContext {
    EvalContext {
        server_name: "test-server".to_string(),
        run_dir: PathBuf::from("/tmp/mcpg-1234"),
        declared_use: vec![],
        scenario_allowances: std::collections::HashMap::new(),
        tool_call_arguments: None,
    }
}

#[test]
fn p1_eval_01_each_rule_fires() {
    let policy = dummy_policy();
    let registry = CanaryRegistry::new();
    let ctx = dummy_context();

    // 1. leak.match -> MCPG002
    let leak_ev = Event::builder(EventKind::LeakMatch, "scenario:test")
        .message("canary leak found")
        .build();
    let findings = evaluate(&[leak_ev], &policy, &registry, &ctx);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "MCPG002");
    assert_eq!(findings[0].level, FindingLevel::Error);

    // 3. proc:foreign:* -> MCPG008
    let foreign_ev = Event::builder(EventKind::FsOpen, "startup")
        .resolved(PathBuf::from("proc:foreign:999/environ"))
        .build();
    let findings = evaluate(&[foreign_ev], &policy, &registry, &ctx);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "MCPG008");

    // 4. fs.open read outside policy -> MCPG003
    let read_ev = Event::builder(EventKind::FsOpen, "startup")
        .resolved(PathBuf::from("/etc/shadow"))
        .access(AccessKind::Read)
        .build();
    let findings = evaluate(&[read_ev], &policy, &registry, &ctx);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "MCPG003");

    // 5. fs.open write outside policy -> MCPG004
    let write_ev = Event::builder(EventKind::FsOpen, "startup")
        .resolved(PathBuf::from("/workspace/evil.sh"))
        .access(AccessKind::Write)
        .build();
    let findings = evaluate(&[write_ev], &policy, &registry, &ctx);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "MCPG004");

    // 6. proc.exec unapproved binary -> MCPG006
    let exec_ev = Event::builder(EventKind::ProcExec, "startup")
        .exe(PathBuf::from("/bin/sh"))
        .build();
    let findings = evaluate(&[exec_ev], &policy, &registry, &ctx);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "MCPG006");

    // 7. net.connect while allow_network=false -> MCPG007
    let net_ev = Event::builder(EventKind::NetConnect, "startup")
        .target("127.0.0.1:8080")
        .build();
    let findings = evaluate(&[net_ev], &policy, &registry, &ctx);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "MCPG007");

    // 8. unix.connect outside allowed_unix_sockets -> MCPG009
    let unix_ev = Event::builder(EventKind::UnixConnect, "startup")
        .resolved(PathBuf::from("/var/run/docker.sock"))
        .build();
    let findings = evaluate(&[unix_ev], &policy, &registry, &ctx);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "MCPG009");

    // 9. tamper.denied -> MCPG010
    let tamper_ev = Event::builder(EventKind::TamperDenied, "startup").build();
    let findings = evaluate(&[tamper_ev], &policy, &registry, &ctx);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "MCPG010");

    // 10. fs.stat sensitive path -> MCPG011
    let stat_ev = Event::builder(EventKind::FsStat, "startup")
        .resolved(PathBuf::from("/tmp/mcpg-1234/home/.ssh"))
        .build();
    let findings = evaluate(&[stat_ev], &policy, &registry, &ctx);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "MCPG011");

    // 11. proc.orphan -> MCPG012
    let orphan_ev = Event::builder(EventKind::ProcOrphan, "shutdown").build();
    let findings = evaluate(&[orphan_ev], &policy, &registry, &ctx);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "MCPG012");
}

#[test]
fn p1_eval_02_canary_beats_out_of_policy_read() {
    let policy = dummy_policy();
    let mut registry = CanaryRegistry::new();
    let canary_path = PathBuf::from("/tmp/mcpg-1234/home/.ssh/id_ed25519");
    registry.records.push(CanaryRecord {
        id: "canary-ssh".to_string(),
        kind: CanaryKind::Ssh,
        tier: mcpg_domain::canary::catalogue::CanaryTier::A,
        path: canary_path.clone(),
        dev: 1,
        ino: 100,
        fp: "fingerprint12".to_string(),
        secrets: vec![],
    });
    let ctx = dummy_context();

    // Event is an fs.open on a path outside policy that ALSO matches a canary file
    let ev = Event::builder(EventKind::FsOpen, "startup")
        .resolved(canary_path)
        .access(AccessKind::Read)
        .dev_ino(1, 100)
        .build();

    let findings = evaluate(&[ev], &policy, &registry, &ctx);
    // Should produce only MCPG001, not MCPG003 (first match wins)
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "MCPG001");
}

#[test]
fn p1_eval_03_tier_b_canary_access_warning() {
    let policy = dummy_policy();
    let mut registry = CanaryRegistry::new();
    let netrc_path = PathBuf::from("/tmp/mcpg-1234/home/.netrc");
    registry.records.push(CanaryRecord {
        id: "canary-netrc".to_string(),
        kind: CanaryKind::Netrc,
        tier: mcpg_domain::canary::catalogue::CanaryTier::B,
        path: netrc_path.clone(),
        dev: 1,
        ino: 101,
        fp: "fingerprint12".to_string(),
        secrets: vec![],
    });
    let ctx = dummy_context();

    let ev = Event::builder(EventKind::FsOpen, "startup")
        .resolved(netrc_path)
        .access(AccessKind::Read)
        .dev_ino(1, 101)
        .build();

    let findings = evaluate(&[ev], &policy, &registry, &ctx);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "MCPG001");
    assert_eq!(findings[0].level, FindingLevel::Warning);
}

#[test]
fn p1_eval_04_declared_use_yields_note() {
    let policy = dummy_policy();
    let mut registry = CanaryRegistry::new();
    let aws_path = PathBuf::from("/tmp/mcpg-1234/home/.aws/credentials");
    registry.records.push(CanaryRecord {
        id: "canary-aws".to_string(),
        kind: CanaryKind::Aws,
        tier: mcpg_domain::canary::catalogue::CanaryTier::A,
        path: aws_path.clone(),
        dev: 1,
        ino: 102,
        fp: "fingerprint12".to_string(),
        secrets: vec![],
    });

    let mut ctx = dummy_context();
    ctx.declared_use.push(CanaryKind::Aws);

    let ev = Event::builder(EventKind::FsOpen, "startup")
        .resolved(aws_path)
        .access(AccessKind::Read)
        .dev_ino(1, 102)
        .build();

    let findings = evaluate(&[ev], &policy, &registry, &ctx);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "MCPG001");
    assert_eq!(findings[0].level, FindingLevel::Note);
}

#[test]
fn p1_eval_04a_scenario_allow_access_yields_note() {
    let policy = dummy_policy();
    let mut registry = CanaryRegistry::new();
    let ssh_path = PathBuf::from("/tmp/mcpg-1234/home/.ssh/id_ed25519");
    registry.records.push(CanaryRecord {
        id: "canary-ssh".to_string(),
        kind: CanaryKind::Ssh,
        tier: mcpg_domain::canary::catalogue::CanaryTier::A,
        path: ssh_path.clone(),
        dev: 1,
        ino: 103,
        fp: "fingerprint12".to_string(),
        secrets: vec![],
    });

    let mut ctx = dummy_context();
    ctx.scenario_allowances
        .insert("sign-note".to_string(), vec![CanaryKind::Ssh]);

    // Access in phase scenario:sign-note
    let ev = Event::builder(EventKind::FsOpen, "scenario:sign-note")
        .resolved(ssh_path)
        .access(AccessKind::Read)
        .dev_ino(1, 103)
        .build();

    let findings = evaluate(&[ev], &policy, &registry, &ctx);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "MCPG001");
    assert_eq!(findings[0].level, FindingLevel::Note);
}

#[test]
fn p1_eval_04b_unallowed_phase_yields_error() {
    let policy = dummy_policy();
    let mut registry = CanaryRegistry::new();
    let ssh_path = PathBuf::from("/tmp/mcpg-1234/home/.ssh/id_ed25519");
    registry.records.push(CanaryRecord {
        id: "canary-ssh".to_string(),
        kind: CanaryKind::Ssh,
        tier: mcpg_domain::canary::catalogue::CanaryTier::A,
        path: ssh_path.clone(),
        dev: 1,
        ino: 103,
        fp: "fingerprint12".to_string(),
        secrets: vec![],
    });

    let mut ctx = dummy_context();
    ctx.scenario_allowances
        .insert("sign-note".to_string(), vec![CanaryKind::Ssh]);

    // Same canary, but in startup phase
    let ev = Event::builder(EventKind::FsOpen, "startup")
        .resolved(ssh_path)
        .access(AccessKind::Read)
        .dev_ino(1, 103)
        .build();

    let findings = evaluate(&[ev], &policy, &registry, &ctx);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "MCPG001");
    assert_eq!(findings[0].level, FindingLevel::Error);
}

#[test]
fn p1_eval_04c_leak_of_allowed_canary_is_error() {
    let policy = dummy_policy();
    let mut registry = CanaryRegistry::new();
    registry.records.push(CanaryRecord {
        id: "canary-ssh".to_string(),
        kind: CanaryKind::Ssh,
        tier: mcpg_domain::canary::catalogue::CanaryTier::A,
        path: PathBuf::from("/tmp/mcpg-1234/home/.ssh/id_ed25519"),
        dev: 1,
        ino: 103,
        fp: "fingerprint12".to_string(),
        secrets: vec![],
    });

    let mut ctx = dummy_context();
    ctx.scenario_allowances
        .insert("sign-note".to_string(), vec![CanaryKind::Ssh]);

    // Leak event during scenario:sign-note
    let ev = Event::builder(EventKind::LeakMatch, "scenario:sign-note")
        .canary_kind(CanaryKind::Ssh)
        .message("Leaked SSH secret")
        .build();

    let findings = evaluate(&[ev], &policy, &registry, &ctx);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "MCPG002");
    assert_eq!(findings[0].level, FindingLevel::Error);
}

#[test]
fn p1_eval_05_identical_events_deduplicated() {
    let policy = dummy_policy();
    let registry = CanaryRegistry::new();
    let ctx = dummy_context();

    let mut events = Vec::new();
    for _ in 0..500 {
        events.push(
            Event::builder(EventKind::FsOpen, "startup")
                .resolved(PathBuf::from("/etc/passwd"))
                .access(AccessKind::Read)
                .build(),
        );
    }

    let findings = evaluate(&events, &policy, &registry, &ctx);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].occurrences, 500);
}

#[test]
fn p1_eval_06_stable_fingerprints_across_runs() {
    let policy = dummy_policy();
    let registry = CanaryRegistry::new();

    let ctx1 = EvalContext {
        server_name: "srv".to_string(),
        run_dir: PathBuf::from("/tmp/mcpg-run1"),
        declared_use: vec![],
        scenario_allowances: std::collections::HashMap::new(),
        tool_call_arguments: None,
    };

    let ctx2 = EvalContext {
        server_name: "srv".to_string(),
        run_dir: PathBuf::from("/tmp/mcpg-run2"),
        declared_use: vec![],
        scenario_allowances: std::collections::HashMap::new(),
        tool_call_arguments: None,
    };

    let ev1 = Event::builder(EventKind::FsOpen, "startup")
        .pid(1111)
        .resolved(PathBuf::from("/tmp/mcpg-run1/home/.ssh/id_ed25519"))
        .access(AccessKind::Read)
        .build();

    let ev2 = Event::builder(EventKind::FsOpen, "startup")
        .pid(2222)
        .resolved(PathBuf::from("/tmp/mcpg-run2/home/.ssh/id_ed25519"))
        .access(AccessKind::Read)
        .build();

    let findings1 = evaluate(&[ev1], &policy, &registry, &ctx1);
    let findings2 = evaluate(&[ev2], &policy, &registry, &ctx2);

    assert_eq!(findings1.len(), 1);
    assert_eq!(findings2.len(), 1);
    assert_eq!(findings1[0].fingerprint, findings2[0].fingerprint);
    assert_eq!(
        findings1[0].normalized_target,
        "<CAPSULE>/home/.ssh/id_ed25519"
    );
    assert_eq!(
        findings2[0].normalized_target,
        "<CAPSULE>/home/.ssh/id_ed25519"
    );
}

#[test]
fn p1_eval_07_deterministic_sorting() {
    let policy = dummy_policy();
    let registry = CanaryRegistry::new();
    let ctx = dummy_context();

    let ev_tamper = Event::builder(EventKind::TamperDenied, "startup").build();
    let ev_read1 = Event::builder(EventKind::FsOpen, "startup")
        .resolved(PathBuf::from("/etc/a"))
        .access(AccessKind::Read)
        .build();
    let ev_read2 = Event::builder(EventKind::FsOpen, "startup")
        .resolved(PathBuf::from("/etc/b"))
        .access(AccessKind::Read)
        .build();

    let findings_a = evaluate(
        &[ev_tamper.clone(), ev_read1.clone(), ev_read2.clone()],
        &policy,
        &registry,
        &ctx,
    );
    let findings_b = evaluate(&[ev_read2, ev_tamper, ev_read1], &policy, &registry, &ctx);

    assert_eq!(findings_a, findings_b);
}
