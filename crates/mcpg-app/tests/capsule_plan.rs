use std::ffi::{CString, OsString};
use std::path::PathBuf;

use mcpg_app::capsule_plan::{CapsulePlan, Mode, PlanError};
use mcpg_domain::config::model::{
    ClientConfig, Config, LimitsConfig, ObserveConfig, PolicyConfig, ProbesConfig, ReportConfig,
    ServerConfig, WorkspaceConfig, WorkspaceMode,
};
use mcpg_domain::config::vars::VarTable;
use mcpg_domain::env::EnvOutcome;

fn sample_config() -> Config {
    Config {
        version: 1,
        server: ServerConfig {
            name: "test-server".to_string(),
            command: "python3".to_string(),
            args: vec![],
            workspace: WorkspaceConfig {
                source: ".".to_string(),
                mode: WorkspaceMode::Copy,
                exclude: vec![],
            },
            env: Default::default(),
            protocol_versions: vec![],
            client: ClientConfig { roots: false },
        },
        policy: PolicyConfig {
            read_paths: vec![],
            write_paths: vec![],
            allowed_child_binaries: vec![],
            allowed_unix_sockets: vec![],
            allow_network: false,
            baseline: Default::default(),
        },
        canaries: Default::default(),
        observe: ObserveConfig::default(),
        probes: ProbesConfig::default(),
        scenarios: vec![],
        limits: LimitsConfig::default(),
        report: ReportConfig::default(),
    }
}

fn sample_vars() -> VarTable {
    VarTable {
        workspace: PathBuf::from("/run/mcpg-1234/workspace"),
        capsule_home: PathBuf::from("/run/mcpg-1234/home"),
        capsule_tmp: PathBuf::from("/run/mcpg-1234/tmp"),
        config_dir: PathBuf::from("/repo"),
    }
}

#[test]
fn plan_envp_is_build_env_output_in_order() {
    let cfg = sample_config();
    let vars = sample_vars();
    let outcome = EnvOutcome {
        vars: vec![
            (
                OsString::from("HOME"),
                OsString::from("/run/mcpg-1234/home"),
            ),
            (OsString::from("LANG"), OsString::from("C.UTF-8")),
            (
                OsString::from("PATH"),
                OsString::from("/usr/local/bin:/usr/bin:/bin"),
            ),
            (
                OsString::from("TMPDIR"),
                OsString::from("/run/mcpg-1234/tmp"),
            ),
            (OsString::from("VAR_Z"), OsString::from("final")),
        ],
        warnings: vec![],
    };

    let plan = CapsulePlan::build(&cfg, &outcome, &vars, Mode::Enforce).expect("build plan");

    assert_eq!(plan.envp.len(), 5);
    assert_eq!(
        plan.envp[0],
        CString::new("HOME=/run/mcpg-1234/home").unwrap()
    );
    assert_eq!(plan.envp[1], CString::new("LANG=C.UTF-8").unwrap());
    assert_eq!(
        plan.envp[2],
        CString::new("PATH=/usr/local/bin:/usr/bin:/bin").unwrap()
    );
    assert_eq!(
        plan.envp[3],
        CString::new("TMPDIR=/run/mcpg-1234/tmp").unwrap()
    );
    assert_eq!(plan.envp[4], CString::new("VAR_Z=final").unwrap());
}

#[test]
fn plan_argv_has_vars_expanded() {
    let mut cfg = sample_config();
    cfg.server.command = "python3".to_string();
    cfg.server.args = vec![
        "${WORKSPACE}/server.py".to_string(),
        "--data-dir".to_string(),
        "${CAPSULE_HOME}/.config".to_string(),
        "--temp".to_string(),
        "${CAPSULE_TMP}/scratch".to_string(),
    ];
    let vars = sample_vars();
    let outcome = EnvOutcome {
        vars: vec![],
        warnings: vec![],
    };

    let plan = CapsulePlan::build(&cfg, &outcome, &vars, Mode::Enforce).expect("build plan");

    assert_eq!(plan.program, CString::new("python3").unwrap());
    assert_eq!(plan.argv.len(), 6);
    assert_eq!(plan.argv[0], CString::new("python3").unwrap());
    assert_eq!(
        plan.argv[1],
        CString::new("/run/mcpg-1234/workspace/server.py").unwrap()
    );
    assert_eq!(plan.argv[2], CString::new("--data-dir").unwrap());
    assert_eq!(
        plan.argv[3],
        CString::new("/run/mcpg-1234/home/.config").unwrap()
    );
    assert_eq!(plan.argv[4], CString::new("--temp").unwrap());
    assert_eq!(
        plan.argv[5],
        CString::new("/run/mcpg-1234/tmp/scratch").unwrap()
    );
}

#[test]
fn plan_cwd_is_prepared_workspace() {
    let cfg = sample_config();
    let vars = sample_vars();
    let outcome = EnvOutcome {
        vars: vec![],
        warnings: vec![],
    };

    let plan = CapsulePlan::build(&cfg, &outcome, &vars, Mode::Observe).expect("build plan");

    assert_eq!(plan.cwd, vars.workspace);
    assert_eq!(plan.mode, Mode::Observe);
}

#[test]
fn plan_rejects_interior_nul() {
    let mut cfg = sample_config();
    cfg.server.args = vec!["arg1\0evil".to_string()];
    let vars = sample_vars();
    let outcome = EnvOutcome {
        vars: vec![],
        warnings: vec![],
    };

    let err =
        CapsulePlan::build(&cfg, &outcome, &vars, Mode::Enforce).expect_err("should reject NUL");
    match err {
        PlanError::InteriorNul(_) => {}
        other => panic!("expected InteriorNul error, got: {other:?}"),
    }
}
