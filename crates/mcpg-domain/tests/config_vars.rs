use std::path::PathBuf;

use mcpg_domain::config::vars::{expand, VarError, VarTable};

fn test_vars() -> VarTable {
    VarTable {
        workspace: PathBuf::from("/capsule/workspace"),
        capsule_home: PathBuf::from("/capsule/home"),
        capsule_tmp: PathBuf::from("/capsule/tmp"),
        config_dir: PathBuf::from("/repo/project"),
    }
}

#[test]
fn p1_cfg_03_var_mid_path_rejected() {
    let vars = test_vars();
    let err = expand("/a/${WORKSPACE}/b", &vars).expect_err("var in middle of path must fail");
    assert!(
        matches!(err, VarError::VariableNotAtStart(_)),
        "expected VariableNotAtStart, got: {:?}",
        err
    );

    let err2 =
        expand("${WORKSPACE}/${CAPSULE_TMP}", &vars).expect_err("multiple vars in path must fail");
    assert!(
        matches!(err2, VarError::VariableNotAtStart(_)),
        "expected VariableNotAtStart, got: {:?}",
        err2
    );
}

#[test]
fn expands_workspace_prefix() {
    let vars = test_vars();

    let res = expand("${WORKSPACE}", &vars).expect("expand ${WORKSPACE}");
    assert_eq!(res, PathBuf::from("/capsule/workspace"));

    let res2 = expand("${WORKSPACE}/notes", &vars).expect("expand ${WORKSPACE}/notes");
    assert_eq!(res2, PathBuf::from("/capsule/workspace/notes"));

    let res_home = expand("${CAPSULE_HOME}/.ssh", &vars).expect("expand ${CAPSULE_HOME}");
    assert_eq!(res_home, PathBuf::from("/capsule/home/.ssh"));

    let res_tmp = expand("${CAPSULE_TMP}/scratch", &vars).expect("expand ${CAPSULE_TMP}");
    assert_eq!(res_tmp, PathBuf::from("/capsule/tmp/scratch"));

    let res_cfg = expand("${CONFIG_DIR}/server.py", &vars).expect("expand ${CONFIG_DIR}");
    assert_eq!(res_cfg, PathBuf::from("/repo/project/server.py"));
}

#[test]
fn unknown_var_rejected() {
    let vars = test_vars();
    let err = expand("${HOME}/foo", &vars).expect_err("unknown variable ${HOME} must fail");
    assert_eq!(err, VarError::UnknownVariable("HOME".to_string()));

    let err2 = expand("${USER}", &vars).expect_err("unknown variable ${USER} must fail");
    assert_eq!(err2, VarError::UnknownVariable("USER".to_string()));
}

#[test]
fn no_host_env_interpolation() {
    let vars = test_vars();
    let err = expand("$PATH", &vars).expect_err("$PATH must not interpolate host env");
    assert_eq!(err, VarError::NotAbsolute(PathBuf::from("$PATH")));

    let literal_abs = expand("/usr/bin/git", &vars).expect("valid absolute path");
    assert_eq!(literal_abs, PathBuf::from("/usr/bin/git"));
}

#[test]
fn var_error_display() {
    let e1 = VarError::VariableNotAtStart("/foo/${BAR}".into());
    assert_eq!(e1.to_string(), "variable not at start of path: /foo/${BAR}");

    let e2 = VarError::UnknownVariable("UNKNOWN".into());
    assert_eq!(e2.to_string(), "unknown variable: UNKNOWN");

    let e3 = VarError::UnclosedVariable("${WORKSPACE".into());
    assert_eq!(e3.to_string(), "unclosed variable in path: ${WORKSPACE");

    let e4 = VarError::NotAbsolute(PathBuf::from("relative/path"));
    assert_eq!(e4.to_string(), "path is not absolute: relative/path");
}
