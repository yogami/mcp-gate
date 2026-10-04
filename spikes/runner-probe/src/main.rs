//! Phase 0 spike: probe what an unprivileged process may do on a hosted CI
//! runner (seccomp user notifications, Landlock, inotify).
//!
//! Single-threaded on purpose. Raw `libc` calls, no abstractions. This crate
//! is deleted in Month 3 once `mcp-gate probe` covers the same ground
//! (see TASKS.md, Phase 0).
//!
//! Output is one JSON document on stdout:
//!
//! ```json
//! {"schema": "runner-probe/v1", "kernel": "...", "arch": "...", "checks": {}}
//! ```
//!
//! Each check writes `{"status": "pass"|"fail"|"info", "detail": {...}}` under
//! `checks["P0-SPIKE-NN"]`. A check that is not written yet reports
//! `"status": "not_implemented"`.

use std::ffi::CStr;
use std::process::ExitCode;

use serde_json::{json, Map, Value};

const SCHEMA: &str = "runner-probe/v1";

/// Every check the spike will eventually implement, in order.
const ALL_CHECKS: [&str; 10] = [
    "P0-SPIKE-01",
    "P0-SPIKE-02",
    "P0-SPIKE-03",
    "P0-SPIKE-04",
    "P0-SPIKE-05",
    "P0-SPIKE-06",
    "P0-SPIKE-07",
    "P0-SPIKE-08",
    "P0-SPIKE-09",
    "P0-SPIKE-10",
];

/// Which checks `--check` selected.
#[derive(Debug, PartialEq, Eq)]
enum Selection {
    None,
    All,
    One(String),
}

#[derive(Debug)]
struct Args {
    selection: Selection,
    /// Accepted for forward compatibility. `--json` is the only output format.
    json: bool,
    /// Loop count for the overhead check (P0-SPIKE-10).
    iterations: u64,
}

fn parse_args<I: Iterator<Item = String>>(mut it: I) -> Result<Args, String> {
    let mut args = Args {
        selection: Selection::All,
        json: false,
        iterations: 100_000,
    };
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--check" => {
                let v = it.next().ok_or("--check needs a value")?;
                args.selection = match v.as_str() {
                    "none" => Selection::None,
                    "all" => Selection::All,
                    id if ALL_CHECKS.contains(&id) => Selection::One(id.to_string()),
                    other => return Err(format!("unknown check: {other}")),
                };
            }
            "--json" => args.json = true,
            "--iterations" => {
                let v = it.next().ok_or("--iterations needs a value")?;
                args.iterations = v
                    .parse()
                    .map_err(|_| format!("--iterations: not a number: {v}"))?;
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    Ok(args)
}

/// `uname -r` and `uname -m` through libc, so the report needs no subprocess.
fn host_info() -> Result<(String, String), String> {
    // SAFETY: `utsname` is plain old data; zeroed is a valid initial state and
    // `uname` fills it in.
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    // SAFETY: `u` is a valid, writable `utsname`.
    if unsafe { libc::uname(&mut u) } != 0 {
        return Err(format!("uname failed: {}", std::io::Error::last_os_error()));
    }
    // SAFETY: `uname` NUL-terminates every field.
    let field = |p: &[libc::c_char]| unsafe { CStr::from_ptr(p.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    Ok((field(&u.release), field(&u.machine)))
}

/// Run one check. Checks are added here by TASK-0.3 to TASK-0.12.
fn run_check(id: &str, _args: &Args) -> Value {
    json!({ "status": "not_implemented", "detail": { "check": id } })
}

fn build_report(args: &Args) -> Result<Value, String> {
    let (kernel, arch) = host_info()?;
    let selected: Vec<&str> = match &args.selection {
        Selection::None => Vec::new(),
        Selection::All => ALL_CHECKS.to_vec(),
        Selection::One(id) => vec![id.as_str()],
    };
    let mut checks = Map::new();
    for id in selected {
        checks.insert(id.to_string(), run_check(id, args));
    }
    Ok(json!({
        "schema": SCHEMA,
        "kernel": kernel,
        "arch": arch,
        "checks": checks,
    }))
}

fn main() -> ExitCode {
    let args = match parse_args(std::env::args().skip(1)) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("runner-probe: {e}");
            return ExitCode::from(64);
        }
    };
    match build_report(&args) {
        Ok(report) => {
            println!("{report}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("runner-probe: {e}");
            ExitCode::from(70)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(v: &[&str]) -> Result<Args, String> {
        parse_args(v.iter().map(|s| s.to_string()))
    }

    #[test]
    fn defaults_to_all_checks() {
        assert_eq!(parse(&[]).unwrap().selection, Selection::All);
    }

    #[test]
    fn parses_single_check_and_iterations() {
        let a = parse(&["--check", "P0-SPIKE-03", "--iterations", "5"]).unwrap();
        assert_eq!(a.selection, Selection::One("P0-SPIKE-03".into()));
        assert_eq!(a.iterations, 5);
    }

    #[test]
    fn rejects_unknown_check() {
        assert!(parse(&["--check", "P0-SPIKE-99"]).is_err());
    }
}
