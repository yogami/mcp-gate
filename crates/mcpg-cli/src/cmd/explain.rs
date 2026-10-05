//! Implementation of `mcp-gate explain <RULE_ID>`.
//!
//! SPEC 2.1, 3.4.4.

use mcpg_domain::verdict::ExitCode;

/// Documentation and metadata for an mcp-gate security or protocol rule.
#[derive(Debug, Clone, Copy)]
pub struct RuleInfo {
    pub id: &'static str,
    pub name: &'static str,
    pub default_level: &'static str,
    pub security_severity: &'static str,
    pub cwe: &'static str,
    pub description: &'static str,
}

pub const RULES: &[RuleInfo] = &[
    RuleInfo {
        id: "MCPG001",
        name: "canary-file-access",
        default_level: "error (tier A), warning (tier B)",
        security_severity: "9.0",
        cwe: "CWE-552",
        description: "Server process accessed a decoy canary file or triggered an inotify tripwire on planted credentials.",
    },
    RuleInfo {
        id: "MCPG002",
        name: "canary-value-leak",
        default_level: "error",
        security_severity: "9.5",
        cwe: "CWE-200",
        description: "Decoy canary secret value observed in stdout, stderr, written files, child process arguments, or network traffic.",
    },
    RuleInfo {
        id: "MCPG003",
        name: "read-outside-policy",
        default_level: "error",
        security_severity: "7.5",
        cwe: "CWE-284",
        description: "File read access outside declared policy read paths and runtime baseline.",
    },
    RuleInfo {
        id: "MCPG004",
        name: "write-outside-policy",
        default_level: "error",
        security_severity: "8.0",
        cwe: "CWE-284",
        description: "File write, creation, truncation, or mutation outside declared policy write paths.",
    },
    RuleInfo {
        id: "MCPG005",
        name: "path-traversal-escape",
        default_level: "error",
        security_severity: "8.5",
        cwe: "CWE-22",
        description: "Path traversal escape via relative components, symlinks, or absolute paths targeting files outside declared directories during a tool call.",
    },
    RuleInfo {
        id: "MCPG006",
        name: "unapproved-child-process",
        default_level: "error",
        security_severity: "8.0",
        cwe: "CWE-78",
        description: "Execution of a binary or child process not permitted by policy allowed child binaries.",
    },
    RuleInfo {
        id: "MCPG007",
        name: "unapproved-network",
        default_level: "error",
        security_severity: "7.5",
        cwe: "CWE-200",
        description: "Network activity (such as socket creation, connect, sendto, or bind on AF_INET/AF_INET6) while allow_network is disabled.",
    },
    RuleInfo {
        id: "MCPG008",
        name: "foreign-proc-access",
        default_level: "error",
        security_severity: "8.0",
        cwe: "CWE-214",
        description: "Access to foreign /proc entries outside the capsule process tree.",
    },
    RuleInfo {
        id: "MCPG009",
        name: "unapproved-unix-socket",
        default_level: "error",
        security_severity: "9.0",
        cwe: "CWE-269",
        description: "Connection to a Unix domain socket not listed in policy allowed_unix_sockets.",
    },
    RuleInfo {
        id: "MCPG010",
        name: "harness-tamper-attempt",
        default_level: "warning",
        security_severity: "6.0",
        cwe: "CWE-693",
        description: "Attempt to tamper with harness execution, send disallowed signals, or invoke restricted system calls like ptrace, io_uring, or clone with new user namespaces.",
    },
    RuleInfo {
        id: "MCPG011",
        name: "sensitive-path-probe",
        default_level: "note",
        security_severity: "3.0",
        cwe: "CWE-200",
        description: "Existence probing or stat on sensitive paths such as user home directories or decoy credential zones.",
    },
    RuleInfo {
        id: "MCPG012",
        name: "process-escape",
        default_level: "warning",
        security_severity: "5.0",
        cwe: "CWE-404",
        description: "Subprocess or orphaned daemon outliving the test run after shutdown signals.",
    },
    RuleInfo {
        id: "MCPG900",
        name: "protocol-violation",
        default_level: "warning",
        security_severity: "n/a",
        cwe: "n/a",
        description: "MCP protocol violation such as non-JSON output on stdout, malformed framing, or oversized stdout lines.",
    },
];

/// Execute `mcp-gate explain <RULE_ID>`.
pub fn execute(rule_query: &str) -> ExitCode {
    let query_norm = rule_query.trim().to_ascii_uppercase();
    let found = RULES
        .iter()
        .find(|r| r.id == query_norm || r.name.eq_ignore_ascii_case(rule_query.trim()));

    let Some(info) = found else {
        eprintln!("Error: unknown rule ID '{rule_query}'");
        return ExitCode::Usage;
    };

    println!("Rule: {}", info.id);
    println!("Name: {}", info.name);
    println!("Default Level: {}", info.default_level);
    println!("Security Severity: {}", info.security_severity);
    println!("CWE: {}", info.cwe);
    println!("Description: {}", info.description);

    ExitCode::Pass
}
