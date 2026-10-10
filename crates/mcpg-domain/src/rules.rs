
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum FindingLevel {
    Note,
    Warning,
    Error,
}

#[derive(Debug, Clone)]
pub struct RuleDef {
    pub id: &'static str,
    pub name: &'static str,
    pub default_level: FindingLevel,
    pub security_severity: &'static str,
    pub cwe: &'static str,
    pub description: &'static str,
}

pub const RULES: &[RuleDef] = &[
    RuleDef {
        id: "MCPG001",
        name: "canary-file-access",
        default_level: FindingLevel::Error,
        security_severity: "9.0",
        cwe: "CWE-552",
        description: "Server process accessed a decoy canary file or triggered an inotify tripwire on planted credentials.",
    },
    RuleDef {
        id: "MCPG002",
        name: "canary-value-leak",
        default_level: FindingLevel::Error,
        security_severity: "9.5",
        cwe: "CWE-200",
        description: "Decoy canary secret value observed in stdout, stderr, written files, child process arguments, or network traffic.",
    },
    RuleDef {
        id: "MCPG003",
        name: "read-outside-policy",
        default_level: FindingLevel::Error,
        security_severity: "7.5",
        cwe: "CWE-284",
        description: "File read access outside declared policy read paths and runtime baseline.",
    },
    RuleDef {
        id: "MCPG004",
        name: "write-outside-policy",
        default_level: FindingLevel::Error,
        security_severity: "8.0",
        cwe: "CWE-284",
        description: "File write, creation, truncation, or mutation outside declared policy write paths.",
    },
    RuleDef {
        id: "MCPG005",
        name: "path-traversal-escape",
        default_level: FindingLevel::Error,
        security_severity: "8.5",
        cwe: "CWE-22",
        description: "Path traversal escape via relative components, symlinks, or absolute paths targeting files outside declared directories during a tool call.",
    },
    RuleDef {
        id: "MCPG006",
        name: "unapproved-child-process",
        default_level: FindingLevel::Error,
        security_severity: "8.0",
        cwe: "CWE-78",
        description: "Execution of a binary or child process not permitted by policy allowed child binaries.",
    },
    RuleDef {
        id: "MCPG007",
        name: "unapproved-network",
        default_level: FindingLevel::Error,
        security_severity: "7.5",
        cwe: "CWE-200",
        description: "Network activity (such as socket creation, connect, sendto, or bind on AF_INET/AF_INET6) while allow_network is disabled.",
    },
    RuleDef {
        id: "MCPG008",
        name: "foreign-proc-access",
        default_level: FindingLevel::Error,
        security_severity: "8.0",
        cwe: "CWE-214",
        description: "Access to foreign /proc entries outside the capsule process tree.",
    },
    RuleDef {
        id: "MCPG009",
        name: "unapproved-unix-socket",
        default_level: FindingLevel::Error,
        security_severity: "9.0",
        cwe: "CWE-269",
        description: "Connection to a Unix domain socket not listed in policy allowed_unix_sockets.",
    },
    RuleDef {
        id: "MCPG010",
        name: "harness-tamper-attempt",
        default_level: FindingLevel::Warning,
        security_severity: "6.0",
        cwe: "CWE-693",
        description: "Attempt to tamper with harness execution, send disallowed signals, or invoke restricted system calls like ptrace, io_uring, or clone with new user namespaces.",
    },
    RuleDef {
        id: "MCPG011",
        name: "sensitive-path-probe",
        default_level: FindingLevel::Note,
        security_severity: "3.0",
        cwe: "CWE-200",
        description: "Existence probing or stat on sensitive paths such as user home directories or decoy credential zones.",
    },
    RuleDef {
        id: "MCPG012",
        name: "process-escape",
        default_level: FindingLevel::Warning,
        security_severity: "5.0",
        cwe: "CWE-404",
        description: "Subprocess or orphaned daemon outliving the test run after shutdown signals.",
    },
    RuleDef {
        id: "MCPG900",
        name: "protocol-violation",
        default_level: FindingLevel::Warning,
        security_severity: "0.0",
        cwe: "n/a",
        description: "MCP protocol violation such as non-JSON output on stdout, malformed framing, or oversized stdout lines.",
    },
];

pub fn get_rule(id: &str) -> Option<RuleDef> {
    RULES.iter().find(|r| r.id == id).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_catalog_contains_all_mcpg_codes() {
        let codes = vec![
            "MCPG001", "MCPG002", "MCPG003", "MCPG004", "MCPG005", "MCPG006",
            "MCPG007", "MCPG008", "MCPG009", "MCPG010", "MCPG011", "MCPG012",
            "MCPG900"
        ];
        for code in codes {
            let rule = get_rule(code).expect(&format!("Rule {} must exist in catalog", code));
            assert_eq!(rule.id, code);
        }
    }
}
