//! Typed configuration data models mirroring SPEC 2.3 JSON schema.
//!
//! All structs deny unknown fields to prevent silent configuration typos.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

fn default_true() -> bool {
    true
}

fn default_workspace_exclude() -> Vec<String> {
    vec![".git".to_string()]
}

fn default_max_events() -> u64 {
    200_000
}

fn default_startup_timeout() -> u64 {
    30
}

fn default_call_timeout() -> u64 {
    30
}

fn default_total_timeout() -> u64 {
    600
}

fn default_shutdown_grace() -> u64 {
    3
}

fn default_max_processes() -> u32 {
    64
}

fn default_max_stdout_line_bytes() -> usize {
    16_777_216
}

/// Root configuration model.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    pub server: ServerConfig,
    pub policy: PolicyConfig,
    #[serde(default)]
    pub canaries: CanariesConfig,
    #[serde(default)]
    pub observe: ObserveConfig,
    #[serde(default)]
    pub probes: ProbesConfig,
    #[serde(default)]
    pub scenarios: Vec<ScenarioConfig>,
    #[serde(default)]
    pub limits: LimitsConfig,
    #[serde(default)]
    pub report: ReportConfig,
}

/// Server execution and containment configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub name: String,
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    pub workspace: WorkspaceConfig,
    #[serde(default)]
    pub env: EnvConfig,
    #[serde(default)]
    pub protocol_versions: Vec<String>,
    #[serde(default)]
    pub client: ClientConfig,
}

/// Workspace setup mode and source path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceConfig {
    pub source: String,
    #[serde(default)]
    pub mode: WorkspaceMode,
    #[serde(default = "default_workspace_exclude")]
    pub exclude: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WorkspaceMode {
    #[default]
    Copy,
    InPlace,
}

/// Scrubbed environment configuration.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvConfig {
    #[serde(default)]
    pub passthrough: Vec<String>,
    #[serde(default)]
    pub set: BTreeMap<String, String>,
    #[serde(default)]
    pub allow_secret_passthrough: bool,
}

/// Client feature advertisements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    #[serde(default = "default_true")]
    pub roots: bool,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self { roots: true }
    }
}

/// Declared capability policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    #[serde(default)]
    pub baseline: Baseline,
    pub read_paths: Vec<String>,
    pub write_paths: Vec<String>,
    pub allowed_child_binaries: Vec<String>,
    pub allow_network: bool,
    #[serde(default)]
    pub allowed_unix_sockets: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Baseline {
    #[default]
    Minimal,
    Python,
    Node,
    None,
}

/// Canary secret planting and detection configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanariesConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub kinds: Vec<CanaryKind>,
    #[serde(default)]
    pub declared_use: Vec<CanaryKind>,
}

impl Default for CanariesConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            kinds: Vec::new(),
            declared_use: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CanaryKind {
    Ssh,
    Aws,
    Gcloud,
    Kube,
    Docker,
    GitCredentials,
    GhCli,
    Netrc,
    Npmrc,
    Pypirc,
    Dotenv,
    Env,
}

/// Observer tuning and limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObserveConfig {
    #[serde(default)]
    pub stat_probes: bool,
    #[serde(default = "default_max_events")]
    pub max_events: u64,
}

impl Default for ObserveConfig {
    fn default() -> Self {
        Self {
            stat_probes: false,
            max_events: default_max_events(),
        }
    }
}

/// Active security probe configuration.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbesConfig {
    #[serde(default)]
    pub path_traversal: Option<ProbeToggle>,
    #[serde(default)]
    pub env_echo: Option<ProbeToggle>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeToggle {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub tools: Option<ProbeTools>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ProbeTools {
    Auto(String),
    List(Vec<String>),
}

/// Test scenario definition.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScenarioConfig {
    pub id: String,
    pub tool: String,
    #[serde(default)]
    pub arguments: serde_json::Value,
    #[serde(default)]
    pub canaries: Option<ScenarioCanaries>,
    #[serde(default)]
    pub expect: Option<ScenarioExpect>,
    #[serde(default, deserialize_with = "deserialize_timeout")]
    pub timeout_s: Option<u64>,
}

fn deserialize_timeout<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v: Option<serde_json::Value> = Option::deserialize(deserializer)?;
    match v {
        Some(serde_json::Value::Number(n)) => {
            if let Some(u) = n.as_u64() {
                Ok(Some(u))
            } else if let Some(f) = n.as_f64() {
                Ok(Some(f as u64))
            } else {
                Err(serde::de::Error::custom("invalid timeout_s number"))
            }
        }
        Some(serde_json::Value::String(s)) => {
            s.parse::<u64>().map(Some).map_err(serde::de::Error::custom)
        }
        Some(_) => Err(serde::de::Error::custom(
            "timeout_s must be a number or string",
        )),
        None => Ok(None),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScenarioCanaries {
    #[serde(default)]
    pub allow_access: Vec<CanaryKind>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScenarioExpect {
    #[serde(default)]
    pub outcome: Option<String>,
    #[serde(default)]
    pub content_contains: Vec<String>,
    #[serde(default)]
    pub content_not_contains: Vec<String>,
}

/// Operational timeouts and process limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsConfig {
    #[serde(default = "default_startup_timeout")]
    pub startup_timeout_s: u64,
    #[serde(default = "default_call_timeout")]
    pub call_timeout_s: u64,
    #[serde(default = "default_total_timeout")]
    pub total_timeout_s: u64,
    #[serde(default = "default_shutdown_grace")]
    pub shutdown_grace_s: u64,
    #[serde(default = "default_max_processes")]
    pub max_processes: u32,
    #[serde(default = "default_max_stdout_line_bytes")]
    pub max_stdout_line_bytes: usize,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            startup_timeout_s: default_startup_timeout(),
            call_timeout_s: default_call_timeout(),
            total_timeout_s: default_total_timeout(),
            shutdown_grace_s: default_shutdown_grace(),
            max_processes: default_max_processes(),
            max_stdout_line_bytes: default_max_stdout_line_bytes(),
        }
    }
}

/// Report thresholds and categories.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportConfig {
    #[serde(default)]
    pub fail_on: Option<FailOnLevel>,
    #[serde(default)]
    pub sarif_category: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FailOnLevel {
    #[default]
    Error,
    Warning,
    Note,
}

impl FailOnLevel {
    pub fn should_fail(self, finding_level: FailOnLevel) -> bool {
        match self {
            FailOnLevel::Error => matches!(finding_level, FailOnLevel::Error),
            FailOnLevel::Warning => {
                matches!(finding_level, FailOnLevel::Error | FailOnLevel::Warning)
            }
            FailOnLevel::Note => true,
        }
    }
}
