//! Canary catalogue definitions and specifications.
//!
//! SPEC 3.2.2:
//! All paths are relative to CAPSULE_HOME unless noted.
//! Tier A files are never read by common runtimes on their own.
//! Tier B files are read automatically by some HTTP and packaging libraries.
//! Egress-only applies to environment decoys.

/// Classification tier for canary access findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CanaryTier {
    /// Tier A: strictly private, access is always an error.
    A,
    /// Tier B: credential files read by common libraries (access is warning).
    B,
    /// Egress only: environment variable canaries tested during exfiltration.
    EgressOnly,
}

/// The set of standard canary kinds defined by the specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

/// A catalogue entry describing a canary kind, its relative paths, and tier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogueEntry {
    pub kind: CanaryKind,
    pub relative_paths: &'static [&'static str],
    pub tier: CanaryTier,
    pub file_mode: u32,
    pub dir_mode: u32,
}

const CATALOGUE: &[CatalogueEntry] = &[
    CatalogueEntry {
        kind: CanaryKind::Ssh,
        relative_paths: &[".ssh/id_ed25519", ".ssh/id_ed25519.pub"],
        tier: CanaryTier::A,
        file_mode: 0o600,
        dir_mode: 0o700,
    },
    CatalogueEntry {
        kind: CanaryKind::Aws,
        relative_paths: &[".aws/credentials", ".aws/config"],
        tier: CanaryTier::A,
        file_mode: 0o600,
        dir_mode: 0o700,
    },
    CatalogueEntry {
        kind: CanaryKind::Gcloud,
        relative_paths: &[".config/gcloud/application_default_credentials.json"],
        tier: CanaryTier::A,
        file_mode: 0o600,
        dir_mode: 0o700,
    },
    CatalogueEntry {
        kind: CanaryKind::Kube,
        relative_paths: &[".kube/config"],
        tier: CanaryTier::A,
        file_mode: 0o600,
        dir_mode: 0o700,
    },
    CatalogueEntry {
        kind: CanaryKind::Docker,
        relative_paths: &[".docker/config.json"],
        tier: CanaryTier::A,
        file_mode: 0o600,
        dir_mode: 0o700,
    },
    CatalogueEntry {
        kind: CanaryKind::GitCredentials,
        relative_paths: &[".git-credentials"],
        tier: CanaryTier::A,
        file_mode: 0o600,
        dir_mode: 0o700,
    },
    CatalogueEntry {
        kind: CanaryKind::GhCli,
        relative_paths: &[".config/gh/hosts.yml"],
        tier: CanaryTier::A,
        file_mode: 0o600,
        dir_mode: 0o700,
    },
    CatalogueEntry {
        kind: CanaryKind::Netrc,
        relative_paths: &[".netrc"],
        tier: CanaryTier::B,
        file_mode: 0o600,
        dir_mode: 0o700,
    },
    CatalogueEntry {
        kind: CanaryKind::Npmrc,
        relative_paths: &[".npmrc"],
        tier: CanaryTier::B,
        file_mode: 0o600,
        dir_mode: 0o700,
    },
    CatalogueEntry {
        kind: CanaryKind::Pypirc,
        relative_paths: &[".pypirc"],
        tier: CanaryTier::B,
        file_mode: 0o600,
        dir_mode: 0o700,
    },
    CatalogueEntry {
        kind: CanaryKind::Dotenv,
        relative_paths: &[".env"],
        tier: CanaryTier::A,
        file_mode: 0o600,
        dir_mode: 0o700,
    },
    CatalogueEntry {
        kind: CanaryKind::Env,
        relative_paths: &[],
        tier: CanaryTier::EgressOnly,
        file_mode: 0o600,
        dir_mode: 0o700,
    },
];

/// Return all catalogue entries.
pub fn all_catalogue_entries() -> &'static [CatalogueEntry] {
    CATALOGUE
}

/// Look up a catalogue entry for a given kind.
pub fn entry_for_kind(kind: CanaryKind) -> &'static CatalogueEntry {
    CATALOGUE
        .iter()
        .find(|e| e.kind == kind)
        .expect("all kinds have a catalogue entry")
}
