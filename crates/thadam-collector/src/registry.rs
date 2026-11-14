//! The tool registry (ADR-003 Decision 5): which running code counts as an AI tool.
//!
//! The registry file is the only place real tool names exist. Tools are matched by
//! code-signing identity, never by file name, because a tool's binary can be renamed on
//! every update. Errors name the field that failed, never the value in it.

use std::path::{Path, PathBuf};

use garde::Validate;
use serde::Deserialize;
use thadam_core::model::MAX_TOOL_KEY;
use thadam_store::Limits;
use thiserror::Error;

use crate::source::Identity;
use crate::source::network::is_host_name;

/// Longest accepted signing identifier, in bytes (estimate; real ones are reverse-DNS names).
const MAX_SIGNING_ID: usize = 255;
/// Longest accepted path or path pattern, in bytes. Same bound as core's `MAX_PATH`.
const MAX_PATTERN: usize = thadam_core::model::MAX_PATH;

/// Folder names whose contents are rolled up inside a project (ADR-005 Rule 1). Generic
/// names such as `build` and `dist` are left out: they too often hold real files.
const DEFAULT_ROLLUP_NAMES: &[&str] = &[
    "target",
    "node_modules",
    ".build",
    "__pycache__",
    ".gradle",
    "DerivedData",
];
/// Dependency and toolchain caches, rolled up wherever they are (ADR-005 Rule 1).
const DEFAULT_ROLLUP_PATHS: &[&str] = &["~/.cargo/registry/", "~/.rustup/", "~/.npm/"];
/// Individual reads per process per window before the rest are rolled up (ADR-005 Rule 2).
/// An estimate: on live run 3 it rolled up 12,202 scan reads and left normal reads alone.
pub const DEFAULT_READ_BUDGET: usize = 100;
/// Largest accepted read budget (estimate; above this the rule has no effect in practice).
const MAX_READ_BUDGET: usize = 100_000;
/// Longest accepted roll-up folder name, in bytes (the usual file name limit).
const MAX_NAME: usize = 255;
/// Bytes out in one network row that make it a large upload (ADR-007 Decision 5, estimate).
pub const DEFAULT_LARGE_UPLOAD: i64 = 10 * 1024 * 1024;
/// Bytes out from one session to one host in an hour that make a large upload (estimate).
pub const DEFAULT_LARGE_UPLOAD_SESSION: i64 = 50 * 1024 * 1024;
/// Largest accepted upload threshold (1 TiB; above this the flag can't fire in practice).
const MAX_UPLOAD_THRESHOLD: i64 = 1 << 40;
/// Longest accepted display name, in characters (ADR-008 Decision 10).
const MAX_DISPLAY_NAME: usize = 64;
/// Most host patterns per tool (estimate; real lists are a handful).
const MAX_KNOWN_HOSTS: usize = 1_000;
/// Retention bounds (ADR-009 Decision 3): ages 7 to 3,650 days, sizes 1 GB to 1 TB, free
/// floor at least 1 GB. The defaults are the store's `Limits::default()`.
const MIN_AGE_DAYS: u32 = 7;
const MAX_AGE_DAYS: u32 = 3_650;
const MAX_GB: u64 = 1_000;
const GB: u64 = 1_000_000_000;

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("cannot read registry file: {0}")]
    Io(#[from] std::io::Error),
    /// serde's message names the line and column and the expected type, not the value.
    #[error("registry file is not valid: {0}")]
    Parse(String),
    #[error("registry file is not valid: {0}")]
    Invalid(String),
}

/// Index of a tool in the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ToolId(usize);

/// A path prefix. `~/` stands for any user's home folder, because the collector runs as
/// root and serves every user on the Mac.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathPattern {
    Absolute(String),
    /// The part after `~/`.
    Home(String),
}

impl PathPattern {
    fn parse(text: &str) -> Self {
        match text.strip_prefix("~/") {
            Some(rest) => PathPattern::Home(rest.to_string()),
            None => PathPattern::Absolute(text.to_string()),
        }
    }

    /// The part of `path` the pattern matched, without a trailing `/`, when `path` lies
    /// under it. For `~/x/` and `/Users/dev/x/y` that is `/Users/dev/x`.
    pub fn matched_prefix<'p>(&self, path: &'p str) -> Option<&'p str> {
        if !self.contains(path) {
            return None;
        }
        let len = match self {
            PathPattern::Absolute(prefix) => prefix.trim_end_matches('/').len(),
            PathPattern::Home(rest) => {
                let relative = home_relative(path)?;
                (path.len() - relative.len()) + rest.trim_end_matches('/').len()
            }
        };
        path.get(..len)
    }

    /// True when `path` is the pattern itself or lies under it.
    pub fn contains(&self, path: &str) -> bool {
        match self {
            PathPattern::Absolute(prefix) => under(path, prefix),
            PathPattern::Home(rest) => match home_relative(path) {
                Some(relative) => rest.is_empty() || under(relative, rest),
                None => false,
            },
        }
    }
}

/// `path` equals `prefix` or lies below it. A prefix ending in `/` names a folder.
pub fn under(path: &str, prefix: &str) -> bool {
    let trimmed = prefix.strip_suffix('/').unwrap_or(prefix);
    if trimmed.is_empty() {
        return path.starts_with('/');
    }
    match path.strip_prefix(trimmed) {
        Some("") => true,
        Some(rest) => rest.starts_with('/'),
        None => false,
    }
}

/// The part of `path` after `/Users/<name>/`, if it is inside a home folder.
pub fn home_relative(path: &str) -> Option<&str> {
    let rest = path.strip_prefix("/Users/")?;
    let slash = rest.find('/')?;
    if slash == 0 {
        return None;
    }
    rest.get(slash + 1..)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Matcher {
    Signed {
        team_id: String,
        signing: Signing,
    },
    /// Weaker: for unsigned or ad-hoc-signed tools only.
    Path(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Signing {
    Exact(String),
    Prefix(String),
}

impl Matcher {
    fn matches(&self, executable: &str, identity: &Identity) -> bool {
        match self {
            Matcher::Signed { team_id, signing } => {
                if identity.team_id.as_deref() != Some(team_id.as_str()) {
                    return false;
                }
                match (signing, identity.signing_id.as_deref()) {
                    (Signing::Exact(want), Some(got)) => want == got,
                    (Signing::Prefix(want), Some(got)) => got.starts_with(want.as_str()),
                    (_, None) => false,
                }
            }
            Matcher::Path(path) => path == executable,
        }
    }
}

/// A host the tool is expected to talk to: an exact name, or `*.` and a suffix, which
/// matches names below the suffix but not the suffix itself (ADR-007 Decision 6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostPattern {
    Exact(String),
    /// Stored with its leading dot, for example `.example.test`.
    Below(String),
}

impl HostPattern {
    fn parse(pattern: &str) -> Self {
        let p = pattern.to_ascii_lowercase();
        match p.strip_prefix('*') {
            Some(suffix) => HostPattern::Below(suffix.to_string()),
            None => HostPattern::Exact(p),
        }
    }

    /// `host` is expected lower case (the network source normalises it).
    pub fn matches(&self, host: &str) -> bool {
        match self {
            HostPattern::Exact(name) => name == host,
            HostPattern::Below(suffix) => {
                host.len() > suffix.len() && host.ends_with(suffix.as_str())
            }
        }
    }
}

/// What a tool's network rows are checked against (ADR-007 Decisions 5 and 6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkPolicy {
    pub known_hosts: Vec<HostPattern>,
    pub large_upload_bytes: i64,
    pub large_upload_session_bytes: i64,
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        Self {
            known_hosts: Vec::new(),
            large_upload_bytes: DEFAULT_LARGE_UPLOAD,
            large_upload_session_bytes: DEFAULT_LARGE_UPLOAD_SESSION,
        }
    }
}

impl NetworkPolicy {
    /// True when `host` matches one of the tool's known hosts.
    pub fn is_known_host(&self, host: &str) -> bool {
        self.known_hosts.iter().any(|p| p.matches(host))
    }
}

/// One registered tool.
#[derive(Debug, Clone)]
pub struct Tool {
    pub key: String,
    matchers: Vec<Matcher>,
    state_dirs: Vec<PathPattern>,
    pub network: NetworkPolicy,
}

impl Tool {
    /// True when `path` is in one of the tool's own state folders.
    pub fn is_state_path(&self, path: &str) -> bool {
        self.state_dirs.iter().any(|p| p.contains(path))
    }

    /// True when the tool can be matched by path, which is weaker than identity.
    pub fn has_path_matcher(&self) -> bool {
        self.matchers.iter().any(|m| matches!(m, Matcher::Path(_)))
    }
}

/// The loaded, validated registry.
#[derive(Debug, Clone)]
pub struct Registry {
    tools: Vec<Tool>,
    not_outside: Vec<PathPattern>,
    sensitive: Vec<PathPattern>,
    responsible_attribution: bool,
    rollup_names: Vec<String>,
    rollup_paths: Vec<PathPattern>,
    read_budget: usize,
    retention: Limits,
}

impl Registry {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, RegistryError> {
        Self::parse(&std::fs::read_to_string(path)?)
    }

    pub fn parse(json: &str) -> Result<Self, RegistryError> {
        let file: RegistryFile =
            serde_json::from_str(json).map_err(|e| RegistryError::Parse(parse_error(&e)))?;
        file.validate()
            .map_err(|report| RegistryError::Invalid(report.to_string()))?;

        let mut tools = Vec::with_capacity(file.tools.len());
        for (i, entry) in file.tools.into_iter().enumerate() {
            if tools.iter().any(|t: &Tool| t.key == entry.key) {
                return Err(RegistryError::Invalid(format!(
                    "tools[{i}].key: duplicate key"
                )));
            }
            let mut matchers = Vec::with_capacity(entry.matchers.len());
            for (j, m) in entry.matchers.into_iter().enumerate() {
                matchers.push(m.into_matcher().map_err(|reason| {
                    RegistryError::Invalid(format!("tools[{i}].match[{j}]: {reason}"))
                })?);
            }
            let network = entry.network.unwrap_or_default();
            tools.push(Tool {
                key: entry.key,
                matchers,
                state_dirs: entry
                    .state_dirs
                    .iter()
                    .map(|p| PathPattern::parse(p))
                    .collect(),
                network: NetworkPolicy {
                    known_hosts: network
                        .known_hosts
                        .iter()
                        .map(|p| HostPattern::parse(p))
                        .collect(),
                    large_upload_bytes: network.large_upload_bytes,
                    large_upload_session_bytes: network.large_upload_session_bytes,
                },
            });
        }
        Ok(Self {
            tools,
            not_outside: file
                .paths
                .not_outside
                .iter()
                .map(|p| PathPattern::parse(p))
                .collect(),
            sensitive: file
                .paths
                .sensitive
                .iter()
                .map(|p| PathPattern::parse(p))
                .collect(),
            responsible_attribution: file.attribution.responsible_process,
            rollup_names: DEFAULT_ROLLUP_NAMES
                .iter()
                .map(|n| (*n).to_string())
                .chain(file.rollup.folder_names)
                .collect(),
            rollup_paths: DEFAULT_ROLLUP_PATHS
                .iter()
                .map(|p| PathPattern::parse(p))
                .chain(file.rollup.paths.iter().map(|p| PathPattern::parse(p)))
                .collect(),
            read_budget: file.rollup.read_budget,
            retention: Limits {
                max_age_days: file.retention.max_age_days,
                max_store_bytes: file.retention.max_store_gb * GB,
                min_free_bytes: file.retention.min_free_gb * GB,
                archive_dir: file.retention.archive_dir.map(PathBuf::from),
            },
        })
    }

    /// The tool this running image belongs to, if any. Platform binaries never match.
    pub fn match_identity(&self, executable: &str, identity: &Identity) -> Option<ToolId> {
        if identity.platform {
            return None;
        }
        self.tools
            .iter()
            .position(|t| t.matchers.iter().any(|m| m.matches(executable, identity)))
            .map(ToolId)
    }

    pub fn tool(&self, id: ToolId) -> Option<&Tool> {
        self.tools.get(id.0)
    }

    pub fn tools(&self) -> impl Iterator<Item = &Tool> {
        self.tools.iter()
    }

    /// Extra prefixes that are never "outside the project".
    pub fn not_outside(&self) -> &[PathPattern] {
        &self.not_outside
    }

    /// Extra sensitive path prefixes, added to the built-in list.
    pub fn sensitive(&self) -> &[PathPattern] {
        &self.sensitive
    }

    /// Whether processes are attributed through the OS's responsible-process link.
    pub fn responsible_attribution(&self) -> bool {
        self.responsible_attribution
    }

    /// Folder names rolled up inside a project, defaults included (ADR-005 Rule 1).
    pub fn rollup_names(&self) -> &[String] {
        &self.rollup_names
    }

    /// Path prefixes rolled up anywhere, defaults included (ADR-005 Rule 1).
    pub fn rollup_paths(&self) -> &[PathPattern] {
        &self.rollup_paths
    }

    /// Individual reads per process per window (ADR-005 Rule 2).
    /// How long and how much the store keeps (ADR-009 Decision 3).
    pub fn retention(&self) -> &Limits {
        &self.retention
    }

    pub fn read_budget(&self) -> usize {
        self.read_budget
    }
}

/// serde_json's message can quote part of the input for some errors; keep only the
/// category and position.
fn parse_error(e: &serde_json::Error) -> String {
    let kind = match e.classify() {
        serde_json::error::Category::Io => "read error",
        serde_json::error::Category::Syntax => "JSON syntax error",
        serde_json::error::Category::Data => "unexpected or missing field",
        serde_json::error::Category::Eof => "unexpected end of file",
    };
    format!("{kind} at line {} column {}", e.line(), e.column())
}

// ---- File format (input boundary: serde for shape, garde for meaning) ----

#[derive(Debug, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
struct RegistryFile {
    #[garde(range(min = 1, max = 1))]
    version: u32,
    #[garde(length(min = 1), dive)]
    tools: Vec<ToolEntry>,
    #[serde(default)]
    #[garde(dive)]
    paths: PathsEntry,
    #[serde(default)]
    #[garde(skip)]
    attribution: AttributionEntry,
    #[serde(default)]
    #[garde(dive)]
    rollup: RollupEntry,
    #[serde(default)]
    #[garde(dive)]
    retention: RetentionEntry,
}

/// Sizes in whole GB (10^9 bytes), as people think of disk space.
#[derive(Debug, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
struct RetentionEntry {
    #[serde(default = "default_max_age_days")]
    #[garde(range(min = MIN_AGE_DAYS, max = MAX_AGE_DAYS))]
    max_age_days: u32,
    #[serde(default = "default_max_store_gb")]
    #[garde(range(min = 1, max = MAX_GB))]
    max_store_gb: u64,
    #[serde(default = "default_min_free_gb")]
    #[garde(range(min = 1, max = MAX_GB))]
    min_free_gb: u64,
    #[serde(default)]
    #[garde(inner(custom(absolute_path)))]
    archive_dir: Option<String>,
}

impl Default for RetentionEntry {
    fn default() -> Self {
        Self {
            max_age_days: default_max_age_days(),
            max_store_gb: default_max_store_gb(),
            min_free_gb: default_min_free_gb(),
            archive_dir: None,
        }
    }
}

fn default_max_age_days() -> u32 {
    Limits::default().max_age_days
}

fn default_max_store_gb() -> u64 {
    Limits::default().max_store_bytes / GB
}

fn default_min_free_gb() -> u64 {
    Limits::default().min_free_bytes / GB
}

#[derive(Debug, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
struct ToolEntry {
    #[garde(length(min = 1, max = MAX_TOOL_KEY), custom(tool_key))]
    key: String,
    /// The dashboard's name for the tool (ADR-008 Decision 10). Read by the API only; the
    /// collector validates it and otherwise ignores it.
    #[serde(default)]
    #[garde(inner(length(chars, min = 1, max = MAX_DISPLAY_NAME), custom(printable)))]
    display_name: Option<String>,
    #[serde(rename = "match")]
    #[garde(length(min = 1), dive)]
    matchers: Vec<MatcherEntry>,
    #[serde(default)]
    #[garde(inner(custom(path_pattern)))]
    state_dirs: Vec<String>,
    #[serde(default)]
    #[garde(dive)]
    network: Option<NetworkEntry>,
}

/// Per tool, the hosts it is expected to reach and the upload thresholds (ADR-007
/// Decision 6). Real host names live only in the real registry file.
#[derive(Debug, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
struct NetworkEntry {
    #[serde(default)]
    #[garde(length(max = MAX_KNOWN_HOSTS), inner(custom(host_pattern)))]
    known_hosts: Vec<String>,
    #[serde(default = "default_large_upload")]
    #[garde(range(min = 1, max = MAX_UPLOAD_THRESHOLD))]
    large_upload_bytes: i64,
    #[serde(default = "default_large_upload_session")]
    #[garde(range(min = 1, max = MAX_UPLOAD_THRESHOLD))]
    large_upload_session_bytes: i64,
}

impl Default for NetworkEntry {
    fn default() -> Self {
        Self {
            known_hosts: Vec::new(),
            large_upload_bytes: DEFAULT_LARGE_UPLOAD,
            large_upload_session_bytes: DEFAULT_LARGE_UPLOAD_SESSION,
        }
    }
}

fn default_large_upload() -> i64 {
    DEFAULT_LARGE_UPLOAD
}

fn default_large_upload_session() -> i64 {
    DEFAULT_LARGE_UPLOAD_SESSION
}

#[derive(Debug, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
struct MatcherEntry {
    #[garde(inner(custom(team_id_format)))]
    team_id: Option<String>,
    #[garde(inner(length(min = 1, max = MAX_SIGNING_ID), custom(printable)))]
    signing_id: Option<String>,
    #[garde(inner(length(min = 1, max = MAX_SIGNING_ID), custom(printable)))]
    signing_id_prefix: Option<String>,
    #[garde(inner(custom(absolute_path)))]
    path: Option<String>,
}

impl MatcherEntry {
    fn into_matcher(self) -> Result<Matcher, &'static str> {
        match (
            self.team_id,
            self.signing_id,
            self.signing_id_prefix,
            self.path,
        ) {
            (Some(team_id), Some(id), None, None) => Ok(Matcher::Signed {
                team_id,
                signing: Signing::Exact(id),
            }),
            (Some(team_id), None, Some(prefix), None) => Ok(Matcher::Signed {
                team_id,
                signing: Signing::Prefix(prefix),
            }),
            (None, None, None, Some(path)) => Ok(Matcher::Path(path)),
            _ => Err(
                "give team_id with exactly one of signing_id or signing_id_prefix, or path alone",
            ),
        }
    }
}

#[derive(Debug, Default, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
struct PathsEntry {
    #[serde(default)]
    #[garde(inner(custom(path_pattern)))]
    not_outside: Vec<String>,
    #[serde(default)]
    #[garde(inner(custom(path_pattern)))]
    sensitive: Vec<String>,
}

/// Extends the built-in roll-up lists; it can't remove defaults (ADR-005 Decision 1).
#[derive(Debug, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
struct RollupEntry {
    #[serde(default)]
    #[garde(inner(length(min = 1, max = MAX_NAME), custom(folder_name)))]
    folder_names: Vec<String>,
    #[serde(default)]
    #[garde(inner(custom(path_pattern)))]
    paths: Vec<String>,
    #[serde(default = "default_read_budget")]
    #[garde(range(min = 1, max = MAX_READ_BUDGET))]
    read_budget: usize,
}

impl Default for RollupEntry {
    fn default() -> Self {
        Self {
            folder_names: Vec::new(),
            paths: Vec::new(),
            read_budget: DEFAULT_READ_BUDGET,
        }
    }
}

fn default_read_budget() -> usize {
    DEFAULT_READ_BUDGET
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttributionEntry {
    #[serde(default = "default_true")]
    responsible_process: bool,
}

impl Default for AttributionEntry {
    fn default() -> Self {
        Self {
            responsible_process: true,
        }
    }
}

fn default_true() -> bool {
    true
}

fn tool_key(value: &str, _ctx: &()) -> garde::Result {
    if value
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
    {
        Ok(())
    } else {
        Err(garde::Error::new(
            "tool key may contain only a-z, 0-9, '-' and '_'",
        ))
    }
}

fn team_id_format(value: &str, _ctx: &()) -> garde::Result {
    if value.len() == 10
        && value
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
    {
        Ok(())
    } else {
        Err(garde::Error::new(
            "team id must be 10 uppercase letters or digits",
        ))
    }
}

fn printable(value: &str, _ctx: &()) -> garde::Result {
    if value.chars().all(|c| !c.is_control()) {
        Ok(())
    } else {
        Err(garde::Error::new("must not contain control characters"))
    }
}

fn folder_name(value: &str, _ctx: &()) -> garde::Result {
    if value.contains('/') || value == "." || value == ".." || value.chars().any(char::is_control) {
        Err(garde::Error::new("must be a single folder name"))
    } else {
        Ok(())
    }
}

fn absolute_path(value: &str, _ctx: &()) -> garde::Result {
    if value.starts_with('/') && value.len() <= MAX_PATTERN && !value.contains('\0') {
        Ok(())
    } else {
        Err(garde::Error::new("must be an absolute path"))
    }
}

/// An exact host name, or `*.` and a name of at least two labels (no bare `*`, no `*.test`).
fn host_pattern(value: &str, _ctx: &()) -> garde::Result {
    let ok = match value.strip_prefix("*.") {
        Some(suffix) => is_host_name(suffix) && suffix.contains('.'),
        None => !value.contains('*') && is_host_name(value),
    };
    if ok && !value.ends_with('.') {
        Ok(())
    } else {
        Err(garde::Error::new(
            "must be a host name, or '*.' and a name with at least two labels",
        ))
    }
}

fn path_pattern(value: &str, _ctx: &()) -> garde::Result {
    let ok_start = value.starts_with('/') || value.starts_with("~/");
    if ok_start && value.len() <= MAX_PATTERN && !value.contains('\0') {
        Ok(())
    } else {
        Err(garde::Error::new("must start with '/' or '~/'"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
      "version": 1,
      "tools": [
        { "key": "cli_agent",
          "match": [ { "team_id": "TEAM000001", "signing_id": "com.example.cli-agent" } ],
          "state_dirs": [ "~/.cli-agent/" ] },
        { "key": "desktop_assistant",
          "match": [ { "team_id": "TEAM000002", "signing_id_prefix": "com.example.assistant" } ] },
        { "key": "local_tool",
          "match": [ { "path": "/Users/test/bin/local-tool" } ] }
      ],
      "paths": { "not_outside": [ "/opt/toolchains/" ], "sensitive": [ "~/.config/sample-cloud/" ] }
    }"#;

    fn signed(team: Option<&str>, id: Option<&str>) -> Identity {
        Identity {
            team_id: team.map(str::to_string),
            signing_id: id.map(str::to_string),
            platform: false,
        }
    }

    fn key(r: &Registry, id: Option<ToolId>) -> Option<&str> {
        id.and_then(|i| r.tool(i)).map(|t| t.key.as_str())
    }

    #[test]
    fn display_names_are_optional_and_validated() {
        let named = SAMPLE.replacen(
            r#"{ "key": "cli_agent","#,
            r#"{ "key": "cli_agent", "display_name": "CLI agent","#,
            1,
        );
        assert!(Registry::parse(&named).is_ok());
        let too_long = format!("\"{}\"", "x".repeat(65));
        for bad in ["\"\"", too_long.as_str(), "\"tab\\there\""] {
            let json = SAMPLE.replacen(
                r#"{ "key": "cli_agent","#,
                &format!(r#"{{ "key": "cli_agent", "display_name": {bad},"#),
                1,
            );
            let err = Registry::parse(&json).unwrap_err().to_string();
            assert!(err.contains("display_name"), "{err}");
        }
    }

    #[test]
    fn retention_defaults_and_valid_values_load() {
        let r = Registry::parse(SAMPLE).unwrap();
        assert_eq!(r.retention(), &Limits::default());
        let custom = SAMPLE.replacen(
            r#""version": 1,"#,
            r#""version": 1, "retention": { "max_age_days": 30, "max_store_gb": 5,
                "min_free_gb": 2, "archive_dir": "/Volumes/Archive/thadam" },"#,
            1,
        );
        let r = Registry::parse(&custom).unwrap();
        assert_eq!(
            r.retention(),
            &Limits {
                max_age_days: 30,
                max_store_bytes: 5 * GB,
                min_free_bytes: 2 * GB,
                archive_dir: Some(PathBuf::from("/Volumes/Archive/thadam")),
            }
        );
    }

    #[test]
    fn out_of_range_retention_is_rejected_without_echoing_the_value() {
        for (field, value) in [
            ("max_age_days", "6"),
            ("max_age_days", "3651"),
            ("max_store_gb", "0"),
            ("max_store_gb", "1001"),
            ("min_free_gb", "0"),
            ("archive_dir", r#""relative/folder-9731""#),
        ] {
            let json = SAMPLE.replacen(
                r#""version": 1,"#,
                &format!(r#""version": 1, "retention": {{ "{field}": {value} }},"#),
                1,
            );
            let err = Registry::parse(&json).unwrap_err().to_string();
            assert!(err.contains(field), "{field}: {err}");
            let bare = value.trim_matches('"');
            assert!(!err.contains(bare), "{field} echoed its value: {err}");
        }
        let unknown = SAMPLE.replacen(
            r#""version": 1,"#,
            r#""version": 1, "retention": { "keep_forever": true },"#,
            1,
        );
        assert!(Registry::parse(&unknown).is_err());
    }

    #[test]
    fn matches_by_identity_not_file_name() {
        let r = Registry::parse(SAMPLE).unwrap();
        let id = signed(Some("TEAM000001"), Some("com.example.cli-agent"));
        // A version-numbered binary path still matches.
        let hit = r.match_identity("/Users/test/.local/share/cli/2.4.1", &id);
        assert_eq!(key(&r, hit), Some("cli_agent"));
        // Same signing id from a different team does not.
        let other = signed(Some("TEAM999999"), Some("com.example.cli-agent"));
        assert_eq!(
            r.match_identity("/Users/test/.local/share/cli/2.4.1", &other),
            None
        );
    }

    #[test]
    fn prefix_matcher_covers_helpers() {
        let r = Registry::parse(SAMPLE).unwrap();
        let helper = signed(Some("TEAM000002"), Some("com.example.assistant.helper"));
        assert_eq!(
            key(&r, r.match_identity("/Applications/X.app/helper", &helper)),
            Some("desktop_assistant")
        );
    }

    #[test]
    fn ad_hoc_code_matches_only_by_path_and_platform_never() {
        let r = Registry::parse(SAMPLE).unwrap();
        let ad_hoc = signed(None, Some("local-tool-55aa"));
        assert_eq!(
            key(&r, r.match_identity("/Users/test/bin/local-tool", &ad_hoc)),
            Some("local_tool")
        );
        assert_eq!(r.match_identity("/Users/test/bin/other", &ad_hoc), None);
        let mut platform = signed(Some("TEAM000001"), Some("com.example.cli-agent"));
        platform.platform = true;
        assert_eq!(r.match_identity("/usr/bin/x", &platform), None);
        assert!(r.tools().any(Tool::has_path_matcher));
    }

    #[test]
    fn home_patterns_match_any_user() {
        let p = PathPattern::parse("~/.cli-agent/");
        assert!(p.contains("/Users/test/.cli-agent/state.json"));
        assert!(p.contains("/Users/other/.cli-agent"));
        assert!(!p.contains("/Users/test/.cli-agent-old/x"));
        assert!(!p.contains("/private/var/root/.cli-agent/x"));
        assert!(under("/a/b", "/a/"));
        assert!(!under("/ab", "/a"));
    }

    #[test]
    fn defaults_apply_when_optional_sections_are_missing() {
        let r = Registry::parse(r#"{"version":1,"tools":[{"key":"t","match":[{"path":"/x"}]}]}"#)
            .unwrap();
        assert!(r.responsible_attribution());
        assert!(r.not_outside().is_empty());
    }

    #[test]
    fn invalid_fields_are_named_without_values() {
        let cases: &[(&str, &str)] = &[
            (
                r#"{"version":2,"tools":[{"key":"t","match":[{"path":"/x"}]}]}"#,
                "version",
            ),
            (r#"{"version":1,"tools":[]}"#, "tools"),
            (
                r#"{"version":1,"tools":[{"key":"Bad Key","match":[{"path":"/x"}]}]}"#,
                "key",
            ),
            (
                r#"{"version":1,"tools":[{"key":"t","match":[{"team_id":"lower00001","signing_id":"a"}]}]}"#,
                "team_id",
            ),
            (
                r#"{"version":1,"tools":[{"key":"t","match":[{"path":"relative/x"}]}]}"#,
                "path",
            ),
            (
                r#"{"version":1,"tools":[{"key":"t","match":[{"team_id":"TEAM000001"}]}]}"#,
                "match[0]",
            ),
            (
                r#"{"version":1,"tools":[{"key":"t","match":[{"path":"/x"}],"state_dirs":["rel/"]}]}"#,
                "state_dirs",
            ),
            (
                r#"{"version":1,"tools":[{"key":"t","match":[{"path":"/x"}]},{"key":"t","match":[{"path":"/y"}]}]}"#,
                "duplicate",
            ),
        ];
        for (json, field) in cases {
            let err = Registry::parse(json).unwrap_err().to_string();
            assert!(err.contains(field), "{err} should name {field}");
            assert!(
                !err.contains("lower00001") && !err.contains("relative/x"),
                "{err}"
            );
        }
    }

    #[test]
    fn network_policy_per_tool() {
        let r = Registry::parse(
            r#"{"version":1,"tools":[
                {"key":"t","match":[{"path":"/x"}],
                 "network":{"known_hosts":["*.Example-Agent.test","registry.example.test"],
                            "large_upload_bytes":1000}},
                {"key":"u","match":[{"path":"/y"}]}]}"#,
        )
        .unwrap();
        let t = &r.tools().next().unwrap().network;
        assert!(t.is_known_host("api.example-agent.test"));
        assert!(t.is_known_host("a.b.example-agent.test"));
        assert!(!t.is_known_host("example-agent.test"));
        assert!(!t.is_known_host("evil-example-agent.test"));
        assert!(t.is_known_host("registry.example.test"));
        assert!(!t.is_known_host("x.registry.example.test"));
        assert_eq!(t.large_upload_bytes, 1000);
        assert_eq!(t.large_upload_session_bytes, DEFAULT_LARGE_UPLOAD_SESSION);
        let u = &r.tools().nth(1).unwrap().network;
        assert_eq!(*u, NetworkPolicy::default());

        for bad in ["*", "*.test", "a.*.test", "bad host.test", "*.", "a.test."] {
            let json = format!(
                r#"{{"version":1,"tools":[{{"key":"t","match":[{{"path":"/x"}}],"network":{{"known_hosts":["{bad}"]}}}}]}}"#
            );
            let err = Registry::parse(&json).unwrap_err().to_string();
            assert!(err.contains("known_hosts"), "{bad}: {err}");
        }
        let zero = r#"{"version":1,"tools":[{"key":"t","match":[{"path":"/x"}],"network":{"large_upload_bytes":0}}]}"#;
        assert!(Registry::parse(zero).is_err());
    }

    #[test]
    fn rollup_lists_extend_the_defaults() {
        let r = Registry::parse(
            r#"{"version":1,"tools":[{"key":"t","match":[{"path":"/x"}]}],
                "rollup":{"folder_names":["build"],"paths":["/opt/cache/"],"read_budget":50}}"#,
        )
        .unwrap();
        assert!(r.rollup_names().iter().any(|n| n == "target"));
        assert!(r.rollup_names().iter().any(|n| n == "build"));
        assert!(r.rollup_paths().iter().any(|p| p.contains("/opt/cache/a")));
        assert!(
            r.rollup_paths()
                .iter()
                .any(|p| p.contains("/Users/test/.cargo/registry/x"))
        );
        assert_eq!(r.read_budget(), 50);
        let d = Registry::parse(r#"{"version":1,"tools":[{"key":"t","match":[{"path":"/x"}]}]}"#)
            .unwrap();
        assert_eq!(d.read_budget(), DEFAULT_READ_BUDGET);

        for bad in [
            r#""rollup":{"folder_names":["a/b"]}"#,
            r#""rollup":{"folder_names":[""]}"#,
            r#""rollup":{"paths":["rel/"]}"#,
            r#""rollup":{"read_budget":0}"#,
            r#""rollup":{"exclude":["target"]}"#,
        ] {
            let json = format!(
                r#"{{"version":1,"tools":[{{"key":"t","match":[{{"path":"/x"}}]}}],{bad}}}"#
            );
            assert!(Registry::parse(&json).is_err(), "{bad}");
        }
    }

    #[test]
    fn matched_prefix_returns_the_concrete_folder() {
        let home = PathPattern::parse("~/.cargo/registry/");
        assert_eq!(
            home.matched_prefix("/Users/test/.cargo/registry/src/x/lib.rs"),
            Some("/Users/test/.cargo/registry")
        );
        let abs = PathPattern::parse("/opt/cache/");
        assert_eq!(abs.matched_prefix("/opt/cache/a/b"), Some("/opt/cache"));
        assert_eq!(abs.matched_prefix("/opt/cachex/a"), None);
    }

    #[test]
    fn unknown_fields_and_bad_json_are_rejected_without_quoting_input() {
        let err = Registry::parse(r#"{"version":1,"tools":[],"secret_note":"x"}"#)
            .unwrap_err()
            .to_string();
        assert!(!err.contains("secret_note"), "{err}");
        assert!(Registry::parse("{not json").is_err());
    }
}
