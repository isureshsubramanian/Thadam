//! The tool registry (ADR-003 Decision 5): which running code counts as an AI tool.
//!
//! The registry file is the only place real tool names exist. Tools are matched by
//! code-signing identity, never by file name, because a tool's binary can be renamed on
//! every update. Errors name the field that failed, never the value in it.

use std::path::Path;

use garde::Validate;
use serde::Deserialize;
use thadam_core::model::MAX_TOOL_KEY;
use thiserror::Error;

use crate::source::Identity;

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

/// One registered tool.
#[derive(Debug, Clone)]
pub struct Tool {
    pub key: String,
    matchers: Vec<Matcher>,
    state_dirs: Vec<PathPattern>,
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
            tools.push(Tool {
                key: entry.key,
                matchers,
                state_dirs: entry
                    .state_dirs
                    .iter()
                    .map(|p| PathPattern::parse(p))
                    .collect(),
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
}

#[derive(Debug, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
struct ToolEntry {
    #[garde(length(min = 1, max = MAX_TOOL_KEY), custom(tool_key))]
    key: String,
    #[serde(rename = "match")]
    #[garde(length(min = 1), dive)]
    matchers: Vec<MatcherEntry>,
    #[serde(default)]
    #[garde(inner(custom(path_pattern)))]
    state_dirs: Vec<String>,
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
