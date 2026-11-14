//! One adapter per tool: the only source files that name a tool (project rule 6). Each
//! maps that tool's hook payloads to `AgentMessage` and owns its hook configuration file.

pub mod claude_code;
pub mod codex;

use serde_json::Value;
use sha2::{Digest, Sha256};
use thadam_core::AgentMessage;

/// A tool's hook configuration: a root-owned file that makes the tool run the hook.
pub struct HookConfig {
    /// Where the file goes.
    pub path: &'static str,
    /// The file's full text, running `hook_bin --tool <key>` on every event in `events`.
    pub render: fn(hook_bin: &str) -> String,
    /// Whether existing text at `path` was written by `render` (safe to replace or remove).
    pub is_ours: fn(existing: &str) -> bool,
}

pub struct Adapter {
    /// The tool's registry key; also the value of `--tool`.
    pub key: &'static str,
    /// Hook events the adapter handles; `config` subscribes to exactly these.
    pub events: &'static [&'static str],
    pub parse: fn(&Value) -> Option<AgentMessage>,
    pub config: HookConfig,
}

pub const ALL: &[&Adapter] = &[&claude_code::ADAPTER, &codex::ADAPTER];

pub fn by_key(key: &str) -> Option<&'static Adapter> {
    ALL.iter().copied().find(|a| a.key == key)
}

/// A string field, or `None` when missing, null, empty or not a string.
pub(crate) fn text(v: &Value, key: &str) -> Option<String> {
    v.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Lower-case hex SHA-256 of `bytes`.
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    thadam_core::to_hex(&Sha256::digest(bytes))
}
