//! The root-managed settings drop-in that runs the hook (ADR-011 Decision 2). The tool merges
//! it with the user's own settings; managed hooks cannot be removed from lower levels.

use serde_json::{Map, Value, json};

pub const PATH: &str = "/Library/Application Support/ClaudeCode/managed-settings.d/thadam.json";

fn command(hook_bin: &str) -> String {
    thadam_core::hook_command(hook_bin, super::KEY)
}

pub fn render(hook_bin: &str) -> String {
    let command = command(hook_bin);
    let hooks: Map<String, Value> = super::EVENTS
        .iter()
        .map(|event| {
            let entry = json!([{ "hooks": [{
                "type": "command", "command": command, "async": true, "timeout": 5
            }] }]);
            ((*event).to_string(), entry)
        })
        .collect();
    let mut text = serde_json::to_string_pretty(&json!({ "hooks": hooks })).unwrap_or_default();
    text.push('\n');
    text
}

/// Ours when the file holds hooks only, and every one runs this hook for this tool. Nothing
/// is added to the file to mark it: any extra field could change what the tool shows.
pub fn is_ours(existing: &str) -> bool {
    let suffix = format!("' --tool {}", super::KEY);
    let Ok(Value::Object(top)) = serde_json::from_str::<Value>(existing) else {
        return false;
    };
    let Some(Value::Object(events)) = top.get("hooks") else {
        return false;
    };
    top.len() == 1
        && !events.is_empty()
        && events.values().all(|groups| {
            groups.as_array().is_some_and(|groups| {
                groups.iter().all(|g| {
                    g.get("hooks").and_then(Value::as_array).is_some_and(|hs| {
                        !hs.is_empty()
                            && hs.iter().all(|h| {
                                h.get("command")
                                    .and_then(Value::as_str)
                                    .is_some_and(|c| c.ends_with(&suffix))
                            })
                    })
                })
            })
        })
}
