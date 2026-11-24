//! The hook side of Thadam's guard (ADR-018 Decision 3): decide whether a call about to run
//! names a protected path. Fails open: anything the guard can't read or resolve lets the
//! call run.

use std::collections::VecDeque;
use std::io::Read;
use std::path::Path;

use thadam_core::guard::{MAX_REGISTRY_BYTES, absolute, candidates, collapse};
use thadam_core::paths::{is_no_touch, is_sensitive};
use thadam_core::{AgentKind, AgentMessage, GuardMode, GuardResult, HookGuard};

/// Most `lstat` calls for one tool call, across all its paths. Worst case for a hostile call:
/// 4,096 `lstat`s of local files, a few microseconds each, so about 20 ms (estimate), well
/// inside the tool's 2 s wait. A call that needs more is treated as a match (fail closed):
/// no ordinary call comes near it, and stopping early would let padded commands through.
pub const MAX_LSTATS: usize = 4_096;
/// Most symbolic links followed while resolving one path: macOS's `MAXSYMLINKS` (32, in
/// `<sys/param.h>`), beyond which the kernel itself fails with `ELOOP`.
pub const MAX_LINK_HOPS: usize = 32;

/// The result of resolving one path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolved {
    Path(String),
    /// A link loop or too many links: the kernel would refuse it too.
    Loop,
    /// The call's `lstat` budget ran out before this path was resolved.
    OutOfBudget,
    /// A `..` follows a part that may not be touched, so where the kernel would land can't be
    /// known without touching it (review A). Treated as a match.
    Unknowable,
}

/// The registry as the hook found it.
pub enum Registry {
    /// No registry file: Thadam is not installed, so there is no guard.
    Missing,
    /// The file exists but could not be read in full.
    Unreadable,
    Text(String),
}

impl Registry {
    pub fn read(path: &Path) -> Self {
        let file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Self::Missing,
            Err(_) => return Self::Unreadable,
        };
        let mut text = String::new();
        let limit = MAX_REGISTRY_BYTES.saturating_add(1);
        match file.take(limit).read_to_string(&mut text) {
            Ok(n) if u64::try_from(n).is_ok_and(|n| n <= MAX_REGISTRY_BYTES) => Self::Text(text),
            _ => Self::Unreadable,
        }
    }
}

/// What the guard decided for one message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub result: GuardResult,
    /// The path (as made absolute) that matched; set for `Blocked` and `WouldBlock`.
    pub path: Option<String>,
}

/// Checks a call that is about to run. `None` when there is nothing to check or record.
/// `can_deny` says whether the tool can refuse a call; without it `enforce` acts as monitor.
/// `registry` is read only when there is a call to check.
pub fn check(
    m: &AgentMessage,
    cwd: Option<&str>,
    home: Option<&str>,
    registry: &dyn Fn() -> Registry,
    can_deny: bool,
    resolve: &mut dyn FnMut(&str) -> Resolved,
) -> Option<Decision> {
    if m.kind != AgentKind::CallStart {
        return None;
    }
    let words = candidates(m.call_kind?, m.text.as_deref()?);
    if words.is_empty() {
        return None;
    }
    let guard = match registry() {
        Registry::Missing => return None,
        Registry::Unreadable => return Some(error()),
        Registry::Text(json) => match HookGuard::from_registry(&json, &m.tool) {
            Ok(g) => g,
            Err(_) => return Some(error()),
        },
    };
    if guard.files == GuardMode::Off {
        return None;
    }
    let path = first_match(&words, cwd, home, &guard, resolve)?;
    let result = if guard.files == GuardMode::Enforce && can_deny {
        GuardResult::Blocked
    } else {
        GuardResult::WouldBlock
    };
    Some(Decision {
        result,
        path: Some(path),
    })
}

fn error() -> Decision {
    Decision {
        result: GuardResult::Error,
        path: None,
    }
}

/// The first word that is a protected path: by its text with `..` removed, or as the kernel
/// would reach it, following links before `..`. Returns the path as the call wrote it.
fn first_match(
    words: &[String],
    cwd: Option<&str>,
    home: Option<&str>,
    guard: &HookGuard,
    resolve: &mut dyn FnMut(&str) -> Resolved,
) -> Option<String> {
    for word in words {
        let Some(path) = absolute(word, cwd, home) else {
            continue;
        };
        let text = collapse(&path);
        if is_sensitive(&text, &guard.sensitive) {
            return Some(text);
        }
        // Guard before touch: network, mounted and synced locations are matched as text only.
        if is_no_touch(&text) {
            continue;
        }
        // As the kernel reads it (links before `..`), and as a tool that removes `..` by
        // text before opening reads it.
        let forms: &[&str] = if text == path {
            &[&path]
        } else {
            &[&path, &text]
        };
        for form in forms {
            match resolve(form) {
                Resolved::Path(real) if is_sensitive(&real, &guard.sensitive) => {
                    return Some(text);
                }
                Resolved::Path(_) | Resolved::Loop => {}
                Resolved::OutOfBudget | Resolved::Unknowable => return Some(text),
            }
        }
    }
    None
}

/// The text the agent sees when a call is refused. Names the path it asked for, nothing else.
pub fn reason(path: &str) -> String {
    format!("Blocked by Thadam guard: {path} is a protected path. Ask the user if this is needed.")
}

/// `path` (absolute, `..` kept) with symbolic links resolved the way the kernel does, links
/// first and `..` after, using `lstat` and `readlink` only, so no link is followed by the OS.
/// Stops touching the disk, and finishes by text, at the first part that is missing or lies
/// in a network, mounted or synced location. Each `lstat` takes one from `budget`.
pub fn resolve_links(path: &str, budget: &mut usize) -> Resolved {
    match walk(path, budget) {
        Ok(p) => Resolved::Path(p),
        Err(r) => r,
    }
}

fn walk(path: &str, budget: &mut usize) -> Result<String, Resolved> {
    let mut pending: VecDeque<String> = parts(path);
    let mut done: Vec<String> = Vec::new();
    let mut hops = 0;
    let mut touch = true;
    let mut held_back = false;
    while let Some(part) = pending.pop_front() {
        if part == ".." {
            if held_back {
                return Err(Resolved::Unknowable);
            }
            done.pop();
            continue;
        }
        done.push(part);
        if !touch {
            continue;
        }
        let current = join(&done);
        if is_no_touch(&current) {
            touch = false;
            held_back = true;
            continue;
        }
        if *budget == 0 {
            return Err(Resolved::OutOfBudget);
        }
        *budget -= 1;
        match std::fs::symlink_metadata(&current) {
            Ok(meta) if meta.file_type().is_symlink() => {
                hops += 1;
                if hops > MAX_LINK_HOPS {
                    return Err(Resolved::Loop);
                }
                // An unreadable or non-UTF-8 link: finish by text from here.
                let Some(target) = std::fs::read_link(&current)
                    .ok()
                    .and_then(|t| t.to_str().map(str::to_string))
                else {
                    touch = false;
                    continue;
                };
                done.pop();
                if target.starts_with('/') {
                    done.clear();
                }
                for p in parts(&target).into_iter().rev() {
                    pending.push_front(p);
                }
            }
            Ok(_) => {}
            Err(_) => touch = false,
        }
    }
    Ok(join(&done))
}

fn parts(path: &str) -> VecDeque<String> {
    path.split('/')
        .filter(|p| !p.is_empty() && *p != ".")
        .map(str::to_string)
        .collect()
}

fn join(parts: &[String]) -> String {
    format!("/{}", parts.join("/"))
}

#[cfg(test)]
mod tests;
