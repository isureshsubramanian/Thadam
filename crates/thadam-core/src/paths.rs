//! Path prefixes and the sensitive-path rule, shared by the collector (which flags) and the
//! hook (which guards, ADR-018 Decision 3), so what is flagged and what is guarded can never
//! drift apart. Text only: nothing here touches the file system.

/// Folders under a home folder that hold credentials. Lower case: compared with `fold`ed paths.
const SENSITIVE_HOME_DIRS: &[&str] = &[".ssh", ".gnupg", "library/keychains", ".netrc"];
const SENSITIVE_EXTENSIONS: &[&str] = &["pem", "p12", "key"];
const SENSITIVE_NAME_PREFIXES: &[&str] = &["id_rsa", "id_ed25519"];

/// Longest accepted path pattern, in bytes (same bound as the event model's paths).
pub const MAX_PATTERN: usize = crate::model::MAX_PATH;
/// Most extra sensitive prefixes the registry may list (estimate; real lists are a handful).
/// Enforced alike by the collector's registry check and the hook's reader.
pub const MAX_SENSITIVE: usize = 1_000;

/// A path prefix. `~/` stands for any user's home folder, because the collector runs as
/// root and serves every user on the Mac.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathPattern {
    Absolute(String),
    /// The part after `~/`.
    Home(String),
}

impl PathPattern {
    pub fn parse(text: &str) -> Self {
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

    /// `contains`, comparing `fold`ed forms.
    fn contains_folded(&self, folded: &str) -> bool {
        match self {
            PathPattern::Absolute(prefix) => under(folded, &fold(prefix)),
            PathPattern::Home(rest) => folded_home_relative(folded)
                .is_some_and(|rel| rest.is_empty() || under(rel, &rest.to_ascii_lowercase())),
        }
    }
}

/// The registry's rule for a path pattern: absolute or `~/`, bounded, no NUL. The one
/// validator for both readers of the registry (collector and hook).
pub fn check_pattern(value: &str, _ctx: &()) -> garde::Result {
    let ok_start = value.starts_with('/') || value.starts_with("~/");
    if ok_start && value.len() <= MAX_PATTERN && !value.contains('\0') {
        Ok(())
    } else {
        Err(garde::Error::new("must start with '/' or '~/'"))
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

/// The form the sensitive and no-touch rules compare, so another spelling of the same file
/// can't slip past them (ADR-018 review, 24 Nov 2026):
/// - ASCII lower case: the default macOS volume ignores case;
/// - the data-volume firmlink removed: `/System/Volumes/Data/Users/x` is `/Users/x`;
/// - `/private/var`, `/private/tmp` and `/private/etc` as `/var`, `/tmp` and `/etc`.
///
/// Unicode case and normalisation are not folded: a rule with non-ASCII letters may miss a
/// differently composed spelling (accepted; the built-in rules are ASCII).
pub fn fold(path: &str) -> String {
    let mut p = path.to_ascii_lowercase();
    if let Some(rest) = p.strip_prefix("/system/volumes/data")
        && (rest.is_empty() || rest.starts_with('/'))
    {
        p = if rest.is_empty() {
            "/".to_string()
        } else {
            rest.to_string()
        };
    }
    if ["/private/var", "/private/tmp", "/private/etc"]
        .iter()
        .any(|d| under(&p, d))
    {
        p.replace_range(.."/private".len(), "");
    }
    p
}

/// `home_relative` for a `fold`ed path.
fn folded_home_relative(folded: &str) -> Option<&str> {
    let rest = folded.strip_prefix("/users/")?;
    let slash = rest.find('/')?;
    if slash == 0 {
        return None;
    }
    rest.get(slash + 1..)
}

/// True when `path` (absolute) holds credentials: the built-in list, or a prefix in `extra`
/// (the registry's `paths.sensitive`). Compared in `fold`ed form.
pub fn is_sensitive(path: &str, extra: &[PathPattern]) -> bool {
    let path = fold(path);
    if extra.iter().any(|p| p.contains_folded(&path)) {
        return true;
    }
    if folded_home_relative(&path)
        .is_some_and(|rel| SENSITIVE_HOME_DIRS.iter().any(|d| under(rel, d)))
    {
        return true;
    }
    let name = path.rsplit('/').next().unwrap_or(&path);
    if name == ".env" || name.starts_with(".env.") {
        return true;
    }
    if SENSITIVE_NAME_PREFIXES.iter().any(|p| name.starts_with(p)) {
        return true;
    }
    match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => SENSITIVE_EXTENSIONS.contains(&ext),
        _ => false,
    }
}

/// Network, mounted and synced locations, lower case. A path under one is never resolved or
/// stat-ed by Thadam: resolving could touch a NAS or a synced folder, or hang on an offline
/// mount (ADR-018 Decision 3, "guard before touch").
const NO_TOUCH_ROOTS: &[&str] = &["/volumes", "/network", "/net"];
const NO_TOUCH_HOME: &[&str] = &[
    "library/cloudstorage",
    "library/mobile documents",
    "synologydrive",
];

/// True when `path` (absolute, as written) lies in a location that must only be matched as
/// text, in any spelling (`fold`). Callers check this before any call that reads, follows or
/// stats `path`.
pub fn is_no_touch(path: &str) -> bool {
    let path = fold(path);
    NO_TOUCH_ROOTS.iter().any(|r| under(&path, r))
        || folded_home_relative(&path)
            .is_some_and(|rel| NO_TOUCH_HOME.iter().any(|d| under(rel, d)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_paths() {
        assert!(is_sensitive("/Users/dev/.ssh/id_ed25519", &[]));
        assert!(is_sensitive("/Users/dev/.ssh", &[]));
        assert!(is_sensitive(
            "/Users/dev/Library/Keychains/login.keychain-db",
            &[]
        ));
        assert!(is_sensitive("/tmp/work/server.key", &[]));
        assert!(is_sensitive("/tmp/work/.env.local", &[]));
        assert!(is_sensitive("/tmp/id_rsa.pub", &[]));
        assert!(!is_sensitive("/Users/dev/.sshx/config", &[]));
        assert!(!is_sensitive("/tmp/work/.key", &[]));
        assert!(!is_sensitive("/tmp/work/keys.txt", &[]));
        let extra = [PathPattern::parse("~/secrets/")];
        assert!(is_sensitive("/Users/dev/secrets/a.txt", &extra));
        assert!(!is_sensitive("/Users/dev/secretsx", &extra));
    }

    #[test]
    fn other_spellings_of_a_sensitive_path_match() {
        let extra = [
            PathPattern::parse("~/secrets/"),
            PathPattern::parse("/var/keys/"),
        ];
        for p in [
            "/Users/dev/.SSH/config",
            "/users/dev/.ssh/config",
            "/System/Volumes/Data/Users/dev/.netrc",
            "/Users/dev/library/keychains/login.keychain-db",
            "/tmp/server.PEM",
            "/tmp/.ENV",
            "/tmp/ID_RSA",
            "/Users/dev/Secrets/a.txt",
            "/private/var/Keys/a",
        ] {
            assert!(is_sensitive(p, &extra), "{p}");
        }
        assert!(!is_sensitive(
            "/System/Volumes/Data/Users/dev/notes.txt",
            &extra
        ));
    }

    #[test]
    fn no_touch_locations() {
        assert!(is_no_touch("/Volumes/nas/share/a"));
        assert!(is_no_touch("/Volumes"));
        assert!(is_no_touch("/Network/Servers/x"));
        assert!(is_no_touch("/net/host/x"));
        assert!(is_no_touch("/Users/dev/Library/CloudStorage/Drive/a"));
        assert!(is_no_touch(
            "/Users/dev/Library/Mobile Documents/com~apple~CloudDocs/a"
        ));
        assert!(is_no_touch("/Users/dev/SynologyDrive/a"));
        assert!(is_no_touch("/System/Volumes/Data/Volumes/nas/a"));
        assert!(!is_no_touch("/Users/dev/Library/Caches/a"));
        assert!(!is_no_touch("/Volumesx/a"));
        assert!(!is_no_touch("/System/Volumes/Data/Users/dev/a"));
        // Other spellings of the same places.
        assert!(is_no_touch("/VOLUMES/nas/a"));
        assert!(is_no_touch("/Users/dev/library/cloudstorage/Drive/a"));
        assert!(is_no_touch("/system/volumes/data/volumes/nas/a"));
    }

    #[test]
    fn prefixes() {
        assert!(under("/a/b", "/a"));
        assert!(under("/a/b", "/a/"));
        assert!(!under("/ab", "/a"));
        assert_eq!(home_relative("/Users/dev/x"), Some("x"));
        assert_eq!(home_relative("/Users//x"), None);
        let p = PathPattern::parse("~/x/");
        assert_eq!(p.matched_prefix("/Users/dev/x/y"), Some("/Users/dev/x"));
        assert_eq!(fold("/private/tmp/A"), "/tmp/a");
        assert_eq!(fold("/system/volumes/data"), "/");
    }
}
