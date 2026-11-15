//! The dashboard password's verifier, checked by the collector (ADR-015 Decision 1).
//!
//! The file is root-only (0600), so no program running as the user, an AI tool included, can
//! read it to guess offline, or replace it. Its format is the API's earlier one (ADR-008
//! Decision 2): PBKDF2-HMAC-SHA256, 600,000 iterations (the OWASP Password Storage Cheat
//! Sheet's figure), a 16-byte salt and a 32-byte hash, here as hex. Never the password.

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use sha2::Sha256;

pub const ALGORITHM: &str = "PBKDF2-HMAC-SHA256";
pub const ITERATIONS: u32 = 600_000;
const SALT_BYTES: usize = 16;
const HASH_BYTES: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialFile {
    pub version: u32,
    pub algorithm: String,
    pub iterations: u32,
    pub salt: String,
    pub hash: String,
}

impl CredentialFile {
    /// A new verifier for `password`, with a fresh random salt.
    pub fn create(password: &str, iterations: u32) -> io::Result<Self> {
        let mut salt = [0u8; SALT_BYTES];
        getrandom::fill(&mut salt).map_err(io::Error::other)?;
        Ok(Self {
            version: 1,
            algorithm: ALGORITHM.to_string(),
            iterations,
            salt: thadam_core::to_hex(&salt),
            hash: thadam_core::to_hex(&derive(password, &salt, iterations)),
        })
    }

    /// True when `password` matches. A file weaker than `min_iterations`, or malformed, never
    /// matches. Compared in constant time.
    pub fn verify(&self, password: &str, min_iterations: u32) -> bool {
        if self.version != 1 || self.algorithm != ALGORITHM || self.iterations < min_iterations {
            return false;
        }
        let (Some(salt), Some(expected)) = (from_hex(&self.salt), from_hex(&self.hash)) else {
            return false;
        };
        if salt.len() != SALT_BYTES || expected.len() != HASH_BYTES {
            return false;
        }
        let actual = derive(password, &salt, self.iterations);
        actual
            .iter()
            .zip(&expected)
            .fold(0u8, |diff, (a, b)| diff | (a ^ b))
            == 0
    }
}

fn derive(password: &str, salt: &[u8], iterations: u32) -> [u8; HASH_BYTES] {
    let mut out = [0u8; HASH_BYTES];
    pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, iterations, &mut out);
    out
}

fn from_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

/// The stored verifier, or `None` when no password has been set. A file that another user
/// owns, that others can read or write, or that is a symlink counts as not set: it cannot be
/// trusted, and the diagnostic says so without naming the path.
pub fn load(path: &Path) -> io::Result<Option<CredentialFile>> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let owner_ok = meta.uid() == crate::peer::euid();
    if !meta.file_type().is_file() || !owner_ok || meta.mode() & 0o077 != 0 {
        crate::diag!("thadam-collector: the credentials file is not private to its owner; ignored");
        return Ok(None);
    }
    let text = fs::read_to_string(path)?;
    match serde_json::from_str(&text) {
        Ok(file) => Ok(Some(file)),
        Err(_) => {
            crate::diag!("thadam-collector: the credentials file is malformed; ignored");
            Ok(None)
        }
    }
}

/// When the file last changed, so a new password can end every session.
pub fn stamp(path: &Path) -> Option<SystemTime> {
    fs::symlink_metadata(path).and_then(|m| m.modified()).ok()
}

/// Writes the verifier: a 0600 temporary file beside it, then a rename, so a reader sees the
/// old file or the new one, never half of one.
pub fn save(path: &Path, file: &CredentialFile) -> io::Result<()> {
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let tmp = dir.join(format!(
        ".credentials-{:016x}.tmp",
        getrandom::u64().map_err(io::Error::other)?
    ));
    let mut out = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    let written = serde_json::to_vec_pretty(file)
        .map_err(io::Error::other)
        .and_then(|bytes| out.write_all(&bytes))
        .and_then(|()| out.sync_all())
        .and_then(|()| fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600)))
        .and_then(|()| fs::rename(&tmp, path));
    if written.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    written
}

/// A new session token: 32 bytes from the OS random source, as hex.
pub fn new_token() -> io::Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(io::Error::other)?;
    Ok(thadam_core::to_hex(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Dir(std::path::PathBuf);
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn dir() -> Dir {
        let d = std::env::temp_dir().join(format!("tcred-{}", new_token().unwrap()));
        fs::create_dir(&d).unwrap();
        Dir(d)
    }

    #[test]
    fn verifies_the_password_and_nothing_else() {
        let file = CredentialFile::create("made up pass phrase", 1).unwrap();
        assert!(file.verify("made up pass phrase", 1));
        assert!(!file.verify("made up pass phrasE", 1));
        assert!(!file.verify("", 1));
        // A file weaker than required never matches.
        assert!(!file.verify("made up pass phrase", 2));
        let bad = CredentialFile {
            hash: "zz".into(),
            ..file.clone()
        };
        assert!(!bad.verify("made up pass phrase", 1));
        assert_ne!(
            CredentialFile::create("made up pass phrase", 1)
                .unwrap()
                .salt,
            file.salt,
            "a fresh salt each time"
        );
    }

    #[test]
    fn matches_the_api_algorithm() {
        // PBKDF2-HMAC-SHA256 test vector (RFC 7914 §11, P = "passwd", S = "salt", c = 1).
        let out = derive("passwd", b"salt", 1);
        assert_eq!(
            thadam_core::to_hex(&out),
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
        );
    }

    #[test]
    fn saved_private_and_loaded_back() {
        let d = dir();
        let path = d.0.join("credentials.json");
        assert_eq!(load(&path).unwrap(), None);
        let file = CredentialFile::create("made up pass phrase", 1).unwrap();
        save(&path, &file).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(load(&path).unwrap(), Some(file));
        let text = fs::read_to_string(&path).unwrap();
        assert!(!text.contains("made up"));
    }

    #[test]
    fn a_readable_or_linked_file_is_not_trusted() {
        let d = dir();
        let path = d.0.join("credentials.json");
        save(
            &path,
            &CredentialFile::create("made up pass phrase", 1).unwrap(),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(load(&path).unwrap(), None);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let link = d.0.join("link.json");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert_eq!(load(&link).unwrap(), None);
    }

    #[test]
    fn tokens_are_random_hex() {
        let (a, b) = (new_token().unwrap(), new_token().unwrap());
        assert_eq!(a.len(), thadam_core::SESSION_HEX);
        assert_ne!(a, b);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
    }
}
