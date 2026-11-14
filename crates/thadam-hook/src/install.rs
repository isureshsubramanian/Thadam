//! Installs and removes the root-owned hook configuration (ADR-011 Decision 2): the hook
//! program beside the collector, and one file per tool (the adapters' `HookConfig`) that
//! makes the tool run it on each event. User-level settings are never touched, and a file
//! at a tool's path that this program did not write is never replaced or removed.

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::adapters::{self, HookConfig};

pub const HOOK_BIN: &str = "/Library/Application Support/Thadam/bin/thadam-hook";

struct Targets<'a> {
    bin: PathBuf,
    configs: Vec<(PathBuf, &'a HookConfig)>,
}

impl Targets<'_> {
    fn system() -> Self {
        Self {
            bin: HOOK_BIN.into(),
            configs: adapters::ALL
                .iter()
                .map(|a| (a.config.path.into(), &a.config))
                .collect(),
        }
    }
}

fn unsafe_folder(dir: &Path, owner: u32) -> io::Result<Option<PathBuf>> {
    for folder in dir.ancestors() {
        let meta = fs::metadata(folder)?;
        if !meta.is_dir() || meta.uid() != owner || meta.mode() & 0o022 != 0 {
            return Ok(Some(folder.into()));
        }
    }
    Ok(None)
}

fn parent(path: &Path) -> io::Result<&Path> {
    path.parent()
        .ok_or_else(|| io::Error::other("missing parent"))
}

fn prepare(dir: &Path, owner: u32) -> io::Result<()> {
    if !dir.exists() {
        prepare(parent(dir)?, owner)?;
        DirBuilder::new().mode(0o755).create(dir)?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o755))?;
        if owner == 0 {
            std::os::unix::fs::chown(dir, Some(0), Some(0))?;
        }
    }
    // Existing ancestors must be safe before any privileged write takes place.
    if let Some(folder) = unsafe_folder(dir, owner)? {
        return Err(io::Error::other(format!(
            "unsafe folder {}",
            folder.display()
        )));
    }
    Ok(())
}

fn atomic_write(path: &Path, bytes: &[u8], owner: u32, mode: u32) -> io::Result<()> {
    let tmp = parent(path)?.join(format!(".thadam-hook-{}.tmp", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    let result = (|| {
        file.write_all(bytes)?;
        if owner == 0 {
            std::os::unix::fs::chown(&tmp, Some(0), Some(0))?;
        }
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        file.sync_all()?;
        fs::rename(&tmp, path)?;
        let meta = fs::metadata(path)?;
        if meta.uid() != owner || meta.mode() & 0o7777 != mode || (owner == 0 && meta.gid() != 0) {
            return Err(io::Error::other("ownership or mode verification failed"));
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(tmp);
    }
    result
}

fn owned(path: &Path, config: &HookConfig) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(meta) if !meta.file_type().is_file() => Ok(false),
        Ok(_) => Ok((config.is_ours)(&fs::read_to_string(path)?)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(true),
        Err(e) => Err(e),
    }
}

fn install_config(path: &Path, config: &HookConfig, bin: &str, owner: u32) -> io::Result<()> {
    prepare(parent(path)?, owner)?;
    if !owned(path, config)? {
        return Err(io::Error::other("foreign file"));
    }
    atomic_write(path, (config.render)(bin).as_bytes(), owner, 0o644)
}

fn remove_config(path: &Path, config: &HookConfig) -> io::Result<()> {
    if !owned(path, config)? {
        return Err(io::Error::other("foreign file"));
    }
    remove(path)
}

fn remove(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        result => result,
    }
}

fn report(path: &Path, action: &str, result: io::Result<()>) -> bool {
    match result {
        Ok(()) => {
            println!("{action}: {}", path.display());
            true
        }
        Err(e) => {
            eprintln!("refused: {} ({e})", path.display());
            false
        }
    }
}

fn cli(args: &[String], installing: bool) -> ExitCode {
    if !args.is_empty() {
        eprintln!("usage: thadam-hook install-hooks | uninstall-hooks");
        return ExitCode::from(2);
    }
    // Read the effective uid without libc or unsafe code. The collector relies on
    // its first privileged write; check explicitly before creating anything here.
    if !std::process::Command::new("/usr/bin/id")
        .arg("-u")
        .output()
        .is_ok_and(|out| out.status.success() && out.stdout == b"0\n")
    {
        eprintln!("refused: / (root required)");
        return ExitCode::FAILURE;
    }
    let targets = Targets::system();
    let mut ok = true;
    if installing {
        let result = (|| {
            prepare(parent(&targets.bin)?, 0)?;
            let source = std::env::current_exe()?;
            atomic_write(&targets.bin, &fs::read(source)?, 0, 0o755)
        })();
        if !report(&targets.bin, "installed", result) {
            return ExitCode::FAILURE;
        }
    }
    for (path, config) in &targets.configs {
        let result = if installing {
            install_config(path, config, HOOK_BIN, 0)
        } else {
            remove_config(path, config)
        };
        ok &= report(
            path,
            if installing { "installed" } else { "removed" },
            result,
        );
    }
    if !installing {
        ok &= report(&targets.bin, "removed", remove(&targets.bin));
    }
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

pub fn cli_install(args: &[String]) -> ExitCode {
    cli(args, true)
}
pub fn cli_uninstall(args: &[String]) -> ExitCode {
    cli(args, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};

    #[test]
    fn renders_and_quotes_both_formats() {
        let bin = "/synthetic/a b'c\\\"\n\t\u{7f}";
        for adapter in adapters::ALL {
            let text = (adapter.config.render)(bin);
            assert!((adapter.config.is_ours)(&text));
            assert!(!(adapter.config.is_ours)("foreign"));
            if adapter.config.path.ends_with(".json") {
                let value: serde_json::Value = serde_json::from_str(&text).unwrap();
                assert_eq!(
                    value["hooks"].as_object().unwrap().len(),
                    adapter.events.len()
                );
                for event in adapter.events {
                    let command = value["hooks"][event][0]["hooks"][0]["command"]
                        .as_str()
                        .unwrap();
                    assert_eq!(
                        command,
                        format!("'{}' --tool {}", bin.replace('\'', "'\\''"), adapter.key)
                    );
                    assert_eq!(value["hooks"][event][0]["hooks"][0]["async"], true);
                    assert!(
                        value["hooks"][event][0]["hooks"][0]
                            .get("statusMessage")
                            .is_none()
                    );
                }
                assert!(!(adapter.config.is_ours)("{}"));
                // A file with any other setting, or another program's hook, is not ours.
                let mut extra = value.clone();
                extra["model"] = serde_json::json!("x");
                assert!(!(adapter.config.is_ours)(&extra.to_string()));
                let mut other = value.clone();
                other["hooks"]["Stop"][0]["hooks"][0]["command"] = serde_json::json!("/bin/other");
                assert!(!(adapter.config.is_ours)(&other.to_string()));
            } else {
                let script = r#"import sys, tomllib, json
v = tomllib.loads(sys.stdin.read())
assert v['features'] == {'hooks': True}
events = json.loads(sys.argv[1])
assert list(v['hooks']) == events
for event in events:
    h = v['hooks'][event][0]['hooks'][0]
    assert h['type'] == 'command'
    assert h['command'] == sys.argv[2]
    assert h['timeout'] == (2 if event == 'SessionEnd' else 5)
    assert ('async' not in h) if event == 'SessionEnd' else h['async'] is True
"#;
                let child = Command::new("python3")
                    .arg("-c")
                    .arg(script)
                    .arg(serde_json::to_string(adapter.events).unwrap())
                    .arg(format!(
                        "'{}' --tool {}",
                        bin.replace('\'', "'\\''"),
                        adapter.key
                    ))
                    .stdin(Stdio::piped())
                    .spawn();
                let mut child = match child {
                    Ok(child) => child,
                    Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                    Err(e) => panic!("{e}"),
                };
                child
                    .stdin
                    .take()
                    .unwrap()
                    .write_all(text.as_bytes())
                    .unwrap();
                assert!(child.wait().unwrap().success());
                assert!(!(adapter.config.is_ours)(&format!("\n{text}")));
            }
        }
    }

    #[test]
    fn foreign_files_survive_and_our_files_are_replaced() {
        // Configuration ownership checks do not need privileged ancestor folders.
        let dir = std::env::temp_dir().join(format!("thadam-hook-files-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let targets = Targets {
            bin: dir.join("bin"),
            configs: adapters::ALL
                .iter()
                .enumerate()
                .map(|(i, a)| (dir.join(format!("{i}.config")), &a.config))
                .collect(),
        };
        let owner = fs::metadata(&dir).unwrap().uid();
        for (path, config) in targets.configs {
            fs::write(&path, "foreign").unwrap();
            assert!(!owned(&path, config).unwrap());
            assert!(remove_config(&path, config).is_err());
            assert_eq!(fs::read_to_string(&path).unwrap(), "foreign");
            fs::write(&path, (config.render)("/synthetic/old")).unwrap();
            assert!(owned(&path, config).unwrap());
            atomic_write(
                &path,
                (config.render)("/synthetic/new").as_bytes(),
                owner,
                0o644,
            )
            .unwrap();
            assert_eq!(
                fs::read_to_string(&path).unwrap(),
                (config.render)("/synthetic/new")
            );
            remove_config(&path, config).unwrap();
            assert!(!path.exists());
        }
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(unsafe_folder(&dir, owner).unwrap(), Some(dir.clone()));
        assert!(prepare(&dir, owner).is_err());
        fs::remove_dir_all(dir).unwrap();
    }
}
