//! Host filesystem grow after cloud block-volume expand (`GrowFs`).
//!
//! Validates mount paths, resolves the block device and filesystem type for a mount point via
//! `findmnt`, then runs optional `growpart` plus `resize2fs` or `xfs_growfs`. Cloud volume resize
//! and capacity observation (heartbeat `statfs` / mount projection via Pion) happen outside this
//! module.
//!
//! Unit and scripted happy and sad paths are covered. End-to-end host `growpart` after a cloud
//! volume expand remains a deferred product proof.

use super::types::{ContainerActionRequest, ContainerActionResponse};
use std::path::{Component, Path};
use std::process::{Command, Stdio};

/// Validate `mount_path` for `GrowFs`: absolute, no `..`, no empty.
///
/// # Errors
///
/// Returns when the path is empty, relative, contains `..`, or is not absolute.
pub fn validate_grow_fs_mount_path(mount_path: &str) -> anyhow::Result<()> {
    let trimmed = mount_path.trim();
    if trimmed.is_empty() {
        anyhow::bail!("grow_fs.mount_path is empty");
    }
    let path = Path::new(trimmed);
    if !path.is_absolute() {
        anyhow::bail!("grow_fs.mount_path must be an absolute path");
    }
    for c in path.components() {
        if matches!(c, Component::ParentDir) {
            anyhow::bail!("grow_fs.mount_path must not contain '..'");
        }
    }
    // Reject obviously unsafe roots that would grow the whole host OS disk by accident
    // when an orchestrator mis-binds the path. Registry/data mounts are under /var/lib etc.
    let normalized = trimmed.trim_end_matches('/');
    if normalized.is_empty() || normalized == "/" {
        anyhow::bail!("grow_fs.mount_path must not be '/'");
    }
    Ok(())
}

/// Classify filesystem type string for grow tool selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GrowFsKind {
    Ext,
    Xfs,
}

impl GrowFsKind {
    pub(crate) fn from_fstype(fstype: &str) -> Option<Self> {
        let t = fstype.trim().to_ascii_lowercase();
        if t.starts_with("ext") {
            Some(Self::Ext)
        } else if t == "xfs" {
            Some(Self::Xfs)
        } else {
            None
        }
    }
}

/// Runs host commands; injectable in unit tests.
pub(crate) trait GrowFsCommandRunner {
    fn run(&self, program: &str, args: &[&str]) -> anyhow::Result<CommandOutput>;
}

#[derive(Debug, Clone)]
pub(crate) struct CommandOutput {
    pub status_success: bool,
    pub stdout: String,
    pub stderr: String,
}

/// Production runner via [`std::process::Command`].
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct ProcessGrowFsRunner;

impl GrowFsCommandRunner for ProcessGrowFsRunner {
    fn run(&self, program: &str, args: &[&str]) -> anyhow::Result<CommandOutput> {
        let output = Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .map_err(|e| anyhow::anyhow!("failed to spawn {program}: {e}"))?;
        Ok(CommandOutput {
            status_success: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).trim().to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }
}

/// Resolve block device and fstype for `mount_path` via `findmnt`.
pub(crate) fn resolve_mount_source(
    runner: &dyn GrowFsCommandRunner,
    mount_path: &str,
) -> anyhow::Result<(String, String)> {
    let out = runner.run(
        "findmnt",
        &["-n", "-o", "SOURCE,FSTYPE", "--target", mount_path],
    )?;
    if !out.status_success {
        anyhow::bail!(
            "findmnt failed for mount_path (exit non-zero): {}",
            truncate_err(&out.stderr)
        );
    }
    let line = out.stdout.lines().next().unwrap_or("").trim();
    let mut parts = line.split_whitespace();
    let source = parts
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("findmnt returned no SOURCE for mount"))?
        .to_string();
    let fstype = parts
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("findmnt returned no FSTYPE for mount"))?
        .to_string();
    Ok((source, fstype))
}

fn truncate_err(s: &str) -> String {
    const MAX: usize = 200;
    let t = s.trim();
    if t.len() <= MAX {
        t.to_string()
    } else {
        format!("{}…", &t[..MAX])
    }
}

/// Grow the filesystem for `mount_path` (partition + FS). Idempotent when already grown.
pub(crate) fn grow_filesystem(
    runner: &dyn GrowFsCommandRunner,
    mount_path: &str,
) -> anyhow::Result<GrowFsOutcome> {
    validate_grow_fs_mount_path(mount_path)?;
    let (source, fstype) = resolve_mount_source(runner, mount_path)?;
    let kind = GrowFsKind::from_fstype(&fstype)
        .ok_or_else(|| anyhow::anyhow!("unsupported filesystem type for grow_fs: {fstype}"))?;

    // Best-effort partition grow when SOURCE looks like a partition (e.g. /dev/sda1).
    try_growpart(runner, &source);

    match kind {
        GrowFsKind::Ext => {
            let out = runner.run("resize2fs", &[&source])?;
            if !out.status_success {
                // resize2fs often succeeds with "Nothing to do!" as non-error; treat
                // already-at-size as success when stderr/stdout mention it.
                let combined = format!("{} {}", out.stdout, out.stderr).to_ascii_lowercase();
                if combined.contains("nothing to do") || combined.contains("is already") {
                    return Ok(GrowFsOutcome {
                        mount_path: mount_path.to_string(),
                        fs_type: fstype,
                        device: source,
                        already_grown: true,
                    });
                }
                anyhow::bail!(
                    "resize2fs failed: {}",
                    truncate_err(if out.stderr.is_empty() {
                        &out.stdout
                    } else {
                        &out.stderr
                    })
                );
            }
            let already = format!("{} {}", out.stdout, out.stderr)
                .to_ascii_lowercase()
                .contains("nothing to do");
            Ok(GrowFsOutcome {
                mount_path: mount_path.to_string(),
                fs_type: fstype,
                device: source,
                already_grown: already,
            })
        }
        GrowFsKind::Xfs => {
            // xfs_growfs operates on the mount point, not the device node.
            let out = runner.run("xfs_growfs", &["-d", mount_path])?;
            if !out.status_success {
                anyhow::bail!(
                    "xfs_growfs failed: {}",
                    truncate_err(if out.stderr.is_empty() {
                        &out.stdout
                    } else {
                        &out.stderr
                    })
                );
            }
            Ok(GrowFsOutcome {
                mount_path: mount_path.to_string(),
                fs_type: fstype,
                device: source,
                already_grown: false,
            })
        }
    }
}

fn try_growpart(runner: &dyn GrowFsCommandRunner, source: &str) {
    // Parse /dev/nvme0n1p1 → disk=nvme0n1 part=1; /dev/sda1 → sda + 1.
    let path = Path::new(source);
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    if name.is_empty() {
        return;
    }
    let (disk, part) = if let Some(idx) = name.rfind('p') {
        // nvme0n1p1 style
        let (d, p) = name.split_at(idx);
        let part_num = p.trim_start_matches('p');
        if part_num.chars().all(|c| c.is_ascii_digit()) && !d.is_empty() {
            (d.to_string(), part_num.to_string())
        } else {
            return;
        }
    } else {
        // sda1 style: trailing digits
        let digits_start = name
            .char_indices()
            .rev()
            .take_while(|(_, c)| c.is_ascii_digit())
            .last()
            .map(|(i, _)| i);
        let Some(i) = digits_start else {
            return;
        };
        if i == 0 {
            return;
        }
        (name[..i].to_string(), name[i..].to_string())
    };
    let disk_path = path
        .parent()
        .map_or_else(|| Path::new("/dev").join(&disk), |p| p.join(&disk));
    let disk_s = disk_path.to_string_lossy();
    let _ = runner.run("growpart", &[&disk_s, &part]);
}

#[derive(Debug, Clone)]
pub(crate) struct GrowFsOutcome {
    pub mount_path: String,
    pub fs_type: String,
    pub device: String,
    pub already_grown: bool,
}

/// Execute [`ContainerActionKind::GrowFs`](super::ContainerActionKind::GrowFs).
#[allow(clippy::cognitive_complexity)] // sequential growpart / resize2fs / xfs_growfs steps
pub(super) fn run_grow_fs(
    request: &ContainerActionRequest,
) -> anyhow::Result<ContainerActionResponse> {
    let spec = request
        .grow_fs
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("grow_fs spec missing"))?;
    let mount_path = spec.mount_path.trim();
    tracing::info!(
        target: "parton.grow_fs",
        mount_path = %mount_path,
        "grow_fs starting"
    );
    match grow_filesystem(&ProcessGrowFsRunner, mount_path) {
        Ok(outcome) => {
            tracing::info!(
                target: "parton.grow_fs",
                mount_path = %outcome.mount_path,
                fs_type = %outcome.fs_type,
                outcome = if outcome.already_grown {
                    "already_grown"
                } else {
                    "grown"
                },
                "grow_fs ok"
            );
            Ok(ContainerActionResponse {
                action: request.action,
                container_ref: request.container_ref.clone(),
                success: true,
                message: if outcome.already_grown {
                    "grow_fs already_grown".to_string()
                } else {
                    "grow_fs ok".to_string()
                },
                payload: serde_json::json!({
                    "mount_path": outcome.mount_path,
                    "fs_type": outcome.fs_type,
                    "device": outcome.device,
                    "already_grown": outcome.already_grown,
                }),
            })
        }
        Err(e) => {
            tracing::warn!(
                target: "parton.grow_fs",
                mount_path = %mount_path,
                outcome = "failed",
                error = %e,
                "grow_fs failed"
            );
            Ok(ContainerActionResponse {
                action: request.action,
                container_ref: request.container_ref.clone(),
                success: false,
                message: format!("grow_fs failed: {e}"),
                payload: serde_json::json!({
                    "mount_path": mount_path,
                    "error_class": "agent_failed",
                }),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[test]
    fn validate_rejects_relative_and_dotdot() {
        assert!(validate_grow_fs_mount_path("").is_err());
        assert!(validate_grow_fs_mount_path("var/lib/registry").is_err());
        assert!(validate_grow_fs_mount_path("/var/../etc").is_err());
        assert!(validate_grow_fs_mount_path("/").is_err());
        assert!(validate_grow_fs_mount_path("/var/lib/registry").is_ok());
    }

    #[test]
    fn fstype_dispatch() {
        assert_eq!(GrowFsKind::from_fstype("ext4"), Some(GrowFsKind::Ext));
        assert_eq!(GrowFsKind::from_fstype("EXT3"), Some(GrowFsKind::Ext));
        assert_eq!(GrowFsKind::from_fstype("xfs"), Some(GrowFsKind::Xfs));
        assert_eq!(GrowFsKind::from_fstype("btrfs"), None);
        assert_eq!(GrowFsKind::from_fstype("overlay"), None);
    }

    struct ScriptedRunner {
        responses: Mutex<HashMap<String, CommandOutput>>,
        calls: Mutex<Vec<(String, Vec<String>)>>,
    }

    impl ScriptedRunner {
        fn new(map: HashMap<String, CommandOutput>) -> Self {
            Self {
                responses: Mutex::new(map),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn key(program: &str, args: &[&str]) -> String {
            format!("{program} {}", args.join(" "))
        }
    }

    impl GrowFsCommandRunner for ScriptedRunner {
        fn run(&self, program: &str, args: &[&str]) -> anyhow::Result<CommandOutput> {
            self.calls.lock().expect("lock").push((
                program.to_string(),
                args.iter().map(|s| (*s).to_string()).collect(),
            ));
            let key = Self::key(program, args);
            let map = self.responses.lock().expect("lock");
            if let Some(out) = map.get(&key) {
                return Ok(out.clone());
            }
            // growpart is best-effort; allow program-only key.
            if let Some(out) = map.get(program) {
                return Ok(out.clone());
            }
            anyhow::bail!("no scripted response for {key}")
        }
    }

    #[test]
    fn grow_ext4_happy_path() {
        let mut map = HashMap::new();
        map.insert(
            "findmnt -n -o SOURCE,FSTYPE --target /var/lib/registry".into(),
            CommandOutput {
                status_success: true,
                stdout: "/dev/sda1 ext4".into(),
                stderr: String::new(),
            },
        );
        map.insert(
            "growpart".into(),
            CommandOutput {
                status_success: true,
                stdout: String::new(),
                stderr: String::new(),
            },
        );
        map.insert(
            "resize2fs /dev/sda1".into(),
            CommandOutput {
                status_success: true,
                stdout: "filesystem resized".into(),
                stderr: String::new(),
            },
        );
        let runner = ScriptedRunner::new(map);
        let out = grow_filesystem(&runner, "/var/lib/registry").expect("grow");
        assert_eq!(out.fs_type, "ext4");
        assert!(!out.already_grown);
    }

    #[test]
    fn grow_unsupported_fs_fails_without_resize() {
        let mut map = HashMap::new();
        map.insert(
            "findmnt -n -o SOURCE,FSTYPE --target /data".into(),
            CommandOutput {
                status_success: true,
                stdout: "/dev/sdb1 btrfs".into(),
                stderr: String::new(),
            },
        );
        let runner = ScriptedRunner::new(map);
        let err = grow_filesystem(&runner, "/data").unwrap_err();
        assert!(err.to_string().contains("unsupported"));
        let calls = runner.calls.lock().expect("lock");
        assert!(calls.iter().all(|(p, _)| p == "findmnt"));
    }

    #[test]
    fn grow_already_grown_ext() {
        let mut map = HashMap::new();
        map.insert(
            "findmnt -n -o SOURCE,FSTYPE --target /var/lib/registry".into(),
            CommandOutput {
                status_success: true,
                stdout: "/dev/sda1 ext4".into(),
                stderr: String::new(),
            },
        );
        map.insert(
            "growpart".into(),
            CommandOutput {
                status_success: false,
                stdout: String::new(),
                stderr: "NOCHANGE".into(),
            },
        );
        map.insert(
            "resize2fs /dev/sda1".into(),
            CommandOutput {
                status_success: false,
                stdout: String::new(),
                stderr: "The filesystem is already 12345 blocks long. Nothing to do!".into(),
            },
        );
        let runner = ScriptedRunner::new(map);
        let out = grow_filesystem(&runner, "/var/lib/registry").expect("already");
        assert!(out.already_grown);
    }
}
