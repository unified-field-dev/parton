//! Static host capability snapshot (hostname, arch, CPU, memory, mounts).

use serde::{Deserialize, Serialize};

/// Static host capability snapshot attached to each heartbeat report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HostCapabilities {
    /// Host name as detected from `HOSTNAME` or `/etc/hostname`.
    pub hostname: String,
    /// Target CPU architecture (e.g. `x86_64`, `aarch64`).
    pub arch: String,
    /// Number of logical CPUs available to the agent process.
    pub cpu_logical: usize,
    /// Total physical memory in bytes (`0` when unavailable).
    pub memory_bytes: u64,
    /// Per-mount disk capacity (total/available bytes), useful for placement decisions that need
    /// headroom on a specific volume rather than relying on a separate `probe_host` round-trip.
    #[serde(default)]
    pub mounts: Vec<crate::host_info::MountInfo>,
    /// Free-form JSON labels describing the host (rack, zone, etc.).
    pub labels: serde_json::Value,
}

fn detect_hostname() -> String {
    let from_env = std::env::var("HOSTNAME")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    if let Some(hostname) = from_env {
        return hostname;
    }

    let from_file = std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    if let Some(hostname) = from_file {
        return hostname;
    }

    "local-agent-node".to_string()
}

fn detect_memory_bytes() -> u64 {
    let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") else {
        return 0;
    };
    parse_memtotal_bytes_from_meminfo(&meminfo).unwrap_or(0)
}

pub(super) fn parse_memtotal_bytes_from_meminfo(meminfo: &str) -> Option<u64> {
    let line = meminfo
        .lines()
        .find(|line| line.trim_start().starts_with("MemTotal:"))?;
    let kib = line
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse::<u64>().ok())?;
    Some(kib.saturating_mul(1024))
}

/// Collect host-level attributes from local runtime and kernel facilities.
// Returns `Result` to keep the heartbeat builder API fallible as host probes gain fallible sources.
#[allow(clippy::unnecessary_wraps)]
pub(crate) fn collect_host_capabilities() -> anyhow::Result<HostCapabilities> {
    let hostname = detect_hostname();
    let arch = std::env::consts::ARCH.to_string();
    let cpu_logical = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
    Ok(HostCapabilities {
        hostname,
        arch,
        cpu_logical,
        memory_bytes: detect_memory_bytes(),
        mounts: crate::host_info::collect_mounts(),
        labels: serde_json::json!({}),
    })
}
