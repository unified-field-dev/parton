//! In-process host hardware snapshot for the Parton native `probe_host` path.
//!
//! Parton owns this schema for fleet capacity / placement (`ProbeHost` + heartbeat mounts).

use serde::Serialize;

/// Per-mount disk capacity, useful for placement decisions that need precise headroom on a
/// specific volume (e.g. `/var/lib/docker`) rather than the coarse host-wide GB sum.
#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq)]
pub struct MountInfo {
    /// Filesystem mount point (e.g. `/`, `/var/lib/docker`).
    pub mount_point: String,
    /// Filesystem type reported by the OS (e.g. `ext4`, `overlay`, `xfs`).
    pub file_system: String,
    /// Total capacity of this mount, in bytes.
    pub total_bytes: u64,
    /// Available (free) capacity of this mount, in bytes.
    pub available_bytes: u64,
    /// Total capacity of this mount, in gibibytes (convenience for callers that only need GB).
    pub total_gb: u64,
    /// Available capacity of this mount, in gibibytes (convenience for callers that only need GB).
    pub available_gb: u64,
    /// `true` when the underlying disk reports as removable media (deprioritize for placement).
    pub is_removable: bool,
}

/// Serializable host probe output with stable keys for control plane / orchestrator merge.
#[derive(Debug, Clone, Serialize)]
pub struct HostInfoJson {
    /// Number of logical CPU cores available to the agent process.
    pub cpu_cores: u32,
    /// Total physical RAM in mebibytes.
    pub ram_mb: u64,
    /// Sum of total disk capacity across mounted filesystems, in gibibytes.
    pub disk_total_gb: u64,
    /// Sum of available disk space across mounted filesystems, in gibibytes.
    pub disk_free_gb: u64,
    /// Per-mount disk capacity breakdown (see [`MountInfo`]); empty when `sysinfo` reports no
    /// mounted filesystems. Placement logic should prefer this over the coarse
    /// [`Self::disk_total_gb`] / [`Self::disk_free_gb`] sums when a specific mount matters
    /// (e.g. the volume backing the Docker data root).
    pub mounts: Vec<MountInfo>,
    /// Primary NIC link speed in megabits per second (`0` when not probed).
    pub nic_speed_mbps: u32,
    /// Kernel version string (empty when unavailable).
    pub kernel: String,
    /// Long OS description, falling back to the OS name.
    pub os: String,
    /// Target CPU architecture (e.g. `x86_64`, `aarch64`).
    pub arch: String,
}

/// Enumerate mounted filesystems via `sysinfo`, shared by [`collect_host_info`] (native
/// `probe_host`) and `crate::heartbeat::collect_host_capabilities` (periodic heartbeat) so both
/// payloads carry the same per-mount capacity fields for placement decisions.
pub fn collect_mounts() -> Vec<MountInfo> {
    let disks = sysinfo::Disks::new_with_refreshed_list();
    let mut mounts = Vec::with_capacity(disks.len());
    for d in &disks {
        let total_bytes = d.total_space();
        let available_bytes = d.available_space();
        mounts.push(MountInfo {
            mount_point: d.mount_point().display().to_string(),
            file_system: d.file_system().to_string_lossy().to_string(),
            total_bytes,
            available_bytes,
            total_gb: total_bytes / 1024 / 1024 / 1024,
            available_gb: available_bytes / 1024 / 1024 / 1024,
            is_removable: d.is_removable(),
        });
    }
    mounts
}

/// Collect CPU, RAM, disk, and OS information using `sysinfo`.
pub fn collect_host_info() -> HostInfoJson {
    let cpu_cores = std::thread::available_parallelism()
        .map_or(1, |n| u32::try_from(n.get()).unwrap_or(u32::MAX));

    let mut sys = sysinfo::System::new_all();
    sys.refresh_cpu_all();
    sys.refresh_memory();
    let ram_mb = sys.total_memory() / 1024 / 1024;

    let mounts = collect_mounts();
    let disk_total_gb = mounts.iter().map(|m| m.total_gb).sum();
    let disk_free_gb = mounts.iter().map(|m| m.available_gb).sum();

    let kernel = sysinfo::System::kernel_version().unwrap_or_default();
    let os = sysinfo::System::long_os_version()
        .unwrap_or_else(|| sysinfo::System::name().unwrap_or_default());
    let arch = std::env::consts::ARCH.to_string();

    HostInfoJson {
        cpu_cores,
        ram_mb,
        disk_total_gb,
        disk_free_gb,
        mounts,
        nic_speed_mbps: 0,
        kernel,
        os,
        arch,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_host_info_reports_at_least_one_mount_with_positive_capacity() {
        let info = collect_host_info();
        assert!(info.cpu_cores >= 1);
        assert!(
            !info.mounts.is_empty(),
            "expected at least one mounted filesystem to be reported"
        );
        for mount in &info.mounts {
            assert!(!mount.mount_point.is_empty());
            assert!(mount.total_bytes >= mount.available_bytes);
            assert_eq!(mount.total_gb, mount.total_bytes / 1024 / 1024 / 1024);
            assert_eq!(
                mount.available_gb,
                mount.available_bytes / 1024 / 1024 / 1024
            );
        }
    }

    #[test]
    fn collect_host_info_mount_sums_match_legacy_disk_totals() {
        let info = collect_host_info();
        let summed_total: u64 = info.mounts.iter().map(|m| m.total_gb).sum();
        let summed_free: u64 = info.mounts.iter().map(|m| m.available_gb).sum();
        assert_eq!(summed_total, info.disk_total_gb);
        assert_eq!(summed_free, info.disk_free_gb);
    }
}
