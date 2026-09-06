//! Deny-by-default host network / host mount / image digest policy checks.
//!
//! Enforced from [`super::execute_container_action`] before a request ever reaches an executor.

use super::types::VolumeMount;

/// Absolute host paths that are never mountable into a container, even with
/// `PARTON_ALLOW_HOST_MOUNTS=1` — bind-mounting any of these is roughly equivalent to granting
/// the container root on the host.
const ALWAYS_DENIED_HOST_MOUNT_PATHS: &[&str] = &[
    "/",
    "/etc",
    "/root",
    "/boot",
    "/proc",
    "/sys",
    "/var/run/docker.sock",
    "/var/lib/docker",
];

fn env_flag_truthy(name: &str) -> bool {
    std::env::var(name).is_ok_and(|v| {
        matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

/// `PARTON_ALLOW_HOST_NETWORK=1` opts into `docker run --network host` (default deny — host
/// networking lets the container see/bind every port on the host's network namespace).
fn allow_host_network() -> bool {
    env_flag_truthy("PARTON_ALLOW_HOST_NETWORK")
}

/// `PARTON_ALLOW_HOST_MOUNTS=1` opts into bind-mounting absolute host paths (default deny —
/// [`ALWAYS_DENIED_HOST_MOUNT_PATHS`] stays denied regardless).
fn allow_host_mounts() -> bool {
    env_flag_truthy("PARTON_ALLOW_HOST_MOUNTS")
}

/// `PARTON_ALLOW_MUTABLE_TAGS=1` opts out of the `@sha256:` digest requirement on deploy /
/// `ensure_docker_image`; `PARTON_REQUIRE_IMAGE_DIGEST`, when explicitly set, overrides both.
fn require_image_digest() -> bool {
    if let Ok(raw) = std::env::var("PARTON_REQUIRE_IMAGE_DIGEST") {
        return matches!(
            raw.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        );
    }
    !env_flag_truthy("PARTON_ALLOW_MUTABLE_TAGS")
}

fn normalize_host_mount_path(path: &str) -> String {
    let p = path.trim();
    if p.len() > 1 {
        p.trim_end_matches('/').to_string()
    } else {
        p.to_string()
    }
}

/// Enforces the host-network deny-by-default policy for `docker run --network <net>`.
///
/// # Errors
///
/// Returns an error when `network` is `host` (case-insensitive) and
/// `PARTON_ALLOW_HOST_NETWORK=1` was not set.
pub(super) fn validate_network_policy(network: Option<&str>) -> anyhow::Result<()> {
    let Some(net) = network.map(str::trim).filter(|n| !n.is_empty()) else {
        return Ok(());
    };
    if net.eq_ignore_ascii_case("host") && !allow_host_network() {
        anyhow::bail!(
            "refusing deploy with network=host: set PARTON_ALLOW_HOST_NETWORK=1 to allow host \
             networking (default deny — it exposes the container to every port on the host's \
             network namespace)"
        );
    }
    Ok(())
}

/// Enforces the host-mount deny-by-default policy for `docker run -v <host_path>:<container_path>`.
///
/// Named volumes (`host_path` without a leading `/`) are always allowed; they're managed by
/// Docker, not raw host filesystem access.
///
/// # Errors
///
/// Returns an error when `host_path` is an absolute path in [`ALWAYS_DENIED_HOST_MOUNT_PATHS`]
/// (always denied), or any other absolute path without `PARTON_ALLOW_HOST_MOUNTS=1` set.
pub(super) fn validate_volume_mount_policy(mounts: &[VolumeMount]) -> anyhow::Result<()> {
    for mount in mounts {
        let host_path = mount.host_path.trim();
        if !host_path.starts_with('/') {
            continue;
        }
        let normalized = normalize_host_mount_path(host_path);
        if ALWAYS_DENIED_HOST_MOUNT_PATHS.contains(&normalized.as_str()) {
            anyhow::bail!(
                "refusing to mount host path `{host_path}`: always-denied sensitive path (not \
                 overridable by PARTON_ALLOW_HOST_MOUNTS)"
            );
        }
        if !allow_host_mounts() {
            anyhow::bail!(
                "refusing to mount absolute host path `{host_path}`: set \
                 PARTON_ALLOW_HOST_MOUNTS=1 to allow bind-mounting host paths into containers \
                 (default deny)"
            );
        }
    }
    Ok(())
}

/// Enforces the pinned-image-digest policy for `deploy` / `ensure_docker_image`.
///
/// # Errors
///
/// Returns an error when [`require_image_digest`] is enabled and `image_ref` has no `@sha256:`
/// digest suffix.
pub(super) fn validate_image_digest_policy(image_ref: &str) -> anyhow::Result<()> {
    if !require_image_digest() {
        return Ok(());
    }
    if !image_ref.to_ascii_lowercase().contains("@sha256:") {
        anyhow::bail!(
            "image_ref `{image_ref}` has no `@sha256:<digest>` pin: set \
             PARTON_ALLOW_MUTABLE_TAGS=1 to allow mutable tags (default deny — a mutable tag can \
             be repointed at a different image after review)"
        );
    }
    Ok(())
}
