//! `WireGuard` peer application (`wg set`) for [`super::types::ContainerActionKind::WireguardPeer`].

use super::types::{ContainerActionRequest, ContainerActionResponse, WireguardPeerSpec};
use anyhow::Context;
use base64::Engine;
use std::process::{Command, Output};

/// Validate a [`WireguardPeerSpec`] before it is ever handed to `wg`.
///
/// # Errors
///
/// Returns an error when `peer_public_key` is not a base64-encoded 32-byte Curve25519 key,
/// `endpoint` is not a well-formed `host:port` pair with a non-zero port, or `allowed_ips`
/// is empty or contains an entry that is not a valid `ip/prefix` CIDR.
pub(super) fn validate_wireguard_peer_spec(spec: &WireguardPeerSpec) -> anyhow::Result<()> {
    let pubkey = spec.peer_public_key.trim();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(pubkey)
        .map_err(|e| anyhow::anyhow!("wireguard_peer.peer_public_key is not valid base64: {e}"))?;
    if decoded.len() != 32 {
        anyhow::bail!(
            "wireguard_peer.peer_public_key must decode to 32 bytes (got {})",
            decoded.len()
        );
    }

    let endpoint = spec.endpoint.trim();
    let (host, port_str) = endpoint
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("wireguard_peer.endpoint must be `host:port`"))?;
    if host.trim().is_empty() {
        anyhow::bail!("wireguard_peer.endpoint host is empty");
    }
    let port: u16 = port_str.parse().map_err(|_| {
        anyhow::anyhow!("wireguard_peer.endpoint port `{port_str}` is not a valid port number")
    })?;
    if port == 0 {
        anyhow::bail!("wireguard_peer.endpoint port must be nonzero");
    }

    let allowed_ips = spec.allowed_ips.trim();
    if allowed_ips.is_empty() {
        anyhow::bail!("wireguard_peer.allowed_ips is empty");
    }
    for cidr in allowed_ips.split(',') {
        let cidr = cidr.trim();
        if cidr.is_empty() {
            anyhow::bail!("wireguard_peer.allowed_ips contains an empty entry");
        }
        let (ip_str, prefix_str) = cidr.split_once('/').ok_or_else(|| {
            anyhow::anyhow!("wireguard_peer.allowed_ips entry `{cidr}` must be CIDR (ip/prefix)")
        })?;
        let ip: std::net::IpAddr = ip_str.parse().map_err(|_| {
            anyhow::anyhow!("wireguard_peer.allowed_ips entry `{cidr}` has an invalid IP address")
        })?;
        let prefix: u8 = prefix_str.parse().map_err(|_| {
            anyhow::anyhow!("wireguard_peer.allowed_ips entry `{cidr}` has an invalid prefix")
        })?;
        let max_prefix = if ip.is_ipv4() { 32 } else { 128 };
        if prefix > max_prefix {
            anyhow::bail!("wireguard_peer.allowed_ips entry `{cidr}` prefix exceeds /{max_prefix}");
        }
    }

    Ok(())
}

/// Abstraction over invoking the `wg` CLI so tests can mock it without a real Wireguard
/// interface on the host (mirrors [`super::docker_exec::DockerCommandRunner`]).
pub(super) trait WgCommandRunner {
    fn run(&self, args: &[String]) -> anyhow::Result<Output>;
}

/// [`WgCommandRunner`] backed by the real `wg` binary on `PATH`.
struct SystemWgCommandRunner;

impl WgCommandRunner for SystemWgCommandRunner {
    fn run(&self, args: &[String]) -> anyhow::Result<Output> {
        Command::new("wg").args(args).output().with_context(|| {
            format!(
                "run `wg {}` (is wireguard-tools installed on PATH?)",
                args.join(" ")
            )
        })
    }
}

/// Apply a Wireguard peer stanza via `wg set <interface> peer <pubkey> endpoint <ep> allowed-ips <ips>`.
///
/// `container_ref` names the target Wireguard interface (mirrors how [`super::types::ContainerActionKind::EnsureNetwork`]
/// uses `container_ref` as the Docker network name).
///
/// # Errors
///
/// Fails closed: returns an error (never a synthetic success) when the spec fails validation,
/// `container_ref` is blank, the `wg` binary is missing from `PATH`, or `wg set` exits non-zero.
pub(super) fn wireguard_peer_response_with_runner<R: WgCommandRunner>(
    request: &ContainerActionRequest,
    runner: &R,
) -> anyhow::Result<ContainerActionResponse> {
    let spec = request
        .wireguard_peer
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("wireguard_peer spec missing"))?;
    validate_wireguard_peer_spec(spec)?;

    let interface = request.container_ref.trim();
    if interface.is_empty() {
        anyhow::bail!("container_ref (wireguard interface name) is required for wireguard_peer");
    }

    let args = vec![
        "set".to_string(),
        interface.to_string(),
        "peer".to_string(),
        spec.peer_public_key.trim().to_string(),
        "endpoint".to_string(),
        spec.endpoint.trim().to_string(),
        "allowed-ips".to_string(),
        spec.allowed_ips.trim().to_string(),
    ];

    let output = runner.run(&args).map_err(|e| {
        anyhow::anyhow!(
            "wg set failed to run on interface `{interface}` \
             (is `wg` / wireguard-tools installed and on PATH?): {e}"
        )
    })?;

    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        anyhow::bail!(
            "wg {} failed (exit={}): {}{}{}",
            args.join(" "),
            output.status.code().unwrap_or(-1),
            stdout,
            if !stdout.is_empty() && !stderr.is_empty() {
                " | "
            } else {
                ""
            },
            stderr,
        );
    }

    Ok(ContainerActionResponse {
        action: request.action,
        container_ref: request.container_ref.clone(),
        success: true,
        message: "wireguard_peer applied".to_string(),
        payload: serde_json::json!({
            "interface": interface,
            "peer_public_key": spec.peer_public_key,
            "endpoint": spec.endpoint,
            "allowed_ips": spec.allowed_ips,
        }),
    })
}

pub(super) fn wireguard_peer_response(
    request: &ContainerActionRequest,
) -> anyhow::Result<ContainerActionResponse> {
    wireguard_peer_response_with_runner(request, &SystemWgCommandRunner)
}
