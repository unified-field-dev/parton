//! Typed container / host action contracts and Docker CLI execution.
//!
//! # Action kinds
//!
//! [`ContainerActionKind`] covers Docker lifecycle (`Start` … `Deploy`), network and
//! image helpers (`EnsureNetwork`, `EnsureDockerImage`), and agent-local probes
//! (`ProbeHost`, `Diagnostic`, `WireguardPeer`, `GrowFs`, `TemplatedExec`). Queue-only kinds such as
//! `health_check` / `deploy_handoff` live in [`crate::command_queue`] and are not
//! variants of this enum.
//!
//! # How to use
//!
//! Prefer [`execute_container_action`] over calling [`ContainerActionExecutor`]
//! directly: it validates request hygiene (non-empty `container_ref`, required
//! specs per kind, digest / mount / network policy, and optional cosign) before
//! dispatching to the executor ([`DockerCliActionExecutor`] for production).
//!
//! # Security (implemented, default deny)
//!
//! Production agents should leave host networking/mounts denied and digest pinning
//! enabled. Cosign is opt-in via `PARTON_COSIGN_MODE`. Operator checklist:
//! crate root `SECURITY.md` (vulnerability reporting).
//!
//! | Variable | Effect when set truthy / configured |
//! |----------|-------------------------------------|
//! | `PARTON_ALLOW_HOST_NETWORK` | Allow `docker run --network host` |
//! | `PARTON_ALLOW_HOST_MOUNTS` | Allow absolute host bind mounts (some paths always denied) |
//! | `PARTON_ALLOW_MUTABLE_TAGS` | Allow image refs without `@sha256:` digests |
//! | `PARTON_REQUIRE_IMAGE_DIGEST` | When set, overrides mutable-tag allowance |
//! | `PARTON_COSIGN_MODE` | `off` (default) / `key` / `keyless` — verify signatures via cosign before pull/run |
//! | `PARTON_COSIGN_KEY` | Public key path when mode=`key` |
//! | `PARTON_COSIGN_CERTIFICATE_IDENTITY` / `PARTON_COSIGN_CERTIFICATE_OIDC_ISSUER` | Fulcio constraints when mode=`keyless` |
//! | `PARTON_COSIGN_BIN` | Override cosign binary path (tests / non-PATH installs) |
//!
//! # Module layout
//!
//! - [`types`] — wire request/response/spec structs and [`ContainerActionKind`].
//! - [`policy`] — mount/network/digest deny-by-default checks.
//! - [`cosign`] — `cosign verify` before pull/run (`PARTON_COSIGN_MODE`).
//! - [`secret_env`] — secret env var validation and the deploy env-file writer.
//! - [`docker_args`] — typed request → `docker` CLI argument vector construction.
//! - [`docker_exec`] — [`DockerCliActionExecutor`] and its Docker CLI plumbing.
//! - [`diagnostic`] — TCP reachability / latency probes.
//! - [`probe_host`] — native host hardware probe.
//! - [`grow_fs`] — host filesystem grow after cloud volume expand.
//! - [`templated_exec`] — allowlisted in-container engine ops (promote / standby).
//! - [`wireguard`] — `wg set` peer application.

mod cosign;
mod diagnostic;
mod docker_args;
mod docker_exec;
mod grow_fs;
mod policy;
mod probe_host;
mod secret_env;
mod templated_exec;
#[cfg(test)]
mod tests;
mod types;
mod wireguard;

use cosign::verify_image_signature;
use policy::{validate_image_digest_policy, validate_network_policy, validate_volume_mount_policy};

pub use docker_exec::DockerCliActionExecutor;
pub use secret_env::{
    validate_deploy_secret_env_entry, validate_deploy_secret_env_name,
    validate_deploy_secret_env_vars, write_deploy_secret_env_file,
};
pub use types::{
    ContainerActionKind, ContainerActionRequest, ContainerActionResponse, ContainerHealthCheck,
    DiagnosticMode, DiagnosticSpec, GrowFsSpec, ResourceLimits, SecretEnvVar, TemplatedExecId,
    TemplatedExecParams, TemplatedExecSpec, VolumeMount, WireguardPeerSpec,
};

/// Abstraction for action execution backends (Docker CLI today, transport in future).
pub trait ContainerActionExecutor {
    /// Execute one already-validated container action.
    ///
    /// # Contract
    ///
    /// Callers should route requests through [`execute_container_action`], which enforces
    /// request hygiene (non-empty `container_ref`, required specs per action kind) before
    /// dispatching here. Implementations may assume those invariants hold.
    ///
    /// # Errors
    ///
    /// Returns an error when the backend cannot perform the action (e.g. the Docker CLI
    /// invocation fails or a required spec is missing).
    fn execute_action(
        &self,
        request: &ContainerActionRequest,
    ) -> anyhow::Result<ContainerActionResponse>;
}

fn log_deploy_deny(node_id: &str, image_ref: &str, reason: &anyhow::Error, msg: &str) {
    tracing::warn!(
        target: "security.deploy",
        node_id = %node_id,
        image_ref = %image_ref,
        reason = %reason,
        "{msg}"
    );
}

fn valid_port_mapping(mapping: &str) -> bool {
    let p = mapping.trim();
    let parts: Vec<&str> = p.split(':').collect();
    match parts.len() {
        2 => parts[0].parse::<u16>().is_ok() && parts[1].parse::<u16>().is_ok(),
        3 => {
            !parts[0].trim().is_empty()
                && parts[1].parse::<u16>().is_ok()
                && parts[2].parse::<u16>().is_ok()
        }
        _ => false,
    }
}

fn validate_deploy_request(
    request: &ContainerActionRequest,
    image_ref: &str,
) -> anyhow::Result<()> {
    if let Err(e) = validate_image_digest_policy(image_ref) {
        log_deploy_deny(
            &request.node_id,
            image_ref,
            &e,
            "deploy denied by image digest policy",
        );
        return Err(e);
    }
    if let Err(e) = validate_network_policy(request.network.as_deref()) {
        log_deploy_deny(
            &request.node_id,
            image_ref,
            &e,
            "deploy denied by network policy",
        );
        return Err(e);
    }
    if let Err(e) = validate_volume_mount_policy(&request.volume_mounts) {
        log_deploy_deny(
            &request.node_id,
            image_ref,
            &e,
            "deploy denied by volume mount policy",
        );
        return Err(e);
    }
    for mapping in &request.port_mappings {
        if !valid_port_mapping(mapping) {
            anyhow::bail!(
                "invalid port mapping '{mapping}': expected host:container or bind:host:container"
            );
        }
    }
    if !request.secret_env_vars.is_empty() {
        validate_deploy_secret_env_vars(&request.secret_env_vars)?;
    }
    if let Err(e) = verify_image_signature(image_ref) {
        log_deploy_deny(
            &request.node_id,
            image_ref,
            &e,
            "deploy denied by cosign verify",
        );
        return Err(e);
    }
    Ok(())
}

fn validate_ensure_image_request(
    request: &ContainerActionRequest,
    image_ref: &str,
) -> anyhow::Result<()> {
    if let Err(e) = validate_image_digest_policy(image_ref) {
        log_deploy_deny(
            &request.node_id,
            image_ref,
            &e,
            "ensure_docker_image denied by image digest policy",
        );
        return Err(e);
    }
    if let Err(e) = verify_image_signature(image_ref) {
        log_deploy_deny(
            &request.node_id,
            image_ref,
            &e,
            "ensure_docker_image denied by cosign verify",
        );
        return Err(e);
    }
    Ok(())
}

/// Validate request invariants before delegating to the selected executor.
///
/// # Errors
///
/// Returns an error when `container_ref` is blank, when a required spec is missing for the
/// selected action (diagnostic / wireguard / deploy image / port mappings / secret env),
/// when digest / mount / network / cosign policy denies the request, or when the executor
/// itself fails.
///
/// # Examples
///
/// ```no_run
/// use parton::{
///     execute_container_action, ContainerActionKind, ContainerActionRequest, DockerCliActionExecutor,
/// };
///
/// # fn main() -> anyhow::Result<()> {
/// let request = ContainerActionRequest {
///     node_id: "node-1".to_string(),
///     container_ref: "my-service".to_string(),
///     action: ContainerActionKind::Inspect,
///     tail_lines: None,
///     image_ref: None,
///     env_vars: vec![],
///     secret_env_vars: vec![],
///     port_mappings: vec![],
///     entrypoint: None,
///     command: vec![],
///     restart_policy: None,
///     volume_mounts: vec![],
///     resource_limits: None,
///     health_check: None,
///     labels: Default::default(),
///     extra_hosts: vec![],
///     network: None,
///     diagnostic: None,
///     wireguard_peer: None,
///     grow_fs: None,
///     templated_exec: None,
///     expected_container_id: None,
/// };
/// let response = execute_container_action(&DockerCliActionExecutor, &request)?;
/// assert!(response.success || !response.message.is_empty());
/// # Ok(())
/// # }
/// ```
pub fn execute_container_action<E: ContainerActionExecutor>(
    executor: &E,
    request: &ContainerActionRequest,
) -> anyhow::Result<ContainerActionResponse> {
    // Common request hygiene checks for all executor backends.
    let container_ref = request.container_ref.trim();
    if container_ref.is_empty() {
        anyhow::bail!("container_ref is required");
    }
    if matches!(request.action, ContainerActionKind::Diagnostic) && request.diagnostic.is_none() {
        anyhow::bail!("diagnostic spec is required for diagnostic");
    }
    if matches!(request.action, ContainerActionKind::WireguardPeer)
        && request.wireguard_peer.is_none()
    {
        anyhow::bail!("wireguard_peer spec is required for wireguard_peer");
    }
    if matches!(request.action, ContainerActionKind::GrowFs) && request.grow_fs.is_none() {
        anyhow::bail!("grow_fs spec is required for grow_fs");
    }
    if matches!(request.action, ContainerActionKind::GrowFs) {
        if let Some(spec) = request.grow_fs.as_ref() {
            grow_fs::validate_grow_fs_mount_path(&spec.mount_path)?;
        }
    }
    if matches!(request.action, ContainerActionKind::TemplatedExec)
        && request.templated_exec.is_none()
    {
        anyhow::bail!("templated_exec spec is required for templated_exec");
    }
    if matches!(request.action, ContainerActionKind::Deploy) {
        let image_ref = request
            .image_ref
            .as_ref()
            .map(|value| value.trim())
            .unwrap_or_default();
        if image_ref.is_empty() {
            anyhow::bail!("image_ref is required for deploy");
        }
        validate_deploy_request(request, image_ref)?;
        tracing::info!(
            target: "security.deploy",
            node_id = %request.node_id,
            container_ref = %container_ref,
            image_ref = %image_ref,
            "deploy policy checks passed; starting executor"
        );
    }
    if matches!(request.action, ContainerActionKind::EnsureDockerImage) {
        let image_ref = request
            .image_ref
            .as_ref()
            .map(|value| value.trim())
            .filter(|s| !s.is_empty());
        let Some(image_ref) = image_ref else {
            anyhow::bail!("image_ref is required for ensure_docker_image");
        };
        validate_ensure_image_request(request, image_ref)?;
    }
    executor.execute_action(request)
}
