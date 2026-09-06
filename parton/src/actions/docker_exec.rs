//! Docker CLI execution: image ensure, general lifecycle actions, identity guards, and the
//! [`super::ContainerActionExecutor`] implementation backed by the real `docker` binary.

use super::diagnostic::run_diagnostic;
use super::docker_args::docker_args_for_action;
use super::grow_fs::run_grow_fs;
use super::probe_host::probe_host_response;
use super::secret_env::write_deploy_secret_env_file;
use super::templated_exec::run_templated_exec;
use super::types::{ContainerActionKind, ContainerActionRequest, ContainerActionResponse};
use super::wireguard::wireguard_peer_response;
use super::ContainerActionExecutor;
use anyhow::Context;
use std::process::{Command, Output};

// Keep command construction and process execution separated so tests can
// validate argument shaping without invoking a local Docker daemon.

pub(super) trait DockerCommandRunner {
    fn run(&self, args: &[String]) -> anyhow::Result<Output>;
}

struct SystemDockerCommandRunner;

impl DockerCommandRunner for SystemDockerCommandRunner {
    fn run(&self, args: &[String]) -> anyhow::Result<Output> {
        Command::new("docker").args(args).output().with_context(|| {
            format!(
                "run `docker {}` (is docker installed on PATH?)",
                args.join(" ")
            )
        })
    }
}

/// [`ContainerActionExecutor`] backed by the local Docker CLI (`docker …` via `std::process`).
pub struct DockerCliActionExecutor;

/// `docker image inspect` then `docker pull` until the image is present, or return an actionable error.
pub(super) fn ensure_docker_image_with_runner<R: DockerCommandRunner>(
    image: &str,
    runner: &R,
) -> anyhow::Result<(&'static str, serde_json::Value)> {
    let image = image.trim();
    if image.is_empty() {
        anyhow::bail!("registry image ref is empty");
    }
    let inspect = runner.run(&[
        "image".to_string(),
        "inspect".to_string(),
        image.to_string(),
    ])?;
    if inspect.status.success() {
        return Ok((
            "inspect",
            serde_json::json!({
                "image_ref": image,
                "registry_image_preflight": "inspect",
            }),
        ));
    }
    let pull = runner.run(&["pull".to_string(), image.to_string()])?;
    if pull.status.success() {
        return Ok((
            "pull",
            serde_json::json!({
                "image_ref": image,
                "registry_image_preflight": "pull",
            }),
        ));
    }
    let stdout_i = String::from_utf8_lossy(&inspect.stdout).trim().to_string();
    let stderr_i = String::from_utf8_lossy(&inspect.stderr).trim().to_string();
    let stdout_p = String::from_utf8_lossy(&pull.stdout).trim().to_string();
    let stderr_p = String::from_utf8_lossy(&pull.stderr).trim().to_string();
    anyhow::bail!(
        "selected host cannot use registry runtime image `{image}` (not cached and pull failed). \
         Preload or mirror this image on the agent host, point `PARTON_REGISTRY_IMAGE_REF` at a reachable registry, \
         or use a future air-gapped tarball path. inspect: {stdout_i}{sep_i}{stderr_i} | pull: {stdout_p}{sep_p}{stderr_p}",
        sep_i = if !stdout_i.is_empty() && !stderr_i.is_empty() {
            " | "
        } else {
            ""
        },
        sep_p = if !stdout_p.is_empty() && !stderr_p.is_empty() {
            " | "
        } else {
            ""
        },
    );
}

/// Run a docker command and normalize stdout/stderr into one user-facing payload.
pub(super) fn run_docker_command_with_runner<R: DockerCommandRunner>(
    runner: &R,
    args: &[String],
) -> anyhow::Result<String> {
    let output = runner.run(args)?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if output.status.success() {
        // For some Docker calls useful output may arrive on stderr; preserve it.
        if stdout.is_empty() {
            return Ok(stderr);
        }
        return Ok(stdout);
    }
    let status = output.status.code().unwrap_or_default();
    anyhow::bail!(
        "docker {} failed (exit={}): {}{}{}",
        args.join(" "),
        status,
        stdout,
        if !stdout.is_empty() && !stderr.is_empty() {
            " | "
        } else {
            ""
        },
        stderr
    );
}

pub(super) fn normalize_docker_id(raw: &str) -> String {
    let s = raw.trim().to_lowercase();
    s.strip_prefix("sha256:")
        .unwrap_or(s.as_str())
        .trim()
        .to_string()
}

/// Returns the Docker daemon id for `container_ref` (name or id), or `None` if absent.
fn docker_inspect_container_id(container_ref: &str) -> anyhow::Result<Option<String>> {
    let name = container_ref.trim();
    if name.is_empty() {
        return Ok(None);
    }
    let out = Command::new("docker")
        .args(["inspect", "-f", "{{.Id}}", name])
        .output()
        .with_context(|| format!("run `docker inspect {name}` (is docker installed on PATH?)"))?;
    if !out.status.success() {
        return Ok(None);
    }
    let id = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if id.is_empty() {
        Ok(None)
    } else {
        Ok(Some(id))
    }
}

fn identity_skip_response(
    request: &ContainerActionRequest,
    reason: &str,
    extra: serde_json::Value,
) -> ContainerActionResponse {
    let mut payload = serde_json::json!({
        "skipped": true,
        "reason": reason,
    });
    if let serde_json::Value::Object(ref mut m) = payload {
        if let serde_json::Value::Object(x) = extra {
            for (k, v) in x {
                m.insert(k.clone(), v.clone());
            }
        }
    }
    ContainerActionResponse {
        action: request.action,
        container_ref: request.container_ref.clone(),
        success: true,
        message: format!("{} skipped ({reason})", request.action.as_str()),
        payload,
    }
}

/// When `expected_container_id` is set, skip `Stop`/`Restart` if the name is absent or points at a different container.
fn maybe_identity_skip_stop_restart(
    request: &ContainerActionRequest,
) -> anyhow::Result<Option<ContainerActionResponse>> {
    if !matches!(
        request.action,
        ContainerActionKind::Stop | ContainerActionKind::Restart
    ) {
        return Ok(None);
    }
    let expected_raw = request
        .expected_container_id
        .as_deref()
        .unwrap_or("")
        .trim();
    if expected_raw.is_empty() {
        return Ok(None);
    }
    let name = request.container_ref.trim();
    let actual = docker_inspect_container_id(name)?;
    let expected_norm = normalize_docker_id(expected_raw);
    match &actual {
        None => Ok(Some(identity_skip_response(
            request,
            "container_absent",
            serde_json::json!({}),
        ))),
        Some(actual_id) => {
            if normalize_docker_id(actual_id) == expected_norm {
                Ok(None)
            } else {
                Ok(Some(identity_skip_response(
                    request,
                    "container_id_mismatch",
                    serde_json::json!({
                        "expected_container_id": expected_raw,
                        "actual_container_id": actual_id,
                    }),
                )))
            }
        }
    }
}

/// Pre-`docker run` cleanup for deploy: only remove an existing container when identity matches expectations.
fn guarded_deploy_precleanup(request: &ContainerActionRequest) -> anyhow::Result<()> {
    let name = request.container_ref.trim();
    let exp = request
        .expected_container_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let actual = docker_inspect_container_id(name)?;
    match (exp, actual.as_deref()) {
        (None | Some(_), None) => Ok(()),
        (None, Some(_)) => {
            let _ = Command::new("docker").args(["stop", name]).output();
            let _ = Command::new("docker").args(["rm", name]).output();
            Ok(())
        }
        (Some(e), Some(a)) => {
            if normalize_docker_id(a) == normalize_docker_id(e) {
                let _ = Command::new("docker").args(["stop", name]).output();
                let _ = Command::new("docker").args(["rm", name]).output();
                Ok(())
            } else {
                anyhow::bail!(
                    "container name `{name}` is occupied by container id `{a}`; \
                     refusing deploy while expected id was `{e}` (stale deploy / name reuse guard)"
                );
            }
        }
    }
}

fn ensure_docker_image_response(
    request: &ContainerActionRequest,
) -> anyhow::Result<ContainerActionResponse> {
    let image = request
        .image_ref
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("image_ref is required for ensure_docker_image"))?;
    let runner = SystemDockerCommandRunner;
    let (preflight, payload) = ensure_docker_image_with_runner(image, &runner)?;
    Ok(ContainerActionResponse {
        action: request.action,
        container_ref: request.container_ref.clone(),
        success: true,
        message: format!("ensure_docker_image ok ({preflight})"),
        payload,
    })
}

fn ensure_network_response(
    request: &ContainerActionRequest,
) -> anyhow::Result<ContainerActionResponse> {
    let name = request.container_ref.trim();
    let runner = SystemDockerCommandRunner;
    let inspect = runner.run(&[
        "network".to_string(),
        "inspect".to_string(),
        name.to_string(),
    ])?;
    if inspect.status.success() {
        return Ok(ContainerActionResponse {
            action: request.action,
            container_ref: request.container_ref.clone(),
            success: true,
            message: format!("{} succeeded", request.action.as_str()),
            payload: serde_json::json!({ "network": name, "created": false }),
        });
    }
    let create = runner.run(&[
        "network".to_string(),
        "create".to_string(),
        name.to_string(),
    ])?;
    if !create.status.success() {
        let stdout = String::from_utf8_lossy(&create.stdout);
        let stderr = String::from_utf8_lossy(&create.stderr);
        anyhow::bail!(
            "docker network create {name} failed (exit={}): {stdout} {stderr}",
            create.status.code().unwrap_or(-1),
        );
    }
    Ok(ContainerActionResponse {
        action: request.action,
        container_ref: request.container_ref.clone(),
        success: true,
        message: format!("{} succeeded", request.action.as_str()),
        payload: serde_json::json!({ "network": name, "created": true }),
    })
}

/// Redacts `NAME=value` env var entries to `NAME=[REDACTED]` for inclusion in action results.
///
/// `env_vars` is meant for non-secret configuration (secrets should use `secret_env_vars`), but
/// operators sometimes pass sensitive values here by mistake; results are persisted and surfaced
/// back to the control plane / UIs, so values are never echoed regardless of intent.
pub(super) fn redact_env_var_values(env_vars: &[String]) -> Vec<String> {
    env_vars
        .iter()
        .map(|entry| {
            entry.split_once('=').map_or_else(
                || entry.clone(),
                |(name, _value)| format!("{name}=[REDACTED]"),
            )
        })
        .collect()
}

/// Build the action-specific payload for the general Docker CLI execution path.
pub(super) fn general_action_payload(
    request: &ContainerActionRequest,
    output: &str,
) -> serde_json::Value {
    match request.action {
        ContainerActionKind::Logs => serde_json::json!({ "logs": output }),
        ContainerActionKind::Inspect => serde_json::json!({ "inspect": output }),
        ContainerActionKind::Deploy => serde_json::json!({
            "container_id": output,
            "image_ref": request.image_ref.clone().unwrap_or_default(),
            "env_vars": redact_env_var_values(&request.env_vars),
            "secret_env_names": request.secret_env_vars.iter().map(|s| s.name.clone()).collect::<Vec<_>>(),
            "port_mappings": request.port_mappings.clone(),
            "entrypoint": request.entrypoint.clone(),
            "command": request.command.clone(),
        }),
        _ => serde_json::json!({ "output": output }),
    }
}

impl DockerCliActionExecutor {
    /// Run the general Docker CLI path (start/stop/restart/logs/inspect/deploy).
    fn run_general_action(
        request: &ContainerActionRequest,
    ) -> anyhow::Result<ContainerActionResponse> {
        if let Some(skip) = maybe_identity_skip_stop_restart(request)? {
            return Ok(skip);
        }
        if matches!(request.action, ContainerActionKind::Deploy) {
            guarded_deploy_precleanup(request)?;
        }
        let secret_env_path = if matches!(request.action, ContainerActionKind::Deploy)
            && !request.secret_env_vars.is_empty()
        {
            Some(write_deploy_secret_env_file(request)?)
        } else {
            None
        };
        let args = docker_args_for_action(request, secret_env_path.as_deref())?;
        let run_result = run_docker_command_with_runner(&SystemDockerCommandRunner, &args);
        if let Some(p) = secret_env_path {
            let _ = std::fs::remove_file(&p);
        }
        let output = run_result?;
        Ok(ContainerActionResponse {
            action: request.action,
            container_ref: request.container_ref.clone(),
            success: true,
            message: format!("{} succeeded", request.action.as_str()),
            payload: general_action_payload(request, &output),
        })
    }
}

impl ContainerActionExecutor for DockerCliActionExecutor {
    fn execute_action(
        &self,
        request: &ContainerActionRequest,
    ) -> anyhow::Result<ContainerActionResponse> {
        match request.action {
            ContainerActionKind::ProbeHost => Ok(probe_host_response(request)),
            ContainerActionKind::Diagnostic => run_diagnostic(request),
            ContainerActionKind::WireguardPeer => wireguard_peer_response(request),
            ContainerActionKind::GrowFs => run_grow_fs(request),
            ContainerActionKind::TemplatedExec => run_templated_exec(request),
            ContainerActionKind::EnsureDockerImage => ensure_docker_image_response(request),
            ContainerActionKind::EnsureNetwork => ensure_network_response(request),
            _ => Self::run_general_action(request),
        }
    }
}
