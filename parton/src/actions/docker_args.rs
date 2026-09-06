//! Build Docker CLI argument vectors from typed action requests.

use super::types::{ContainerActionKind, ContainerActionRequest};
use serde_json::Value;
use std::path::Path;

fn deploy_command_strings(request: &ContainerActionRequest) -> anyhow::Result<Vec<String>> {
    let mut out = Vec::new();
    for v in &request.command {
        match v {
            Value::String(s) => out.push(s.clone()),
            _ => anyhow::bail!(
                "container deploy command must use string args after pion $secret_ref resolution; got: {v}"
            ),
        }
    }
    Ok(out)
}

/// Build Docker CLI argument vectors from typed action requests.
///
/// For [`ContainerActionKind::Deploy`], `deploy_secret_env_file` must point at a file containing
/// [`ContainerActionRequest::secret_env_vars`] when that list is non-empty.
pub(super) fn docker_args_for_action(
    request: &ContainerActionRequest,
    deploy_secret_env_file: Option<&Path>,
) -> anyhow::Result<Vec<String>> {
    match request.action {
        // Start/stop/restart map directly to single-container Docker subcommands.
        ContainerActionKind::Start => Ok(vec!["start".to_string(), request.container_ref.clone()]),
        ContainerActionKind::Stop => Ok(vec!["stop".to_string(), request.container_ref.clone()]),
        ContainerActionKind::Restart => {
            Ok(vec!["restart".to_string(), request.container_ref.clone()])
        }
        // Logs defaults to a bounded tail to avoid huge payloads.
        ContainerActionKind::Logs => Ok(vec![
            "logs".to_string(),
            "--tail".to_string(),
            request.tail_lines.unwrap_or(200).max(1).to_string(),
            request.container_ref.clone(),
        ]),
        ContainerActionKind::Inspect => {
            Ok(vec!["inspect".to_string(), request.container_ref.clone()])
        }
        ContainerActionKind::EnsureNetwork => Ok(vec![
            "network".to_string(),
            "inspect".to_string(),
            request.container_ref.clone(),
        ]),
        ContainerActionKind::Deploy => deploy_docker_args(request, deploy_secret_env_file),
        // ProbeHost / Diagnostic / WireguardPeer / GrowFs / TemplatedExec are handled
        // directly by the executor.
        ContainerActionKind::ProbeHost
        | ContainerActionKind::Diagnostic
        | ContainerActionKind::WireguardPeer
        | ContainerActionKind::GrowFs
        | ContainerActionKind::TemplatedExec => Ok(Vec::new()),
        ContainerActionKind::EnsureDockerImage => anyhow::bail!(
            "internal: EnsureDockerImage is executed directly in DockerCliActionExecutor"
        ),
    }
}

/// Build the `docker run` argument vector for a [`ContainerActionKind::Deploy`] request.
fn deploy_docker_args(
    request: &ContainerActionRequest,
    deploy_secret_env_file: Option<&Path>,
) -> anyhow::Result<Vec<String>> {
    // Deploy creates a detached container with explicit env/port options.
    let mut args = vec![
        "run".to_string(),
        "-d".to_string(),
        "--name".to_string(),
        request.container_ref.clone(),
    ];
    if let Some(net) = request
        .network
        .as_ref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        args.push("--network".to_string());
        args.push(net.to_string());
    }
    for host in &request.extra_hosts {
        let h = host.trim();
        if !h.is_empty() {
            args.push("--add-host".to_string());
            args.push(h.to_string());
        }
    }
    for env_var in &request.env_vars {
        args.push("-e".to_string());
        args.push(env_var.clone());
    }
    if let Some(path) = deploy_secret_env_file {
        args.push("--env-file".to_string());
        args.push(path.display().to_string());
    }
    for mapping in &request.port_mappings {
        args.push("-p".to_string());
        args.push(mapping.clone());
    }
    for vol in &request.volume_mounts {
        let mut spec = format!("{}:{}", vol.host_path.trim(), vol.container_path.trim());
        if vol.read_only {
            spec.push_str(":ro");
        }
        args.push("-v".to_string());
        args.push(spec);
    }
    for (k, v) in &request.labels {
        args.push("--label".to_string());
        args.push(format!("{}={}", k.trim(), v.trim()));
    }
    if let Some(lim) = &request.resource_limits {
        if lim.memory_mb > 0 {
            args.push("--memory".to_string());
            args.push(format!("{}m", lim.memory_mb));
        }
        if lim.cpu_shares > 0 {
            args.push("--cpu-shares".to_string());
            args.push(lim.cpu_shares.to_string());
        }
    }
    if let Some(h) = &request.health_check {
        let path = h.endpoint.trim();
        let path = if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{path}")
        };
        // BusyBox wget (Alpine) or similar — best-effort HTTP probe.
        let cmd = format!(
            "wget -q -O /dev/null http://127.0.0.1:{}{path} || exit 1",
            h.internal_port
        );
        args.push("--health-cmd".to_string());
        args.push(cmd);
        args.push("--health-interval".to_string());
        args.push(format!("{}s", h.interval_secs.max(1)));
        args.push("--health-timeout".to_string());
        args.push(format!("{}s", h.timeout_secs.max(1)));
    }
    if let Some(ep) = request
        .entrypoint
        .as_ref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        args.push("--entrypoint".to_string());
        args.push(ep.to_string());
    }
    if let Some(pol) = request
        .restart_policy
        .as_ref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        args.push("--restart".to_string());
        args.push(pol.to_string());
    }
    args.push(
        request
            .image_ref
            .as_ref()
            .map(|value| value.trim().to_string())
            .unwrap_or_default(),
    );
    for arg in deploy_command_strings(request)? {
        args.push(arg);
    }
    Ok(args)
}
