//! `deploy_handoff` / `teardown_handoff` queue actions: map handoff wire payloads onto
//! [`crate::ContainerActionRequest`] and run them through the configured executor.

use super::report::{error_report, response_to_report_fields, success_report};
use super::types::{
    ClaimedNodeActionBody, DeployHandoffWire, DeploySecretEnvVarWire, ReportRequestBody,
    TeardownHandoffWire,
};
use crate::{
    execute_container_action, validate_deploy_secret_env_entry, ContainerActionExecutor,
    ContainerActionKind, ContainerActionRequest, SecretEnvVar,
};
use anyhow::Context;
use serde_json::Value;
use std::collections::HashMap;

/// Merge a canonical import URL (env override or deploy request) into the deploy payload.
fn merge_import_base_url(payload: &mut serde_json::Value, deploy_import_base_url: Option<&str>) {
    if !payload.is_object() {
        *payload = serde_json::json!({ "executor_payload": payload });
    }
    let Some(obj) = payload.as_object_mut() else {
        return;
    };
    if let Ok(raw) = std::env::var("PARTON_HANDOFF_IMPORT_BASE_URL") {
        let u = raw.trim();
        if !u.is_empty() {
            obj.insert(
                "import_base_url".into(),
                serde_json::Value::String(u.to_string()),
            );
            obj.insert(
                "source".into(),
                serde_json::Value::String("parton_env".into()),
            );
        }
    } else if let Some(u) = deploy_import_base_url {
        obj.insert(
            "import_base_url".into(),
            serde_json::Value::String(u.to_string()),
        );
        obj.insert(
            "source".into(),
            serde_json::Value::String("deploy_request".into()),
        );
    }
}

fn map_deploy_handoff_secret_env(
    wire: Vec<DeploySecretEnvVarWire>,
) -> anyhow::Result<Vec<SecretEnvVar>> {
    let mut out = Vec::with_capacity(wire.len());
    for e in wire {
        let s = match &e.value {
            Value::String(s) => s.clone(),
            other => anyhow::bail!(
                "deploy_handoff secret_env_vars values must be JSON strings after claim-time $secret_ref resolution; got {other}"
            ),
        };
        validate_deploy_secret_env_entry(e.name.trim(), s.as_str())?;
        out.push(SecretEnvVar {
            name: e.name.trim().to_string(),
            value: s,
        });
    }
    Ok(out)
}

fn container_action_from_deploy_handoff(
    req: DeployHandoffWire,
    agent_node_id: &str,
) -> anyhow::Result<ContainerActionRequest> {
    if req.node_id != agent_node_id {
        anyhow::bail!(
            "deploy_handoff node_id mismatch (payload {}, agent {})",
            req.node_id,
            agent_node_id
        );
    }
    let mut labels = HashMap::new();
    if let Some(t) = req.transfer_id.clone() {
        labels.insert("handoff.transfer_id".to_string(), t);
    }
    if let Some(u) = req.health_url.clone() {
        labels.insert("handoff.health_url".to_string(), u);
    }
    if let Some(u) = req.import_base_url.clone() {
        labels.insert("handoff.import_base_url".to_string(), u);
    }
    let secret_env_vars = map_deploy_handoff_secret_env(req.secret_env_vars)?;
    Ok(ContainerActionRequest {
        node_id: req.node_id,
        container_ref: req.container_ref,
        action: ContainerActionKind::Deploy,
        tail_lines: None,
        image_ref: Some(req.image_ref),
        env_vars: req.env_vars,
        secret_env_vars,
        port_mappings: req.port_mappings,
        extra_hosts: req.extra_hosts,
        entrypoint: None,
        command: vec![],
        restart_policy: Some("unless-stopped".to_string()),
        volume_mounts: req.volume_mounts,
        resource_limits: None,
        health_check: None,
        labels,
        network: req.network,
        diagnostic: None,
        wireguard_peer: None,
        grow_fs: None,
        templated_exec: None,
        expected_container_id: None,
    })
}

fn container_action_from_teardown_handoff(
    req: TeardownHandoffWire,
    agent_node_id: &str,
) -> anyhow::Result<ContainerActionRequest> {
    if req.node_id != agent_node_id {
        anyhow::bail!(
            "teardown_handoff node_id mismatch (payload {}, agent {})",
            req.node_id,
            agent_node_id
        );
    }
    // `remove_volumes` drives the follow-up `docker rm -v` step in
    // `run_teardown_handoff_with_volume_runner`, not the Stop request itself.
    Ok(ContainerActionRequest {
        node_id: req.node_id,
        container_ref: req.container_ref,
        action: ContainerActionKind::Stop,
        tail_lines: None,
        image_ref: None,
        env_vars: vec![],
        secret_env_vars: vec![],
        port_mappings: vec![],
        extra_hosts: vec![],
        entrypoint: None,
        command: vec![],
        restart_policy: None,
        volume_mounts: vec![],
        resource_limits: None,
        health_check: None,
        labels: HashMap::new(),
        network: None,
        diagnostic: None,
        wireguard_peer: None,
        grow_fs: None,
        templated_exec: None,
        expected_container_id: req.expected_container_id,
    })
}

pub(super) fn run_deploy_handoff<E: ContainerActionExecutor>(
    executor: &E,
    claimed: &ClaimedNodeActionBody,
    agent_node_id: &str,
) -> anyhow::Result<ReportRequestBody> {
    let wire: DeployHandoffWire = serde_json::from_value(claimed.payload_json.clone())
        .context("parse deploy_handoff payload")?;
    let deploy_import_base_url = wire
        .import_base_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let req = container_action_from_deploy_handoff(wire, agent_node_id)?;
    match execute_container_action(executor, &req) {
        Ok(res) => {
            let (stdout, stderr, mut payload) = response_to_report_fields(&res);
            // CN-4: merge deploy-reported canonical import URL when the agent operator sets it.
            merge_import_base_url(&mut payload, deploy_import_base_url.as_deref());
            Ok(success_report(
                claimed,
                agent_node_id,
                &stdout,
                &stderr,
                payload,
            ))
        }
        Err(e) => Ok(error_report(claimed, agent_node_id, &e)),
    }
}

/// Abstraction over invoking `docker rm -v <container>` for the `teardown_handoff`
/// volume-removal step, so tests can mock it without a real Docker daemon (mirrors
/// `crate::actions`' internal `DockerCommandRunner` pattern).
pub(super) trait TeardownVolumeRunner {
    fn remove_with_volumes(&self, container_ref: &str) -> anyhow::Result<std::process::Output>;
}

/// [`TeardownVolumeRunner`] backed by the real `docker` binary on `PATH`.
struct SystemTeardownVolumeRunner;

impl TeardownVolumeRunner for SystemTeardownVolumeRunner {
    fn remove_with_volumes(&self, container_ref: &str) -> anyhow::Result<std::process::Output> {
        std::process::Command::new("docker")
            .args(["rm", "-v", container_ref])
            .output()
            .with_context(|| {
                format!("run `docker rm -v {container_ref}` (is docker installed on PATH?)")
            })
    }
}

pub(super) fn run_teardown_handoff<E: ContainerActionExecutor>(
    executor: &E,
    claimed: &ClaimedNodeActionBody,
    agent_node_id: &str,
) -> anyhow::Result<ReportRequestBody> {
    run_teardown_handoff_with_volume_runner(
        executor,
        &SystemTeardownVolumeRunner,
        claimed,
        agent_node_id,
    )
}

/// Runs the `teardown_handoff` Stop action and, when `remove_volumes` is set on the payload,
/// follows it with `docker rm -v <container_ref>` so anonymous/named volumes are reclaimed.
///
/// Fails closed: if the Stop succeeds but the volume-removal step cannot run (missing `docker`
/// binary) or exits non-zero, the overall result is reported as a failure rather than a
/// synthetic success, since the caller explicitly asked for volumes to be removed.
pub(super) fn run_teardown_handoff_with_volume_runner<
    E: ContainerActionExecutor,
    R: TeardownVolumeRunner,
>(
    executor: &E,
    volume_runner: &R,
    claimed: &ClaimedNodeActionBody,
    agent_node_id: &str,
) -> anyhow::Result<ReportRequestBody> {
    let wire: TeardownHandoffWire = serde_json::from_value(claimed.payload_json.clone())
        .context("parse teardown_handoff payload")?;
    let remove_volumes = wire.remove_volumes;
    let container_ref = wire.container_ref.clone();
    let req = container_action_from_teardown_handoff(wire, agent_node_id)?;
    let res = match execute_container_action(executor, &req) {
        Ok(res) => res,
        Err(e) => return Ok(error_report(claimed, agent_node_id, &e)),
    };
    let (stdout, stderr, mut payload) = response_to_report_fields(&res);
    if !remove_volumes {
        return Ok(success_report(
            claimed,
            agent_node_id,
            &stdout,
            &stderr,
            payload,
        ));
    }
    match volume_runner.remove_with_volumes(&container_ref) {
        Ok(output) if output.status.success() => {
            if let Some(obj) = payload.as_object_mut() {
                obj.insert("volumes_removed".to_string(), serde_json::Value::Bool(true));
            }
            let stdout = format!("{stdout}\ndocker rm -v {container_ref} succeeded");
            Ok(success_report(
                claimed,
                agent_node_id,
                &stdout,
                &stderr,
                payload,
            ))
        }
        Ok(output) => {
            let out_stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let out_stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let err = anyhow::anyhow!(
                "{container_ref} stopped but `docker rm -v {container_ref}` failed (exit={}): {out_stdout}{sep}{out_stderr}",
                output.status.code().unwrap_or(-1),
                sep = if !out_stdout.is_empty() && !out_stderr.is_empty() {
                    " | "
                } else {
                    ""
                },
            );
            Ok(error_report(claimed, agent_node_id, &err))
        }
        Err(e) => {
            let err = anyhow::anyhow!(
                "{container_ref} stopped but `docker rm -v {container_ref}` could not run \
                 (is `docker` installed on this host?): {e}"
            );
            Ok(error_report(claimed, agent_node_id, &err))
        }
    }
}
