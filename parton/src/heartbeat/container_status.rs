//! Container status types plus the `docker ps` / `docker inspect` probing and parsing logic
//! that builds a [`ContainerStatusReport`] for each heartbeat.

use anyhow::Context;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::process::Command;

/// Container runtime counts summarized from Docker status output.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ContainerStatusSummary {
    /// Number of running (or restarting) containers.
    pub running: u64,
    /// Number of non-running containers (exited, dead, created, …).
    pub exited: u64,
    /// Number of running containers reporting an unhealthy Docker health check.
    pub unhealthy: u64,
}

/// Normalized container lifecycle state from Docker.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ContainerState {
    /// Container created but not yet started.
    Created,
    /// Container process is running.
    Running,
    /// Container is restarting.
    Restarting,
    /// Container is paused.
    Paused,
    /// Container has exited.
    Exited,
    /// Container is dead (daemon could not stop/remove it cleanly).
    Dead,
    /// Container is being removed.
    Removing,
}

/// Docker HEALTHCHECK rollup when present.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ContainerHealth {
    /// Health check is still in its start period.
    Starting,
    /// Health check reports healthy.
    Healthy,
    /// Health check reports unhealthy.
    Unhealthy,
    /// Container defines no health check.
    NoCheck,
    /// Health could not be determined.
    Unknown,
}

/// One container observed on the agent host.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ContainerStatus {
    /// Full (non-truncated) Docker container id.
    pub container_id: String,
    /// Primary container name (leading `/` stripped).
    pub container_name: String,
    /// Instance id from the optional `gluon.instance_id` container label, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<String>,
    /// Normalized lifecycle state.
    pub state: ContainerState,
    /// Exit code for non-running containers (from `docker inspect`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// Last start timestamp, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<DateTime<Utc>>,
    /// Last finish timestamp, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<DateTime<Utc>>,
    /// Health check rollup.
    pub health: ContainerHealth,
    /// Docker restart count.
    pub restart_count: u64,
    /// Timestamp when this snapshot was taken.
    pub last_observed_at: DateTime<Utc>,
    /// Error captured while probing this container (e.g. `docker inspect` failure).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe_error: Option<String>,
}

/// Per-container list plus roll-up counts for older control planes.
#[derive(Debug, Clone, PartialEq)]
pub struct ContainerStatusReport {
    /// Per-container observations on the host.
    pub containers: Vec<ContainerStatus>,
    /// Roll-up counts derived from `containers`.
    pub summary: ContainerStatusSummary,
}

impl ContainerStatusReport {
    /// Borrow the roll-up counts (`running` / `exited` / `unhealthy`).
    ///
    /// Prefer this accessor over the public `summary` field when writing new code so
    /// callers stay stable if summary derivation moves behind a method later. On
    /// deserialize, a missing wire `summary` is recomputed from `containers`.
    #[must_use]
    pub fn summary(&self) -> &ContainerStatusSummary {
        &self.summary
    }
}

impl Serialize for ContainerStatusReport {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut st = serializer.serialize_struct("ContainerStatusReport", 2)?;
        st.serialize_field("containers", &self.containers)?;
        st.serialize_field("summary", &self.summary)?;
        st.end()
    }
}

impl<'de> Deserialize<'de> for ContainerStatusReport {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        if let Some(arr) = value.get("containers").and_then(|v| v.as_array()) {
            let containers: Vec<ContainerStatus> =
                serde_json::from_value(serde_json::Value::Array(arr.clone()))
                    .map_err(serde::de::Error::custom)?;
            let summary = value
                .get("summary")
                .map(|s| serde_json::from_value(s.clone()))
                .transpose()
                .map_err(serde::de::Error::custom)?
                .unwrap_or_else(|| summarize_from_containers(&containers));
            return Ok(Self {
                containers,
                summary,
            });
        }
        if value.get("running").is_some()
            || value.get("exited").is_some()
            || value.get("unhealthy").is_some()
        {
            let summary: ContainerStatusSummary =
                serde_json::from_value(value).map_err(serde::de::Error::custom)?;
            return Ok(Self {
                containers: Vec::new(),
                summary,
            });
        }
        Err(serde::de::Error::custom(
            "expected ContainerStatusReport or legacy ContainerStatusSummary",
        ))
    }
}

pub(super) trait DockerContainerRunner {
    fn list_containers_json(&self) -> anyhow::Result<String>;
    fn inspect_state_json(&self, container_id: &str) -> anyhow::Result<String>;
}

struct SystemDockerContainerRunner;

impl DockerContainerRunner for SystemDockerContainerRunner {
    fn list_containers_json(&self) -> anyhow::Result<String> {
        let output = Command::new("docker")
            .args(["ps", "-a", "--no-trunc", "--format", "{{json .}}"])
            .output()
            .context("run `docker ps` (is docker installed on PATH?)")?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            anyhow::bail!(
                "docker ps probe failed (exit={}): stdout='{}' stderr='{}'",
                output.status.code().unwrap_or_default(),
                stdout,
                stderr
            );
        }
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    fn inspect_state_json(&self, container_id: &str) -> anyhow::Result<String> {
        let output = Command::new("docker")
            .args(["inspect", container_id, "--format", "{{json .State}}"])
            .output()
            .with_context(|| {
                format!("run `docker inspect {container_id}` (is docker installed on PATH?)")
            })?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            anyhow::bail!("docker inspect failed for {container_id}: {stderr}");
        }
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
}

#[derive(Debug, Deserialize)]
struct DockerPsRow {
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "Names")]
    names: String,
    #[serde(rename = "State")]
    state: String,
    #[serde(rename = "Status")]
    status: String,
    #[serde(rename = "Labels", default)]
    labels: String,
}

#[derive(Debug, Deserialize)]
struct DockerInspectState {
    #[serde(rename = "Status", default)]
    status: String,
    #[serde(rename = "ExitCode", default)]
    exit_code: i32,
    #[serde(rename = "StartedAt", default)]
    started_at: String,
    #[serde(rename = "FinishedAt", default)]
    finished_at: String,
    #[serde(rename = "RestartCount", default)]
    restart_count: u64,
}

fn parse_docker_timestamp(raw: &str) -> Option<DateTime<Utc>> {
    let t = raw.trim();
    if t.is_empty() || t.starts_with("0001-01-01") {
        return None;
    }
    chrono::DateTime::parse_from_rfc3339(t)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

fn label_value(labels: &str, key: &str) -> Option<String> {
    for part in labels.split(',') {
        let part = part.trim();
        if let Some((k, v)) = part.split_once('=') {
            if k.trim() == key {
                let v = v.trim().trim_matches('"');
                if !v.is_empty() {
                    return Some(v.to_string());
                }
            }
        }
    }
    None
}

fn normalize_container_name(names: &str) -> String {
    names
        .split(',')
        .next()
        .unwrap_or(names)
        .trim()
        .trim_start_matches('/')
        .to_string()
}

fn map_docker_state(state: &str) -> ContainerState {
    match state.trim().to_ascii_lowercase().as_str() {
        "created" => ContainerState::Created,
        "running" => ContainerState::Running,
        "restarting" => ContainerState::Restarting,
        "paused" => ContainerState::Paused,
        "dead" => ContainerState::Dead,
        "removing" => ContainerState::Removing,
        // "exited" and any unknown state both map to Exited.
        _ => ContainerState::Exited,
    }
}

fn map_health_from_status(status: &str, state: ContainerState) -> ContainerHealth {
    let lower = status.to_ascii_lowercase();
    if lower.contains("(unhealthy)") {
        return ContainerHealth::Unhealthy;
    }
    if lower.contains("(health: starting)") || lower.contains("(health: starting") {
        return ContainerHealth::Starting;
    }
    if lower.contains("(healthy)") {
        return ContainerHealth::Healthy;
    }
    if matches!(state, ContainerState::Running | ContainerState::Restarting) {
        ContainerHealth::NoCheck
    } else {
        ContainerHealth::Unknown
    }
}

fn summarize_from_containers(containers: &[ContainerStatus]) -> ContainerStatusSummary {
    let mut summary = ContainerStatusSummary::default();
    for c in containers {
        match c.state {
            ContainerState::Running | ContainerState::Restarting => {
                summary.running = summary.running.saturating_add(1);
                if matches!(c.health, ContainerHealth::Unhealthy) {
                    summary.unhealthy = summary.unhealthy.saturating_add(1);
                }
            }
            _ => {
                summary.exited = summary.exited.saturating_add(1);
            }
        }
    }
    summary
}

pub(super) fn enrich_non_running_with_inspect<R: DockerContainerRunner>(
    runner: &R,
    mut status: ContainerStatus,
) -> ContainerStatus {
    if matches!(
        status.state,
        ContainerState::Running | ContainerState::Restarting
    ) {
        return status;
    }
    match runner.inspect_state_json(&status.container_id) {
        Ok(json) => {
            if let Ok(state) = serde_json::from_str::<DockerInspectState>(&json) {
                status.state = map_docker_state(&state.status);
                status.exit_code = Some(state.exit_code);
                status.restart_count = state.restart_count;
                status.started_at = parse_docker_timestamp(&state.started_at);
                status.finished_at = parse_docker_timestamp(&state.finished_at);
            }
        }
        Err(err) => {
            status.probe_error = Some(err.to_string());
        }
    }
    status
}

pub(crate) fn parse_container_status_report_from_ps_json(
    output: &str,
    observed_at: DateTime<Utc>,
) -> ContainerStatusReport {
    let mut containers = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(row) = serde_json::from_str::<DockerPsRow>(line) else {
            continue;
        };
        let state = map_docker_state(&row.state);
        let health = map_health_from_status(&row.status, state);
        containers.push(ContainerStatus {
            container_id: row.id,
            container_name: normalize_container_name(&row.names),
            instance_id: label_value(&row.labels, "gluon.instance_id"),
            state,
            exit_code: None,
            started_at: None,
            finished_at: None,
            health,
            restart_count: 0,
            last_observed_at: observed_at,
            probe_error: None,
        });
    }
    let summary = summarize_from_containers(&containers);
    ContainerStatusReport {
        containers,
        summary,
    }
}

pub(super) fn collect_container_status_report_with_runner<R: DockerContainerRunner>(
    runner: &R,
) -> ContainerStatusReport {
    let observed_at = Utc::now();
    let output = runner.list_containers_json();
    let Ok(output) = output else {
        tracing::warn!("docker status probe failed");
        return ContainerStatusReport {
            containers: Vec::new(),
            summary: ContainerStatusSummary::default(),
        };
    };
    let mut report = parse_container_status_report_from_ps_json(&output, observed_at);
    report.containers = report
        .containers
        .into_iter()
        .map(|c| enrich_non_running_with_inspect(runner, c))
        .collect();
    report.summary = summarize_from_containers(&report.containers);
    tracing::info!(
        running = report.summary.running,
        exited = report.summary.exited,
        unhealthy = report.summary.unhealthy,
        containers = report.containers.len(),
        "docker status probe"
    );
    report
}

pub(super) fn collect_container_status_report() -> ContainerStatusReport {
    collect_container_status_report_with_runner(&SystemDockerContainerRunner)
}
