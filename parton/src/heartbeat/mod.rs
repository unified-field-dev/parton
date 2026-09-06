//! Heartbeat report construction and control-plane transport.
//!
//! # Flow
//!
//! 1. **Build** — [`build_heartbeat_report`] (or
//!    [`build_heartbeat_report_with_overrides`]) probes host capabilities and Docker
//!    container status into a [`NodeHeartbeatReport`].
//! 2. **Send** — [`send_heartbeat`] POSTs the report to the configured ingest URL
//!    and deserializes a [`HeartbeatResponse`].
//! 3. **Apply** — when the response carries [`AgentDirective`] values, the binary /
//!    [`crate::agent_runtime`] loop applies them (re-enroll, revoke) via
//!    [`crate::apply_directives`].
//!
//! Library callers that only need a snapshot (no network) stop after step 1; see
//! the `heartbeat_report` example.
//!
//! # Module layout
//!
//! - [`types`] — [`NodeHeartbeatReport`], [`HeartbeatResponse`], [`AgentDirective`], overrides.
//! - [`host_capabilities`] — [`HostCapabilities`] and its detection probes.
//! - [`container_status`] — container status types plus `docker ps` / `docker inspect` probing.
//! - [`transport`] — [`send_heartbeat`] HTTP POST.

// Heartbeat assembly is split into small probes so each parsing boundary can
// be unit tested independently from host runtime behavior.

mod container_status;
mod host_capabilities;
#[cfg(test)]
mod tests;
mod transport;
mod types;

use anyhow::Context;

pub use container_status::{
    ContainerHealth, ContainerState, ContainerStatus, ContainerStatusReport, ContainerStatusSummary,
};
pub use host_capabilities::HostCapabilities;
pub use transport::send_heartbeat;
pub use types::{AgentDirective, HeartbeatReportOverrides, HeartbeatResponse, NodeHeartbeatReport};

/// Build a full heartbeat report by combining host probes and container summary.
///
/// Reads `PARTON_ENROLLMENT_TOKEN` from the environment when set (unless suppressed via
/// [`build_heartbeat_report_with_overrides`]).
///
/// # Errors
///
/// Returns an error when host capabilities cannot be collected.
///
/// # Examples
///
/// ```no_run
/// use parton::build_heartbeat_report;
///
/// # fn main() -> anyhow::Result<()> {
/// let report = build_heartbeat_report("node-1", "local-default")?;
/// assert_eq!(report.node_id, "node-1");
/// assert_eq!(report.cell_id, "local-default");
/// # Ok(())
/// # }
/// ```
pub fn build_heartbeat_report(
    node_id: impl Into<String>,
    cell_id: impl Into<String>,
) -> anyhow::Result<NodeHeartbeatReport> {
    build_heartbeat_report_with_overrides(node_id, cell_id, HeartbeatReportOverrides::default())
}

/// Like [`build_heartbeat_report`] but merges `overrides` for directive-ack / failure stamps.
///
/// # Errors
///
/// Returns an error when host capabilities cannot be collected.
pub fn build_heartbeat_report_with_overrides(
    node_id: impl Into<String>,
    cell_id: impl Into<String>,
    overrides: HeartbeatReportOverrides,
) -> anyhow::Result<NodeHeartbeatReport> {
    let enrollment_token = if overrides.suppress_enrollment_token {
        None
    } else {
        std::env::var("PARTON_ENROLLMENT_TOKEN")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    };
    Ok(NodeHeartbeatReport {
        node_id: node_id.into(),
        cell_id: cell_id.into(),
        capabilities: host_capabilities::collect_host_capabilities()?,
        containers: container_status::collect_container_status_report(),
        observed_at: chrono::Utc::now(),
        enrollment_token,
        applied_directive_token: overrides.applied_directive_token,
        apply_failed: overrides.apply_failed,
    })
}

/// Async wrapper for [`build_heartbeat_report_with_overrides`] for use from async call sites
/// (e.g. [`crate::agent_runtime`]'s heartbeat loop).
///
/// The underlying probes shell out to `docker ps` / `docker inspect` and read host files
/// (`/etc/hostname`, `/proc/meminfo`), all of which are blocking syscalls; running the whole
/// build on [`tokio::task::spawn_blocking`]'s dedicated thread pool keeps those probes from
/// stalling the async runtime's worker threads.
///
/// # Errors
///
/// Returns an error when the blocking task cannot be joined (panicked or was cancelled), or
/// when [`build_heartbeat_report_with_overrides`] itself fails.
#[tracing::instrument(
    skip_all,
    fields(node_id = tracing::field::Empty, cell_id = tracing::field::Empty)
)]
pub async fn build_heartbeat_report_with_overrides_async(
    node_id: impl Into<String>,
    cell_id: impl Into<String>,
    overrides: HeartbeatReportOverrides,
) -> anyhow::Result<NodeHeartbeatReport> {
    let node_id = node_id.into();
    let cell_id = cell_id.into();
    let span = tracing::Span::current();
    span.record("node_id", tracing::field::display(&node_id));
    span.record("cell_id", tracing::field::display(&cell_id));
    tokio::task::spawn_blocking(move || {
        build_heartbeat_report_with_overrides(node_id, cell_id, overrides)
    })
    .await
    .context("heartbeat report task join")?
}
