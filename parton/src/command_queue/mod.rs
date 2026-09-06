//! HTTP client helpers for the control-plane node action queue (claim → execute → result).
//!
//! # Lifecycle
//!
//! 1. [`post_claim_action`] — claim one pending command (HTTP 204 = empty queue).
//! 2. [`execute_claimed_node_action`] — run it on this host.
//! 3. [`post_action_result`] — report success/failure; optionally
//!    [`post_extend_action_lease`] during long work.
//!
//! # `payload_json` shapes by `action_kind`
//!
//! See [`ClaimedNodeActionBody::payload_json`]. `deploy_handoff` / `teardown_handoff`
//! wire fields must stay in sync with Pion's
//! `DeployHandoffActionRequest` / `TeardownHandoffActionRequest`.
//!
//! # Module layout
//!
//! - [`types`] — [`ClaimedNodeActionBody`] / [`ReportRequestBody`] and the private handoff wire structs.
//! - [`http`] — claim / extend-lease / result HTTP calls.
//! - [`report`] — success/failure [`ReportRequestBody`] construction shared by all action kinds.
//! - [`health_check`] / [`handoff_bundle_import`] / [`handoff`] / [`generic`] — one module per `action_kind` family.

mod generic;
mod handoff;
mod handoff_bundle_import;
mod health_check;
mod http;
mod report;
#[cfg(test)]
mod tests;
mod types;

use std::sync::Arc;

use anyhow::Context;

use crate::ContainerActionExecutor;

pub use http::{
    derive_agent_api_base_url, post_action_result, post_claim_action, post_extend_action_lease,
};
pub use types::{ClaimedNodeActionBody, ReportRequestBody};

/// Runs one claimed command on this host (Docker and/or outbound HTTP as required).
///
/// Docker/agent-local kinds (`deploy_handoff`, `teardown_handoff`, and the generic Docker
/// CLI actions) run their blocking `docker`/`wg` invocations on
/// [`tokio::task::spawn_blocking`]'s dedicated thread pool so they never stall this async
/// task or the runtime's async worker threads. `executor` is `Arc`-wrapped so it can be
/// cheaply cloned into each blocking closure.
///
/// # Errors
///
/// Returns an error when a required payload field is missing, when a handoff payload targets a
/// different node, when outbound HTTP (health check / import) cannot be performed, when the
/// blocking task panics or is cancelled (join failure), or when the `action_kind` is
/// unsupported. Action execution failures are reported inside the returned
/// [`ReportRequestBody`] (with `success = false`) rather than as an `Err`.
#[tracing::instrument(
    skip(executor, claimed),
    fields(
        command_id = %claimed.command_id,
        node_id = %agent_node_id,
        action_kind = %claimed.action_kind.trim(),
        attempt = claimed.attempt,
    )
)]
pub async fn execute_claimed_node_action<E: ContainerActionExecutor + Send + Sync + 'static>(
    executor: Arc<E>,
    claimed: &ClaimedNodeActionBody,
    agent_node_id: &str,
) -> anyhow::Result<ReportRequestBody> {
    let started = std::time::Instant::now();
    let report = match claimed.action_kind.trim() {
        "health_check" => health_check::run_health_check(claimed, agent_node_id).await?,
        "handoff_bundle_import" => {
            handoff_bundle_import::run_handoff_bundle_import(claimed, agent_node_id).await?
        }
        "deploy_handoff" => {
            let claimed = claimed.clone();
            let agent_node_id = agent_node_id.to_string();
            let executor = Arc::clone(&executor);
            tokio::task::spawn_blocking(move || {
                handoff::run_deploy_handoff(executor.as_ref(), &claimed, &agent_node_id)
            })
            .await
            .context("action task join")??
        }
        "teardown_handoff" => {
            let claimed = claimed.clone();
            let agent_node_id = agent_node_id.to_string();
            let executor = Arc::clone(&executor);
            tokio::task::spawn_blocking(move || {
                handoff::run_teardown_handoff(executor.as_ref(), &claimed, &agent_node_id)
            })
            .await
            .context("action task join")??
        }
        "deploy"
        | "restart"
        | "start"
        | "stop"
        | "logs"
        | "inspect"
        | "ensure_network"
        | "probe_host"
        | "diagnostic"
        | "wireguard_peer"
        | "ensure_docker_image"
        | "grow_fs"
        | "templated_exec" => {
            let claimed = claimed.clone();
            let agent_node_id = agent_node_id.to_string();
            let executor = Arc::clone(&executor);
            tokio::task::spawn_blocking(move || {
                generic::run_generic_container_action(executor.as_ref(), &claimed, &agent_node_id)
            })
            .await
            .context("action task join")?
        }
        other => anyhow::bail!("unsupported action_kind {other:?}"),
    };
    crate::agent_metrics::record_action_result(
        claimed.action_kind.trim(),
        report.success,
        started.elapsed(),
    );
    Ok(report)
}
