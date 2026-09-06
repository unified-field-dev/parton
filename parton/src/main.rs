//! `parton` binary runtime loop.
//!
//! This binary wraps the reusable library APIs from [`parton`] and runs a
//! periodic heartbeat loop that:
//!
//! - builds node telemetry via [`parton::build_heartbeat_report`],
//! - sends telemetry via [`parton::send_heartbeat`],
//! - and repeats at `PARTON_HEARTBEAT_INTERVAL_SECS`.
//!
//! For orchestration contracts and container action APIs, see the library crate
//! documentation in [`parton`].

use std::sync::Arc;
use std::time::Duration;

use parton::{
    agent_runtime::{run_heartbeat_step, AgentRuntimeConfig, HeartbeatStepOutcome},
    derive_agent_api_base_url, execute_claimed_node_action, post_action_result, post_claim_action,
    post_extend_action_lease, DockerCliActionExecutor, PendingReenrollGrace,
};

fn clip_action_error_summary(detail: &str) -> String {
    const MAX: usize = 3500;
    if detail.len() <= MAX {
        format!("execute_claimed_node_action: {detail}")
    } else {
        format!(
            "execute_claimed_node_action: {}…",
            &detail[..MAX.saturating_sub(32)]
        )
    }
}

/// Extend the claim lease for long-running action kinds; failures are logged, not fatal.
#[tracing::instrument(
    skip(base, config, claimed),
    fields(
        command_id = %claimed.command_id,
        node_id = %config.node_id,
        action_kind = %claimed.action_kind.trim(),
    )
)]
async fn maybe_extend_lease(
    base: &str,
    config: &AgentRuntimeConfig,
    claimed: &parton::ClaimedNodeActionBody,
) {
    let kind = claimed.action_kind.trim();
    if !matches!(
        kind,
        "deploy" | "handoff_bundle_import" | "deploy_handoff" | "teardown_handoff"
    ) {
        return;
    }
    if let Err(e) = post_extend_action_lease(
        base,
        &claimed.command_id,
        &config.node_id,
        Some(config.action_lease_extend_secs),
        config.token.as_deref(),
    )
    .await
    {
        tracing::warn!(error = %e, "action extend-lease failed (continuing)");
    }
}

/// Run a claimed action and produce the result body, converting hard errors into a failure report.
#[tracing::instrument(
    skip(config, executor, claimed),
    fields(
        command_id = %claimed.command_id,
        node_id = %config.node_id,
        action_kind = %claimed.action_kind.trim(),
        attempt = claimed.attempt,
    )
)]
async fn run_claimed_action(
    config: &AgentRuntimeConfig,
    executor: &Arc<DockerCliActionExecutor>,
    claimed: &parton::ClaimedNodeActionBody,
) -> parton::ReportRequestBody {
    match execute_claimed_node_action(Arc::clone(executor), claimed, &config.node_id).await {
        Ok(r) => r,
        Err(e) => {
            let detail = e.to_string();
            tracing::error!(
                command_id = %claimed.command_id,
                action_kind = %claimed.action_kind.trim(),
                attempt = claimed.attempt,
                error = %detail,
                "execute_claimed_node_action failed"
            );
            let summary = clip_action_error_summary(&detail);
            parton::ReportRequestBody {
                command_id: claimed.command_id.clone(),
                node_id: config.node_id.clone(),
                attempt: claimed.attempt,
                success: false,
                stdout: None,
                stderr: Some(detail),
                error_summary: Some(summary),
                payload_json: Some(serde_json::json!({})),
            }
        }
    }
}

#[tracing::instrument(skip(config, executor), fields(node_id = %config.node_id))]
async fn poll_one_node_action(
    config: &AgentRuntimeConfig,
    executor: &Arc<DockerCliActionExecutor>,
) {
    let base = derive_agent_api_base_url(&config.endpoint);
    let claimed = match post_claim_action(
        &base,
        &config.node_id,
        Some(config.action_lease_secs),
        config.token.as_deref(),
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "action claim request failed");
            return;
        }
    };
    let Some(claimed) = claimed else {
        return;
    };
    maybe_extend_lease(&base, config, &claimed).await;
    let report = run_claimed_action(config, executor, &claimed).await;
    if let Err(e) = post_action_result(&base, report, config.token.as_deref()).await {
        tracing::warn!(error = %e, "action result post failed");
    }
}

fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = EnvFilter::try_from_env("PARTON_LOG")
        .or_else(|_| EnvFilter::try_from_default_env())
        .unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = fmt().with_env_filter(filter).try_init();
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    if let Some(addr) = parton::agent_metrics::maybe_install_prometheus_exporter_from_env()? {
        tracing::info!(%addr, "prometheus metrics scrape listener installed (PARTON_METRICS_BIND)");
    }
    let mut config = AgentRuntimeConfig::from_env()?;
    let mut pending_applied_token: Option<String> = None;
    let mut pending_apply_failed: Option<String> = None;
    let mut pending_grace: Option<PendingReenrollGrace> = None;
    let mut enrollment_acknowledged = false;
    let executor = Arc::new(DockerCliActionExecutor);

    loop {
        match run_heartbeat_step(
            &mut config,
            &mut pending_applied_token,
            &mut pending_apply_failed,
            &mut pending_grace,
            &mut enrollment_acknowledged,
        )
        .await?
        {
            HeartbeatStepOutcome::Continue => {}
            HeartbeatStepOutcome::ExitGraceExpired | HeartbeatStepOutcome::ExitRevoked => {
                std::process::exit(1);
            }
        }
        poll_one_node_action(&config, &executor).await;
        tokio::time::sleep(Duration::from_secs(config.interval_secs)).await;
    }
}
