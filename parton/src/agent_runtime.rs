//! One heartbeat loop iteration for the `parton` binary (and embedders).
//!
//! [`run_heartbeat_step`] builds a report, POSTs it, applies any directives from the
//! response, then claims and runs queued node actions. After a re-enroll handoff it
//! honors a grace window before treating the new control plane as authoritative, and
//! stamps `apply_failed` on the next report when directive application fails so the
//! control plane can fall back to the prior enrollment.

use chrono::{DateTime, Utc};

use crate::{
    apply_directives, build_heartbeat_report_with_overrides_async, send_heartbeat,
    HeartbeatReportOverrides, HeartbeatResponse,
};

/// Parsed agent configuration from environment (mirrors the `parton` binary).
#[derive(Debug, Clone)]
pub struct AgentRuntimeConfig {
    /// Control-plane heartbeat ingest URL (`PARTON_HEARTBEAT_URL`).
    pub endpoint: String,
    /// Stable node identifier (`PARTON_NODE_ID`).
    pub node_id: String,
    /// Cell / group identifier (`PARTON_CELL_ID`).
    pub cell_id: String,
    /// Heartbeat interval in seconds (`PARTON_HEARTBEAT_INTERVAL_SECS`).
    pub interval_secs: u64,
    /// Optional shared token sent as the `x-parton-token` header (`PARTON_SHARED_TOKEN`).
    pub token: Option<String>,
    /// Claim lease duration in seconds (`PARTON_ACTION_LEASE_SECS`).
    pub action_lease_secs: u64,
    /// Lease extension in seconds before long actions (`PARTON_ACTION_LEASE_EXTEND_SECS`).
    pub action_lease_extend_secs: u64,
    /// Seconds to keep retrying the new CP before exiting (re-enroll grace window).
    pub grace_window_secs: u64,
}

impl AgentRuntimeConfig {
    /// Build a config from process environment variables.
    ///
    /// Missing optional variables fall back to the documented defaults (see the crate README).
    /// `PARTON_NODE_ID` is required: blank/unset fails closed so the agent never invents an
    /// identity that could collide with another node.
    ///
    /// # Errors
    ///
    /// Returns an error when `PARTON_NODE_ID` is unset or blank after trim.
    pub fn from_env() -> anyhow::Result<Self> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// Build a config from a custom lookup closure (used for deterministic tests).
    ///
    /// The closure receives an environment variable name and returns its value if set.
    ///
    /// # Errors
    ///
    /// Returns an error when `PARTON_NODE_ID` is unset or blank after trim.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> anyhow::Result<Self> {
        let endpoint = lookup("PARTON_HEARTBEAT_URL")
            .unwrap_or_else(|| "http://127.0.0.1:3000/api/parton/heartbeat".to_string());
        let node_id = lookup("PARTON_NODE_ID")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "PARTON_NODE_ID is not set; refusing to start without a stable node identity"
                )
            })?;
        let cell_id = lookup("PARTON_CELL_ID").unwrap_or_else(|| "local-default".to_string());
        let interval_secs = lookup("PARTON_HEARTBEAT_INTERVAL_SECS")
            .and_then(|raw| raw.parse::<u64>().ok())
            .unwrap_or(10);
        let token = lookup("PARTON_SHARED_TOKEN");
        let action_lease_secs = lookup("PARTON_ACTION_LEASE_SECS")
            .and_then(|raw| raw.parse::<u64>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(120);
        let action_lease_extend_secs = lookup("PARTON_ACTION_LEASE_EXTEND_SECS")
            .and_then(|raw| raw.parse::<u64>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(600);
        let grace_window_secs = lookup("PARTON_DIRECTIVE_GRACE_SECS")
            .and_then(|raw| raw.parse::<u64>().ok())
            .unwrap_or(300)
            .max(30);
        Ok(Self {
            endpoint,
            node_id,
            cell_id,
            interval_secs,
            token,
            action_lease_secs,
            action_lease_extend_secs,
            grace_window_secs,
        })
    }
}

/// After a successful re-enroll apply, retry the new CP until `deadline`; on failure, one fallback
/// heartbeat to the previous CP with `apply_failed` until grace expires.
#[derive(Debug, Clone)]
pub struct PendingReenrollGrace {
    /// Previous CP heartbeat URL to fall back to while the grace window is open.
    pub prev_endpoint: String,
    /// Previous CP token snapshot captured before the `parton.env` rewrite.
    pub prev_token: Option<String>,
    /// Instant after which the agent stops retrying the new CP and exits non-zero.
    pub deadline: DateTime<Utc>,
}

/// Result of one heartbeat loop iteration (testable without `process::exit`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeartbeatStepOutcome {
    /// Heartbeat handled; the loop should continue to the next iteration.
    Continue,
    /// Grace window elapsed while the new CP still rejects heartbeats.
    ExitGraceExpired,
    /// A verified `Revoke` directive was applied.
    ExitRevoked,
}

/// One heartbeat + optional directive apply. Updates `config`, `pending_grace`, and pending ack/fail stamps.
///
/// # Errors
///
/// Returns an error only for unrecoverable failures such as being unable to build the
/// heartbeat report or a directive-apply error; transport failures are handled inline
/// (retried, or reported as [`HeartbeatStepOutcome::ExitGraceExpired`]).
#[tracing::instrument(
    skip(config, pending_token, pending_fail, pending_grace, enrollment_acknowledged),
    fields(node_id = %config.node_id, cell_id = %config.cell_id)
)]
pub async fn run_heartbeat_step(
    config: &mut AgentRuntimeConfig,
    pending_token: &mut Option<String>,
    pending_fail: &mut Option<String>,
    pending_grace: &mut Option<PendingReenrollGrace>,
    enrollment_acknowledged: &mut bool,
) -> anyhow::Result<HeartbeatStepOutcome> {
    let overrides = HeartbeatReportOverrides {
        applied_directive_token: pending_token.take(),
        apply_failed: pending_fail.take(),
        suppress_enrollment_token: *enrollment_acknowledged,
    };
    let report = build_heartbeat_report_with_overrides_async(
        config.node_id.clone(),
        config.cell_id.clone(),
        overrides,
    )
    .await?;

    match send_heartbeat(&config.endpoint, &report, config.token.as_deref()).await {
        Ok(response) => {
            // A successful send means the control plane has already recorded this node (or just
            // enrolled it via this report's token); no need to keep resending the enrollment
            // token on every subsequent beat (F11).
            *enrollment_acknowledged = true;
            if pending_grace.is_some() {
                *pending_grace = None;
            }
            process_successful_heartbeat(
                config,
                pending_token,
                pending_grace,
                enrollment_acknowledged,
                &report,
                &response,
            )
        }
        Err(error) => handle_heartbeat_error(&report, pending_fail, pending_grace, &error).await,
    }
}

/// Handle a failed heartbeat send: within the grace window, fall back to the previous CP;
/// once the deadline passes, signal exit.
async fn handle_heartbeat_error(
    report: &crate::NodeHeartbeatReport,
    pending_fail: &mut Option<String>,
    pending_grace: &mut Option<PendingReenrollGrace>,
    error: &anyhow::Error,
) -> anyhow::Result<HeartbeatStepOutcome> {
    let Some(grace) = pending_grace.as_ref() else {
        tracing::warn!(%error, "heartbeat send failed");
        return Ok(HeartbeatStepOutcome::Continue);
    };
    if Utc::now() >= grace.deadline {
        tracing::error!(%error, "new CP heartbeat failed after grace window");
        return Ok(HeartbeatStepOutcome::ExitGraceExpired);
    }
    let fail_msg = format!("new CP heartbeat failed (within grace): {error}");
    tracing::warn!(%error, "new CP heartbeat failed within grace window");
    send_apply_failed_fallback(grace, report, &fail_msg).await;
    *pending_fail = Some(fail_msg);
    Ok(HeartbeatStepOutcome::Continue)
}

fn process_successful_heartbeat(
    config: &mut AgentRuntimeConfig,
    pending_token: &mut Option<String>,
    pending_grace: &mut Option<PendingReenrollGrace>,
    enrollment_acknowledged: &mut bool,
    report: &crate::NodeHeartbeatReport,
    response: &HeartbeatResponse,
) -> anyhow::Result<HeartbeatStepOutcome> {
    let _ = report;
    tracing::info!(
        node_id = %config.node_id,
        cell_id = %config.cell_id,
        directives = response.directives.len(),
        "heartbeat sent"
    );
    if response.directives.is_empty() {
        return Ok(HeartbeatStepOutcome::Continue);
    }

    let apply = apply_directives(&response.directives)?;
    if apply.revoke_exit {
        tracing::warn!("revoke directive applied; exiting");
        return Ok(HeartbeatStepOutcome::ExitRevoked);
    }
    if apply.next_applied_directive_token.is_some() {
        if pending_grace.is_none() {
            if let (Some(prev_ep), _) = (apply.prev_endpoint.clone(), apply.prev_token.clone()) {
                *pending_grace = Some(PendingReenrollGrace {
                    prev_endpoint: prev_ep,
                    prev_token: apply.prev_token.clone(),
                    deadline: Utc::now()
                        + chrono::Duration::seconds(
                            i64::try_from(config.grace_window_secs).unwrap_or(i64::MAX),
                        ),
                });
            }
        }
        *pending_token = apply.next_applied_directive_token;
        let fresh = AgentRuntimeConfig::from_env()?;
        config.endpoint = fresh.endpoint;
        config.token = fresh.token;
        config.node_id = fresh.node_id;
        config.cell_id = fresh.cell_id;
        // Re-enroll rewrites `parton.env` with a fresh PARTON_ENROLLMENT_TOKEN for the new CP,
        // which hasn't seen this node yet — resume sending it until that CP acknowledges.
        *enrollment_acknowledged = false;
    }
    Ok(HeartbeatStepOutcome::Continue)
}

/// Build the `apply_failed` fallback report, logging (not propagating) build failures.
async fn build_fallback_report(
    base_report: &crate::NodeHeartbeatReport,
    fail_msg: &str,
) -> Option<crate::NodeHeartbeatReport> {
    let overrides = HeartbeatReportOverrides {
        applied_directive_token: None,
        apply_failed: Some(fail_msg.to_string()),
        suppress_enrollment_token: false,
    };
    match build_heartbeat_report_with_overrides_async(
        base_report.node_id.clone(),
        base_report.cell_id.clone(),
        overrides,
    )
    .await
    {
        Ok(r) => Some(r),
        Err(e) => {
            tracing::error!(error = %e, "build fallback heartbeat report failed");
            None
        }
    }
}

async fn send_apply_failed_fallback(
    grace: &PendingReenrollGrace,
    base_report: &crate::NodeHeartbeatReport,
    fail_msg: &str,
) {
    let Some(fallback_report) = build_fallback_report(base_report, fail_msg).await else {
        return;
    };
    match send_heartbeat(
        &grace.prev_endpoint,
        &fallback_report,
        grace.prev_token.as_deref(),
    )
    .await
    {
        Ok(_) => tracing::info!(
            endpoint = %grace.prev_endpoint,
            "reported apply_failed to previous CP"
        ),
        Err(e) => tracing::warn!(error = %e, "fallback heartbeat to previous CP failed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::IntoFuture;
    use std::sync::{Arc, Mutex};

    use axum::extract::State;
    use axum::routing::post;
    use axum::{Json, Router};
    use tokio::sync::oneshot;

    #[test]
    fn grace_window_secs_defaults_and_clamps() {
        let c = AgentRuntimeConfig::from_lookup(|key| match key {
            "PARTON_NODE_ID" => Some("test-node".to_string()),
            "PARTON_DIRECTIVE_GRACE_SECS" => Some("5".to_string()),
            _ => None,
        })
        .expect("config");
        assert_eq!(c.grace_window_secs, 30);

        let c = AgentRuntimeConfig::from_lookup(|key| match key {
            "PARTON_NODE_ID" => Some("test-node".to_string()),
            "PARTON_DIRECTIVE_GRACE_SECS" => Some("120".to_string()),
            _ => None,
        })
        .expect("config");
        assert_eq!(c.grace_window_secs, 120);
    }

    #[test]
    fn from_lookup_requires_non_empty_node_id() {
        let err = AgentRuntimeConfig::from_lookup(|_| None).expect_err("missing node id");
        assert!(
            err.to_string().contains("PARTON_NODE_ID"),
            "unexpected error: {err}"
        );
        let err = AgentRuntimeConfig::from_lookup(|key| match key {
            "PARTON_NODE_ID" => Some("   ".to_string()),
            _ => None,
        })
        .expect_err("blank node id");
        assert!(err.to_string().contains("PARTON_NODE_ID"));
    }

    #[derive(Clone, Default)]
    struct CaptureState {
        tokens: Arc<Mutex<Vec<Option<String>>>>,
    }

    async fn capture_handler(
        State(state): State<CaptureState>,
        Json(report): Json<crate::NodeHeartbeatReport>,
    ) -> Json<HeartbeatResponse> {
        state
            .tokens
            .lock()
            .expect("lock")
            .push(report.enrollment_token);
        Json(HeartbeatResponse::default())
    }

    /// F11: the enrollment token is only sent on the first (unacknowledged) heartbeat; once a
    /// heartbeat has been accepted, subsequent beats must not resend the long-lived token.
    #[tokio::test]
    #[serial_test::serial]
    async fn run_heartbeat_step_stops_resending_enrollment_token_after_first_ack(
    ) -> anyhow::Result<()> {
        std::env::set_var("PARTON_ENROLLMENT_TOKEN", "ghe.abc.secret");

        let state = CaptureState::default();
        let app = Router::new()
            .route("/api/parton/heartbeat", post(capture_handler))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        tokio::spawn(
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .into_future(),
        );

        let mut config = AgentRuntimeConfig {
            endpoint: format!("http://{addr}/api/parton/heartbeat"),
            node_id: "enroll-node".to_string(),
            cell_id: "local-default".to_string(),
            interval_secs: 1,
            token: None,
            action_lease_secs: 120,
            action_lease_extend_secs: 600,
            grace_window_secs: 300,
        };
        let mut pending_token = None;
        let mut pending_fail = None;
        let mut pending_grace = None;
        let mut enrollment_acknowledged = false;

        for _ in 0..3 {
            run_heartbeat_step(
                &mut config,
                &mut pending_token,
                &mut pending_fail,
                &mut pending_grace,
                &mut enrollment_acknowledged,
            )
            .await?;
        }

        let seen = state.tokens.lock().expect("lock").clone();
        assert_eq!(seen.len(), 3);
        assert_eq!(
            seen[0],
            Some("ghe.abc.secret".to_string()),
            "first heartbeat must present the enrollment token"
        );
        assert_eq!(
            seen[1], None,
            "second heartbeat must not resend the enrollment token"
        );
        assert_eq!(
            seen[2], None,
            "third heartbeat must not resend the enrollment token"
        );

        let _ = shutdown_tx.send(());
        std::env::remove_var("PARTON_ENROLLMENT_TOKEN");
        Ok(())
    }
}
