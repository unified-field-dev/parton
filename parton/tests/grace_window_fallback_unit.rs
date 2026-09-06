//! Grace-window fallback: failed new-CP heartbeat reports `apply_failed` to the previous CP.

// Integration test harness: panics on setup/teardown are acceptable failure signals.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::future::IntoFuture;
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use chrono::{Duration, Utc};
use parton::{
    agent_runtime::{
        run_heartbeat_step, AgentRuntimeConfig, HeartbeatStepOutcome, PendingReenrollGrace,
    },
    NodeHeartbeatReport,
};
use tokio::sync::oneshot;

#[derive(Clone)]
struct CaptureState {
    reports: Arc<Mutex<Vec<NodeHeartbeatReport>>>,
    fail: Arc<std::sync::atomic::AtomicBool>,
}

async fn ingest_handler(
    State(state): State<CaptureState>,
    Json(report): Json<NodeHeartbeatReport>,
) -> (StatusCode, Json<&'static str>) {
    state.reports.lock().expect("lock").push(report);
    if state.fail.load(std::sync::atomic::Ordering::SeqCst) {
        return (StatusCode::UNAUTHORIZED, Json("unauthorized"));
    }
    (StatusCode::OK, Json("ok"))
}

#[tokio::test]
async fn failed_new_cp_heartbeat_reports_apply_failed_to_previous_cp() -> anyhow::Result<()> {
    let old_reports = Arc::new(Mutex::new(Vec::<NodeHeartbeatReport>::new()));
    let new_fail = Arc::new(std::sync::atomic::AtomicBool::new(true));

    let old_state = CaptureState {
        reports: old_reports.clone(),
        fail: Arc::new(std::sync::atomic::AtomicBool::new(false)),
    };
    let new_state = CaptureState {
        reports: Arc::new(Mutex::new(Vec::new())),
        fail: new_fail.clone(),
    };

    let old_app = Router::new()
        .route("/api/parton/heartbeat", post(ingest_handler))
        .with_state(old_state);
    let new_app = Router::new()
        .route("/api/parton/heartbeat", post(ingest_handler))
        .with_state(new_state);

    let old_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let new_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let old_addr = old_listener.local_addr()?;
    let new_addr = new_listener.local_addr()?;
    let (old_shutdown, old_rx) = oneshot::channel();
    let (new_shutdown, new_rx) = oneshot::channel();
    tokio::spawn(
        axum::serve(old_listener, old_app)
            .with_graceful_shutdown(async move {
                let _ = old_rx.await;
            })
            .into_future(),
    );
    tokio::spawn(
        axum::serve(new_listener, new_app)
            .with_graceful_shutdown(async move {
                let _ = new_rx.await;
            })
            .into_future(),
    );

    let old_url = format!("http://{old_addr}/api/parton/heartbeat");
    let new_url = format!("http://{new_addr}/api/parton/heartbeat");

    let mut config = AgentRuntimeConfig {
        endpoint: new_url,
        node_id: "grace-node".to_string(),
        cell_id: "local-default".to_string(),
        interval_secs: 1,
        token: None,
        action_lease_secs: 120,
        action_lease_extend_secs: 600,
        grace_window_secs: 300,
    };
    let mut pending_token = None;
    let mut pending_fail = None;
    let mut pending_grace = Some(PendingReenrollGrace {
        prev_endpoint: old_url.clone(),
        prev_token: None,
        deadline: Utc::now() + Duration::minutes(5),
    });
    let mut enrollment_acknowledged = false;

    let outcome = run_heartbeat_step(
        &mut config,
        &mut pending_token,
        &mut pending_fail,
        &mut pending_grace,
        &mut enrollment_acknowledged,
    )
    .await?;
    assert_eq!(outcome, HeartbeatStepOutcome::Continue);

    let old = old_reports.lock().expect("lock");
    assert!(
        old.iter()
            .any(|r| r.apply_failed.as_ref().is_some_and(|s| !s.is_empty())),
        "expected apply_failed on fallback heartbeat to previous CP"
    );

    let _ = old_shutdown.send(());
    let _ = new_shutdown.send(());
    Ok(())
}

#[tokio::test]
async fn grace_expiry_returns_exit_outcome() -> anyhow::Result<()> {
    let new_fail = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let new_state = CaptureState {
        reports: Arc::new(Mutex::new(Vec::new())),
        fail: new_fail,
    };
    let new_app = Router::new()
        .route("/api/parton/heartbeat", post(ingest_handler))
        .with_state(new_state);
    let new_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let new_addr = new_listener.local_addr()?;
    let (new_shutdown, new_rx) = oneshot::channel();
    tokio::spawn(
        axum::serve(new_listener, new_app)
            .with_graceful_shutdown(async move {
                let _ = new_rx.await;
            })
            .into_future(),
    );

    let mut config = AgentRuntimeConfig {
        endpoint: format!("http://{new_addr}/api/parton/heartbeat"),
        node_id: "grace-node".to_string(),
        cell_id: "local-default".to_string(),
        interval_secs: 1,
        token: None,
        action_lease_secs: 120,
        action_lease_extend_secs: 600,
        grace_window_secs: 30,
    };
    let mut pending_grace = Some(PendingReenrollGrace {
        prev_endpoint: "http://127.0.0.1:9/api/parton/heartbeat".to_string(),
        prev_token: None,
        deadline: Utc::now() - Duration::seconds(1),
    });

    let mut enrollment_acknowledged = false;
    let outcome = run_heartbeat_step(
        &mut config,
        &mut None,
        &mut None,
        &mut pending_grace,
        &mut enrollment_acknowledged,
    )
    .await?;
    assert_eq!(outcome, HeartbeatStepOutcome::ExitGraceExpired);

    let _ = new_shutdown.send(());
    Ok(())
}
