use super::generic::run_generic_container_action;
use super::handoff::{run_teardown_handoff_with_volume_runner, TeardownVolumeRunner};
use super::*;
use crate::{
    ContainerActionExecutor, ContainerActionKind, ContainerActionRequest, ContainerActionResponse,
};
use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::post;
use axum::Json;
use axum::Router;
use serial_test::serial;
use std::future::IntoFuture;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::sync::oneshot;

#[derive(Clone, Default)]
struct CapturedHeaders {
    node_id: Arc<Mutex<Option<String>>>,
    authorization: Arc<Mutex<Option<String>>>,
    parton_token: Arc<Mutex<Option<String>>>,
}

fn extract_node_id_header(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-parton-node-id")
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string)
}

fn capture_auth_headers(state: &CapturedHeaders, headers: &HeaderMap) {
    *state.node_id.lock().expect("lock") = extract_node_id_header(headers);
    *state.authorization.lock().expect("lock") = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string);
    *state.parton_token.lock().expect("lock") = headers
        .get("x-parton-token")
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string);
}

async fn claim_handler(
    State(state): State<CapturedHeaders>,
    headers: HeaderMap,
    Json(_body): Json<serde_json::Value>,
) -> axum::http::StatusCode {
    capture_auth_headers(&state, &headers);
    axum::http::StatusCode::NO_CONTENT
}

async fn extend_lease_handler(
    State(state): State<CapturedHeaders>,
    headers: HeaderMap,
    Json(_body): Json<serde_json::Value>,
) -> axum::http::StatusCode {
    capture_auth_headers(&state, &headers);
    axum::http::StatusCode::NO_CONTENT
}

async fn result_handler(
    State(state): State<CapturedHeaders>,
    headers: HeaderMap,
    Json(_body): Json<serde_json::Value>,
) -> axum::http::StatusCode {
    capture_auth_headers(&state, &headers);
    axum::http::StatusCode::ACCEPTED
}

async fn spawn_test_server(
    router: Router,
) -> anyhow::Result<(String, oneshot::Sender<()>, tokio::task::JoinHandle<()>)> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr: SocketAddr = listener.local_addr()?;
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let server = axum::serve(listener, router).with_graceful_shutdown(async move {
        let _ = shutdown_rx.await;
    });
    let handle = tokio::spawn(async move {
        let _ = server.into_future().await;
    });
    Ok((format!("http://{addr}"), shutdown_tx, handle))
}

#[tokio::test]
#[serial]
async fn post_claim_action_sends_node_id_header() -> anyhow::Result<()> {
    clear_spiffe_auth_env();
    let state = CapturedHeaders::default();
    let app = Router::new()
        .route("/actions/claim", post(claim_handler))
        .with_state(state.clone());
    let (base, shutdown_tx, handle) = spawn_test_server(app).await?;

    post_claim_action(&base, "node-xyz", None, None).await?;
    assert_eq!(
        state.node_id.lock().expect("lock").clone(),
        Some("node-xyz".to_string())
    );

    let _ = shutdown_tx.send(());
    let _ = handle.await;
    clear_spiffe_auth_env();
    Ok(())
}

#[tokio::test]
async fn post_extend_action_lease_sends_node_id_header() -> anyhow::Result<()> {
    let state = CapturedHeaders::default();
    let app = Router::new()
        .route("/actions/extend-lease", post(extend_lease_handler))
        .with_state(state.clone());
    let (base, shutdown_tx, handle) = spawn_test_server(app).await?;

    post_extend_action_lease(&base, "cmd-1", "node-xyz", None, None).await?;
    assert_eq!(
        state.node_id.lock().expect("lock").clone(),
        Some("node-xyz".to_string())
    );

    let _ = shutdown_tx.send(());
    let _ = handle.await;
    Ok(())
}

#[tokio::test]
async fn post_action_result_sends_node_id_header() -> anyhow::Result<()> {
    let state = CapturedHeaders::default();
    let app = Router::new()
        .route("/actions/result", post(result_handler))
        .with_state(state.clone());
    let (base, shutdown_tx, handle) = spawn_test_server(app).await?;

    post_action_result(
        &base,
        ReportRequestBody {
            command_id: "cmd-1".to_string(),
            node_id: "node-xyz".to_string(),
            attempt: 1,
            success: true,
            stdout: None,
            stderr: None,
            error_summary: None,
            payload_json: None,
        },
        None,
    )
    .await?;
    assert_eq!(
        state.node_id.lock().expect("lock").clone(),
        Some("node-xyz".to_string())
    );

    let _ = shutdown_tx.send(());
    let _ = handle.await;
    Ok(())
}

fn clear_spiffe_auth_env() {
    for k in [
        "PARTON_AUTH_MODE",
        "PARTON_SPIFFE_JWT",
        "PARTON_SPIFFE_JWT_PATH",
        "SPIFFE_ENDPOINT_SOCKET",
    ] {
        std::env::remove_var(k);
    }
}

#[tokio::test]
#[serial]
async fn post_claim_action_sends_authorization_bearer_in_spiffe_mode() -> anyhow::Result<()> {
    clear_spiffe_auth_env();
    std::env::set_var("PARTON_AUTH_MODE", "spiffe");
    std::env::set_var("PARTON_SPIFFE_JWT", "aaa.bbb.ccc");

    let state = CapturedHeaders::default();
    let app = Router::new()
        .route("/actions/claim", post(claim_handler))
        .with_state(state.clone());
    let (base, shutdown_tx, handle) = spawn_test_server(app).await?;

    post_claim_action(&base, "node-xyz", None, Some("shared-token")).await?;
    assert_eq!(
        state.authorization.lock().expect("lock").clone(),
        Some("Bearer aaa.bbb.ccc".to_string())
    );
    assert_eq!(
        state.parton_token.lock().expect("lock").clone(),
        Some("shared-token".to_string())
    );

    let _ = shutdown_tx.send(());
    let _ = handle.await;
    clear_spiffe_auth_env();
    Ok(())
}

#[tokio::test]
#[serial]
async fn post_action_result_sends_authorization_bearer_in_spiffe_mode() -> anyhow::Result<()> {
    clear_spiffe_auth_env();
    std::env::set_var("PARTON_AUTH_MODE", "spiffe");
    std::env::set_var("PARTON_SPIFFE_JWT", "result.jwt.token");

    let state = CapturedHeaders::default();
    let app = Router::new()
        .route("/actions/result", post(result_handler))
        .with_state(state.clone());
    let (base, shutdown_tx, handle) = spawn_test_server(app).await?;

    post_action_result(
        &base,
        ReportRequestBody {
            command_id: "cmd-1".to_string(),
            node_id: "node-xyz".to_string(),
            attempt: 1,
            success: true,
            stdout: None,
            stderr: None,
            error_summary: None,
            payload_json: None,
        },
        None,
    )
    .await?;
    assert_eq!(
        state.authorization.lock().expect("lock").clone(),
        Some("Bearer result.jwt.token".to_string())
    );

    let _ = shutdown_tx.send(());
    let _ = handle.await;
    clear_spiffe_auth_env();
    Ok(())
}

#[tokio::test]
#[serial]
async fn post_claim_action_fails_before_http_when_spiffe_without_jwt() -> anyhow::Result<()> {
    clear_spiffe_auth_env();
    std::env::set_var("PARTON_AUTH_MODE", "spiffe");

    let state = CapturedHeaders::default();
    let app = Router::new()
        .route("/actions/claim", post(claim_handler))
        .with_state(state.clone());
    let (base, shutdown_tx, handle) = spawn_test_server(app).await?;

    let err = post_claim_action(&base, "node-xyz", None, None)
        .await
        .expect_err("spiffe without jwt");
    assert!(!err.to_string().is_empty());
    assert!(
        state.node_id.lock().expect("lock").is_none(),
        "server must not see the request"
    );

    let _ = shutdown_tx.send(());
    let _ = handle.await;
    clear_spiffe_auth_env();
    Ok(())
}

struct RecordingExecutor {
    seen_action: std::cell::RefCell<Option<ContainerActionKind>>,
    seen_container_ref: std::cell::RefCell<Option<String>>,
}

impl RecordingExecutor {
    fn new() -> Self {
        Self {
            seen_action: std::cell::RefCell::new(None),
            seen_container_ref: std::cell::RefCell::new(None),
        }
    }
}

impl ContainerActionExecutor for RecordingExecutor {
    fn execute_action(
        &self,
        request: &ContainerActionRequest,
    ) -> anyhow::Result<ContainerActionResponse> {
        *self.seen_action.borrow_mut() = Some(request.action);
        *self.seen_container_ref.borrow_mut() = Some(request.container_ref.clone());
        Ok(ContainerActionResponse {
            action: request.action,
            container_ref: request.container_ref.clone(),
            success: true,
            message: "stop succeeded".to_string(),
            payload: serde_json::json!({}),
        })
    }
}

struct FailingStopExecutor;
impl ContainerActionExecutor for FailingStopExecutor {
    fn execute_action(
        &self,
        _request: &ContainerActionRequest,
    ) -> anyhow::Result<ContainerActionResponse> {
        anyhow::bail!("docker stop failed")
    }
}

fn generic_claimed(payload: serde_json::Value) -> ClaimedNodeActionBody {
    ClaimedNodeActionBody {
        command_id: "cmd-generic".to_string(),
        action_kind: "stop".to_string(),
        payload_json: payload,
        attempt: 1,
        correlation_key: None,
        sequence: None,
    }
}

fn generic_container_action_request(node_id: &str) -> serde_json::Value {
    serde_json::json!({
        "node_id": node_id,
        "container_ref": "svc-a",
        "action": "stop",
        "env_vars": [],
        "secret_env_vars": [],
        "port_mappings": [],
        "extra_hosts": [],
        "command": [],
        "volume_mounts": [],
        "labels": {},
    })
}

/// F10: `run_generic_container_action` must refuse a payload whose `node_id` does not match
/// the executing agent, mirroring the same guard on `deploy_handoff` / `teardown_handoff`.
#[test]
fn run_generic_container_action_rejects_node_id_mismatch() {
    let claimed = generic_claimed(generic_container_action_request("node-other"));
    let executor = RecordingExecutor::new();
    let report = run_generic_container_action(&executor, &claimed, "node-1");
    assert!(
        !report.success,
        "mismatched node_id must not be treated as success"
    );
    assert!(
        executor.seen_action.borrow().is_none(),
        "executor must not run when node_id mismatches"
    );
    assert!(report
        .error_summary
        .unwrap_or_default()
        .contains("node_id mismatch"));
}

#[test]
fn run_generic_container_action_allows_matching_node_id() {
    let claimed = generic_claimed(generic_container_action_request("node-1"));
    let executor = RecordingExecutor::new();
    let report = run_generic_container_action(&executor, &claimed, "node-1");
    assert!(report.success);
    assert_eq!(
        executor.seen_action.borrow().clone(),
        Some(ContainerActionKind::Stop)
    );
}

struct RecordingVolumeRunner {
    result: anyhow::Result<std::process::Output>,
    seen_container_ref: std::cell::RefCell<Option<String>>,
}

impl TeardownVolumeRunner for RecordingVolumeRunner {
    fn remove_with_volumes(&self, container_ref: &str) -> anyhow::Result<std::process::Output> {
        *self.seen_container_ref.borrow_mut() = Some(container_ref.to_string());
        match &self.result {
            Ok(output) => Ok(output.clone()),
            Err(e) => Err(anyhow::anyhow!("{e}")),
        }
    }
}

fn rm_output(status: i32, stdout: &str, stderr: &str) -> std::process::Output {
    use std::os::unix::process::ExitStatusExt;
    std::process::Output {
        status: std::process::ExitStatus::from_raw(status),
        stdout: stdout.as_bytes().to_vec(),
        stderr: stderr.as_bytes().to_vec(),
    }
}

fn teardown_claimed(payload: serde_json::Value) -> ClaimedNodeActionBody {
    ClaimedNodeActionBody {
        command_id: "cmd-1".to_string(),
        action_kind: "teardown_handoff".to_string(),
        payload_json: payload,
        attempt: 1,
        correlation_key: None,
        sequence: None,
    }
}

#[test]
fn teardown_handoff_maps_to_stop_action() {
    let claimed = teardown_claimed(serde_json::json!({
        "node_id": "node-1",
        "container_ref": "svc-a",
        "remove_volumes": false,
    }));
    let executor = RecordingExecutor::new();
    let runner = RecordingVolumeRunner {
        result: Ok(rm_output(0, "", "")),
        seen_container_ref: std::cell::RefCell::new(None),
    };
    let report = run_teardown_handoff_with_volume_runner(&executor, &runner, &claimed, "node-1")
        .expect("teardown succeeds");
    assert!(report.success);
    assert_eq!(
        executor.seen_action.borrow().clone(),
        Some(ContainerActionKind::Stop)
    );
    assert!(
        runner.seen_container_ref.borrow().is_none(),
        "docker rm -v must not run when remove_volumes is false"
    );
}

#[test]
fn teardown_handoff_runs_docker_rm_v_when_remove_volumes_true() {
    let claimed = teardown_claimed(serde_json::json!({
        "node_id": "node-1",
        "container_ref": "svc-a",
        "remove_volumes": true,
    }));
    let executor = RecordingExecutor::new();
    let runner = RecordingVolumeRunner {
        result: Ok(rm_output(0, "svc-a", "")),
        seen_container_ref: std::cell::RefCell::new(None),
    };
    let report = run_teardown_handoff_with_volume_runner(&executor, &runner, &claimed, "node-1")
        .expect("teardown + volume removal succeeds");
    assert!(report.success);
    assert_eq!(
        runner.seen_container_ref.borrow().clone(),
        Some("svc-a".to_string())
    );
    let payload = report.payload_json.expect("payload present");
    assert_eq!(payload["volumes_removed"], serde_json::json!(true));
}

#[test]
fn teardown_handoff_fails_closed_when_docker_rm_v_exits_nonzero() {
    let claimed = teardown_claimed(serde_json::json!({
        "node_id": "node-1",
        "container_ref": "svc-a",
        "remove_volumes": true,
    }));
    let executor = RecordingExecutor::new();
    let runner = RecordingVolumeRunner {
        result: Ok(rm_output(1, "", "no such container")),
        seen_container_ref: std::cell::RefCell::new(None),
    };
    let report = run_teardown_handoff_with_volume_runner(&executor, &runner, &claimed, "node-1")
        .expect("report is still produced");
    assert!(!report.success, "nonzero docker rm -v must fail closed");
    assert!(report
        .error_summary
        .unwrap_or_default()
        .contains("docker rm -v"));
}

#[test]
fn teardown_handoff_fails_closed_when_docker_missing() {
    let claimed = teardown_claimed(serde_json::json!({
        "node_id": "node-1",
        "container_ref": "svc-a",
        "remove_volumes": true,
    }));
    let executor = RecordingExecutor::new();
    let runner = RecordingVolumeRunner {
        result: Err(anyhow::anyhow!("docker: command not found")),
        seen_container_ref: std::cell::RefCell::new(None),
    };
    let report = run_teardown_handoff_with_volume_runner(&executor, &runner, &claimed, "node-1")
        .expect("report is still produced");
    assert!(
        !report.success,
        "missing docker binary must fail closed, never a synthetic success"
    );
}

#[test]
fn teardown_handoff_does_not_remove_volumes_when_stop_fails() {
    let claimed = teardown_claimed(serde_json::json!({
        "node_id": "node-1",
        "container_ref": "svc-a",
        "remove_volumes": true,
    }));
    let runner = RecordingVolumeRunner {
        result: Ok(rm_output(0, "", "")),
        seen_container_ref: std::cell::RefCell::new(None),
    };
    let report =
        run_teardown_handoff_with_volume_runner(&FailingStopExecutor, &runner, &claimed, "node-1")
            .expect("report is still produced");
    assert!(!report.success);
    assert!(
        runner.seen_container_ref.borrow().is_none(),
        "docker rm -v must not run when Stop itself failed"
    );
}
