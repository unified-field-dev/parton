use super::container_status::{
    collect_container_status_report_with_runner, enrich_non_running_with_inspect,
    parse_container_status_report_from_ps_json, DockerContainerRunner,
};
use super::host_capabilities::parse_memtotal_bytes_from_meminfo;
use super::transport::parse_heartbeat_response_body;
use super::*;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::post;
use axum::{Json, Router};
use chrono::Utc;
use std::future::IntoFuture;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::sync::oneshot;

struct StubContainerRunner {
    ps_output: anyhow::Result<String>,
    inspect: std::collections::HashMap<String, anyhow::Result<String>>,
}

impl DockerContainerRunner for StubContainerRunner {
    fn list_containers_json(&self) -> anyhow::Result<String> {
        match &self.ps_output {
            Ok(v) => Ok(v.clone()),
            Err(e) => Err(anyhow::anyhow!(e.to_string())),
        }
    }

    fn inspect_state_json(&self, container_id: &str) -> anyhow::Result<String> {
        match self.inspect.get(container_id) {
            Some(Ok(s)) => Ok(s.clone()),
            Some(Err(e)) => Err(anyhow::anyhow!(e.to_string())),
            None => Err(anyhow::anyhow!("no inspect stub")),
        }
    }
}

#[test]
fn parse_memtotal_bytes_from_meminfo_works() {
    let meminfo = "MemTotal:       16384256 kB\nMemFree:        123456 kB\n";
    let parsed = parse_memtotal_bytes_from_meminfo(meminfo).expect("memtotal parsed");
    assert_eq!(parsed, 16_384_256_u64 * 1024);
}

#[test]
fn parse_container_status_report_from_ps_json_parses_labels() {
    let line = r#"{"ID":"abc123","Names":"/photon-home-0","State":"exited","Status":"Exited (137) 1 hour ago","Labels":"gluon.instance_id=inst-1,gluon.app_id=app-1"}"#;
    let report = parse_container_status_report_from_ps_json(line, Utc::now());
    assert_eq!(report.containers.len(), 1);
    assert_eq!(report.containers[0].instance_id.as_deref(), Some("inst-1"));
    assert_eq!(report.summary.exited, 1);
}

#[test]
fn container_status_report_deserializes_legacy_summary_only() {
    let json = r#"{"running":2,"exited":1,"unhealthy":0}"#;
    let report: ContainerStatusReport = serde_json::from_str(json).expect("deserialize");
    assert!(report.containers.is_empty());
    assert_eq!(report.summary.running, 2);
    assert_eq!(report.summary.exited, 1);
}

#[test]
fn container_status_report_roundtrip_includes_per_container_list() {
    let report = ContainerStatusReport {
        containers: vec![ContainerStatus {
            container_id: "id1".into(),
            container_name: "apps-home-0".into(),
            instance_id: Some("inst".into()),
            state: ContainerState::Running,
            exit_code: None,
            started_at: None,
            finished_at: None,
            health: ContainerHealth::NoCheck,
            restart_count: 0,
            last_observed_at: Utc::now(),
            probe_error: None,
        }],
        summary: ContainerStatusSummary {
            running: 1,
            exited: 0,
            unhealthy: 0,
        },
    };
    let encoded = serde_json::to_value(&report).expect("serialize");
    assert!(encoded.get("containers").is_some());
    let decoded: ContainerStatusReport = serde_json::from_value(encoded).expect("deserialize");
    assert_eq!(decoded.containers.len(), 1);
}

#[test]
fn enrich_non_running_applies_inspect_exit_code() {
    let runner = StubContainerRunner {
        ps_output: Ok(String::new()),
        inspect: [(
            "cid".to_string(),
            Ok(r#"{"Status":"exited","ExitCode":137,"StartedAt":"2026-05-15T15:25:18.928Z","FinishedAt":"2026-05-15T15:26:01.436Z","RestartCount":0}"#.to_string()),
        )]
        .into_iter()
        .collect(),
    };
    let status = ContainerStatus {
        container_id: "cid".into(),
        container_name: "photon-home-0".into(),
        instance_id: None,
        state: ContainerState::Exited,
        exit_code: None,
        started_at: None,
        finished_at: None,
        health: ContainerHealth::Unknown,
        restart_count: 0,
        last_observed_at: Utc::now(),
        probe_error: None,
    };
    let enriched = enrich_non_running_with_inspect(&runner, status);
    assert_eq!(enriched.exit_code, Some(137));
    assert!(enriched.finished_at.is_some());
}

#[test]
fn collect_container_status_report_returns_empty_on_runner_error() {
    let report = collect_container_status_report_with_runner(&StubContainerRunner {
        ps_output: Err(anyhow::anyhow!("boom")),
        inspect: std::collections::HashMap::default(),
    });
    assert!(report.containers.is_empty());
    assert_eq!(report.summary.running, 0);
}

/// F11: `suppress_enrollment_token` must omit the token even when the env var is set, so the
/// agent can stop resending it after a heartbeat has been acknowledged.
#[test]
#[serial_test::serial]
fn build_heartbeat_report_suppresses_enrollment_token_when_overridden() {
    std::env::set_var("PARTON_ENROLLMENT_TOKEN", "ghe.abc.secret");
    let report = build_heartbeat_report_with_overrides(
        "node-1",
        "cell-1",
        HeartbeatReportOverrides {
            suppress_enrollment_token: true,
            ..Default::default()
        },
    )
    .expect("build report");
    assert_eq!(report.enrollment_token, None);
    std::env::remove_var("PARTON_ENROLLMENT_TOKEN");
}

#[test]
#[serial_test::serial]
fn build_heartbeat_report_includes_enrollment_token_by_default() {
    std::env::set_var("PARTON_ENROLLMENT_TOKEN", "ghe.abc.secret");
    let report = build_heartbeat_report_with_overrides(
        "node-1",
        "cell-1",
        HeartbeatReportOverrides::default(),
    )
    .expect("build report");
    assert_eq!(report.enrollment_token, Some("ghe.abc.secret".to_string()));
    std::env::remove_var("PARTON_ENROLLMENT_TOKEN");
}

#[test]
fn heartbeat_roundtrip_json_is_stable() {
    let report = NodeHeartbeatReport {
        node_id: "node-1".to_string(),
        cell_id: "local-default".to_string(),
        capabilities: HostCapabilities {
            hostname: "node-1.local".to_string(),
            arch: "x86_64".to_string(),
            cpu_logical: 8,
            memory_bytes: 0,
            mounts: vec![],
            labels: serde_json::json!({"rack":"a"}),
        },
        containers: ContainerStatusReport {
            containers: Vec::new(),
            summary: ContainerStatusSummary {
                running: 1,
                exited: 0,
                unhealthy: 0,
            },
        },
        observed_at: Utc::now(),
        enrollment_token: None,
        applied_directive_token: None,
        apply_failed: None,
    };
    let encoded = serde_json::to_value(&report).expect("serialize");
    let decoded: NodeHeartbeatReport = serde_json::from_value(encoded).expect("deserialize");
    assert_eq!(decoded.node_id, report.node_id);
    assert_eq!(decoded.containers.summary.running, 1);
}

#[derive(Clone)]
struct HeaderState {
    token: Arc<Mutex<Option<String>>>,
    node_id_header: Arc<Mutex<Option<String>>>,
    authorization: Arc<Mutex<Option<String>>>,
}

async fn success_handler(
    State(state): State<HeaderState>,
    headers: HeaderMap,
    Json(_report): Json<NodeHeartbeatReport>,
) -> Json<HeartbeatResponse> {
    let token = headers
        .get("x-parton-token")
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string);
    *state.token.lock().expect("lock") = token;
    let node_id_header = headers
        .get("x-parton-node-id")
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string);
    *state.node_id_header.lock().expect("lock") = node_id_header;
    *state.authorization.lock().expect("lock") = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string);
    Json(HeartbeatResponse::default())
}

fn sample_report() -> NodeHeartbeatReport {
    NodeHeartbeatReport {
        node_id: "node-1".to_string(),
        cell_id: "cell-1".to_string(),
        capabilities: HostCapabilities {
            hostname: "host".to_string(),
            arch: "x86_64".to_string(),
            cpu_logical: 4,
            memory_bytes: 0,
            mounts: vec![],
            labels: serde_json::json!({}),
        },
        containers: ContainerStatusReport {
            containers: Vec::new(),
            summary: ContainerStatusSummary::default(),
        },
        observed_at: Utc::now(),
        enrollment_token: None,
        applied_directive_token: None,
        apply_failed: None,
    }
}

#[test]
fn parse_heartbeat_response_accepts_legacy_ok() {
    let r = parse_heartbeat_response_body("ok");
    assert!(r.directives.is_empty());
}

#[tokio::test]
async fn send_heartbeat_sets_token_header_when_present() -> anyhow::Result<()> {
    let state = HeaderState {
        token: Arc::new(Mutex::new(None)),
        node_id_header: Arc::new(Mutex::new(None)),
        authorization: Arc::new(Mutex::new(None)),
    };
    let app = Router::new()
        .route("/heartbeat", post(success_handler))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr: SocketAddr = listener.local_addr()?;
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let server = axum::serve(listener, app).with_graceful_shutdown(async move {
        let _ = shutdown_rx.await;
    });
    let server_handle = tokio::spawn(server.into_future());

    let endpoint = format!("http://{addr}/heartbeat");
    send_heartbeat(&endpoint, &sample_report(), Some("shared-token")).await?;
    assert_eq!(
        state.token.lock().expect("lock").clone(),
        Some("shared-token".to_string())
    );
    assert_eq!(
        state.node_id_header.lock().expect("lock").clone(),
        Some(sample_report().node_id)
    );

    let _ = shutdown_tx.send(());
    let _ = server_handle.await;
    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn send_heartbeat_attaches_bearer_in_spiffe_mode() -> anyhow::Result<()> {
    for k in [
        "PARTON_AUTH_MODE",
        "PARTON_SPIFFE_JWT",
        "PARTON_SPIFFE_JWT_PATH",
        "SPIFFE_ENDPOINT_SOCKET",
    ] {
        std::env::remove_var(k);
    }
    std::env::set_var("PARTON_AUTH_MODE", "spiffe");
    std::env::set_var("PARTON_SPIFFE_JWT", "hb.jwt.token");

    let state = HeaderState {
        token: Arc::new(Mutex::new(None)),
        node_id_header: Arc::new(Mutex::new(None)),
        authorization: Arc::new(Mutex::new(None)),
    };
    let app = Router::new()
        .route("/heartbeat", post(success_handler))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr: SocketAddr = listener.local_addr()?;
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let server = axum::serve(listener, app).with_graceful_shutdown(async move {
        let _ = shutdown_rx.await;
    });
    let server_handle = tokio::spawn(server.into_future());

    let endpoint = format!("http://{addr}/heartbeat");
    send_heartbeat(&endpoint, &sample_report(), None).await?;
    assert_eq!(
        state.authorization.lock().expect("lock").clone(),
        Some("Bearer hb.jwt.token".to_string())
    );

    let _ = shutdown_tx.send(());
    let _ = server_handle.await;
    for k in [
        "PARTON_AUTH_MODE",
        "PARTON_SPIFFE_JWT",
        "PARTON_SPIFFE_JWT_PATH",
        "SPIFFE_ENDPOINT_SOCKET",
    ] {
        std::env::remove_var(k);
    }
    Ok(())
}
