//! Integration tests for `execute_claimed_node_action` handoff/deploy command-queue paths.

// Integration test harness: panics on setup/teardown are acceptable failure signals.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::{Arc, Mutex};

use parton::{
    execute_claimed_node_action, ClaimedNodeActionBody, ContainerActionExecutor,
    ContainerActionKind, ContainerActionRequest, ContainerActionResponse,
};

// `execute_claimed_node_action` moves the executor into a `tokio::task::spawn_blocking`
// closure, so it must be `Send + Sync + 'static`; `Mutex` (not `RefCell`) backs the recorded
// state and `Arc` lets the test keep its own handle for post-call assertions.
struct RecordingExecutor {
    last_action: Mutex<Option<ContainerActionKind>>,
    last_request: Mutex<Option<ContainerActionRequest>>,
}

impl ContainerActionExecutor for RecordingExecutor {
    fn execute_action(
        &self,
        request: &ContainerActionRequest,
    ) -> anyhow::Result<ContainerActionResponse> {
        *self.last_action.lock().expect("lock") = Some(request.action);
        *self.last_request.lock().expect("lock") = Some(request.clone());
        Ok(ContainerActionResponse {
            action: request.action,
            container_ref: request.container_ref.clone(),
            success: true,
            message: "stub".into(),
            payload: serde_json::json!({}),
        })
    }
}

#[tokio::test]
async fn deploy_handoff_executes_as_deploy() -> anyhow::Result<()> {
    let ex = Arc::new(RecordingExecutor {
        last_action: Mutex::new(None),
        last_request: Mutex::new(None),
    });
    let claimed = ClaimedNodeActionBody {
        command_id: "cmd1".into(),
        action_kind: "deploy_handoff".into(),
        payload_json: serde_json::json!({
            "node_id": "node-a",
            "container_ref": "c1",
            "image_ref": "img@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "env_vars": ["E=1"],
            "secret_env_vars": [],
            "port_mappings": ["80:80"],
            "extra_hosts": [],
            "volume_mounts": [],
            "network": "bridge",
            "transfer_id": "t1"
        }),
        attempt: 1,
        correlation_key: None,
        sequence: None,
    };
    let report = execute_claimed_node_action(Arc::clone(&ex), &claimed, "node-a").await?;
    assert!(report.success);
    assert_eq!(
        *ex.last_action.lock().expect("lock"),
        Some(ContainerActionKind::Deploy)
    );
    Ok(())
}

#[tokio::test]
async fn deploy_handoff_maps_resolved_secret_env_vars() -> anyhow::Result<()> {
    let ex = Arc::new(RecordingExecutor {
        last_action: Mutex::new(None),
        last_request: Mutex::new(None),
    });
    let claimed = ClaimedNodeActionBody {
        command_id: "cmd1b".into(),
        action_kind: "deploy_handoff".into(),
        payload_json: serde_json::json!({
            "node_id": "node-a",
            "container_ref": "c1",
            "image_ref": "img@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "env_vars": [],
            "secret_env_vars": [
                {"name": "HANDOFF_BUNDLE_ROOT_SECRET", "value": "c2VjcmV0"}
            ],
            "port_mappings": [],
            "extra_hosts": [],
            "volume_mounts": [],
            "network": null,
            "transfer_id": "t1"
        }),
        attempt: 1,
        correlation_key: None,
        sequence: None,
    };
    let report = execute_claimed_node_action(Arc::clone(&ex), &claimed, "node-a").await?;
    assert!(report.success);
    let req = ex
        .last_request
        .lock()
        .expect("lock")
        .clone()
        .expect("captured request");
    assert_eq!(req.secret_env_vars.len(), 1);
    assert_eq!(req.secret_env_vars[0].name, "HANDOFF_BUNDLE_ROOT_SECRET");
    assert_eq!(req.secret_env_vars[0].value, "c2VjcmV0");
    Ok(())
}

#[tokio::test]
async fn deploy_handoff_rejects_non_string_secret_env_value() {
    let ex = Arc::new(RecordingExecutor {
        last_action: Mutex::new(None),
        last_request: Mutex::new(None),
    });
    let claimed = ClaimedNodeActionBody {
        command_id: "cmd1c".into(),
        action_kind: "deploy_handoff".into(),
        payload_json: serde_json::json!({
            "node_id": "node-a",
            "container_ref": "c1",
            "image_ref": "img:1",
            "env_vars": [],
            "secret_env_vars": [
                {"name": "HANDOFF_BUNDLE_ROOT_SECRET", "value": {"$secret_ref": {"id": "x", "version": 1}, "field": "root_secret"}}
            ],
            "port_mappings": [],
            "extra_hosts": [],
            "volume_mounts": [],
            "network": null,
            "transfer_id": "t1"
        }),
        attempt: 1,
        correlation_key: None,
        sequence: None,
    };
    let err = execute_claimed_node_action(Arc::clone(&ex), &claimed, "node-a")
        .await
        .expect_err("non-string secret");
    let msg = err.to_string();
    assert!(
        msg.contains("JSON strings") || msg.contains("secret_env_vars"),
        "{msg}"
    );
}

#[tokio::test]
async fn teardown_handoff_executes_as_stop() -> anyhow::Result<()> {
    let ex = Arc::new(RecordingExecutor {
        last_action: Mutex::new(None),
        last_request: Mutex::new(None),
    });
    let claimed = ClaimedNodeActionBody {
        command_id: "cmd2".into(),
        action_kind: "teardown_handoff".into(),
        payload_json: serde_json::json!({
            "node_id": "node-a",
            "container_ref": "c1",
            "remove_volumes": false,
            "expected_container_id": "abc123"
        }),
        attempt: 1,
        correlation_key: None,
        sequence: None,
    };
    let report = execute_claimed_node_action(Arc::clone(&ex), &claimed, "node-a").await?;
    assert!(report.success);
    assert_eq!(
        *ex.last_action.lock().expect("lock"),
        Some(ContainerActionKind::Stop)
    );
    Ok(())
}
