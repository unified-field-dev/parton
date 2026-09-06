//! Integration tests for `execute_container_action` request validation and executor dispatch.

use std::collections::HashMap;

use parton::{
    execute_container_action, ContainerActionExecutor, ContainerActionKind, ContainerActionRequest,
    ContainerActionResponse,
};

struct StubExecutor {
    fail: bool,
}

impl ContainerActionExecutor for StubExecutor {
    fn execute_action(
        &self,
        request: &ContainerActionRequest,
    ) -> anyhow::Result<ContainerActionResponse> {
        if self.fail {
            anyhow::bail!("simulated failure: {}", request.action.as_str());
        }
        Ok(ContainerActionResponse {
            action: request.action,
            container_ref: request.container_ref.clone(),
            success: true,
            message: "ok".to_string(),
            payload: serde_json::json!({ "output": "stub" }),
        })
    }
}

#[test]
fn action_executor_returns_success_response_shape() -> anyhow::Result<()> {
    let request = ContainerActionRequest {
        node_id: "node-a".to_string(),
        container_ref: "svc".to_string(),
        action: ContainerActionKind::Inspect,
        tail_lines: None,
        image_ref: None,
        env_vars: vec![],
        secret_env_vars: vec![],
        port_mappings: vec![],
        entrypoint: None,
        command: vec![],
        restart_policy: None,
        volume_mounts: vec![],
        resource_limits: None,
        health_check: None,
        labels: HashMap::new(),
        extra_hosts: vec![],
        network: None,
        diagnostic: None,
        wireguard_peer: None,
        grow_fs: None,
        templated_exec: None,
        expected_container_id: None,
    };
    let result = execute_container_action(&StubExecutor { fail: false }, &request)?;
    assert_eq!(result.action, ContainerActionKind::Inspect);
    assert_eq!(result.container_ref, "svc");
    assert!(result.success);
    assert_eq!(result.payload["output"], "stub");
    Ok(())
}

#[test]
fn action_executor_failure_surfaces_error() {
    let request = ContainerActionRequest {
        node_id: "node-a".to_string(),
        container_ref: "svc".to_string(),
        action: ContainerActionKind::Restart,
        tail_lines: None,
        image_ref: None,
        env_vars: vec![],
        secret_env_vars: vec![],
        port_mappings: vec![],
        entrypoint: None,
        command: vec![],
        restart_policy: None,
        volume_mounts: vec![],
        resource_limits: None,
        health_check: None,
        labels: HashMap::new(),
        extra_hosts: vec![],
        network: None,
        diagnostic: None,
        wireguard_peer: None,
        grow_fs: None,
        templated_exec: None,
        expected_container_id: None,
    };
    let err =
        execute_container_action(&StubExecutor { fail: true }, &request).expect_err("failure");
    assert!(err.to_string().contains("simulated failure"));
}
