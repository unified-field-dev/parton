//! Wire types for the node action queue: claimed commands, result reports, and the private
//! `deploy_handoff` / `teardown_handoff` payload shapes.

use crate::VolumeMount;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A single action claimed from the control-plane node action queue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimedNodeActionBody {
    /// Server-assigned command identifier (idempotency + result correlation).
    pub command_id: String,
    /// Wire action kind (e.g. `deploy`, `health_check`, `deploy_handoff`).
    pub action_kind: String,
    /// Action-specific JSON payload. Required fields by `action_kind`:
    ///
    /// | `action_kind` | Payload shape |
    /// |---------------|---------------|
    /// | `health_check` | `{ "url": "…", "require_mode_remote"?: bool, "require_all_per_logical_state_ok"?: bool, "assertions"?: […] }` — `url` is SSRF-gated |
    /// | `handoff_bundle_import` | `{ "url", "authorization_bearer", "bundle_base64" }` |
    /// | `deploy_handoff` | Deploy handoff wire (`node_id`, `container_ref`, `image_ref`, env/ports/volumes, optional `health_url` / `import_base_url` / `transfer_id`) |
    /// | `teardown_handoff` | `{ "node_id", "container_ref", "remove_volumes"?: bool, "expected_container_id"?: string }` |
    /// | Docker / agent kinds (`deploy`, `start`, `stop`, `restart`, `logs`, `inspect`, `ensure_network`, `probe_host`, `diagnostic`, `wireguard_peer`, `ensure_docker_image`, `grow_fs`, `templated_exec`) | Full [`crate::ContainerActionRequest`] JSON (`node_id` must match this agent) |
    pub payload_json: serde_json::Value,
    /// Attempt counter for this command (increments on retry).
    pub attempt: i64,
    /// Optional correlation key grouping related commands.
    pub correlation_key: Option<String>,
    /// Optional monotonic sequence number within a correlation group.
    pub sequence: Option<i64>,
}

/// Result body `POSTed` back to the control plane after executing a claimed action.
#[derive(Debug, Serialize)]
pub struct ReportRequestBody {
    /// Command identifier being reported (matches [`ClaimedNodeActionBody::command_id`]).
    pub command_id: String,
    /// Reporting node id.
    pub node_id: String,
    /// Attempt counter this result corresponds to.
    pub attempt: i64,
    /// Whether the action succeeded.
    pub success: bool,
    /// Captured stdout (clipped), when any.
    pub stdout: Option<String>,
    /// Captured stderr (clipped), when any.
    pub stderr: Option<String>,
    /// Short error summary for failed actions.
    pub error_summary: Option<String>,
    /// Structured, action-specific result payload.
    pub payload_json: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub(super) struct DeploySecretEnvVarWire {
    pub(super) name: String,
    pub(super) value: Value,
}

#[derive(Debug, Deserialize)]
pub(super) struct DeployHandoffWire {
    pub(super) node_id: String,
    pub(super) container_ref: String,
    pub(super) image_ref: String,
    #[serde(default)]
    pub(super) env_vars: Vec<String>,
    #[serde(default)]
    pub(super) secret_env_vars: Vec<DeploySecretEnvVarWire>,
    #[serde(default)]
    pub(super) port_mappings: Vec<String>,
    #[serde(default)]
    pub(super) extra_hosts: Vec<String>,
    #[serde(default)]
    pub(super) volume_mounts: Vec<VolumeMount>,
    pub(super) network: Option<String>,
    pub(super) health_url: Option<String>,
    pub(super) import_base_url: Option<String>,
    pub(super) transfer_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct TeardownHandoffWire {
    pub(super) node_id: String,
    pub(super) container_ref: String,
    #[serde(default)]
    pub(super) remove_volumes: bool,
    pub(super) expected_container_id: Option<String>,
}
