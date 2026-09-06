//! Host agent library and binary: heartbeat telemetry, Docker / host actions, and a
//! leased command-queue client that talks to a cell control plane over HTTP.
//!
//! Library callers use the same APIs as the `parton` binary. Queue-only kinds include
//! `health_check`, `handoff_bundle_import`, `deploy_handoff`, and `teardown_handoff`.
//!
//! # Features
//!
//! - **Heartbeat telemetry** — build and send [`NodeHeartbeatReport`] payloads with
//!   [`build_heartbeat_report`] / [`send_heartbeat`] ([Quick Example](#quick-example)).
//! - **Command queue client** — claim a leased action, run it, and post the result with
//!   [`post_claim_action`] and [`execute_claimed_node_action`]
//!   ([Command queue client](#command-queue-client)).
//! - **Docker lifecycle** — start/stop/deploy/inspect and allowlisted
//!   [`TemplatedExecId`] ops via [`execute_container_action`]
//!   ([Quick Example](#quick-example)).
//! - **Host ops** — probe, grow filesystem, `WireGuard` peer, and diagnostics
//!   ([`GrowFsSpec`], [`DiagnosticSpec`], [`WireguardPeerSpec`], [`collect_host_info`]).
//! - **Handoff directives** — apply signed re-enroll / revoke directives with
//!   [`apply_directives`] ([Handoff directives](#handoff-directives)).
//! - **SSRF / deploy policy / cosign** — URL allowlists and digest-pinned deploy defaults
//!   on [`url_allowed_for_agent_fetch`] and [`execute_container_action`].
//! - **Prometheus metrics** — scrape helpers in [`agent_metrics`].
//! - **Agent binary loop** — one heartbeat iteration via [`agent_runtime`]
//!   ([Binary Runtime](#binary-runtime)).
//!
//! # Quick Example
//!
//! Prerequisites: a Rust crate depending on `parton`. Docker is required only for
//! container / `templated_exec` calls (the heartbeat builder tolerates a missing daemon).
//!
//! 1. Call [`build_heartbeat_report`] with a stable node id and cell id.
//! 2. Serialize or POST the report ([`send_heartbeat`]) and inspect the JSON / ack.
//! 3. For local container work, build a [`ContainerActionRequest`] and call
//!    [`execute_container_action`].
//!
//! Failures: Docker CLI errors, policy denials (host networking, unpinned images), and
//! HTTP / auth errors on send. Next: [Command queue client](#command-queue-client) or
//! [Binary Runtime](#binary-runtime). Runnable JSON smoke:
//! `cargo run -p parton --example heartbeat_report`.
//!
//! Build and serialize a heartbeat payload:
//!
//! ```no_run
//! use parton::build_heartbeat_report;
//!
//! # fn main() -> anyhow::Result<()> {
//! let report = build_heartbeat_report("node-1", "local-default")?;
//! assert_eq!(report.node_id, "node-1");
//! println!("{}", serde_json::to_string_pretty(&report)?);
//! # Ok(())
//! # }
//! ```
//!
//! Promote a Postgres replica in-container via allowlisted [`TemplatedExecId`]
//! (placement ids are already resolved by the control plane):
//!
//! ```no_run
//! use parton::{
//!     execute_container_action, ContainerActionKind, ContainerActionRequest,
//!     DockerCliActionExecutor, TemplatedExecId, TemplatedExecParams, TemplatedExecSpec,
//! };
//!
//! # fn main() -> anyhow::Result<()> {
//! let request = ContainerActionRequest {
//!     node_id: "node-1".to_string(),
//!     container_ref: "pg-replica-0".to_string(),
//!     action: ContainerActionKind::TemplatedExec,
//!     tail_lines: None,
//!     image_ref: None,
//!     env_vars: vec![],
//!     secret_env_vars: vec![],
//!     port_mappings: vec![],
//!     entrypoint: None,
//!     command: vec![],
//!     restart_policy: None,
//!     volume_mounts: vec![],
//!     resource_limits: None,
//!     health_check: None,
//!     labels: Default::default(),
//!     extra_hosts: vec![],
//!     network: None,
//!     diagnostic: None,
//!     wireguard_peer: None,
//!     grow_fs: None,
//!     templated_exec: Some(TemplatedExecSpec {
//!         template: TemplatedExecId::PgPromote,
//!         params: TemplatedExecParams::default(),
//!     }),
//!     expected_container_id: None,
//! };
//! let response = execute_container_action(&DockerCliActionExecutor, &request)?;
//! assert_eq!(response.action.as_str(), "templated_exec");
//! // success includes idempotent already-primary / not-in-recovery
//! println!("templated_exec success={}", response.success);
//! # Ok(())
//! # }
//! ```
//!
//! Point a Redis replica at a primary via allowlisted [`TemplatedExecId::RedisReplicaof`]
//! (default port `6379` when `primary_port` is `0`):
//!
//! ```no_run
//! use parton::{
//!     execute_container_action, ContainerActionKind, ContainerActionRequest,
//!     DockerCliActionExecutor, TemplatedExecId, TemplatedExecParams, TemplatedExecSpec,
//! };
//!
//! # fn main() -> anyhow::Result<()> {
//! let request = ContainerActionRequest {
//!     node_id: "node-1".to_string(),
//!     container_ref: "redis-replica-0".to_string(),
//!     action: ContainerActionKind::TemplatedExec,
//!     tail_lines: None,
//!     image_ref: None,
//!     env_vars: vec![],
//!     secret_env_vars: vec![],
//!     port_mappings: vec![],
//!     entrypoint: None,
//!     command: vec![],
//!     restart_policy: None,
//!     volume_mounts: vec![],
//!     resource_limits: None,
//!     health_check: None,
//!     labels: Default::default(),
//!     extra_hosts: vec![],
//!     network: None,
//!     diagnostic: None,
//!     wireguard_peer: None,
//!     grow_fs: None,
//!     templated_exec: Some(TemplatedExecSpec {
//!         template: TemplatedExecId::RedisReplicaof,
//!         params: TemplatedExecParams {
//!             primary_host: "10.0.0.5".into(),
//!             primary_port: 0,
//!             ..Default::default()
//!         },
//!     }),
//!     expected_container_id: None,
//! };
//! let response = execute_container_action(&DockerCliActionExecutor, &request)?;
//! assert!(response.success);
//! # Ok(())
//! # }
//! ```
//!
//! Promote a Redis replica to master via allowlisted [`TemplatedExecId::RedisReplicaofNoOne`]:
//!
//! ```no_run
//! use parton::{
//!     execute_container_action, ContainerActionKind, ContainerActionRequest,
//!     DockerCliActionExecutor, TemplatedExecId, TemplatedExecParams, TemplatedExecSpec,
//! };
//!
//! # fn main() -> anyhow::Result<()> {
//! let request = ContainerActionRequest {
//!     node_id: "node-1".to_string(),
//!     container_ref: "redis-replica-0".to_string(),
//!     action: ContainerActionKind::TemplatedExec,
//!     tail_lines: None,
//!     image_ref: None,
//!     env_vars: vec![],
//!     secret_env_vars: vec![],
//!     port_mappings: vec![],
//!     entrypoint: None,
//!     command: vec![],
//!     restart_policy: None,
//!     volume_mounts: vec![],
//!     resource_limits: None,
//!     health_check: None,
//!     labels: Default::default(),
//!     extra_hosts: vec![],
//!     network: None,
//!     diagnostic: None,
//!     wireguard_peer: None,
//!     grow_fs: None,
//!     templated_exec: Some(TemplatedExecSpec {
//!         template: TemplatedExecId::RedisReplicaofNoOne,
//!         params: TemplatedExecParams::default(),
//!     }),
//!     expected_container_id: None,
//! };
//! let response = execute_container_action(&DockerCliActionExecutor, &request)?;
//! assert!(response.success);
//! # Ok(())
//! # }
//! ```
//!
//! # Command queue client
//!
//! Claim one pending command from the control plane, run it locally, and post the result.
//!
//! Prerequisites: a reachable control-plane base URL (from [`derive_agent_api_base_url`]),
//! optional `x-parton-token` / SPIFFE auth, and Docker when the claimed kind needs it.
//!
//! 1. Derive the agent API base with [`derive_agent_api_base_url`].
//! 2. [`post_claim_action`] — `None` means the queue was empty this tick.
//! 3. [`execute_claimed_node_action`], then [`post_action_result`].
//!
//! Failures: HTTP / auth errors, lease expiry, and action execution errors (reported on
//! the result body when possible). Next: [Handoff directives](#handoff-directives).
//!
//! ```no_run
//! use parton::{
//!     derive_agent_api_base_url, execute_claimed_node_action, post_action_result,
//!     post_claim_action, DockerCliActionExecutor,
//! };
//! use std::sync::Arc;
//!
//! # async fn demo() -> anyhow::Result<()> {
//! let base = derive_agent_api_base_url("https://cp.example:3000");
//! let claimed = post_claim_action(&base, "node-1", None, Some("shared-token")).await?;
//! if let Some(body) = claimed {
//!     let report = execute_claimed_node_action(
//!         Arc::new(DockerCliActionExecutor),
//!         &body,
//!         "node-1",
//!     )
//!     .await?;
//!     post_action_result(&base, report, Some("shared-token")).await?;
//!     assert!(!body.command_id.is_empty());
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Handoff directives
//!
//! Apply signed re-enroll / revoke directives carried on a heartbeat response.
//!
//! Prerequisites: `PARTON_AUTHORITY_VERIFY_KEY` (and related agent data dir / env rewrite
//! paths) when verifying live handoffs. Local crypto smoke:
//! `cargo run -p parton --example identity_seal`.
//!
//! 1. Collect [`AgentDirective`] values from [`HeartbeatResponse`].
//! 2. Call [`apply_directives`].
//! 3. On re-enroll, stamp `next_applied_directive_token` on the next heartbeat; on revoke,
//!    exit when `revoke_exit` is true.
//!
//! Failures: [`DirectiveError`] for verify / apply problems. Next:
//! [Binary Runtime](#binary-runtime) (grace window after re-enroll).
//!
//! ```no_run
//! use parton::{apply_directives, AgentDirective};
//!
//! # fn demo(directives: Vec<AgentDirective>) -> anyhow::Result<()> {
//! let outcome = apply_directives(&directives)?;
//! println!(
//!     "revoke_exit={} token_pending={}",
//!     outcome.revoke_exit,
//!     outcome.next_applied_directive_token.is_some()
//! );
//! if directives.is_empty() {
//!     assert!(!outcome.revoke_exit);
//!     assert!(outcome.next_applied_directive_token.is_none());
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Binary Runtime
//!
//! Run one heartbeat loop iteration the same way the `parton` binary does: build a report,
//! POST it, apply directives, then claim/run queued actions (claim/result live in `main`).
//!
//! Prerequisites: `PARTON_NODE_ID` required; optional `PARTON_HEARTBEAT_URL`,
//! `PARTON_CELL_ID`, `PARTON_SHARED_TOKEN`, lease / grace env vars (see crate README).
//!
//! 1. Load [`agent_runtime::AgentRuntimeConfig`] from the environment.
//! 2. Call [`agent_runtime::run_heartbeat_step`] each tick.
//! 3. Branch on [`agent_runtime::HeartbeatStepOutcome`] (`Continue`, grace expiry, revoke).
//!
//! Failures: missing `PARTON_NODE_ID`, report build errors, and directive-apply errors.
//! Transport failures usually return `Continue` (or grace fallback). Next: operator
//! see repository `SECURITY.md` for vulnerability reporting.
//!
//! ```no_run
//! use parton::agent_runtime::{
//!     run_heartbeat_step, AgentRuntimeConfig, HeartbeatStepOutcome,
//! };
//!
//! # async fn demo() -> anyhow::Result<()> {
//! let mut config = AgentRuntimeConfig::from_env()?;
//! let mut pending_token = None;
//! let mut pending_fail = None;
//! let mut pending_grace = None;
//! let mut enrollment_acknowledged = false;
//! let outcome = run_heartbeat_step(
//!     &mut config,
//!     &mut pending_token,
//!     &mut pending_fail,
//!     &mut pending_grace,
//!     &mut enrollment_acknowledged,
//! )
//! .await?;
//! println!("heartbeat step: {outcome:?}");
//! assert!(matches!(
//!     outcome,
//!     HeartbeatStepOutcome::Continue
//!         | HeartbeatStepOutcome::ExitGraceExpired
//!         | HeartbeatStepOutcome::ExitRevoked
//! ));
//! # Ok(())
//! # }
//! ```
//!
//! # Security
//!
//! Deploy policy defaults to deny host networking/mounts and require digest-pinned
//! images; shared-token / SPIFFE presentation and optional cosign verify are
//! implemented. Vulnerability reporting: repository root `SECURITY.md`.

mod actions;
pub mod agent_metrics;
pub mod agent_runtime;
mod command_queue;
mod directive_apply;
mod directives_wire;
mod heartbeat;
mod host_info;
pub mod identity;
pub mod spiffe_client;
mod ssrf_guard;

pub use actions::{
    execute_container_action, validate_deploy_secret_env_entry, validate_deploy_secret_env_name,
    validate_deploy_secret_env_vars, write_deploy_secret_env_file, ContainerActionExecutor,
    ContainerActionKind, ContainerActionRequest, ContainerActionResponse, ContainerHealthCheck,
    DiagnosticMode, DiagnosticSpec, DockerCliActionExecutor, GrowFsSpec, ResourceLimits,
    SecretEnvVar, TemplatedExecId, TemplatedExecParams, TemplatedExecSpec, VolumeMount,
    WireguardPeerSpec,
};
pub use agent_runtime::{
    run_heartbeat_step, AgentRuntimeConfig, HeartbeatStepOutcome, PendingReenrollGrace,
};
pub use command_queue::{
    derive_agent_api_base_url, execute_claimed_node_action, post_action_result, post_claim_action,
    post_extend_action_lease, ClaimedNodeActionBody, ReportRequestBody,
};
pub use directive_apply::{
    agent_data_dir, apply_directives, DirectiveApplyOutcome, DirectiveError,
};
pub use directives_wire::{
    handoff_reenroll_directive_signature_message_v1, handoff_revoke_directive_signature_message_v1,
};
pub use heartbeat::{
    build_heartbeat_report, build_heartbeat_report_with_overrides,
    build_heartbeat_report_with_overrides_async, send_heartbeat, AgentDirective, ContainerHealth,
    ContainerState, ContainerStatus, ContainerStatusReport, ContainerStatusSummary,
    HeartbeatReportOverrides, HeartbeatResponse, HostCapabilities, NodeHeartbeatReport,
};
pub use host_info::{collect_host_info, collect_mounts, HostInfoJson, MountInfo};
pub use identity::{
    box_public_key_base64, box_public_key_from_base64, box_secret_key_from_identity_json,
    directive_sign, directive_signing_key_from_seed, directive_verify,
    directive_verifying_key_from_base64, generate_box_keypair, generate_directive_signing_key,
    identity_file_json_from_box_secret, random_directive_signing_pair_b64, seal_to_recipient,
    unseal_with_box_secret, IdentityError, PartonIdentityFileV1,
};
pub use spiffe_client::{apply_agent_auth_headers, maybe_jwt_svid, PartonAuthMode};
pub use ssrf_guard::{
    check_ip_allowed_for_agent_fetch, diagnostic_target_allowed_for_agent_probe,
    url_allowed_for_agent_fetch, SsrfError,
};
