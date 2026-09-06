//! Allowlisted in-container engine ops (`TemplatedExec`).
//!
//! Builds fixed `docker` argv vectors from [`TemplatedExecId`](crate::TemplatedExecId) and runs
//! them inside the target container. Promote paths treat not-in-recovery and already-master as
//! idempotent success. Redis coverage includes `REPLICAOF` follow, cluster meet / replicate /
//! slot assign / migrate, and slot-key `MIGRATE`. Postgres lab copy uses
//! [`TemplatedExecId::PgShardBulkCopy`] on `nucleus_rebalance_lab`; `ClickHouse` lab copy uses
//! [`TemplatedExecId::ChShardBulkCopy`] on `default.nucleus_rebalance_lab`. `MongoDB` replica-set
//! and sharded templates run `mongosh --eval` scripts. `ClickHouse` distributed / Keeper quorum
//! templates apply remote-server and quorum configuration inside the container.
//!
//! The control plane / orchestrator owns role swap and reconcile orchestration; deploy,
//! [`GrowFs`](crate::GrowFsSpec), and diagnostic action kinds live in sibling modules.
//!
//! # Examples
//!
//! Testing Postgres promote (`user` defaults to `nucleus` when empty):
//!
//! ```no_run
//! use parton::{TemplatedExecId, TemplatedExecParams, TemplatedExecSpec};
//!
//! let promote = TemplatedExecSpec {
//!     template: TemplatedExecId::PgPromote,
//!     params: TemplatedExecParams {
//!         user: "nucleus".into(),
//!         ..Default::default()
//!     },
//! };
//! let _ = promote;
//! ```
//!
//! Redis follow (default port `6379` when `primary_port` is `0`):
//!
//! ```no_run
//! use parton::{TemplatedExecId, TemplatedExecParams, TemplatedExecSpec};
//!
//! let follow = TemplatedExecSpec {
//!     template: TemplatedExecId::RedisReplicaof,
//!     params: TemplatedExecParams {
//!         primary_host: "10.0.0.5".into(),
//!         primary_port: 0,
//!         ..Default::default()
//!     },
//! };
//! let _ = follow;
//! ```
//!
//! `MongoDB` `rs.initiate` (replica-set name in `user`; default port `27017`):
//!
//! ```no_run
//! use parton::{TemplatedExecId, TemplatedExecParams, TemplatedExecSpec};
//!
//! let initiate = TemplatedExecSpec {
//!     template: TemplatedExecId::MongoRsInitiate,
//!     params: TemplatedExecParams {
//!         primary_host: "10.0.0.1".into(),
//!         primary_port: 27017,
//!         user: "rs-docs".into(),
//!         ..Default::default()
//!     },
//! };
//! let _ = initiate;
//! ```
//!
//! Cluster meet then assign an initial slot batch (the control plane / orchestrator owns ordering):
//!
//! ```no_run
//! use parton::{TemplatedExecId, TemplatedExecParams, TemplatedExecSpec};
//!
//! let meet = TemplatedExecSpec {
//!     template: TemplatedExecId::RedisClusterMeet,
//!     params: TemplatedExecParams {
//!         primary_host: "10.0.0.1".into(),
//!         primary_port: 6379,
//!         ..Default::default()
//!     },
//! };
//! let slots = TemplatedExecSpec {
//!     template: TemplatedExecId::RedisClusterSlotsAssign,
//!     params: TemplatedExecParams {
//!         slot_start: 8192,
//!         slot_end: 8255,
//!         ..Default::default()
//!     },
//! };
//! let _ = (meet, slots);
//! ```
//!
//! Testing Postgres shard bulk copy to a peer (rebalance Moving tick):
//!
//! ```no_run
//! use parton::{TemplatedExecId, TemplatedExecParams, TemplatedExecSpec};
//!
//! let copy = TemplatedExecSpec {
//!     template: TemplatedExecId::PgShardBulkCopy,
//!     params: TemplatedExecParams {
//!         primary_host: "10.0.0.2".into(),
//!         primary_port: 5432,
//!         user: "nucleus".into(),
//!         ..Default::default()
//!     },
//! };
//! let _ = copy;
//! ```
//!
//! Lab `ClickHouse` shard bulk copy to a peer (rebalance Moving tick; native port `9000`):
//!
//! ```no_run
//! use parton::{TemplatedExecId, TemplatedExecParams, TemplatedExecSpec};
//!
//! let copy = TemplatedExecSpec {
//!     template: TemplatedExecId::ChShardBulkCopy,
//!     params: TemplatedExecParams {
//!         primary_host: "10.0.0.2".into(),
//!         primary_port: 9000,
//!         ..Default::default()
//!     },
//! };
//! let _ = copy;
//! ```

mod clickhouse_bulk_copy;
mod clickhouse_rmt;
mod mongodb_rs;
mod mongodb_sharded;
mod postgres_bulk_copy;
mod postgres_standby;
mod redis_migrate_keys;
mod registry;
mod runner;

use super::types::{
    ContainerActionKind, ContainerActionRequest, ContainerActionResponse, TemplatedExecId,
    ValidatedTemplatedExecParams,
};
use clickhouse_bulk_copy::run_ch_shard_bulk_copy;
use clickhouse_rmt::clickhouse_templated_exec_argv;
use mongodb_rs::mongodb_templated_exec_argv;
use mongodb_sharded::mongodb_sharded_templated_exec_argv;
use postgres_bulk_copy::run_pg_shard_bulk_copy;
use postgres_standby::{run_standby_bootstrap, run_standby_follow};
use redis_migrate_keys::run_migrate_slot_keys;
use registry::{classify_promote_outcome, promote_exec_argv, redis_templated_exec_argv};
use runner::{DockerCliRunner, ProcessDockerCliRunner};

/// Execute templated exec with an injectable runner (unit tests).
pub(crate) fn run_templated_exec_with(
    request: &ContainerActionRequest,
    runner: &dyn DockerCliRunner,
) -> anyhow::Result<ContainerActionResponse> {
    let spec = request
        .templated_exec
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("templated_exec spec is required"))?;
    let container_ref = request.container_ref.trim();
    let params = spec.params.validate_for(spec.template)?;
    let template = spec.template;

    tracing::info!(
        target: "parton.templated_exec",
        container_ref = %container_ref,
        template = %template.as_str(),
        "templated_exec starting"
    );

    let (success, message, payload_extra) =
        dispatch_templated_exec(container_ref, template, &params, runner)?;

    if success {
        tracing::info!(
            target: "parton.templated_exec",
            container_ref = %container_ref,
            template = %template.as_str(),
            message,
            "templated_exec ok"
        );
    } else {
        tracing::warn!(
            target: "parton.templated_exec",
            container_ref = %container_ref,
            template = %template.as_str(),
            message,
            "templated_exec failed"
        );
    }

    Ok(ContainerActionResponse {
        action: ContainerActionKind::TemplatedExec,
        container_ref: request.container_ref.clone(),
        success,
        message: message.to_string(),
        payload: payload_extra,
    })
}

#[allow(clippy::too_many_lines)]
fn dispatch_templated_exec(
    container_ref: &str,
    template: TemplatedExecId,
    params: &ValidatedTemplatedExecParams,
    runner: &dyn DockerCliRunner,
) -> anyhow::Result<(bool, &'static str, serde_json::Value)> {
    Ok(match template {
        TemplatedExecId::PgPromote
        | TemplatedExecId::RedisReplicaofNoOne
        | TemplatedExecId::ChPromote => {
            let argv = promote_exec_argv(container_ref, template, params.user.as_str());
            let output = runner.run(&argv)?;
            let (success, message) =
                classify_promote_outcome(template, output.status_success, &output.combined());
            (
                success,
                message,
                serde_json::json!({
                    "template": template.as_str(),
                    "status_success": output.status_success,
                }),
            )
        }
        TemplatedExecId::MongoRsInitiate
        | TemplatedExecId::MongoRsAdd
        | TemplatedExecId::MongoRsStepDown => {
            let argv = mongodb_templated_exec_argv(container_ref, template, params);
            let output = runner.run(&argv)?;
            let (success, message) =
                classify_promote_outcome(template, output.status_success, &output.combined());
            (
                success,
                message,
                serde_json::json!({
                    "template": template.as_str(),
                    "status_success": output.status_success,
                }),
            )
        }
        TemplatedExecId::MongoConfigRsInitiate
        | TemplatedExecId::MongoConfigRsAdd
        | TemplatedExecId::MongoShardsvrEnable
        | TemplatedExecId::MongoAddShard
        | TemplatedExecId::MongoMoveChunk => {
            let argv = mongodb_sharded_templated_exec_argv(container_ref, template, params);
            let output = runner.run(&argv)?;
            let (success, message) =
                classify_promote_outcome(template, output.status_success, &output.combined());
            (
                success,
                message,
                serde_json::json!({
                    "template": template.as_str(),
                    "status_success": output.status_success,
                }),
            )
        }
        TemplatedExecId::ChRemoteServersApply => {
            let (success, message, output) =
                clickhouse_rmt::run_ch_remote_servers_apply(container_ref, params, runner)?;
            (
                success,
                message,
                serde_json::json!({
                    "template": template.as_str(),
                    "status_success": output.status_success,
                }),
            )
        }
        TemplatedExecId::ChDistributedEnsure => {
            let (success, message, output) =
                clickhouse_rmt::run_ch_distributed_ensure(container_ref, params, runner)?;
            (
                success,
                message,
                serde_json::json!({
                    "template": template.as_str(),
                    "status_success": output.status_success,
                }),
            )
        }
        TemplatedExecId::ChRmtBootstrap
        | TemplatedExecId::ChRmtFollow
        | TemplatedExecId::ChKeeperQuorumApply => {
            let argv = clickhouse_templated_exec_argv(container_ref, template, params);
            let output = runner.run(&argv)?;
            let (success, message) =
                classify_promote_outcome(template, output.status_success, &output.combined());
            (
                success,
                message,
                serde_json::json!({
                    "template": template.as_str(),
                    "status_success": output.status_success,
                }),
            )
        }
        TemplatedExecId::RedisReplicaof
        | TemplatedExecId::RedisClusterMeet
        | TemplatedExecId::RedisClusterReplicate
        | TemplatedExecId::RedisClusterSlotsAssign
        | TemplatedExecId::RedisClusterMigrate
        | TemplatedExecId::RedisClusterSetslotImporting
        | TemplatedExecId::RedisClusterSetslotMigrating => {
            let argv = redis_templated_exec_argv(container_ref, template, params);
            let output = runner.run(&argv)?;
            let (success, message) =
                classify_promote_outcome(template, output.status_success, &output.combined());
            (
                success,
                message,
                serde_json::json!({
                    "template": template.as_str(),
                    "status_success": output.status_success,
                }),
            )
        }
        TemplatedExecId::RedisClusterMyId => {
            let argv = redis_templated_exec_argv(container_ref, template, params);
            let output = runner.run(&argv)?;
            let (success, message) =
                classify_promote_outcome(template, output.status_success, &output.combined());
            let node_id = output.stdout.trim();
            (
                success,
                message,
                serde_json::json!({
                    "template": template.as_str(),
                    "status_success": output.status_success,
                    "cluster_node_id": node_id,
                }),
            )
        }
        TemplatedExecId::RedisClusterMigrateSlotKeys => {
            let (success, message, output) = run_migrate_slot_keys(container_ref, params, runner)?;
            (
                success,
                message,
                serde_json::json!({
                    "template": template.as_str(),
                    "status_success": output.status_success,
                }),
            )
        }
        TemplatedExecId::PgStandbyBootstrap => {
            let (success, message, output) = run_standby_bootstrap(container_ref, params, runner)?;
            (
                success,
                message,
                serde_json::json!({
                    "template": template.as_str(),
                    "status_success": output.status_success,
                }),
            )
        }
        TemplatedExecId::PgStandbyFollow => {
            let (success, message, output) = run_standby_follow(container_ref, params, runner)?;
            (
                success,
                message,
                serde_json::json!({
                    "template": template.as_str(),
                    "status_success": output.status_success,
                }),
            )
        }
        TemplatedExecId::PgShardBulkCopy => {
            let (success, message, output) = run_pg_shard_bulk_copy(container_ref, params, runner)?;
            (
                success,
                message,
                serde_json::json!({
                    "template": template.as_str(),
                    "status_success": output.status_success,
                }),
            )
        }
        TemplatedExecId::ChShardBulkCopy => {
            let (success, message, output) = run_ch_shard_bulk_copy(container_ref, params, runner)?;
            (
                success,
                message,
                serde_json::json!({
                    "template": template.as_str(),
                    "status_success": output.status_success,
                }),
            )
        }
    })
}

/// Execute [`ContainerActionKind::TemplatedExec`].
pub(super) fn run_templated_exec(
    request: &ContainerActionRequest,
) -> anyhow::Result<ContainerActionResponse> {
    run_templated_exec_with(request, &ProcessDockerCliRunner)
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
