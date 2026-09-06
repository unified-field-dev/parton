//! Fixed argv builders and outcome classifiers for [`super::TemplatedExecId`].

use super::super::types::{TemplatedExecId, ValidatedTemplatedExecParams};

/// Testing Postgres image used for one-shot `pg_basebackup` / `pg_rewind` helpers.
pub(crate) const PG_HELPER_IMAGE: &str = "docker.io/library/postgres:16";

/// PGDATA path inside the official Postgres image / volume mount.
pub(crate) const PGDATA: &str = "/var/lib/postgresql/data";

/// Build `docker …` argv segments (without the `docker` binary) for single-step templates.
///
/// `user` is the validated lab DB role for [`TemplatedExecId::PgPromote`] (ignored otherwise).
/// Templates that need validated host/port/node/slots use [`redis_templated_exec_argv`].
#[must_use]
pub(crate) fn promote_exec_argv(
    container_ref: &str,
    id: TemplatedExecId,
    user: &str,
) -> Vec<String> {
    match id {
        TemplatedExecId::PgPromote => vec![
            "exec".into(),
            container_ref.to_string(),
            "psql".into(),
            "-U".into(),
            user.to_string(),
            "-v".into(),
            "ON_ERROR_STOP=1".into(),
            "-c".into(),
            "SELECT pg_promote();".into(),
        ],
        TemplatedExecId::RedisReplicaofNoOne => vec![
            "exec".into(),
            container_ref.to_string(),
            "redis-cli".into(),
            "REPLICAOF".into(),
            "NO".into(),
            "ONE".into(),
        ],
        TemplatedExecId::ChPromote => vec![
            "exec".into(),
            container_ref.to_string(),
            "clickhouse-client".into(),
            "-q".into(),
            "SELECT 1".into(),
        ],
        TemplatedExecId::PgStandbyBootstrap
        | TemplatedExecId::PgStandbyFollow
        | TemplatedExecId::RedisReplicaof
        | TemplatedExecId::RedisClusterMeet
        | TemplatedExecId::RedisClusterReplicate
        | TemplatedExecId::RedisClusterSlotsAssign
        | TemplatedExecId::RedisClusterMigrate
        | TemplatedExecId::RedisClusterMyId
        | TemplatedExecId::RedisClusterSetslotImporting
        | TemplatedExecId::RedisClusterSetslotMigrating
        | TemplatedExecId::RedisClusterMigrateSlotKeys
        | TemplatedExecId::PgShardBulkCopy
        | TemplatedExecId::ChRmtBootstrap
        | TemplatedExecId::ChRmtFollow
        | TemplatedExecId::ChRemoteServersApply
        | TemplatedExecId::ChKeeperQuorumApply
        | TemplatedExecId::ChDistributedEnsure
        | TemplatedExecId::ChShardBulkCopy
        | TemplatedExecId::MongoRsInitiate
        | TemplatedExecId::MongoRsAdd
        | TemplatedExecId::MongoRsStepDown
        | TemplatedExecId::MongoConfigRsInitiate
        | TemplatedExecId::MongoConfigRsAdd
        | TemplatedExecId::MongoShardsvrEnable
        | TemplatedExecId::MongoAddShard
        | TemplatedExecId::MongoMoveChunk => Vec::new(),
    }
}

/// Build argv for Redis follow / CLUSTER templates (discrete tokens only).
#[must_use]
pub(crate) fn redis_templated_exec_argv(
    container_ref: &str,
    id: TemplatedExecId,
    params: &ValidatedTemplatedExecParams,
) -> Vec<String> {
    let mut argv = vec!["exec".into(), container_ref.to_string(), "redis-cli".into()];
    match id {
        TemplatedExecId::RedisReplicaof => {
            argv.push("REPLICAOF".into());
            argv.push(params.primary_host.clone());
            argv.push(params.primary_port.to_string());
        }
        TemplatedExecId::RedisClusterMeet => {
            argv.push("CLUSTER".into());
            argv.push("MEET".into());
            argv.push(params.primary_host.clone());
            argv.push(params.primary_port.to_string());
        }
        TemplatedExecId::RedisClusterReplicate => {
            argv.push("CLUSTER".into());
            argv.push("REPLICATE".into());
            argv.push(params.cluster_node_id.clone());
        }
        TemplatedExecId::RedisClusterSlotsAssign => {
            argv.push("CLUSTER".into());
            argv.push("ADDSLOTS".into());
            for slot in params.slot_start..=params.slot_end {
                argv.push(slot.to_string());
            }
        }
        TemplatedExecId::RedisClusterMigrate => {
            // Single-slot ownership handoff per call when start==end; batch SETSLOT NODE.
            argv.push("CLUSTER".into());
            argv.push("SETSLOT".into());
            argv.push(params.slot_start.to_string());
            argv.push("NODE".into());
            argv.push(params.cluster_node_id.clone());
        }
        TemplatedExecId::RedisClusterMyId => {
            argv.push("CLUSTER".into());
            argv.push("MYID".into());
        }
        TemplatedExecId::RedisClusterSetslotImporting => {
            argv.push("CLUSTER".into());
            argv.push("SETSLOT".into());
            argv.push(params.slot_start.to_string());
            argv.push("IMPORTING".into());
            argv.push(params.cluster_node_id.clone());
        }
        TemplatedExecId::RedisClusterSetslotMigrating => {
            argv.push("CLUSTER".into());
            argv.push("SETSLOT".into());
            argv.push(params.slot_start.to_string());
            argv.push("MIGRATING".into());
            argv.push(params.cluster_node_id.clone());
        }
        _ => {}
    }
    argv
}

pub(crate) fn classify_promote_outcome(
    id: TemplatedExecId,
    status_success: bool,
    combined: &str,
) -> (bool, &'static str) {
    let lower = combined.to_ascii_lowercase();
    if status_success {
        return (true, promote_success_message(id));
    }
    classify_promote_failure(id, &lower)
}

fn promote_success_message(id: TemplatedExecId) -> &'static str {
    match id {
        TemplatedExecId::PgPromote => "pg_promote ok",
        TemplatedExecId::RedisReplicaofNoOne => "replicaof no one ok",
        TemplatedExecId::RedisReplicaof => "replicaof ok",
        TemplatedExecId::RedisClusterMeet => "redis_cluster_meet ok",
        TemplatedExecId::RedisClusterReplicate => "redis_cluster_replicate ok",
        TemplatedExecId::RedisClusterSlotsAssign => "redis_cluster_slots_assign ok",
        TemplatedExecId::RedisClusterMigrate => "redis_cluster_migrate ok",
        TemplatedExecId::RedisClusterMyId => "redis_cluster_myid ok",
        TemplatedExecId::RedisClusterSetslotImporting => "redis_cluster_setslot_importing ok",
        TemplatedExecId::RedisClusterSetslotMigrating => "redis_cluster_setslot_migrating ok",
        TemplatedExecId::RedisClusterMigrateSlotKeys => "redis_cluster_migrate_slot_keys ok",
        TemplatedExecId::PgStandbyBootstrap => "pg_standby_bootstrap ok",
        TemplatedExecId::PgStandbyFollow => "pg_standby_follow ok",
        TemplatedExecId::PgShardBulkCopy => "pg_shard_bulk_copy ok",
        TemplatedExecId::ChRmtBootstrap => "ch_rmt_bootstrap ok",
        TemplatedExecId::ChRmtFollow => "ch_rmt_follow ok",
        TemplatedExecId::ChPromote => "ch_promote ok",
        TemplatedExecId::ChRemoteServersApply => "ch_remote_servers_apply ok",
        TemplatedExecId::ChKeeperQuorumApply => "ch_keeper_quorum_apply ok",
        TemplatedExecId::ChDistributedEnsure => "ch_distributed_ensure ok",
        TemplatedExecId::ChShardBulkCopy => "ch_shard_bulk_copy ok",
        TemplatedExecId::MongoRsInitiate => "mongo_rs_initiate ok",
        TemplatedExecId::MongoRsAdd => "mongo_rs_add ok",
        TemplatedExecId::MongoRsStepDown => "mongo_rs_step_down ok",
        TemplatedExecId::MongoConfigRsInitiate => "mongo_config_rs_initiate ok",
        TemplatedExecId::MongoConfigRsAdd => "mongo_config_rs_add ok",
        TemplatedExecId::MongoShardsvrEnable => "mongo_shardsvr_enable ok",
        TemplatedExecId::MongoAddShard => "mongo_add_shard ok",
        TemplatedExecId::MongoMoveChunk => "mongo_move_chunk ok",
    }
}

fn classify_promote_failure(id: TemplatedExecId, lower: &str) -> (bool, &'static str) {
    match id {
        TemplatedExecId::PgPromote if postgres_idempotent_ok(lower) => {
            (true, "pg_promote already_primary")
        }
        TemplatedExecId::RedisReplicaofNoOne if redis_idempotent_ok(lower) => {
            (true, "replicaof already_master")
        }
        TemplatedExecId::RedisReplicaof if redis_replicaof_idempotent_ok(lower) => {
            (true, "replicaof already_following")
        }
        TemplatedExecId::MongoRsInitiate | TemplatedExecId::MongoConfigRsInitiate
            if mongo_rs_idempotent_ok(lower) =>
        {
            (
                true,
                if matches!(id, TemplatedExecId::MongoConfigRsInitiate) {
                    "mongo_config_rs_initiate already"
                } else {
                    "mongo_rs_initiate already"
                },
            )
        }
        TemplatedExecId::MongoRsAdd | TemplatedExecId::MongoConfigRsAdd
            if mongo_rs_add_idempotent_ok(lower) =>
        {
            (
                true,
                if matches!(id, TemplatedExecId::MongoConfigRsAdd) {
                    "mongo_config_rs_add already_member"
                } else {
                    "mongo_rs_add already_member"
                },
            )
        }
        TemplatedExecId::MongoRsStepDown if mongo_rs_step_down_idempotent_ok(lower) => {
            (true, "mongo_rs_step_down already")
        }
        TemplatedExecId::MongoAddShard if mongo_add_shard_idempotent_ok(lower) => {
            (true, "mongo_add_shard already")
        }
        TemplatedExecId::MongoMoveChunk if mongo_move_chunk_idempotent_ok(lower) => {
            (true, "mongo_move_chunk already")
        }
        TemplatedExecId::PgPromote => (false, "pg_promote failed"),
        TemplatedExecId::RedisReplicaofNoOne | TemplatedExecId::RedisReplicaof => {
            (false, "replicaof failed")
        }
        TemplatedExecId::RedisClusterMeet => (false, "redis_cluster_meet failed"),
        TemplatedExecId::RedisClusterReplicate => (false, "redis_cluster_replicate failed"),
        TemplatedExecId::RedisClusterSlotsAssign => (false, "redis_cluster_slots_assign failed"),
        TemplatedExecId::RedisClusterMigrate => (false, "redis_cluster_migrate failed"),
        TemplatedExecId::RedisClusterMyId => (false, "redis_cluster_myid failed"),
        TemplatedExecId::RedisClusterSetslotImporting => {
            (false, "redis_cluster_setslot_importing failed")
        }
        TemplatedExecId::RedisClusterSetslotMigrating => {
            (false, "redis_cluster_setslot_migrating failed")
        }
        TemplatedExecId::RedisClusterMigrateSlotKeys => {
            (false, "redis_cluster_migrate_slot_keys failed")
        }
        TemplatedExecId::PgStandbyBootstrap => (false, "pg_standby_bootstrap failed"),
        TemplatedExecId::PgStandbyFollow => (false, "pg_standby_follow failed"),
        TemplatedExecId::PgShardBulkCopy => (false, "pg_shard_bulk_copy failed"),
        TemplatedExecId::ChRmtBootstrap => (false, "ch_rmt_bootstrap failed"),
        TemplatedExecId::ChRmtFollow => (false, "ch_rmt_follow failed"),
        TemplatedExecId::ChPromote => (false, "ch_promote failed"),
        TemplatedExecId::ChRemoteServersApply => (false, "ch_remote_servers_apply failed"),
        TemplatedExecId::ChKeeperQuorumApply => (false, "ch_keeper_quorum_apply failed"),
        TemplatedExecId::ChDistributedEnsure => (false, "ch_distributed_ensure failed"),
        TemplatedExecId::ChShardBulkCopy => (false, "ch_shard_bulk_copy failed"),
        TemplatedExecId::MongoRsInitiate => (false, "mongo_rs_initiate failed"),
        TemplatedExecId::MongoRsAdd => (false, "mongo_rs_add failed"),
        TemplatedExecId::MongoRsStepDown => (false, "mongo_rs_step_down failed"),
        TemplatedExecId::MongoConfigRsInitiate => (false, "mongo_config_rs_initiate failed"),
        TemplatedExecId::MongoConfigRsAdd => (false, "mongo_config_rs_add failed"),
        TemplatedExecId::MongoShardsvrEnable => (false, "mongo_shardsvr_enable failed"),
        TemplatedExecId::MongoAddShard => (false, "mongo_add_shard failed"),
        TemplatedExecId::MongoMoveChunk => (false, "mongo_move_chunk failed"),
    }
}

fn mongo_add_shard_idempotent_ok(lower: &str) -> bool {
    lower.contains("already exists")
        || lower.contains("host already used")
        || lower.contains("is already a member")
}

fn mongo_move_chunk_idempotent_ok(lower: &str) -> bool {
    lower.contains("that chunk is already on shard")
        || lower.contains("chunk with the given bounds")
}

fn postgres_idempotent_ok(lower: &str) -> bool {
    lower.contains("not in recovery")
        || lower.contains("is not in recovery")
        || (lower.contains("pg_promote") && lower.contains("false"))
}

fn redis_idempotent_ok(lower: &str) -> bool {
    lower.contains("ok")
        || lower.is_empty()
        || lower.contains("already")
        || lower.contains("not a replica")
        || lower.contains("master")
}

fn redis_replicaof_idempotent_ok(lower: &str) -> bool {
    lower.contains("ok") || lower.is_empty() || lower.contains("already")
}

fn mongo_rs_idempotent_ok(lower: &str) -> bool {
    lower.contains("already initialized")
        || lower.contains("already initiated")
        || lower.contains("ismaster")
        || lower.contains("setname")
}

fn mongo_rs_add_idempotent_ok(lower: &str) -> bool {
    lower.contains("already a member") || lower.contains("found two member")
}

fn mongo_rs_step_down_idempotent_ok(lower: &str) -> bool {
    lower.contains("not currently a primary") || lower.contains("not primary")
}

/// `docker stop <container>`.
#[must_use]
pub(crate) fn docker_stop_argv(container_ref: &str) -> Vec<String> {
    vec!["stop".into(), container_ref.to_string()]
}

/// `docker start <container>`.
#[must_use]
pub(crate) fn docker_start_argv(container_ref: &str) -> Vec<String> {
    vec!["start".into(), container_ref.to_string()]
}

/// Clear PGDATA via one-shot helper (`find -mindepth 1 -delete`).
#[must_use]
pub(crate) fn clear_pgdata_argv(container_ref: &str) -> Vec<String> {
    vec![
        "run".into(),
        "--rm".into(),
        "--volumes-from".into(),
        container_ref.to_string(),
        PG_HELPER_IMAGE.into(),
        "find".into(),
        PGDATA.into(),
        "-mindepth".into(),
        "1".into(),
        "-delete".into(),
    ]
}

/// `pg_basebackup -R -X stream` into PGDATA using `--volumes-from`.
///
/// Uses the helper's own bridge network (plus `host.docker.internal`) rather than
/// `--network=container:<standby>`. Bootstrap stops the standby before basebackup,
/// and Docker rejects joining a non-running container's network namespace.
#[must_use]
pub(crate) fn pg_basebackup_argv(
    container_ref: &str,
    params: &ValidatedTemplatedExecParams,
) -> Vec<String> {
    vec![
        "run".into(),
        "--rm".into(),
        "--volumes-from".into(),
        container_ref.to_string(),
        "--add-host".into(),
        "host.docker.internal:host-gateway".into(),
        PG_HELPER_IMAGE.into(),
        "pg_basebackup".into(),
        "-h".into(),
        params.primary_host.clone(),
        "-p".into(),
        params.primary_port.to_string(),
        "-U".into(),
        params.user.clone(),
        "-D".into(),
        PGDATA.into(),
        "-R".into(),
        "-X".into(),
        "stream".into(),
        "--no-password".into(),
    ]
}

/// `pg_rewind` against the new primary (may fail; caller falls back to wipe+basebackup).
///
/// Same network choice as [`pg_basebackup_argv`] — standby is stopped during follow.
#[must_use]
pub(crate) fn pg_rewind_argv(
    container_ref: &str,
    params: &ValidatedTemplatedExecParams,
) -> Vec<String> {
    let source = format!(
        "host={} port={} user={}",
        params.primary_host, params.primary_port, params.user
    );
    vec![
        "run".into(),
        "--rm".into(),
        "--volumes-from".into(),
        container_ref.to_string(),
        "--add-host".into(),
        "host.docker.internal:host-gateway".into(),
        PG_HELPER_IMAGE.into(),
        "pg_rewind".into(),
        format!("--target-pgdata={PGDATA}"),
        format!("--source-server={source}"),
        "--no-password".into(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn promote_argv_fixed() {
        let pg = promote_exec_argv("c1", TemplatedExecId::PgPromote, "nucleus");
        assert_eq!(pg[0], "exec");
        assert!(pg.iter().any(|a| a == "SELECT pg_promote();"));
        assert_eq!(
            pg.iter()
                .position(|a| a == "-U")
                .and_then(|i| pg.get(i + 1)),
            Some(&"nucleus".to_string())
        );
        let redis = promote_exec_argv("c2", TemplatedExecId::RedisReplicaofNoOne, "");
        assert_eq!(&redis[2..], ["redis-cli", "REPLICAOF", "NO", "ONE"]);
        let ch = promote_exec_argv("c3", TemplatedExecId::ChPromote, "");
        assert_eq!(&ch[2..], ["clickhouse-client", "-q", "SELECT 1"]);
    }

    #[test]
    fn promote_argv_pg_uses_custom_user() {
        let pg = promote_exec_argv("c1", TemplatedExecId::PgPromote, "postgres");
        assert_eq!(
            pg.iter()
                .position(|a| a == "-U")
                .and_then(|i| pg.get(i + 1)),
            Some(&"postgres".to_string())
        );
    }

    #[test]
    fn promote_argv_redis_replicaof_splices_host_port() {
        let p = ValidatedTemplatedExecParams {
            primary_host: "10.0.0.5".into(),
            primary_port: 6379,
            user: String::new(),
            cluster_node_id: String::new(),
            slot_start: 0,
            slot_end: 0,
            topology_peers: String::new(),
        };
        let args = redis_templated_exec_argv("redis-1", TemplatedExecId::RedisReplicaof, &p);
        assert_eq!(&args[2..], ["redis-cli", "REPLICAOF", "10.0.0.5", "6379"]);
        assert!(!args.iter().any(|a| a.contains(';')));
    }

    #[test]
    fn redis_cluster_meet_argv_splices_peer() {
        let p = ValidatedTemplatedExecParams {
            primary_host: "10.0.0.6".into(),
            primary_port: 6379,
            user: String::new(),
            cluster_node_id: String::new(),
            slot_start: 0,
            slot_end: 0,
            topology_peers: String::new(),
        };
        let args = redis_templated_exec_argv("redis-1", TemplatedExecId::RedisClusterMeet, &p);
        assert_eq!(
            &args[2..],
            ["redis-cli", "CLUSTER", "MEET", "10.0.0.6", "6379"]
        );
    }

    #[test]
    fn redis_cluster_slots_assign_discrete_slots() {
        let p = ValidatedTemplatedExecParams {
            primary_host: String::new(),
            primary_port: 6379,
            user: String::new(),
            cluster_node_id: String::new(),
            slot_start: 10,
            slot_end: 12,
            topology_peers: String::new(),
        };
        let args =
            redis_templated_exec_argv("redis-1", TemplatedExecId::RedisClusterSlotsAssign, &p);
        assert_eq!(
            &args[2..],
            ["redis-cli", "CLUSTER", "ADDSLOTS", "10", "11", "12"]
        );
    }

    #[test]
    fn redis_cluster_migrate_argv_splices_slot_and_node() {
        let p = ValidatedTemplatedExecParams {
            primary_host: String::new(),
            primary_port: 6379,
            user: String::new(),
            cluster_node_id: "d".repeat(40),
            slot_start: 7,
            slot_end: 7,
            topology_peers: String::new(),
        };
        let args = redis_templated_exec_argv("redis-1", TemplatedExecId::RedisClusterMigrate, &p);
        assert_eq!(
            &args[2..],
            [
                "redis-cli",
                "CLUSTER",
                "SETSLOT",
                "7",
                "NODE",
                p.cluster_node_id.as_str()
            ]
        );
    }

    #[test]
    fn redis_cluster_myid_argv() {
        let p = ValidatedTemplatedExecParams {
            primary_host: String::new(),
            primary_port: 6379,
            user: String::new(),
            cluster_node_id: String::new(),
            slot_start: 0,
            slot_end: 0,
            topology_peers: String::new(),
        };
        let args = redis_templated_exec_argv("redis-1", TemplatedExecId::RedisClusterMyId, &p);
        assert_eq!(&args[2..], ["redis-cli", "CLUSTER", "MYID"]);
    }

    #[test]
    fn redis_cluster_setslot_importing_argv() {
        let p = ValidatedTemplatedExecParams {
            primary_host: String::new(),
            primary_port: 6379,
            user: String::new(),
            cluster_node_id: "e".repeat(40),
            slot_start: 9,
            slot_end: 9,
            topology_peers: String::new(),
        };
        let args =
            redis_templated_exec_argv("redis-1", TemplatedExecId::RedisClusterSetslotImporting, &p);
        assert_eq!(
            &args[2..],
            [
                "redis-cli",
                "CLUSTER",
                "SETSLOT",
                "9",
                "IMPORTING",
                p.cluster_node_id.as_str()
            ]
        );
    }

    #[test]
    fn basebackup_argv_splices_params_as_discrete_args() {
        let p = ValidatedTemplatedExecParams {
            primary_host: "10.0.0.5".into(),
            primary_port: 5432,
            user: "nucleus".into(),
            cluster_node_id: String::new(),
            slot_start: 0,
            slot_end: 0,
            topology_peers: String::new(),
        };
        let args = pg_basebackup_argv("pg-1", &p);
        assert!(args.iter().any(|a| a == "pg_basebackup"));
        assert!(args.windows(2).any(|w| w == ["-h", "10.0.0.5"]));
        assert!(args
            .windows(2)
            .any(|w| w == ["--add-host", "host.docker.internal:host-gateway"]));
        assert!(!args.iter().any(|a| a.starts_with("--network=container:")));
        assert!(!args.iter().any(|a| a.contains(';')));
    }
}
