//! Typed request/response contracts for container / host actions.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// The supported container lifecycle and inspection operations.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ContainerActionKind {
    /// `docker start <container_ref>`.
    Start,
    /// `docker stop <container_ref>`.
    Stop,
    /// `docker restart <container_ref>`.
    Restart,
    /// `docker logs --tail <n> <container_ref>`.
    Logs,
    /// `docker inspect <container_ref>`.
    Inspect,
    /// `docker run -d …` to create a detached container.
    Deploy,
    /// Idempotent `docker network inspect || docker network create` using `container_ref` as the network name.
    EnsureNetwork,
    /// Native host hardware probe executed by the Parton agent process.
    ProbeHost,
    /// Network reachability from the agent host (TCP connect / sampled latency). Use [`ContainerActionRequest::diagnostic`].
    Diagnostic,
    /// Apply a Wireguard peer stanza on the host agent via `wg set` (see [`WireguardPeerSpec`]).
    WireguardPeer,
    /// Ensure a Docker image exists locally: `docker image inspect` then `docker pull` on miss.
    ///
    /// Requires non-empty [`ContainerActionRequest::image_ref`] (stable `container_ref` may be a log label only).
    EnsureDockerImage,
    /// Grow the filesystem on a host mount after cloud block-volume expand.
    ///
    /// Requires [`ContainerActionRequest::grow_fs`]. Host-native (not Docker); shares the
    /// deploy capability gate on Pion.
    GrowFs,
    /// Allowlisted in-container engine op (`pg_promote`, standby bootstrap/follow, …).
    ///
    /// Requires [`ContainerActionRequest::templated_exec`]. Fixed argv templates only
    /// (no free-text shell). Shares the deploy capability gate on Pion.
    TemplatedExec,
}

/// Mode for [`ContainerActionKind::Diagnostic`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticMode {
    /// Single TCP connect reachability probe.
    TcpProbe,
    /// Repeated TCP connect timing (`samples` connects, default 5).
    Latency {
        /// Number of TCP connect samples to take (clamped to 1..=32 at execution).
        samples: u8,
    },
}

/// Target for a diagnostic action (interpreted on the agent).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiagnosticSpec {
    /// Target host name or IP to probe from the agent.
    pub target_host: String,
    /// Target TCP port.
    pub port: u16,
    /// Probe mode (single connect or repeated latency sampling).
    pub mode: DiagnosticMode,
}

/// Spec for [`ContainerActionKind::GrowFs`] — grow the filesystem under `mount_path`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GrowFsSpec {
    /// Absolute host mount path (e.g. `/var/lib/registry`). Must not contain `..`.
    pub mount_path: String,
}

/// Compile-time catalog of in-container engine operations (no free-text shell).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[must_use]
pub enum TemplatedExecId {
    /// `pg_basebackup -R -X stream` into PGDATA, then start the container.
    PgStandbyBootstrap,
    /// Stop → rewind or resync → start as standby of a new primary.
    PgStandbyFollow,
    /// `SELECT pg_promote();` via `psql` (former `EnginePromote` / Postgres).
    ///
    /// Lab DB `user` defaults to `nucleus` when empty (matches lab `POSTGRES_USER`).
    PgPromote,
    /// `REPLICAOF NO ONE` via `redis-cli` (former `EnginePromote` / Redis).
    RedisReplicaofNoOne,
    /// `REPLICAOF <host> <port>` via `redis-cli` (classic replica follow).
    RedisReplicaof,
    /// `CLUSTER MEET <host> <port>` via `redis-cli`.
    RedisClusterMeet,
    /// `CLUSTER REPLICATE <node-id>` via `redis-cli`.
    RedisClusterReplicate,
    /// `CLUSTER ADDSLOTS` for a bounded slot range via `redis-cli`.
    RedisClusterSlotsAssign,
    /// `CLUSTER SETSLOT <slot> NODE <node-id>` (ownership handoff; one slot per call).
    RedisClusterMigrate,
    /// `CLUSTER MYID` — capture node id in response payload (`cluster_node_id` field).
    RedisClusterMyId,
    /// `CLUSTER SETSLOT <slot> IMPORTING <node-id>` on the destination (one slot).
    RedisClusterSetslotImporting,
    /// `CLUSTER SETSLOT <slot> MIGRATING <node-id>` on the source (one slot).
    RedisClusterSetslotMigrating,
    /// `CLUSTER GETKEYSINSLOT` then `MIGRATE` keys to peer (one slot; peer host/port required).
    RedisClusterMigrateSlotKeys,
    /// Lab shard bulk copy: dump fixed table `nucleus_rebalance_lab` on source → apply on dest peer.
    ///
    /// Requires peer `primary_host` / `primary_port` (destination) and lab DB `user` (default `nucleus`).
    PgShardBulkCopy,
    /// `ClickHouse` RMT replica readiness / join check (`clickhouse-client` SELECT 1).
    ///
    /// Requires Keeper/peer `primary_host` / `primary_port` (lab default port `9181`).
    ChRmtBootstrap,
    /// `ClickHouse` demoted-follow / rejoin heal (`clickhouse-client` SELECT 1).
    ///
    /// Requires new primary `primary_host` / `primary_port` (lab default port `8123`).
    ChRmtFollow,
    /// `ClickHouse` promote readiness (`clickhouse-client` SELECT 1; the control plane / orchestrator owns role swap).
    ChPromote,
    /// Apply `remote_servers` topology (lab: `SYSTEM RELOAD CONFIG` after validated peers).
    ///
    /// Requires non-empty `topology_peers` (`shard@host:port` comma-separated) and cluster name in `user`.
    ChRemoteServersApply,
    /// Apply Keeper quorum peer list (lab: readiness `SELECT 1` with validated peers).
    ///
    /// Requires non-empty `topology_peers` (`host:port` comma-separated).
    ChKeeperQuorumApply,
    /// Lab Distributed table ensure (`CREATE TABLE IF NOT EXISTS … ENGINE = Distributed`).
    ///
    /// Requires cluster name in `user` (lab charset).
    ChDistributedEnsure,
    /// Lab shard bulk copy: ensure fixed `MergeTree` `default.nucleus_rebalance_lab` on dest
    /// peer, then `INSERT INTO FUNCTION remote(…) SELECT *` from the source container.
    ///
    /// Requires peer `primary_host` / `primary_port` (destination native protocol; default `9000`).
    /// Lab no-auth (default user). Multi-step; fail-closed.
    ChShardBulkCopy,
    /// `MongoDB` `rs.initiate` via `mongosh --eval` (lab no-auth).
    ///
    /// Requires this member's advertise `primary_host` / `primary_port` (default `27017`).
    /// `user` carries the replica-set name (default `rs0` when empty; same charset as PG user).
    MongoRsInitiate,
    /// `MongoDB` `rs.add("host:port")` via `mongosh --eval` (run on primary).
    ///
    /// Requires peer `primary_host` / `primary_port` (default `27017`).
    MongoRsAdd,
    /// `MongoDB` `rs.stepDown()` via `mongosh --eval` (promote path; the control plane / orchestrator owns role swap).
    MongoRsStepDown,
    /// Config-server replica-set `rs.initiate` with `configsvr: true` (lab no-auth).
    ///
    /// Requires advertise `primary_host` / `primary_port` (default `27017`).
    /// `user` carries the config RS name (default `cfg0` when empty).
    MongoConfigRsInitiate,
    /// Config-server `rs.add("host:port")` via `mongosh --eval` (run on CSRS primary).
    ///
    /// Requires peer `primary_host` / `primary_port` (default `27017`).
    MongoConfigRsAdd,
    /// Lab readiness: confirm this `mongod` was started with `--shardsvr` (after orchestrator recreate).
    MongoShardsvrEnable,
    /// `sh.addShard("rsName/host:port")` via `mongosh` on a `mongos` (lab no-auth).
    ///
    /// Requires shard seed `primary_host` / `primary_port` and RS name in `user`.
    MongoAddShard,
    /// Lab `sh.moveChunk` for fixed `nucleus_rebalance.nucleus_rebalance_lab` (shard key `sk`).
    ///
    /// Run on `mongos`. `user` is the target shard name (replica-set name).
    /// `slot_start` is the lab key value to move (default `0`).
    MongoMoveChunk,
}

impl TemplatedExecId {
    /// Stable wire / log label.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PgStandbyBootstrap => "pg_standby_bootstrap",
            Self::PgStandbyFollow => "pg_standby_follow",
            Self::PgPromote => "pg_promote",
            Self::RedisReplicaofNoOne => "redis_replicaof_no_one",
            Self::RedisReplicaof => "redis_replicaof",
            Self::RedisClusterMeet => "redis_cluster_meet",
            Self::RedisClusterReplicate => "redis_cluster_replicate",
            Self::RedisClusterSlotsAssign => "redis_cluster_slots_assign",
            Self::RedisClusterMigrate => "redis_cluster_migrate",
            Self::RedisClusterMyId => "redis_cluster_myid",
            Self::RedisClusterSetslotImporting => "redis_cluster_setslot_importing",
            Self::RedisClusterSetslotMigrating => "redis_cluster_setslot_migrating",
            Self::RedisClusterMigrateSlotKeys => "redis_cluster_migrate_slot_keys",
            Self::PgShardBulkCopy => "pg_shard_bulk_copy",
            Self::ChRmtBootstrap => "ch_rmt_bootstrap",
            Self::ChRmtFollow => "ch_rmt_follow",
            Self::ChPromote => "ch_promote",
            Self::ChRemoteServersApply => "ch_remote_servers_apply",
            Self::ChKeeperQuorumApply => "ch_keeper_quorum_apply",
            Self::ChDistributedEnsure => "ch_distributed_ensure",
            Self::ChShardBulkCopy => "ch_shard_bulk_copy",
            Self::MongoRsInitiate => "mongo_rs_initiate",
            Self::MongoRsAdd => "mongo_rs_add",
            Self::MongoRsStepDown => "mongo_rs_step_down",
            Self::MongoConfigRsInitiate => "mongo_config_rs_initiate",
            Self::MongoConfigRsAdd => "mongo_config_rs_add",
            Self::MongoShardsvrEnable => "mongo_shardsvr_enable",
            Self::MongoAddShard => "mongo_add_shard",
            Self::MongoMoveChunk => "mongo_move_chunk",
        }
    }

    /// Whether [`TemplatedExecParams`] must include a non-empty `primary_host`.
    #[must_use]
    pub fn requires_primary_conn(self) -> bool {
        matches!(
            self,
            Self::PgStandbyBootstrap
                | Self::PgStandbyFollow
                | Self::RedisReplicaof
                | Self::RedisClusterMeet
                | Self::RedisClusterMigrateSlotKeys
                | Self::PgShardBulkCopy
                | Self::ChShardBulkCopy
                | Self::ChRmtBootstrap
                | Self::ChRmtFollow
                | Self::MongoRsInitiate
                | Self::MongoRsAdd
                | Self::MongoConfigRsInitiate
                | Self::MongoConfigRsAdd
                | Self::MongoAddShard
        )
    }

    /// Whether `user` carries a Mongo replica-set / shard name (lab charset).
    #[must_use]
    pub fn requires_mongo_rs_name(self) -> bool {
        matches!(
            self,
            Self::MongoRsInitiate
                | Self::MongoConfigRsInitiate
                | Self::MongoAddShard
                | Self::MongoMoveChunk
        )
    }

    /// Whether [`TemplatedExecParams`] must include a non-empty `cluster_node_id`.
    #[must_use]
    pub fn requires_cluster_node_id(self) -> bool {
        matches!(
            self,
            Self::RedisClusterReplicate
                | Self::RedisClusterMigrate
                | Self::RedisClusterSetslotImporting
                | Self::RedisClusterSetslotMigrating
        )
    }

    /// Whether [`TemplatedExecParams`] must include a valid slot range.
    #[must_use]
    pub fn requires_slot_range(self) -> bool {
        matches!(
            self,
            Self::RedisClusterSlotsAssign
                | Self::RedisClusterMigrate
                | Self::RedisClusterSetslotImporting
                | Self::RedisClusterSetslotMigrating
                | Self::RedisClusterMigrateSlotKeys
        )
    }

    /// Whether [`TemplatedExecParams`] must include a non-empty validated `topology_peers`.
    #[must_use]
    pub fn requires_topology_peers(self) -> bool {
        matches!(self, Self::ChRemoteServersApply | Self::ChKeeperQuorumApply)
    }

    /// Whether [`TemplatedExecParams`] must include a cluster name in `user`.
    #[must_use]
    pub fn requires_ch_cluster_name(self) -> bool {
        matches!(self, Self::ChRemoteServersApply | Self::ChDistributedEnsure)
    }

    /// Default primary port when `primary_port` is `0` for templates that need a host.
    #[must_use]
    pub fn default_primary_port(self) -> u16 {
        match self {
            Self::RedisReplicaof | Self::RedisClusterMeet | Self::RedisClusterMigrateSlotKeys => {
                6379
            }
            Self::ChRmtBootstrap | Self::ChKeeperQuorumApply => 9181,
            Self::ChRmtFollow => 8123,
            Self::ChRemoteServersApply | Self::ChShardBulkCopy => 9000,
            Self::MongoRsInitiate
            | Self::MongoRsAdd
            | Self::MongoConfigRsInitiate
            | Self::MongoConfigRsAdd
            | Self::MongoAddShard => 27017,
            _ => 5432,
        }
    }
}

/// Max slots included in one `CLUSTER ADDSLOTS` / SETSLOT batch argv.
pub const TEMPLATED_EXEC_MAX_SLOT_BATCH: u16 = 64;

/// Typed parameters for standby / Redis / CLUSTER templates.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TemplatedExecParams {
    /// Primary / peer hostname or IP (required for PG standby, Redis REPLICAOF, CLUSTER MEET).
    #[serde(default)]
    pub primary_host: String,
    /// Primary / peer port (`0` → template default: `5432` PG, `6379` Redis).
    #[serde(default)]
    pub primary_port: u16,
    /// Replication / DB user (lab default `nucleus` when empty for PG standby / `PgPromote`).
    #[serde(default)]
    pub user: String,
    /// Redis Cluster node id (required for REPLICATE / MIGRATE).
    #[serde(default)]
    pub cluster_node_id: String,
    /// Inclusive slot range start (`0..=16383`).
    #[serde(default)]
    pub slot_start: u16,
    /// Inclusive slot range end (`0..=16383`).
    #[serde(default)]
    pub slot_end: u16,
    /// Bounded topology peer list for `ClickHouse` Distributed / Keeper quorum.
    ///
    /// Keeper: `host:port,host:port`. Remote servers: `shard@host:port,shard@host:port`.
    #[serde(default)]
    pub topology_peers: String,
}

impl TemplatedExecParams {
    /// Validate and normalize params for `template`.
    ///
    /// # Errors
    ///
    /// `primary_host_empty` / `primary_host_invalid` / `user_invalid` /
    /// `cluster_node_id_empty` / `cluster_node_id_invalid` / `slot_range_invalid`.
    pub fn validate_for(
        &self,
        template: TemplatedExecId,
    ) -> anyhow::Result<ValidatedTemplatedExecParams> {
        let (primary_host, primary_port, mut user) = self.validate_primary_conn(template)?;
        let mut slot_start = 0u16;
        let mut slot_end = 0u16;

        if matches!(template, TemplatedExecId::MongoMoveChunk) {
            let u = self.user.trim();
            if u.is_empty() || !templated_user_allowed(u) {
                anyhow::bail!("user_invalid");
            }
            user = u.to_string();
            slot_start = self.slot_start;
        }

        let cluster_node_id = self.validate_cluster_node_id(template)?;
        if template.requires_slot_range() {
            (slot_start, slot_end) = self.validate_slot_range(template)?;
        }
        let topology_peers = self.validate_topology_peers(template)?;

        if template.requires_ch_cluster_name() {
            let u = self.user.trim();
            if u.is_empty() || !templated_user_allowed(u) {
                anyhow::bail!("user_invalid");
            }
            user = u.to_string();
        }

        // Testing Postgres promote: same default user as standby (`nucleus`); allow override.
        if matches!(template, TemplatedExecId::PgPromote) {
            let u = self.user.trim();
            if u.is_empty() {
                user = "nucleus".to_string();
            } else if !templated_user_allowed(u) {
                anyhow::bail!("user_invalid");
            } else {
                user = u.to_string();
            }
        }

        Ok(ValidatedTemplatedExecParams {
            primary_host,
            primary_port,
            user,
            cluster_node_id,
            slot_start,
            slot_end,
            topology_peers,
        })
    }

    fn validate_primary_conn(
        &self,
        template: TemplatedExecId,
    ) -> anyhow::Result<(String, u16, String)> {
        let mut primary_host = String::new();
        let mut primary_port = template.default_primary_port();
        let mut user = String::new();

        if !template.requires_primary_conn() {
            return Ok((primary_host, primary_port, user));
        }

        let host = self.primary_host.trim();
        if host.is_empty() {
            anyhow::bail!("primary_host_empty");
        }
        if !templated_host_allowed(host) {
            anyhow::bail!("primary_host_invalid");
        }
        primary_host = host.to_string();
        primary_port = if self.primary_port == 0 {
            template.default_primary_port()
        } else {
            self.primary_port
        };
        // PG standby / bulk-copy: lab DB user. Mongo initiate: replica-set name in `user`.
        if matches!(
            template,
            TemplatedExecId::PgStandbyBootstrap
                | TemplatedExecId::PgStandbyFollow
                | TemplatedExecId::PgShardBulkCopy
        ) {
            let u = self.user.trim();
            if u.is_empty() {
                user = "nucleus".to_string();
            } else if !templated_user_allowed(u) {
                anyhow::bail!("user_invalid");
            } else {
                user = u.to_string();
            }
        } else if template.requires_mongo_rs_name()
            && !matches!(template, TemplatedExecId::MongoMoveChunk)
        {
            let u = self.user.trim();
            let default = if matches!(template, TemplatedExecId::MongoConfigRsInitiate) {
                "cfg0"
            } else {
                "rs0"
            };
            if u.is_empty() {
                user = default.to_string();
            } else if !templated_user_allowed(u) {
                anyhow::bail!("user_invalid");
            } else {
                user = u.to_string();
            }
        }

        Ok((primary_host, primary_port, user))
    }

    fn validate_cluster_node_id(&self, template: TemplatedExecId) -> anyhow::Result<String> {
        if !template.requires_cluster_node_id() {
            return Ok(String::new());
        }
        let id = self.cluster_node_id.trim();
        if id.is_empty() {
            anyhow::bail!("cluster_node_id_empty");
        }
        if !templated_cluster_node_id_allowed(id) {
            anyhow::bail!("cluster_node_id_invalid");
        }
        Ok(id.to_string())
    }

    fn validate_slot_range(&self, template: TemplatedExecId) -> anyhow::Result<(u16, u16)> {
        let slot_start = self.slot_start;
        let slot_end = self.slot_end;
        if slot_start > 16_383 || slot_end > 16_383 || slot_start > slot_end {
            anyhow::bail!("slot_range_invalid");
        }
        let count = u32::from(slot_end - slot_start) + 1;
        if matches!(
            template,
            TemplatedExecId::RedisClusterMigrate
                | TemplatedExecId::RedisClusterSetslotImporting
                | TemplatedExecId::RedisClusterSetslotMigrating
                | TemplatedExecId::RedisClusterMigrateSlotKeys
        ) {
            // One slot per docker exec; the control plane / orchestrator batches via multiple enqueues.
            if slot_start != slot_end {
                anyhow::bail!("slot_range_invalid");
            }
        } else if count > u32::from(TEMPLATED_EXEC_MAX_SLOT_BATCH) {
            anyhow::bail!("slot_range_invalid");
        }
        Ok((slot_start, slot_end))
    }

    fn validate_topology_peers(&self, template: TemplatedExecId) -> anyhow::Result<String> {
        if !template.requires_topology_peers() {
            return Ok(String::new());
        }
        let raw = self.topology_peers.trim();
        if raw.is_empty() {
            anyhow::bail!("topology_peers_empty");
        }
        if raw.len() > 4096 {
            anyhow::bail!("topology_peers_too_long");
        }
        let parts: Vec<&str> = raw.split(',').filter(|p| !p.is_empty()).collect();
        if parts.is_empty() {
            anyhow::bail!("topology_peers_empty");
        }
        if parts.len() > 64 {
            anyhow::bail!("topology_peers_too_many");
        }
        let shard_form = matches!(template, TemplatedExecId::ChRemoteServersApply);
        for part in &parts {
            if shard_form {
                let Some((shard, hostport)) = part.split_once('@') else {
                    anyhow::bail!("topology_peers_invalid");
                };
                if shard.is_empty() || !shard.chars().all(|c| c.is_ascii_digit()) || shard.len() > 8
                {
                    anyhow::bail!("topology_peers_invalid");
                }
                let Some((host, port)) = hostport.rsplit_once(':') else {
                    anyhow::bail!("topology_peers_invalid");
                };
                if !templated_host_allowed(host) {
                    anyhow::bail!("topology_peers_invalid");
                }
                if port.parse::<u16>().is_err() {
                    anyhow::bail!("topology_peers_invalid");
                }
            } else {
                let Some((host, port)) = part.rsplit_once(':') else {
                    anyhow::bail!("topology_peers_invalid");
                };
                if !templated_host_allowed(host) {
                    anyhow::bail!("topology_peers_invalid");
                }
                if port.parse::<u16>().is_err() {
                    anyhow::bail!("topology_peers_invalid");
                }
            }
        }
        Ok(parts.join(","))
    }
}

/// Normalized params after [`TemplatedExecParams::validate_for`].
#[derive(Debug, Clone)]
pub struct ValidatedTemplatedExecParams {
    /// Validated primary / peer host.
    pub primary_host: String,
    /// Validated primary / peer port.
    pub primary_port: u16,
    /// Validated DB / replication user (empty for Redis templates).
    pub user: String,
    /// Validated Redis Cluster node id (empty when unused).
    pub cluster_node_id: String,
    /// Inclusive slot range start.
    pub slot_start: u16,
    /// Inclusive slot range end.
    pub slot_end: u16,
    /// Validated topology peer list (empty when unused).
    pub topology_peers: String,
}

fn templated_host_allowed(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && !host.contains([
            ' ', '\t', '\n', '\r', ';', '|', '&', '$', '`', '(', ')', '<', '>', '"', '\'', '\\',
            '\0',
        ])
}

fn templated_user_allowed(user: &str) -> bool {
    !user.is_empty()
        && user.len() <= 63
        && user
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn templated_cluster_node_id_allowed(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.chars().all(|c| c.is_ascii_hexdigit())
}

/// Spec for [`ContainerActionKind::TemplatedExec`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TemplatedExecSpec {
    /// Allowlisted template id (enum; unknown wire values fail deserialize).
    pub template: TemplatedExecId,
    /// Typed params (host/port/user for standby templates).
    #[serde(default)]
    pub params: TemplatedExecParams,
}

impl ContainerActionKind {
    /// Stable lowercase wire string for this action kind (matches the queue `action_kind`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Restart => "restart",
            Self::Logs => "logs",
            Self::Inspect => "inspect",
            Self::Deploy => "deploy",
            Self::EnsureNetwork => "ensure_network",
            Self::ProbeHost => "probe_host",
            Self::Diagnostic => "diagnostic",
            Self::WireguardPeer => "wireguard_peer",
            Self::EnsureDockerImage => "ensure_docker_image",
            Self::GrowFs => "grow_fs",
            Self::TemplatedExec => "templated_exec",
        }
    }
}

/// `WireGuard` peer parameters for [`ContainerActionKind::WireguardPeer`] (`wg set` on the host).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WireguardPeerSpec {
    /// Peer's Wireguard public key.
    pub peer_public_key: String,
    /// Peer endpoint (`host:port`).
    pub endpoint: String,
    /// Comma-separated allowed IPs / CIDRs routed to the peer.
    pub allowed_ips: String,
}

/// Bind mount for `docker run -v`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VolumeMount {
    /// Absolute host path to mount.
    pub host_path: String,
    /// Mount target path inside the container.
    pub container_path: String,
    /// When `true`, the mount is read-only (`:ro`).
    #[serde(default)]
    pub read_only: bool,
}

/// Container resource limits applied at `docker run`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourceLimits {
    /// Memory limit in mebibytes (`--memory`); `0` disables the limit.
    pub memory_mb: u32,
    /// CPU shares (`--cpu-shares`); `0` disables the setting.
    pub cpu_shares: u32,
}

/// Resolved secret env var for deploy; injected with `docker run --env-file` (never `-e NAME=value`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretEnvVar {
    /// Env var name (`[A-Z_][A-Z0-9_]*`).
    pub name: String,
    /// Resolved secret value (must not contain newlines).
    pub value: String,
}

/// Docker `--health-cmd` wiring (HTTP check inside the container network namespace).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContainerHealthCheck {
    /// HTTP path probed inside the container (leading `/` optional).
    pub endpoint: String,
    /// Port the health check connects to on `127.0.0.1` inside the container.
    pub internal_port: u16,
    /// Interval between health checks in seconds.
    pub interval_secs: u32,
    /// Per-check timeout in seconds.
    pub timeout_secs: u32,
}

/// Request payload for a container action invocation on a specific node.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContainerActionRequest {
    /// Target node id (used to guard node-scoped handoff payloads).
    pub node_id: String,
    /// Container name or id the action targets (also used as a log label for some kinds).
    pub container_ref: String,
    /// The lifecycle / inspection operation to perform.
    pub action: ContainerActionKind,
    /// For [`ContainerActionKind::Logs`], the number of trailing log lines to fetch.
    pub tail_lines: Option<u32>,
    /// Registry image reference (required for deploy and `ensure_docker_image`).
    #[serde(default)]
    pub image_ref: Option<String>,
    /// Non-secret `NAME=value` env vars passed via `-e`.
    #[serde(default)]
    pub env_vars: Vec<String>,
    /// Deploy-only: passed via a short-lived `--env-file` so values never appear in `-e` args.
    #[serde(default)]
    pub secret_env_vars: Vec<SecretEnvVar>,
    /// Port mappings (`host:container` or `bind:host:container`) passed via `-p`.
    #[serde(default)]
    pub port_mappings: Vec<String>,
    /// Each entry is passed to `docker run --add-host …` (e.g. `host.docker.internal:host-gateway`).
    #[serde(default)]
    pub extra_hosts: Vec<String>,
    /// When set, `docker run --entrypoint …` is emitted before the image ref.
    #[serde(default)]
    pub entrypoint: Option<String>,
    /// Arguments after the image ref (replaces image CMD), e.g. `-c` and a shell script.
    /// Each entry is usually a JSON string. Non-string values (e.g. pre-claim `{"$secret_ref":…}`)
    /// are rejected at execution: the pion control plane should resolve before Parton runs the command.
    #[serde(default)]
    pub command: Vec<serde_json::Value>,
    /// When set (e.g. `unless-stopped`), passed to `docker run --restart …`.
    #[serde(default)]
    pub restart_policy: Option<String>,
    /// Bind mounts passed via `-v`.
    #[serde(default)]
    pub volume_mounts: Vec<VolumeMount>,
    /// Optional CPU / memory limits.
    #[serde(default)]
    pub resource_limits: Option<ResourceLimits>,
    /// Optional Docker health check wiring.
    #[serde(default)]
    pub health_check: Option<ContainerHealthCheck>,
    /// Docker labels applied via `--label`.
    #[serde(default)]
    pub labels: HashMap<String, String>,
    /// When set, `docker run --network …` is emitted for [`ContainerActionKind::Deploy`].
    #[serde(default)]
    pub network: Option<String>,
    /// When [`ContainerActionKind::Diagnostic`] is selected, must be set.
    #[serde(default)]
    pub diagnostic: Option<DiagnosticSpec>,
    /// When [`ContainerActionKind::WireguardPeer`] is selected, must be set.
    #[serde(default)]
    pub wireguard_peer: Option<WireguardPeerSpec>,
    /// When [`ContainerActionKind::GrowFs`] is selected, must be set.
    #[serde(default)]
    pub grow_fs: Option<GrowFsSpec>,
    /// When [`ContainerActionKind::TemplatedExec`] is selected, must be set.
    #[serde(default)]
    pub templated_exec: Option<TemplatedExecSpec>,
    /// When set, destructive actions (`Stop`, `Restart`, deploy pre-cleanup) only apply if
    /// `docker inspect` reports this container id for `container_ref`. Prevents stale
    /// `gluon-stop:*` / redeploy races from killing a newer container that reused the same name.
    #[serde(default)]
    pub expected_container_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pg_promote_validate_defaults_user_to_nucleus() {
        let v = TemplatedExecParams::default()
            .validate_for(TemplatedExecId::PgPromote)
            .expect("ok");
        assert_eq!(v.user, "nucleus");
    }

    #[test]
    fn pg_promote_validate_keeps_custom_user() {
        let v = TemplatedExecParams {
            user: "postgres".into(),
            ..Default::default()
        }
        .validate_for(TemplatedExecId::PgPromote)
        .expect("ok");
        assert_eq!(v.user, "postgres");
    }

    #[test]
    fn pg_promote_validate_rejects_invalid_user() {
        let err = TemplatedExecParams {
            user: "bad;user".into(),
            ..Default::default()
        }
        .validate_for(TemplatedExecId::PgPromote)
        .expect_err("user_invalid");
        assert!(err.to_string().contains("user_invalid"));
    }
}

/// Normalized response shape returned by action executors.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ContainerActionResponse {
    /// Action kind that was dispatched (echo of the request).
    pub action: ContainerActionKind,
    /// Container name, network name, or host label the action targeted.
    pub container_ref: String,
    /// `true` when the backend completed successfully; `false` for skipped/failed outcomes
    /// that still return a structured response (see `message` / `payload`).
    pub success: bool,
    /// Short operator-facing summary (e.g. `restart succeeded`, skip reason).
    pub message: String,
    /// Structured, action-specific result (logs text, inspect JSON, probe metrics, …).
    pub payload: serde_json::Value,
}
