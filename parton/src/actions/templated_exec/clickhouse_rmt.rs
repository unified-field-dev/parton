//! `ClickHouse` RMT / promote / Distributed allowlisted `docker exec` argv builders.

use super::super::types::{TemplatedExecId, ValidatedTemplatedExecParams};
use super::registry::classify_promote_outcome;
use super::runner::{CommandOutput, DockerCliRunner};

/// Fixed lab local table for Distributed fan-out proofs.
pub(crate) const LAB_LOCAL_TABLE: &str = "nucleus_local_lab";

/// Fixed lab Distributed table wrapping [`LAB_LOCAL_TABLE`].
pub(crate) const LAB_DISTRIBUTED_TABLE: &str = "nucleus_distributed_lab";

const REMOTE_SERVERS_CONFIG_PATH: &str =
    "/etc/clickhouse-server/config.d/nucleus_remote_servers.xml";

/// Build argv for `ClickHouse` RMT / Distributed templates (discrete tokens only).
///
/// Lab control-plane readiness uses `clickhouse-client` queries. The control plane /
/// orchestrator validates Keeper/peer/topology params; the container query proves the
/// agent path without free-text shell.
#[must_use]
pub(crate) fn clickhouse_templated_exec_argv(
    container_ref: &str,
    id: TemplatedExecId,
    params: &ValidatedTemplatedExecParams,
) -> Vec<String> {
    match id {
        TemplatedExecId::ChRmtBootstrap
        | TemplatedExecId::ChRmtFollow
        | TemplatedExecId::ChKeeperQuorumApply => vec![
            "exec".into(),
            container_ref.to_string(),
            "clickhouse-client".into(),
            "-q".into(),
            "SELECT 1".into(),
        ],
        TemplatedExecId::ChRemoteServersApply => {
            // Multi-step path uses [`run_ch_remote_servers_apply`]; single-argv callers
            // still get RELOAD after XML write helpers build their own argv.
            vec![
                "exec".into(),
                container_ref.to_string(),
                "clickhouse-client".into(),
                "-q".into(),
                "SYSTEM RELOAD CONFIG".into(),
            ]
        }
        TemplatedExecId::ChDistributedEnsure => {
            let cluster = params.user.as_str();
            let sql = format!(
                "CREATE TABLE IF NOT EXISTS default.{LAB_DISTRIBUTED_TABLE} AS default.{LAB_LOCAL_TABLE} ENGINE = Distributed('{cluster}', 'default', '{LAB_LOCAL_TABLE}', rand())"
            );
            vec![
                "exec".into(),
                container_ref.to_string(),
                "clickhouse-client".into(),
                "-q".into(),
                sql,
            ]
        }
        _ => Vec::new(),
    }
}

/// Write validated `remote_servers` XML then `SYSTEM RELOAD CONFIG`.
pub(crate) fn run_ch_remote_servers_apply(
    container_ref: &str,
    params: &ValidatedTemplatedExecParams,
    runner: &dyn DockerCliRunner,
) -> anyhow::Result<(bool, &'static str, CommandOutput)> {
    let xml = build_remote_servers_xml(params.user.as_str(), params.topology_peers.as_str());
    let write = runner.run(&write_remote_servers_xml_argv(container_ref, &xml))?;
    if !write.status_success {
        return Ok((false, "ch_remote_servers_apply failed", write));
    }
    let reload = runner.run(&clickhouse_templated_exec_argv(
        container_ref,
        TemplatedExecId::ChRemoteServersApply,
        params,
    ))?;
    let (ok, msg) = classify_promote_outcome(
        TemplatedExecId::ChRemoteServersApply,
        reload.status_success,
        &reload.combined(),
    );
    Ok((ok, msg, reload))
}

/// Create local `MergeTree` lab table, then Distributed wrapper.
pub(crate) fn run_ch_distributed_ensure(
    container_ref: &str,
    params: &ValidatedTemplatedExecParams,
    runner: &dyn DockerCliRunner,
) -> anyhow::Result<(bool, &'static str, CommandOutput)> {
    let local_sql = format!(
        "CREATE TABLE IF NOT EXISTS default.{LAB_LOCAL_TABLE} (id UInt64, payload String) ENGINE = MergeTree ORDER BY id"
    );
    let local = runner.run(&clickhouse_query_argv(container_ref, &local_sql))?;
    if !local.status_success {
        return Ok((false, "ch_distributed_ensure failed", local));
    }
    let dist = runner.run(&clickhouse_templated_exec_argv(
        container_ref,
        TemplatedExecId::ChDistributedEnsure,
        params,
    ))?;
    let (ok, msg) = classify_promote_outcome(
        TemplatedExecId::ChDistributedEnsure,
        dist.status_success,
        &dist.combined(),
    );
    Ok((ok, msg, dist))
}

/// Build `ClickHouse` `remote_servers` XML from validated `shard@host:port` peers.
#[must_use]
pub(crate) fn build_remote_servers_xml(cluster: &str, topology_peers: &str) -> String {
    let mut shards: Vec<(String, Vec<(String, String)>)> = Vec::new();
    for part in topology_peers.split(',').filter(|p| !p.is_empty()) {
        let Some((shard, hostport)) = part.split_once('@') else {
            continue;
        };
        let Some((host, port)) = hostport.rsplit_once(':') else {
            continue;
        };
        if let Some((_, replicas)) = shards.iter_mut().find(|(s, _)| s == shard) {
            replicas.push((host.to_string(), port.to_string()));
        } else {
            shards.push((
                shard.to_string(),
                vec![(host.to_string(), port.to_string())],
            ));
        }
    }
    let mut body = String::new();
    body.push_str("<clickhouse><remote_servers><");
    body.push_str(cluster);
    body.push('>');
    for (_, replicas) in &shards {
        body.push_str("<shard>");
        for (host, port) in replicas {
            body.push_str("<replica><host>");
            body.push_str(host);
            body.push_str("</host><port>");
            body.push_str(port);
            body.push_str("</port></replica>");
        }
        body.push_str("</shard>");
    }
    body.push_str("</");
    body.push_str(cluster);
    body.push_str("></remote_servers></clickhouse>");
    body
}

fn write_remote_servers_xml_argv(container_ref: &str, xml: &str) -> Vec<String> {
    // Single-quoted printf payload: validated hosts/ports/cluster only (no user free text).
    let escaped = xml.replace('\'', "'\\''");
    let script = format!("printf '%s' '{escaped}' > {REMOTE_SERVERS_CONFIG_PATH}");
    vec![
        "exec".into(),
        container_ref.to_string(),
        "sh".into(),
        "-c".into(),
        script,
    ]
}

fn clickhouse_query_argv(container_ref: &str, sql: &str) -> Vec<String> {
    vec![
        "exec".into(),
        container_ref.to_string(),
        "clickhouse-client".into(),
        "-q".into(),
        sql.to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::types::ValidatedTemplatedExecParams;

    fn params() -> ValidatedTemplatedExecParams {
        ValidatedTemplatedExecParams {
            primary_host: "10.0.0.1".into(),
            primary_port: 9181,
            user: String::new(),
            cluster_node_id: String::new(),
            slot_start: 0,
            slot_end: 0,
            topology_peers: String::new(),
        }
    }

    #[test]
    fn templated_exec_ch_rmt_bootstrap_argv_shape() {
        let args =
            clickhouse_templated_exec_argv("ch-1", TemplatedExecId::ChRmtBootstrap, &params());
        assert_eq!(
            args,
            vec!["exec", "ch-1", "clickhouse-client", "-q", "SELECT 1",]
        );
    }

    #[test]
    fn templated_exec_ch_rmt_follow_argv_shape() {
        let args = clickhouse_templated_exec_argv("ch-1", TemplatedExecId::ChRmtFollow, &params());
        assert_eq!(args[2], "clickhouse-client");
        assert_eq!(args[4], "SELECT 1");
    }

    #[test]
    fn templated_exec_ch_promote_argv_shape() {
        use super::super::registry::promote_exec_argv;
        let args = promote_exec_argv("ch-1", TemplatedExecId::ChPromote, "");
        assert_eq!(
            args,
            vec!["exec", "ch-1", "clickhouse-client", "-q", "SELECT 1",]
        );
    }

    #[test]
    fn templated_exec_ch_remote_servers_apply_argv_embeds_topology_hosts() {
        let mut p = params();
        p.user = "nucleus_stack".into();
        p.topology_peers = "0@10.0.0.1:9000,1@10.0.0.2:9000".into();
        let xml = build_remote_servers_xml(p.user.as_str(), p.topology_peers.as_str());
        assert!(xml.contains("<host>10.0.0.1</host>"));
        assert!(xml.contains("<host>10.0.0.2</host>"));
        assert!(xml.contains("<nucleus_stack>"));
        let write = write_remote_servers_xml_argv("ch-1", &xml);
        assert_eq!(write[2], "sh");
        assert!(write[4].contains("10.0.0.1"));
        assert!(write[4].contains(REMOTE_SERVERS_CONFIG_PATH));
        let reload =
            clickhouse_templated_exec_argv("ch-1", TemplatedExecId::ChRemoteServersApply, &p);
        assert_eq!(reload[4], "SYSTEM RELOAD CONFIG");
    }

    #[test]
    fn templated_exec_ch_keeper_quorum_apply_argv_shape() {
        let mut p = params();
        p.topology_peers = "10.0.0.1:9181,10.0.0.2:9181,10.0.0.3:9181".into();
        let args = clickhouse_templated_exec_argv("ch-1", TemplatedExecId::ChKeeperQuorumApply, &p);
        assert_eq!(args[4], "SELECT 1");
    }

    #[test]
    fn templated_exec_ch_distributed_ensure_argv_shape() {
        let mut p = params();
        p.user = "nucleus_stack".into();
        let args = clickhouse_templated_exec_argv("ch-1", TemplatedExecId::ChDistributedEnsure, &p);
        assert!(args[4].contains("Distributed('nucleus_stack'"));
        assert!(args[4].contains(LAB_DISTRIBUTED_TABLE));
        assert!(args[4].contains(LAB_LOCAL_TABLE));
    }
}
