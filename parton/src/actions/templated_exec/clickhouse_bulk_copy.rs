//! Multi-step lab `ClickHouse` shard bulk copy (fixed `MergeTree` → peer via `remote()`).

use super::super::types::{TemplatedExecId, ValidatedTemplatedExecParams};
use super::registry::classify_promote_outcome;
use super::runner::{CommandOutput, DockerCliRunner};

/// Fixed lab table copied by [`TemplatedExecId::ChShardBulkCopy`] (not caller-controlled).
pub(crate) const LAB_REBALANCE_TABLE: &str = "nucleus_rebalance_lab";

const CREATE_TABLE_SQL: &str = "CREATE TABLE IF NOT EXISTS default.nucleus_rebalance_lab (id String, payload String) ENGINE = MergeTree ORDER BY id";

/// Ensure table on dest → push local rows via `remote()` to dest.
pub(crate) fn run_ch_shard_bulk_copy(
    container_ref: &str,
    params: &ValidatedTemplatedExecParams,
    runner: &dyn DockerCliRunner,
) -> anyhow::Result<(bool, &'static str, CommandOutput)> {
    let create = runner.run(&clickhouse_peer_argv(
        container_ref,
        params,
        CREATE_TABLE_SQL,
    ))?;
    if !create.status_success {
        return Ok((false, "ch_shard_bulk_copy failed", create));
    }
    let insert = runner.run(&clickhouse_remote_insert_argv(container_ref, params))?;
    let (ok, msg) = classify_promote_outcome(
        TemplatedExecId::ChShardBulkCopy,
        insert.status_success,
        &insert.combined(),
    );
    Ok((ok, msg, insert))
}

/// `clickhouse-client -h <dest> -p <port> -q <sql>` on the source container.
#[must_use]
pub(crate) fn clickhouse_peer_argv(
    container_ref: &str,
    params: &ValidatedTemplatedExecParams,
    sql: &str,
) -> Vec<String> {
    vec![
        "exec".into(),
        container_ref.to_string(),
        "clickhouse-client".into(),
        "-h".into(),
        params.primary_host.clone(),
        "-p".into(),
        params.primary_port.to_string(),
        "-q".into(),
        sql.to_string(),
    ]
}

/// Push local lab table rows to dest via `INSERT INTO FUNCTION remote(...)`.
#[must_use]
pub(crate) fn clickhouse_remote_insert_argv(
    container_ref: &str,
    params: &ValidatedTemplatedExecParams,
) -> Vec<String> {
    let remote_addr = format!("{}:{}", params.primary_host, params.primary_port);
    let sql = format!(
        "INSERT INTO FUNCTION remote('{remote_addr}', 'default', '{LAB_REBALANCE_TABLE}') SELECT * FROM default.{LAB_REBALANCE_TABLE}"
    );
    vec![
        "exec".into(),
        container_ref.to_string(),
        "clickhouse-client".into(),
        "-q".into(),
        sql,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_argv_splices_validated_host_port() {
        let p = ValidatedTemplatedExecParams {
            primary_host: "10.0.0.2".into(),
            primary_port: 9000,
            user: String::new(),
            cluster_node_id: String::new(),
            slot_start: 0,
            slot_end: 0,
            topology_peers: String::new(),
        };
        let args = clickhouse_peer_argv("ch-src", &p, CREATE_TABLE_SQL);
        assert_eq!(args[0], "exec");
        assert_eq!(args[1], "ch-src");
        assert!(args.iter().any(|a| a == "10.0.0.2"));
        assert!(args.iter().any(|a| a == "9000"));
        assert!(args.iter().any(|a| a.contains(LAB_REBALANCE_TABLE)));
        assert!(args.iter().any(|a| a.contains("MergeTree")));
    }

    #[test]
    fn remote_insert_argv_targets_peer_and_lab_table() {
        let p = ValidatedTemplatedExecParams {
            primary_host: "10.0.0.3".into(),
            primary_port: 9000,
            user: String::new(),
            cluster_node_id: String::new(),
            slot_start: 0,
            slot_end: 0,
            topology_peers: String::new(),
        };
        let args = clickhouse_remote_insert_argv("ch-src", &p);
        assert_eq!(args[0], "exec");
        let sql = args.last().expect("sql");
        assert!(sql.contains("10.0.0.3:9000"));
        assert!(sql.contains(LAB_REBALANCE_TABLE));
        assert!(sql.contains("INSERT INTO FUNCTION remote"));
    }
}
