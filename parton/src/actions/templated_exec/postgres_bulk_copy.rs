//! Multi-step lab Postgres shard bulk copy (fixed table → peer).
//!
//! Order: `CREATE` on the **source** container, `CREATE` on the dest peer,
//! `pg_dump` (source), then apply the dump on the dest. Creating only on dest
//! left `pg_dump -t nucleus_rebalance_lab` failing on an empty source.

use super::super::types::{TemplatedExecId, ValidatedTemplatedExecParams};
use super::registry::classify_promote_outcome;
use super::runner::{CommandOutput, DockerCliRunner};

/// Fixed lab table copied by [`TemplatedExecId::PgShardBulkCopy`] (not caller-controlled).
pub(crate) const LAB_REBALANCE_TABLE: &str = "nucleus_rebalance_lab";

/// Lab database name inside the Postgres image.
pub(crate) const LAB_DB: &str = "nucleus";

const DUMP_PATH: &str = "/tmp/nucleus_rebalance_lab.sql";

const CREATE_TABLE_SQL: &str = "CREATE TABLE IF NOT EXISTS nucleus_rebalance_lab (id text PRIMARY KEY, payload text NOT NULL);";

/// Ensure table on source and dest → dump from local → apply dump on dest.
pub(crate) fn run_pg_shard_bulk_copy(
    container_ref: &str,
    params: &ValidatedTemplatedExecParams,
    runner: &dyn DockerCliRunner,
) -> anyhow::Result<(bool, &'static str, CommandOutput)> {
    // Source must have the lab table before pg_dump; dest CREATE alone left dump failing.
    let create_src = runner.run(&psql_local_argv(container_ref, params, CREATE_TABLE_SQL))?;
    if !create_src.status_success {
        return Ok((false, "pg_shard_bulk_copy failed", create_src));
    }
    let create_dst = runner.run(&psql_peer_argv(container_ref, params, CREATE_TABLE_SQL))?;
    if !create_dst.status_success {
        return Ok((false, "pg_shard_bulk_copy failed", create_dst));
    }
    let dump = runner.run(&pg_dump_lab_table_argv(container_ref, params))?;
    if !dump.status_success {
        return Ok((false, "pg_shard_bulk_copy failed", dump));
    }
    let apply = runner.run(&psql_peer_file_argv(container_ref, params))?;
    let (ok, msg) = classify_promote_outcome(
        TemplatedExecId::PgShardBulkCopy,
        apply.status_success,
        &apply.combined(),
    );
    Ok((ok, msg, apply))
}

#[must_use]
fn psql_local_argv(
    container_ref: &str,
    params: &ValidatedTemplatedExecParams,
    sql: &str,
) -> Vec<String> {
    vec![
        "exec".into(),
        container_ref.to_string(),
        "psql".into(),
        "-U".into(),
        params.user.clone(),
        "-d".into(),
        LAB_DB.into(),
        "-v".into(),
        "ON_ERROR_STOP=1".into(),
        "-c".into(),
        sql.to_string(),
    ]
}

#[must_use]
fn psql_peer_argv(
    container_ref: &str,
    params: &ValidatedTemplatedExecParams,
    sql: &str,
) -> Vec<String> {
    vec![
        "exec".into(),
        container_ref.to_string(),
        "psql".into(),
        "-h".into(),
        params.primary_host.clone(),
        "-p".into(),
        params.primary_port.to_string(),
        "-U".into(),
        params.user.clone(),
        "-d".into(),
        LAB_DB.into(),
        "-v".into(),
        "ON_ERROR_STOP=1".into(),
        "-c".into(),
        sql.to_string(),
    ]
}

#[must_use]
fn pg_dump_lab_table_argv(
    container_ref: &str,
    params: &ValidatedTemplatedExecParams,
) -> Vec<String> {
    vec![
        "exec".into(),
        container_ref.to_string(),
        "pg_dump".into(),
        "-U".into(),
        params.user.clone(),
        "-d".into(),
        LAB_DB.into(),
        "-t".into(),
        LAB_REBALANCE_TABLE.into(),
        "--data-only".into(),
        "-f".into(),
        DUMP_PATH.into(),
    ]
}

#[must_use]
fn psql_peer_file_argv(container_ref: &str, params: &ValidatedTemplatedExecParams) -> Vec<String> {
    vec![
        "exec".into(),
        container_ref.to_string(),
        "psql".into(),
        "-h".into(),
        params.primary_host.clone(),
        "-p".into(),
        params.primary_port.to_string(),
        "-U".into(),
        params.user.clone(),
        "-d".into(),
        LAB_DB.into(),
        "-v".into(),
        "ON_ERROR_STOP=1".into(),
        "-f".into(),
        DUMP_PATH.into(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_argv_splices_validated_host_port_user() {
        let p = ValidatedTemplatedExecParams {
            primary_host: "10.0.0.2".into(),
            primary_port: 5432,
            user: "nucleus".into(),
            cluster_node_id: String::new(),
            slot_start: 0,
            slot_end: 0,
            topology_peers: String::new(),
        };
        let args = psql_peer_argv("pg-src", &p, CREATE_TABLE_SQL);
        assert_eq!(args[0], "exec");
        assert!(args.iter().any(|a| a == "10.0.0.2"));
        assert!(args.iter().any(|a| a.contains(LAB_REBALANCE_TABLE)));
        let dump = pg_dump_lab_table_argv("pg-src", &p);
        assert!(dump.iter().any(|a| a == LAB_REBALANCE_TABLE));
        assert!(dump.iter().any(|a| a == DUMP_PATH));
    }

    #[test]
    fn local_create_argv_has_no_peer_host() {
        let p = ValidatedTemplatedExecParams {
            primary_host: "10.0.0.2".into(),
            primary_port: 5432,
            user: "nucleus".into(),
            cluster_node_id: String::new(),
            slot_start: 0,
            slot_end: 0,
            topology_peers: String::new(),
        };
        let args = psql_local_argv("pg-src", &p, CREATE_TABLE_SQL);
        assert!(!args.iter().any(|a| a == "-h"));
        assert!(!args.iter().any(|a| a == "10.0.0.2"));
        assert!(args.iter().any(|a| a.contains(LAB_REBALANCE_TABLE)));
    }
}
