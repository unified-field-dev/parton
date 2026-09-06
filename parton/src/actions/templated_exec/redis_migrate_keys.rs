//! Multi-step Redis Cluster slot key migrate (`GETKEYSINSLOT` → `MIGRATE`).

use super::super::types::{TemplatedExecId, ValidatedTemplatedExecParams};
use super::registry::classify_promote_outcome;
use super::runner::{CommandOutput, DockerCliRunner};

/// Max keys moved in one [`TemplatedExecId::RedisClusterMigrateSlotKeys`] call.
pub(crate) const MIGRATE_KEYS_BATCH: usize = 100;

/// MIGRATE timeout milliseconds (fixed allowlisted token).
const MIGRATE_TIMEOUT_MS: &str = "5000";

/// GETKEYSINSLOT then MIGRATE to peer; empty key set is success.
pub(crate) fn run_migrate_slot_keys(
    container_ref: &str,
    params: &ValidatedTemplatedExecParams,
    runner: &dyn DockerCliRunner,
) -> anyhow::Result<(bool, &'static str, CommandOutput)> {
    let get_argv = getkeysinslot_argv(container_ref, params.slot_start);
    let get_out = runner.run(&get_argv)?;
    if !get_out.status_success {
        return Ok((false, "redis_cluster_migrate_slot_keys failed", get_out));
    }
    let keys = parse_getkeysinslot_keys(&get_out.stdout);
    if keys.is_empty() {
        let (ok, msg) =
            classify_promote_outcome(TemplatedExecId::RedisClusterMigrateSlotKeys, true, "ok");
        return Ok((ok, msg, get_out));
    }
    for key in &keys {
        if !templated_redis_key_allowed(key) {
            return Ok((
                false,
                "redis_cluster_migrate_slot_keys failed",
                CommandOutput {
                    status_success: false,
                    stdout: String::new(),
                    stderr: "key_invalid".into(),
                },
            ));
        }
    }
    let migrate_argv = migrate_keys_argv(container_ref, params, &keys);
    let migrate_out = runner.run(&migrate_argv)?;
    let (ok, msg) = classify_promote_outcome(
        TemplatedExecId::RedisClusterMigrateSlotKeys,
        migrate_out.status_success,
        &migrate_out.combined(),
    );
    Ok((ok, msg, migrate_out))
}

#[must_use]
fn getkeysinslot_argv(container_ref: &str, slot: u16) -> Vec<String> {
    vec![
        "exec".into(),
        container_ref.to_string(),
        "redis-cli".into(),
        "CLUSTER".into(),
        "GETKEYSINSLOT".into(),
        slot.to_string(),
        MIGRATE_KEYS_BATCH.to_string(),
    ]
}

#[must_use]
fn migrate_keys_argv(
    container_ref: &str,
    params: &ValidatedTemplatedExecParams,
    keys: &[String],
) -> Vec<String> {
    let mut argv = vec![
        "exec".into(),
        container_ref.to_string(),
        "redis-cli".into(),
        "MIGRATE".into(),
        params.primary_host.clone(),
        params.primary_port.to_string(),
        String::new(),
        "0".into(),
        MIGRATE_TIMEOUT_MS.into(),
        "KEYS".into(),
    ];
    argv.extend(keys.iter().cloned());
    argv
}

fn parse_getkeysinslot_keys(stdout: &str) -> Vec<String> {
    stdout
        .split(|c: char| c.is_whitespace())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

fn templated_redis_key_allowed(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 512
        && !key.contains([
            ' ', '\t', '\n', '\r', ';', '|', '&', '$', '`', '(', ')', '<', '>', '"', '\'', '\\',
            '\0',
        ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn getkeysinslot_argv_fixed() {
        let args = getkeysinslot_argv("redis-1", 42);
        assert_eq!(
            &args[2..],
            ["redis-cli", "CLUSTER", "GETKEYSINSLOT", "42", "100"]
        );
    }

    #[test]
    fn migrate_argv_splices_peer_and_keys() {
        let p = ValidatedTemplatedExecParams {
            primary_host: "10.0.0.9".into(),
            primary_port: 6379,
            user: String::new(),
            cluster_node_id: String::new(),
            slot_start: 1,
            slot_end: 1,
            topology_peers: String::new(),
        };
        let args = migrate_keys_argv("redis-1", &p, &["a".into(), "b".into()]);
        assert!(args.iter().any(|a| a == "MIGRATE"));
        assert!(args.iter().any(|a| a == "10.0.0.9"));
        assert_eq!(args[args.len() - 2], "a");
        assert_eq!(args[args.len() - 1], "b");
    }

    #[test]
    fn parse_keys_splits_whitespace() {
        assert_eq!(
            parse_getkeysinslot_keys("k1\nk2 k3"),
            vec!["k1".to_string(), "k2".to_string(), "k3".to_string()]
        );
    }
}
