use super::*;
use crate::actions::types::{TemplatedExecParams, TemplatedExecSpec};
use runner::CommandOutput;
use std::cell::RefCell;

struct ScriptedRunner {
    outputs: RefCell<Vec<CommandOutput>>,
    seen: RefCell<Vec<Vec<String>>>,
}

impl DockerCliRunner for ScriptedRunner {
    fn run(&self, args: &[String]) -> anyhow::Result<CommandOutput> {
        self.seen.borrow_mut().push(args.to_vec());
        let mut outs = self.outputs.borrow_mut();
        if outs.is_empty() {
            anyhow::bail!("no scripted outputs left");
        }
        Ok(outs.remove(0))
    }
}

fn request(template: TemplatedExecId, params: TemplatedExecParams) -> ContainerActionRequest {
    ContainerActionRequest {
        node_id: "n1".into(),
        container_ref: "pg-1".into(),
        action: ContainerActionKind::TemplatedExec,
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
        labels: std::collections::HashMap::default(),
        extra_hosts: vec![],
        network: None,
        diagnostic: None,
        wireguard_peer: None,
        grow_fs: None,
        templated_exec: Some(TemplatedExecSpec { template, params }),
        expected_container_id: None,
    }
}

#[test]
fn templated_exec_pg_promote_success() {
    let runner = ScriptedRunner {
        outputs: RefCell::new(vec![CommandOutput {
            status_success: true,
            stdout: "t".into(),
            stderr: String::new(),
        }]),
        seen: RefCell::new(vec![]),
    };
    let resp = run_templated_exec_with(
        &request(TemplatedExecId::PgPromote, TemplatedExecParams::default()),
        &runner,
    )
    .expect("ok");
    assert!(resp.success);
    assert_eq!(resp.message, "pg_promote ok");
    assert_eq!(resp.action.as_str(), "templated_exec");
}

#[test]
fn templated_exec_pg_promote_not_in_recovery_is_ok() {
    let runner = ScriptedRunner {
        outputs: RefCell::new(vec![CommandOutput {
            status_success: false,
            stdout: String::new(),
            stderr: "ERROR:  pg_promote: server is not in recovery".into(),
        }]),
        seen: RefCell::new(vec![]),
    };
    let resp = run_templated_exec_with(
        &request(TemplatedExecId::PgPromote, TemplatedExecParams::default()),
        &runner,
    )
    .expect("ok");
    assert!(resp.success);
    assert_eq!(resp.message, "pg_promote already_primary");
}

#[test]
fn templated_exec_pg_promote_hard_fail() {
    let runner = ScriptedRunner {
        outputs: RefCell::new(vec![CommandOutput {
            status_success: false,
            stdout: String::new(),
            stderr: "connection refused".into(),
        }]),
        seen: RefCell::new(vec![]),
    };
    let resp = run_templated_exec_with(
        &request(TemplatedExecId::PgPromote, TemplatedExecParams::default()),
        &runner,
    )
    .expect("response");
    assert!(!resp.success);
}

#[test]
fn templated_exec_redis_replicaof_no_one_success() {
    let runner = ScriptedRunner {
        outputs: RefCell::new(vec![CommandOutput {
            status_success: true,
            stdout: "OK".into(),
            stderr: String::new(),
        }]),
        seen: RefCell::new(vec![]),
    };
    let mut req = request(
        TemplatedExecId::RedisReplicaofNoOne,
        TemplatedExecParams::default(),
    );
    req.container_ref = "redis-1".into();
    let resp = run_templated_exec_with(&req, &runner).expect("ok");
    assert!(resp.success);
}

#[test]
fn templated_exec_redis_already_master_is_ok() {
    let runner = ScriptedRunner {
        outputs: RefCell::new(vec![CommandOutput {
            status_success: false,
            stdout: String::new(),
            stderr: "ERR already a master".into(),
        }]),
        seen: RefCell::new(vec![]),
    };
    let resp = run_templated_exec_with(
        &request(
            TemplatedExecId::RedisReplicaofNoOne,
            TemplatedExecParams::default(),
        ),
        &runner,
    )
    .expect("ok");
    assert!(resp.success);
    assert_eq!(resp.message, "replicaof already_master");
}

#[test]
fn templated_exec_spec_missing_errors() {
    let mut req = request(TemplatedExecId::PgPromote, TemplatedExecParams::default());
    req.templated_exec = None;
    let err = run_templated_exec_with(&req, &ProcessDockerCliRunner).expect_err("missing");
    assert!(err.to_string().contains("templated_exec spec is required"));
}

#[test]
fn templated_exec_params_reject_empty_primary_host() {
    let err = run_templated_exec_with(
        &request(
            TemplatedExecId::PgStandbyBootstrap,
            TemplatedExecParams::default(),
        ),
        &ProcessDockerCliRunner,
    )
    .expect_err("empty host");
    assert!(err.to_string().contains("primary_host_empty"));
}

#[test]
fn templated_exec_params_reject_shell_metachar_host() {
    let err = run_templated_exec_with(
        &request(
            TemplatedExecId::PgStandbyFollow,
            TemplatedExecParams {
                primary_host: "evil;rm".into(),
                primary_port: 5432,
                user: "nucleus".into(),
                ..Default::default()
            },
        ),
        &ProcessDockerCliRunner,
    )
    .expect_err("meta");
    assert!(err.to_string().contains("primary_host_invalid"));
}

#[test]
fn templated_exec_redis_replicaof_success() {
    let runner = ScriptedRunner {
        outputs: RefCell::new(vec![CommandOutput {
            status_success: true,
            stdout: "OK".into(),
            stderr: String::new(),
        }]),
        seen: RefCell::new(vec![]),
    };
    let resp = run_templated_exec_with(
        &request(
            TemplatedExecId::RedisReplicaof,
            TemplatedExecParams {
                primary_host: "10.0.0.5".into(),
                primary_port: 0, // → 6379
                ..Default::default()
            },
        ),
        &runner,
    )
    .expect("ok");
    assert!(resp.success);
    assert_eq!(resp.message, "replicaof ok");
    let seen = runner.seen.borrow();
    assert_eq!(
        &seen[0][2..],
        ["redis-cli", "REPLICAOF", "10.0.0.5", "6379"]
    );
}

#[test]
fn templated_exec_redis_replicaof_hard_fail() {
    let runner = ScriptedRunner {
        outputs: RefCell::new(vec![CommandOutput {
            status_success: false,
            stdout: String::new(),
            stderr: "ERR invalid".into(),
        }]),
        seen: RefCell::new(vec![]),
    };
    let resp = run_templated_exec_with(
        &request(
            TemplatedExecId::RedisReplicaof,
            TemplatedExecParams {
                primary_host: "10.0.0.5".into(),
                primary_port: 6379,
                ..Default::default()
            },
        ),
        &runner,
    )
    .expect("response");
    assert!(!resp.success);
    assert_eq!(resp.message, "replicaof failed");
}

#[test]
fn templated_exec_ch_rmt_bootstrap_hard_fail() {
    let runner = ScriptedRunner {
        outputs: RefCell::new(vec![CommandOutput {
            status_success: false,
            stdout: String::new(),
            stderr: "Code: 210. Connection refused".into(),
        }]),
        seen: RefCell::new(vec![]),
    };
    let resp = run_templated_exec_with(
        &request(
            TemplatedExecId::ChRmtBootstrap,
            TemplatedExecParams {
                primary_host: "10.0.0.11".into(),
                primary_port: 8123,
                ..Default::default()
            },
        ),
        &runner,
    )
    .expect("response");
    assert!(!resp.success);
    assert_eq!(resp.message, "ch_rmt_bootstrap failed");
}

#[test]
fn templated_exec_ch_rmt_follow_hard_fail() {
    let runner = ScriptedRunner {
        outputs: RefCell::new(vec![CommandOutput {
            status_success: false,
            stdout: String::new(),
            stderr: "Code: 210. Connection refused".into(),
        }]),
        seen: RefCell::new(vec![]),
    };
    let resp = run_templated_exec_with(
        &request(
            TemplatedExecId::ChRmtFollow,
            TemplatedExecParams {
                primary_host: "10.0.0.11".into(),
                primary_port: 8123,
                ..Default::default()
            },
        ),
        &runner,
    )
    .expect("response");
    assert!(!resp.success);
    assert_eq!(resp.message, "ch_rmt_follow failed");
}

#[test]
fn templated_exec_ch_rmt_bootstrap_params_reject_empty_host() {
    let err = run_templated_exec_with(
        &request(
            TemplatedExecId::ChRmtBootstrap,
            TemplatedExecParams::default(),
        ),
        &ProcessDockerCliRunner,
    )
    .expect_err("empty host");
    assert!(err.to_string().contains("primary_host_empty"));
}

#[test]
fn templated_exec_ch_rmt_bootstrap_params_reject_shell_metachar_host() {
    let err = run_templated_exec_with(
        &request(
            TemplatedExecId::ChRmtBootstrap,
            TemplatedExecParams {
                primary_host: "evil;rm".into(),
                primary_port: 8123,
                ..Default::default()
            },
        ),
        &ProcessDockerCliRunner,
    )
    .expect_err("meta");
    assert!(err.to_string().contains("primary_host_invalid"));
}

#[test]
fn templated_exec_redis_replicaof_params_reject_empty_host() {
    let err = run_templated_exec_with(
        &request(
            TemplatedExecId::RedisReplicaof,
            TemplatedExecParams::default(),
        ),
        &ProcessDockerCliRunner,
    )
    .expect_err("empty host");
    assert!(err.to_string().contains("primary_host_empty"));
}

#[test]
fn templated_exec_redis_cluster_meet_success() {
    let runner = ScriptedRunner {
        outputs: RefCell::new(vec![CommandOutput {
            status_success: true,
            stdout: "OK".into(),
            stderr: String::new(),
        }]),
        seen: RefCell::new(vec![]),
    };
    let resp = run_templated_exec_with(
        &request(
            TemplatedExecId::RedisClusterMeet,
            TemplatedExecParams {
                primary_host: "10.0.0.6".into(),
                primary_port: 6379,
                ..Default::default()
            },
        ),
        &runner,
    )
    .expect("ok");
    assert!(resp.success);
    assert_eq!(resp.message, "redis_cluster_meet ok");
}

#[test]
fn templated_exec_redis_cluster_replicate_rejects_empty_node_id() {
    let err = run_templated_exec_with(
        &request(
            TemplatedExecId::RedisClusterReplicate,
            TemplatedExecParams::default(),
        ),
        &ProcessDockerCliRunner,
    )
    .expect_err("empty node");
    assert!(err.to_string().contains("cluster_node_id_empty"));
}

#[test]
fn templated_exec_redis_cluster_slots_assign_success() {
    let runner = ScriptedRunner {
        outputs: RefCell::new(vec![CommandOutput {
            status_success: true,
            stdout: "OK".into(),
            stderr: String::new(),
        }]),
        seen: RefCell::new(vec![]),
    };
    let resp = run_templated_exec_with(
        &request(
            TemplatedExecId::RedisClusterSlotsAssign,
            TemplatedExecParams {
                slot_start: 0,
                slot_end: 2,
                ..Default::default()
            },
        ),
        &runner,
    )
    .expect("ok");
    assert!(resp.success);
    let seen = runner.seen.borrow();
    assert_eq!(
        &seen[0][2..],
        ["redis-cli", "CLUSTER", "ADDSLOTS", "0", "1", "2"]
    );
}

#[test]
fn templated_exec_redis_cluster_slots_reject_oversized_batch() {
    let err = run_templated_exec_with(
        &request(
            TemplatedExecId::RedisClusterSlotsAssign,
            TemplatedExecParams {
                slot_start: 0,
                slot_end: 100,
                ..Default::default()
            },
        ),
        &ProcessDockerCliRunner,
    )
    .expect_err("batch");
    assert!(err.to_string().contains("slot_range_invalid"));
}

#[test]
fn templated_exec_redis_replicaof_params_reject_shell_metachar_host() {
    let err = run_templated_exec_with(
        &request(
            TemplatedExecId::RedisReplicaof,
            TemplatedExecParams {
                primary_host: "evil;rm".into(),
                primary_port: 6379,
                ..Default::default()
            },
        ),
        &ProcessDockerCliRunner,
    )
    .expect_err("meta");
    assert!(err.to_string().contains("primary_host_invalid"));
}

#[test]
fn templated_exec_redis_cluster_meet_params_reject_empty_host() {
    let err = run_templated_exec_with(
        &request(
            TemplatedExecId::RedisClusterMeet,
            TemplatedExecParams::default(),
        ),
        &ProcessDockerCliRunner,
    )
    .expect_err("empty host");
    assert!(err.to_string().contains("primary_host_empty"));
}

#[test]
fn templated_exec_redis_cluster_meet_params_reject_shell_metachar_host() {
    let err = run_templated_exec_with(
        &request(
            TemplatedExecId::RedisClusterMeet,
            TemplatedExecParams {
                primary_host: "evil;rm".into(),
                primary_port: 6379,
                ..Default::default()
            },
        ),
        &ProcessDockerCliRunner,
    )
    .expect_err("meta");
    assert!(err.to_string().contains("primary_host_invalid"));
}

#[test]
fn templated_exec_redis_cluster_meet_hard_fail() {
    let runner = ScriptedRunner {
        outputs: RefCell::new(vec![CommandOutput {
            status_success: false,
            stdout: String::new(),
            stderr: "ERR meet failed".into(),
        }]),
        seen: RefCell::new(vec![]),
    };
    let resp = run_templated_exec_with(
        &request(
            TemplatedExecId::RedisClusterMeet,
            TemplatedExecParams {
                primary_host: "10.0.0.6".into(),
                primary_port: 6379,
                ..Default::default()
            },
        ),
        &runner,
    )
    .expect("response");
    assert!(!resp.success);
    assert_eq!(resp.message, "redis_cluster_meet failed");
}

#[test]
fn templated_exec_redis_cluster_replicate_success() {
    let runner = ScriptedRunner {
        outputs: RefCell::new(vec![CommandOutput {
            status_success: true,
            stdout: "OK".into(),
            stderr: String::new(),
        }]),
        seen: RefCell::new(vec![]),
    };
    let node_id = "a".repeat(40);
    let resp = run_templated_exec_with(
        &request(
            TemplatedExecId::RedisClusterReplicate,
            TemplatedExecParams {
                cluster_node_id: node_id.clone(),
                ..Default::default()
            },
        ),
        &runner,
    )
    .expect("ok");
    assert!(resp.success);
    assert_eq!(resp.message, "redis_cluster_replicate ok");
    let seen = runner.seen.borrow();
    assert_eq!(
        &seen[0][2..],
        ["redis-cli", "CLUSTER", "REPLICATE", node_id.as_str()]
    );
}

#[test]
fn templated_exec_redis_cluster_replicate_rejects_invalid_node_id() {
    let err = run_templated_exec_with(
        &request(
            TemplatedExecId::RedisClusterReplicate,
            TemplatedExecParams {
                cluster_node_id: "not-hex!".into(),
                ..Default::default()
            },
        ),
        &ProcessDockerCliRunner,
    )
    .expect_err("invalid node");
    assert!(err.to_string().contains("cluster_node_id_invalid"));
}

#[test]
fn templated_exec_redis_cluster_slots_reject_start_gt_end() {
    let err = run_templated_exec_with(
        &request(
            TemplatedExecId::RedisClusterSlotsAssign,
            TemplatedExecParams {
                slot_start: 10,
                slot_end: 5,
                ..Default::default()
            },
        ),
        &ProcessDockerCliRunner,
    )
    .expect_err("range");
    assert!(err.to_string().contains("slot_range_invalid"));
}

#[test]
fn templated_exec_redis_cluster_slots_reject_above_max() {
    let err = run_templated_exec_with(
        &request(
            TemplatedExecId::RedisClusterSlotsAssign,
            TemplatedExecParams {
                slot_start: 16_384,
                slot_end: 16_384,
                ..Default::default()
            },
        ),
        &ProcessDockerCliRunner,
    )
    .expect_err("max");
    assert!(err.to_string().contains("slot_range_invalid"));
}

#[test]
fn templated_exec_redis_cluster_migrate_success() {
    let runner = ScriptedRunner {
        outputs: RefCell::new(vec![CommandOutput {
            status_success: true,
            stdout: "OK".into(),
            stderr: String::new(),
        }]),
        seen: RefCell::new(vec![]),
    };
    let node_id = "b".repeat(40);
    let resp = run_templated_exec_with(
        &request(
            TemplatedExecId::RedisClusterMigrate,
            TemplatedExecParams {
                slot_start: 42,
                slot_end: 42,
                cluster_node_id: node_id.clone(),
                ..Default::default()
            },
        ),
        &runner,
    )
    .expect("ok");
    assert!(resp.success);
    assert_eq!(resp.message, "redis_cluster_migrate ok");
    let seen = runner.seen.borrow();
    assert_eq!(
        &seen[0][2..],
        [
            "redis-cli",
            "CLUSTER",
            "SETSLOT",
            "42",
            "NODE",
            node_id.as_str()
        ]
    );
}

#[test]
fn templated_exec_redis_cluster_migrate_hard_fail() {
    let runner = ScriptedRunner {
        outputs: RefCell::new(vec![CommandOutput {
            status_success: false,
            stdout: String::new(),
            stderr: "ERR migrate".into(),
        }]),
        seen: RefCell::new(vec![]),
    };
    let resp = run_templated_exec_with(
        &request(
            TemplatedExecId::RedisClusterMigrate,
            TemplatedExecParams {
                slot_start: 1,
                slot_end: 1,
                cluster_node_id: "c".repeat(40),
                ..Default::default()
            },
        ),
        &runner,
    )
    .expect("response");
    assert!(!resp.success);
    assert_eq!(resp.message, "redis_cluster_migrate failed");
}

#[test]
fn templated_exec_pg_standby_bootstrap_argv_and_success() {
    let runner = ScriptedRunner {
        outputs: RefCell::new(vec![
            CommandOutput {
                status_success: true,
                stdout: String::new(),
                stderr: String::new(),
            },
            CommandOutput {
                status_success: true,
                stdout: String::new(),
                stderr: String::new(),
            },
            CommandOutput {
                status_success: true,
                stdout: String::new(),
                stderr: String::new(),
            },
            CommandOutput {
                status_success: true,
                stdout: String::new(),
                stderr: String::new(),
            },
        ]),
        seen: RefCell::new(vec![]),
    };
    let params = TemplatedExecParams {
        primary_host: "10.0.0.5".into(),
        primary_port: 5432,
        user: "nucleus".into(),
        ..Default::default()
    };
    let resp = run_templated_exec_with(
        &request(TemplatedExecId::PgStandbyBootstrap, params),
        &runner,
    )
    .expect("ok");
    assert!(resp.success);
    assert!(runner
        .seen
        .borrow()
        .iter()
        .any(|a| a.iter().any(|x| x == "pg_basebackup")));
}

#[test]
fn templated_exec_pg_standby_bootstrap_runner_fail_is_not_success() {
    let runner = ScriptedRunner {
        outputs: RefCell::new(vec![
            CommandOutput {
                status_success: true,
                stdout: String::new(),
                stderr: String::new(),
            },
            CommandOutput {
                status_success: false,
                stdout: String::new(),
                stderr: "clear failed".into(),
            },
        ]),
        seen: RefCell::new(vec![]),
    };
    let params = TemplatedExecParams {
        primary_host: "10.0.0.5".into(),
        primary_port: 5432,
        user: "nucleus".into(),
        ..Default::default()
    };
    let resp = run_templated_exec_with(
        &request(TemplatedExecId::PgStandbyBootstrap, params),
        &runner,
    )
    .expect("response");
    assert!(!resp.success);
}

#[test]
fn templated_exec_pg_standby_follow_success() {
    let runner = ScriptedRunner {
        outputs: RefCell::new(vec![
            CommandOutput {
                status_success: true,
                stdout: String::new(),
                stderr: String::new(),
            },
            CommandOutput {
                status_success: true,
                stdout: String::new(),
                stderr: String::new(),
            },
            CommandOutput {
                status_success: true,
                stdout: String::new(),
                stderr: String::new(),
            },
        ]),
        seen: RefCell::new(vec![]),
    };
    let params = TemplatedExecParams {
        primary_host: "10.0.0.6".into(),
        primary_port: 5432,
        user: "nucleus".into(),
        ..Default::default()
    };
    let resp = run_templated_exec_with(&request(TemplatedExecId::PgStandbyFollow, params), &runner)
        .expect("ok");
    assert!(resp.success);
}

#[test]
fn templated_exec_pg_standby_follow_fail() {
    // stop (ignored) → rewind fail → clear fail → follow fails closed
    let runner = ScriptedRunner {
        outputs: RefCell::new(vec![
            CommandOutput {
                status_success: true,
                stdout: String::new(),
                stderr: String::new(),
            },
            CommandOutput {
                status_success: false,
                stdout: String::new(),
                stderr: "rewind failed".into(),
            },
            CommandOutput {
                status_success: false,
                stdout: String::new(),
                stderr: "clear failed".into(),
            },
        ]),
        seen: RefCell::new(vec![]),
    };
    let params = TemplatedExecParams {
        primary_host: "10.0.0.6".into(),
        primary_port: 5432,
        user: "nucleus".into(),
        ..Default::default()
    };
    let resp = run_templated_exec_with(&request(TemplatedExecId::PgStandbyFollow, params), &runner)
        .expect("response");
    assert!(!resp.success);
}

#[test]
fn templated_exec_redis_replicaof_no_one_hard_fail() {
    let runner = ScriptedRunner {
        outputs: RefCell::new(vec![CommandOutput {
            status_success: false,
            stdout: String::new(),
            stderr: "ERR unknown command".into(),
        }]),
        seen: RefCell::new(vec![]),
    };
    let resp = run_templated_exec_with(
        &request(
            TemplatedExecId::RedisReplicaofNoOne,
            TemplatedExecParams::default(),
        ),
        &runner,
    )
    .expect("response");
    assert!(!resp.success);
}

#[test]
fn templated_exec_redis_cluster_myid_success_payload() {
    let node_id = "a".repeat(40);
    let runner = ScriptedRunner {
        outputs: RefCell::new(vec![CommandOutput {
            status_success: true,
            stdout: node_id.clone(),
            stderr: String::new(),
        }]),
        seen: RefCell::new(vec![]),
    };
    let resp = run_templated_exec_with(
        &request(
            TemplatedExecId::RedisClusterMyId,
            TemplatedExecParams::default(),
        ),
        &runner,
    )
    .expect("ok");
    assert!(resp.success);
    assert_eq!(resp.message, "redis_cluster_myid ok");
    assert_eq!(
        resp.payload.get("cluster_node_id").and_then(|v| v.as_str()),
        Some(node_id.as_str())
    );
    let seen = runner.seen.borrow();
    assert!(seen[0].iter().any(|a| a == "MYID"));
}

#[test]
fn templated_exec_redis_cluster_myid_hard_fail() {
    let runner = ScriptedRunner {
        outputs: RefCell::new(vec![CommandOutput {
            status_success: false,
            stdout: String::new(),
            stderr: "ERR".into(),
        }]),
        seen: RefCell::new(vec![]),
    };
    let resp = run_templated_exec_with(
        &request(
            TemplatedExecId::RedisClusterMyId,
            TemplatedExecParams::default(),
        ),
        &runner,
    )
    .expect("resp");
    assert!(!resp.success);
    assert_eq!(resp.message, "redis_cluster_myid failed");
}

#[test]
fn templated_exec_redis_setslot_importing_success() {
    let runner = ScriptedRunner {
        outputs: RefCell::new(vec![CommandOutput {
            status_success: true,
            stdout: "OK".into(),
            stderr: String::new(),
        }]),
        seen: RefCell::new(vec![]),
    };
    let node_id = "c".repeat(40);
    let resp = run_templated_exec_with(
        &request(
            TemplatedExecId::RedisClusterSetslotImporting,
            TemplatedExecParams {
                slot_start: 3,
                slot_end: 3,
                cluster_node_id: node_id.clone(),
                ..Default::default()
            },
        ),
        &runner,
    )
    .expect("ok");
    assert!(resp.success);
    let seen = runner.seen.borrow();
    assert_eq!(
        &seen[0][2..],
        [
            "redis-cli",
            "CLUSTER",
            "SETSLOT",
            "3",
            "IMPORTING",
            node_id.as_str()
        ]
    );
}

#[test]
fn templated_exec_redis_setslot_migrating_hard_fail() {
    let runner = ScriptedRunner {
        outputs: RefCell::new(vec![CommandOutput {
            status_success: false,
            stdout: String::new(),
            stderr: "ERR".into(),
        }]),
        seen: RefCell::new(vec![]),
    };
    let resp = run_templated_exec_with(
        &request(
            TemplatedExecId::RedisClusterSetslotMigrating,
            TemplatedExecParams {
                slot_start: 1,
                slot_end: 1,
                cluster_node_id: "d".repeat(40),
                ..Default::default()
            },
        ),
        &runner,
    )
    .expect("resp");
    assert!(!resp.success);
    assert_eq!(resp.message, "redis_cluster_setslot_migrating failed");
}

#[test]
fn templated_exec_redis_migrate_slot_keys_empty_is_ok() {
    let runner = ScriptedRunner {
        outputs: RefCell::new(vec![CommandOutput {
            status_success: true,
            stdout: String::new(),
            stderr: String::new(),
        }]),
        seen: RefCell::new(vec![]),
    };
    let resp = run_templated_exec_with(
        &request(
            TemplatedExecId::RedisClusterMigrateSlotKeys,
            TemplatedExecParams {
                primary_host: "10.0.0.8".into(),
                primary_port: 6379,
                slot_start: 5,
                slot_end: 5,
                ..Default::default()
            },
        ),
        &runner,
    )
    .expect("ok");
    assert!(resp.success);
    assert_eq!(runner.seen.borrow().len(), 1);
}

#[test]
fn templated_exec_redis_migrate_slot_keys_with_keys() {
    let runner = ScriptedRunner {
        outputs: RefCell::new(vec![
            CommandOutput {
                status_success: true,
                stdout: "k1\nk2".into(),
                stderr: String::new(),
            },
            CommandOutput {
                status_success: true,
                stdout: "OK".into(),
                stderr: String::new(),
            },
        ]),
        seen: RefCell::new(vec![]),
    };
    let resp = run_templated_exec_with(
        &request(
            TemplatedExecId::RedisClusterMigrateSlotKeys,
            TemplatedExecParams {
                primary_host: "10.0.0.8".into(),
                primary_port: 6379,
                slot_start: 5,
                slot_end: 5,
                ..Default::default()
            },
        ),
        &runner,
    )
    .expect("ok");
    assert!(resp.success);
    let seen = runner.seen.borrow();
    assert_eq!(seen.len(), 2);
    assert!(seen[1].iter().any(|a| a == "MIGRATE"));
    assert!(seen[1].iter().any(|a| a == "k1"));
    assert!(seen[1].iter().any(|a| a == "k2"));
}

#[test]
fn templated_exec_redis_migrate_slot_keys_rejects_empty_host() {
    let err = run_templated_exec_with(
        &request(
            TemplatedExecId::RedisClusterMigrateSlotKeys,
            TemplatedExecParams {
                slot_start: 1,
                slot_end: 1,
                ..Default::default()
            },
        ),
        &ProcessDockerCliRunner,
    )
    .expect_err("host");
    assert!(err.to_string().contains("primary_host_empty"));
}

#[test]
fn templated_exec_pg_shard_bulk_copy_success() {
    let runner = ScriptedRunner {
        outputs: RefCell::new(vec![
            CommandOutput {
                status_success: true,
                stdout: "CREATE TABLE".into(),
                stderr: String::new(),
            },
            CommandOutput {
                status_success: true,
                stdout: "CREATE TABLE".into(),
                stderr: String::new(),
            },
            CommandOutput {
                status_success: true,
                stdout: String::new(),
                stderr: String::new(),
            },
            CommandOutput {
                status_success: true,
                stdout: "INSERT 0 1".into(),
                stderr: String::new(),
            },
        ]),
        seen: RefCell::new(vec![]),
    };
    let resp = run_templated_exec_with(
        &request(
            TemplatedExecId::PgShardBulkCopy,
            TemplatedExecParams {
                primary_host: "10.0.0.2".into(),
                primary_port: 5432,
                ..Default::default()
            },
        ),
        &runner,
    )
    .expect("ok");
    assert!(resp.success);
    assert_eq!(resp.message, "pg_shard_bulk_copy ok");
    // source CREATE → dest CREATE → pg_dump → apply
    assert_eq!(runner.seen.borrow().len(), 4);
    let seen = runner.seen.borrow();
    assert!(
        !seen[0].iter().any(|a| a == "-h"),
        "first step is local CREATE on source"
    );
    assert!(
        seen[1].iter().any(|a| a == "-h"),
        "second step is peer CREATE on dest"
    );
}

#[test]
fn templated_exec_pg_shard_bulk_copy_hard_fail() {
    let runner = ScriptedRunner {
        outputs: RefCell::new(vec![CommandOutput {
            status_success: false,
            stdout: String::new(),
            stderr: "connection refused".into(),
        }]),
        seen: RefCell::new(vec![]),
    };
    let resp = run_templated_exec_with(
        &request(
            TemplatedExecId::PgShardBulkCopy,
            TemplatedExecParams {
                primary_host: "10.0.0.2".into(),
                primary_port: 5432,
                ..Default::default()
            },
        ),
        &runner,
    )
    .expect("resp");
    assert!(!resp.success);
    assert_eq!(resp.message, "pg_shard_bulk_copy failed");
}

#[test]
fn templated_exec_pg_shard_bulk_copy_rejects_metachar_host() {
    let err = run_templated_exec_with(
        &request(
            TemplatedExecId::PgShardBulkCopy,
            TemplatedExecParams {
                primary_host: "evil;rm".into(),
                primary_port: 5432,
                ..Default::default()
            },
        ),
        &ProcessDockerCliRunner,
    )
    .expect_err("host");
    assert!(err.to_string().contains("primary_host_invalid"));
}
