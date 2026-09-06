//! Multi-step Postgres standby bootstrap / follow sequences.

use super::super::types::{TemplatedExecId, ValidatedTemplatedExecParams};
use super::registry::{
    classify_promote_outcome, clear_pgdata_argv, docker_start_argv, docker_stop_argv,
    pg_basebackup_argv, pg_rewind_argv,
};
use super::runner::{CommandOutput, DockerCliRunner};

/// Stop → clear PGDATA → `pg_basebackup -R` → start.
pub(crate) fn run_standby_bootstrap(
    container_ref: &str,
    params: &ValidatedTemplatedExecParams,
    runner: &dyn DockerCliRunner,
) -> anyhow::Result<(bool, &'static str, CommandOutput)> {
    let stop = runner.run(&docker_stop_argv(container_ref))?;
    // Stop may fail if already stopped — continue.
    let _ = stop;
    let clear = runner.run(&clear_pgdata_argv(container_ref))?;
    if !clear.status_success {
        return Ok((false, "pg_standby_bootstrap failed", clear));
    }
    let backup = runner.run(&pg_basebackup_argv(container_ref, params))?;
    if !backup.status_success {
        return Ok((false, "pg_standby_bootstrap failed", backup));
    }
    let start = runner.run(&docker_start_argv(container_ref))?;
    let (ok, msg) = classify_promote_outcome(
        TemplatedExecId::PgStandbyBootstrap,
        start.status_success,
        &start.combined(),
    );
    Ok((ok && backup.status_success, msg, start))
}

/// Stop → try `pg_rewind` → on failure wipe+basebackup → start.
pub(crate) fn run_standby_follow(
    container_ref: &str,
    params: &ValidatedTemplatedExecParams,
    runner: &dyn DockerCliRunner,
) -> anyhow::Result<(bool, &'static str, CommandOutput)> {
    let _ = runner.run(&docker_stop_argv(container_ref))?;
    let rewind = runner.run(&pg_rewind_argv(container_ref, params))?;
    if !rewind.status_success {
        let clear = runner.run(&clear_pgdata_argv(container_ref))?;
        if !clear.status_success {
            return Ok((false, "pg_standby_follow failed", clear));
        }
        let backup = runner.run(&pg_basebackup_argv(container_ref, params))?;
        if !backup.status_success {
            return Ok((false, "pg_standby_follow failed", backup));
        }
    }
    let start = runner.run(&docker_start_argv(container_ref))?;
    let (ok, msg) = classify_promote_outcome(
        TemplatedExecId::PgStandbyFollow,
        start.status_success,
        &start.combined(),
    );
    Ok((ok, msg, start))
}
