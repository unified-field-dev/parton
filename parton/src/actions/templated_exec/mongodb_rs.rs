//! `MongoDB` replica-set allowlisted `docker exec` argv builders.

use super::super::types::{TemplatedExecId, ValidatedTemplatedExecParams};

/// Build argv for Mongo RS initiate / add / stepDown (discrete tokens only).
///
/// Lab control plane uses `mongosh --eval` with fixed scripts built from
/// validated host/port/replica-set name (`user` on initiate). No free-text shell.
#[must_use]
pub(crate) fn mongodb_templated_exec_argv(
    container_ref: &str,
    id: TemplatedExecId,
    params: &ValidatedTemplatedExecParams,
) -> Vec<String> {
    let eval = match id {
        TemplatedExecId::MongoRsInitiate => {
            // Idempotent: if rs.status() works, already initiated.
            format!(
                "try {{ rs.status() }} catch (e) {{ rs.initiate({{_id:'{}',members:[{{_id:0,host:'{}:{}'}}]}}) }}",
                params.user, params.primary_host, params.primary_port
            )
        }
        TemplatedExecId::MongoRsAdd => {
            format!(
                "try {{ rs.add('{}:{}') }} catch (e) {{ if (String(e).includes('already a member') || String(e).includes('Found two member')) {{ }} else {{ throw e }} }}",
                params.primary_host, params.primary_port
            )
        }
        TemplatedExecId::MongoRsStepDown => {
            "try { rs.stepDown() } catch (e) { if (String(e).includes('not currently a primary') || String(e).includes('not primary')) { } else { throw e } }"
                .to_string()
        }
        _ => return Vec::new(),
    };
    vec![
        "exec".into(),
        container_ref.to_string(),
        "mongosh".into(),
        "--quiet".into(),
        "--eval".into(),
        eval,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::types::ValidatedTemplatedExecParams;

    fn params_host(host: &str, port: u16, rs_name: &str) -> ValidatedTemplatedExecParams {
        ValidatedTemplatedExecParams {
            primary_host: host.into(),
            primary_port: port,
            user: rs_name.into(),
            cluster_node_id: String::new(),
            slot_start: 0,
            slot_end: 0,
            topology_peers: String::new(),
        }
    }

    #[test]
    fn mongo_rs_initiate_argv_shape() {
        let args = mongodb_templated_exec_argv(
            "mongo-0",
            TemplatedExecId::MongoRsInitiate,
            &params_host("10.0.0.1", 27017, "rs-docs"),
        );
        assert_eq!(args[0], "exec");
        assert_eq!(args[1], "mongo-0");
        assert_eq!(args[2], "mongosh");
        assert_eq!(args[3], "--quiet");
        assert_eq!(args[4], "--eval");
        assert!(args[5].contains("rs.initiate"));
        assert!(args[5].contains("rs-docs"));
        assert!(args[5].contains("10.0.0.1:27017"));
        assert!(!args[5].contains(';') || args[5].contains("try"));
    }

    #[test]
    fn mongo_rs_add_argv_shape() {
        let args = mongodb_templated_exec_argv(
            "mongo-0",
            TemplatedExecId::MongoRsAdd,
            &params_host("10.0.0.2", 27017, ""),
        );
        assert_eq!(args[2], "mongosh");
        assert!(args[5].contains("rs.add"));
        assert!(args[5].contains("10.0.0.2:27017"));
    }

    #[test]
    fn mongo_rs_step_down_argv_shape() {
        let args = mongodb_templated_exec_argv(
            "mongo-0",
            TemplatedExecId::MongoRsStepDown,
            &params_host("", 0, ""),
        );
        assert_eq!(args[2], "mongosh");
        assert!(args[5].contains("rs.stepDown"));
    }
}
