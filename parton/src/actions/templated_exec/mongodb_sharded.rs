//! `MongoDB` sharded-cluster allowlisted `docker exec` argv builders.

use super::super::types::{TemplatedExecId, ValidatedTemplatedExecParams};

/// Fixed lab namespace.collection for [`TemplatedExecId::MongoMoveChunk`].
pub(crate) const LAB_MOVE_CHUNK_NS: &str = "nucleus_rebalance.nucleus_rebalance_lab";

/// Build argv for Mongo config RS / shardsvr / addShard / moveChunk (discrete tokens only).
///
/// Lab control plane uses `mongosh --eval` with fixed scripts from validated host/port/RS
/// name. No free-text shell. Collection name for moveChunk is a fixed literal.
#[must_use]
pub(crate) fn mongodb_sharded_templated_exec_argv(
    container_ref: &str,
    id: TemplatedExecId,
    params: &ValidatedTemplatedExecParams,
) -> Vec<String> {
    let eval = match id {
        TemplatedExecId::MongoConfigRsInitiate => {
            format!(
                "try {{ rs.status() }} catch (e) {{ rs.initiate({{_id:'{}',configsvr:true,members:[{{_id:0,host:'{}:{}'}}]}}) }}",
                params.user, params.primary_host, params.primary_port
            )
        }
        TemplatedExecId::MongoConfigRsAdd => {
            format!(
                "try {{ rs.add('{}:{}') }} catch (e) {{ if (String(e).includes('already a member') || String(e).includes('Found two member')) {{ }} else {{ throw e }} }}",
                params.primary_host, params.primary_port
            )
        }
        TemplatedExecId::MongoShardsvrEnable => {
            // Orchestrator recreates with --shardsvr; this confirms clusterRole before addShard.
            "(() => { const o = db.serverCmdLineOpts(); const role = (o.parsed && o.parsed.sharding && o.parsed.sharding.clusterRole) || ''; if (role !== 'shardsvr') { throw new Error('not_shardsvr'); } return role; })()"
                .to_string()
        }
        TemplatedExecId::MongoAddShard => {
            format!(
                "try {{ sh.addShard('{}/{}:{}') }} catch (e) {{ if (String(e).includes('already exists') || String(e).includes('host already used') || String(e).includes('is already a member')) {{ }} else {{ throw e }} }}",
                params.user, params.primary_host, params.primary_port
            )
        }
        TemplatedExecId::MongoMoveChunk => {
            let key = params.slot_start;
            format!(
                "(() => {{ const ns = '{LAB_MOVE_CHUNK_NS}'; const sk = NumberInt({key}); const prefer = '{}'; const shards = (db.adminCommand({{listShards:1}}).shards)||[]; if (shards.length < 2) {{ throw new Error('need_two_shards:'+shards.length) }} let dest = prefer; if (!shards.some(s => s._id === dest)) {{ dest = shards[shards.length-1]._id }} try {{ sh.enableSharding('nucleus_rebalance') }} catch (e) {{}} db.getSiblingDB('nucleus_rebalance').nucleus_rebalance_lab.createIndex({{ sk: 1 }}); try {{ sh.shardCollection(ns, {{ sk: 1 }}) }} catch (e) {{}} db.getSiblingDB('nucleus_rebalance').nucleus_rebalance_lab.updateOne({{ sk: sk }}, {{ $setOnInsert: {{ sk: sk }} }}, {{ upsert: true }}); try {{ sh.moveChunk(ns, {{ sk: sk }}, dest) }} catch (e) {{ if (String(e).includes('that chunk is already on shard') || String(e).includes('Chunk with the given bounds')) {{ }} else {{ throw e }} }} }})()",
                params.user
            )
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
    fn mongo_config_rs_initiate_argv_shape() {
        let args = mongodb_sharded_templated_exec_argv(
            "cfg-0",
            TemplatedExecId::MongoConfigRsInitiate,
            &params_host("10.0.0.1", 27017, "cfg-docs"),
        );
        assert_eq!(args[2], "mongosh");
        assert!(args[5].contains("rs.initiate"));
        assert!(args[5].contains("configsvr:true") || args[5].contains("configsvr: true"));
        assert!(args[5].contains("cfg-docs"));
        assert!(args[5].contains("10.0.0.1:27017"));
    }

    #[test]
    fn mongo_config_rs_add_argv_shape() {
        let args = mongodb_sharded_templated_exec_argv(
            "cfg-0",
            TemplatedExecId::MongoConfigRsAdd,
            &params_host("10.0.0.2", 27017, ""),
        );
        assert!(args[5].contains("rs.add"));
        assert!(args[5].contains("10.0.0.2:27017"));
    }

    #[test]
    fn mongo_shardsvr_enable_argv_shape() {
        let args = mongodb_sharded_templated_exec_argv(
            "mongo-0",
            TemplatedExecId::MongoShardsvrEnable,
            &params_host("", 0, ""),
        );
        assert_eq!(args[2], "mongosh");
        assert!(args[5].contains("shardsvr"));
        assert!(args[5].contains("serverCmdLineOpts"));
    }

    #[test]
    fn mongo_add_shard_argv_shape() {
        let args = mongodb_sharded_templated_exec_argv(
            "mongos-0",
            TemplatedExecId::MongoAddShard,
            &params_host("10.0.0.3", 27017, "rs-docs-s0"),
        );
        assert!(args[5].contains("sh.addShard"));
        assert!(args[5].contains("rs-docs-s0/10.0.0.3:27017"));
    }

    #[test]
    fn mongo_move_chunk_argv_shape() {
        let mut p = params_host("", 0, "rs-docs-s1");
        p.slot_start = 1;
        let args =
            mongodb_sharded_templated_exec_argv("mongos-0", TemplatedExecId::MongoMoveChunk, &p);
        assert!(args[5].contains("sh.moveChunk"));
        assert!(args[5].contains(LAB_MOVE_CHUNK_NS));
        assert!(args[5].contains("rs-docs-s1"));
        assert!(args[5].contains("NumberInt(1)"));
    }
}
