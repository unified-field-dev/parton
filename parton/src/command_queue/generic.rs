//! Generic Docker / agent-local queue actions: deserialize the payload straight into a
//! [`crate::ContainerActionRequest`] and dispatch through the executor.

use super::report::{error_report, response_to_report_fields, success_report};
use super::types::{ClaimedNodeActionBody, ReportRequestBody};
use crate::{execute_container_action, ContainerActionExecutor, ContainerActionRequest};

pub(super) fn run_generic_container_action<E: ContainerActionExecutor>(
    executor: &E,
    claimed: &ClaimedNodeActionBody,
    agent_node_id: &str,
) -> ReportRequestBody {
    let req: ContainerActionRequest = match serde_json::from_value(claimed.payload_json.clone()) {
        Ok(r) => r,
        Err(e) => {
            let mut report = error_report(claimed, agent_node_id, &anyhow::anyhow!(e));
            report.error_summary = Some("invalid ContainerActionRequest payload".to_string());
            return report;
        }
    };
    // Same node-scoping guard as the deploy_handoff / teardown_handoff payloads: a claimed
    // command must never be executed on behalf of a different node_id than this agent.
    if req.node_id != agent_node_id {
        let err = anyhow::anyhow!(
            "container action node_id mismatch (payload {}, agent {})",
            req.node_id,
            agent_node_id
        );
        let mut report = error_report(claimed, agent_node_id, &err);
        report.error_summary = Some("container action node_id mismatch".to_string());
        return report;
    }
    match execute_container_action(executor, &req) {
        Ok(res) => {
            let (stdout, stderr, payload) = response_to_report_fields(&res);
            success_report(claimed, agent_node_id, &stdout, &stderr, payload)
        }
        Err(e) => error_report(claimed, agent_node_id, &e),
    }
}
