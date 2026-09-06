//! Native host hardware probe executed by the Parton agent process.

use super::types::{ContainerActionRequest, ContainerActionResponse};

pub(super) fn probe_host_response(request: &ContainerActionRequest) -> ContainerActionResponse {
    let parsed = serde_json::to_value(crate::host_info::collect_host_info())
        .unwrap_or_else(|_| serde_json::json!({}));
    ContainerActionResponse {
        action: request.action,
        container_ref: request.container_ref.clone(),
        success: true,
        message: "probe_host ok".to_string(),
        payload: serde_json::json!({ "host_info": parsed }),
    }
}
