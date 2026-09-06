//! Report body construction shared by every claimed-action code path.

use super::types::{ClaimedNodeActionBody, ReportRequestBody};
use crate::ContainerActionResponse;

pub(super) fn response_to_report_fields(
    res: &ContainerActionResponse,
) -> (String, String, serde_json::Value) {
    let stdout = res.message.clone();
    let stderr = String::new();
    (stdout, stderr, res.payload.clone())
}

/// Build a success [`ReportRequestBody`] with clipped stdout/stderr.
pub(super) fn success_report(
    claimed: &ClaimedNodeActionBody,
    agent_node_id: &str,
    stdout: &str,
    stderr: &str,
    payload: serde_json::Value,
) -> ReportRequestBody {
    ReportRequestBody {
        command_id: claimed.command_id.clone(),
        node_id: agent_node_id.to_string(),
        attempt: claimed.attempt,
        success: true,
        stdout: Some(clip_str(stdout, 8000)),
        stderr: Some(clip_str(stderr, 8000)),
        error_summary: Some(String::new()),
        payload_json: Some(payload),
    }
}

/// Build a failure [`ReportRequestBody`] from an execution error.
pub(super) fn error_report(
    claimed: &ClaimedNodeActionBody,
    agent_node_id: &str,
    error: &anyhow::Error,
) -> ReportRequestBody {
    ReportRequestBody {
        command_id: claimed.command_id.clone(),
        node_id: agent_node_id.to_string(),
        attempt: claimed.attempt,
        success: false,
        stdout: None,
        stderr: Some(clip_str(&error.to_string(), 8000)),
        error_summary: Some(clip_str(&error.to_string(), 2000)),
        payload_json: Some(serde_json::json!({})),
    }
}

pub(super) fn clip_str(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max.saturating_sub(8)])
    }
}
