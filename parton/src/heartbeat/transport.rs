//! POST a heartbeat report to the control-plane ingest endpoint.

use super::types::{HeartbeatResponse, NodeHeartbeatReport};
use anyhow::Context;

pub(super) fn parse_heartbeat_response_body(body: &str) -> HeartbeatResponse {
    let trimmed = body.trim();
    if trimmed.is_empty() || trimmed == "ok" || trimmed == "\"ok\"" {
        return HeartbeatResponse {
            acknowledged_at: chrono::Utc::now(),
            directives: Vec::new(),
        };
    }
    match serde_json::from_str::<HeartbeatResponse>(trimmed) {
        Ok(r) => r,
        Err(_) => HeartbeatResponse {
            acknowledged_at: chrono::Utc::now(),
            directives: Vec::new(),
        },
    }
}

/// Send a heartbeat payload to the configured control-plane endpoint.
///
/// On HTTP success, parses a [`HeartbeatResponse`] (forward-compatible with legacy `"ok"` bodies).
///
/// # Errors
///
/// Returns an error when the request cannot be sent or the control plane responds with a
/// non-success HTTP status.
#[tracing::instrument(skip(report, token), fields(node_id = %report.node_id, cell_id = %report.cell_id))]
pub async fn send_heartbeat(
    endpoint: &str,
    report: &NodeHeartbeatReport,
    token: Option<&str>,
) -> anyhow::Result<HeartbeatResponse> {
    let started = std::time::Instant::now();
    let result = send_heartbeat_inner(endpoint, report, token).await;
    crate::agent_metrics::record_heartbeat(result.is_ok(), started.elapsed());
    result
}

async fn send_heartbeat_inner(
    endpoint: &str,
    report: &NodeHeartbeatReport,
    token: Option<&str>,
) -> anyhow::Result<HeartbeatResponse> {
    let client = reqwest::Client::new();
    let mut request = client
        .post(endpoint)
        .header("x-parton-node-id", report.node_id.as_str())
        .json(report);
    request = crate::spiffe_client::apply_agent_auth_headers(request, token)?;

    let response = request
        .send()
        .await
        .with_context(|| format!("POST heartbeat to {endpoint}"))?;
    if response.status().is_success() {
        let body = response.text().await.unwrap_or_default();
        return Ok(parse_heartbeat_response_body(&body));
    }

    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    anyhow::bail!("heartbeat POST failed ({status}): {body}");
}
