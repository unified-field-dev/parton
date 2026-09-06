//! HTTP client calls against the control-plane node action queue endpoints.

use super::types::{ClaimedNodeActionBody, ReportRequestBody};
use anyhow::Context;
use serde::Serialize;

/// Strip `/heartbeat` from the configured ingest URL to get `/api/parton`.
pub fn derive_agent_api_base_url(heartbeat_endpoint: &str) -> String {
    let e = heartbeat_endpoint.trim_end_matches('/');
    if let Some(prefix) = e.strip_suffix("/heartbeat") {
        prefix.to_string()
    } else {
        e.to_string()
    }
}

#[derive(Debug, Serialize)]
struct ClaimRequestBody {
    node_id: String,
    lease_duration_secs: Option<u64>,
}

/// POST claim; returns `Ok(None)` on HTTP 204.
///
/// # Errors
///
/// Returns an error when the HTTP client cannot be built, the request fails, the control
/// plane responds with a non-success status, or the claim body cannot be deserialized.
pub async fn post_claim_action(
    agent_api_base: &str,
    node_id: &str,
    lease_duration_secs: Option<u64>,
    token: Option<&str>,
) -> anyhow::Result<Option<ClaimedNodeActionBody>> {
    let url = format!("{}/actions/claim", agent_api_base.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_mins(2))
        .build()
        .context("build HTTP client for claim request")?;
    let mut req = client
        .post(&url)
        .header("x-parton-node-id", node_id)
        .json(&ClaimRequestBody {
            node_id: node_id.to_string(),
            lease_duration_secs,
        });
    req = crate::spiffe_client::apply_agent_auth_headers(req, token)?;
    let resp = req.send().await.with_context(|| format!("POST {url}"))?;
    if resp.status() == reqwest::StatusCode::NO_CONTENT {
        crate::agent_metrics::record_action_claimed("empty");
        return Ok(None);
    }
    if !resp.status().is_success() {
        let status = resp.status();
        let txt = resp.text().await.unwrap_or_default();
        crate::agent_metrics::record_action_claimed("error");
        anyhow::bail!("claim HTTP {status}: {txt}");
    }
    let claimed = resp
        .json()
        .await
        .with_context(|| format!("parse claim response body from {url}"))?;
    crate::agent_metrics::record_action_claimed("claimed");
    Ok(Some(claimed))
}

#[derive(Debug, Serialize)]
struct ExtendLeaseRequestBody {
    command_id: String,
    node_id: String,
    additional_secs: Option<u64>,
}

/// Ask the control plane to extend the lease for a long-running action (deploy, import, …).
///
/// # Errors
///
/// Returns an error when the HTTP client cannot be built, the request fails, or the control
/// plane responds with a non-success status.
pub async fn post_extend_action_lease(
    agent_api_base: &str,
    command_id: &str,
    node_id: &str,
    additional_secs: Option<u64>,
    token: Option<&str>,
) -> anyhow::Result<()> {
    let url = format!(
        "{}/actions/extend-lease",
        agent_api_base.trim_end_matches('/')
    );
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_mins(1))
        .build()
        .context("build HTTP client for extend-lease request")?;
    let mut req =
        client
            .post(&url)
            .header("x-parton-node-id", node_id)
            .json(&ExtendLeaseRequestBody {
                command_id: command_id.to_string(),
                node_id: node_id.to_string(),
                additional_secs,
            });
    req = crate::spiffe_client::apply_agent_auth_headers(req, token)?;
    let resp = req.send().await.with_context(|| format!("POST {url}"))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let txt = resp.text().await.unwrap_or_default();
        anyhow::bail!("extend-lease HTTP {status}: {txt}");
    }
    Ok(())
}

/// POST an action result back to the control-plane queue.
///
/// # Errors
///
/// Returns an error when the HTTP client cannot be built, the request fails, or the control
/// plane responds with a non-success status.
pub async fn post_action_result(
    agent_api_base: &str,
    body: ReportRequestBody,
    token: Option<&str>,
) -> anyhow::Result<()> {
    let url = format!("{}/actions/result", agent_api_base.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_mins(2))
        .build()
        .context("build HTTP client for action result request")?;
    let mut req = client
        .post(&url)
        .header("x-parton-node-id", body.node_id.as_str())
        .json(&body);
    req = crate::spiffe_client::apply_agent_auth_headers(req, token)?;
    let resp = req.send().await.with_context(|| format!("POST {url}"))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let txt = resp.text().await.unwrap_or_default();
        anyhow::bail!("result HTTP {status}: {txt}");
    }
    Ok(())
}
