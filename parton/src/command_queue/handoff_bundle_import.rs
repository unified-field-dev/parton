//! `handoff_bundle_import` queue action: decode a base64 bundle and POST it to the import endpoint.

use super::report::clip_str;
use super::types::{ClaimedNodeActionBody, ReportRequestBody};
use anyhow::Context;
use base64::Engine;

pub(super) async fn run_handoff_bundle_import(
    claimed: &ClaimedNodeActionBody,
    agent_node_id: &str,
) -> anyhow::Result<ReportRequestBody> {
    let url = claimed
        .payload_json
        .get("url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("handoff_bundle_import missing url"))?;
    let auth = claimed
        .payload_json
        .get("authorization_bearer")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("handoff_bundle_import missing authorization_bearer"))?;
    let b64 = claimed
        .payload_json
        .get("bundle_base64")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("handoff_bundle_import missing bundle_base64"))?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|e| anyhow::anyhow!("bundle_base64 decode: {e}"))?;
    crate::url_allowed_for_agent_fetch(url)?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_mins(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("build HTTP client for handoff_bundle_import request")?;
    let resp = client
        .post(url)
        .header("Authorization", auth)
        .body(bytes)
        .send()
        .await
        .with_context(|| format!("POST {url} (handoff_bundle_import)"))?;
    let status = resp.status();
    let ok = status.is_success();
    let txt = resp.text().await.unwrap_or_default();
    Ok(ReportRequestBody {
        command_id: claimed.command_id.clone(),
        node_id: agent_node_id.to_string(),
        attempt: claimed.attempt,
        success: ok,
        stdout: Some(if ok {
            format!("import HTTP {status}")
        } else {
            String::new()
        }),
        stderr: Some(if ok {
            String::new()
        } else {
            clip_str(&txt, 8000)
        }),
        error_summary: Some(if ok {
            String::new()
        } else {
            format!("handoff_bundle_import HTTP {status}")
        }),
        payload_json: Some(serde_json::json!({ "http_status": status.as_u16() })),
    })
}
