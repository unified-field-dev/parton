//! `health_check` queue action: outbound HTTP GET plus body assertions.

use super::report::clip_str;
use super::types::{ClaimedNodeActionBody, ReportRequestBody};
use anyhow::Context;
use serde_json::Value;

fn json_path_get<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cur = root;
    for seg in path.split('.') {
        if seg.is_empty() {
            continue;
        }
        cur = cur.get(seg)?;
    }
    Some(cur)
}

/// When `per_logical` is an object, require every entry's `state` field to be `"ok"`.
fn per_logical_all_state_ok(root: &Value) -> bool {
    let Some(obj) = root.get("per_logical").and_then(|v| v.as_object()) else {
        return false;
    };
    for (_k, entry) in obj {
        let st = entry.get("state").and_then(|s| s.as_str());
        if st != Some("ok") {
            return false;
        }
    }
    true
}

/// Validate the JSON body of a `health_check` response against the configured assertions.
///
/// Returns `(body_ok, body_detail)`; `body_detail` is empty when everything passes.
fn evaluate_health_body(
    payload: &Value,
    parsed: Option<&Value>,
    status_ok: bool,
) -> anyhow::Result<(bool, String)> {
    let mut body_ok = true;
    let mut body_detail = String::new();

    if payload.get("require_mode_remote").and_then(Value::as_bool) == Some(true) {
        if let Some(v) = parsed {
            let mode = v.get("mode").and_then(|m| m.as_str());
            if mode == Some("embedded_aliased_as_tikv") {
                body_ok = false;
                body_detail =
                    "require_mode_remote: db-ready mode=embedded_aliased_as_tikv (not on TiKV)"
                        .to_string();
            } else if status_ok && mode != Some("remote") {
                body_ok = false;
                body_detail = format!("require_mode_remote: expected mode=remote, got {mode:?}");
            }
        } else if status_ok {
            body_ok = false;
            body_detail = "require_mode_remote: response body is not JSON".to_string();
        }
    }

    if !status_ok {
        return Ok((body_ok, body_detail));
    }

    if payload
        .get("require_all_per_logical_state_ok")
        .and_then(Value::as_bool)
        == Some(true)
    {
        if let Some(v) = parsed {
            if !per_logical_all_state_ok(v) {
                body_ok = false;
                body_detail = "per_logical entries missing state=ok".to_string();
            }
        } else {
            body_ok = false;
            body_detail = "invalid JSON body (per_logical check)".to_string();
        }
    }

    if let Some(arr) = payload
        .get("body_json_assertions")
        .and_then(|v| v.as_array())
    {
        if let Some(root) = parsed {
            for a in arr {
                let path = a
                    .get("path")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("body_json_assertions entry missing path"))?;
                let expected = a
                    .get("equals")
                    .ok_or_else(|| anyhow::anyhow!("body_json_assertions entry missing equals"))?;
                let got = json_path_get(root, path);
                if got != Some(expected) {
                    body_ok = false;
                    body_detail =
                        format!("assertion failed path={path} expected={expected} got={got:?}");
                    break;
                }
            }
        } else {
            body_ok = false;
            body_detail = "invalid JSON for assertions".to_string();
        }
    }

    Ok((body_ok, body_detail))
}

pub(super) async fn run_health_check(
    claimed: &ClaimedNodeActionBody,
    agent_node_id: &str,
) -> anyhow::Result<ReportRequestBody> {
    let url = claimed
        .payload_json
        .get("url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("health_check missing url"))?;
    crate::url_allowed_for_agent_fetch(url)?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_mins(1))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("build HTTP client for health_check request")?;
    let resp = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("GET {url} (health_check)"))?;
    let status = resp.status();
    let status_ok = status.is_success();
    let txt = resp.text().await.unwrap_or_default();
    let parsed: Option<Value> = serde_json::from_str(&txt).ok();
    let (body_ok, body_detail) =
        evaluate_health_body(&claimed.payload_json, parsed.as_ref(), status_ok)?;
    let ok = status_ok && body_ok;

    let stdout = if ok {
        format!("HTTP {status}")
    } else {
        String::new()
    };
    let stderr = if ok {
        body_detail.clone()
    } else {
        let mut s = clip_str(&txt, 8000);
        if !body_detail.is_empty() {
            if !s.is_empty() {
                s.push_str(" | ");
            }
            s.push_str(&body_detail);
        }
        s
    };
    let error_summary = if ok {
        String::new()
    } else {
        let suffix = if body_detail.is_empty() {
            ""
        } else {
            body_detail.as_str()
        };
        format!("health_check HTTP {status} {suffix}")
    };
    Ok(ReportRequestBody {
        command_id: claimed.command_id.clone(),
        node_id: agent_node_id.to_string(),
        attempt: claimed.attempt,
        success: ok,
        stdout: Some(stdout),
        stderr: Some(stderr),
        error_summary: Some(error_summary),
        payload_json: Some(serde_json::json!({
            "http_status": status.as_u16(),
            "body_ok": body_ok,
        })),
    })
}
