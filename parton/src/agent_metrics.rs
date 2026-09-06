//! Prometheus metrics surface (via the [`metrics`] crate) for the Parton agent.
//!
//! Recording happens unconditionally at the library entry points ([`crate::send_heartbeat`],
//! [`crate::post_claim_action`], [`crate::execute_claimed_node_action`]); it's a safe no-op until
//! a recorder is installed, so embedders that don't care about metrics pay only the cost of an
//! atomic load per call.
//!
//! [`maybe_install_prometheus_exporter_from_env`] is what the `parton` binary uses to opt into a
//! scrape endpoint (see `main.rs`); it's exposed here so other embedders of this crate can reuse
//! it instead of the whole binary.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Context;

/// Records one heartbeat send attempt.
///
/// Emits `parton_heartbeat_total{outcome="ok"|"fail"}` and `parton_heartbeat_roundtrip_ms`.
pub fn record_heartbeat(ok: bool, elapsed: Duration) {
    let outcome = if ok { "ok" } else { "fail" };
    metrics::counter!("parton_heartbeat_total", "outcome" => outcome).increment(1);
    metrics::histogram!("parton_heartbeat_roundtrip_ms").record(duration_ms(elapsed));
}

/// Records one node-action claim attempt.
///
/// Emits `parton_action_claimed_total{result="claimed"|"empty"|"error"}`.
pub fn record_action_claimed(result: &'static str) {
    metrics::counter!("parton_action_claimed_total", "result" => result).increment(1);
}

/// Records one node-action execution outcome and duration.
///
/// Emits `parton_action_result_total{success="true"|"false"}` and
/// `parton_action_execute_ms{action_kind=...}`.
pub fn record_action_result(action_kind: &str, success: bool, elapsed: Duration) {
    metrics::counter!(
        "parton_action_result_total",
        "success" => if success { "true" } else { "false" }
    )
    .increment(1);
    metrics::histogram!("parton_action_execute_ms", "action_kind" => action_kind.to_string())
        .record(duration_ms(elapsed));
}

fn duration_ms(elapsed: Duration) -> f64 {
    elapsed.as_secs_f64() * 1000.0
}

/// Installs a Prometheus scrape HTTP listener when `PARTON_METRICS_BIND` is set; a no-op
/// otherwise (default OFF — see the crate README).
///
/// Must be called from within a Tokio runtime (the exporter's HTTP server is spawned onto it).
///
/// # Errors
///
/// Returns an error when `PARTON_METRICS_BIND` is set but is not a valid socket address, or when
/// the exporter cannot be built/installed (for example the address is already in use).
pub fn maybe_install_prometheus_exporter_from_env() -> anyhow::Result<Option<SocketAddr>> {
    let Some(bind) = std::env::var("PARTON_METRICS_BIND")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
    else {
        return Ok(None);
    };
    let addr: SocketAddr = bind
        .parse()
        .with_context(|| format!("invalid PARTON_METRICS_BIND `{bind}`"))?;
    metrics_exporter_prometheus::PrometheusBuilder::new()
        .with_http_listener(addr)
        .install()
        .with_context(|| format!("install prometheus exporter on {addr}"))?;
    Ok(Some(addr))
}
