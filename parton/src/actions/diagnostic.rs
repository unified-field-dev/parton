//! Network reachability / latency diagnostics executed on the agent host.

use super::types::{ContainerActionRequest, ContainerActionResponse, DiagnosticMode};
use anyhow::Context;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

fn percentile_us(sorted: &[u128], p: f64) -> u128 {
    if sorted.is_empty() {
        return 0;
    }
    // Percentile index over a bounded sample count (<= 32); float rounding to an index is exact here.
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

/// TCP reachability / latency from this host (agent or local executor).
pub(super) fn run_diagnostic(
    request: &ContainerActionRequest,
) -> anyhow::Result<ContainerActionResponse> {
    let spec = request
        .diagnostic
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("diagnostic spec missing"))?;
    let host = spec.target_host.trim();
    if host.is_empty() {
        anyhow::bail!("diagnostic.target_host is empty");
    }
    let port = spec.port;
    crate::diagnostic_target_allowed_for_agent_probe(host, port)?;
    let addr_s = format!("{host}:{port}");
    let mut addrs = addr_s
        .to_socket_addrs()
        .with_context(|| format!("resolve diagnostic target {addr_s}"))?;
    let addr: SocketAddr = addrs
        .next()
        .ok_or_else(|| anyhow::anyhow!("no socket addr for {addr_s}"))?;
    let timeout = Duration::from_secs(5);

    match &spec.mode {
        DiagnosticMode::TcpProbe => {
            let start = Instant::now();
            TcpStream::connect_timeout(&addr, timeout)
                .with_context(|| format!("tcp connect to {addr_s}"))?;
            let us = start.elapsed().as_micros();
            Ok(ContainerActionResponse {
                action: request.action,
                container_ref: request.container_ref.clone(),
                success: true,
                message: "diagnostic tcp_probe ok".to_string(),
                payload: serde_json::json!({
                    "target": addr_s,
                    "latency_us": us,
                }),
            })
        }
        DiagnosticMode::Latency { samples } => {
            let n = (*samples).clamp(1, 32) as usize;
            let mut lat: Vec<u128> = Vec::with_capacity(n);
            for _ in 0..n {
                let start = Instant::now();
                let _ = TcpStream::connect_timeout(&addr, timeout)
                    .with_context(|| format!("tcp connect to {addr_s} (latency sampling)"))?;
                lat.push(start.elapsed().as_micros());
            }
            lat.sort_unstable();
            let p50 = percentile_us(&lat, 0.50);
            let p99 = percentile_us(&lat, 0.99);
            Ok(ContainerActionResponse {
                action: request.action,
                container_ref: request.container_ref.clone(),
                success: true,
                message: "diagnostic latency ok".to_string(),
                payload: serde_json::json!({
                    "target": addr_s,
                    "samples": n,
                    "p50_us": p50,
                    "p99_us": p99,
                }),
            })
        }
    }
}
