//! SSRF guardrails for agent-initiated outbound requests (`health_check`, `handoff_bundle_import`,
//! `diagnostic`).
//!
//! The control plane can hand an agent a URL or `target_host:port` sourced from queued action
//! payloads. Without a check here, a compromised or overly-trusting control plane (or a
//! malicious queued payload) could direct the agent to fetch the cloud provider's instance
//! metadata endpoint (`169.254.169.254`) or other link-local-only services reachable from the
//! agent host, and relay the response back through the action result.

use std::net::{IpAddr, Ipv6Addr, ToSocketAddrs};

/// Typed failure reasons for the SSRF guard checks in this module.
///
/// Every public guard function ([`check_ip_allowed_for_agent_fetch`],
/// [`diagnostic_target_allowed_for_agent_probe`], [`url_allowed_for_agent_fetch`]) returns this
/// type directly so callers can match on *why* a target was rejected (for example to
/// distinguish a blocked metadata address from a plain DNS resolution failure) instead of
/// string-matching an opaque [`anyhow::Error`]. Because this type implements
/// [`std::error::Error`], it converts into `anyhow::Error` automatically via `?` at any call
/// site that still returns `anyhow::Result`.
#[derive(Debug, thiserror::Error)]
pub enum SsrfError {
    /// `ip` is link-local, unspecified, or an IPv6 unique-local link-local equivalent (this
    /// range includes the cloud metadata address `169.254.169.254`).
    #[error(
        "target IP {ip} is link-local/unspecified (this range includes the cloud metadata \
         address 169.254.169.254); refusing to fetch"
    )]
    AlwaysBlocked {
        /// The rejected IP address.
        ip: IpAddr,
    },
    /// `ip` is a private-network address and `PARTON_BLOCK_PRIVATE_NETWORK_FETCH=1` opted into
    /// rejecting it.
    #[error(
        "target IP {ip} is a private-network address and {ALLOW_PRIVATE_NETWORK_ENV}=1 is set; refusing to fetch"
    )]
    PrivateNetworkBlocked {
        /// The rejected IP address.
        ip: IpAddr,
    },
    /// The target host string was empty.
    #[error("target host is empty")]
    EmptyHost,
    /// The target host did not resolve to any address.
    #[error("host `{host}` did not resolve to any address")]
    NoAddresses {
        /// The host that failed to resolve.
        host: String,
    },
    /// DNS resolution of the target host failed outright.
    #[error("failed to resolve host `{host}`: {source}")]
    ResolveFailed {
        /// The host that failed to resolve.
        host: String,
        /// Underlying I/O error from [`ToSocketAddrs`].
        #[source]
        source: std::io::Error,
    },
    /// `raw_url` could not be parsed as a URL.
    #[error("invalid URL `{raw_url}`: {message}")]
    InvalidUrl {
        /// The raw URL string that failed to parse.
        raw_url: String,
        /// Underlying `url` crate parse error, rendered to a message (the `url` crate is only
        /// a transitive dependency here via `reqwest`, so its error type isn't named directly).
        message: String,
    },
    /// The URL scheme is not `http`/`https` (for example `file://`, `gopher://`).
    #[error("unsupported URL scheme `{scheme}` for agent fetch (only http/https allowed)")]
    UnsupportedScheme {
        /// The rejected scheme.
        scheme: String,
    },
    /// The URL has no host component.
    #[error("URL `{raw_url}` has no host")]
    NoHost {
        /// The raw URL string with no host.
        raw_url: String,
    },
}

/// Env var: set to `1` / `true` / `yes` / `on` to additionally reject RFC1918 / RFC4193 private
/// network targets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`). Off by default
/// because `health_check` / `diagnostic` commonly target other hosts on the same private LAN.
const ALLOW_PRIVATE_NETWORK_ENV: &str = "PARTON_BLOCK_PRIVATE_NETWORK_FETCH";

fn block_private_networks() -> bool {
    std::env::var(ALLOW_PRIVATE_NETWORK_ENV).is_ok_and(|v| {
        matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

fn is_ipv6_unique_local(v6: Ipv6Addr) -> bool {
    (v6.segments()[0] & 0xfe00) == 0xfc00
}

/// Always-blocked SSRF targets: link-local (covers the `169.254.169.254` cloud metadata
/// address), unspecified, and IPv6 unique-local link-local equivalents.
fn is_always_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_link_local() || v4.is_unspecified(),
        IpAddr::V6(v6) => v6.is_unspecified() || (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

fn is_private_network_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private(),
        IpAddr::V6(v6) => is_ipv6_unique_local(v6),
    }
}

/// Returns `Err` when `ip` is a target agent fetches must never reach.
///
/// # Errors
///
/// Returns [`SsrfError::AlwaysBlocked`] for link-local/metadata/unspecified addresses, or
/// [`SsrfError::PrivateNetworkBlocked`] for private-network addresses when
/// `PARTON_BLOCK_PRIVATE_NETWORK_FETCH=1` is set.
pub fn check_ip_allowed_for_agent_fetch(ip: IpAddr) -> Result<(), SsrfError> {
    if is_always_blocked_ip(ip) {
        return Err(SsrfError::AlwaysBlocked { ip });
    }
    if block_private_networks() && is_private_network_ip(ip) {
        return Err(SsrfError::PrivateNetworkBlocked { ip });
    }
    Ok(())
}

fn check_host_allowed_for_agent_fetch(host: &str, port: u16) -> Result<(), SsrfError> {
    let host = host.trim();
    if host.is_empty() {
        return Err(SsrfError::EmptyHost);
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return check_ip_allowed_for_agent_fetch(ip);
    }
    // Not an IP literal: resolve and check every candidate address, since an attacker-controlled
    // hostname could otherwise resolve straight to the metadata IP or another blocked target.
    let addrs = (host, port)
        .to_socket_addrs()
        .map_err(|source| SsrfError::ResolveFailed {
            host: host.to_string(),
            source,
        })?;
    let mut any = false;
    for addr in addrs {
        any = true;
        check_ip_allowed_for_agent_fetch(addr.ip())?;
    }
    if !any {
        return Err(SsrfError::NoAddresses {
            host: host.to_string(),
        });
    }
    Ok(())
}

/// Validates a `target_host` / `port` pair (used by [`crate::DiagnosticSpec`]) against SSRF
/// guardrails before the agent probes it.
///
/// # Errors
///
/// Returns [`SsrfError::EmptyHost`] when the host is empty, [`SsrfError::AlwaysBlocked`] /
/// [`SsrfError::PrivateNetworkBlocked`] when it resolves to (or is) a blocked IP, or
/// [`SsrfError::ResolveFailed`] / [`SsrfError::NoAddresses`] when resolution fails.
pub fn diagnostic_target_allowed_for_agent_probe(
    target_host: &str,
    port: u16,
) -> Result<(), SsrfError> {
    check_host_allowed_for_agent_fetch(target_host, port)
}

/// Validates a URL (used by `health_check` / `handoff_bundle_import` queue payloads) against SSRF
/// guardrails before the agent fetches it.
///
/// Rejects non-`http(s)` schemes outright (e.g. `file://`, `gopher://`), then rejects link-local
/// / metadata / unspecified target hosts (and, when
/// `PARTON_BLOCK_PRIVATE_NETWORK_FETCH=1`, private-network targets too).
///
/// # Errors
///
/// Returns [`SsrfError::InvalidUrl`] when `raw_url` doesn't parse, [`SsrfError::UnsupportedScheme`]
/// / [`SsrfError::NoHost`] for scheme or host problems, or any of [`check_ip_allowed_for_agent_fetch`]'s
/// errors for the resolved host.
pub fn url_allowed_for_agent_fetch(raw_url: &str) -> Result<(), SsrfError> {
    let url = reqwest::Url::parse(raw_url.trim()).map_err(|e| SsrfError::InvalidUrl {
        raw_url: raw_url.to_string(),
        message: e.to_string(),
    })?;
    match url.scheme() {
        "http" | "https" => {}
        other => {
            return Err(SsrfError::UnsupportedScheme {
                scheme: other.to_string(),
            })
        }
    }
    let host = url.host_str().ok_or_else(|| SsrfError::NoHost {
        raw_url: raw_url.to_string(),
    })?;
    let port = url.port_or_known_default().unwrap_or(80);
    check_host_allowed_for_agent_fetch(host, port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_metadata_ip_literal_url() {
        let err = url_allowed_for_agent_fetch("http://169.254.169.254/latest/meta-data/")
            .expect_err("metadata ip must be blocked");
        assert!(err.to_string().contains("link-local"));
        assert!(matches!(err, SsrfError::AlwaysBlocked { .. }));
    }

    #[test]
    fn error_variant_is_matchable_without_string_parsing() {
        let err =
            url_allowed_for_agent_fetch("file:///etc/passwd").expect_err("file scheme rejected");
        match err {
            SsrfError::UnsupportedScheme { scheme } => assert_eq!(scheme, "file"),
            other => panic!("expected UnsupportedScheme, got {other:?}"),
        }
    }

    #[test]
    fn blocks_link_local_range_url() {
        assert!(url_allowed_for_agent_fetch("http://169.254.1.1:8080/x").is_err());
    }

    #[test]
    fn blocks_unspecified_ip() {
        assert!(url_allowed_for_agent_fetch("http://0.0.0.0/").is_err());
    }

    #[test]
    fn allows_public_ip_literal_url() {
        assert!(url_allowed_for_agent_fetch("http://93.184.216.34/").is_ok());
    }

    #[test]
    fn rejects_non_http_scheme() {
        let err =
            url_allowed_for_agent_fetch("file:///etc/passwd").expect_err("file scheme rejected");
        assert!(err.to_string().contains("unsupported URL scheme"));
    }

    #[test]
    fn diagnostic_target_blocks_metadata_ip() {
        assert!(diagnostic_target_allowed_for_agent_probe("169.254.169.254", 80).is_err());
    }

    #[test]
    fn diagnostic_target_allows_public_ip() {
        assert!(diagnostic_target_allowed_for_agent_probe("93.184.216.34", 443).is_ok());
    }

    #[test]
    fn ipv6_link_local_is_blocked() {
        let ip: IpAddr = "fe80::1".parse().expect("valid ipv6");
        assert!(check_ip_allowed_for_agent_fetch(ip).is_err());
    }

    #[test]
    fn private_network_allowed_by_default_blocked_when_env_set() {
        std::env::remove_var(super::ALLOW_PRIVATE_NETWORK_ENV);
        let ip: IpAddr = "10.1.2.3".parse().expect("valid ipv4");
        assert!(
            check_ip_allowed_for_agent_fetch(ip).is_ok(),
            "private networks allowed by default"
        );

        std::env::set_var(super::ALLOW_PRIVATE_NETWORK_ENV, "1");
        assert!(
            check_ip_allowed_for_agent_fetch(ip).is_err(),
            "private networks blocked when env opt-in is set"
        );
        std::env::remove_var(super::ALLOW_PRIVATE_NETWORK_ENV);
    }
}
