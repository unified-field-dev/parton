//! SPIFFE JWT-SVID attachment for agent → control-plane HTTP calls.
//!
//! Implemented for fleets that run SPIRE. When `PARTON_AUTH_MODE` is `spiffe` or `dual`,
//! Parton attaches `Authorization: Bearer <jwt>` on heartbeat/claim/result/extend-lease
//! requests.
//!
//! JWT sources (first wins):
//! 1. `PARTON_SPIFFE_JWT` — literal token (tests / injected secrets)
//! 2. `PARTON_SPIFFE_JWT_PATH` — file contents
//! 3. `spire-agent api fetch jwt` against `SPIFFE_ENDPOINT_SOCKET`
//!
//! Rollout guide: repository `docs/spiffe.md`. Vulnerability reporting: `SECURITY.md`.

use std::process::Command;

/// Agent auth presentation mode (`PARTON_AUTH_MODE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartonAuthMode {
    /// Shared token only (default).
    SharedToken,
    /// Send shared token when set, and also attach a JWT-SVID when available.
    Dual,
    /// Require a JWT-SVID (fail if none can be fetched).
    Spiffe,
}

impl PartonAuthMode {
    /// Parse `PARTON_AUTH_MODE`.
    #[must_use]
    pub fn from_env() -> Self {
        Self::from_raw(std::env::var("PARTON_AUTH_MODE").ok().as_deref())
    }

    /// Parse a raw mode string (`shared_token` / `dual` / `spiffe`).
    #[must_use]
    pub fn from_raw(raw: Option<&str>) -> Self {
        match raw.map_or("", str::trim).to_ascii_lowercase().as_str() {
            "spiffe" => Self::Spiffe,
            "dual" => Self::Dual,
            _ => Self::SharedToken,
        }
    }

    /// Whether this mode should attach a JWT-SVID when one is available.
    #[must_use]
    pub fn wants_jwt(self) -> bool {
        matches!(self, Self::Dual | Self::Spiffe)
    }
}

fn audience() -> String {
    std::env::var("PARTON_SPIFFE_AUDIENCE")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            std::env::var("PION_SPIFFE_AUDIENCE")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| "pion".to_string())
}

fn fetch_jwt_via_spire_agent() -> anyhow::Result<String> {
    let socket = std::env::var("SPIFFE_ENDPOINT_SOCKET")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "SPIFFE_ENDPOINT_SOCKET is unset; cannot fetch JWT-SVID via spire-agent"
            )
        })?;
    let bin = std::env::var("PARTON_SPIRE_AGENT_BIN")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "spire-agent".to_string());
    let aud = audience();
    let output = Command::new(&bin)
        .args([
            "api",
            "fetch",
            "jwt",
            "-audience",
            &aud,
            "-socketPath",
            &socket,
        ])
        .output()
        .map_err(|e| {
            anyhow::anyhow!(
                "failed to run `{bin} api fetch jwt`: {e} (install spire-agent or set PARTON_SPIFFE_JWT)"
            )
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "`{bin} api fetch jwt` failed (exit={}): {stderr}",
            output.status.code().unwrap_or_default()
        );
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    // spire-agent prints the JWT on its own line (or JSON depending on flags); take the
    // first non-empty line that looks like a JWT (three base64url segments).
    for line in stdout.lines() {
        let line = line.trim();
        if line.split('.').count() == 3 && !line.contains(' ') {
            return Ok(line.to_string());
        }
    }
    anyhow::bail!("spire-agent jwt fetch produced no JWT in stdout")
}

/// Resolve a JWT-SVID string when auth mode wants one.
///
/// # Errors
///
/// Returns an error in `spiffe` mode when no JWT source succeeds. In `dual` mode, missing JWT
/// yields `Ok(None)` so the shared token can still authenticate.
pub fn maybe_jwt_svid() -> anyhow::Result<Option<String>> {
    let mode = PartonAuthMode::from_env();
    if !mode.wants_jwt() {
        return Ok(None);
    }
    if let Ok(jwt) = std::env::var("PARTON_SPIFFE_JWT") {
        let jwt = jwt.trim().to_string();
        if !jwt.is_empty() {
            return Ok(Some(jwt));
        }
    }
    if let Ok(path) = std::env::var("PARTON_SPIFFE_JWT_PATH") {
        let path = path.trim();
        if !path.is_empty() {
            let jwt = std::fs::read_to_string(path)
                .map_err(|e| anyhow::anyhow!("read PARTON_SPIFFE_JWT_PATH `{path}`: {e}"))?;
            let jwt = jwt.trim().to_string();
            if !jwt.is_empty() {
                return Ok(Some(jwt));
            }
        }
    }
    match fetch_jwt_via_spire_agent() {
        Ok(jwt) => Ok(Some(jwt)),
        Err(e) if matches!(mode, PartonAuthMode::Dual) => {
            tracing::debug!(error = %e, "JWT-SVID unavailable in dual mode; continuing with shared token");
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

/// Attach shared-token and optional JWT-SVID headers to a reqwest builder.
///
/// # Errors
///
/// Returns an error when `PARTON_AUTH_MODE=spiffe` and no JWT-SVID can be resolved.
pub fn apply_agent_auth_headers(
    mut request: reqwest::RequestBuilder,
    token: Option<&str>,
) -> anyhow::Result<reqwest::RequestBuilder> {
    if let Some(shared_token) = token.map(str::trim).filter(|t| !t.is_empty()) {
        request = request.header("x-parton-token", shared_token);
    }
    if let Some(jwt) = maybe_jwt_svid()? {
        request = request.header("Authorization", format!("Bearer {jwt}"));
    }
    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn clear() {
        for k in [
            "PARTON_AUTH_MODE",
            "PARTON_SPIFFE_JWT",
            "PARTON_SPIFFE_JWT_PATH",
            "SPIFFE_ENDPOINT_SOCKET",
        ] {
            std::env::remove_var(k);
        }
    }

    #[test]
    fn mode_parsing() {
        assert_eq!(PartonAuthMode::from_raw(None), PartonAuthMode::SharedToken);
        assert_eq!(PartonAuthMode::from_raw(Some("dual")), PartonAuthMode::Dual);
        assert_eq!(
            PartonAuthMode::from_raw(Some("spiffe")),
            PartonAuthMode::Spiffe
        );
    }

    #[test]
    #[serial]
    fn maybe_jwt_reads_env_literal() {
        clear();
        std::env::set_var("PARTON_AUTH_MODE", "spiffe");
        std::env::set_var("PARTON_SPIFFE_JWT", "aaa.bbb.ccc");
        let jwt = maybe_jwt_svid().expect("ok").expect("some");
        assert_eq!(jwt, "aaa.bbb.ccc");
        clear();
    }

    #[test]
    #[serial]
    fn maybe_jwt_reads_path_file() {
        clear();
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("svid.jwt");
        std::fs::write(&path, "path.jwt.token\n").expect("write");
        std::env::set_var("PARTON_AUTH_MODE", "spiffe");
        std::env::set_var("PARTON_SPIFFE_JWT_PATH", path.to_str().expect("utf8"));
        let jwt = maybe_jwt_svid().expect("ok").expect("some");
        assert_eq!(jwt, "path.jwt.token");
        clear();
    }

    #[test]
    #[serial]
    fn maybe_jwt_spiffe_mode_errors_without_source() {
        clear();
        std::env::set_var("PARTON_AUTH_MODE", "spiffe");
        // No JWT env/path and no SPIFFE_ENDPOINT_SOCKET → fail closed.
        let err = maybe_jwt_svid().expect_err("spiffe requires jwt");
        assert!(
            err.to_string().contains("SPIFFE_ENDPOINT_SOCKET") || err.to_string().contains("JWT"),
            "got: {err}"
        );
        clear();
    }

    #[test]
    #[serial]
    fn maybe_jwt_dual_mode_ok_none_without_source() {
        clear();
        std::env::set_var("PARTON_AUTH_MODE", "dual");
        assert!(maybe_jwt_svid().expect("ok").is_none());
        clear();
    }

    #[test]
    #[serial]
    fn shared_token_mode_skips_jwt() {
        clear();
        std::env::set_var("PARTON_SPIFFE_JWT", "aaa.bbb.ccc");
        assert!(maybe_jwt_svid().expect("ok").is_none());
        clear();
    }

    #[test]
    #[serial]
    fn apply_agent_auth_headers_spiffe_without_jwt_errors() {
        clear();
        std::env::set_var("PARTON_AUTH_MODE", "spiffe");
        let client = reqwest::Client::new();
        let builder = client.get("http://127.0.0.1:9/");
        let err = apply_agent_auth_headers(builder, None).expect_err("no jwt");
        assert!(!err.to_string().is_empty());
        clear();
    }
}
