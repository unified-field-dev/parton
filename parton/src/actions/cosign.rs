//! Optional cosign image signature verification before Docker pull/run.
//!
//! Digest pinning ([`super::policy`]) is the baseline. When `PARTON_COSIGN_MODE` is `key` or
//! `keyless`, Parton shells out to `cosign verify` (override binary via `PARTON_COSIGN_BIN`)
//! and fails closed on non-zero exit. Mode `off` (default) skips signature verification.
//!
//! Vulnerability reporting: repository root `SECURITY.md`.

use std::process::Command;

/// Cosign verification mode selected by `PARTON_COSIGN_MODE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CosignMode {
    /// Digest policy only; no signature check.
    Off,
    /// `cosign verify --key $PARTON_COSIGN_KEY <image>`.
    Key,
    /// Keyless Fulcio verify with certificate identity constraints.
    Keyless,
}

impl CosignMode {
    /// Parse `PARTON_COSIGN_MODE` (`off` / `key` / `keyless`). Unset or unknown → [`Self::Off`].
    pub(super) fn from_env() -> Self {
        Self::from_raw(std::env::var("PARTON_COSIGN_MODE").ok().as_deref())
    }

    pub(super) fn from_raw(raw: Option<&str>) -> Self {
        match raw.map_or("", str::trim).to_ascii_lowercase().as_str() {
            "key" => Self::Key,
            "keyless" => Self::Keyless,
            _ => Self::Off,
        }
    }

    pub(super) fn is_enabled(self) -> bool {
        !matches!(self, Self::Off)
    }
}

fn cosign_bin() -> String {
    std::env::var("PARTON_COSIGN_BIN")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "cosign".to_string())
}

/// Build argv for `cosign verify …` (excluding the binary name).
///
/// # Errors
///
/// Returns an error when mode is enabled but required env vars are missing, or when
/// `image_ref` lacks an `@sha256:` digest pin (required whenever cosign is on).
pub(super) fn build_cosign_verify_args(
    mode: CosignMode,
    image_ref: &str,
) -> anyhow::Result<Vec<String>> {
    let image = image_ref.trim();
    if image.is_empty() {
        anyhow::bail!("image_ref is empty for cosign verify");
    }
    if !image.to_ascii_lowercase().contains("@sha256:") {
        anyhow::bail!(
            "cosign verify requires a digest-pinned image_ref (`@sha256:…`); got `{image}`"
        );
    }
    let mut args = vec!["verify".to_string()];
    match mode {
        CosignMode::Off => {
            anyhow::bail!("build_cosign_verify_args called with CosignMode::Off");
        }
        CosignMode::Key => {
            let key = std::env::var("PARTON_COSIGN_KEY")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "PARTON_COSIGN_MODE=key requires PARTON_COSIGN_KEY (path to public key)"
                    )
                })?;
            args.push("--key".to_string());
            args.push(key);
        }
        CosignMode::Keyless => {
            let identity = std::env::var("PARTON_COSIGN_CERTIFICATE_IDENTITY")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "PARTON_COSIGN_MODE=keyless requires PARTON_COSIGN_CERTIFICATE_IDENTITY"
                    )
                })?;
            let issuer = std::env::var("PARTON_COSIGN_CERTIFICATE_OIDC_ISSUER")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "PARTON_COSIGN_MODE=keyless requires PARTON_COSIGN_CERTIFICATE_OIDC_ISSUER"
                    )
                })?;
            args.push("--certificate-identity".to_string());
            args.push(identity);
            args.push("--certificate-oidc-issuer".to_string());
            args.push(issuer);
        }
    }
    args.push(image.to_string());
    Ok(args)
}

/// Run cosign verify when mode is enabled; no-op for [`CosignMode::Off`].
///
/// # Errors
///
/// Fails when argv cannot be built, the binary is missing, or cosign exits non-zero.
pub(super) fn verify_image_signature(image_ref: &str) -> anyhow::Result<()> {
    let mode = CosignMode::from_env();
    if !mode.is_enabled() {
        return Ok(());
    }
    let args = build_cosign_verify_args(mode, image_ref)?;
    let bin = cosign_bin();
    tracing::info!(
        target: "security.deploy",
        image_ref = %image_ref.trim(),
        mode = ?mode,
        cosign_bin = %bin,
        "running cosign verify before docker pull/run"
    );
    let output = Command::new(&bin).args(&args).output().map_err(|e| {
        anyhow::anyhow!(
            "failed to run `{bin} {}`: {e} (is cosign installed, or set PARTON_COSIGN_BIN?)",
            args.join(" ")
        )
    })?;
    if output.status.success() {
        tracing::info!(
            target: "security.deploy",
            image_ref = %image_ref.trim(),
            "cosign verify succeeded"
        );
        return Ok(());
    }
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    tracing::warn!(
        target: "security.deploy",
        image_ref = %image_ref.trim(),
        exit = output.status.code().unwrap_or_default(),
        "cosign verify failed"
    );
    anyhow::bail!(
        "cosign verify failed for `{image}` (exit={}): {stdout}{}{stderr}",
        output.status.code().unwrap_or_default(),
        if !stdout.is_empty() && !stderr.is_empty() {
            " | "
        } else {
            ""
        },
        image = image_ref.trim(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    const DIGEST_PINNED: &str =
        "ghcr.io/acme/svc@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn clear_cosign_env() {
        for k in [
            "PARTON_COSIGN_MODE",
            "PARTON_COSIGN_KEY",
            "PARTON_COSIGN_CERTIFICATE_IDENTITY",
            "PARTON_COSIGN_CERTIFICATE_OIDC_ISSUER",
            "PARTON_COSIGN_BIN",
        ] {
            std::env::remove_var(k);
        }
    }

    /// Writes an executable stub that exits with `code`.
    fn write_cosign_stub(exit_code: i32) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("cosign-stub");
        let script = format!("#!/bin/sh\nexit {exit_code}\n");
        std::fs::write(&path, script).expect("write stub");
        let mut perms = std::fs::metadata(&path).expect("meta").permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).expect("chmod");
        (dir, path)
    }

    #[test]
    fn mode_from_raw_parses_known_values() {
        assert_eq!(CosignMode::from_raw(None), CosignMode::Off);
        assert_eq!(CosignMode::from_raw(Some("off")), CosignMode::Off);
        assert_eq!(CosignMode::from_raw(Some("KEY")), CosignMode::Key);
        assert_eq!(CosignMode::from_raw(Some("keyless")), CosignMode::Keyless);
        assert_eq!(CosignMode::from_raw(Some("nope")), CosignMode::Off);
    }

    #[test]
    #[serial]
    fn key_mode_requires_key_and_digest() {
        clear_cosign_env();
        std::env::set_var("PARTON_COSIGN_KEY", "/tmp/cosign.pub");
        let args = build_cosign_verify_args(CosignMode::Key, DIGEST_PINNED).expect("args");
        assert_eq!(
            args,
            vec![
                "verify".to_string(),
                "--key".to_string(),
                "/tmp/cosign.pub".to_string(),
                DIGEST_PINNED.to_string(),
            ]
        );
        let err = build_cosign_verify_args(CosignMode::Key, "ghcr.io/acme/svc:latest")
            .expect_err("mutable tag");
        assert!(err.to_string().contains("@sha256:"));
        std::env::remove_var("PARTON_COSIGN_KEY");
        let err =
            build_cosign_verify_args(CosignMode::Key, DIGEST_PINNED).expect_err("missing key");
        assert!(err.to_string().contains("PARTON_COSIGN_KEY"));
        clear_cosign_env();
    }

    #[test]
    #[serial]
    fn keyless_mode_requires_identity_and_issuer() {
        clear_cosign_env();
        let digest =
            "ghcr.io/acme/svc@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        std::env::set_var(
            "PARTON_COSIGN_CERTIFICATE_IDENTITY",
            "https://github.com/acme/svc/.github/workflows/release.yml@refs/tags/v1",
        );
        std::env::set_var(
            "PARTON_COSIGN_CERTIFICATE_OIDC_ISSUER",
            "https://token.actions.githubusercontent.com",
        );
        let args = build_cosign_verify_args(CosignMode::Keyless, digest).expect("args");
        assert!(args.contains(&"--certificate-identity".to_string()));
        assert!(args.contains(&"--certificate-oidc-issuer".to_string()));
        assert_eq!(args.last().map(String::as_str), Some(digest));
        clear_cosign_env();
    }

    #[test]
    #[serial]
    fn verify_noop_when_mode_off() {
        clear_cosign_env();
        verify_image_signature("anything:latest").expect("off is noop");
    }

    #[test]
    #[serial]
    fn verify_image_signature_succeeds_with_stub_bin() {
        clear_cosign_env();
        let (_dir, stub) = write_cosign_stub(0);
        std::env::set_var("PARTON_COSIGN_MODE", "key");
        std::env::set_var("PARTON_COSIGN_KEY", "/tmp/cosign.pub");
        std::env::set_var("PARTON_COSIGN_BIN", stub.to_str().expect("utf8 path"));
        verify_image_signature(DIGEST_PINNED).expect("stub exit 0");
        clear_cosign_env();
    }

    #[test]
    #[serial]
    fn verify_image_signature_fails_closed_on_nonzero_exit() {
        clear_cosign_env();
        let (_dir, stub) = write_cosign_stub(1);
        std::env::set_var("PARTON_COSIGN_MODE", "key");
        std::env::set_var("PARTON_COSIGN_KEY", "/tmp/cosign.pub");
        std::env::set_var("PARTON_COSIGN_BIN", stub.to_str().expect("utf8 path"));
        let err = verify_image_signature(DIGEST_PINNED).expect_err("stub exit 1");
        assert!(
            err.to_string().contains("cosign verify failed"),
            "got: {err}"
        );
        clear_cosign_env();
    }

    #[test]
    #[serial]
    fn verify_image_signature_fails_when_bin_missing() {
        clear_cosign_env();
        std::env::set_var("PARTON_COSIGN_MODE", "key");
        std::env::set_var("PARTON_COSIGN_KEY", "/tmp/cosign.pub");
        std::env::set_var(
            "PARTON_COSIGN_BIN",
            "/nonexistent/parton-cosign-stub-missing-bin",
        );
        let err = verify_image_signature(DIGEST_PINNED).expect_err("missing bin");
        assert!(
            err.to_string().contains("failed to run")
                || err.to_string().contains("PARTON_COSIGN_BIN"),
            "got: {err}"
        );
        clear_cosign_env();
    }

    /// Documents a live `cosign` invocation; ignored in CI unless the binary is present.
    #[test]
    #[ignore = "requires cosign on PATH and a signed digest-pinned image"]
    fn live_cosign_verify_smoke() {
        let image = std::env::var("PARTON_COSIGN_SMOKE_IMAGE")
            .expect("set PARTON_COSIGN_SMOKE_IMAGE to a signed @sha256: ref");
        std::env::set_var("PARTON_COSIGN_MODE", "key");
        verify_image_signature(&image).expect("cosign verify");
    }
}
