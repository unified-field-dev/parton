//! Apply signed CP directives (re-enroll / revoke) after a successful heartbeat response.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context, Result};
use base64::Engine;
use chrono::Utc;

use crate::directives_wire::{
    handoff_reenroll_directive_signature_message_v1, handoff_revoke_directive_signature_message_v1,
};
use crate::identity::{
    box_secret_key_from_identity_json, directive_verify, directive_verifying_key_from_base64,
    unseal_with_box_secret,
};
use crate::AgentDirective;

/// Typed failure reasons for directive application setup and hard apply failures.
///
/// Individual directives that fail signature or validity checks are skipped (logged), not
/// returned as [`DirectiveError`]. Crypto decode failures surface as [`crate::IdentityError`]
/// via `?`. This enum covers the agent-local configuration prerequisites and hard apply
/// failures callers may match on. Because this type implements [`std::error::Error`], it
/// converts into `anyhow::Error` automatically via `?` (see [`apply_directives`]).
#[derive(Debug, thiserror::Error)]
pub enum DirectiveError {
    /// `PARTON_AUTHORITY_VERIFY_KEY` is unset or empty.
    #[error("PARTON_AUTHORITY_VERIFY_KEY is not set; cannot verify directives")]
    MissingAuthorityVerifyKey,
    /// `HOME` is unset so default identity / env paths cannot be resolved.
    #[error("HOME is not set; cannot locate {0}")]
    MissingHome(&'static str),
    /// `PARTON_NODE_ID` is unset; refusing re-enroll without a stable node identity.
    #[error(
        "PARTON_NODE_ID is not set; refusing to apply re-enroll directive without a stable node identity"
    )]
    MissingNodeId,
    /// Re-enroll file rewrite is only supported on Unix in this release.
    #[error("directive apply (re-enroll) is only supported on Unix targets in this release")]
    UnsupportedPlatform,
}

/// Result of applying a batch of signed directives to the agent's local state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DirectiveApplyOutcome {
    /// Base64(STANDARD) of the decrypted wire token; send as `applied_directive_token` on the next heartbeat to the new CP.
    pub next_applied_directive_token: Option<String>,
    /// When true, the process should exit with code 1 (revoked agent).
    pub revoke_exit: bool,
    /// Prior CP heartbeat URL captured before `parton.env` rewrite (grace-window fallback target).
    pub prev_endpoint: Option<String>,
    /// Prior `PARTON_ENROLLMENT_TOKEN` / shared token snapshot before rewrite.
    pub prev_token: Option<String>,
}

/// User-level agent state directory (binary, env file, identity) under `home`.
///
/// Override the entire directory with `PARTON_AGENT_DATA_DIR` (absolute path recommended).
#[must_use]
pub fn agent_data_dir(home: &std::path::Path) -> PathBuf {
    if let Ok(raw) = std::env::var("PARTON_AGENT_DATA_DIR") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    home.join(".local/share/unified-field-agent")
}

fn default_identity_path() -> Result<PathBuf> {
    let home = std::env::var("HOME").map_err(|_| DirectiveError::MissingHome("parton.identity"))?;
    Ok(agent_data_dir(std::path::Path::new(&home)).join("parton.identity"))
}

fn default_env_path() -> Result<PathBuf> {
    let home = std::env::var("HOME").map_err(|_| DirectiveError::MissingHome("parton.env"))?;
    Ok(agent_data_dir(std::path::Path::new(&home)).join("parton.env"))
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;
    let digest = Sha256::digest(data);
    digest
        .iter()
        .fold(String::with_capacity(digest.len() * 2), |mut acc, b| {
            let _ = write!(acc, "{b:02x}");
            acc
        })
}

fn parse_env_file(body: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let key = k.trim().to_string();
        if !key.is_empty() {
            out.insert(key, v.to_string());
        }
    }
    out
}

fn render_env_file(map: &BTreeMap<String, String>) -> String {
    map.iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

/// Apply zero or more [`AgentDirective`] values: verify signatures, decrypt tokens, rewrite `parton.env`.
///
/// Linux: atomic replace via write temp + `fsync` + `rename`. Non-Linux: currently no-op for file IO
/// (returns errors explaining the platform gate).
///
/// # Errors
///
/// Returns [`DirectiveError::MissingAuthorityVerifyKey`] / [`DirectiveError::MissingHome`] /
/// [`DirectiveError::MissingNodeId`] for agent-local config prerequisites,
/// [`crate::IdentityError`] when the authority verify key or identity file crypto fails,
/// [`DirectiveError::UnsupportedPlatform`] on non-Unix re-enroll, or an I/O /
/// base64 error when reading identity / rewriting `parton.env`.
/// Individual directives with an out-of-window validity or a failed signature check are
/// skipped (logged, not returned as an error).
#[tracing::instrument(skip(directives), fields(directive_count = directives.len()))]
pub fn apply_directives(directives: &[AgentDirective]) -> Result<DirectiveApplyOutcome> {
    let mut out = DirectiveApplyOutcome::default();
    if directives.is_empty() {
        return Ok(out);
    }

    let vk_b64 = std::env::var("PARTON_AUTHORITY_VERIFY_KEY")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or(DirectiveError::MissingAuthorityVerifyKey)?;
    let vk = directive_verifying_key_from_base64(&vk_b64)?;

    let identity_path = match std::env::var("PARTON_IDENTITY_PATH") {
        Ok(s) if !s.trim().is_empty() => PathBuf::from(s),
        _ => default_identity_path()?,
    };
    let identity_json = fs::read_to_string(&identity_path)
        .with_context(|| format!("read {}", identity_path.display()))?;
    let box_sk = box_secret_key_from_identity_json(&identity_json)?;

    for d in directives {
        match d {
            AgentDirective::ReEnroll { .. } => apply_reenroll_directive(&vk, &box_sk, d, &mut out)?,
            AgentDirective::Revoke { .. } => apply_revoke_directive(&vk, d, &mut out),
        }
    }

    Ok(out)
}

/// Verify and apply a single [`AgentDirective::ReEnroll`], mutating `out`.
fn apply_reenroll_directive(
    vk: &ed25519_dalek::VerifyingKey,
    box_sk: &crypto_box::SecretKey,
    directive: &AgentDirective,
    out: &mut DirectiveApplyOutcome,
) -> Result<()> {
    let AgentDirective::ReEnroll {
        directive_id,
        new_cp_url,
        new_authority_id,
        new_authority_verify_key,
        new_token_ciphertext,
        not_before,
        not_after,
        issued_by_authority_id,
        issued_at,
        signature,
    } = directive
    else {
        return Ok(());
    };

    let now = Utc::now();
    if now < *not_before || now > *not_after {
        tracing::warn!(
            directive_id = %directive_id,
            "skipping re-enroll directive: outside not_before/not_after window"
        );
        return Ok(());
    }

    // Fail closed rather than silently signing/verifying against an empty target_node_id: an
    // agent with no configured PARTON_NODE_ID has no stable identity to bind this directive to,
    // and `handoff_reenroll_directive_signature_message_v1` would otherwise embed an empty
    // `target_node_id` field, which widens the set of directives that verify successfully.
    let node_id = std::env::var("PARTON_NODE_ID")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or(DirectiveError::MissingNodeId)?;

    let ct_bytes = base64::engine::general_purpose::STANDARD
        .decode(new_token_ciphertext.trim())
        .context("new_token_ciphertext base64")?;
    let wire = unseal_with_box_secret(box_sk, &ct_bytes)
        .context("decrypt directive token (sealed box)")?;
    let digest_hex = sha256_hex(&wire);
    let msg = handoff_reenroll_directive_signature_message_v1(
        directive_id,
        // target_node_id is implied by the agent; the server used the same node id when signing.
        &node_id,
        new_cp_url,
        new_authority_id,
        new_authority_verify_key,
        new_token_ciphertext.trim(),
        &digest_hex,
        not_before,
        not_after,
        issued_by_authority_id,
        issued_at,
    );
    if !directive_verify(vk, msg.as_bytes(), signature) {
        tracing::warn!(
            directive_id = %directive_id,
            "rejecting re-enroll directive: signature verify failed"
        );
        return Ok(());
    }

    #[cfg(unix)]
    {
        let env_path = match std::env::var("PARTON_ENV_PATH") {
            Ok(s) if !s.trim().is_empty() => PathBuf::from(s),
            _ => default_env_path()?,
        };
        let body = fs::read_to_string(&env_path)
            .with_context(|| format!("read {}", env_path.display()))?;
        let map_before = parse_env_file(&body);
        out.prev_endpoint = map_before.get("PARTON_HEARTBEAT_URL").cloned();
        out.prev_token = map_before
            .get("PARTON_SHARED_TOKEN")
            .cloned()
            .or_else(|| map_before.get("PARTON_ENROLLMENT_TOKEN").cloned());

        apply_reenroll_env_unix(new_cp_url, new_authority_verify_key, &wire)?;
        out.next_applied_directive_token =
            Some(base64::engine::general_purpose::STANDARD.encode(&wire));
    }
    #[cfg(not(unix))]
    {
        let _ = out;
        return Err(DirectiveError::UnsupportedPlatform.into());
    }
    #[cfg(unix)]
    Ok(())
}

/// Verify a single [`AgentDirective::Revoke`], marking `out` for exit when valid.
///
/// # Validity window
///
/// Unlike [`AgentDirective::ReEnroll`], `Revoke` carries only a point-in-time `revoked_at` and no
/// `not_before`/`not_after` window: revocation is meant to take effect immediately and
/// unconditionally once the signature verifies, so a window would only add a way to delay or
/// bound an otherwise-valid revoke. We intentionally do **not** add optional `not_before`/
/// `not_after` fields here: `handoff_revoke_directive_signature_message_v1`'s signed message
/// format is shared wire-format with the control-plane issuer, and any new field must either be
/// included in the signed message (a breaking change requiring coordinated rollout with every
/// directive issuer) or left unsigned (in which case it carries no security guarantee and an
/// attacker could freely rewrite it in transit). Revisit only alongside a versioned wire format
/// (see `directives_wire.rs`).
fn apply_revoke_directive(
    vk: &ed25519_dalek::VerifyingKey,
    directive: &AgentDirective,
    out: &mut DirectiveApplyOutcome,
) {
    let AgentDirective::Revoke {
        directive_id,
        reason,
        revoked_at,
        issued_by_authority_id,
        signature,
    } = directive
    else {
        return;
    };
    let msg = handoff_revoke_directive_signature_message_v1(
        directive_id,
        reason,
        revoked_at,
        issued_by_authority_id,
    );
    if directive_verify(vk, msg.as_bytes(), signature) {
        out.revoke_exit = true;
    } else {
        tracing::warn!(
            directive_id = %directive_id,
            "ignoring revoke directive: signature verify failed"
        );
    }
}

#[cfg(unix)]
fn apply_reenroll_env_unix(
    new_cp_url: &str,
    new_authority_verify_key: &str,
    wire_token: &[u8],
) -> Result<()> {
    let env_path = match std::env::var("PARTON_ENV_PATH") {
        Ok(s) if !s.trim().is_empty() => PathBuf::from(s),
        _ => default_env_path()?,
    };
    let body =
        fs::read_to_string(&env_path).with_context(|| format!("read {}", env_path.display()))?;
    let mut map = parse_env_file(&body);
    let node_id = map
        .get("PARTON_NODE_ID")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "PARTON_NODE_ID missing from {}; refusing re-enroll env rewrite without a stable node identity",
                env_path.display()
            )
        })?;
    let cell_id = map
        .get("PARTON_CELL_ID")
        .cloned()
        .unwrap_or_else(|| "local-default".to_string());
    let shared = map.get("PARTON_SHARED_TOKEN").cloned();

    let hb_url = if new_cp_url.contains("/api/parton/heartbeat") {
        new_cp_url.trim().to_string()
    } else {
        format!("{}/api/parton/heartbeat", new_cp_url.trim_end_matches('/'))
    };
    map.insert("PARTON_HEARTBEAT_URL".to_string(), hb_url);
    map.insert(
        "PARTON_ENROLLMENT_TOKEN".to_string(),
        base64::engine::general_purpose::STANDARD.encode(wire_token),
    );
    map.insert(
        "PARTON_AUTHORITY_VERIFY_KEY".to_string(),
        new_authority_verify_key.trim().to_string(),
    );
    map.insert("PARTON_NODE_ID".to_string(), node_id);
    map.insert("PARTON_CELL_ID".to_string(), cell_id);
    if let Some(t) = shared {
        map.insert("PARTON_SHARED_TOKEN".to_string(), t);
    }

    let rendered = render_env_file(&map);
    let tmp = env_path.with_extension("env.tmp");
    {
        let mut f = fs::File::create(&tmp).with_context(|| format!("create {}", tmp.display()))?;
        f.write_all(rendered.as_bytes())
            .with_context(|| format!("write {}", tmp.display()))?;
        f.sync_all()
            .with_context(|| format!("fsync {}", tmp.display()))?;
    }
    fs::rename(&tmp, &env_path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), env_path.display()))?;

    // `parton.env` carries PARTON_SHARED_TOKEN / PARTON_ENROLLMENT_TOKEN in plaintext; restrict
    // it to owner read/write after every rewrite so a directive apply can't accidentally widen
    // permissions (e.g. a permissive umask on first-write).
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o600);
        fs::set_permissions(&env_path, perms)
            .with_context(|| format!("chmod 0600 {}", env_path.display()))?;
    }

    Ok(())
}

#[cfg(all(test, unix))]
mod apply_env_tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::print_stderr)]

    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{Mutex, MutexGuard};

    /// Serialize process-global `HOME` / `PARTON_ENV_PATH` mutations across these tests.
    fn env_lock() -> MutexGuard<'static, ()> {
        static LOCK: Mutex<()> = Mutex::new(());
        LOCK.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    struct ClearReenrollEnv;
    impl Drop for ClearReenrollEnv {
        fn drop(&mut self) {
            // Edition 2021: env mutation is safe; serialized by `env_lock` / `serial_test`.
            std::env::remove_var("PARTON_ENV_PATH");
            std::env::remove_var("HOME");
        }
    }

    fn restore_dir_writable(dir: &std::path::Path) {
        if let Ok(meta) = fs::metadata(dir) {
            let mut perms = meta.permissions();
            perms.set_mode(0o755);
            let _ = fs::set_permissions(dir, perms);
        }
    }

    #[test]
    #[serial_test::serial]
    fn apply_reenroll_does_not_mutate_env_when_directory_not_writable() {
        let _guard = env_lock();
        let _clear = ClearReenrollEnv;
        let dir = tempfile::tempdir().expect("tempdir");
        let env_path = dir.path().join("parton.env");
        fs::write(
            &env_path,
            "PARTON_NODE_ID=node-a\nPARTON_CELL_ID=cell-a\nPARTON_HEARTBEAT_URL=http://old/cp\n",
        )
        .expect("write env");
        let before = fs::read(&env_path).expect("read before");

        let mut perms = fs::metadata(dir.path()).expect("meta").permissions();
        perms.set_mode(0o555);
        fs::set_permissions(dir.path(), perms).expect("chmod dir");

        // Some CI/container setups ignore DAC (or run with privileges that bypass mode bits).
        // Probe first so we don't flake when the platform cannot enforce read-only dirs.
        let probe = dir.path().join(".write_probe");
        if fs::File::create(&probe).is_ok() {
            let _ = fs::remove_file(&probe);
            restore_dir_writable(dir.path());
            eprintln!("skipping: filesystem does not enforce directory mode 0555");
            return;
        }

        std::env::set_var("PARTON_ENV_PATH", env_path.to_str().expect("utf8"));
        std::env::set_var("HOME", dir.path().to_str().expect("utf8"));

        let wire = b"wire-token-bytes";
        let err = apply_reenroll_env_unix(
            "http://new-cp.example",
            base64::engine::general_purpose::STANDARD
                .encode([1u8; 32].as_slice())
                .as_str(),
            wire,
        );
        assert!(err.is_err(), "expected write failure on read-only dir");

        let after = fs::read(&env_path).expect("read after");
        assert_eq!(
            before, after,
            "parton.env must be unchanged on failed apply"
        );

        restore_dir_writable(dir.path());
    }

    #[test]
    #[serial_test::serial]
    fn apply_reenroll_env_unix_chmods_env_file_to_0600() {
        let _guard = env_lock();
        let _clear = ClearReenrollEnv;
        let dir = tempfile::tempdir().expect("tempdir");
        restore_dir_writable(dir.path());
        let env_path = dir.path().join("parton.env");
        fs::write(
            &env_path,
            "PARTON_NODE_ID=node-a\nPARTON_CELL_ID=cell-a\nPARTON_HEARTBEAT_URL=http://old/cp\n",
        )
        .expect("write env");
        // Start from an intentionally-too-permissive mode so the assertion actually exercises
        // the chmod call rather than passing on whatever the umask produced.
        fs::set_permissions(&env_path, fs::Permissions::from_mode(0o644)).expect("chmod loose");

        std::env::set_var("PARTON_ENV_PATH", env_path.to_str().expect("utf8"));
        std::env::set_var("HOME", dir.path().to_str().expect("utf8"));

        apply_reenroll_env_unix(
            "http://new-cp.example",
            base64::engine::general_purpose::STANDARD
                .encode([2u8; 32].as_slice())
                .as_str(),
            b"wire-token-bytes",
        )
        .expect("apply reenroll env");

        let mode = fs::metadata(&env_path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "parton.env must be chmod 0600 after rewrite");
    }
}
