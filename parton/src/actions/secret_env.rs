//! Secret env var name/value validation and the short-lived deploy env-file writer.

use super::types::{ContainerActionRequest, SecretEnvVar};
use anyhow::Context;
use std::path::PathBuf;

/// Conservative env var name rule for secret env-file entries: `[A-Z_][A-Z0-9_]*`.
///
/// # Errors
///
/// Returns an error when `name` is empty, starts with a character other than `[A-Z_]`,
/// or contains any character other than `[A-Z0-9_]`.
pub fn validate_deploy_secret_env_name(name: &str) -> anyhow::Result<()> {
    let n = name.trim();
    if n.is_empty() {
        anyhow::bail!("secret env var name is empty");
    }
    let mut it = n.chars();
    let Some(first) = it.next() else {
        anyhow::bail!("secret env var name is empty");
    };
    if !(first.is_ascii_uppercase() || first == '_') {
        anyhow::bail!(
            "invalid secret env var name {n:?}: first character must be [A-Z_] (docker env-file safety)"
        );
    }
    for c in it {
        if !(c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_') {
            anyhow::bail!(
                "invalid secret env var name {n:?}: only [A-Z0-9_] allowed after the first character"
            );
        }
    }
    Ok(())
}

fn validate_deploy_secret_env_value(value: &str) -> anyhow::Result<()> {
    if value.contains('\n') || value.contains('\r') {
        anyhow::bail!("secret env var value must not contain newline characters (env-file safety)");
    }
    Ok(())
}

/// Validates one resolved secret env entry (used by deploy and `deploy_handoff` mapping).
///
/// # Errors
///
/// Returns an error when the name is invalid (see [`validate_deploy_secret_env_name`]) or the
/// value contains newline characters.
pub fn validate_deploy_secret_env_entry(name: &str, value: &str) -> anyhow::Result<()> {
    validate_deploy_secret_env_name(name)?;
    validate_deploy_secret_env_value(value)?;
    Ok(())
}

/// Validates all [`SecretEnvVar`] entries on a deploy request.
///
/// # Errors
///
/// Returns an error on the first entry that fails [`validate_deploy_secret_env_entry`].
pub fn validate_deploy_secret_env_vars(vars: &[SecretEnvVar]) -> anyhow::Result<()> {
    for v in vars {
        validate_deploy_secret_env_entry(v.name.trim(), v.value.as_str())?;
    }
    Ok(())
}

fn env_file_line(key: &str, val: &str) -> String {
    let needs_quote = val
        .chars()
        .any(|c| c.is_whitespace() || matches!(c, '#' | '$' | '"' | '\\' | '\''));
    if !needs_quote {
        return format!("{key}={val}\n");
    }
    let escaped = val.replace('\\', "\\\\").replace('"', "\\\"");
    format!("{key}=\"{escaped}\"\n")
}

/// Writes [`ContainerActionRequest::secret_env_vars`] to a new temp file (Unix mode `0o600`).
///
/// # Errors
///
/// Returns an error when a secret entry is invalid, when the temp file cannot be written,
/// or (on Unix) when its permissions cannot be tightened to `0o600`.
pub fn write_deploy_secret_env_file(request: &ContainerActionRequest) -> anyhow::Result<PathBuf> {
    validate_deploy_secret_env_vars(&request.secret_env_vars)?;
    let dir = std::env::temp_dir();
    let name = format!(
        "parton-deploy-secret-env-{}.env",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    let path = dir.join(name);
    let mut contents = String::new();
    for v in &request.secret_env_vars {
        contents.push_str(&env_file_line(v.name.trim(), v.value.as_str()));
    }
    std::fs::write(&path, contents.as_bytes())
        .with_context(|| format!("write deploy secret env file {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&path)
            .with_context(|| format!("stat deploy secret env file {}", path.display()))?
            .permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&path, perms)
            .with_context(|| format!("chmod 0600 {}", path.display()))?;
    }
    Ok(path)
}
