//! Canonical signing payloads for control-plane handoff directives (shared with Pion ingest).

use chrono::{DateTime, SecondsFormat, Utc};

/// Deterministic UTF-8 message signed by the CP authority for [`crate::AgentDirective::ReEnroll`].
// Args mirror the canonical wire fields 1:1; grouping into a struct would obscure the signed layout.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn handoff_reenroll_directive_signature_message_v1(
    directive_id: &str,
    target_node_id: &str,
    new_cp_url: &str,
    new_authority_id: &str,
    new_authority_verify_key: &str,
    new_token_ciphertext: &str,
    new_token_sha256_hex: &str,
    not_before: &DateTime<Utc>,
    not_after: &DateTime<Utc>,
    issued_by_authority_id: &str,
    issued_at: &DateTime<Utc>,
) -> String {
    let nb = not_before.to_rfc3339_opts(SecondsFormat::Secs, true);
    let na = not_after.to_rfc3339_opts(SecondsFormat::Secs, true);
    let ia = issued_at.to_rfc3339_opts(SecondsFormat::Secs, true);
    format!(
        "pion_handoff_directive/v1/re_enroll\n\
directive_id={directive_id}\n\
target_node_id={target_node_id}\n\
new_cp_url={new_cp_url}\n\
new_authority_id={new_authority_id}\n\
new_authority_verify_key={new_authority_verify_key}\n\
new_token_ciphertext={new_token_ciphertext}\n\
new_token_sha256_hex={new_token_sha256_hex}\n\
not_before={nb}\n\
not_after={na}\n\
issued_by_authority_id={issued_by_authority_id}\n\
issued_at={ia}\n"
    )
}

/// Deterministic UTF-8 message for [`crate::AgentDirective::Revoke`].
#[must_use]
pub fn handoff_revoke_directive_signature_message_v1(
    directive_id: &str,
    reason: &str,
    revoked_at: &DateTime<Utc>,
    issued_by_authority_id: &str,
) -> String {
    let ra = revoked_at.to_rfc3339_opts(SecondsFormat::Secs, true);
    format!(
        "pion_handoff_directive/v1/revoke\n\
directive_id={directive_id}\n\
reason={reason}\n\
revoked_at={ra}\n\
issued_by_authority_id={issued_by_authority_id}\n"
    )
}
