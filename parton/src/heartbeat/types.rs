//! Report-shape types: the heartbeat response, agent directives, and the canonical
//! [`NodeHeartbeatReport`] payload.

use super::container_status::ContainerStatusReport;
use super::host_capabilities::HostCapabilities;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Control-plane → agent instructions returned on successful heartbeat POST.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HeartbeatResponse {
    /// Server timestamp acknowledging the heartbeat.
    pub acknowledged_at: DateTime<Utc>,
    /// Signed directives the agent should verify and apply, if any.
    #[serde(default)]
    pub directives: Vec<AgentDirective>,
}

impl Default for HeartbeatResponse {
    fn default() -> Self {
        Self {
            acknowledged_at: Utc::now(),
            directives: Vec::new(),
        }
    }
}

/// Signed directive the agent may apply after verifying chain-of-custody.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AgentDirective {
    /// Instructs the agent to re-enroll against a new control plane, rewriting `parton.env`.
    ReEnroll {
        /// Unique directive identifier (idempotency + audit key).
        directive_id: String,
        /// New control-plane base or heartbeat URL.
        new_cp_url: String,
        /// New authority identifier that signed this directive.
        new_authority_id: String,
        /// New Ed25519 authority verifying key (base64) for future directive checks.
        new_authority_verify_key: String,
        /// Sealed-box ciphertext (base64) of the new enrollment token.
        new_token_ciphertext: String,
        /// Directive is invalid before this instant.
        not_before: DateTime<Utc>,
        /// Directive is invalid after this instant.
        not_after: DateTime<Utc>,
        /// Authority id that issued (signed) the directive.
        issued_by_authority_id: String,
        /// Issuance timestamp.
        issued_at: DateTime<Utc>,
        /// Detached Ed25519 signature (base64) over the canonical message.
        signature: String,
    },
    /// Instructs the agent to treat itself as revoked and exit.
    Revoke {
        /// Unique directive identifier (idempotency + audit key).
        directive_id: String,
        /// Human-readable revocation reason.
        reason: String,
        /// Revocation timestamp.
        revoked_at: DateTime<Utc>,
        /// Authority id that issued (signed) the directive.
        issued_by_authority_id: String,
        /// Detached Ed25519 signature (base64) over the canonical message.
        signature: String,
    },
}

/// Canonical heartbeat payload ingested by the Pion control plane.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NodeHeartbeatReport {
    /// Stable node identifier.
    pub node_id: String,
    /// Cell / group identifier.
    pub cell_id: String,
    /// Static host capability snapshot.
    pub capabilities: HostCapabilities,
    /// Observed container status report (per-container list + summary).
    pub containers: ContainerStatusReport,
    /// Timestamp when the report was assembled.
    pub observed_at: DateTime<Utc>,
    /// One-time host enrollment token (`ghe.<id>.<secret>`), when joining a strict control plane.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrollment_token: Option<String>,
    /// When the agent has applied a re-enroll directive, reports the new wire token so the CP can mark the directive acknowledged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applied_directive_token: Option<String>,
    /// Agent-reported failure applying a directive (fallback heartbeat to old CP during grace window).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub apply_failed: Option<String>,
}

/// Optional fields merged into the next [`NodeHeartbeatReport`] (directive ack / grace reporting).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HeartbeatReportOverrides {
    /// New wire token to report as `applied_directive_token` after a re-enroll apply.
    pub applied_directive_token: Option<String>,
    /// Failure message reported as `apply_failed` during a grace-window fallback heartbeat.
    pub apply_failed: Option<String>,
    /// When `true`, omit `enrollment_token` from the built report even if
    /// `PARTON_ENROLLMENT_TOKEN` is set in the environment.
    ///
    /// The enrollment token only needs to reach the control plane once (to authorize the first
    /// heartbeat for a not-yet-known node); resending a long-lived token on every subsequent
    /// heartbeat needlessly repeats sensitive material over the wire and into CP-side telemetry
    /// persistence. Callers should set this once a heartbeat has been acknowledged.
    pub suppress_enrollment_token: bool,
}
