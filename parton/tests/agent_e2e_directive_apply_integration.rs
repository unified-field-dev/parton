//! Linux-only: signed `ReEnroll` directive applies atomically to `parton.env`.

#![cfg(target_os = "linux")]
// Integration test harness: panics on setup/teardown are acceptable failure signals.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fs;
use std::sync::Mutex;

static ENV_TEST_LOCK: Mutex<()> = Mutex::new(());

use base64::Engine;
use chrono::Utc;
use parton::{
    apply_directives, directive_sign, directive_signing_key_from_seed, generate_box_keypair,
    handoff_reenroll_directive_signature_message_v1, seal_to_recipient, AgentDirective,
};

fn build_signed_reenroll(
    signing_seed: &[u8; 32],
    box_pk_b64: &str,
    wire: &[u8],
    signature_override: Option<&str>,
) -> anyhow::Result<(AgentDirective, String)> {
    let sk = directive_signing_key_from_seed(signing_seed);
    let vk_b64 = base64::engine::general_purpose::STANDARD.encode(sk.verifying_key().to_bytes());
    let digest_hex: String = {
        use sha2::{Digest, Sha256};
        use std::fmt::Write as _;
        Sha256::digest(wire)
            .iter()
            .fold(String::new(), |mut acc, b| {
                let _ = write!(acc, "{b:02x}");
                acc
            })
    };
    let ct_b64 =
        base64::engine::general_purpose::STANDARD.encode(seal_to_recipient(box_pk_b64, wire)?);
    let now = Utc::now();
    let not_before = now - chrono::Duration::minutes(5);
    let not_after = now + chrono::Duration::hours(4);
    let msg = handoff_reenroll_directive_signature_message_v1(
        "dir-1",
        "node-a",
        "http://new-cp.example",
        "auth-1",
        &vk_b64,
        &ct_b64,
        &digest_hex,
        &not_before,
        &not_after,
        "auth-1",
        &now,
    );
    let sig =
        signature_override.map_or_else(|| directive_sign(&sk, msg.as_bytes()), ToString::to_string);
    let d = AgentDirective::ReEnroll {
        directive_id: "dir-1".to_string(),
        new_cp_url: "http://new-cp.example".to_string(),
        new_authority_id: "auth-1".to_string(),
        new_authority_verify_key: vk_b64.clone(),
        new_token_ciphertext: ct_b64,
        not_before,
        not_after,
        issued_by_authority_id: "auth-1".to_string(),
        issued_at: now,
        signature: sig,
    };
    Ok((d, vk_b64))
}

#[test]
fn apply_reenroll_rewrites_env_and_returns_wire_token() -> anyhow::Result<()> {
    let _guard = ENV_TEST_LOCK.lock().expect("env test lock");
    let dir = tempfile::tempdir()?;
    let identity_path = dir.path().join("parton.identity");
    let env_path = dir.path().join("parton.env");

    let (box_sk, box_pk) = generate_box_keypair();
    fs::write(
        &identity_path,
        parton::identity_file_json_from_box_secret(&box_sk)?,
    )?;
    fs::write(
        &env_path,
        "PARTON_NODE_ID=node-a\nPARTON_CELL_ID=cell-a\nPARTON_HEARTBEAT_URL=http://old.example/api/parton/heartbeat\n",
    )?;

    let signing_seed = [7u8; 32];
    let wire = b"directive-wire-token-bytes";
    let (directive, vk_b64) = build_signed_reenroll(
        &signing_seed,
        &parton::box_public_key_base64(&box_pk),
        wire,
        None,
    )?;

    std::env::set_var(
        "PARTON_IDENTITY_PATH",
        identity_path.to_str().expect("utf8"),
    );
    std::env::set_var("PARTON_ENV_PATH", env_path.to_str().expect("utf8"));
    std::env::set_var("PARTON_AUTHORITY_VERIFY_KEY", &vk_b64);
    std::env::set_var("PARTON_NODE_ID", "node-a");
    std::env::set_var("HOME", dir.path().to_str().expect("utf8"));

    let out = apply_directives(&[directive])?;
    let token_b64 = out.next_applied_directive_token.expect("applied token");
    let decoded = base64::engine::general_purpose::STANDARD.decode(token_b64)?;
    assert_eq!(decoded, wire);

    let body = fs::read_to_string(&env_path)?;
    assert!(body.contains("http://new-cp.example/api/parton/heartbeat"));
    assert_eq!(
        out.prev_endpoint.as_deref(),
        Some("http://old.example/api/parton/heartbeat")
    );

    std::env::remove_var("PARTON_IDENTITY_PATH");
    std::env::remove_var("PARTON_ENV_PATH");
    std::env::remove_var("PARTON_AUTHORITY_VERIFY_KEY");
    std::env::remove_var("PARTON_NODE_ID");
    Ok(())
}

#[test]
fn apply_reenroll_fails_closed_when_node_id_env_is_empty() -> anyhow::Result<()> {
    let _guard = ENV_TEST_LOCK.lock().expect("env test lock");
    let dir = tempfile::tempdir()?;
    let identity_path = dir.path().join("parton.identity");
    let env_path = dir.path().join("parton.env");

    let (box_sk, box_pk) = generate_box_keypair();
    fs::write(
        &identity_path,
        parton::identity_file_json_from_box_secret(&box_sk)?,
    )?;
    fs::write(
        &env_path,
        "PARTON_NODE_ID=node-a\nPARTON_CELL_ID=cell-a\nPARTON_HEARTBEAT_URL=http://old.example/api/parton/heartbeat\n",
    )?;

    let signing_seed = [9u8; 32];
    let wire = b"directive-wire-token-bytes";
    let (directive, vk_b64) = build_signed_reenroll(
        &signing_seed,
        &parton::box_public_key_base64(&box_pk),
        wire,
        None,
    )?;

    std::env::set_var(
        "PARTON_IDENTITY_PATH",
        identity_path.to_str().expect("utf8"),
    );
    std::env::set_var("PARTON_ENV_PATH", env_path.to_str().expect("utf8"));
    std::env::set_var("PARTON_AUTHORITY_VERIFY_KEY", &vk_b64);
    std::env::remove_var("PARTON_NODE_ID");
    std::env::set_var("HOME", dir.path().to_str().expect("utf8"));

    let before = fs::read_to_string(&env_path)?;
    let result = apply_directives(&[directive]);
    assert!(
        result.is_err(),
        "expected re-enroll to fail closed without PARTON_NODE_ID"
    );
    assert_eq!(
        fs::read_to_string(&env_path)?,
        before,
        "parton.env must be unchanged when re-enroll fails closed"
    );

    std::env::remove_var("PARTON_IDENTITY_PATH");
    std::env::remove_var("PARTON_ENV_PATH");
    std::env::remove_var("PARTON_AUTHORITY_VERIFY_KEY");
    Ok(())
}

#[test]
fn bad_signature_skips_apply_and_leaves_env_unchanged() -> anyhow::Result<()> {
    let _guard = ENV_TEST_LOCK.lock().expect("env test lock");
    let dir = tempfile::tempdir()?;
    let identity_path = dir.path().join("parton.identity");
    let env_path = dir.path().join("parton.env");

    let (box_sk, box_pk) = generate_box_keypair();
    fs::write(
        &identity_path,
        parton::identity_file_json_from_box_secret(&box_sk)?,
    )?;
    let before =
        "PARTON_NODE_ID=node-a\nPARTON_HEARTBEAT_URL=http://old.example/api/parton/heartbeat\n";
    fs::write(&env_path, before)?;

    let signing_seed = [8u8; 32];
    let (directive, vk_b64) = build_signed_reenroll(
        &signing_seed,
        &parton::box_public_key_base64(&box_pk),
        b"wire",
        Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="),
    )?;

    std::env::set_var(
        "PARTON_IDENTITY_PATH",
        identity_path.to_str().expect("utf8"),
    );
    std::env::set_var("PARTON_ENV_PATH", env_path.to_str().expect("utf8"));
    std::env::set_var("PARTON_AUTHORITY_VERIFY_KEY", &vk_b64);
    std::env::set_var("PARTON_NODE_ID", "node-a");
    std::env::set_var("HOME", dir.path().to_str().expect("utf8"));

    let out = apply_directives(&[directive])?;
    assert!(out.next_applied_directive_token.is_none());
    assert_eq!(fs::read_to_string(&env_path)?, before);

    std::env::remove_var("PARTON_IDENTITY_PATH");
    std::env::remove_var("PARTON_ENV_PATH");
    std::env::remove_var("PARTON_AUTHORITY_VERIFY_KEY");
    std::env::remove_var("PARTON_NODE_ID");
    Ok(())
}
