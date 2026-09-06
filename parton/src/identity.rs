//! Enrollment sealed-box keys ([`crypto_box`]) and Ed25519 helpers for signed CP directives.
//!
//! - **Enrollment** uses `crypto_box` X25519 sealed boxes (`PublicKey::seal` / [`SecretKey::unseal`]).
//! - **Directive signatures** use Ed25519 (authority signs; agent verifies with `PARTON_AUTHORITY_VERIFY_KEY`).

use base64::Engine;
use crypto_box::aead::rand_core::OsRng;
use crypto_box::{PublicKey, SecretKey};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng as RandOsRng;
use serde::{Deserialize, Serialize};

/// Typed failure reasons for identity / crypto helpers in this module.
///
/// Every public parse, seal, and unseal helper here returns this type directly so callers can
/// match on *why* a key or ciphertext was rejected (bad base64 vs. wrong length vs. a failed
/// AEAD open) instead of string-matching an opaque [`anyhow::Error`]. Because this type
/// implements [`std::error::Error`], it converts into `anyhow::Error` automatically via `?` at
/// any call site that still returns `anyhow::Result` (see [`crate::apply_directives`]).
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    /// Base64 decoding failed for the named field.
    #[error("{field} base64 decode: {source}")]
    Base64Decode {
        /// Human-readable name of the field being decoded (for example `enrollment_pubkey`).
        field: &'static str,
        /// Underlying base64 decode error.
        #[source]
        source: base64::DecodeError,
    },
    /// Decoded key material was not the expected byte length.
    #[error("{field} must be {expected} bytes (got {got})")]
    InvalidKeyLength {
        /// Human-readable name of the field being decoded.
        field: &'static str,
        /// Expected length in bytes.
        expected: usize,
        /// Actual decoded length in bytes.
        got: usize,
    },
    /// Failed to parse or serialize `parton.identity` JSON.
    #[error("parton.identity json: {0}")]
    Json(#[from] serde_json::Error),
    /// `crypto_box` sealed-box encryption failed.
    #[error("crypto_box seal failed: {0}")]
    Seal(#[source] crypto_box::aead::Error),
    /// `crypto_box` sealed-box decryption failed (wrong key, or tampered/malformed ciphertext).
    #[error("crypto_box unseal failed: {0}")]
    Unseal(#[source] crypto_box::aead::Error),
    /// The decoded bytes are not a valid Ed25519 verifying key.
    #[error("invalid ed25519 verifying key: {0}")]
    InvalidVerifyingKey(#[source] ed25519_dalek::SignatureError),
}

/// JSON written to `parton.identity` (mode 0600): X25519 secret for sealed-box decrypt only.
#[derive(Debug, Serialize, Deserialize)]
pub struct PartonIdentityFileV1 {
    /// Identity file schema version (currently `1`).
    pub version: u32,
    /// Base64 STANDARD, 32-byte [`SecretKey`] material for [`SecretKey::from_bytes`].
    pub box_secret_key_b64: String,
}

/// Generate a fresh `crypto_box` keypair for agent enrollment sealed boxes.
pub fn generate_box_keypair() -> (SecretKey, PublicKey) {
    let sk = SecretKey::generate(&mut OsRng);
    let pk = sk.public_key();
    (sk, pk)
}

/// Encode a [`PublicKey`] for persistence (`pion_agent_host_enrollments.enrollment_pubkey`).
#[must_use]
pub fn box_public_key_base64(pk: &PublicKey) -> String {
    base64::engine::general_purpose::STANDARD.encode(pk.as_bytes())
}

/// Decode enrollment public key from base64 (32 bytes).
///
/// # Errors
///
/// Returns [`IdentityError`] when `b64` is not valid base64 or does not decode to exactly
/// [`crypto_box::KEY_SIZE`] bytes.
pub fn box_public_key_from_base64(b64: &str) -> Result<PublicKey, IdentityError> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|source| IdentityError::Base64Decode {
            field: "enrollment_pubkey",
            source,
        })?;
    let arr: [u8; crypto_box::KEY_SIZE] =
        raw.as_slice()
            .try_into()
            .map_err(|_| IdentityError::InvalidKeyLength {
                field: "enrollment_pubkey",
                expected: crypto_box::KEY_SIZE,
                got: raw.len(),
            })?;
    Ok(PublicKey::from(arr))
}

/// Serialize identity file JSON for `$PARTON_IDENTITY_PATH`.
///
/// Production installs often use `/var/lib/parton/parton.identity`. User-level installs (for example
/// a fleet Linux install helper) default under [`crate::agent_data_dir`] unless the path is overridden.
///
/// # Errors
///
/// Returns [`IdentityError::Json`] if the identity struct cannot be serialized.
pub fn identity_file_json_from_box_secret(sk: &SecretKey) -> Result<String, IdentityError> {
    let body = PartonIdentityFileV1 {
        version: 1,
        box_secret_key_b64: base64::engine::general_purpose::STANDARD.encode(sk.to_bytes()),
    };
    Ok(serde_json::to_string_pretty(&body)?)
}

/// Load [`SecretKey`] from `parton.identity` JSON.
///
/// # Errors
///
/// Returns [`IdentityError`] when `json` cannot be parsed, the embedded base64 is invalid,
/// or the decoded key is not exactly [`crypto_box::KEY_SIZE`] bytes.
pub fn box_secret_key_from_identity_json(json: &str) -> Result<SecretKey, IdentityError> {
    let parsed: PartonIdentityFileV1 = serde_json::from_str(json)?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(parsed.box_secret_key_b64.trim())
        .map_err(|source| IdentityError::Base64Decode {
            field: "box_secret_key_b64",
            source,
        })?;
    let arr: [u8; crypto_box::KEY_SIZE] =
        raw.as_slice()
            .try_into()
            .map_err(|_| IdentityError::InvalidKeyLength {
                field: "box_secret_key_b64",
                expected: crypto_box::KEY_SIZE,
                got: raw.len(),
            })?;
    Ok(SecretKey::from(arr))
}

/// Encrypt `plaintext` to a recipient's enrollment public key (anonymous sealed box).
///
/// # Errors
///
/// Returns [`IdentityError`] when `recipient_pk_b64` is not a valid public key or when the
/// underlying `crypto_box` seal operation fails.
pub fn seal_to_recipient(
    recipient_pk_b64: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>, IdentityError> {
    let pk = box_public_key_from_base64(recipient_pk_b64)?;
    pk.seal(&mut OsRng, plaintext).map_err(IdentityError::Seal)
}

/// Decrypt sealed-box ciphertext with the agent's box secret key.
///
/// # Errors
///
/// Returns [`IdentityError::Unseal`] when `ciphertext` was not sealed to `recipient_sk` or is
/// otherwise malformed / tampered.
pub fn unseal_with_box_secret(
    recipient_sk: &SecretKey,
    ciphertext: &[u8],
) -> Result<Vec<u8>, IdentityError> {
    recipient_sk
        .unseal(ciphertext)
        .map_err(IdentityError::Unseal)
}

/// Ed25519 verifying key from base64 (32-byte raw seed form used by Dalek `VerifyingKey::from_bytes`).
///
/// # Errors
///
/// Returns [`IdentityError`] when `b64` is not valid base64, is not exactly 32 bytes, or is
/// not a valid Ed25519 verifying key.
pub fn directive_verifying_key_from_base64(b64: &str) -> Result<VerifyingKey, IdentityError> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|source| IdentityError::Base64Decode {
            field: "PARTON_AUTHORITY_VERIFY_KEY",
            source,
        })?;
    let arr: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| IdentityError::InvalidKeyLength {
            field: "PARTON_AUTHORITY_VERIFY_KEY",
            expected: 32,
            got: raw.len(),
        })?;
    VerifyingKey::from_bytes(&arr).map_err(IdentityError::InvalidVerifyingKey)
}

/// Sign `message` with an Ed25519 signing key (CP authority issuance).
///
/// Returns the detached signature as base64 STANDARD.
///
/// # Examples
///
/// ```
/// use parton::{directive_sign, directive_verify, generate_directive_signing_key};
///
/// let signing_key = generate_directive_signing_key();
/// let verifying_key = signing_key.verifying_key();
/// let message = b"pion_handoff_directive/v1/revoke";
///
/// let signature = directive_sign(&signing_key, message);
/// assert!(directive_verify(&verifying_key, message, &signature));
/// assert!(!directive_verify(&verifying_key, b"tampered", &signature));
/// ```
pub fn directive_sign(signing_key: &SigningKey, message: &[u8]) -> String {
    let sig: Signature = signing_key.sign(message);
    base64::engine::general_purpose::STANDARD.encode(sig.to_bytes())
}

/// Verify a base64-encoded detached Ed25519 signature over `message`.
pub fn directive_verify(verifying_key: &VerifyingKey, message: &[u8], signature_b64: &str) -> bool {
    let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(signature_b64.trim()) else {
        return false;
    };
    let sig_bytes: [u8; 64] = match raw.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let Ok(sig) = Signature::from_slice(&sig_bytes) else {
        return false;
    };
    verifying_key.verify(message, &sig).is_ok()
}

/// Random Ed25519 signing key for tests / authority bootstrap.
pub fn generate_directive_signing_key() -> SigningKey {
    SigningKey::generate(&mut RandOsRng)
}

/// Random directive signing keypair: `(verify_key_base64, signing_seed_32_bytes)` for Neutrino seal.
pub fn random_directive_signing_pair_b64() -> (String, Vec<u8>) {
    let sk = generate_directive_signing_key();
    let vk_b64 = base64::engine::general_purpose::STANDARD.encode(sk.verifying_key().to_bytes());
    (vk_b64, sk.to_bytes().to_vec())
}

/// Build a [`SigningKey`] from a 32-byte Ed25519 seed (Neutrino-stored directive signing material).
pub fn directive_signing_key_from_seed(seed: &[u8; 32]) -> SigningKey {
    SigningKey::from_bytes(seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn box_seal_unseal_roundtrip() {
        let (sk, pk) = generate_box_keypair();
        let msg = b"token-material";
        let sealed = pk.seal(&mut OsRng, msg).expect("seal");
        let out = sk.unseal(&sealed).expect("unseal");
        assert_eq!(out, msg);
    }

    #[test]
    fn identity_file_roundtrip() {
        let (sk, _pk) = generate_box_keypair();
        let json = identity_file_json_from_box_secret(&sk).unwrap();
        let sk2 = box_secret_key_from_identity_json(&json).unwrap();
        assert_eq!(sk.to_bytes(), sk2.to_bytes());
    }

    #[test]
    fn ed25519_sign_verify_roundtrip() {
        let sk = generate_directive_signing_key();
        let vk = sk.verifying_key();
        let msg = b"directive-payload";
        let sig_b64 = directive_sign(&sk, msg);
        assert!(directive_verify(&vk, msg, &sig_b64));
        assert!(!directive_verify(&vk, b"tampered", &sig_b64));
    }
}
