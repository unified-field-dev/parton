//! Demonstrate the identity crypto primitives: sealed-box encryption and
//! Ed25519 directive signing.
//!
//! Run with:
//!
//! ```bash
//! cargo run -p parton --example identity_seal
//! ```

// Examples are user-facing CLIs; writing results to stdout is the intended behavior.
#![allow(clippy::print_stdout)]

use parton::{
    box_public_key_base64, directive_sign, directive_verify, generate_box_keypair,
    generate_directive_signing_key, seal_to_recipient, unseal_with_box_secret,
};

fn main() -> anyhow::Result<()> {
    // 1. Sealed-box roundtrip: encrypt to a recipient's public key, then decrypt
    //    with the matching secret key.
    let (recipient_sk, recipient_pk) = generate_box_keypair();
    let recipient_pk_b64 = box_public_key_base64(&recipient_pk);

    let plaintext = b"pion_handoff_directive/v1/payload";
    let ciphertext = seal_to_recipient(&recipient_pk_b64, plaintext)?;
    let recovered = unseal_with_box_secret(&recipient_sk, &ciphertext)?;
    assert_eq!(recovered.as_slice(), plaintext);
    println!(
        "sealed-box: recipient_pk={recipient_pk_b64} ciphertext_len={} roundtrip_ok={}",
        ciphertext.len(),
        recovered == plaintext
    );

    // 2. Directive signing: sign a canonical message and verify the signature.
    let signing_key = generate_directive_signing_key();
    let verifying_key = signing_key.verifying_key();
    let message = b"pion_handoff_directive/v1/revoke";
    let signature = directive_sign(&signing_key, message);

    let valid = directive_verify(&verifying_key, message, &signature);
    let tampered = directive_verify(&verifying_key, b"tampered", &signature);
    println!(
        "directive: signature={signature} valid={valid} tampered_rejected={}",
        !tampered
    );

    assert!(valid);
    assert!(!tampered);
    Ok(())
}
