//! Micro-benchmarks for CPU-bound Parton helpers (SSRF IP checks, Ed25519 sign/verify).
#![allow(missing_docs)]

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};

use criterion::{criterion_group, criterion_main, Criterion};
use parton::{
    check_ip_allowed_for_agent_fetch, directive_sign, directive_verify,
    generate_directive_signing_key, url_allowed_for_agent_fetch,
};

fn bench_ssrf_ip(c: &mut Criterion) {
    let public = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
    let metadata = IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254));
    c.bench_function("ssrf_check_ip_public", |b| {
        b.iter(|| {
            let _ = check_ip_allowed_for_agent_fetch(black_box(public));
        });
    });
    c.bench_function("ssrf_check_ip_metadata", |b| {
        b.iter(|| {
            let _ = check_ip_allowed_for_agent_fetch(black_box(metadata));
        });
    });
    c.bench_function("ssrf_url_https_literal_ip", |b| {
        b.iter(|| {
            let _ = url_allowed_for_agent_fetch(black_box("https://8.8.8.8/health"));
        });
    });
}

fn bench_directive_crypto(c: &mut Criterion) {
    let sk = generate_directive_signing_key();
    let vk = sk.verifying_key();
    let msg = b"pion_handoff_directive/v1/revoke|id|node|exp";
    let sig = directive_sign(&sk, msg);
    c.bench_function("directive_sign", |b| {
        b.iter(|| {
            let _ = directive_sign(black_box(&sk), black_box(msg));
        });
    });
    c.bench_function("directive_verify", |b| {
        b.iter(|| {
            let _ = directive_verify(black_box(&vk), black_box(msg), black_box(&sig));
        });
    });
}

criterion_group!(benches, bench_ssrf_ip, bench_directive_crypto);
criterion_main!(benches);
