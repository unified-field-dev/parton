# Verification

Pre-ship and CI parity for this workspace. Full notes (lint policy, examples,
coverage ratchet): [`docs/VERIFICATION.md`](docs/VERIFICATION.md).

## Environment

```bash
export CARGO_BUILD_JOBS=1
export CARGO_TARGET_DIR=target-parton
```

## Commands

Run from the repo root; each must pass with no warnings:

```bash
cargo fmt --all --check
cargo check -p parton
cargo clippy -p parton --all-targets --all-features -- -D warnings
cargo test -p parton
RUSTDOCFLAGS="-D warnings" cargo doc -p parton --no-deps
cargo test -p parton --doc
cargo deny check
cargo llvm-cov -p parton --fail-under-lines 64 --summary-only
```
