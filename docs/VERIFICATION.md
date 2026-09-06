# Verification

Re-run after code or doc changes. See [CONTRIBUTING.md](../CONTRIBUTING.md#rust-standards--lint-policy)
for the lint policy these commands enforce.

## Environment

All cargo commands use a single build job and a dedicated target dir so local verification
doesn't collide with other workspaces on the same machine:

```bash
export CARGO_BUILD_JOBS=1
export CARGO_TARGET_DIR=target-parton
```

## Commands

Run these in order; each must pass with no warnings. This is the same command block CI runs
([`.github/workflows/ci.yml`](../.github/workflows/ci.yml)):

```bash
# Formatting
cargo fmt --all --check

# Type/borrow check (workspace missing_docs = deny)
cargo check -p parton

# Full lint gate (lib + bins + tests + examples), warnings are errors
cargo clippy -p parton --all-targets --all-features -- -D warnings

# Unit + integration tests
cargo test -p parton

# API docs render cleanly (fail on rustdoc warnings)
RUSTDOCFLAGS="-D warnings" cargo doc -p parton --no-deps

# Doctests (rust,no_run compile-checked; runnable ones executed)
cargo test -p parton --doc

# Dependency policy (advisories, licenses, sources) — see docs/supply-chain.md
cargo deny check

# Coverage floor (ratchet toward 90%)
cargo llvm-cov -p parton --fail-under-lines 64 --summary-only

# Optional: Criterion micro-benches
# cargo bench -p parton --bench micro
```

## Examples

The runnable examples under [`parton/examples/`](../parton/examples/) double as smoke checks:

```bash
cargo run -p parton --example heartbeat_report -- my-node local-default
cargo run -p parton --example identity_seal
```

## Notes

- Workspace `[workspace.lints.rust] missing_docs = "deny"` and `unsafe_code = "forbid"`;
  `[workspace.lints.rustdoc]` denies broken/private intra-doc links, invalid HTML/codeblock
  attributes, and missing crate-level docs; restriction lints (`unwrap_used`, `expect_used`,
  `print_stdout`, `print_stderr`, `dbg_macro`, `todo`, `unimplemented`) are enforced in
  `[workspace.lints.clippy]`.
- [`clippy.toml`](../clippy.toml) allows `unwrap` in tests; integration test files also
  carry a file-level allow where the config does not reach helper functions.
- Trait `# Contract` section: [`ContainerActionExecutor::execute_action`](../parton/src/actions/mod.rs).
- Library/binary logging goes through `tracing`; the binary initializes a subscriber in
  `main.rs` (filter via `PARTON_LOG` / `RUST_LOG`). Optional Prometheus scrape via
  `PARTON_METRICS_BIND`. Examples are the only paths that print to stdout, via a documented
  `#![allow(clippy::print_stdout)]`.
- Structure: soft 500 / hard 800 LOC per production module; `too_many_lines` and
  `cognitive_complexity` are **deny**.
