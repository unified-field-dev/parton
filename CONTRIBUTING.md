# Contributing to parton

`parton` is the node agent for Unified Field control-plane hosts (Pion). It ships
a library (`parton`) plus the `parton` binary that runs the heartbeat + action loop.

## Documentation

When you change public API behavior, configuration, or wiring steps:

1. Update rustdoc on the affected symbols (the workspace enforces `missing_docs = "deny"`).
2. Public functions returning `Result` need a `# Errors` section describing failure modes.
3. Trait methods with meaningful semantics carry a `# Contract` subsection (invariants,
   caller obligations, no-op behavior) — see [`ContainerActionExecutor`](parton/src/actions/mod.rs).
4. Add or update a runnable example under [`parton/examples/`](parton/examples/) when
   introducing a new user-facing workflow.
5. Run the verification block in [`docs/VERIFICATION.md`](docs/VERIFICATION.md) before opening a PR.

### Style

- Organize crate-root docs by **task** (heartbeat telemetry, container actions,
  binary runtime).
- Put full code snippets on the item that owns the API; the crate root links without duplicating.
- Prefer `# Examples` on key entry points ([`build_heartbeat_report`](parton/src/heartbeat/mod.rs),
  [`directive_sign`](parton/src/identity.rs)).

## Rust standards & lint policy

Workspace lints live in the root [`Cargo.toml`](Cargo.toml) (`[workspace.lints.*]`).
Library and binary crates inherit them via `[lints] workspace = true`. CI runs:

```bash
CARGO_BUILD_JOBS=1 cargo clippy -p parton --all-targets --all-features -- -D warnings
```

### Enforced (restriction / correctness)

| Lint | Level | Intent |
|------|-------|--------|
| `clippy::unwrap_used` / `expect_used` | deny | No silent panics in library/runtime paths |
| `clippy::dbg_macro` | deny | No leftover debug macros |
| `clippy::print_stdout` / `print_stderr` | deny | Prefer `tracing` in library/binary paths |
| `clippy::todo` / `unimplemented` | deny | No placeholders in shipped code |
| `clippy::too_many_arguments` | deny | Group related args (canonical wire structs may `#[allow]` with a reason) |
| `clippy::unnested_or_patterns` | deny | Collapse `A | B` patterns |
| `rust.missing_docs` | deny | Public API docs |
| `rust.unsafe_code` | forbid | No `unsafe` |
| `rustdoc::broken_intra_doc_links` | deny | No broken `[…]` links in rustdoc |
| `rustdoc::private_intra_doc_links` | deny | No links to private items from public docs |
| `rustdoc::invalid_html_tags` | deny | Valid HTML in rustdoc |
| `rustdoc::invalid_codeblock_attributes` | deny | Valid codeblock attributes |
| `rustdoc::missing_crate_level_docs` | deny | Crate-level `//!` required |

Pedantic is enabled at warn (CI denies via `-D warnings`); nursery is allowed.
`too_many_lines` / `cognitive_complexity` are warn — prefer extracting helpers; only
`#[allow(...)]` with a one-line reason when a refactor would risk behavior change.

### Logging

Replace `println!` / `eprintln!` in library and binary paths with `tracing`
(`tracing::info!` / `warn!` / `error!`). The binary initializes a `tracing-subscriber`
in `main.rs` (filter via `PARTON_LOG` or `RUST_LOG`). Examples are the exception:
they carry a file-level `#![allow(clippy::print_stdout)]` with a one-line reason since
printing results is their purpose.

### Tests

Unit tests (`#[cfg(test)]`) and integration tests under `parton/tests/` may use
`unwrap` / `expect`; [`clippy.toml`](clippy.toml) allows this, and integration test
files carry a file-level `#![allow(clippy::unwrap_used, clippy::expect_used)]` where the
config does not reach helper fns. Do not re-add broad workspace `allow`s for restriction
lints without discussion.

### Error handling

Prefer typed errors (`thiserror`) for public matchable APIs — [`SsrfError`](parton/src/ssrf_guard.rs),
[`IdentityError`](parton/src/identity.rs), [`DirectiveError`](parton/src/directive_apply.rs) —
and `anyhow::Result` with `.context()` at binary / HTTP glue boundaries. Document failure modes
in `# Errors`.

### Structure budgets

Production module files: soft max **500** LOC / hard max **800** LOC (excluding `#[cfg(test)]`
and generated code). Prefer domain `mod` directories over mega-files; no kitchen-sink `utils`.
Clippy denies `too_many_lines` (≤120), `too_many_arguments` (≤7), and `cognitive_complexity`.

### Telemetry

- Logging: `tracing` + `#[instrument]` on async entry points (filter via `PARTON_LOG` / `RUST_LOG`).
- Metrics: `metrics` public crate (`parton_heartbeat_total`, `parton_action_*`). Optional Prometheus
  scrape when `PARTON_METRICS_BIND` is set (default off).

### Supply chain

Use **cargo-deny** (`deny.toml` + CI `deny` job) for advisories/licenses/sources — this satisfies
the RustSec advisory gate (no separate `cargo-audit` job). See
[`docs/supply-chain.md`](docs/supply-chain.md).

### Coverage & benches

- CI `coverage` job: `cargo llvm-cov -p parton --fail-under-lines 64` (baseline ~74%; ratchet toward 90%).
- Criterion micro-benches: `cargo bench -p parton --bench micro`.

## CI

CI runs on every push and PR ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)):

```bash
export CARGO_BUILD_JOBS=1
export CARGO_TARGET_DIR=target-parton
cargo fmt --all --check
cargo check -p parton
cargo clippy -p parton --all-targets --all-features -- -D warnings
cargo test -p parton
cargo deny check
cargo llvm-cov -p parton --fail-under-lines 64 --summary-only
```

## Verification

See [`docs/VERIFICATION.md`](docs/VERIFICATION.md) for the full command block and

## Security (contributors)

Follow [`SECURITY.md`](SECURITY.md) for vulnerability reporting when changing auth,
enrollment, deploy policy, or agent HTTP surfaces. SPIFFE guide: [`docs/spiffe.md`](docs/spiffe.md).

Coverage floor is **64%** lines (ratchet toward 90%).
