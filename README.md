# Parton

[![CI](https://github.com/unified-field-dev/parton/actions/workflows/ci.yml/badge.svg)](https://github.com/unified-field-dev/parton/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

[GitHub](https://github.com/unified-field-dev/parton) · `cargo doc -p parton --open`

## About

Parton is a long-running **host agent** (and library contracts) for cell control
planes. It heartbeats inventory to a Pion-compatible `/api/parton/*` endpoint,
claims leased node actions, executes Docker and host-native ops under a strict
policy, and applies signed re-enroll/revoke directives.

- **Heartbeat** — capabilities, mounts, container status
- **Command queue** — claim / extend-lease / result
- **Docker lifecycle** — start, stop, restart, logs, inspect, deploy, ensure network/image
- **Host ops** — `probe_host`, `diagnostic` (SSRF-gated), `grow_fs`, WireGuard peer apply
- **Allowlisted `templated_exec`** — engine ops without free-text shell (Postgres, Redis,
  ClickHouse, MongoDB wire ids)
- **Queue-only** — `health_check`, handoff deploy/teardown, bundle import
- **Auth** — shared token or SPIFFE; sealed enrollment; Ed25519 handoff directives
- **Policy** — digest-pinned images by default; deny host net/mounts; optional cosign
- **Metrics** — Prometheus agent metrics

Optional observation of `gluon.*` container labels when a control-plane peer sets
them (opaque wire keys on the container, not a product dependency).

See [`parton/README.md`](parton/README.md) for the library API and env table.

## Examples

Teaching examples for identity crypto and heartbeat JSON live under
[`parton/examples/`](parton/examples/README.md).

## Getting started

```toml
[dependencies]
parton = { git = "https://github.com/unified-field-dev/parton", branch = "main" }
```

```bash
export CARGO_BUILD_JOBS=1
export CARGO_TARGET_DIR=target-parton
cargo test -p parton
```

Run the agent (match token with Pion):

```bash
export PARTON_HEARTBEAT_URL="http://127.0.0.1:3000/api/parton/heartbeat"
export PARTON_NODE_ID="dev-node-1"
export PARTON_CELL_ID="local-default"
export PARTON_SHARED_TOKEN="dev-shared-token"
# For handoff directives: PARTON_AUTHORITY_VERIFY_KEY=…
cargo run -p parton
```

## Security

Vulnerability reporting: [`SECURITY.md`](SECURITY.md). Dependency policy:
[`docs/supply-chain.md`](docs/supply-chain.md). SPIFFE auth modes:
[`docs/spiffe.md`](docs/spiffe.md).

## Verify

CI runs on every push and PR ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)):

```bash
export CARGO_BUILD_JOBS=1
export CARGO_TARGET_DIR=target-parton
cargo fmt --all --check
cargo check -p parton
cargo clippy -p parton --all-targets --all-features -- -D warnings
cargo test -p parton
cargo deny check
```

Full command block: [`VERIFICATION.md`](VERIFICATION.md) (details in
[`docs/VERIFICATION.md`](docs/VERIFICATION.md)). Contribute:
[`CONTRIBUTING.md`](CONTRIBUTING.md).

## FAQ

**Is it production-ready?** v0.1.0. Auth, signing/sealing, Docker deploy policy, SSRF
guards, and optional cosign / SPIFFE are implemented and tested. It is currently
experimental.

**Does Parton need root?** The binary itself does not require root, but it shells out
to the Docker CLI, and Docker daemon access is effectively root on the host. Run on
dedicated hosts.

**How does the agent authenticate to the control plane?** By default a shared token
(`PARTON_SHARED_TOKEN`) plus Ed25519-signed directives. For production fleets, enable
SPIFFE JWT-SVIDs (`PARTON_AUTH_MODE=dual` then `spiffe`) — see
[`docs/spiffe.md`](docs/spiffe.md).

**What happens if the control plane goes away?** The agent keeps its last-known
configuration and retries; a `Revoke` directive (verified against
`PARTON_AUTHORITY_VERIFY_KEY`) stops the agent from acting for a decommissioned CP.

## License

MIT. See [LICENSE](LICENSE).
