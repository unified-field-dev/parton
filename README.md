# Parton

[![CI](https://github.com/unified-field-dev/parton/actions/workflows/ci.yml/badge.svg)](https://github.com/unified-field-dev/parton/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

[GitHub](https://github.com/unified-field-dev/parton) · `cargo doc -p parton --open`

## About

Parton is a long-running host agent, with library contracts, for cell control
planes. A cell is a named group of nodes managed by one control plane. The agent
sends inventory heartbeats to a control plane that implements the `/api/parton/*`
HTTP API, claims leased node actions, runs Docker and host-native operations under
a strict policy, and applies signed re-enroll and revoke directives.

- Heartbeat: capabilities, mounts, container status
- Command queue: claim, extend-lease, result
- Docker lifecycle: start, stop, restart, logs, inspect, deploy, ensure network/image
- Host ops: `probe_host`, `diagnostic` (SSRF-gated), `grow_fs`, WireGuard peer apply
- Allowlisted `templated_exec`: engine ops without free-text shell (Postgres, Redis,
  ClickHouse, MongoDB)
- Queue-only kinds: `health_check`, handoff deploy/teardown, bundle import
- Auth: shared token or SPIFFE, sealed enrollment, Ed25519 handoff directives
- Policy: digest-pinned images by default, host networking and mounts denied, optional cosign
- Metrics: Prometheus agent metrics

Container status includes an `instance_id`, read from the optional
`gluon.instance_id` container label when whatever deployed the container set it.

See [`parton/README.md`](parton/README.md) for the library API and env table.

## Examples

Teaching examples for identity crypto and heartbeat JSON live under
[`parton/examples/`](parton/examples/README.md).

## Getting started

You need a stable Rust toolchain. Docker is needed only for container actions; the
heartbeat builder tolerates a missing daemon.

```bash
git clone https://github.com/unified-field-dev/parton
cd parton
cargo test -p parton
```

Both examples run offline and need no control plane:

```bash
cargo run -p parton --example identity_seal
cargo run -p parton --example heartbeat_report
```

To use Parton as a library:

```toml
[dependencies]
parton = { git = "https://github.com/unified-field-dev/parton", branch = "main" }
```

Running the agent itself needs a control plane that implements the `/api/parton/*`
endpoints (heartbeat, action claim, lease extend, result). By default the agent
posts to `http://127.0.0.1:3000/api/parton/heartbeat`; set `PARTON_HEARTBEAT_URL`
to point elsewhere. Without a reachable control plane the agent logs each failed
heartbeat and keeps retrying.

```bash
export PARTON_HEARTBEAT_URL="http://127.0.0.1:3000/api/parton/heartbeat"
export PARTON_NODE_ID="dev-node-1"
export PARTON_CELL_ID="local-default"
export PARTON_SHARED_TOKEN="dev-shared-token"   # must match the control plane
# For handoff directives: PARTON_AUTHORITY_VERIFY_KEY=...
cargo run -p parton
```

## Security

Vulnerability reporting: [`SECURITY.md`](SECURITY.md). Dependency policy:
[`docs/supply-chain.md`](docs/supply-chain.md). SPIFFE auth modes:
[`docs/spiffe.md`](docs/spiffe.md).

## Verify

CI runs on every push and PR ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)):

```bash
cargo fmt --all --check
cargo check -p parton
cargo clippy -p parton --all-targets --all-features -- -D warnings
cargo test -p parton
cargo deny check
```

Full command block: [`docs/VERIFICATION.md`](docs/VERIFICATION.md). Contribute:
[`CONTRIBUTING.md`](CONTRIBUTING.md).

## FAQ

**Is it production-ready?** No. Parton is v0.1.0 and experimental. Auth,
signing and sealing, Docker deploy policy, SSRF guards, and optional cosign and SPIFFE
are implemented and tested, but the API and wire contract may change before 1.0.

**Does Parton need root?** The binary itself does not require root, but it shells out
to the Docker CLI, and Docker daemon access is effectively root on the host. Run on
dedicated hosts.

**How does the agent authenticate to the control plane?** By default a shared token
(`PARTON_SHARED_TOKEN`) plus Ed25519-signed directives. For production fleets, enable
SPIFFE JWT-SVIDs (`PARTON_AUTH_MODE=dual` then `spiffe`); see
[`docs/spiffe.md`](docs/spiffe.md).

**What happens if the control plane goes away?** The agent keeps its last-known
configuration and retries; a `Revoke` directive (verified against
`PARTON_AUTHORITY_VERIFY_KEY`) stops the agent from acting for a decommissioned CP.

## License

MIT. See [LICENSE](LICENSE).
