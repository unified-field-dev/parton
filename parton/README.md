# parton

Host agent for cell control-plane heartbeat reporting and Docker / host actions.

This crate provides:

- A shared heartbeat contract used by the agent and control-plane ingest (Pion).
- A periodic sender-loop binary (`src/main.rs`) for node telemetry.
- Typed container action contracts and Docker CLI execution helpers.
- Signed handoff directives (re-enroll / revoke) and claim/result/lease HTTP clients.

## Feature overview

- **Heartbeat model** — `NodeHeartbeatReport`, `build_heartbeat_report`, `send_heartbeat`
- **Command queue** — claim / extend-lease / result against `/api/parton/actions/*`
- **Docker lifecycle** — `start`, `stop`, `restart`, `logs`, `inspect`, `deploy`, `ensure_network`, `ensure_docker_image`
- **Host ops** — `probe_host`, `diagnostic`, `grow_fs`, `wireguard_peer`
- **Allowlisted `templated_exec`** — see `TemplatedExecId` (full catalog in rustdoc)
- **Queue-only** — `health_check`, `handoff_bundle_import`, `deploy_handoff`, `teardown_handoff`
- **Directives** — apply signed `ReEnroll` / `Revoke` to `parton.env`
- **Policy** — digest pins, SSRF guards, optional cosign; Prometheus `agent_metrics`

## How to run examples

Canonical teaching path for library primitives. These smoke checks exercise crypto and
heartbeat JSON locally; point the agent binary at Pion when you are ready for a live control
plane.

### 1. Identity crypto — `identity_seal`

Run when you need to verify sealed-box encryption and Ed25519 directive signing before wiring
handoff directives (`ReEnroll` / `Revoke`) against Pion.

```bash
export CARGO_BUILD_JOBS=1
export CARGO_TARGET_DIR=target-parton
cargo run -p parton --example identity_seal
```

Success: stdout prints `sealed-box: recipient_pk=… ciphertext_len=… roundtrip_ok=true` and
`directive: signature=… valid=true tampered_rejected=true`.

Look next at `examples/identity_seal.rs` for `seal_to_recipient`, `unseal_with_box_secret`,
`directive_sign`, and `directive_verify` — the same primitives the agent uses for signed
handoffs.

### 2. Heartbeat report — `heartbeat_report`

Run when you want to inspect the JSON shape of `NodeHeartbeatReport` before pointing the
agent at a Pion ingest URL.

```bash
cargo run -p parton --example heartbeat_report -- my-node-id my-cell-id
```

Success: stdout prints pretty JSON for the report, then a summary line like
`-- collected N container(s); M running` (counts depend on local Docker state; defaults
`example-node` / `local-default` when args are omitted).

Look next at `examples/heartbeat_report.rs` and `build_heartbeat_report`, then compare the
output to what Pion expects at `PARTON_HEARTBEAT_URL`.

## Quickstart

```bash
export CARGO_BUILD_JOBS=1
export CARGO_TARGET_DIR=target-parton
cargo test -p parton
```

Run the agent:

```bash
export PARTON_HEARTBEAT_URL="http://127.0.0.1:3000/api/parton/heartbeat"
export PARTON_NODE_ID="dev-node-1"
export PARTON_CELL_ID="local-default"
cargo run -p parton
```

## Runtime configuration (binary)

| Variable | Default | Purpose |
|---|---|---|
| `PARTON_HEARTBEAT_URL` | `http://127.0.0.1:3000/api/parton/heartbeat` | Control-plane heartbeat ingest URL |
| `PARTON_NODE_ID` | **required** | Stable node identifier (fail closed if unset/blank) |
| `PARTON_CELL_ID` | `local-default` | Cell/group identifier |
| `PARTON_HEARTBEAT_INTERVAL_SECS` | `10` | Heartbeat interval seconds |
| `PARTON_SHARED_TOKEN` | _(unset)_ | Shared token (`x-parton-token`); required for production shared-token auth |
| `PARTON_AUTH_MODE` | `shared_token` | `shared_token` / `dual` / `spiffe` — see [`../docs/spiffe.md`](../docs/spiffe.md) |
| `PARTON_COSIGN_MODE` | `off` | `off` / `key` / `keyless` — cosign verify before pull/run |
| `PARTON_ENROLLMENT_TOKEN` | _(unset)_ | One-time enrollment token |
| `PARTON_ACTION_LEASE_SECS` | `120` | Claim lease duration |
| `PARTON_ACTION_LEASE_EXTEND_SECS` | `600` | Lease extension before long actions |
| `PARTON_HANDOFF_IMPORT_BASE_URL` | _(unset)_ | Optional import base URL for handoff results |
| `PARTON_DIRECTIVE_GRACE_SECS` | `300` | Post re-enroll grace window |
| `PARTON_AUTHORITY_VERIFY_KEY` | _(unset)_ | Ed25519 verify key for handoff directives (required for signed handoffs) |

## Security

Deploy policy defaults to deny host networking/mounts and require digest-pinned images.
Optional cosign (`PARTON_COSIGN_MODE`) and SPIFFE (`PARTON_AUTH_MODE`) are implemented —
vulnerability reporting: [`../SECURITY.md`](../SECURITY.md).

## Docs

```bash
export CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=target-parton
RUSTDOCFLAGS="-D warnings" cargo doc -p parton --no-deps
```

See the [root README](../README.md) for verification, and
See crate docs and [`../docs/spiffe.md`](../docs/spiffe.md) for auth modes.

