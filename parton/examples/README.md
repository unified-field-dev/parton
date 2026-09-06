# Parton examples

Canonical teaching path for library primitives. These smoke checks exercise crypto and
heartbeat JSON locally; point the agent binary at Pion when you are ready for a live control
plane.

## 1. Identity crypto — `identity_seal`

Verify sealed-box encryption and Ed25519 directive signing before wiring handoff directives
(`ReEnroll` / `Revoke`) against Pion.

```bash
export CARGO_BUILD_JOBS=1
export CARGO_TARGET_DIR=target-parton
cargo run -p parton --example identity_seal
```

Success: stdout prints `sealed-box: recipient_pk=… ciphertext_len=… roundtrip_ok=true` and
`directive: signature=… valid=true tampered_rejected=true`.

Look next at `identity_seal.rs` for `seal_to_recipient`, `unseal_with_box_secret`,
`directive_sign`, and `directive_verify`.

## 2. Heartbeat report — `heartbeat_report`

Inspect the JSON shape of `NodeHeartbeatReport` before pointing the agent at a Pion ingest URL.

```bash
cargo run -p parton --example heartbeat_report -- my-node-id my-cell-id
```

Success: pretty JSON for the report, then a summary line like
`-- collected N container(s); M running` (counts depend on local Docker state; defaults
`example-node` / `local-default` when args are omitted).

Look next at `heartbeat_report.rs` and `build_heartbeat_report`, then compare the output to
what Pion expects at `PARTON_HEARTBEAT_URL`.
