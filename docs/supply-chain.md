# Supply chain policy

Parton pins third-party crates through `Cargo.lock` and enforces dependency policy with
[`cargo-deny`](https://github.com/EmbarkStudios/cargo-deny) (`deny.toml`).

## What CI checks

The `deny` job in CI runs `cargo deny check` on every push and pull request to `main`. That covers:

- RustSec advisories (with documented ignores in `deny.toml`)
- Allowed license set
- Allowed crate sources (crates.io only; no unknown registries or Git remotes)

## Rules

1. **Prefer crates.io** for all dependencies.
2. **New Git dependencies** require:
   - An entry in [`deny.toml`](../deny.toml) `[sources].allow-git`
   - A short note in this file (why Git, which rev, migration plan)
3. **Ignored advisories** in [`deny.toml`](../deny.toml) must cite the affected crate and a
   removal trigger (for example, "remove once crate X ships a patched release").

## Advisory ignores

None currently. If an advisory ignore is added, it must include a `reason` in `deny.toml` and
a corresponding entry here.

## Verification

Run locally:

```bash
cargo install cargo-deny --locked
cargo deny check
```

See [`docs/VERIFICATION.md`](VERIFICATION.md) for the full verification command block.
