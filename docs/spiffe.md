# SPIFFE / SPIRE workload identity (Parton agent)

SPIFFE JWT-SVID **presentation is implemented** in Parton. Standing up SPIRE (install,
registration policies, JWT key distribution) remains an operator concern.

## SPIFFE ID convention

```text
spiffe://{trust_domain}/parton/node/{node_id}
```

Must match `PARTON_NODE_ID` and the control plane's configured SPIFFE trust domain.

## `PARTON_AUTH_MODE`

| Value | Behavior |
|---|---|
| `shared_token` (default) | Send `x-parton-token` only |
| `dual` | Send shared token when set; also attach JWT-SVID when available |
| `spiffe` | Require a JWT-SVID (fail the request if none can be fetched) |

JWT sources (first wins): `PARTON_SPIFFE_JWT`, `PARTON_SPIFFE_JWT_PATH`, then
`spire-agent api fetch jwt` via `SPIFFE_ENDPOINT_SOCKET`.
