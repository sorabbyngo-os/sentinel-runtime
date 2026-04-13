# sentinel-runtime

> Part of the SORABBYNGO OS Security & Control Layer (SCL)

Runtime attestation engine for Sorabbyngo OS. Verifies process identity, checks runtime integrity, produces signed attestation reports, and publishes findings to the Sentinel decision pipeline via NATS.

## Architecture
┌─────────────────────────────────────────────────────┐
│                  sentinel-runtime                    │
│                                                      │
│  ingest ──► detect ──► enforce ──► bus               │
│    │           │           │        │                │
│  kernel      hash        policy    NATS              │
│  events    verify       execute  publish             │
└─────────────────────────────────────────────────────┘

## Services

| Service | Binary | Role |
|---------|--------|------|
| `ingest` | `cmd/ingest` | Reads kernel events, process lineage |
| `detect` | `cmd/detect` | Hash verification, integrity checks |
| `enforce` | `cmd/enforce` | Executes L1-L4 response actions |
| `bus` | `cmd/bus` | NATS publisher/subscriber |
| `policy` | `cmd/policy` | Loads and evaluates policy rules |

## NATS Subjects

| Subject | Direction | Description |
|---------|-----------|-------------|
| `sorabbyngo.kcp.>` | Subscribe | Raw kernel events from KCP |
| `sorabbyngo.sentinel.threat` | Publish | High-confidence threats |
| `sorabbyngo.sentinel.contained` | Publish | Contained/monitored events |
| `sorabbyngo.sentinel.attest` | Publish | Attestation reports |
| `sorabbyngo.sentinel.learned` | Publish | Learning updates |

## Attestation Report

Every verified process produces a signed attestation:

```json
{
  "pid":        1234,
  "comm":       "python3",
  "exe_hash":   "sha256:abc123...",
  "node_id":    "fc035f19...",
  "sealed":     true,
  "response":   "L2_CONTAIN",
  "confidence": 0.87,
  "timestamp":  1712345678,
  "signature":  "ed25519:..."
}
```

## Response Ladder

| Level | Action | Latency Target |
|-------|--------|----------------|
| L1 | Monitor — log only | <1ms |
| L2 | Soft contain — flag + rate limit | <10ms |
| L3 | Kill + block pattern | <100ms |
| L4 | Subsystem lockdown | <500ms |

## Build

```bash
go build ./cmd/ingest
go build ./cmd/detect
go build ./cmd/enforce
go build ./cmd/bus
go build ./cmd/policy
```

## Run

```bash
# Start full runtime
./sentinel-runtime
```

## Security

- All attestation reports signed with Ed25519 node key
- NodeID from `/proc/sorabbyngo/nodeid` seals reports to device
- Policy files verified before loading (Ed25519)
- Audit trail append-only, hash-chained

## Status

🚧 Active Development — SCL Phase 1

## License

Proprietary — © SORABBYNGO Labs
