<p align="center">
  <img src="./assets/banner.svg" alt="Sentinel Runtime" width="800"/>
</p>

<p align="center">
  <strong>Sentinel Runtime — Ring 2 Attestation Engine</strong><br/>
  Process integrity · Hash-chain audit · Signed attestation · NATS decision pipeline
</p>

<p align="center">
  <img src="https://img.shields.io/badge/ring-2%20%E2%80%94%20Audit-purple?style=flat-square"/>
  <img src="https://img.shields.io/badge/language-Go-purple?style=flat-square&logo=go&logoColor=white"/>
  <img src="https://img.shields.io/badge/transport-NATS%20JetStream-purple?style=flat-square"/>
  <img src="https://img.shields.io/badge/crypto-ed25519-purple?style=flat-square"/>
  <img src="https://img.shields.io/badge/ledger-hash--chained-purple?style=flat-square"/>
</p>

---

Runtime attestation engine for Sorabbyngo OS. Verifies process identity, checks runtime integrity, produces signed attestation reports, and publishes findings to the Sentinel decision pipeline via NATS.

---

## Pipeline architecture

```mermaid
graph LR
    KRN["Kernel Events\nsorabbyngo_nodeid.ko\nprocess lineage"] --> ING

    subgraph sr["Sentinel Runtime"]
        ING["ingest\ncmd/ingest\nreads kernel events"]
        DET["detect\ncmd/detect\nhash verify · integrity"]
        ENF["enforce\ncmd/enforce\nL1–L4 response actions"]
        POL["policy\ncmd/policy\nloads · evaluates rules"]
        BUS["bus\ncmd/bus\nNATS pub · sub"]

        ING --> DET --> ENF
        POL --> ENF
        ENF --> BUS
    end

    BUS -->|sorabbyngo.sentinel.threat| NATS["NATS JetStream"]
    BUS -->|sorabbyngo.sentinel.attest| NATS
    BUS -->|sorabbyngo.sentinel.contained| NATS
    NATS --> CHA["chameha"]
    NATS --> BYN["byngox\nsecurity_agent"]

    style KRN fill:#0a000d,stroke:#cc44ff,color:#dd66ff
    style ING fill:#0a000d,stroke:#9922cc,color:#dd66ff
    style DET fill:#0a000d,stroke:#9922cc,color:#dd66ff
    style ENF fill:#0a000d,stroke:#9922cc,color:#dd66ff
    style POL fill:#0a000d,stroke:#9922cc,color:#dd66ff
    style BUS fill:#0a000d,stroke:#cc44ff,color:#dd66ff
    style NATS fill:#060008,stroke:#661188,color:#bb44ee
    style CHA  fill:#060008,stroke:#661188,color:#bb44ee
    style BYN  fill:#060008,stroke:#661188,color:#bb44ee
```

---

## Services

| Service | Binary | Role |
|---|---|---|
| `ingest` | `cmd/ingest` | Reads kernel events, process lineage |
| `detect` | `cmd/detect` | Hash verification, integrity checks |
| `enforce` | `cmd/enforce` | Executes L1–L4 response actions |
| `bus` | `cmd/bus` | NATS publisher and subscriber |
| `policy` | `cmd/policy` | Loads and evaluates policy rules |

---

## Response ladder

| Level | Action | Latency target |
|---|---|---|
| L1 | Monitor — log only | < 1ms |
| L2 | Soft contain — flag + rate limit | < 10ms |
| L3 | Kill + block pattern | < 100ms |
| L4 | Subsystem lockdown | < 500ms |

```mermaid
graph LR
    T["Threat detected"] --> L1["L1 Monitor\nlog only\n< 1ms"]
    L1 -->|confidence rises| L2["L2 Contain\nflag + rate limit\n< 10ms"]
    L2 -->|confirmed threat| L3["L3 Kill\nblock pattern\n< 100ms"]
    L3 -->|coordinated attack| L4["L4 Lockdown\nsubsystem shutdown\n< 500ms"]

    style T  fill:#0a000d,stroke:#cc44ff,color:#dd66ff
    style L1 fill:#0a000d,stroke:#6611aa,color:#cc88ff
    style L2 fill:#0a000d,stroke:#8822bb,color:#cc88ff
    style L3 fill:#0a000d,stroke:#aa33cc,color:#dd66ff
    style L4 fill:#0a000d,stroke:#cc44ff,color:#dd66ff
```

---

## Attestation report

Every verified process produces a signed attestation report published to NATS:

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

---

## NATS subjects

| Subject | Direction | Description |
|---|---|---|
| `sorabbyngo.kcp.>` | Subscribe | Raw kernel events from KCP |
| `sorabbyngo.sentinel.threat` | Publish | High-confidence threats |
| `sorabbyngo.sentinel.contained` | Publish | Contained / monitored events |
| `sorabbyngo.sentinel.attest` | Publish | Signed attestation reports |
| `sorabbyngo.sentinel.learned` | Publish | Learning updates |

---

## Build and run

```bash
# Build all services
go build ./cmd/ingest
go build ./cmd/detect
go build ./cmd/enforce
go build ./cmd/bus
go build ./cmd/policy

# Run full runtime
./sentinel-runtime
```

---

## Related repositories

| Repo | Ring | Role |
|---|:---:|---|
| `security` | — | 7-ring master architecture |
| `sorabbyngo-cyberwall` | 7 | Publishes threat alerts sentinel consumes |
| `cml` | 4 | Safety filter — sentinel enforces CML decisions |
| `identity-core` | 3 | SUID used in every attestation report |
| `sorabbyngo-os` | 1 | Kernel events — source of all ingest data |
| `byngox` | — | security_agent receives escalation from sentinel |

---

<p align="center">
  <strong>Sorabbyngo Company</strong> · Kisii, Kenya · 2026<br/>
  <em>Rhythm of Digital Life</em>
</p>
