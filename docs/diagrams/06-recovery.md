# 06 — HA, DR & key protection

Operator-managed failover and recovery boundaries. No physical readiness claim.

[← Visual atlas](README.md) · [Authority visual atlas](https://github.com/VY-Groups/gatewaycore-license-authority/tree/docs/visual-authority-atlas/docs/diagrams)

> Source snapshot: `6c24dbbab53718102cd96c6380bbe15263a36fe9` (commercial development candidate, not a production release). Diagrams are logical views, not physical deployment instructions. Optional integrations must be explicitly provisioned. See the linked source and exact-head CI before treating any behavior as accepted.

## Active-active traffic and node failure
```mermaid
flowchart LR
C["Clients"] --> VIP["Health-aware upstream ingress"]
VIP --> A["Gateway A active"]
VIP --> B["Gateway B active"]
A --> O1["Origin A"]
A --> O2["Origin B"]
B --> O1
B --> O2
A -. "if unhealthy: external ingress ejects A" .-> X["A unavailable"]
VIP -. "new requests to survivor after detection" .-> B
```

Real independent-host VIP/ECMP, ingress redundancy and application idempotence are external acceptance. Existing connections may fail; no automatic replay of non-idempotent calls.

**Source at candidate:** [control-center/docs/V1_HA_SCOPE.md](https://github.com/VY-Groups/yarp-lb/blob/6c24dbbab53718102cd96c6380bbe15263a36fe9/control-center/docs/V1_HA_SCOPE.md) · [control-center/docs/FAILOVER_POLICY.md](https://github.com/VY-Groups/yarp-lb/blob/6c24dbbab53718102cd96c6380bbe15263a36fe9/control-center/docs/FAILOVER_POLICY.md)

## DC/DR design
```mermaid
flowchart TB
D["Authoritative DNS / site decision"] --> DC["DC ingress"]
D --> DR["DR ingress"]
subgraph A["DC — external infrastructure"]
 DC --> G1["Gateway nodes"]
 G1 --> APP["Application services"]
 APP --> DB1[("Application database primary")]
end
subgraph B["DR — external infrastructure"]
 DR --> G2["Gateway nodes"]
 G2 --> APP2["Application services"]
 APP2 --> DB2[("Application database replica")]
end
DB1 -. "operator-managed replication and database failover" .-> DB2
OP["Independent operational acceptance"] -.-> D
OP -.-> DB2
```

Logical reference only. GatewayCore does not promote or reconcile application databases. Validate DNS cache convergence, application readiness and replication independently.

**Source at candidate:** [control-center/docs/ARCHITECTURE.md](https://github.com/VY-Groups/yarp-lb/blob/6c24dbbab53718102cd96c6380bbe15263a36fe9/control-center/docs/ARCHITECTURE.md) · [engines/GslbDns/README.md](https://github.com/VY-Groups/yarp-lb/blob/6c24dbbab53718102cd96c6380bbe15263a36fe9/engines/GslbDns/README.md)

## Protected key and state recovery
```mermaid
flowchart TD
S["Service-owned private state"] --> P{"Platform / explicitly configured mode"}
P -->|Windows| W["DPAPI / approved shared fleet certificate migration"]
P -->|Linux local| L["Protected key ring; wrapping certificate and private paths"]
P -->|Linux distributed opt-in| Q["Pinned etcd members / encrypted key XML"]
W --> B["Protected backups and separate key custody"]
L --> B
Q --> B
B --> F["Fence old authority and inspect intended restore"]
F --> V{"Identity, trust, monotonic state, decrypt and application tests pass?"}
V -->|No| N["Keep fenced; independent recovery"]
V -->|Yes| R["Reviewed service restoration"]
```

```mermaid
flowchart LR
R["DP reader"] --> Q["Matching linearizable encrypted-ring reads"]
W["Explicit writer"] --> C["Create-only CAS checks pinned writer epoch"]
C --> Q
Q --> E["Encrypted XML; approved wrapping recipients"]
Q -. "minority / invalid writer" .-> X["Refuse operation; no local fallback"]
```

This is separate from commercial installation key protection and L7 fleet fencing. Neither filesystem backups nor logical test recovery prove whole-snapshot anti-rollback or site RPO/RTO.

**Source at candidate:** [control-center/docs/DATA_PROTECTION_PLATFORM_SUPPORT.md](https://github.com/VY-Groups/yarp-lb/blob/6c24dbbab53718102cd96c6380bbe15263a36fe9/control-center/docs/DATA_PROTECTION_PLATFORM_SUPPORT.md) · [ops/fleet/LINUX_DP_DISTRIBUTED_RUNTIME.md](https://github.com/VY-Groups/yarp-lb/blob/6c24dbbab53718102cd96c6380bbe15263a36fe9/ops/fleet/LINUX_DP_DISTRIBUTED_RUNTIME.md) · [ops/fleet/LINUX_DP_QUORUM_AUTHORITY.md](https://github.com/VY-Groups/yarp-lb/blob/6c24dbbab53718102cd96c6380bbe15263a36fe9/ops/fleet/LINUX_DP_QUORUM_AUTHORITY.md)

## Physical acceptance
```mermaid
flowchart TD
S["Frozen verified software candidate"] --> H["Independent hosts / real ingress / production-like PKI"]
H --> C["Solo capacity on each gateway; 60 min and agreed headroom"]
H --> F["Node kill, link partition, ingress and backend failover"]
H --> R["Backup, key restore and rollback"]
H --> M["Monitoring, security, application readiness"]
C --> A["Independent evidence review"]
F --> A
R --> A
M --> A
A --> G{"All operational gates passed?"}
G -->|No| N["NO-GO; record gaps"]
G -->|Yes| Y["Authorized deployment decision"]
```

See [issue #36](https://github.com/VY-Groups/yarp-lb/issues/36) and official acceptance runbooks. No physical tests were performed by creating these diagrams.

**Source at candidate:** [ops/release/README.md](https://github.com/VY-Groups/yarp-lb/blob/6c24dbbab53718102cd96c6380bbe15263a36fe9/ops/release/README.md) · [control-center/docs/ONPREM_PRODUCTION_GO_GATES.md](https://github.com/VY-Groups/yarp-lb/blob/6c24dbbab53718102cd96c6380bbe15263a36fe9/control-center/docs/ONPREM_PRODUCTION_GO_GATES.md)

