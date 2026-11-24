# 02 — Traffic & engines

Logical traffic decisions, distinct from the management workflow.

[← Visual atlas](README.md) · [Authority visual atlas](https://github.com/VY-Groups/gatewaycore-license-authority/tree/docs/visual-authority-atlas/docs/diagrams)

> Source snapshot: `6c24dbbab53718102cd96c6380bbe15263a36fe9` (commercial development candidate, not a production release). Diagrams are logical views, not physical deployment instructions. Optional integrations must be explicitly provisioned. See the linked source and exact-head CI before treating any behavior as accepted.

## L7 HTTP request lifecycle
```mermaid
flowchart TD
R["HTTP(S) request"] --> L["Configured traffic listener and route"]
L --> E{"Commercial L7 admission active?"}
E -->|No| D["Deny new traffic"]
E -->|Yes| Q{"Local concurrency / rate quota permits?"}
Q -->|No| X["429 or configured shared quota 503"]
Q -->|Yes| M{"Matching route and eligible destinations?"}
M -->|No route| N["404"]
M -->|All down with strict policy| S["503"]
M -->|Yes| P["Filter draining and health state"]
P --> B["Session affinity / balancing policy"]
B --> A{"Destination admission permit?"}
A -->|No| J["Bounded queue / rejection"]
A -->|Yes| U["YARP forwards to selected origin"]
U --> V["Return response; release permits; record telemetry"]
```

Logical decision view; not an exact middleware order or universal HTTP status contract. No automatic replay of non-idempotent requests. Health/affinity settings affect eligible selection.

**Source at candidate:** [control-center/Program.cs](https://github.com/VY-Groups/yarp-lb/blob/6c24dbbab53718102cd96c6380bbe15263a36fe9/control-center/Program.cs) · [control-center/docs/L7_LIFECYCLE_OBSERVABILITY.md](https://github.com/VY-Groups/yarp-lb/blob/6c24dbbab53718102cd96c6380bbe15263a36fe9/control-center/docs/L7_LIFECYCLE_OBSERVABILITY.md) · [control-center/docs/PROXY_OVERLOAD_RECOVERY.md](https://github.com/VY-Groups/yarp-lb/blob/6c24dbbab53718102cd96c6380bbe15263a36fe9/control-center/docs/PROXY_OVERLOAD_RECOVERY.md)

## Load balancing and health
```mermaid
flowchart TD
H["Active probes / passive transport failures"] --> F["Configured health policy"]
F --> E["Available non-draining destinations"]
E --> P{"Cluster policy"}
P --> R["RoundRobin / LeastRequests / PowerOfTwoChoices"]
P --> W["WeightedRandom"]
P --> I["SourceIpHash: weighted rendezvous"]
P --> K["Primary / backup as configured"]
W --> SS["Optional slow-start weight ramp"]
R --> D["Selected origin"]
SS --> D
I --> D
K --> D
```

```mermaid
stateDiagram-v2
[*] --> Unhealthy: RiseFall startup
Unhealthy --> Healthy: configured consecutive successful probes
Healthy --> Unhealthy: configured consecutive failed probes
Healthy --> Healthy: success resets failure streak
Unhealthy --> Unhealthy: failure resets success streak
```

RiseFall is opt-in. Draining is a separate administrative condition; existing forwarded work is not automatically replayed.

**Source at candidate:** [control-center/docs/TRAFFIC_ENGINE.md](https://github.com/VY-Groups/yarp-lb/blob/6c24dbbab53718102cd96c6380bbe15263a36fe9/control-center/docs/TRAFFIC_ENGINE.md) · [control-center/docs/ACTIVE_HEALTH_RISE_FALL.md](https://github.com/VY-Groups/yarp-lb/blob/6c24dbbab53718102cd96c6380bbe15263a36fe9/control-center/docs/ACTIVE_HEALTH_RISE_FALL.md) · [control-center/docs/PRIMARY_BACKUP_ROUTING.md](https://github.com/VY-Groups/yarp-lb/blob/6c24dbbab53718102cd96c6380bbe15263a36fe9/control-center/docs/PRIMARY_BACKUP_ROUTING.md)

## L4 TCP and UDP
```mermaid
flowchart LR
T["TCP client"] --> A["L4 TCP listener"]
A --> B["Bounded new connection admission"]
B --> C["Select non-draining backend; connect-time fallback"]
C <--> D["Bidirectional stream / half-close"]
D --> E["Idle timeout / close"]
U["UDP client"] --> V["UDP listener"]
V --> W{"Existing source IP:port session?"}
W -->|Yes| S["Pinned upstream socket"]
W -->|No| N["Bounded new session / round-robin"]
N --> S
S <--> O["UDP backend"]
S --> Z["Idle sweep"]
```

Independent process; no SNI/TLS termination or cross-process session replication assumed. Commercial entitlement loss can stop new and established forwarding in the candidate.

**Source at candidate:** [engines/L4/README.md](https://github.com/VY-Groups/yarp-lb/blob/6c24dbbab53718102cd96c6380bbe15263a36fe9/engines/L4/README.md) · [docs/OFFLINE_COMMERCIAL_LICENSING.md](https://github.com/VY-Groups/yarp-lb/blob/6c24dbbab53718102cd96c6380bbe15263a36fe9/docs/OFFLINE_COMMERCIAL_LICENSING.md)

## GSLB authoritative DNS and readiness
```mermaid
sequenceDiagram
participant R as Recursive resolver
participant D as Authoritative DNS
participant H as Local probe state
participant O as Independent observers
participant A as Signed agent reports
O-->>D: Fresh signed challenge readiness
A-->>D: Authenticated monotonic health reports
H-->>D: Local readiness and hysteresis
R->>D: UDP or TCP A / AAAA query
D->>D: Validate zone, family, health and configured authority gate
alt Eligible sites
  D->>D: Weighted, failover or configured region selection
  D-->>R: Authoritative answer and TTL
else No eligible site
  D-->>R: Configured all-down response
end
```

Observer/report authority modes are opt-in. DNSSEC and actual public delegation, resolver cache convergence and real regional network validation are separate acceptance requirements.

**Source at candidate:** [engines/GslbDns/README.md](https://github.com/VY-Groups/yarp-lb/blob/6c24dbbab53718102cd96c6380bbe15263a36fe9/engines/GslbDns/README.md) · [engines/GslbObserver/README.md](https://github.com/VY-Groups/yarp-lb/blob/6c24dbbab53718102cd96c6380bbe15263a36fe9/engines/GslbObserver/README.md) · [engines/GslbDns/AuthorityFence.cs](https://github.com/VY-Groups/yarp-lb/blob/6c24dbbab53718102cd96c6380bbe15263a36fe9/engines/GslbDns/AuthorityFence.cs)

## External WAF policy rollout
```mermaid
flowchart TD
P["Candidate CRS policy + exact evidence"] --> A["Two independent signed approvals"]
A --> V["Verify policy digest, scope and revision"]
V --> Q{"External etcd lease authority valid?"}
Q -->|No| N["Reject / reconcile"]
Q -->|Yes| S["Authenticated fenced node A/B operations"]
S --> C{"Both applied and verified?"}
C -->|Yes| R["Receipt / report"]
C -->|No| B["Fenced compensation or unresolved state"]
```

The WAF lease contract is **not** the persistent commercial L7 fleet lock. Policy acceptance is not proof of false-positive rates, real traffic or production performance.

**Source at candidate:** [ops/waf/SIGNED_POLICY_ACCEPTANCE.md](https://github.com/VY-Groups/yarp-lb/blob/6c24dbbab53718102cd96c6380bbe15263a36fe9/ops/waf/SIGNED_POLICY_ACCEPTANCE.md) · [ops/waf/ETCD_QUORUM_FENCING.md](https://github.com/VY-Groups/yarp-lb/blob/6c24dbbab53718102cd96c6380bbe15263a36fe9/ops/waf/ETCD_QUORUM_FENCING.md) · [ops/waf/REMOTE_FENCED_NODE.md](https://github.com/VY-Groups/yarp-lb/blob/6c24dbbab53718102cd96c6380bbe15263a36fe9/ops/waf/REMOTE_FENCED_NODE.md)

## Optional shared quota and telemetry
```mermaid
flowchart LR
A["Gateway A"] --> L["One TLS Redis writer / atomic Lua quota"]
B["Gateway B"] --> L
L --> D{"Result"}
D -->|Within quota| OK["Forward"]
D -->|Cap reached| R["429"]
D -->|Unavailable / uncertain| F["503; no local fallback"]
A <-. "signed bounded counter snapshots; telemetry only" .-> B
```

The Redis experiment is not a v1 HA dependency, distributed session store, or safe automatic replica promotion solution.

**Source at candidate:** [control-center/docs/SHARED_RATE_QUOTA_EXPERIMENT.md](https://github.com/VY-Groups/yarp-lb/blob/6c24dbbab53718102cd96c6380bbe15263a36fe9/control-center/docs/SHARED_RATE_QUOTA_EXPERIMENT.md) · [control-center/docs/PEER_COUNTER_SYNC.md](https://github.com/VY-Groups/yarp-lb/blob/6c24dbbab53718102cd96c6380bbe15263a36fe9/control-center/docs/PEER_COUNTER_SYNC.md)

