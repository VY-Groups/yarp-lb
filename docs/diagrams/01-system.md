# 01 — System & deployment

Architectural context and responsibility boundaries.

[← Visual atlas](README.md) · [Authority visual atlas](https://github.com/VY-Groups/gatewaycore-license-authority/tree/docs/visual-authority-atlas/docs/diagrams)

> Source snapshot: `6c24dbbab53718102cd96c6380bbe15263a36fe9` (commercial development candidate, not a production release). Diagrams are logical views, not physical deployment instructions. Optional integrations must be explicitly provisioned. See the linked source and exact-head CI before treating any behavior as accepted.

## Logical network and trust zones
```mermaid
flowchart TB
I["External clients"] --> F["Operator firewall / ACL"]
F --> PUB["Public traffic listener"]
INT["Internal clients"] --> PRIV["Restricted traffic listener"]
PUB --> W["Optional external WAF / ingress"]
W --> A["Gateway A"]
PRIV --> A
W --> B["Gateway B"]
PRIV --> B
A --> AP["IIS / Apache / Nginx / Tomcat / APIs"]
B --> AP
AP --> DB["Existing application DB / Pgpool / services"]
M["Administrator via management network"] --> MC["Separate management listener / Control Center"]
MC --> AG["Authenticated gateway agents"]
AG --> A
AG --> B
MC -.-> AUD["Independent audit collector"]
A -.-> MET["Local metrics / optional OTLP"]
B -.-> MET
PKI["CA/HSM/signing services"] -. "separate authorization and network controls" .-> AP
```

GatewayCore does not own the application database, firewall, HSM, or external VIP. Listener segregation is configured, not a replacement for network ACLs.

**Source at candidate:** [control-center/docs/ARCHITECTURE.md](https://github.com/VY-Groups/yarp-lb/blob/6c24dbbab53718102cd96c6380bbe15263a36fe9/control-center/docs/ARCHITECTURE.md) · [control-center/docs/WEB_SERVER_BACKENDS.md](https://github.com/VY-Groups/yarp-lb/blob/6c24dbbab53718102cd96c6380bbe15263a36fe9/control-center/docs/WEB_SERVER_BACKENDS.md) · [control-center/docs/EXTERNAL_INTEGRATION_ACCEPTANCE.md](https://github.com/VY-Groups/yarp-lb/blob/6c24dbbab53718102cd96c6380bbe15263a36fe9/control-center/docs/EXTERNAL_INTEGRATION_ACCEPTANCE.md)

## Deployment modes
```mermaid
flowchart TB
subgraph S["Standalone"]
  C1["Client"] --> G1["Gateway + local controller"]
  G1 --> O1["Origins"]
end
subgraph H["HA pair — intended topology"]
  C2["Clients"] --> V["External health-aware VIP / ECMP"]
  V --> G2["Active A"]
  V --> G3["Active B"]
  G2 --> O2["Shared healthy origins"]
  G3 --> O2
  M2["Controller"] -. "signed management" .-> G2
  M2 -. "signed management" .-> G3
end
subgraph F["Fleet — intended topology"]
  C3["Clients"] --> E["Ingress per zone"]
  E --> N1["Active gateway 1"]
  E --> N2["Active gateway 2"]
  E --> N3["Active gateway 3+"]
  M3["Authorized controller(s)"] -.-> N1
  M3 -.-> N2
  M3 -.-> N3
end
```

All data-plane gateways are active peers; controller ownership is separate. The topology API stores design metadata only. A multi-controller desired-state database and physical ingress are not created by onboarding.

**Source at candidate:** [control-center/Onboarding.cs](https://github.com/VY-Groups/yarp-lb/blob/6c24dbbab53718102cd96c6380bbe15263a36fe9/control-center/Onboarding.cs) · [control-center/docs/V1_HA_SCOPE.md](https://github.com/VY-Groups/yarp-lb/blob/6c24dbbab53718102cd96c6380bbe15263a36fe9/control-center/docs/V1_HA_SCOPE.md)

## Component ownership
```mermaid
flowchart LR
C["Control Center"] --> L7["YARP L7"]
C --> Agent["Gateway Agent"]
Agent -. "separate signed config contract" .-> L4["Standalone L4"]
Agent -. "separate signed config contract" .-> DNS["Standalone GSLB DNS"]
DNS --> Obs["External readiness observers"]
L7 -.-> Q["Optional Redis quota"]
L7 -.-> Audit["Audit collector"]
Ingress["External ingress"] --> WAF["External ModSecurity CRS"]
WAF --> L7
```

Separate binaries and optional integrations have distinct configuration, credentials and acceptance gates. This is not a single automatically installed appliance.

**Source at candidate:** [engines/L4/README.md](https://github.com/VY-Groups/yarp-lb/blob/6c24dbbab53718102cd96c6380bbe15263a36fe9/engines/L4/README.md) · [engines/GslbDns/README.md](https://github.com/VY-Groups/yarp-lb/blob/6c24dbbab53718102cd96c6380bbe15263a36fe9/engines/GslbDns/README.md) · [engines/GslbObserver/README.md](https://github.com/VY-Groups/yarp-lb/blob/6c24dbbab53718102cd96c6380bbe15263a36fe9/engines/GslbObserver/README.md) · [control-center/docs/ENGINE_GATES.md](https://github.com/VY-Groups/yarp-lb/blob/6c24dbbab53718102cd96c6380bbe15263a36fe9/control-center/docs/ENGINE_GATES.md)

