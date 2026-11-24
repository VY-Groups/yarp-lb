# 03 — Control Center & security

Identity, approval, configuration, certificates and observability.

[← Visual atlas](README.md) · [Authority visual atlas](https://github.com/VY-Groups/gatewaycore-license-authority/tree/docs/visual-authority-atlas/docs/diagrams)

> Source snapshot: `6c24dbbab53718102cd96c6380bbe15263a36fe9` (commercial development candidate, not a production release). Diagrams are logical views, not physical deployment instructions. Optional integrations must be explicitly provisioned. See the linked source and exact-head CI before treating any behavior as accepted.

## Sign-in and administrative access
```mermaid
flowchart TD
S["Management HTTPS listener"] --> A{"Configured identity mode"}
A -->|Local / directory| L["Password / optional configured OTP"]
A -->|Enterprise OIDC| O["Authorization code + PKCE at IdP"]
O --> V["Validate signed claims and configured assurance"]
L --> C["Authenticated session cookie"]
V --> C
C --> P{"Current privacy notice accepted?"}
P -->|No| N["Review exact notice; CSRF-protected acceptance"]
N --> P
P -->|Yes| R{"Role and step-up permit action?"}
R -->|No| D["401 / 403 / 428 as applicable"]
R -->|Yes| U["Management API"]
U --> E{"Commercial feature gate, if enabled"}
E -->|Denied| X["402 except defined recovery endpoints"]
E -->|Allowed| G["Authorized operation"]
```

Logical gates rather than literal middleware order. Viewer cannot perform ordinary mutations; approved recovery exceptions are deliberately narrow. IdP owns passkey verification. Notice acknowledgement is not a legal compliance certification.

**Source at candidate:** [control-center/Program.cs](https://github.com/VY-Groups/yarp-lb/blob/6c24dbbab53718102cd96c6380bbe15263a36fe9/control-center/Program.cs) · [control-center/ManagementPrivacyPolicy.cs](https://github.com/VY-Groups/yarp-lb/blob/6c24dbbab53718102cd96c6380bbe15263a36fe9/control-center/ManagementPrivacyPolicy.cs) · [control-center/docs/ENTERPRISE_OIDC.md](https://github.com/VY-Groups/yarp-lb/blob/6c24dbbab53718102cd96c6380bbe15263a36fe9/control-center/docs/ENTERPRISE_OIDC.md)

## Reviewed configuration
```mermaid
sequenceDiagram
actor A as Requester
actor B as Independent administrator
participant C as Control Center
participant J as Change state / audit
participant R as Runtime configuration
A->>C: Create draft routes and clusters
C->>C: Validate schema and revision
C->>J: Persist pending change
B->>C: Review exact proposal
alt Rejected or stale
  C->>J: Record refusal
else Approved and authorized apply
  C->>J: Confirm audit intent where configured
  C->>R: Save reviewed configuration
  R-->>C: Runtime reload observation
  C->>J: Record outcome
end
```

For remote fleet changes use the separate [quorum sequence](05-fencing.md); local change approval is not proof of every remote activation or application health.

**Source at candidate:** [control-center/Program.cs](https://github.com/VY-Groups/yarp-lb/blob/6c24dbbab53718102cd96c6380bbe15263a36fe9/control-center/Program.cs) · [control-center/docs/API_CONTRACT.md](https://github.com/VY-Groups/yarp-lb/blob/6c24dbbab53718102cd96c6380bbe15263a36fe9/control-center/docs/API_CONTRACT.md)

## External audit
```mermaid
sequenceDiagram
participant G as Gateway
participant C as Independent audit collector
participant L as Append-only signed ledger
participant W as Optional object-lock store
G->>C: HTTPS intent + node HMAC + exact state digests
C->>C: Validate identity, time, schema and replay
C->>L: Append and flush signed entry
opt Configured independent retention
  C->>W: Conditional object put and verify exact retention
end
C-->>G: RSA-PSS signed receipt
alt Receipt valid
  G->>G: Recheck plan and perform mutation
else Missing or invalid
  G->>G: Fail closed; no mutation
end
```

The receipt proves the accepted intent, not application of the later write. Retention enforcement and external provider trust require operational verification.

**Source at candidate:** [engines/AuditCollector/README.md](https://github.com/VY-Groups/yarp-lb/blob/6c24dbbab53718102cd96c6380bbe15263a36fe9/engines/AuditCollector/README.md) · [control-center/docs/EXTERNAL_AUDIT_INTENT.md](https://github.com/VY-Groups/yarp-lb/blob/6c24dbbab53718102cd96c6380bbe15263a36fe9/control-center/docs/EXTERNAL_AUDIT_INTENT.md)

## TLS and ACME
```mermaid
flowchart TD
T["Renewal coordinator; configured renewal window"] --> D{"Due?"}
D -->|No| W["Wait / periodic checks"]
D -->|Yes| C{"Explicit challenge mode"}
C -->|HTTP-01| H["Bounded traffic challenge store"]
C -->|DNS-01| N["Pinned nsupdate + scoped TSIG TXT update"]
N --> P["Independent authoritative TCP TXT readiness"]
H --> A["ACME order / signed certificate"]
P --> A
A --> V["Validate chain, SAN, EKU, key and validity"]
V --> S["Stage PFX and atomic replacement"]
S --> X{"Listener selects new leaf?"}
X -->|Yes| K["Keep new certificate; exact cleanup"]
X -->|No| R["Restore last-good PFX"]
```

Both are explicitly configured opt-in paths; external CA/domain/TSIG interoperability, multi-node issuance and custody require real acceptance.

**Source at candidate:** [control-center/docs/ACME_IMPLEMENTATION_STATUS.md](https://github.com/VY-Groups/yarp-lb/blob/6c24dbbab53718102cd96c6380bbe15263a36fe9/control-center/docs/ACME_IMPLEMENTATION_STATUS.md) · [control-center/AcmeRenewal.cs](https://github.com/VY-Groups/yarp-lb/blob/6c24dbbab53718102cd96c6380bbe15263a36fe9/control-center/AcmeRenewal.cs)

## Observability
```mermaid
flowchart LR
P["L7 request lifecycle"] --> M["Bounded local metrics"]
P --> L["Nonblocking access logging"]
P --> T["Sampled tracing"]
M --> Prom["Local Prometheus collector"]
T --> O["Optional OTLP batch exporter"]
M --> O
L --> O
Prom --> Dash["Grafana / alerting"]
O --> Col["Protected OTLP collector"]
Col --> Dash
O -. "export outage: bounded queue/drop" .-> Drop["Observe loss counters"]
```

Metrics are not approval records; no telemetry dependency on the per-request license path. External monitoring and alert delivery need deployment acceptance.

**Source at candidate:** [control-center/docs/OTEL_EXPORT.md](https://github.com/VY-Groups/yarp-lb/blob/6c24dbbab53718102cd96c6380bbe15263a36fe9/control-center/docs/OTEL_EXPORT.md) · [control-center/docs/NONBLOCKING_LOGGING.md](https://github.com/VY-Groups/yarp-lb/blob/6c24dbbab53718102cd96c6380bbe15263a36fe9/control-center/docs/NONBLOCKING_LOGGING.md)

