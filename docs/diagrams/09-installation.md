# 09 — Installation, onboarding and configuration as code

[← Visual atlas](README.md)

Source snapshot: `6c24dbbab53718102cd96c6380bbe15263a36fe9`. These are controlled testing and operator workflows, not automatic production deployment.

## Windows offline installation / test upgrade

```mermaid
flowchart TD
A["Reviewed Windows test package and dependencies"] --> B["Verify source / package, stop old test process"]
B --> C["Back up existing app and private state independently"]
C --> D{"Fresh install or verified same test identity?"}
D -->|Fresh| E["Extract into fresh directory"]
D -->|Same identity| F["Explicit state reuse after matching origin/config checks"]
D -->|Mismatch| X["Stop; reconcile, never overwrite identities"]
E --> G["Offline precheck / configured loopback origin"]
F --> G
G --> H["Start isolated GatewayCore"]
H --> I["Verify liveness, actual origin response and dashboard"]
I --> J{"Acceptance passed?"}
J -->|No| R["Stop and restore reviewed lab backup"]
J -->|Yes| T["Controlled test only"]
```

The Windows test package is distinct from the commercial signed package. Existing state is not automatically overwritten. Health 200 is liveness, not upstream readiness. No firewall, IIS or database modification is implied.

**Source:** [ops/windows-test/README.md](https://github.com/VY-Groups/yarp-lb/blob/6c24dbbab53718102cd96c6380bbe15263a36fe9/ops/windows-test/README.md) · [control-center/docs/SETUP_CHECKLIST.md](https://github.com/VY-Groups/yarp-lb/blob/6c24dbbab53718102cd96c6380bbe15263a36fe9/control-center/docs/SETUP_CHECKLIST.md)


## Ubuntu disposable Docker laboratory

```mermaid
flowchart LR
S["Reviewed source + dependencies"] --> D["Docker Compose test kit"]
D --> I["nginx ingress"]
I --> A["Gateway A container"]
I --> B["Gateway B container"]
A --> O["Disposable HTTP origins"]
B --> O
T["Separate test generator"] --> I
I -. "restricted management / metrics" .-> X["403 expected through ingress"]
A --> E["Evidence: smoke, logs, counters"]
B --> E
E --> R["Preserve evidence; stop test stack"]
```

One Docker host is not two physical HA hosts. Use a separate load generator for capacity evidence and retain raw results.

**Source:** [ops/test-server/README.md](https://github.com/VY-Groups/yarp-lb/blob/6c24dbbab53718102cd96c6380bbe15263a36fe9/ops/test-server/README.md)


## Architecture onboarding

```mermaid
stateDiagram-v2
[*] --> NotStarted
NotStarted --> Draft: save validated design
Draft --> Draft: edit with current revision
Draft --> DesignConfirmed: confirm after validation
DesignConfirmed --> Draft: reviewed design edit
Draft --> Draft: stale revision rejected
DesignConfirmed --> DesignConfirmed: stale revision rejected
```

This state machine deliberately has no deployed state. Onboarding validates and stores metadata; actual routing changes use reviewed changes.

**Source:** [control-center/Onboarding.cs](https://github.com/VY-Groups/yarp-lb/blob/6c24dbbab53718102cd96c6380bbe15263a36fe9/control-center/Onboarding.cs) · [control-center/docs/ARCHITECTURE.md](https://github.com/VY-Groups/yarp-lb/blob/6c24dbbab53718102cd96c6380bbe15263a36fe9/control-center/docs/ARCHITECTURE.md)


## Offline GitOps-style planning and Gateway API import

```mermaid
flowchart TD
A["Reviewed desired schema-1 JSON"] --> V["Offline validate"]
K["Exported Kubernetes Gateway API V1 subset"] --> I["Offline importer: supported listener / route / service / ReferenceGrant"]
I --> V
V -->|Invalid or unsupported| X["Reject"]
V -->|Valid| P["Read-only plan against current JSON"]
P --> R["ID-only diff for Git review"]
R --> S["Operator submits validated desired change"]
S --> D["Separate administrator approval"]
D --> E["Reviewed Control Center apply / fleet workflow"]
```

The tool has no cluster lookup, watch, live reconciliation, Terraform provider, full Kubernetes controller, or automatic revocation of a changed ReferenceGrant. Import output contains addresses and requires protected storage. Plan/validate output is redacted. Unsupported configuration semantics must be rejected, not silently stripped.

**Source:** [control-center/tools/GatewayConfigPlan/README.md](https://github.com/VY-Groups/yarp-lb/blob/6c24dbbab53718102cd96c6380bbe15263a36fe9/control-center/tools/GatewayConfigPlan/README.md) · [control-center/tools/GatewayConfigPlan/PlanEngine.cs](https://github.com/VY-Groups/yarp-lb/blob/6c24dbbab53718102cd96c6380bbe15263a36fe9/control-center/tools/GatewayConfigPlan/PlanEngine.cs) · [control-center/tools/GatewayConfigPlan/GatewayApiImport.cs](https://github.com/VY-Groups/yarp-lb/blob/6c24dbbab53718102cd96c6380bbe15263a36fe9/control-center/tools/GatewayConfigPlan/GatewayApiImport.cs)

