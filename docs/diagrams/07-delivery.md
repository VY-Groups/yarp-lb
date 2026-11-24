# 07 — Build, test & release

Source to acceptance. No automatic production deployment.

[← Visual atlas](README.md) · Authority visual atlas — `gatewaycore-license-authority:docs/diagrams/README.md`

> Source snapshot: `6c24dbbab53718102cd96c6380bbe15263a36fe9` (commercial development candidate, not a production release). Diagrams are logical views, not physical deployment instructions. Optional integrations must be explicitly provisioned. See the linked source and exact-head CI before treating any behavior as accepted.

## Customer licensing stack and authority integration
```mermaid
flowchart TD
M["Customer main"] --> A["#546 offline commercial licensing"]
A --> B["#547 fleet installation and site proof"]
B --> C["#548 revoked recovery and fresh fleet proof"]
C --> D["#549 persistent quorum fencing"]
AM["Authority main: merged #1–#5"] --> AX["Authority #6 integrated candidate tests"]
D -. "exact pinned customer source" .-> AX
D --> V["Review + exact-head green CI + dependency-order integration"]
AX --> V
V --> F["Freeze final merged customer SHA; repin authority tests"]
F --> S["Company signing ceremony and package integrity"]
S --> P["Controlled software test candidate"]
P --> H["Issue #36 physical and operational acceptance"]
```

This is a dependency map, not live PR status. Check PRs and CI links before merging or releasing. Historical public-source licensing obligations and owner-approved commercial terms remain separate.

**Source at candidate:** `docs/OFFLINE_COMMERCIAL_LICENSING.md` (source 6c24dbb) · `ops/release/README.md` (source 6c24dbb)

## CI gate and release
```mermaid
flowchart TD
P["PR exact head SHA"] --> B["Build / static / security checks"]
P --> T["Real process, socket and browser integration"]
P --> Q["Quorum, recovery, HA and performance harnesses"]
B --> G{"All required checks green on exact SHA?"}
T --> G
Q --> G
G -->|No| F["Fix and rerun; no stale results"]
G -->|Yes| R{"Independent approval and dependencies?"}
R -->|No| W["Hold"]
R -->|Yes| M["Merge in dependency order"]
M --> V["Recheck merged main SHA"]
V --> S["Freeze reviewed candidate"]
S --> K["Separate company release signing"]
K --> H["Physical / operational signoff"]
```

Individual job graphs are in the [CI catalog](08-ci-index.md). The catalog is source-derived; green run status is not inferred.

**Source at candidate:** `docs/CI_SCOPE.md` (source 6c24dbb) · `control-center/docs/RELEASE_GATES.md` (source 6c24dbb) · `ops/release/README.md` (source 6c24dbb)

