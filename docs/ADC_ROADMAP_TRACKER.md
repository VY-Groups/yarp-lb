# ADC roadmap requirements tracker

Baseline: customer main 961b4385f68f535671c48de6d3b3d4fc03220542, frozen candidate run 46130189104 (33/33). The completed software candidate is not completion of broader ADC roadmap. Scope below follows the owner-directed order; no new runtime capability is implied by UI exposure. Physical and production acceptance is tracked only in #36.

## Phase 1 — ADC frontend redesign

Current comparison: Overview has a route-to-cluster-to-destination snapshot but no dedicated ADC navigation, search or contextual direct operations. Reusable objects exist as snapshots. Independent engines and host bindings must not be conflated with route objects. The capability register contains older baseline terminology and is not live deployment evidence. Existing reviewed editor and API contracts must be reused; no direct live-write shortcut.

| ID | Requirement and acceptance | Evidence implementation | Gate status |
|---|---|---|---|
| P1-01 | Dedicated responsive service-map navigation; approved revision and draft state visible; show actual route, listener reference, cluster, policy, member address/weight/role/configured state, empty and unreferenced groups. Search by route/host/group/member. Never imply live VIP/health. | app.ts/app.js, index.html, style.css; existing Chromium + live Kestrel test | Implemented; CI and review pending |
| P1-02 | Direct route/group/member/policy/monitor/persistence/listener actions use existing reviewed editors; drain/resume and enable/disable remain local draft; cancellation and reload preserve approved state. Viewer has no map mutation affordances. | ADC browser workflow in tests/E2E/management.spec.mjs; existing API change approval tests | Implemented; CI and review pending |
| P1-03 | API-backed explicit implemented/partial/unavailable coverage; list scope limits and evidence reference; separate L4/DNS and snapshot catalogs; no feature-deployment or production claim. | CapabilityRegistry.cs; real_control_center.py and Chromium feature coverage checks | Implemented; CI and review pending |
| P1-04 | Authenticated API: anonymous access denied, all roles inspect same approved state, no mutation on map/coverage inspection; approval workflow requires different administrator; browser shows approved route and read-only Viewer after approval. | real_control_center.py + management.spec.mjs; existing real API approval/RBAC/CSRF tests | Implemented; CI and review pending |
| P1-05 | Exact-head Windows/Linux build, frontend reproducibility, real Chromium and API checks, no regressions, independent approval, merged-main verification. Capture exact head/run evidence before marking phase complete. | control-center-ci.yml, e2e-real-control-center.yml, required repository checks | Pending |

## Later phases (do not start before Phase 1 acceptance)

| Phase | Current state | Remaining acceptance |
|---|---|---|
| 2 Virtual servers and reusable objects | Partial: isolated L7 sockets, reusable catalogs, independent snapshots and signed fleet materialization | Typed L4/L7 registry and conflicts, safe object-reference lifecycle, migration, deletion guards, runtime binding/rollback and browser/API tests |
| 3 Advanced balancing and persistence | Partial: tested bounded HTTP/TCP algorithms and secure HTTPS affinity | Complete agreed advanced profiles, protocol-specific selection and persistence, expiration/recovery, actual runtime and failover evidence |
| 4 Health monitors and templates | Partial: HTTP/TCP compound probes and reusable snapshots | Bounded protocol-specific monitors, reusable lifecycle, validated application templates and positive/negative actual traffic |
| 5 Network management | Partial: inventory, Linux VLAN observation, VIP fencing | Authorized platform IP/interface/VLAN/routing/NAT/SNAT lifecycle, preflight, journal/rollback and actual OS tests; physical environment under #36 |
| 6 Security and access | Partial: TLS/CIDR, WAF, quotas; app SSO unavailable | Application identity-aware access, policy enforcement, isolation, security regressions, bounded admission and upstream mitigation; no appliance throughput claim |
| 7 Observability, CLI, SOP and training | Partial: local telemetry, diagnostics CLI and operator manual | Unified service analytics, scoped CLI, audit/privacy, validated offline docs and training workflows, final integrated regression and release handoff |

Every implementation item requires a reviewed PR, exact-head evidence, backend/API/browser/traffic tests as appropriate, no weakening of security/approval or production gates, and merged-main verification. Update this tracker with exact commit and workflow links after review. Earlier frozen artifacts remain the physical-test baseline until a new candidate is explicitly accepted.
