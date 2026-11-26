# ADC feature completion program
Baseline: main 43317115a9594f6f4b580a4bc51417b575906094. This is an independently developed software ADC. Public feature references: https://www.a10networks.com/products/thunder-adc/ and https://documentation.a10networks.com/ACOS-Docs/axapi/607/slb_service_group.html . These references describe expected feature categories, not code, license or UI assets for reuse.

No feature is complete on the basis of a page, schema, capability label or green unrelated CI. Require shipping backend, role-gated UI/API, approval/rollback, positive and negative traffic tests, Windows/Linux checks, independent review, offline packaging and operator SOP. Physical #36 remains separate.

| Area | Baseline / gap | Required acceptance |
|---|---|---|
| ADC GUI | routes, clusters, backends and guide exist; unified ADC object view incomplete | role-aware navigation, real objects, dependencies, draft review, browser workflows |
| Virtual servers/ports | routes and isolated listeners exist separately | typed VIP/service bindings, L4/L7 conflict detection and runtime binding |
| Real servers/service groups | YARP destination/cluster configuration exists; cross-group reusable identity incomplete | typed references, deletion guard, safe migration and actual routing |
| Load algorithms | round robin, least requests, weighted random, source IP, primary/backup exist; this PR adds weighted least HTTP requests | real in-flight/drain test; remaining L4 weighted least connections, weighted RR and measured fastest response require distinct tests |
| Persistence | existing cookie affinity validation and source IP hash | review secure profiles, shared key scope, expiration, failover, multiple protocols |
| Monitors | active/passive HTTP, thresholds, GSLB and L4 engine checks | reusable monitor objects, bounded protocol checks, composite semantics and probe evidence |
| Acceleration | YARP pooling exists; caching/compression parity unverified | opt-in safe public content cache, Vary/private/auth separation, compression/security and performance tests |
| Rules/templates | route transforms and existing config plans | bounded declarative rules with validated actions, no arbitrary scripting or management bypass, app templates |
| Network | separate host listeners and signed agent restart; OS networking management not established | privileged independently authorized host adapter, IP/VIP/routes/VLAN/NAT with atomic rollback and out-of-band recovery |
| HA/DC-DR | existing signed fleet/quorum and staged workflows | dashboard evidence and cross-host traffic/partition/recovery under #36 |
| WAF/DDoS | existing external CRS and quota controls; appliance volumetric mitigation not established | policy isolation and tuning, bounded admission, upstream mitigation integration; no unsupported line-rate claims |
| Access | admin identity/OTP/OIDC exists | application access policies are separate; prove authorization on proxied routes, not merely management login |
| DNS/GSLB | authoritative DNSSEC and signed rollout exist | deeper reusable DNS profiles, DNS firewall/caching only after semantics and isolation tests |
| Multi-tenancy | current design single-tenant | separate isolation architecture for identities, secrets, runtime, resources and audit; no metadata-only tenancy |
| Analytics/CLI/API | current telemetry, management API, operator commands | unified service map, read-only diagnostics, scoped configuration CLI, retention and privacy |
| Release | existing installer and SOP | updated exact-source installer, approved tests and independent review; #36 physical gates unchanged |

Hardware acceleration and upstream volumetric DDoS absorption are deployment-dependent, not promised software equivalence. No copied proprietary interface or assets.

## Implemented in this PR (awaiting exact-head acceptance)
- Weighted least outstanding HTTP request selection in shipping runtime, reviewed draft validator and UI, with pure and real L7 acceptance tests.
- ADC service map on Overview, derived from actual route-to-cluster-to-destination configuration including disabled members, policies, unresolved references and unreferenced groups. Distinguishes draft/configured state from live traffic and routes through existing authorized editors. This is not the new VIP/object persistence model or a full ADC navigation redesign.

- L4 weighted rotation (TCP and new UDP sessions) and weighted least TCP connections added in engine and signed staging, with real socket acceptance. Exact-head verification pending; L4 dashboard configuration editor and runtime rollout remain incomplete.
