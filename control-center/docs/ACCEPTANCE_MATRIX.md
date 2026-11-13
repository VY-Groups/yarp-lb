# Acceptance matrix for Windows Server 2022 lab and later production

| ID | Gate | Command/evidence | Pass condition |
| --- | --- | --- | --- |
| BUILD-01 | Gateway C# compilation | `dotnet build --no-restore` | no CS errors |
| CORE-01 | Pure LB algorithms | `VERIFY-TRAFFIC-EXPANSION.ps1` | deterministic tests pass; no invalid weights |
| UI-01 | Frontend compile | `npx tsc -p wwwroot/tsconfig.json` on build machine | zero errors |
| AUTH-01 | Anonymous admin endpoint | `GET /admin/api/organization` | 401 (unless login) |
| AUTH-02 | Profile update authorization | logged-in Viewer PUT profile | 403 |
| CSRF-01 | Profile update without token | logged-in Admin PUT profile without `X-CSRF-Token` | 403 |
| PROFILE-01 | Revision conflict | Admin PUT with stale expectedRevision | 409, unchanged record |
| PROFILE-02 | Invalid industry/name | Admin PUT invalid field | 400, unchanged record |
| PROFILE-03 | Organization update | Admin PUT valid profile | incremented revision, audit entry, UI updates after refresh |
| HEALTH-01 | Gateway liveness | GET `/gateway/health` on loopback | 200; does NOT prove backend health |
| METRICS-01 | Prometheus text format | GET `http://127.0.0.1:8080/gateway/metrics` | 200 and documented counters |
| METRICS-02 | Metrics exposure | GET `/gateway/metrics` from another host | 403 (requires controlled network listener test) |
| L7-01 | Two test backends | MockHttpBackend on 18081/18082 and approved lab route | response identity reaches both nodes |
| L7-02 | Policy distribution | run HTTP verifier with expected algorithm | distribution within chosen confidence band, client identity verified |
| L7-03 | Active failure | mock readiness false on one node | after configured health threshold, only healthy node served |
| L7-04 | Recovery | mock readiness true on failed node | backend returns to service under configured policy |
| L7-05 | HTTP protocol | API/gRPC/WebSocket, upload and large response tests | correct protocol negotiation and no unexpected rewrites |
| CHANGE-01 | Approvals | submit by Operator, approve with different Admin | self-approval denied; approved config applied and auditable |
| HA-01 | Gateway failure | stop YARP-01 with healthy YARP-02 + VIP | new traffic still served; measure outage |
| TLS-01 | Certificate trust | valid/invalid SAN, expiry, backend mTLS | invalid cert blocked, rotation tested |
| REG-CA-01 | CA/PKI special routes (if applicable) | OCSP GET/POST, CRL/approval/issuance workflows | protocol/caching/transaction requirements preserved |
| SEC-01 | Independent security review | SAST/DAST, threat model, IdP/WORM tests | no critical defects or uncontrolled changes |

A successful compile is necessary but not sufficient for production. Keep test evidence with hashes and dates. Live load-balancing traffic must not use a CA signing/approval production endpoint as a test target.
