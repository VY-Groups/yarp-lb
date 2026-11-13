# API contract — SpeedSign Control Center 0.1

All `/admin/api/*` endpoints are **loopback restricted** by `Program.cs` and are not internet APIs. Cookie authentication, CSRF and server role checks apply. The response shapes below describe current behavior, not remote production guarantees.

| Method and path | Access | Semantics |
| --- | --- | --- |
| `GET /admin/api/session` | Anonymous allowed | Initial-admin presence, session, role, anti-CSRF token after login |
| `POST /admin/api/bootstrap` | Anonymous, only if zero accounts | Creates recovery Administrator; cannot be used again |
| `POST /admin/api/login` | Anonymous, rate limited | Local or AD password login; may initiate OTP |
| `POST /admin/api/login/verify` | Anonymous, challenge limited | Complete pending one-time email code challenge |
| `POST /admin/api/logout` | Signed-in; CSRF | End cookie session |
| `GET /admin/api/setup/version` | Signed-in | `{version:"0.1",channel:"development",deploymentCertified:false}` |
| `GET /admin/api/setup/overview` | Signed-in | Configuration-derived setup stages with `configured`, `unverified`, `not-implemented` etc. statuses |
| `GET /admin/api/setup/freeze` | Signed-in | Local routing freeze state |
| `POST /admin/api/setup/freeze` | Administrator, CSRF | `{frozen:boolean,reason:string}` (reason 12–500 characters); updates local freeze and audit log |
| `GET /admin/api/runtime/destinations` | Signed-in | Runtime YARP active/passive health + concurrent requests, per gateway |
| `GET/POST /admin/api/onboarding` | GET signed-in, POST Administrator + CSRF | Read/update topology **design**; optimistic revision lock |
| `POST /admin/api/onboarding/validate` | Administrator + CSRF | Design validation, no live mutation |
| `GET /admin/api/state` | Signed-in | Current reverse proxy config and SHA-256 revision; no secrets exposed intentionally |
| `GET /admin/api/metrics` | Signed-in | Process-local HTTP totals and mean latency |
| `GET /admin/api/destination-metrics` | Signed-in | Per-destination request counters, reset after gateway restart |
| `POST /admin/api/probe` | Operator/Administrator, CSRF | On-demand HTTP probe, **not** internal YARP health state |
| `GET/POST /admin/api/change-requests` | GET signed-in, POST Operator/Admin + CSRF | Request route/cluster/destination change, not direct apply |
| `POST /admin/api/change-requests/{id}/decision` | Different Administrator + CSRF | Review/approve/reject; approval updates live local config |
| `GET /admin/api/backups`, `POST /admin/api/restore/{name}` | GET signed-in, POST Administrator + CSRF | Local configuration backup and restore |
| `GET/POST/DELETE /admin/api/fleet...` | Per-endpoint Admin/role checks | Gateway inventory, authenticated agent reports, staged rollout **where configured and enabled** |
| `GET/POST /admin/api/mail`, `POST /admin/api/mail/test` | Administrator + CSRF on POST | SMTP/OTP config and relay-accepted test |
| `GET/POST /admin/api/directory`, `/test`, `/test-user` | Administrator + CSRF | LDAPS configuration, connection and authorized user tests |
| `GET/POST /admin/api/users` and user-specific mutations | Administrator + CSRF on writes | Account management and session invalidation |

**Freeze behavior:** When enabled, the local routing freeze middleware returns HTTP **423 Locked** for POST/PUT/PATCH/DELETE against `change-requests`, `restore`, and `fleet/rollout` endpoints. It does **not** stop existing YARP proxy traffic; LDAP/mail operations and user account management remain available. It is **not a distributed lock** among independent controllers.

**Health semantics:** `Unknown` is an expected internal YARP health value until YARP policy has classified a destination. `GET /gateway/health` returns *gateway-process* liveness only; it must never be used as proof that any backend is reachable.

**Security constraints:** No general-purpose shell/WinRM endpoints are exposed. Client certificate authentication is required to connect to enrolled gateway agents. Exposing the existing admin UI on a non-loopback interface is prohibited for this 0.1 dev build.
