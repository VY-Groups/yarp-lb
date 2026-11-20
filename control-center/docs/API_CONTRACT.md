# API contract — GatewayCore Control Center 0.1

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


### Durable fleet rollout and recovery

POST /admin/api/fleet/rollout/{changeId} accepts only an independently approved saved change. Preflight obtains the original full configuration revision of every registered agent and requires rollbackFenceProtocol=1. Upgrade agents before the controller; old agents are not eligible. In external-audit mode FLEET_ROLLOUT_INTENT signs the SHA-256 of the initial journal (transaction ID, approved change digest, fleet inventory digest, target IDs and original revisions), before any prepare or activate dispatch. No configuration contents or credentials are exported. Each prepare/activate attempt is flushed to an atomic journal before dispatch. Agent responses must bind the transaction and revisions. The controller holds its local fleet writer gate and rechecks actor, topology, approved change and inventory before forward dispatch. Cancellation stops forward progress, not compensation. A successful deployment reports activated-pending-health-validation, not verified application health.

GET /admin/api/fleet/rollouts lists recent journals. The fleet UI offers the journal and an Administrator-only explicit Recover / rollback action. POST /admin/api/fleet/rollouts/{id}/recover requires a valid unfinished schema-2 journal, the original inventory digest, the original gateway IDs and current authorization; in external-audit mode FLEET_RECOVERY_INTENT must be retained before the recovery begins. It NEVER replays prepare or activate. Only targets with a durable prepare-dispatch marker and no prior verified rollback are contacted. Successful rollback requires the upgraded agent's terminal fence acknowledgment and a separate authenticated status read that matches the recorded original revision. An independent agent's rollback creates and flushes a terminal fence before restoration; delayed activation of that transaction is rejected. A missing transaction, unknown outcome, mismatched revision, superseding sequence, inaccessible agent or local journal error is not treated as successful recovery. Recover again only after investigation; incomplete records block new rollouts and membership changes. Do not delete journals to bypass the gate.

Recovery does not resume the original rollout. Existing legacy journals with ambiguous states lack the necessary target evidence and require independent reconciliation; no automatic conversion or destructive cleanup. Keep protected controller journals, agent stage directories and sequence state together across upgrades and restore. The original config is preserved on each agent; no modification to public proxy traffic or automatic service reinstall is performed by the controller recovery endpoint. This is a single-controller crash recovery mechanism, not distributed consensus or global atomic activation. Actual app reload, failover, health and live traffic require separate evidence. The tests cover durable journal reload, attempted-only selection, original inventory/revision fencing and malformed state. A disposable full controller/two-agent interrupted-rollout acceptance test remains required; physical tests stay in #36. Before rollback of the software version, reconcile every unfinished journal on the current version; do not downgrade to agents that ignore terminal fences.

Rollback recovery is independently authorized and uses the existing management listener and role/CSRF checks. A local routing freeze prevents new forward rollout; rollback-only recovery remains available to resolve an interrupted rollout. The confirmed multi-gateway design requirement remains in force.
