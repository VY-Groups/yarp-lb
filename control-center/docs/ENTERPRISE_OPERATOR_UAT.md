# GatewayCore enterprise operator UAT — customer release gate

**Result:** **NOT YET RUN AT CUSTOMER SITE / PRODUCTION NO-GO**.
Software CI green is a *prerequisite*, not customer signoff. No HAProxy native protocol or license claim is made.

## Evidence record (complete this in the real environment)

Record UTC timestamp, gateway **exact git SHA and installed binary SHA256**, browser/OS, signed configuration revision, operator role, change request ID, screenshots, audit IDs, relevant HTTP response codes, logs and the relevant host/network facts. Redact credentials, cookies, HMAC keys, OTPs and customer personal information. For each scenario record **PASS / FAIL / BLOCKED**, test owner and a link to approved evidence. Never silently treat skipped tests as pass.

## Day-one customer workflow: login through final page

| Scenario | Steps on the deployed management address | Required result |
| --- | --- | --- |
| Fresh bootstrap | Start with clean encrypted state on approved HTTPS management listener. Create an initial administrator. Try duplicate submission. | One user created, no duplicate account; password restrictions enforced; management path not available on data-plane public VIP |
| Existing admin login | Log out, sign in, reject incorrect password, expire/revoke the session, attempt an authenticated API call with the old cookie. | 401/403 as appropriate; no prior user's route drafts, OTP values, passwords or topology remain in the browser |
| MFA and directory | Configure site-approved SMTP + AD/LDAPS with certificate validation and group mapping. Attempt wrong bind, wrong OTP, disabled account, Viewer and Operator roles. | Fail closed; no unexpected elevation; audit records contain no passwords or private session tokens |
| Dashboard accuracy | With all backends down, visit Overview and Peer status. Restore one backend and refresh. | Readiness reports *no healthy destination* vs *at least one destination ready* correctly; no static unverified ONLINE claim |
| All management pages | Navigate Workspace, Traffic, Operations, Platform, and Security sections. Verify Routes, Clusters, Backends, Health, Metrics, Approvals, Backups, Fleet, Inventory, Users, Mail, Directory, Capabilities and peer diagnostics. | No empty page, console exception, broken action, unauthorized control or hidden navigation item on an authorized role |
| Draft safety | Create a route/cluster edit, navigate to a different page, cancel a modal, refresh, sign out, sign in as a different operator. | Draft remains private during navigation, refresh prompts before discarding, sign-out warns, and next operator inherits **no** unsent draft |
| Change approval | Operator creates a proposed route change, another authorized administrator approves, verify signed revision, then roll back. | Requestor cannot self-approve; activity audited; no live change before approval; revisions and rollback are consistent |
| Operational failure | Stop backend, interrupt UI API calls, force session expiry while editing, restore service. | No stale dashboard assertions, unhandled browser exceptions, duplicate submission or authorization bypass; retry only safe read-only operations |
| Backup and restore | Backup an approved test configuration; alter routing; restore and verify correct revision and audit trail. | Restore is explicit, isolated and tested; old encryption keys/migration behavior never assumed |

### Mobile and accessibility matrices

Execute at **390×667**, **768×1024** and **1440×900** viewport sizes on current customer-approved Edge/Chromium and Firefox; add actual mobile Safari/Chrome device testing when customer devices are available. Include browser zoom **200%**, landscape, touch scrolling, keyboard-only navigation, focus order, modal Escape/Cancel, screen-reader form labels, color contrast, autofill, multi-step onboarding and error displays. Tests must not hide important pages behind a fixed sidebar or introduce horizontal page overflow outside intended table/navigation containers.

At each viewport collect screenshots of **login, setup, overview, routes, health, peer sync, approval detail, users, mail and directory**. Record visible text clipping, focus loss, broken layouts, inaccessible controls, and the user-visible errors for disconnected API calls. Any P0/P1 issue is a **release blocker**. Automated GitHub Actions 390px Chromium checks do not replace real-device signoff.

## HAProxy-inspired reliability gates

| Area | Required live fault | PASS evidence |
| --- | --- | --- |
| Peer freshness | Block the internal TLS connection in both directions for at least 45 seconds; restore it | Signed peer status goes stale/unknown; no false synchronized claim; eventual recovery without replayed counters |
| Peer restart | Restart each gateway while traffic runs; inject old signed frames | Fresh boot-epoch resynchronizes; old epoch, duplicate nonce and counter rollback rejected; no process crash |
| Peer security | Wrong CA, wrong peer identity, bad HMAC, missing cert trust, bad clock, oversized body | Access refused with bounded resource use and no secret leakage |
| Atomic shared quota | Use two gateway nodes with the same Redis quota; disconnect Redis while generating traffic | Quota never double-spent through a local fallback; requests return 503 on Redis outage; account for Redis async failover limitation |
| Active-active | Two independent physical gateways with separately powered NICs and explicit ingress/VIP | Drain before graceful stop, SIGKILL and network partition recorded by absolute failures, failure window and no replay of non-idempotent operations |
| Sustained throughput | Each *surviving gateway alone* takes the real peak + approved headroom for 60 complete minutes | For verified 500 **Mbps** peak with 50% headroom: >=750 Mbps body throughput in **every** 60-second window plus approved RPS floor; zero errors, p99 under approved limit, no NIC drops, log loss or GC saturation |
| Recovery and upgrades | Restart on live site, roll back a failed config and reboot hardware | Verified signed config revision, durable audit, restored credentials and explicit existing-state migration |

Check `control-center/docs/ONPREM_PRODUCTION_GO_GATES.md`, `control-center/docs/PEER_COUNTER_SYNC.md`, `ops/capacity/EOD_500MBPS_RELEASE_PLAN.md` and the two Ubuntu CI workflows for detailed procedures. **Two Ubuntu cloud runners are independent VMs, not the site's physical HA and NIC test.**

## HAProxy parity — engineering boundaries

Read-only HAProxy reference: branch `ha-praxy`, particularly `src/peers.c`, `src/stick_table.c` and `src/queue.c`. Those files carry GPL licensing; study algorithms and operational semantics, do **not** copy GPL C into the product or promise HAProxy protocol interoperability.

GatewayCore currently has **opt-in signed two-node request-counter telemetry**, boot-epoch resynchronization and a **separate** opt-in Redis atomic per-IP rate limit. The following remain **not implemented/equivalence unproven**, rather than silently treating CI green as parity: general-purpose multi-table key/data types; persistence of stickiness/server-id assignment; HAProxy GPC/GPT/rate fields; full incremental delta/backfill and cold-start teaching state machine; TTL/LRU and table expiry semantics matched to HAProxy; HAProxy peers wire-protocol interoperability; peer-set/multi-peer topology; persistent state after node replacement; safe reload migrations; proven zero-loss recovery across split-brain and physical failover. Implement and regression-test each contract independently, then verify with live fault injection before changing its status.

## Customer release decision

- **Development/CI GO:** strict exact-SHA source, browser/API, security and HA simulation workflows pass.
- **Customer UAT GO:** all scenarios above recorded PASS by actual operators in the target site, with sign-off for access, navigation and recovery.
- **Production GO:** additionally all physical capacity, fault-domain, PKI, migration, observability and incident response gates in the production release document are authorized. **Any missing critical evidence => NO-GO.**

Never substitute development-source changes for upgrading the installed Windows/Linux binary. Release packages and migration/rollback steps must reference the same approved source commit and immutable artifact hash.
