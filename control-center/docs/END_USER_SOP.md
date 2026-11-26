# GatewayCore end-user manual and standard operating procedures

Offline reference for L0 new starters, L1 daily operators, L2 administrators and L3 specialists. Applies to the implemented GatewayCore development build; features are conditional on role, license, host provisioning and topology. Production acceptance remains separate. All examples are placeholders.

## Learning path

L0: foundations; L1: daily operations; L2: administration; L3: specialist deployment and recovery. The dashboard **User guide** includes the same chapters and local search. The short five-step guide remains available above them.

## Contents

- L0 · SOP-01: Start here: how GatewayCore works
- L0 · SOP-02: Windows offline installation and upgrade
- L0 · SOP-03: First administrator: sender-first registration
- L0 · SOP-04: Employee sign-in, invitation and access
- L0 · SOP-05: Commercial offline activation and renewal
- L1 · SOP-06: Organization and architecture setup
- L1 · SOP-07: Add a website or API
- L1 · SOP-08: Backend groups, balancing and maintenance
- L1 · SOP-09: Change requests, approval and freeze
- L1 · SOP-10: Daily monitoring and shift handover
- L1 · SOP-11: SMTP, OTP, directory and account recovery
- L2 · SOP-12: TLS bootstrap and certificate inventory
- L2 · SOP-13: Certificate renewal, import and revocation
- L3 · SOP-14: Commercial fleet certificate rotation
- L2 · SOP-15: HA, Active-Active, DC-DR and fleet rollout
- L2 · SOP-16: WAF policy and signed dashboard deployment
- L2 · SOP-17: DNS/GSLB zone configuration and DNSSEC
- L3 · SOP-18: Signed rolling DNS deployment and Windows restart
- L2 · SOP-19: L4 TCP/UDP, capability inventory and GitOps
- L2 · SOP-20: Backups, restore, upgrade rollback and disaster recovery
- L2 · SOP-21: Observability and incident response
- L1 · SOP-22: Troubleshooting decision tree: 401, 403, 404, 409, 423, 429, 502, 503, 504
- L1 · SOP-23: Safe diagnostic commands for Windows and Linux
- L1 · SOP-24: Incident escalation and RCA template
- L3 · SOP-25: Release, physical acceptance and operator qualification

## L0 · SOP-01: Start here: how GatewayCore works

**Who:** All users

**Before you start:** Understand the terms before operating a gateway.

1. Client → approved DNS/firewall/VIP → GatewayCore → backend group → application server. A route selects a group by hostname/path; a destination is one server. The management listener is separate from client traffic.
2. Dashboard shows this gateway, not proof that every site is healthy. Use Health checks and Traffic metrics; design records are not deployed infrastructure.
3. Use a named account, never a shared login. Viewer reads; Operator prepares drafts; Administrator manages security and approvals. The requester cannot approve their own routing change.

**Troubleshooting and stop conditions:** If a menu is missing, check your role, topology, configured module and license. Do not try to bypass the restriction.

**Completion evidence:** Explain the traffic path and demonstrate the difference between design, draft, applied configuration and real traffic.

## L0 · SOP-02: Windows offline installation and upgrade

**Who:** Host administrator

**Before you start:** Obtain the exact approved package and prepare an isolated x64 Windows Server 2022 or later lab.

1. Obtain GatewayCore-Setup-win-x64.exe, SHA256SUMS.txt and SOURCE_COMMIT.txt from the successful exact-source installer workflow. Verify Get-FileHash -Algorithm SHA256 against the approved hash and independently verify package authorization. Ordinary lab EXE is unsigned; it is not the commercial release.
2. Use an elevated local account; confirm disk space, existing service ownership, backup custody and planned maintenance. Setup is self-contained and does not download a runtime or open firewall ports.
3. Run Setup. The lab dashboard opens only after local service health succeeds. Open http://127.0.0.1:8080/dashboard on the host, not on a public address. Existing accounts and supported configuration are retained on upgrade.
4. Record source SHA, package hash, installer exit status, service identity, local health and the retained backup. The installer rolls back the failed candidate when its immediate health gate fails; later rollback is a separate approved operation.

**Troubleshooting and stop conditions:** If Setup fails, retain its Inno log in the invoking account TEMP directory, or use /LOG with an approved path. Check OS/architecture, disk, rights, conflicting port/service and rollback evidence. Never delete ProgramData to force installation.

**Completion evidence:** Successful health gate, dashboard opens, correct version and service identity; preserve state and rollback evidence.

## L0 · SOP-03: First administrator: sender-first registration

**Who:** Host administrator / first Administrator

**Before you start:** Approved existing company sender or relay, readable test mailbox and protected installation claim.

1. On a fresh ordinary Windows lab installation open C:\ProgramData\GatewayCoreYarp\ControlPlane\first-run-code.txt locally as administrator. Authorize installation with the one-time claim; do not send it to anyone.
2. Connect company email: enter sender (for example noreply@example.invalid), verification inbox, SMTP hostname and port, approved authentication method and dedicated credentials. STARTTLS is required; implicit TLS port 465 is unsupported.
3. Receive the sender verification OTP and enter it. Register the first administrator email, receive its separate OTP and verify it.
4. Create a named username and unique password (16–256 characters); confirm it. Sign in using the configured login OTP workflow, accept Privacy Policy and configure the organization. Existing initialized installations do not repeat first-run enrollment.

**Troubleshooting and stop conditions:** If OTP never arrives, check relay reachability, TLS, allowed sender, recipient quarantine and actual inbox. SMTP acceptance is not mailbox delivery. Restart an expired setup flow using the protected claim only if still unconsumed; contact the host administrator for recovery.

**Completion evidence:** Sender OTP and administrator OTP both verified; named recovery administrator can sign in; no credential included in ticket or screenshots.

## L0 · SOP-04: Employee sign-in, invitation and access

**Who:** Viewer / Operator / Administrator

**Before you start:** Verified mail, separate named accounts; invitation enrollment only where supported.

1. Administrator: Security & accounts → Admin accounts → Invite employee. In an ordinary standalone local-account lab choose named username, company email and Viewer or Operator. Invitations cannot assign Administrator.
2. Employee: open the authorized dashboard, choose Accept employee invitation, enter the one-time code, then set and confirm a unique password. Invitation lasts at most 30 minutes; completion capability lasts at most 10 minutes. Sign in using password and separate login OTP; accept privacy terms.
3. For other deployment modes use the authorized local/enterprise identity enrollment procedure. Test a separate reviewer in a different session. Revoke expired or unwanted invitations and disable accounts through authorized account administration.

**Troubleshooting and stop conditions:** Expired code or service restart: ask issuer to revoke/reissue; do not reuse/forward codes. 401 means sign in again or verify identity; 403 can be role, policy or entitlement denial. Use the authorized recovery account if locked out.

**Completion evidence:** Separate accounts can sign in; role permitted actions verified; departing staff access revoked and audited.

## L0 · SOP-05: Commercial offline activation and renewal

**Who:** License administrator

**Before you start:** Commercial package and independently authorized issuer, not the unsigned lab package.

1. Open License Center where available. Download the activation request from the actual installation. Transfer using the approved offline channel to the issuer.
2. Import only the signed license (.lic) issued for that installation via Activate / renew. Review licensed features, node limits and expiration. For an approved revocation, use Import revocation with the signed .gcv document.
3. Keep issuer signing keys outside the customer gateway. Do not copy licenses between installations, change system time, edit entitlement state or use an unsigned test build as a commercial package.

**Troubleshooting and stop conditions:** If activation fails, preserve the nonsecret request/status and verify package profile, installation binding, validity dates, authorized issuer and feature entitlement; contact the license custodian. Never bypass licensing or roll back trusted state.

**Completion evidence:** Installation reports the correct licensed scope; required operations allowed and excluded operations denied; record sanitized evidence.

## L1 · SOP-06: Organization and architecture setup

**Who:** Administrator

**Before you start:** Actual organization, host inventory, approved network design and change ticket.

1. Start here → Organization: configure company labels and region. These are metadata, not tenancy or isolation.
2. Start here → Gateway architecture: choose Standalone for a single lab, or the applicable HA/fleet design; enter gateway and application hosts and DC/DR site assignments. Review the topology diagram and confirm.
3. Follow the Approval team step. Create/test a separate authorized administrator and use an Operator for preparing routine changes. Record backup and approved maintenance procedures.
4. Network team independently provisions listeners, firewall, ingress VIP/ECMP, node identities and agent trust. GatewayCore does not provision those merely by saving the design.

**Troubleshooting and stop conditions:** If checklist says Required, open its recommended next action. A confirmed design with no enrolled agents or VIP is not a live HA deployment.

**Completion evidence:** Organization and design saved, second approver verified, network implementation/evidence tracked separately.

## L1 · SOP-07: Add a website or API

**Who:** Operator / independent Administrator

**Before you start:** Approved client hostname, path, trusted HTTPS backend root URL, application owner and readiness contract.

1. Start here → Add website / API. Enter a name, client hostname and backend root URL; add a second distinct server if equal round-robin is intended. For an existing loopback HTTP lab site use Local website test (/lab/).
2. Review Websites & routes and Backend servers. Match only intended host/path; use trusted HTTPS origins. Confirm application auth, session state and path handling with its owner. Do not expose restricted admin/CA endpoints by copying a public route.
3. Submit for approval with a reason of at least 12 characters. A different Administrator opens Change requests → Review full draft, checks the exact JSON and approves or rejects.
4. After approval verify runtime routes and destinations, actual client requests on the approved listener, expected status/body and metrics. Enable readiness checks only after verifying the real endpoint.

**Troubleshooting and stop conditions:** 404: confirm hostname/path and approved revision; 502: inspect backend DNS/TCP/TLS and app logs; 503: inspect eligible destinations and readiness; 504: check downstream latency/timeouts. Do not retry non-idempotent signing or payment operations blindly.

**Completion evidence:** Correct client response and backend selection, independent approval ID, no unauthorized route exposure.

## L1 · SOP-08: Backend groups, balancing and maintenance

**Who:** Operator / independent Administrator

**Before you start:** Healthy application origins and tested policy.

1. Configuration → Backend groups → Edit; review policy guidance. RoundRobin spreads equal requests; LeastRequests uses active requests; PowerOfTwoChoices compares two eligible destinations; WeightedRandom uses configured weights; SourceIpHash uses immediate trusted peer identity; FirstAlphabetical prefers the first eligible destination. Primary/backup requires explicit roles and health policy where supported.
2. Backend servers: add or edit destination URL, weight (1–100 where weighted policy applies) and enable state. Configure verified readiness path and active thresholds; do not treat Unknown as Healthy.
3. For planned maintenance, use the approved drain/disable workflow, verify surviving capacity and existing traffic completion, then service the backend. Restore only after app readiness, actual client test and approval where configuration changes are required.

**Troubleshooting and stop conditions:** Uneven traffic can be expected with weighting, connection reuse or SNAT. Check actual request distribution, policy, health and role/weight settings; do not disable TLS or fail open to sick nodes.

**Completion evidence:** Approved policy; actual distribution and graceful drain verified under representative traffic.

## L1 · SOP-09: Change requests, approval and freeze

**Who:** Operator / independent Administrator

**Before you start:** Named requester, different approver, change record and current revision.

1. Prepare a draft and review route/backend changes and advanced JSON. Record business reason, affected services, expected outcome, verification and rollback.
2. Submit for approval. Reviewer opens Change requests → Review full draft; compare exact JSON and revision, reject unexpected edits or approve using a different account.
3. If freeze is active, do not bypass it. Administrator uses the authorized freeze/unfreeze workflow with reason. Local freeze is not a fleet quorum lock.
4. On revision conflict, reread current live configuration, reconcile the draft and submit a new request. After approval verify loaded configuration and real traffic; approval alone is not success.

**Troubleshooting and stop conditions:** HTTP 423 indicates frozen changes; 409 indicates conflicting revision/state or operation. Do not create duplicates or reuse stale approval. For uncertain apply, inspect audit and current revision before retrying.

**Completion evidence:** Request, reviewer and applied revision recorded; traffic verification and rollback decision attached.

## L1 · SOP-10: Daily monitoring and shift handover

**Who:** Viewer / Operator

**Before you start:** Approved read-only access and site-specific baselines.

1. Dashboard: inspect local status and gateway readiness. Health checks: compare runtime active/passive states with on-demand probes; a process health response is not end-to-end availability.
2. Traffic metrics: inspect request counts, failures, latency and backend distribution; local counters reset at process restart and may not represent fleet totals.
3. Review change requests, certificate expiry, backups and audit, fleet state and configured license status. Check configured external telemetry and audit delivery for stale/drop/block indicators.
4. At shift handover record UTC time, site/node, affected services, current revision, incidents, upcoming maintenance/renewals, unresolved alarms and the next owner.

**Troubleshooting and stop conditions:** If an alarm appears, collect evidence before changing anything. Compare another gateway and actual client path. Do not reset counters or restart a service just to make an alarm disappear.

**Completion evidence:** Known health, documented deviations, named owner and next action for each unresolved alert.

## L1 · SOP-11: SMTP, OTP, directory and account recovery

**Who:** Administrator / identity specialist

**Before you start:** Dedicated credentials, valid CA chains and tested recovery account.

1. Security & accounts → Mail & OTP: configure approved relay/FQDN, STARTTLS and allowed sender; test delivery to the real registered inbox before enabling/changing OTP. Use approved relay/app credentials or configured Google/Microsoft OAuth modes.
2. Active Directory: verify LDAPS FQDN, trusted server SAN/chain, port 636 (or approved GC 3269), read-only bind account, search base and exact group-to-role mapping. Test each role with real directory accounts and populated mail attributes.
3. Enterprise SSO is separately host-configured with the trusted HTTPS OIDC issuer, exact immutable subject/group mapping, PKCE, phishing-resistant assurance and tested local recovery account. It is not automatic enrollment.
4. Keep recovery administrator access under custody; never disable OTP/TLS or remove protected identity state for recovery.

**Troubleshooting and stop conditions:** Mail: distinguish DNS/TCP, TLS, relay authentication and final mailbox delivery. Directory: distinguish bind failure, trust error, missing group or mail. SSO: check issuer/redirect/claims and real IdP assurance; escalate to identity team.

**Completion evidence:** Tested allowed and denied roles, actual delivery, recovery account and audited policy change.

## L2 · SOP-12: TLS bootstrap and certificate inventory

**Who:** Host administrator / PKI specialist

**Before you start:** Approved encrypted PFX files, protected password files, trusted management client CA/pins, distinct addresses and measured limit.

1. Before initial isolated HTTPS management, provision approved traffic and management PFX and trust on host. Run the installed executable with --listener-bootstrap-wizard followed by an existing absolute private directory. Enter IPs, ports, protected file paths (not passwords), management CIDRs, pins, DNS names and measured concurrency limit.
2. Type CREATE only after validation; wizard creates new listeners.json without overwrite. Configure YARP_LISTENERS_CONFIG_FILE under the service identity, then start through approved host procedure. Verify actual management mTLS and traffic TLS separately.
3. Security & accounts → Certificates & TLS: inspect local inventory, expiry, EKU and configured capabilities. Inventory dates do not prove trust, selected leaf or live handshake.
4. Configure backend mTLS only with approved installed client certificate and HTTPS origins. Review the draft thumbprint and independently approve; verify actual backend handshake on every target gateway.

**Troubleshooting and stop conditions:** If certificate unavailable, inspect store/service identity, private ACL, password file, SAN/EKU, chain and trust under actual service identity. Never import a private key into chat or disable validation.

**Completion evidence:** Correct live leaf on both listeners, trusted handshake and denied unauthorized management client.

## L2 · SOP-13: Certificate renewal, import and revocation

**Who:** Administrator / PKI specialist

**Before you start:** Configured ACME or approved host-staged certificate and current authority.

1. Certificates & TLS → Check renewal now when configured. It checks due-date policy using the existing issuer; no forced early issuance. Independently test the actual TLS leaf after the result.
2. For staged import, host operator explicitly enables YARP_STAGED_TRAFFIC_CERTIFICATE_IMPORT and places approved encrypted PFX at the fixed active path plus .pending.pfx using existing protected password. Preview the candidate/active digests; type ACTIVATE and exact candidate SHA-256, then activate. Standalone enterprise mode additionally checks current authority and external audit where configured.
3. In commercial fleet mode use the separate SOP below. For historical ACME revocation, provide exact public DER base64, 40-character uppercase thumbprint, supported reason and typed REVOKE confirmation. The active certificate is protected. Revocation is irreversible.
4. Verify live handshake, expiry, audit and continuity. A pending or unconfirmed operation is not safe to replay.

**Troubleshooting and stop conditions:** Not due is not a failure. For import conflict, compare active/candidate digests and authority, check protected PFX and live listener. For uncertain renewal/revocation, verify live TLS and CA status before retrying; do not revoke as a troubleshooting shortcut.

**Completion evidence:** New leaf verified independently, or not-due result recorded; old leaf status and audit confirmed.

## L3 · SOP-14: Commercial fleet certificate rotation

**Who:** Fleet operator / independent signer / Administrator

**Before you start:** Licensed TLS/HA/fleet; existing quorum, external audit/outbox, no conflicting ACME; per-node approved PFX and peer-health evidence.

1. Verify peer capacity and live traffic first. Obtain staged preview on target. Authorized host operator runs GatewayCoreYarp --fleet-tls-lock acquire with exact active, candidate and peer-evidence SHA-256 values. Preserve the durable plan. If acquisition uncertain, use recover only for the same transaction.
2. Independent signer uses ops/fleet/sign_fleet_tls_grant.py --plan with copied plan, --key with protected P-256 key and --purpose activate. Provision fleet-tls-approval.json and pinned signer public key as documented. Never copy private signer key to gateway.
3. Administrator refreshes preview until grant/quorum are observed, then confirms exact candidate. Server rechecks authority and consumes one-time epoch. Verify actual TLS leaf and surviving peer traffic.
4. Signer issues separate activated or rolled-back completion grant with evidence SHA-256. Provision fleet-tls-completion.json and run --fleet-tls-lock release. Only after exact active file and live TLS verification plus original quorum release may the next node be rotated.

**Troubleshooting and stop conditions:** No grant/current quorum or unconfirmed activation: stop. Preserve plan, epoch, journal and audit; recover same transaction with custodian. Never delete the plan, manually clear quorum or rotate both nodes together.

**Completion evidence:** One-node-at-a-time verified live TLS, independent completion evidence and confirmed original fence release.

## L2 · SOP-15: HA, Active-Active, DC-DR and fleet rollout

**Who:** Platform / network specialist / independent reviewer

**Before you start:** Distinct host identities, management mTLS, signed plan, approved VIP/ECMP, quorum and physical test plan.

1. Record gateway/site topology and workload ownership. Network team configures health-aware ingress separately. Enroll agents with pinned identity and verify Gateway fleet/runtime status.
2. Use existing signed fleet configuration workflow: inspect current exact revision and enrolled membership, obtain independent signature and valid authority, stage and verify candidate, activate in the approved order and verify live configuration/traffic. Preserve receipts.
3. For planned node maintenance verify remaining capacity, drain the target where supported, validate live traffic before and after, recover and rejoin using current approved config. For unplanned failure follow site incident procedure; never replay in-flight POSTs.
4. DC-DR data replication and consistency are application-owned. GatewayCore does not replicate application databases. Failback only after data owner, network and gateway teams confirm safe authority and current state.

**Troubleshooting and stop conditions:** Partition, expired lease, mismatch or failed rollout: stop mutations, preserve receipts, inspect both sites and quorum. Do not force promotion or clear fencing. Local UI freeze does not fence other controllers.

**Completion evidence:** Physical node loss, partition, VIP migration, failback and measured capacity demonstrated; issue #36 and authorized production release signoff separate.

## L2 · SOP-16: WAF policy and signed dashboard deployment

**Who:** Security specialist / Administrator / independent reviewers

**Before you start:** Pinned CRS ruleset, representative redacted corpus, independent review, configured operator broker and live external fence.

1. Multi-gateway & modules → WAF policy workflow: prepare unsigned candidate with fresh revision, observed ruleset SHA-256, lifetime, detect/block mode and narrowly scoped exceptions where supported. Block requires reviewed shadow evidence. Export exact bytes and digest.
2. Obtain two independent signatures and verify against actual ruleset, trusted revision floor and evidence. The current signed coordinator supports mode transitions without scoped exceptions; do not assume draft exceptions can be activated.
3. Where configured, use dashboard Deploy independently signed specialist configuration. Enter exact independently staged revision/digest, select Read-only preflight and type PREFLIGHT plus digest. Review evidence; choose execute only with authorized change and typed EXECUTE. Windows dashboard reaches independently administered Linux operator over pinned mTLS; native Windows WAF engine not provided.
4. Applied-uncommitted means both nodes verified, independent authority commit still required. For intentional rollback prepare a fresh signed revision to prior mode, not stale policy replay; use existing compensating transaction and preserve receipts.

**Troubleshooting and stop conditions:** Missing broker: check feature, configuration and role. Signature/ruleset mismatch: re-review exact bytes. Unexpected WAF 403: correlate rule and representative traffic, never disable protection globally. Unconfirmed deployment: stop/reconcile receipts and authority before retry.

**Completion evidence:** Detection and block accuracy, per-route evidence, two-node deployment, compensation, independent commit and representative latency/capacity verified.

## L2 · SOP-17: DNS/GSLB zone configuration and DNSSEC

**Who:** DNS specialist / Administrator

**Before you start:** Zone ownership, parent delegation plan, nameservers, forward serial, sites and verified health endpoints.

1. Multi-gateway & modules → DNS & GSLB workflow: enter authoritative zone, SOA contact, positive serial, TTL, distinct nameserver/site addresses, HTTPS health URLs, routing policy, weights/priorities and probe thresholds. Export validated unsigned loopback candidate; no actual delegation or live config change.
2. Open DNSSEC and delegated authority: choose Disabled, NSEC or NSEC3. Enter only approved absolute signing-key references, optional rollover public/additional key paths, explicit NSEC3 salt/iterations and child delegations/DS records. Never paste key contents.
3. Have DNS/PKI operator independently prepare signed engine config and authority/quorum; provision actual interfaces and trust. Validate serial advance, parent DS and DNSSEC response chain, and site failure behavior using real UDP/TCP queries.
4. All-down is fail-closed; do not promise site failover merely because a zone is saved.

**Troubleshooting and stop conditions:** SERVFAIL: check DNSSEC signer/clock/DS/trust, authority status and health. NXDOMAIN: verify queried name/zone/delegation. Wrong address: check TTL/cache, actual authoritative response and site health. Do not remove DNSSEC or publish an older SOA serial to fix a symptom.

**Completion evidence:** Expected direct authoritative UDP/TCP answers, SOA, DNSSEC and resolver convergence verified before parent delegation.

## L3 · SOP-18: Signed rolling DNS deployment and Windows restart

**Who:** DNS / fleet operator / Administrator

**Before you start:** Two independently enrolled authorities, exact signed prepare envelopes, common forward serial transition, approved mTLS broker/agent and current quorum where required.

1. Operator stages a private approved two-node plan with signed envelopes and baseline SOA; broker --describe produces sequence and canonical digest. In dashboard enter exact sequence/digest and run read-only preflight with typed confirmation. Preflight proves baseline runtime/SOA, not all signature checks.
2. After independent authorization execute the same plan. Coordinator prepares both agents, activates/restarts one authority, verifies loaded digest and real UDP/TCP SOA, then repeats on the second and checks both.
3. Windows uses the fixed GatewayCoreGslb service with native SCM lifetime; Linux uses gatewaycore-gslb.service. Restart must be explicitly enabled on agent with allowlisted config, loopback metrics and delegated service rights. Commercial operations require current authenticated fence.
4. Preserve journal and complete independent authority commit. If a restart may have published a new serial, old-file rollback is refused; use fresh signed forward recovery after reconciliation.

**Troubleshooting and stop conditions:** If file revision differs from loaded revision, restart not confirmed or SOA differs, stop before touching second authority. Preserve restart intent and private journal; never restart both at once or replay uncertain transaction.

**Completion evidence:** Both authorities serve expected forward serial over UDP and TCP; loaded digest and authority commit confirmed.

## L2 · SOP-19: L4 TCP/UDP, capability inventory and GitOps

**Who:** Platform specialist

**Before you start:** Opt-in engine/service, authorized listeners, separate config and acceptance.

1. Open Traffic engine & modules / Capabilities to inspect supported/configured features. L4 is a separate engine, not an HTTP route; use the documented signed agent workflow and approved bind/target addresses.
2. Validate TCP connectivity and UDP behavior, drain/stop and backend failure with representative protocol traffic. Do not replay bytes after uncertain forwarding. Actual listeners, firewalls and service configuration are host-managed.
3. GitOps or infrastructure integrations are capability-dependent; use the documented reviewed workflow and compare desired vs actual state. Do not assume a capability listing means a controller has been installed or accepted.

**Troubleshooting and stop conditions:** Port binding failures: check approved listener, ownership and firewall; protocol timeouts: inspect backend path and runtime evidence. Do not expose management or disable restrictions.

**Completion evidence:** Separate runtime and protocol-specific acceptance for any enabled engine.

## L2 · SOP-20: Backups, restore, upgrade rollback and disaster recovery

**Who:** Administrator / backup custodian

**Before you start:** Approved maintenance, protected backups and recovery procedure.

1. Configuration → Backups & audit: identify snapshot and verify revision/contents and independent retention. Maintain separately protected offline copies of config, identity/key state and release artifacts under authorized custody.
2. Restore only with approved change and correct snapshot; respect freeze and current revision. Preserve prior evidence, verify restored routing and client traffic. A config restore is not a complete host or identity restore.
3. For lab installer upgrade rollback, use retained versioned binaries and protected backup/runbook; installer auto-rollback only covers failed immediate health gate. Uninstall retains ProgramData state. Do not copy Windows DPAPI state to another host.
4. For fleet/DR key recovery, use existing authenticated signed recovery and fencing procedures. Application database backup and recovery remain separate.

**Troubleshooting and stop conditions:** Restore blocked: verify Administrator authority, freeze, revision, backup integrity and target identity. Never delete keys or replace entire state from another node as a shortcut.

**Completion evidence:** Restore drill demonstrates correct revision, authorized login, live traffic and auditable recovery; independent backup retention confirmed.

## L2 · SOP-21: Observability and incident response

**Who:** Viewer / Operator / platform specialist

**Before you start:** Site-specific thresholds and external telemetry/audit setup where enabled.

1. Traffic metrics and health: record UTC, gateway, route, backend, status/error rates and latency. Compare with actual traffic and approved baseline; distinguish app errors from gateway transport failures.
2. For configured OTLP, verify collector HTTPS trust, connectivity, sampling and queue/drop counters. Collector outage can lose telemetry without stopping proxy; audit delivery has separate durable outbox and blocked/fault indicators.
3. Do not log authorization headers, passwords, OTPs, private keys, request bodies or customer-sensitive payloads. Use redacted correlation identifiers and timestamps. Preserve audit, transaction IDs and configuration revision.
4. Classify incident severity, notify owner/security as needed, freeze risky changes under authorization, investigate one hypothesis at a time and verify recovery before closure.

**Troubleshooting and stop conditions:** Telemetry missing: check configured endpoint, service identity, TLS, collector ingestion and drop/staleness. Audit blocked: escalate before further protected changes; never disable audit to proceed.

**Completion evidence:** Evidence-based RCA, restored traffic, audit continuity and corrective action owner.

## L1 · SOP-22: Troubleshooting decision tree: 401, 403, 404, 409, 423, 429, 502, 503, 504

**Who:** All users / authorized support

**Before you start:** Collect evidence without mutation first.

1. 401: sign-in/session/OTP; 403: check role, entitlement, WAF or management access policy and audit. Do not bypass auth. 404: check correct listener, hostname/path and route revision.
2. 409: revision, state or authority conflict; reread current state, reconcile before new action. 423: freeze; ask authorized administrator. 429: respect rate limits; stop repeated attempts.
3. 502: gateway-to-backend failure or upstream response; verify approved DNS/TCP/TLS and backend logs. 503: readiness/eligible destinations or service/entitlement state; check health and configuration. 504: upstream timeout; correlate app latency and network evidence.
4. If impact is broad, compare another gateway and independent client probe. For signing/payment/non-idempotent POST uncertainty, reconcile the business transaction with application owner; never assume failure means it did not commit.

**Troubleshooting and stop conditions:** Escalate when there is customer impact, suspected compromise, uncertain mutation, lost quorum, both nodes unhealthy, or no verified recovery path. Do not restart indiscriminately.

**Completion evidence:** Identify failing layer, collect reproducible sanitized evidence, verify recovery with an independent request.

## L1 · SOP-23: Safe diagnostic commands for Windows and Linux

**Who:** Authorized support / host administrator

**Before you start:** Use only approved endpoints and read-only commands; replace placeholders with authorized values.

1. Windows PowerShell: Get-Service to inspect service status; Get-WinEvent -LogName Application -MaxEvents 30 for recent application events; Resolve-DnsName for approved hostname; Test-NetConnection with approved host and port. Get-FileHash -Algorithm SHA256 verifies package or approved artifact.
2. Linux: systemctl status with the approved unit; journalctl -u with approved unit and time window; ss -lntup for listening sockets; getent hosts for configured hostname. Use normal service-manager authorization; do not restart without approval.
3. Local ordinary lab: curl http://127.0.0.1:8080/gateway/health or Invoke-WebRequest to inspect liveness. Readiness is /gateway/health/ready on the appropriate approved listener. For trusted HTTPS use normal certificate validation; never use -k to claim success.
4. For authoritative DNS use approved DNS host and port: dig @server -p port zone SOA +norecurse and repeat with +tcp, validate AA and expected serial. On Windows use approved DNS tooling capable of direct UDP and TCP proof. Do not query public resolvers with sensitive names.

**Troubleshooting and stop conditions:** If a command is unavailable, use approved equivalent or escalate to host team. Redact machine-specific sensitive details before sharing logs; never include passwords, tokens or private keys.

**Completion evidence:** Actual observed output supports the failing layer; all diagnostics are read-only unless separately authorized.

## L1 · SOP-24: Incident escalation and RCA template

**Who:** All users

**Before you start:** Use your organization's severity policy and contact roster.

1. Record incident ID, UTC start/end, affected sites/services, business impact, observed symptoms, exact approved version/revision and recent change.
2. Collect sanitized request/correlation ID, status, time window, health/metrics, relevant logs, current signed transaction/receipt and configuration diff; exclude OTPs, keys, license secrets and personal data.
3. Escalate to L1 service desk for access/basic monitoring, L2 gateway/network/application support for route/backend/service failures, L3 platform/PKI/DNS/security for authority, keys, quorum, DNSSEC, WAF and enterprise identity. Suspected compromise or broad outage follows emergency/security process.
4. Document hypothesis vs confirmed root cause, containment, approved corrective action, verification, rollback status, preventive action, owner and due date. Do not mark resolved from a green process health check alone.

**Troubleshooting and stop conditions:** If evidence is inconclusive, say so. If mutation status is uncertain, stop further changes and reconcile. Contact names and response targets must be supplied by the customer's approved SOP.

**Completion evidence:** Incident owner accepts actual service recovery; RCA and follow-up tasks recorded.

## L3 · SOP-25: Release, physical acceptance and operator qualification

**Who:** Platform lead / security / change authority

**Before you start:** Exact reviewed source, approved artifacts, site evidence and authorized production decision.

1. Verify exact-head CI including separate CodeQL gate, independent approval, post-merge main CI and final installer/source SHA-256. A green build is software evidence only.
2. Use issue #36 physical acceptance: actual independent hosts, VIP/ECMP, real failover/failback and partition, sustained site-specific capacity/latency, TLS/identity/audit, backup recovery and real representative traffic. Do not lower approved thresholds or substitute synthetic runs.
3. Train new employees in isolated environment: first login, named role, website draft with separate reviewer, actual request, health incident and escalation. L2/L3 demonstrate certificate, DNS, WAF and recovery procedures with authorized specialists.
4. Production remains NO-GO until owner/site change authority signs acceptance. Keep documented release and rollback evidence; do not treat the manual as authorization to execute.

**Troubleshooting and stop conditions:** Failed/unknown gate: stop release, preserve results and assign corrective action. Do not expose lab management to public traffic.

**Completion evidence:** Separate software, user training, physical environment and authorized release signoffs.

## Detailed engineering references

- [Operator quick guide](OPERATOR_QUICK_GUIDE.md)
- [Windows offline lab installer](../../ops/windows-installer/README.md)
- [Enterprise OIDC](ENTERPRISE_OIDC.md) and [LDAP/mail](LDAP_MAIL_SETUP.md)
- [Signed fleet configuration](SIGNED_FLEET_CONFIG.md) and [engine staging](../GatewayAgent/ENGINE_STAGING.md)
- [WAF remote fenced node](../../ops/waf/REMOTE_FENCED_NODE.md) and [GSLB engine](../../engines/GslbDns/README.md)
- [OTLP export](OTEL_EXPORT.md) and [production gates](ONPREM_PRODUCTION_GO_GATES.md)

Customer-specific contacts, SLA thresholds and approval authorities must be completed locally. No private credentials or installation-specific values belong in this guide.
