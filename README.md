# GatewayCore / YARP Control Center — v0.1

## Ownership and future commercial licensing

**GatewayCore is intended as an owner-controlled proprietary software product,
not an open-source product offering.** Its eventual customer licensing,
activation, maintenance and distribution terms are **to be designed only after
the remaining development issues are completed**. No commercial licensing
module, license server, subscription enforcement or customer activation scheme
is implemented or authorized by this statement.

**Reference-only clarification from the owner (2026-11-21):** OpenGSLB was
consulted only to understand feature behavior. GatewayCore's DNSSEC NSEC3
functionality is independently implemented in C# against RFC 5155. The current
checkout has no root `LICENSE` file, and earlier repository revisions included
project-wide AGPL license text. Review that licensing history before making
distribution claims.

Repository visibility is separate from copyright: a GitHub repository can be
public without being an offered open-source product, but public source remains
readable and clonable. Source confidentiality requires a deliberate repository
visibility/access-control decision by the owner.

A **single-tenant, on-premises HTTP(S) L7 reverse proxy and management control center**, built with .NET 10 and [YARP](https://microsoft.github.io/reverse-proxy/). Designed for isolated Windows and Linux testing with a controlled configuration approval workflow.

> **Status: GO for controlled test/staging environments; NOT production-certified.** Successful GitHub Actions and real-browser integration tests do not prove actual-server HA, sustained capacity, external identity/PKI acceptance or security signoff. Do not deploy this test build in front of production services.

## About GatewayCore

**GatewayCore** is an owner-controlled, **single-organization, self-hosted application gateway and management platform**. Its core is an ASP.NET Core **.NET 10** application using **YARP** to route HTTP(S) traffic to approved web applications and APIs. Operators use a separate **Control Center** to manage inventory, review routing changes, control access, view local health and metrics, and exercise backup/rollback procedures. It is intended for controlled, isolated Windows and Linux deployments—not a cloud-managed SaaS service.

**In one sentence:** GatewayCore aims to provide reviewed, observable on-premises L7 traffic routing, with **optional and still experimental** adjacent DNS/GSLB, L4 TCP/UDP, WAF, GitOps and enterprise integrations.

**Audience:** platform/DevOps engineers, network and application operators, and security reviewers who need to operate self-hosted HTTP reverse proxies behind their own firewall/VIP and connect them to existing applications. It can front IIS, Apache, Nginx and compatible HTTP backends without taking ownership of their application databases, signing keys, or internal business transactions.

**Repository About description (suggested):** `Self-hosted .NET 10/YARP L7 gateway with an approval-based Control Center; experimental GSLB, L4, WAF and GitOps integrations.`

> **Release boundary:** The software is suitable for **controlled test/staging evaluation only**. A green workflow or a successful local proxy request is **not** proof of independent physical-node HA, secure public DNS delegation, 60-minute capacity, enterprise PKI/IdP, or production availability. **Production: NO-GO** until the [physical and operational acceptance gates](control-center/docs/ONPREM_PRODUCTION_GO_GATES.md) are signed off.

## How the architecture fits together

```text
                         Clients / internal applications
                                     |
                    Operator-managed DNS / firewall / VIP
                                     |
                Optional external WAF and ingress (separate)
                            /                   \
                  Gateway instance A       Gateway instance B
                  .NET 10 + YARP L7        .NET 10 + YARP L7
                            \                   /
                             \                 /
                       HTTP(S) destination cluster
                       IIS / Apache / Nginx / APIs
                                     |
                   Existing application databases/services
                     (not controlled by GatewayCore)

    Separate management plane:
    Administrators -> Control Center -> reviewed change requests
                    -> authorization/audit -> approved YARP config

    Opt-in standalone/lab components, NOT in the L7 request path by default:
       GSLB authoritative DNS | L4 TCP/UDP engine | external OWASP CRS WAF
       GitOps read-only planner | fleet / telemetry integration contracts
```

This diagram shows the **target topology**, not a claim that the repository provisions a floating VIP or has completed physical two-host failover. Gateway instances are active HTTP workers, **not database replication masters**. A working active/active site requires separate ingress health checks and a valid configuration on each participating host. Backend PostgreSQL/Pgpool or other transactional systems remain independent and must handle their own consistency and disaster recovery.

### Components and current support

| Component | What it does today | What it does **not** establish |
| --- | --- | --- |
| **YARP L7 data plane** | HTTP routing to destination clusters, balancing, active/passive health, controlled routing changes and local liveness/readiness. | Guaranteed zero-error node failure, automatic ingress VIP creation, signed-transaction replay safety or a physical traffic SLA. |
| **Control Center** | Single-organization setup, administrator access, route/cluster inventory, revision checks, CSRF/RBAC, different requester/approver, audit records and managed change/restore workflows. | A multi-tenant SaaS control plane, an immutable external WORM audit service or fully accepted enterprise SSO. |
| **Fleet/availability** | Local or selected signed configuration/agent contracts and disposable failure/restart tests. | Proven physical multi-gateway synchronization, independent host failure, power-loss recovery or deployment-wide traffic availability. |
| **DNS / GSLB** | A separate opt-in .NET authority-style engine with UDP/TCP, NS/SOA, EDNS, signed health reports/authority fencing and selected DNSSEC/geo policies; see its own tests. | Public delegation certification, complete DNS standard interoperability, production multi-NS consistency or managed Control Center provisioning. |
| **L4 engine** | Separate experimental TCP stream and UDP endpoint relay with bounded sessions, health/drain and platform socket tests. | L4 as YARP middleware, production-grade cross-host L4 control, TLS/SNI switching or all PROXY protocol variants. |
| **WAF** | A **separate external** ModSecurity/OWASP CRS Docker lab with detection/blocking-mode tests and measured synthetic traffic. | An embedded gateway WAF, universal attack coverage, a production policy exception lifecycle or verified site false-positive rates. |
| **GitOps/config plans** | Authenticated server-side dry-run and a read-only offline schema-limited route/cluster diff planner. | Automated signed Git reconciliation, a Terraform provider, Kubernetes Gateway API controller or automatic apply. |
| **Identity, email, certificates, observability** | Local administrator/security flows, mail/OTP configuration and isolated relay tests, selected certificate/data-protection controls, local metrics and optional telemetry export. | Live provider delivery, production OIDC/AD/LDAPS, CA/HSM/OCSP verification, external immutable audit or delivered on-call alerts. |

### How an operator change reaches traffic

1. **Bootstrap** a *fresh, isolated* installation; configure the organization and create its first recovery administrator. Back up existing test state before upgrading.
2. **Register and validate** intended websites, destination clusters and routing rules. A dry-run plan can describe differences, but a plan alone never activates a route.
3. **Request a configuration change** under the administrator role and the site's authorization/CSRF policies. The change is revision-bound; a stale revision is rejected.
4. **Approve independently** with a different authorized reviewer. A successful approval triggers the supported state/config application path and records a local audit event.
5. **Verify** liveness, readiness, backend HTTP behavior, logs and metrics; exercise a documented rollback before accepting the change.

Do not place the management listener on the public data-plane interface, treat a matching YARP route as a firewall rule, or retry a non-idempotent signing/transaction POST merely because an upstream timed out.

### What to install — and what not to expect

- **Windows x64 disposable evaluation:** use the latest verified **test pre-release** and the [Windows test launcher guide](ops/windows-test/README.md). The launcher defaults to loopback; its parameter `-IisBackendUrl` is a compatibility name and can point at other approved local HTTP origins. It does not install IIS, a service, a firewall rule, an ingress VIP or a production certificate.
- **Linux source/systemd evaluation:** follow [Control Center setup](control-center/README.md), [platform key-ring support](control-center/docs/DATA_PROTECTION_PLATFORM_SUPPORT.md) and the [systemd template](ops/systemd/gatewaycore-yarp.service). A source build and an example service file do not equal an installed or approved production service.
- **Optional components:** [GSLB](engines/GslbDns/README.md), [L4](engines/L4/README.md), [external WAF](integrations/WafCrs/README.md) and [offline config planner](control-center/tools/GatewayConfigPlan/README.md) each have separate configuration, safety limits and test harnesses. None is silently installed by the Windows launcher.

### Developer quick reference

Requires the **.NET 10 SDK** (see [global.json](global.json)) for source builds, Python 3 for selected acceptance harnesses, and Docker for the standalone WAF integration lab. These are development/test commands from a clean checkout, **not production deployment commands**:

```bash
dotnet build control-center/GatewayCoreYarp.csproj -c Release
dotnet build engines/GslbDns/GslbDns.csproj -c Release
dotnet run --project tests/GslbAcceptance/GslbAcceptance.csproj -c Release -- "$PWD"
python3 -m unittest discover -s tests/CI/branding -p 'test_*.py' -v

# Optional: uses disposable containers; does not configure a production WAF.
bash tests/WafCrs/verify.sh
```

For PR acceptance, inspect **all required workflows on the exact PR head SHA**, including CodeQL, Windows/Linux builds, real-process integrations and domain-specific tests. [CI release evidence](ops/release/README.md) and the [software/physical acceptance ledger](ops/acceptance/V1_CONSOLIDATED_EVIDENCE_LEDGER.md) explain the distinction. Failed, queued or missing checks are not success.

### Maintainer documentation map

| Need | Authoritative project guide |
| --- | --- |
| Topology, management/data-plane separation | [Architecture specification](control-center/docs/ARCHITECTURE.md) |
| Setup, operators, API and approvals | [Control Center README](control-center/README.md) |
| Security and Data Protection by platform | [Windows/Linux support matrix](control-center/docs/DATA_PROTECTION_PLATFORM_SUPPORT.md) |
| Offline install, packaging and rollback | [Windows test guide](ops/windows-test/README.md) and [release procedure](ops/release/README.md) |
| Traffic metrics and load acceptance | [Capacity kit](ops/capacity/README.md) |
| GSLB, L4, WAF and GitOps boundaries | [DNS](engines/GslbDns/README.md), [L4](engines/L4/README.md), [WAF](integrations/WafCrs/README.md), [GitOps](control-center/tools/GatewayConfigPlan/README.md) |
| Current implementation gaps and tests | [GitHub issues](../../issues), [open pull requests](../../pulls) and [Actions](../../actions) |
| Physical GO / NO-GO | [On-prem production gates](control-center/docs/ONPREM_PRODUCTION_GO_GATES.md) |

**Licensing and redistribution:** Proprietary customer licensing is a future project phase, not a feature in this release. See [ownership and licensing status](#ownership-and-future-commercial-licensing) and [reference and license status](REFERENCE_AND_LICENSE_STATUS.md). Earlier project-wide license terms require review before distribution claims.

## Latest published Windows test build

**[GatewayCore v0.1.0-test.12 — GitHub Release](../../releases/tag/v0.1.0-test.12)**

- Self-contained **Windows x64** test application; no local .NET SDK installation is required to launch the published executable.
- Includes Mail & OTP provider presets, Gmail/Microsoft OAuth2 client flows, Zoho India SMTP, an enforced security verification workflow, and fixes for same-page form resets and scrollable navigation.
- Built and tested with real Windows executable/proxy smoke, frontend TypeScript parity, real-process API acceptance, and headless Chromium browser tests.
- The test release is not a Windows Service installer or code-signed production release. Windows Smart App Control or organizational application-control policy may block an unsigned executable. **Do not disable endpoint protection** to work around it.

[Windows test installation and precautions](ops/windows-test/README.md) · [Windows release workflow](.github/workflows/windows-test-release.yml) · [Release SHA-256 checksums](../../releases/download/v0.1.0-test.12/SHA256SUMS.txt)

### First test on a disposable Windows server

1. Back up any previous **test** configuration and `C:\ProgramData\GatewayCoreYarp\ControlPlane` (including the Data Protection key ring), stop any running GatewayCore process, and extract the new ZIP to **a separate directory**. Never overwrite a running installation.
2. Start a known-good **local test HTTP origin** (for example IIS on port 80) and verify `http://127.0.0.1/` responds.
3. Open **Administrator PowerShell** in the extracted ZIP's top-level folder:

```powershell
.\Start-GatewayCore-Test.ps1 -IisBackendUrl "http://127.0.0.1:80/"
```

The parameter name `-IisBackendUrl` is retained for launcher compatibility; the configured destination can be a **local Apache, Nginx, IIS or other HTTP server**, provided its URL is an approved isolated test origin. The launcher does **not** install or configure those servers, change firewall rules, or create a production edge/VIP.

For the **same previously initialized v0.1 test installation only**, after an independently verified backup, the launcher also supports explicit `-ReuseExistingTestState`. This is **not** a general-purpose migration from renamed legacy identities, old encrypted secrets or existing production state.

In a second terminal, verify both routes:

```powershell
curl.exe -i http://127.0.0.1:8080/gateway/health
curl.exe -i http://127.0.0.1:8080/proxy/
```

Open **http://127.0.0.1:8080/dashboard** on the test host. Create the first recovery administrator only for a fresh installation, then complete Organization → Setup Center → Architecture & Setup. Routing changes require independent approval. The gateway binds **localhost only** in this launcher; publishing it externally needs a separate, approved deployment and security review.

## Tested capabilities and evidence

Real-process integration tests start the shipping ASP.NET Core application with disposable, protected state and send real HTTP requests. Browser tests use Chromium without mocked administrative APIs.

| Area | Automated acceptance evidence | Boundary |
| --- | --- | --- |
| Control Center & browser | Administrator bootstrap, sign-in/out, role restrictions, session invalidation, Setup Center, Architecture, Add Website, Edit Route, Reset Password, navigation and mobile-width UI | Not a substitute for testing every browser or your own deployment |
| Administrative API/workflows | Cookie/CSRF authorization, onboarding revisions, inventory, separate requester/approver, freeze, live route reload, backups/rollback, audit records and process restart | Real external systems and failure recovery remain site-specific |
| HTTP L7 gateway | Real requests through YARP, load balancing, metrics, health and controlled failover | Actual traffic mix, TLS policies, hardware HA and sustained throughput require physical testing |
| Experimental GSLB DNS engine | Independent .NET authoritative-style A/AAAA + NS/SOA, UDP/TCP/EDNS0, weighted/failover/CIDR and opt-in trusted-ECS MaxMind country/ASN routing, HTTP/TCP health, opt-in DNSSEC, Windows/Linux DNS acceptance | Separate process with static JSON; not a complete authoritative DNS or UI-managed production deployment |
| Web servers | Real **Apache httpd** and **Nginx** HTTP origins plus an Nginx → YARP → origin ingress-style chain | This is **not** a Kubernetes Ingress Controller, nor proof of actual IIS/Apache/Nginx site TLS/redirect/auth behavior |
| SMTP & email OTP | Isolated authenticated STARTTLS SMTP server, certificate verification, protected credentials, message acceptance and OTP sign-in | **Live Zoho inbox delivery remains NOT VERIFIED** |
| AD/LDAPS | Backend support and local validation/security gates | Live domain controller, CA trust, nested-role mapping and revocation not accepted |
| Fleet / PKI / SSO / audit | Selected contracts and defensive tests exist | Physical fleet HA, Kubernetes ingress, HSM/OCSP/CRL, immutable WORM audit and enterprise OIDC/FIDO2 SSO are **not fully implemented or accepted** |

Relevant tests and workflows:

- [Real browser and administrative API E2E](.github/workflows/e2e-real-control-center.yml) — [test code](tests/E2E/)
- [Real Apache and Nginx HTTP integration](.github/workflows/external-origins-e2e.yml)
- [Isolated authenticated SMTP STARTTLS and OTP](.github/workflows/smtp-starttls-e2e.yml)
- [Windows and Linux Control Center source checks](.github/workflows/control-center-ci.yml)
- [L7 HTTP traffic and failover tests](tests/L7/)
- [Standalone DNS/GSLB acceptance (Windows & Linux)](.github/workflows/gslb-acceptance.yml) — [test code](tests/GslbAcceptance/)
- [External integration evidence and manual acceptance ledger](control-center/docs/EXTERNAL_INTEGRATION_ACCEPTANCE.md)

**Verified source reference:** [PR #71](../../pull/71) passed **11/11 exact-commit CI workflows**, including the new mail-provider security gate; [PR #68](../../pull/68) delivered the earlier browser fixes. The [Windows test-release workflow](.github/workflows/windows-test-release.yml) independently gates source parity, Windows executable smoke and security tests. These results apply only to their verified commits, not to future changes. Check the [latest Actions status](../../actions) before installation.

## Experimental GSLB engine — opt-in lab only

The standalone `engines/GslbDns` process provides **DNS-based global site
selection**, separate from the YARP HTTP load-balancing dataplane and the
Control Center's currently managed routes. It is **not automatically deployed,
configured or controlled by the main GatewayCore management UI**.

Implemented in independently authored .NET code and verified in disposable
Windows/Linux DNS acceptance: non-recursive UDP/TCP responses for A, AAAA,
NS and SOA (where configured), EDNS0, address-family-correct negative answers,
weighted site distribution, optional priority failover, private resolver-CIDR
and opt-in trusted-ECS country/ASN region mapping using operator-supplied
MaxMind MMDB files, bounded health hysteresis, HTTP(S) / TCP checks, and capped
parallel health sweeps. The GSLB engine also has opt-in P-256 DNSSEC signing;
parent DS publication and independent public delegation acceptance remain open.

The private CIDR mapping uses the **DNS resolver socket address**. The separate
`GeoIpEcs` policy uses only explicitly allowlisted recursive resolvers, caps
client subnet detail at IPv4 `/24` and IPv6 `/56`, and requires an operator
licensed, current MMDB file. Unknown, conflicting or more-specific GeoIP data
falls back to weighted routing. Do not delegate production DNS domains to this
prototype. TSIG, full authoritative DNS conformance, distributed signed health
quorum, remote API configuration, multi-authority propagation, public-network
DNS interoperability and physical DC/DR failover remain open.

- [GSLB configuration, behavior and limitations](engines/GslbDns/README.md)
- [Enterprise feature-parity and release evidence matrix](engines/GslbDns/GSLB_CAPABILITY_PARITY.md)
- [Updated OpenGSLB source review and licensing boundary](engines/GslbDns/OPENGSLB_REFERENCE_REVIEW.md)
- [P0 authoritative GSLB issue #52](../../issues/52)

The `gslb` branch contains OpenGSLB, which was consulted only as a feature
reference. GatewayCore's NSEC3 behavior is independently implemented against
RFC 5155. The separate reference project's license does not describe GatewayCore.
Feature and cost tables are requirements inputs, not vendor certifications.

## SMTP providers and security verification

The **Mail & OTP** console supports strict STARTTLS relay/application-password
submission as well as provider-specific **Google and Microsoft OAuth2/XOAUTH2**
token acquisition. Presets include Gmail/Google Workspace, Microsoft 365,
Outlook.com, Exchange Server on-premises, Zoho India, Yahoo, iCloud, Fastmail
and custom SMTP. **An SMTP preset is not an OAuth consent screen or a promise
that an account is permitted to send.** OAuth applications, tenant consent,
mailbox access and any provider app passwords must be configured separately.
Integrated Exchange Windows/NTLM authentication and implicit TLS port 465
are not supported in the current package.

Security controls include pinned OAuth token endpoints, provider-bound SMTP
token destinations, protected secrets, CSRF/role validation, and an enforced
save → test → enable-OTP sequence. The
[dedicated security CI workflow](.github/workflows/security-acceptance.yml)
runs real administrative API/authorization checks and cross-platform
provider/OAuth security tests; the
[mail provider setup guide](control-center/docs/MAIL_PROVIDER_SETUP.md)
describes per-provider prerequisites and known limitations. External provider
delivery and OAuth consent still require a real authorized acceptance test.

## Zoho Mail India: SMTP and OTP testing

**`https://mail.zoho.in/` is webmail, not an SMTP server.** Choose the outgoing SMTP host from the account's **Zoho Mail → Server Configuration Details**. Typical India-region options are:

| Account type | SMTP hostname | Port | Transport |
| --- | --- | --- | --- |
| Organization / eligible paid domain | `smtppro.zoho.in` | 587 | STARTTLS |
| Other eligible accounts | `smtp.zoho.in` | 587 | STARTTLS |

The Mail & OTP screen offers presets that fill the **hostname, port and STARTTLS**, leave the account/password blank, and keep OTP disabled until delivery has been tested. Provider eligibility and host selection must be checked against your specific Zoho account. An app-specific SMTP password may be necessary when MFA is enabled.

**Optional authorized, live send-to-self test** (from a local checkout on an approved test machine with Python 3 and network access):

```powershell
python tests/E2E/zoho_india_authenticated_mail_test.py --host smtppro.zoho.in --username YOUR_TEST_EMAIL --send-to-self
```

The script prompts for the SMTP password **without echoing it**, enforces trusted STARTTLS with hostname validation on port 587, and sends **one** test message only to that account. It returns SMTP acceptance status and a reference token; **SMTP acceptance does not establish inbox delivery**. Open `mail.zoho.in` and confirm the matching subject. Use the other SMTP hostname only if your Zoho Server Configuration Details require it.

For a no-authentication/no-send connectivity check, use:

```powershell
python tests/E2E/zoho_india_smtp_preflight.py --host smtppro.zoho.in
```

**Never commit or paste credentials into GitHub, Actions secrets/logs, issues, code, or screenshots.** A password disclosed in a screenshot should be rotated or revoked even if the mailbox is temporary. The repository's automated CI tests deliberately use a separate disposable mail relay; they do **not** access or authenticate to your Zoho account.

[Zoho official SMTP guide](https://www.zoho.com/mail/help/zoho-smtp.html) · [Detailed mail and other integration acceptance](control-center/docs/EXTERNAL_INTEGRATION_ACCEPTANCE.md)

## Production gates — still NO-GO

A production decision requires **all** relevant gates to pass on the **actual deployment**:

- Verify observed traffic units. For a confirmed **500 Mbps** peak and 50% headroom, each surviving physical gateway must independently sustain **at least 750 Mbps** of actual HTTP response-body throughput **plus peak-RPS headroom**, over **60 minutes**, with zero errors, acceptable per-window p99 and no NIC/log loss. If the reported traffic is **500 MB/s** rather than 500 Mbps, recalculate the target; do not use 750 Mbps.
- Prove two independent hosts, ingress/VIP failover, graceful drain, hard-kill recovery, config integrity, certificate trust, audit and rollback while traffic is flowing.
- Validate real SMTP delivery, AD/LDAPS, upstream TLS/PKI, operator monitoring and independent change approval as appropriate.
- Do **not** overwrite or copy old encrypted identity stores: renamed application/cookie/Data Protection purposes need a separately approved migration and rollback.

[Single-tenant on-prem production GO/NO-GO gates](control-center/docs/ONPREM_PRODUCTION_GO_GATES.md) · [Control Center architecture and detailed installation](control-center/README.md) · [Repository Actions](../../actions)

## Repository layout

| Path | Role |
| --- | --- |
| `control-center/` | .NET GatewayCore/YARP control plane, frontend and application tests |
| `tests/E2E/` | Real-process administrative API, browser, SMTP and Apache/Nginx acceptance |
| `tests/L7/` | L7 traffic, routing and load-test harnesses |
| `ops/windows-test/` | Windows test launcher and safe installation instructions |
| `ops/` | Capacity, infrastructure, operations and release-evidence procedures |
| `.github/workflows/` | Exact-source build, integration, safety and test-release gates |

**No GitHub workflow in this repository is permission to deploy or change your private on-prem servers.** Treat test-release binaries and CI fixtures as evidence for controlled testing, not production certification.
