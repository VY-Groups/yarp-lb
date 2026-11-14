# GatewayCore / YARP Control Center — v0.1

A **single-tenant, on-premises HTTP(S) L7 reverse proxy and management control center**, built with .NET 10 and [YARP](https://microsoft.github.io/reverse-proxy/). Designed for isolated Windows and Linux testing with a controlled configuration approval workflow.

> **Status: GO for controlled test/staging environments; NOT production-certified.** Successful GitHub Actions and real-browser integration tests do not prove actual-server HA, sustained capacity, external identity/PKI acceptance or security signoff. Do not deploy this test build in front of production services.

## Latest Windows test build

**[GatewayCore v0.1.0-test.11 — GitHub Release](../../releases/tag/v0.1.0-test.11)**

- Self-contained **Windows x64** test application; no local .NET SDK installation is required to launch the published executable.
- Includes Mail & OTP provider presets, Gmail/Microsoft OAuth2 client flows, Zoho India SMTP, an enforced security verification workflow, and fixes for same-page form resets and scrollable navigation.
- Built and tested with real Windows executable/proxy smoke, frontend TypeScript parity, real-process API acceptance, and headless Chromium browser tests.
- The test release is not a Windows Service installer or code-signed production release. Windows Smart App Control or organizational application-control policy may block an unsigned executable. **Do not disable endpoint protection** to work around it.

[Windows test installation and precautions](ops/windows-test/README.md) · [Windows release workflow](.github/workflows/windows-test-release.yml) · [Release SHA-256 checksums](../../releases/download/v0.1.0-test.11/SHA256SUMS.txt)

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
- [External integration evidence and manual acceptance ledger](control-center/docs/EXTERNAL_INTEGRATION_ACCEPTANCE.md)

**Verified source reference:** [PR #71](../../pull/71) passed **11/11 exact-commit CI workflows**, including the new mail-provider security gate; [PR #68](../../pull/68) delivered the earlier browser fixes. The [test.11 Windows release workflow](.github/workflows/windows-test-release.yml) independently gates source parity, Windows executable smoke and security tests. These results apply only to their verified commits, not to future changes. Check the [latest Actions status](../../actions) before installation.

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
