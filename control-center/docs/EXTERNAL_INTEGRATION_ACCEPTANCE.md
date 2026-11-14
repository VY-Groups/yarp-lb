# External integrations — evidence-based acceptance

Single-tenant, on-prem GatewayCore. **Source CI passing is not production GO.**
No live credentials, company names, domain details or screenshots are used in
test fixtures. An account password shown in chat or a screenshot must be
considered exposed and rotated separately.

## CI acceptance delivered

| Suite | Real components | Proven when the exact-SHA job succeeds | Does NOT prove |
|---|---|---|---|
| External HTTP origin integrations - Apache and Nginx | Shipping .NET GatewayCore, real Docker Apache 2.4 and Nginx origins, separate Nginx ingress-style proxy | Two-person-approved YARP config change, real HTTP forwarding via Nginx → YARP → Apache/Nginx | Live IIS, HTTPS/mTLS rewrites, real Kubernetes ingress controller |
| Real SMTP STARTTLS and OTP integration (isolated CI) | Shipping .NET GatewayCore and independent authenticated STARTTLS SMTP fixture | Platform trust, protected password at rest, accepted message, wrong-code rejection, real email OTP cookie login | Actual Zoho/enterprise SMTP delivery or provider quotas |
| Real Control Center E2E - browser and API | Production-mode .NET app and headless Chromium | RBAC, CSRF, account lifecycle, approvals, rollback, browser navigation | External system availability, physical HA |

A cancelled, skipped or failed test is not positive evidence.

## Required external systems and remaining gates

| Area | Verification required for live-site GO | Status |
|---|---|---|
| SMTP/OTP | Rotate exposed credentials; configure account-specific SMTP hostname, port 587 STARTTLS and distinct app password in secure UI; verify real inbox delivery, authenticated login, outage and retry controls | NOT VERIFIED externally |
| AD/LDAPS | Authorized DC, trusted certificate hostname/chain, read-only bind account and 636/TCP; test nested groups, disabled users, role revocation, DC outage, OTP | NOT VERIFIED externally |
| Apache/Nginx | Real origins now tested over local HTTP in CI; still test application host/path routing, TLS, sessions, redirects, WebSockets and health on your actual servers | PARTIALLY VERIFIED |
| IIS | Actual Windows IIS site, certificates, application pools, cookie/auth, and redirects; an IIS-like CI stub does NOT equal real IIS | NOT VERIFIED against real IIS in this CI |
| Kubernetes Ingress | Real controller and Kubernetes Ingress/Service/Endpoint objects, TLS/namespace isolation, reload and failover. Standalone Nginx ingress-style proxy does not qualify | NOT IMPLEMENTED/NOT VERIFIED |
| Fleet and physical HA | Two physical nodes, agents with real mutual TLS and revocation, independent approvals, partial rollout recovery, VIP passive ejection, live SIGTERM/KILL, sustained per-node capacity evidence | HARDWARE GATE OPEN |
| OCSP/CRL/HSM/PKI | HSM-key non-exportability proof, PKCS#11/approved interface, chain and revocation policy, OCSP/CRL happy/negative paths and authorized PKI reviewer | NOT IMPLEMENTED/NOT VERIFIED |
| Independent immutable audit | Real external WORM sink, retention/legal hold and write isolation, tamper/replay detection, export receipts, failure-mode acceptance | NOT IMPLEMENTED |
| Enterprise SSO | Approved OIDC/SAML identity provider with issuer/audience/nonce/state/PKCE and enforced FIDO2/smartcard, roles, token revocation and break-glass | NOT IMPLEMENTED |

## Mail provider guidance

Zoho's official SMTP guide says to confirm exact SMTP hostname in the
account's Server Configuration Details. Paid domain-based organizations may
use smtppro.zoho.com and others smtp.zoho.com, with port 587 and STARTTLS.
With MFA use an app-specific password. The webmail login URL is not SMTP.
Do not store secrets in source, GitHub Actions logs, images, tickets or chat.

Official source: https://www.zoho.com/mail/help/zoho-smtp.html

## GO/NO-GO rule

- SOURCE/CI GO only after exact-SHA build and all required real-process tests.
- CONTROLLED TEST GO requires isolated hosts and a proven rollback.
- ALL-FEATURE GO is false if ANY requested item remains NOT IMPLEMENTED.
- PRODUCTION GO additionally requires physical HA/capacity, approved identity,
  cert trust/revocation, WORM/SSO controls where required and governance signoff.

See ONPREM_PRODUCTION_GO_GATES.md. No test in this PR alters a user server,
connects to a real provider mailbox or bypasses TLS trust.
