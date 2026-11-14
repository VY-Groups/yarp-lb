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

For an India data-center account the webmail login is mail.zoho.in
(HTTPS); it is NOT the SMTP server. Zoho's India data-center notice lists
smtppro.zoho.in and smtp.zoho.in as SMTP hostnames. For a paid
custom-domain organization try smtppro.zoho.in, port 587, STARTTLS; for
personal/free accounts try smtp.zoho.in, port 587, STARTTLS.
Always confirm the exact hostname in Zoho Mail's Server Configuration Details,
because account type and data center determine the correct endpoint.
With MFA use a NEW app-specific password and rotate any exposed credentials.
Never put credentials in GitHub, issues, logs, screenshots or test fixtures.

The Mail & OTP page now offers Zoho India presets that only fill host,
port and STARTTLS, while leaving usernames and passwords to the operator.
To test the real network/TLS handshake WITHOUT AUTH or sending a message,
run the optional preflight on an approved testing server:

    python tests/E2E/zoho_india_smtp_preflight.py --host smtppro.zoho.in

A successful preflight is NOT evidence of provider credentials, actual email
delivery, inbox receipt or OTP verification. Those require a separately
provisioned least-privilege testing mailbox and operator approval. Never
hardcode this account's credentials in the repository or CI.

Official SMTP source: https://www.zoho.com/mail/help/zoho-smtp.html
India data center notice: https://help.zoho.com/portal/en/community/topic/important-notice-to-zoho-mail-indian-datacentre-in-dc-deployment-users

## GO/NO-GO rule

- SOURCE/CI GO only after exact-SHA build and all required real-process tests.
- CONTROLLED TEST GO requires isolated hosts and a proven rollback.
- ALL-FEATURE GO is false if ANY requested item remains NOT IMPLEMENTED.
- PRODUCTION GO additionally requires physical HA/capacity, approved identity,
  cert trust/revocation, WORM/SSO controls where required and governance signoff.

See ONPREM_PRODUCTION_GO_GATES.md. No test in this PR alters a user server,
connects to a real provider mailbox or bypasses TLS trust.
