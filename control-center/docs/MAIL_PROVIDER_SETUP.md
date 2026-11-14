# GatewayCore mail providers, OAuth2 and administrator security

**Single-tenant on-prem testing only. No external mailbox credentials belong in GitHub.**
The Mail & OTP page configures outgoing **SMTP** for administrator test mail and
one-time codes; it is not a general IMAP, Exchange mailbox or Microsoft Graph
client. The connection is mandatory STARTTLS with normal platform certificate
and hostname verification; port 465 implicit TLS remains unsupported.

## Provider selection

| Provider / deployment | Suggested SMTP server | Supported authentication in this version | External prerequisites |
| --- | --- | --- | --- |
| Gmail and Google Workspace | `smtp.gmail.com:587` | Delegated OAuth2 / XOAUTH2 with client secret + refresh token; authorized account app password when available | Google OAuth app registration, authorization and SMTP scope, mailbox/provider policy |
| Microsoft 365 / Exchange Online | `smtp.office365.com:587` | Delegated OAuth2 or app-only Microsoft Entra OAuth2 | SMTP AUTH permission, Entra consent, mailbox/service principal and SendAs authorizations |
| Outlook.com / Hotmail | `smtp-mail.outlook.com:587` | Microsoft delegated OAuth2 (consumer tenant) | Outlook SMTP OAuth consent and a refresh token |
| Exchange Server on-premises | **Your approved Exchange receive/submission connector** | STARTTLS with SMTP AUTH password or trusted relay without SMTP AUTH | Connector settings, TLS certificate and IP restrictions. **Integrated Windows/Kerberos/NTLM SMTP auth is not implemented.** |
| Zoho India organization | `smtppro.zoho.in:587` | Approved SMTP app-specific password or policy-enabled authenticated SMTP | Check account's own Server Configuration Details |
| Zoho India personal/free | `smtp.zoho.in:587` | Approved SMTP app-specific password | Check account's own Server Configuration Details |
| Yahoo Mail | `smtp.mail.yahoo.com:587` | SMTP application password, where provider permits | Provider-verified app password |
| Apple iCloud | `smtp.mail.me.com:587` | App-specific SMTP password | Apple account app-specific password |
| Fastmail | `smtp.fastmail.com:587` | SMTP application password | Provider application password |
| Custom SMTP relay | Your approved hostname and STARTTLS port | SMTP AUTH credentials or trusted no-auth local relay | Explicit sender allowlist, secure TLS certificate, source restrictions |

Presets only fill server/mode/port/STARTTLS and **disable OTP** until a
fresh test succeeds; no passwords or tokens are copied into HTML. Provider
names and default endpoints are suggestions, not a guarantee that every
account type supports SMTP AUTH or the necessary application registrations.
Check live account documentation before configuring a hosted service.

## OAuth modes

**Google delegated OAuth2** requires a previously approved Google Cloud OAuth
client ID/secret and a delegated refresh token authorized for Gmail SMTP.
The gateway exchanges that refresh token at the **pinned** Google token
endpoint and authenticates with SMTP SASL XOAUTH2 at `smtp.gmail.com`.

**Microsoft delegated OAuth2** requires a Microsoft Entra client ID/secret,
a delegated refresh token and the tenant GUID, `organizations` or `consumers`.
The approved scope is `https://outlook.office.com/SMTP.Send offline_access`.
The client obtains a short-lived access token from Microsoft's pinned tenant
endpoint and uses SASL XOAUTH2. For consumer Outlook accounts use the
`consumers` tenant, not an organization app-only credential.

**Microsoft 365 app-only OAuth2** requires a concrete tenant GUID, Entra
client ID and client secret, admin consent to `SMTP.SendAsApp`, Exchange
registration of the service principal and mailbox-level authorization
(including SendAs when required). The token grant uses
`https://outlook.office365.com/.default` and `smtp.office365.com:587`.

The current UI **does not perform an interactive OAuth authorization-code,
device-code, or consent flow** and does not automatically write back a newly
rotated refresh token. Set up the approved OAuth registration separately and
supply credentials via the local administrator UI. All stored OAuth client
secrets and refresh tokens use the existing protected Data Protection store;
they are not sent by the GET settings API. Tokens are refreshed on each send.
Do not upload access tokens or refresh tokens to GitHub or attach them to
support tickets.

For Microsoft 365, verify SMTP AUTH is enabled on the specific mailbox and
that tenant policy permits the flow. SMTP AUTH Basic authentication is on a
deprecation path: **do not build a new production deployment around Basic**.

Official documentation:
- Google: https://developers.google.com/workspace/gmail/imap/imap-smtp
- Microsoft OAuth: https://learn.microsoft.com/en-us/exchange/client-developer/legacy-protocols/how-to-authenticate-an-imap-pop-smtp-application-by-using-oauth
- Microsoft SMTP AUTH: https://learn.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/authenticated-client-smtp-submission
- Microsoft January 2026 timeline: https://techcommunity.microsoft.com/blog/exchange/updated-exchange-online-smtp-auth-basic-authentication-deprecation-timeline/4489835

## Safe setup and operational security

1. Sign in with a dedicated Administrator on a test gateway bound to
   **localhost or a separately approved HTTPS management network**.
2. In **Mail & OTP**, select the provider and authentication mode, then
   confirm SMTP host, correct sender and account/tenant permissions.
3. Save with **Require email OTP disabled**.
4. Select **Send test to my account**. A test is rate limited and directed
   to the currently signed-in administrator's registered mailbox.
5. Confirm the email **arrived in the inbox**; an SMTP 250 acceptance alone
   is not end-to-end receipt. Only then enable email OTP and save again.
6. Sign out and prove correct-code, wrong-code, expired-code and relay-outage
   behavior using nonproduction accounts. Keep a protected recovery path.

Mandatory invariants:
- OAuth tokens may only be sent to the matching approved Google or Microsoft
  SMTP hosts. The OAuth token server cannot be supplied by a user-entered URL.
- All SMTP modes require STARTTLS with certificate/hostname verification.
- Secret changes, provider/host changes and switching authentication modes
  invalidate previous delivery proof; no OTP enable without a new test.
- An existing saved secret can be preserved only for the identical OAuth
  host/username/client/tenant and mode; switching identities cannot reuse it.
- An unauthorized role, missing session, missing/invalid CSRF or invalid
  provider settings must be rejected server-side.
- Never disable TLS/certificate verification, log token endpoints' returned
  secrets, or copy another instance's Data Protection key ring.

## Automated security acceptance

- [Dedicated security gate](../../.github/workflows/security-acceptance.yml):
  Windows/Linux token-host policy tests plus real authenticated .NET
  administrator session/CSRF/role/change-approval validation.
- [Real browser+API gate](../../.github/workflows/e2e-real-control-center.yml):
  provider presets, OTP toggles, sign-in/out and UI interactions.
- [Isolated SMTP+OTP gate](../../.github/workflows/smtp-starttls-e2e.yml):
  actual SMTP STARTTLS authentication and OTP with a disposable relay.

These CI jobs **never** authenticate to real Google, Microsoft, Exchange
or Zoho accounts. Third-party consent, provider token rotation and actual
mailbox delivery require a separate authorized integration acceptance
before production GO.
