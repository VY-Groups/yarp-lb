# GatewayCore operator quick guide

Open the installed dashboard at http://127.0.0.1:8080/dashboard on the gateway host. This is a lab management listener, not a public traffic endpoint.

## First shift: what to prepare

Ask your lead for the approved sender and SMTP settings, a second authorized administrator, the gateway server names, the client hostname, backend addresses, a known readiness URL and the change-ticket number. Never use production credentials in training, and never share an administrator account. Administrator configures identity and gateway design and reviews other people's changes; Operator prepares drafts; Viewer observes status. An enabled account count does not prove that the reviewer can sign in or that mail works.

## Daily workflow

1. On a fresh Windows Setup installation, open the protected `C:\ProgramData\GatewayCoreYarp\ControlPlane\first-run-code.txt` as a local administrator. In the dashboard wizard, authorize installation, configure the existing company sender or approved SMTP relay, verify a code in a readable mailbox, enter the administrator email, verify its separate registration OTP, and create the username/password. Email OTP is enabled at completion. Accept the Privacy Policy and set the organization. Existing initialized installations keep their current accounts and mail configuration.
2. Open **Start here → Gateway architecture**. Choose Standalone for a single test gateway or document an HA design. The quick standalone template fills design fields only. Review and confirm the design.
3. In **Start here**, follow the Approval team step. An administrator creates a separate authorized reviewer in **Security & accounts → Admin accounts**. Verify the reviewer can sign in in a separate session. Use a named Operator account for daily configuration whenever possible.
4. Choose **Add website / API**. Enter a name, actual client hostname and trusted HTTPS backend root URL. Leave the second server blank for a single origin; add a second distinct HTTPS server for round-robin. Active readiness checks are initially disabled until a real readiness endpoint is verified. For an existing local HTTP website on a standalone gateway, use **Local website test** and the /lab/ path.
5. Review **Websites & routes** and **Backend servers**. Use **Configuration → Backend groups** for balancing and health settings. Submit the browser-session draft with a reason of at least 12 characters. A different authorized administrator opens **Change requests → Review full draft**. Read the proposed route and backend tables, inspect the complete exact JSON (including advanced policy, disabled servers and revision), enter the independent review note and approve or reject. The requester cannot make a decision on their own request. Drafts are not live routing.
6. After approval and application, inspect backend runtime health, run probes and test real client traffic through the approved listener. Local test URL: http://127.0.0.1:8080/lab/. Unknown is not healthy. Review Traffic metrics.

## Where to find settings

| Task | Page |
| --- | --- |
| Common tasks and onboarding | Start here |
| Local process status | Dashboard |
| Host/path rules | Websites & routes |
| Server addresses, drain, runtime status | Backend servers |
| Balancing policies and readiness paths | Configuration → Backend groups |
| Backup, audit and recovery | Configuration → Backups & audit |
| Users, OTP and directory | Security & accounts |
| Multi-node evidence, peer state and module inventory | Multi-gateway & modules |

## Safety and troubleshooting

- A route maps client hostname/path to a backend group (cluster); a backend is one application origin (destination).
- Separate public/private host matching is not network isolation. Configure trusted TLS, listener restrictions and firewall policies independently.
- A confirmed architecture is design metadata, not deployment. HA, VIP, agent enrollment and signed rollout require independent operational verification.
- On a failed installation, keep protected state and keys, and inspect the automatically created Setup log. Never delete state to bypass a guard.
- The ordinary lab package is unsigned and not a commercial or production release. Issue #36 physical acceptance remains separate.

The same guide is available inside the dashboard through **User guide**. No network access is needed to read it.

## First-shift troubleshooting

| Symptom | Next safe action |
| --- | --- |
| Setup checklist says Required | Follow the recommended action. If your role cannot configure it, ask the platform administrator. |
| One administrator | Create and test a separate named reviewer account. Never approve using shared credentials. |
| Draft not submitted | Use Submit for approval and enter the actual change-ticket reason; fix any error without losing the draft. |
| Request pending | Ask the independent reviewer to open the saved request. Do not create duplicate requests. |
| Revision conflict | Read the current live config, reconcile the draft and submit a new reviewed revision. |
| No healthy backend | Inspect active/passive states and verify the real health URL and trusted TLS. An unknown state is not proof of failure or health. |
| 502/503 errors | Check saved host/path routing, backend availability, certificate trust and freeze/rollout state. Review traffic metrics and audit before changing configuration. |
| Need rollback | Locate the correct backup and follow the documented recovery procedure with change authorization; do not delete protected state. |

A new employee is ready to operate only after demonstrating the approved workflow with two distinct accounts and a real test request. Production traffic, VIP failover, capacity and recovery require separate physical acceptance.

## Invite a new employee (ordinary standalone local-account lab)

After verified SMTP is configured, open **Security & accounts → Admin accounts → Invite employee**. Enter the named username, company mailbox and Viewer or Operator role. The employee receives a one-time email code valid for at most 30 minutes. They open the authorized management dashboard, choose **Accept employee invitation**, verify the code, then enter and confirm their own 16–256 character password. The short-lived completion capability expires within 10 minutes and is never placed in a URL. The employee signs in normally with password and a separate delivered login OTP, then accepts the Privacy Policy. Invitations never assign Administrator privileges. The issuer may revoke a pending invitation; a service restart invalidates all pending invitations. Changes to the issuing administrator’s authority or verified sender invalidate redemption. Do not forward codes or passwords. Reissue only after revocation or expiry. Commercial, multi-gateway, enterprise SSO and external audit deployments retain their own enrollment paths; this local feature is not distributed identity enrollment.
