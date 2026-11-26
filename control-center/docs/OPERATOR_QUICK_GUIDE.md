# GatewayCore operator quick guide

Open the installed dashboard at http://127.0.0.1:8080/dashboard on the gateway host. This is a lab management listener, not a public traffic endpoint.

## Daily workflow

1. On a fresh Windows Setup installation, open the protected `C:\ProgramData\GatewayCoreYarp\ControlPlane\first-run-code.txt` as a local administrator. In the dashboard wizard, authorize installation, configure the existing company sender or approved SMTP relay, verify a code in a readable mailbox, enter the administrator email, verify its separate registration OTP, and create the username/password. Email OTP is enabled at completion. Accept the Privacy Policy and set the organization. Existing initialized installations keep their current accounts and mail configuration.
2. Open **Start here → Gateway architecture**. Choose Standalone for a single test gateway or document an HA design. The quick standalone template fills design fields only. Review and confirm the design.
3. Choose **Add website / API**. Enter a name, actual client hostname and trusted HTTPS backend root URL. Leave the second server blank for a single origin; add a second distinct HTTPS server for round-robin. Active readiness checks are initially disabled until a real readiness endpoint is verified. For an existing local HTTP website on a standalone gateway, use **Local website test** and the /lab/ path.
4. Review **Websites & routes** and **Backend servers**. Use **Configuration → Backend groups** for balancing and health settings. Submit the browser-session draft with a reason of at least 12 characters. A different authorized administrator must review and approve it in **Change requests**. Drafts are not live routing.
5. After approval and application, inspect backend runtime health, run probes and test real client traffic through the approved listener. Local test URL: http://127.0.0.1:8080/lab/. Unknown is not healthy. Review Traffic metrics.

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
