# 0.1 operator runbook

## First-run browser bootstrap

1. Install into the existing offline Windows Server test project. Keep the admin listener restricted to 127.0.0.1.
2. Open `/dashboard`. The initial screen creates a **local recovery Administrator**; do not store a default password in the package.
3. Sign in and open **Setup Center**. Its status cards are backed by `/admin/api/setup/overview`; it does not claim that configured backends are healthy.
4. Configure internal SMTP and test its delivery. If needed, configure AD/LDAPS and verify certificate trust and group-to-role mapping before enabling directory sign-in.
5. In **Architecture & Setup**, choose standalone, HA pair or fleet, then save/confirm the design. No Windows services, firewall rules, or YARP routes are touched by confirmation.

## Public application onboarding from frontend

1. In Setup Center, click **Onboard public application**.
2. Enter an application ID, hostname, HTTP route pattern, two independent HTTPS backend URLs and readiness endpoint.
3. This generates a **local draft**, not active traffic. It does not configure TLS certificates, firewall VIPs or AD authorization policies.
4. Verify endpoint ownership and safety of sessions, background jobs and the existing Pgpool-II connection path.
5. Submit the draft as a change request. A different Administrator must approve. During a routing change freeze, requests/approval/restores are blocked with HTTP 423.
6. After approval, query **Live YARP health states** and test actual proxying and failover. Enable active readiness checks only after your backend endpoint contract is verified.

**Restricted RA/SSCA and OCSP/CRL** are intentionally excluded from this quick-create wizard. Configure these via your change-controlled routing procedures and validate CA-specific policy before any production migration.

## Gateway health vs backend health

- `/gateway/health`: local gateway process HTTP liveness.
- `/admin/api/runtime/destinations`: actual YARP runtime active/passive health values. `Unknown` is not "Healthy".
- `/admin/api/probe`: independent on-demand HTTP readiness test. It is not YARP's internal health state.
- `/admin/api/destination-metrics`: local request counters since process start, not fleet-wide persisted telemetry.

## Change freeze and recovery

- Setup Center → **Freeze routing changes**. Enter a reason of at least 12 characters. Operator/Viewer cannot change the freeze state.
- Local approved configuration writes, route-change submissions, restore and fleet rollout return HTTP 423 while frozen; current proxied traffic continues.
- Unfreeze with an audit reason. Local freeze is not a distributed lock across two independent YARP controllers.
- Use Administrator → Backups & audit to restore a snapshot. Restore requires Administrator and is blocked by routing freeze.
- Keep independent offline backups of source **and** ProgramData identity/secret state; the installer only backs up source automatically.

## Disaster and rollback

- Do not overwrite production gateway artifacts before staging tests and signing off an approved CA change.
- If `INSTALL.ps1` fails, inspect its backup path under `C:\YARP\Backups`, then follow `RESTORE-BACKUP.ps1` guidance. A restored source build does not necessarily revert ProgramData edits made after installation.
- For real gateway HA, monitor the upstream VIP and test both YARP gateway failures and APP-01/APP-02 failures independently.
