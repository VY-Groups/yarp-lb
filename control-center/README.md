# YARP Control Center — 0.1 (universal / development)

A **single-organization**, Windows-first YARP management application. The operator supplies its organization name and sector (general, technology, finance, healthcare, government, telecom, e-commerce, education, CA/PKI or other). The CA profile is **optional**; no CA application/database/topology is assumed by the product.

> **Not production certified.** Source, offline installer and browser frontend are provided. Windows C# compilation, integration tests, security review, and environment-specific CA/industry acceptance remain required. A checkbox or profile choice does not implement a WAF, GSLB, enterprise IdP, L4 transport or real multi-tenant isolation.

## What's actually new in this package

- Brand-neutral browser frontend with **Organization** configuration as first-time step after initial local administrator setup.
- Authenticated `GET /admin/api/organization`, `GET /admin/api/organization/sectors` and administrator-only/CSRF-protected `PUT /admin/api/organization` with revision checks. Store: protected local ProgramData file. On save, an administrative audit entry is appended (local/mutable, **not WORM**).
- Sector profiles for the ten stated industries. **Advisory labels only**; no automatic CA/finance/medical compliance.
- Local-only `/gateway/metrics` Prometheus 0.0.4 text format using per-process counters; can be scraped from the same machine by a collector. **Not OpenTelemetry or distributed metrics by itself.**
- Two standalone test HTTP backends (`tests/MockHttpBackend`) and a read-only real-traffic measurement script (`tests/L7Integration/VERIFY-HTTP-DISTRIBUTION.ps1`) for a laboratory route.
- Existing YARP policies (RoundRobin/LeastRequests/PowerOfTwoChoices etc), source-implemented weighted random and source-IP rendezvous hashing, active/passive YARP health configuration, independent change approval, local auth/AD integration, onboarding and offline packaging inherited from 0.1.
- Existing `appsettings.json`, users and deployment state are **not** reset by installation.

## Architecture boundary and limits

**Data plane**: YARP HTTP/HTTPS L7 gateway instances. **Control plane**: administration + draft approval, separate identity/secrets/state. **External edge**: VIP/firewall, WAF/DDoS, GSLB/DNS and L4 engine as optional, separately installed components. **Applications**: arbitrary web/API destinations including CA/PKI, healthcare and government, with policy specific to service type.

This release currently assumes ONE organization per controller. Different industries can deploy independent instances. **It is not SaaS multi-tenant safe**: profiles do not enforce per-tenant authorization or storage segregation.

**Legacy migration compatibility:** the existing Windows project path `C:\YARP\SpeedSignYarp`, .NET assembly name, cookie name, ASP.NET Data Protection application name and `C:\ProgramData\SpeedSignYarp\ControlPlane` store remain unchanged. Renaming them without an explicit migration would break current accounts/cookies/encrypted SMTP settings. New installations will receive a separate path migration in a future validated release.

## Run on a Windows 10/11 laptop (no elevated shell)

On your laptop with .NET SDK 10 and Git installed:

```powershell
git clone https://github.com/VY-Groups/yarp-lb.git
cd yarp-lb\control-center
powershell -NoProfile -ExecutionPolicy Bypass -File .\dev\laptop\Start-Laptop.ps1
```

The script builds the project, generates a loopback-only **development** `appsettings.json` (only if missing), starts two mock backends and the full Control Center, prints the dashboard URL, and stops the processes it owns on Ctrl+C. Development login/OTP state is isolated under `%LOCALAPPDATA%\YarpControlCenterDev\state`; server state is untouched. For an automated check, run `Start-Laptop.ps1 -SmokeTest`. Read `dev/laptop/README.md`. It is **not** the Windows Server installer and must never be exposed on a public address.

## Install on offline test server

1. Stop existing `SpeedSignYarp` process, obtain a separate verified backup of both the project and `C:\ProgramData\SpeedSignYarp\ControlPlane`.
2. Extract ZIP to Desktop or another folder **outside** the C# project, open PowerShell as Administrator.
3. Run one command at a time:

```powershell
cd "C:\Users\Administrator\Desktop\YARP-Control-Center-0.1-Universal"
.\PRECHECK.ps1
.\INSTALL.ps1
```

4. If the installer reports PASS:

```powershell
cd C:\YARP\SpeedSignYarp
dotnet run --no-build --no-launch-profile
```

5. Open **http://127.0.0.1:8080/dashboard** from the test server only. If no initial admin exists, bootstrap a recovery admin. Next, complete **Organization**, **Setup Center** and **Architecture & setup**. Configure routes only as drafts requiring independent approval. On an existing installation, verify the Organization page and save the correct name/profile.
6. In a second console run the verification suite:

```powershell
cd "C:\Users\Administrator\Desktop\YARP-Control-Center-0.1-Universal"
.\VERIFY-UNIVERSAL.ps1
```

The gateway remains a loopback-only laboratory service; HTTPS and production network binding are **not** configured by the setup wizard.

## Lab HTTP tests (not production)

On the test server, open two separate PowerShell windows to run disposable ASP.NET Core backends. All listeners are loopback-only and need no network/external package restore:

```powershell
cd "C:\Users\Administrator\Desktop\YARP-Control-Center-0.1-Universal\tests\MockHttpBackend"
dotnet restore --ignore-failed-sources
dotnet run --no-restore -- 18081 node-a
```

In the second window, from the same folder:

```powershell
dotnet run --no-restore -- 18082 node-b
```

In the console, create **lab-only** route `/api/{**catch-all}` for host `lab.example.test` with destination addresses `http://127.0.0.1:18081/` and `http://127.0.0.1:18082/` (the generic public HTTPS wizard is intentionally unsuitable for these lab-only HTTP addresses). Have a second administrator approve. Do not replace a production route. Use a dedicated test cluster. Then:

```powershell
.\tests\L7Integration\VERIFY-HTTP-DISTRIBUTION.ps1 -GatewayUrl 'http://127.0.0.1:8080/api/identity' -HostHeader 'lab.example.test' -Requests 200
```

This checks that response identities from BOTH backends are observed. Use `/test/ready/false` on a mock backend to test configured active health checks, re-test, and recover with `/test/ready/true`. Test weighted ratios and source hashing separately with the right policies and connection identity. Confirm no two-person or CA policy bypass.

## Test and security status

- Frontend TypeScript compilation and Node UI tests: executable in build environment.
- C# source compilation and real HTTP routing: **operator's Windows gate** (not executed in this build environment).
- `/gateway/metrics` is loopback restricted and unauthenticated only to support a local collector. Never forward it publicly.
- SMTP/LDAPS require actual approved relay/CA trust and network testing. Enterprise OIDC/FIDO2, immutable central audit, PostgreSQL HA control plane, fleet agent enrollment, L4 and GSLB are NOT delivered here.
- Review `docs/UNIVERSAL_PLATFORM_PLAN.md` and `docs/ACCEPTANCE_MATRIX.md` before considering expansion.
