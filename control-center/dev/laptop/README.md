# Windows laptop development environment

This is a **0.1 developer sandbox** for Windows 10/11 with .NET 10 SDK. No Server 2022, Docker, administrator privileges, domain controller, SMTP server, Redis or public DNS is required for this *local* smoke test.

## Prerequisites
- `dotnet --list-sdks` includes a `10.0.x` SDK
- Windows PowerShell 5.1 or PowerShell 7
- Git for cloning (or extract the GitHub repository ZIP)
- First run needs access to NuGet.org for `Yarp.ReverseProxy` and `System.DirectoryServices.Protocols`.

## Start
From your cloned repo:

```powershell
cd .\control-center
powershell -NoProfile -ExecutionPolicy Bypass -File .\dev\laptop\Start-Laptop.ps1
```

On first launch the script generates `control-center/appsettings.json` **only if missing**, and refuses to use preexisting files unless tagged `DevelopmentLab.LabOnly=true` and configured for loopback. Never place production secrets or hostnames into this test config.

The script runs `BackendLab.dll` twice (127.0.0.1:18081 and :18082), and the full Control Center at `http://127.0.0.1:8080/dashboard`. Use the dashboard to bootstrap a development administrator with a unique password at least 16 characters and a valid email address. No mail will be sent unless you explicitly configure SMTP. Local state, including encrypted test credentials, lives under `%LOCALAPPDATA%\YarpControlCenterDev\state` and is user-specific DPAPI protected. This mode is Windows-only; it is not a multi-user production security design.

## Automated developer verification

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\dev\laptop\Start-Laptop.ps1 -SmokeTest
```

Success requires: both mock backends ready, management dashboard 200, 120 real YARP HTTP requests routed to both backends, anonymous protected-API access denied (401), and a Prometheus histogram. The script stops only the dotnet processes it launched. Read startup errors in `%LOCALAPPDATA%\YarpControlCenterDev\logs`.

## Security boundaries
- Only loopback addresses, no firewall changes, no Windows services, no real CA/PKI routes, no AD/SMTP/ACME by default.
- Do not set `ASPNETCORE_URLS` to public interfaces or forward port 8080 externally.
- A separate Windows Server installer exists, but it is **not** suitable for initial local setup.
- Control plane currently remains single-organization. Distributed HA, L4, DNS/GSLB, WAF, automatic certificate issuance, OIDC, immutable audit, Terraform and Kubernetes integration are independent work and are not simulated by this script.

## Troubleshooting
If ports 8080 or 18081/18082 are occupied, stop your previous local gateway/backend, or close the other instance before starting. If NuGet restore fails, inspect `dotnet nuget list source` and your network/proxy. If DPAPI or other state is corrupt, **back up** `%LOCALAPPDATA%\YarpControlCenterDev\state` before modifying files; reinstalling code does not reset that state.
