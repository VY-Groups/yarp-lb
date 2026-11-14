# GatewayCore v0.1 Windows IIS reverse-proxy test release

**Pre-release / laptop test only. Not approved for production.**

The GitHub release ZIP is a **self-contained Windows x64** .NET 10 ASP.NET Core
GatewayCore executable, plus \`Start-GatewayCore-Test.ps1\`. There is **no Apache
dependency** and no need to install Apache. IIS remains the upstream web server;
GatewayCore sits in front of it for locally generated test requests.

## Install on Windows 10/11 or Windows Server (x64)

1. Download the ZIP from this repository's GitHub **Releases** page, not
   from a random mirror. Extract the *whole ZIP* into a new directory,
   e.g. \`C:\GatewayCore-Test\`. Do **not** copy it over any existing Control Center.
2. Open **Windows PowerShell as Administrator** (isolated testing only).
   Find the actual IIS website binding with \`Get-Website\` (WebAdministration
   module where IIS is installed). Start the site; ensure its local URL responds:
   \`Invoke-WebRequest -UseBasicParsing http://127.0.0.1/\`.
   If your site has another local port, substitute it.
3. Enter your extracted directory and run:

\`\`\`powershell
cd C:\GatewayCore-Test
.\Start-GatewayCore-Test.ps1 -IisBackendUrl "http://127.0.0.1:80/"
\`\`\`

**Upgrade from the previous v0.1.0-test.1 or test.2 package:** stop its
GatewayCore process first. Independently back up the old extracted app folder
and `C:\ProgramData\GatewayCoreYarp\ControlPlane` (including keys, users and
configuration). Extract the new release into its **own fresh directory**. On
the same machine, with the **same locally verified IIS origin URL** and the
same v0.1 test identity, use the explicit opt-in parameter:

```powershell
.\Start-GatewayCore-Test.ps1 -IisBackendUrl "http://127.0.0.1:80/" -ReuseExistingTestState
```

The switch does not copy, delete or rewrite old state and refuses to replace
an existing mismatched `appsettings.json`. It permits the same development
application to use its previous state; it is **not** a production migration
tool or permission to merge unrelated credentials. If this is not the same
test installation, use a disposable Windows VM instead. Existing v0.1
management identity files remain sensitive.

The program stays in the foreground until you press Ctrl+C. It binds
**127.0.0.1:8080 only**, leaving IIS on 80/443 untouched. This is the
first run on a **fresh test machine**. Existing appsettings or populated
GatewayCore Windows ProgramData state makes the installer stop instead of
overwriting identities/keys. To choose a different gateway port use \`-Port 18080\`.

## Test IIS through GatewayCore

In a second PowerShell window:

\`\`\`powershell
Invoke-WebRequest -UseBasicParsing http://127.0.0.1:8080/gateway/health
Invoke-WebRequest -UseBasicParsing http://127.0.0.1:8080/proxy/
\`\`\`

A 200 from \`/gateway/health\` proves liveness, not upstream readiness.
\`/proxy/\` should return the IIS site's actual status/content; if your IIS
application returns 401, 403, or 404, examine its binding, authentication,
host header and rewrite rules rather than declaring gateway success.

Use a **separate load generator** whenever measuring meaningful capacity;
this localhost-only installer is for first-stage functional testing:

\`\`\`powershell
oha -z 30s -q 50 -c 20 --no-tui http://127.0.0.1:8080/proxy/
\`\`\`

Do not route live traffic here. Do not run load tests against a real
customer-facing IIS application or production database. Use an isolated
IIS test website serving fixed-size static files, and establish a baseline
against the IIS URL directly before comparing gateway throughput.
The generator's traffic is always limited to this laptop's loopback
for this package; do not publish 8080 via firewall/NAT.

## Stop, cleanup, and limitations

Press Ctrl+C in the gateway console. The extracted files are not installed
as a Windows Service; no IIS configuration or firewall rules are edited.
The application does create a local Windows Control Plane state directory
under ProgramData. Retain it for audit or remove it only after confirming
that this test installation owns it and you have a backup. Never overwrite
an existing Data Protection key ring.

A successful GitHub publish/smoke proves a usable *testing package only*.
Physical 750 Mbps+RPS/60-minute per-node acceptance, independent-host HA,
logging reliability, PKI validation and CAB signoff remain production NO-GO.
