# SpeedSign 0.1 — Traffic engine and platform boundary

## Scope of this engineering update

**Code added**: two YARP `ILoadBalancingPolicy` implementations, deterministic/pure selection core, destination weight editor, reviewed-change validation, authenticated capability inventory API, and a corresponding browser page. This update **does not** install a firewall, DNS server, WAF, packet proxy, metrics collector, Redis, or Kubernetes controller.

**Windows acceptance still pending**: `dotnet build`, pure algorithm test project, HTTP traffic distribution, changed-membership behavior, CSRF/RBAC, approved change rollout to each gateway, and backend failover drills. Do not forward CA production traffic until these tests pass.

## What the new policies actually do

| Policy | Algorithm | When to use | Limitations |
|---|---|---|---|
| `WeightedRandom` | Cryptographically uniform random draw over the sum of 1–100 destination weights | Simple canary/weighted traffic between healthy HTTP destinations | Per-request share is statistical, not exact; requests are not sticky |
| `SourceIpHash` | Weighted rendezvous hash of immediate TCP peer address and destination ID | HTTP traffic with real, trusted client-IP visibility and stable backend IDs | Firewall SNAT collapses clients onto one identity; changed membership can remap some users; do not use to protect transaction state |
| `RoundRobin` | Built-in | Equal-weight backend distribution | No per-destination weight |
| `LeastRequests` | Built-in | Uneven request duration | Not TCP connection count, not EWMA latency |
| `PowerOfTwoChoices` | Built-in/default | General healthy-destination selection | Not actual least-response-time routing |
| `FirstAlphabetical` | Built-in | Prefer one destination with failover | **Not** active-active request spreading |

### Weight metadata

In the browser: **Backends → Add/Edit backend → Traffic weight (1–100)**. To apply weighting, select `WeightedRandom` or `SourceIpHash` for the **Cluster**. Example:

```json
{
  "ReverseProxy": {
    "Routes": {
      "sample": { "ClusterId":"sample", "Match":{"Hosts":["api.example.com"],"Path":"/api/{**remainder}"} }
    },
    "Clusters": {
      "sample": {
        "LoadBalancingPolicy": "WeightedRandom",
        "Destinations": {
          "api01": { "Address":"https://api01.internal.example.com:5001/", "Metadata":{"Weight":"80"} },
          "api02": { "Address":"https://api02.internal.example.com:5001/", "Metadata":{"Weight":"20"} }
        }
      }
    }
  }
}
```

All addresses are placeholders. The existing management app adds edits to a draft. A different authorized administrator must approve a change. Certificates must validate; proxy applications must not bypass authentication/authorization.

### Source IP warnings

The custom `SourceIpHash` only uses `context.Connection.RemoteIpAddress`, **not any raw, spoofable X-Forwarded-For header**. If your perimeter firewall performs source NAT, several users may be hashed as the firewall, and all use the same destination. A properly tested trusted-forwarded-headers configuration can modify this property, but must only trust known upstream addresses and proxies. Never enable this policy merely by guessing client identity.

YARP's available destination list is already filtered through configured health policies before the load-balancing selection is called. Neither custom policy repairs stateful applications or implements failover for in-flight requests.

## Install in existing SpeedSign 0.1 lab

1. Back up `C:\YARP\SpeedSignYarp` and `C:\ProgramData\SpeedSignYarp\ControlPlane` securely.
2. Stop the running .NET gateway and open elevated Windows PowerShell.
3. Extract this ZIP, review `PRECHECK.ps1` and `INSTALL.ps1`, then run them. The installer does not overwrite `appsettings.json`, and it backs up source under `C:\YARP\Backups`.
4. If the C# compilation passes, run `VERIFY-TRAFFIC-EXPANSION.ps1` **before** starting the gateway. It runs the pure algorithm tests too; the unauthenticated HTTP check only runs if a gateway is separately started.
5. Start the gateway with `dotnet run --no-build --no-launch-profile`. Open `http://127.0.0.1:8080/dashboard` **on the same server**, then sign in.
6. Open **Traffic Engine & modules** to view declared status, not manufactured availability.
7. Under **Clusters**, select an approved algorithm. Under **Backends**, set validated weights. Submit changes and obtain independent approval.
8. For acceptance, run repeatable HTTP traffic through both healthy test backend instances and record per-destination observations. Disable one backend, verify requests go only to the surviving healthy destination after health detection, then restore the backend and observe reintegration.
9. Verify configuration revision consistency across any additional gateway. This package does not make distributed rollout atomic.

## Validate from Windows Server (runtime compilation required)

```powershell
cd C:\YARP\SpeedSignYarp
dotnet build --no-restore
cd C:\Users\Administrator\Desktop\SpeedSign-YARP-ControlCenter-0.1-Traffic-Expansion
dotnet restore .\tests\LoadBalancingCoreTests\LoadBalancingCoreTests.csproj --ignore-failed-sources
dotnet run --project .\tests\LoadBalancingCoreTests\LoadBalancingCoreTests.csproj --no-restore
```

`LoadBalancingCoreTests` has no external NuGet references. Your gateway still needs the YARP and LDAP packages in the local feed for a restored build. For detailed use, see README.md.

## Rejected shortcuts

- No fabricated switch to turn YARP into a TCP/UDP balancer, authoritative DNS, anycast BGP router, DDoS appliance or OWASP CRS engine.
- No blanket automatic retries for POST signing, RA approvals, OCSP updates, or eKYC submissions.
- No arbitrary remote command endpoint for Windows enrollment.
- No public exposure of the local control-plane HTTP listener.
- No assertion that selecting a custom algorithm alone is proof of production readiness.
