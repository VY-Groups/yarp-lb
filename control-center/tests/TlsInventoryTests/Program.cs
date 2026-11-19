var now = new DateTime(2026,11,13,12,0,0,DateTimeKind.Utc);
if (TlsInventory.ExpiryState(now.AddDays(-1),now) != "expired") throw new Exception("expired state");
if (TlsInventory.ExpiryState(now.AddDays(10),now) != "expiring-within-30-days") throw new Exception("warning state");
if (TlsInventory.ExpiryState(now.AddDays(60),now) != "valid-date-only") throw new Exception("valid state");
Console.WriteLine("PASS: TLS certificate expiry boundaries");

var staging = "https://acme-staging-v02.api.letsencrypt.org/directory";
var eligible = AcmeTargetPolicy.Validate(staging, "api.example.com", http01: true,
    publicChallengeEntrypointEnabled: true);
if (!eligible.Allowed || eligible.NormalizedDnsName != "api.example.com")
    throw new Exception("public ACME HTTP-01 target should pass preflight");
var idn = AcmeTargetPolicy.Validate(staging, "bücher.com", http01: false,
    publicChallengeEntrypointEnabled: false);
if (!idn.Allowed || idn.NormalizedDnsName != "xn--bcher-kva.com")
    throw new Exception("public IDN name should normalize to its ASCII DNS form");

void Reject(string? directory, string? name, bool http01 = true, bool entrypoint = false,
    bool loopbackTestAuthority = false)
{
    if (AcmeTargetPolicy.Validate(directory, name, http01, entrypoint, loopbackTestAuthority).Allowed)
        throw new Exception($"unsafe ACME target policy input unexpectedly allowed: {name}");
}

Reject("http://acme-staging-v02.api.letsencrypt.org/directory", "api.example.com");
Reject("https://user:password@acme-staging-v02.api.letsencrypt.org/directory", "api.example.com");
Reject("https://127.0.0.1/directory", "api.example.com");
Reject("https://acme-staging-v02.api.letsencrypt.org:8443/directory", "api.example.com");
Reject("https://acme-staging-v02.api.letsencrypt.org/other", "api.example.com");
Reject(staging, "127.0.0.1");
Reject(staging, "service.internal");
Reject(staging, "service.local");
Reject(staging, "*.example.com");
Reject(staging, "api.example.com", http01: true, entrypoint: false);
Reject("https://127.0.0.1:14000/directory", "api.example.test", http01: true,
    entrypoint: true, loopbackTestAuthority: false);
var localAuthority = AcmeTargetPolicy.Validate("https://127.0.0.1:14000/directory",
    "api.example.com", http01: true, publicChallengeEntrypointEnabled: true,
    allowLoopbackTestAuthority: true);
if (!localAuthority.Allowed)
    throw new Exception("explicit loopback test authority should be accepted for isolated fixture use");
Console.WriteLine("PASS: ACME target preflight rejects unsafe authority, hostname and HTTP-01 inputs");
await AcmeHttp01Acceptance.RunAsync();
await TrafficHttp3Acceptance.RunAsync();
await TrafficCertificateRotationAcceptance.RunAsync();
