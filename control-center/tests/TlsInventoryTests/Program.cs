using System.Net.Sockets;

var now = new DateTime(2026,11,13,12,0,0,DateTimeKind.Utc);
if (TlsInventory.ExpiryState(now.AddDays(-1),now) != "expired") throw new Exception("expired state");
if (TlsInventory.ExpiryState(now.AddDays(10),now) != "expiring-within-30-days") throw new Exception("warning state");
if (TlsInventory.ExpiryState(now.AddDays(60),now) != "valid-date-only") throw new Exception("valid state");
Console.WriteLine("PASS: TLS certificate expiry boundaries");

var tcpCandidates = new Queue<int>([51001, 51002, 51003, 51004]);
var tcpReservationAttempts = 0;
var udpReservationAttempts = 0;
var selectedDualTransportPort = TrafficHttp3Acceptance.SelectDualTransportPort(
    () =>
    {
        tcpReservationAttempts++;
        if (tcpReservationAttempts == 1)
            throw new SocketException((int)SocketError.AccessDenied);
        return (tcpCandidates.Dequeue(), new MemoryStream());
    },
    _ =>
    {
        udpReservationAttempts++;
        if (udpReservationAttempts == 1) throw new SocketException((int)SocketError.AccessDenied);
        if (udpReservationAttempts == 2) throw new SocketException((int)SocketError.AddressAlreadyInUse);
        return new MemoryStream();
    });
if (selectedDualTransportPort != 51003 || tcpReservationAttempts != 4 || udpReservationAttempts != 3)
    throw new Exception("TCP-first dual-transport selection must retry reserved TCP and UDP candidates");
Console.WriteLine("PASS: TCP-first dual TCP/UDP port selection retries reserved and occupied candidates");

// Windows can reject every TCP-allocated ephemeral port when UDP has a
// different excluded-port range. Try UDP allocator first and alternate,
// without bypassing the real joint bind or loosening the QUIC requirement.
var tcpFirstAttempts = 0;
var udpFirstAttempts = 0;
MemoryStream? successfulUdpReservation = null;
var selectedFallbackPort = TrafficHttp3Acceptance.SelectDualTransportPort(
    reserveTcp: () =>
    {
        tcpFirstAttempts++;
        throw new SocketException((int)SocketError.AccessDenied);
    },
    reserveUdp: _ => throw new SocketException((int)SocketError.AccessDenied),
    maxAttempts: 4,
    reserveUdpCandidate: () =>
    {
        udpFirstAttempts++;
        if (udpFirstAttempts == 1)
            throw new SocketException((int)SocketError.AccessDenied);
        successfulUdpReservation = new MemoryStream();
        return (52001, successfulUdpReservation);
    },
    reserveTcpAtPort: _ => new MemoryStream());
if (selectedFallbackPort != 52001 ||
    tcpFirstAttempts != 1 || udpFirstAttempts != 2 ||
    successfulUdpReservation is null || successfulUdpReservation.CanRead)
    throw new Exception("UDP-first dual-transport fallback must retry both OS allocators and dispose reservations");

var refusesUnpairedFallback = false;
try
{
    _ = TrafficHttp3Acceptance.SelectDualTransportPort(
        () => (52002, new MemoryStream()),
        _ => new MemoryStream(),
        reserveUdpCandidate: () => (52002, new MemoryStream()));
}
catch (ArgumentException) { refusesUnpairedFallback = true; }
if (!refusesUnpairedFallback)
    throw new Exception("Unpaired UDP-first callback must fail before any port reservation");

Console.WriteLine("PASS: UDP-first cross-protocol fallback retries Windows reserved ports without skipping HTTP/3");

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
if (!AcmeTargetPolicy.IsApprovedDirectoryUrl(staging) ||
    !AcmeTargetPolicy.IsApprovedDirectoryUrl("https://acme-v02.api.letsencrypt.org/directory"))
    throw new Exception("approved ACME authorities must be usable for certificate revocation");
foreach (var unapproved in new[] {
    "http://acme-staging-v02.api.letsencrypt.org/directory",
    "https://example.invalid/directory",
    "https://user:secret@acme-staging-v02.api.letsencrypt.org/directory",
    "https://acme-staging-v02.api.letsencrypt.org:8443/directory",
    "https://acme-staging-v02.api.letsencrypt.org/not-directory",
    "https://acme-staging-v02.api.letsencrypt.org/directory?token=x",
    "https://acme-staging-v02.api.letsencrypt.org/directory#fragment",
    "https://127.0.0.1:14000/directory"
})
{
    if (AcmeTargetPolicy.IsApprovedDirectoryUrl(unapproved))
        throw new Exception("unsafe ACME revocation directory passed preflight");
}
if (!AcmeTargetPolicy.IsApprovedDirectoryUrl(
        "https://127.0.0.1:14000/directory", allowLoopbackTestAuthority: true))
    throw new Exception("explicit isolated loopback test policy should remain supported");
Console.WriteLine("PASS: ACME target preflight rejects unsafe authority, hostname and HTTP-01 inputs");
await AcmeHttp01Acceptance.RunAsync();
await AcmeDns01Acceptance.RunAsync();
await AcmeDns01WireAcceptance.RunAsync();
await AcmeDns01NsupdateAcceptance.RunAsync();
await TrafficHttp3Acceptance.RunAsync();
await DestinationAdmissionHttp3Acceptance.RunAsync();
await DestinationAdmissionGrpcAcceptance.RunAsync();
await TrafficCertificateRotationAcceptance.RunAsync();
await AcmeRenewalAcceptance.RunAsync();
