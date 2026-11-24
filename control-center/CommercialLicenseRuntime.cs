#if GATEWAYCORE_COMMERCIAL
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Security.Cryptography;
using GatewayCore.Licensing;

internal sealed class CommercialLicenseRuntime : BackgroundService
{
    private readonly OfflineLicenseStore store;
    private readonly object sync = new();
    private VerifiedLicense? current;
    private string state = "unavailable";
    private int admittedTraffic;
    private long admissionDeadlineMs;
    private long signedExpiryUnixMs;
    // Development default: bounded continuity on unexpected storage failure,
    // never beyond signed expiry. Explicit downgrade/revocation fences now.
    private const long FaultContinuityMs = 15 * 60 * 1000;
    private const int MaxUpload = 24576;

    public CommercialLicenseRuntime(string directory)
    {
        using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("GatewayCore.CommercialTrust")
            ?? throw new InvalidOperationException("Commercial build lacks pinned issuer trust.");
        if (stream.Length is < 1 or > 16384) throw new InvalidDataException("Invalid trust resource.");
        var keys = JsonSerializer.Deserialize<Dictionary<string, byte[]>>(stream)
            ?? throw new InvalidDataException("Missing issuer trust.");
        store = new OfflineLicenseStore(directory, new OfflineLicenseVerifier(keys));
    }

    public void Initialize() => store.Initialize();
    public void Refresh()
    {
        lock (sync)
        {
            try
            {
                ApplyVerified(store.Inspect(DateTimeOffset.UtcNow));
            }
            catch (Exception e) when (e is IOException or CryptographicException or InvalidDataException or
                FormatException or JsonException or UnauthorizedAccessException or ArgumentException or InvalidOperationException)
            {
                // Repeated failures must not renew the continuity window.
                if (state != "unavailable")
                    Volatile.Write(ref admissionDeadlineMs,
                        Math.Min(Volatile.Read(ref admissionDeadlineMs), Environment.TickCount64 + FaultContinuityMs));
                current = null;
                state = "unavailable";
            }
        }
    }

    // Explicit signed downgrade/revocation and signed expiry fence new
    // requests. In-flight requests are not forcibly terminated. A temporary
    // state fault has bounded continuity only on an already admitted process.
    private void ApplyVerified(VerifiedLicense? license)
    {
        current = license;
        state = license?.Validity.ToString().ToLowerInvariant() ?? "unactivated";
        if (license is { Validity: LicenseValidity.Active } && license.Allows("l7"))
        {
            var now = DateTimeOffset.UtcNow;
            var remainingMs = Math.Max(0L, (long)(license.ExpiresAt - now).TotalMilliseconds);
            Volatile.Write(ref signedExpiryUnixMs, license.ExpiresAt.ToUnixTimeMilliseconds());
            Volatile.Write(ref admissionDeadlineMs, Environment.TickCount64 + remainingMs);
            Volatile.Write(ref admittedTraffic, remainingMs > 0 ? 1 : 0);
        }
        else
        {
            Volatile.Write(ref admittedTraffic, 0);
            Volatile.Write(ref admissionDeadlineMs, 0);
            Volatile.Write(ref signedExpiryUnixMs, 0);
            if (license is { Validity: LicenseValidity.Active }) state = "feature-restricted";
        }
    }

    // No disk access, signature verification or network dependency in the
    // data path. Both wall clock and monotonic bounds must still be valid.
    public bool TrafficAdmitted => Volatile.Read(ref admittedTraffic) == 1 &&
        Environment.TickCount64 < Volatile.Read(ref admissionDeadlineMs) &&
        DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() < Volatile.Read(ref signedExpiryUnixMs);
    public bool Allows(string feature)
    {
        lock (sync)
            return current is { Validity: LicenseValidity.Active } && current.ExpiresAt > DateTimeOffset.UtcNow &&
                current.NotBefore <= DateTimeOffset.UtcNow && current.Allows(feature);
    }

    public object Status()
    {
        lock (sync)
        {
            var active = Allows("l7");
            return new { commercial = true, state = active ? "active" :
                current?.Validity == LicenseValidity.Active && current.ExpiresAt <= DateTimeOffset.UtcNow ? "expired" : state,
                active, trafficAdmitted = TrafficAdmitted, edition = current?.Edition, licenseId = current?.LicenseId,
                allocationId = current?.AllocationId, expiresAt = current?.ExpiresAt, maxNodes = current?.MaxNodes,
                maxSites = current?.MaxSites, revision = current?.Revision,
                features = current?.Features.Order(StringComparer.Ordinal).ToArray() ?? Array.Empty<string>() };
        }
    }

    public byte[] Request() { lock (sync) return store.ExportActivationRequest(); }
    public VerifiedLicense Import(byte[] bytes, bool revoke)
    {
        lock (sync)
        {
            var result = revoke ? store.ImportRevocation(bytes, DateTimeOffset.UtcNow)
                : store.Import(bytes, DateTimeOffset.UtcNow);
            // Apply the exact committed result; do not depend on a second
            // disk read that could fail and accidentally retain old admission.
            ApplyVerified(result);
            return result;
        }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(15));
        while (await timer.WaitForNextTickAsync(stoppingToken)) Refresh();
    }

    internal static bool RecoveryEndpoint(PathString path) =>
        path == "/admin/api/session" || path == "/admin/api/auth-methods" ||
        path == "/admin/api/bootstrap" || path == "/admin/api/login" ||
        path == "/admin/api/login/verify" || path == "/admin/api/logout" ||
        path == "/admin/api/license/status" || path == "/admin/api/license/request" ||
        path == "/admin/api/license/import" || path == "/admin/api/license/revoke" ||
        path == "/admin/api/privacy/accept";

    // Local controller cap; does not assert that every remote gateway has
    // a valid unique allocation or prove a global site count.
    internal bool AllowsFleetCount(int count)
    {
        lock (sync)
            return count >= 0 && Allows("l7") && Allows("fleet") && Allows("ha") &&
                current is not null && count <= current.MaxNodes;
    }

    internal bool AllowsTopology(OnboardingPlan plan)
    {
        lock (sync)
        {
            if (!Allows("l7") || current is null || plan.Gateways is null ||
                plan.Gateways.Count > current.MaxNodes) return false;
            return plan.Mode switch
            {
                "standalone" => true,
                "ha-pair" => Allows("ha") && Allows("fleet"),
                "fleet" => Allows("ha") && Allows("fleet"),
                _ => false
            };
        }
    }

    internal bool Permits(PathString path)
    {
        lock (sync)
        {
            if (!Allows("l7")) return false;
            if (path.StartsWithSegments("/admin/api/fleet")) return Allows("fleet") && Allows("ha");
            if (path.StartsWithSegments("/admin/api/peer-sync")) return Allows("ha");
            if (path.StartsWithSegments("/admin/api/gitops")) return Allows("gitops");
            if (path.StartsWithSegments("/admin/api/tls")) return Allows("tls");
            if (path.StartsWithSegments("/admin/api/audit")) return Allows("audit");
            if (path.StartsWithSegments("/admin/api/directory")) return Allows("enterprise-sso");
            if (path.StartsWithSegments("/admin/api/metrics") ||
                path.StartsWithSegments("/admin/api/destination-metrics") ||
                path.StartsWithSegments("/admin/api/reports") ||
                path.StartsWithSegments("/admin/api/logging-health")) return Allows("monitoring");
            return true;
        }
    }

    internal static async Task<byte[]> ReadUpload(HttpContext ctx)
    {
        if (ctx.Request.ContentLength is > MaxUpload) throw new InvalidDataException("License upload too large.");
        using var body = new MemoryStream();
        var buffer = new byte[4096];
        while (true)
        {
            var n = await ctx.Request.Body.ReadAsync(buffer, ctx.RequestAborted);
            if (n == 0) break;
            if (body.Length + n > MaxUpload) throw new InvalidDataException("License upload too large.");
            body.Write(buffer, 0, n);
        }
        using var json = JsonDocument.Parse(body.ToArray(), new JsonDocumentOptions { MaxDepth = 2 });
        var root = json.RootElement;
        if (root.ValueKind != JsonValueKind.Object || root.EnumerateObject().Count() != 1 ||
            !root.TryGetProperty("file", out var item) || item.ValueKind != JsonValueKind.String ||
            item.GetString() is not string value || value.Length > OfflineLicenseVerifier.MaxLicenseBytes ||
            value.Any(x => x is < (char)33 or > (char)126))
            throw new InvalidDataException("Invalid license upload.");
        return Encoding.ASCII.GetBytes(value);
    }
}
#endif
