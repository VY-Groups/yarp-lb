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
                current = null;
                state = "unavailable";
            }
        }
    }

    // An explicit signed downgrade takes effect immediately, unlike an
    // unexpected expiry/state fault. Existing in-flight requests are not aborted.
    private void ApplyVerified(VerifiedLicense? license)
    {
        current = license;
        state = license?.Validity.ToString().ToLowerInvariant() ?? "unactivated";
        if (license is null || license.Validity == LicenseValidity.NotYetValid)
            Volatile.Write(ref admittedTraffic, 0);
        else if (license.Validity == LicenseValidity.Active)
        {
            Volatile.Write(ref admittedTraffic, license.Allows("l7") ? 1 : 0);
            if (!license.Allows("l7")) state = "feature-restricted";
        }
    }

    // A valid running process retains forwarding on expiry/revocation/state
    // fault; an unlicensed fresh process cannot start forwarding. This is a
    // deliberately narrow continuity prototype, not a production DR policy.
    public bool TrafficAdmitted => Volatile.Read(ref admittedTraffic) == 1;
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

    internal bool Permits(PathString path)
    {
        if (!Allows("l7")) return false;
        if (path.StartsWithSegments("/admin/api/fleet")) return Allows("fleet") && Allows("ha");
        if (path.StartsWithSegments("/admin/api/gitops")) return Allows("gitops");
        if (path.StartsWithSegments("/admin/api/tls")) return Allows("tls");
        if (path.StartsWithSegments("/admin/api/audit")) return Allows("audit");
        return true;
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
