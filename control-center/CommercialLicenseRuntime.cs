#if GATEWAYCORE_COMMERCIAL
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Security.Cryptography;
using GatewayCore.Licensing;

internal sealed class CommercialLicenseRuntime : BackgroundService
{
    private readonly OfflineLicenseStore store;
    private readonly OfflineLicenseVerifier verifier;
    private readonly object sync = new();
    private VerifiedLicense? current;
    private string state = "unavailable";
    private sealed record TrafficGrant(long DeadlineTick,long ExpiryUnixMs);
    private TrafficGrant? trafficGrant;
    private string? lastVerifiedPayload;
    private long lastVerifiedDeadline;
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
        verifier = new OfflineLicenseVerifier(keys);
        store = new OfflineLicenseStore(directory, verifier);
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
                if (state != "unavailable" && Volatile.Read(ref trafficGrant) is { } oldGrant)
                    Volatile.Write(ref trafficGrant,oldGrant with
                    {DeadlineTick=Math.Min(oldGrant.DeadlineTick,Environment.TickCount64+FaultContinuityMs)});
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
        if(license is not null)
        {
            var remainingMs=Math.Max(0L,(long)(license.ExpiresAt-DateTimeOffset.UtcNow).TotalMilliseconds);
            var proposed=Environment.TickCount64+remainingMs;
            if(lastVerifiedPayload==license.PayloadSha256)
                proposed=Math.Min(lastVerifiedDeadline,proposed);
            lastVerifiedPayload=license.PayloadSha256;
            lastVerifiedDeadline=proposed;
        }
        // One immutable publication prevents readers observing mixed old/new
        // admission fields. Refreshing the same signed payload never extends
        // its monotonic expiry, even after a recoverable store fault.
        Volatile.Write(ref trafficGrant,license is {Validity:LicenseValidity.Active} && license.Allows("l7") &&
            Environment.TickCount64<lastVerifiedDeadline
            ?new TrafficGrant(lastVerifiedDeadline,license.ExpiresAt.ToUnixTimeMilliseconds()):null);
        if(license is {Validity:LicenseValidity.Active} && !license.Allows("l7"))state="feature-restricted";
    }

    public bool TrafficAdmitted
    {
        get
        {
            var grant=Volatile.Read(ref trafficGrant);
            return grant is not null && Environment.TickCount64<grant.DeadlineTick &&
                DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()<grant.ExpiryUnixMs;
        }
    }
    public bool Allows(string feature)
    {
        lock (sync)
            return current is {Validity:LicenseValidity.Active} && Environment.TickCount64<lastVerifiedDeadline &&
                current.ExpiresAt>DateTimeOffset.UtcNow && current.NotBefore<=DateTimeOffset.UtcNow && current.Allows(feature);
    }

    public object Status()
    {
        lock (sync)
        {
            var active = Allows("l7");
            return new { commercial = true, state = active ? "active" :
                current?.Validity == LicenseValidity.Active && (current.ExpiresAt <= DateTimeOffset.UtcNow ||
                    Environment.TickCount64>=lastVerifiedDeadline) ? "expired" : state,
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

    internal static bool FleetRecoveryEndpoint(string method,PathString path)
    {
        if(method=="GET" && path=="/admin/api/fleet/rollouts")return true;
        if(method!="POST" || path.Value is not string value)return false;
        const string prefix="/admin/api/fleet/rollouts/";
        const string suffix="/recover";
        if(!value.StartsWith(prefix,StringComparison.OrdinalIgnoreCase) ||
           !value.EndsWith(suffix,StringComparison.OrdinalIgnoreCase) ||
           value.Length!=prefix.Length+32+suffix.Length)return false;
        return FleetRolloutJournal.IsTransaction(value.Substring(prefix.Length,32));
    }

    internal static bool RecoveryEndpoint(PathString path) =>
        path == "/admin/api/session" || path == "/admin/api/auth-methods" ||
        path == "/admin/api/bootstrap" || path == "/admin/api/login" ||
        path == "/admin/api/login/verify" || path == "/admin/api/logout" ||
        path == "/admin/api/license/status" || path == "/admin/api/license/request" ||
        path == "/admin/api/license/import" || path == "/admin/api/license/revoke" ||
        path == "/admin/api/privacy/accept";

    internal VerifiedLicense VerifyPeerProof(string proof,string challenge)
    {
        if(proof.Length>32768 || proof.Any(c=>c is < (char)33 or > (char)126))
            throw new InvalidDataException("Invalid peer proof.");
        return verifier.VerifyInstallationProof(Encoding.ASCII.GetBytes(proof),challenge,DateTimeOffset.UtcNow);
    }

    internal string FleetScope()
    {
        lock(sync)
        {
            var local=store.Inspect(DateTimeOffset.UtcNow)??throw new InvalidOperationException("Missing local fleet license.");
            ApplyVerified(local);
            if(!Allows("ha")||!Allows("fleet")||local.SiteId is null)throw new InvalidOperationException("Site-bound fleet entitlement required.");
            return FleetQuorum.DeploymentScope(local.LicenseId,local.CustomerId,local.DeploymentId);
        }
    }

    internal void ValidateFleetProofs(IReadOnlyList<VerifiedLicense> peers)
    {
        lock(sync)
        {
            // Consult exact persisted local state for a control-plane decision,
            // not the continuity/admission cache.
            var local=store.Inspect(DateTimeOffset.UtcNow)??throw new InvalidOperationException("Missing local license.");
            ApplyVerified(local);
            if(!Allows("l7") || !Allows("ha") || !Allows("fleet"))
                throw new CryptographicException("Local fleet entitlement unavailable.");
            FleetLicensePolicy.Validate(local,peers,DateTimeOffset.UtcNow);
        }
    }

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
