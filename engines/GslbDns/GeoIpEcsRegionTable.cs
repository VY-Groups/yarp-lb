using System.Net;
using MaxMind.Db;

// Offline MaxMind MMDB lookups. The ECS prefix is already privacy-masked before
// this class is called; finer database records are rejected to avoid guessing
// that the rest of the client subnet shares the same geography/ASN.
internal sealed class GeoIpEcsDatabase : IDisposable
{
    private readonly Reader? country;
    private readonly Reader? asn;

    private readonly int maxAgeDays;
    private readonly TimeProvider clock;

    public GeoIpEcsDatabase(string? countryPath, string? asnPath, int maxAgeDays,
        TimeProvider? clock = null)
    {
        this.clock = clock ?? TimeProvider.System;
        this.maxAgeDays = maxAgeDays;
        if (maxAgeDays is < 0 or > 3650)
            throw new InvalidDataException("GeoIP maximum database age must be 0..3650 days (0 disables age enforcement)");
        country = Open(countryPath, "Country", maxAgeDays, this.clock);
        try { asn = Open(asnPath, "ASN", maxAgeDays, this.clock); }
        catch { country?.Dispose(); throw; }
    }

    public GeoIpEcsRegionTable CreateTable(
        IEnumerable<GeoCountryRoute>? countryRoutes,
        IEnumerable<GeoAsnRoute>? asnRoutes) =>
        new(country, asn, countryRoutes ?? [], asnRoutes ?? [], maxAgeDays, clock);

    public void Dispose()
    {
        country?.Dispose();
        asn?.Dispose();
    }

    private static Reader? Open(string? path, string expected, int maxAgeDays, TimeProvider clock)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;
        if (!Path.IsPathFullyQualified(path) || !File.Exists(path))
            throw new InvalidDataException($"Configured GeoIP {expected} database must be an existing absolute path");
        var reader = new Reader(path);
        try
        {
            var type = reader.Metadata.DatabaseType;
            var validType = expected == "Country"
                ? type.Contains("Country", StringComparison.OrdinalIgnoreCase)
                : type.Contains("ASN", StringComparison.OrdinalIgnoreCase);
            if (!validType)
                throw new InvalidDataException($"GeoIP {expected} database has unexpected MMDB type '{type}'");
            var age = clock.GetUtcNow().UtcDateTime - reader.Metadata.BuildDate;
            if (age < TimeSpan.FromDays(-1) || maxAgeDays > 0 && age > TimeSpan.FromDays(maxAgeDays))
                throw new InvalidDataException($"GeoIP {expected} database build date is outside the configured age window");
            Console.WriteLine($"GSLB_GEOIP database={expected} type={type} build_date={reader.Metadata.BuildDate:yyyy-MM-dd} age_days={Math.Max(0, (int)age.TotalDays)}");
            return reader;
        }
        catch { reader.Dispose(); throw; }
    }
}

internal sealed record GeoCountryRoute(string CountryCode, string Region);
internal sealed record GeoAsnRoute(long Asn, string Region);
internal sealed class GeoIpCountryLookup
{
    [MapKey("country")]
    public GeoIpCountryRecord? Country { get; init; }
    [Network]
    public Network? Network { get; init; }
}
internal sealed class GeoIpCountryRecord
{
    [MapKey("iso_code")]
    public string? IsoCode { get; init; }
}
internal sealed class GeoIpAsnLookup
{
    [MapKey("autonomous_system_number")]
    public long? Number { get; init; }
    [Network]
    public Network? Network { get; init; }
}

internal sealed class GeoIpEcsRegionTable
{
    private readonly Reader? country;
    private readonly Reader? asn;
    private readonly Dictionary<string, string> countries;
    private readonly Dictionary<long, string> autonomousSystems;

    private readonly TimeProvider clock;
    private readonly long openedAt;
    private readonly TimeSpan? remainingLifetime;
    private readonly DateTime? expiresUtc;
    private int expired;

    public GeoIpEcsRegionTable(Reader? country, Reader? asn,
        IEnumerable<GeoCountryRoute> countryRoutes, IEnumerable<GeoAsnRoute> asnRoutes,
        int maxAgeDays = 0, TimeProvider? clock = null)
    {
        this.clock = clock ?? TimeProvider.System;
        openedAt = this.clock.GetTimestamp();
        this.country = country;
        this.asn = asn;
        var countryRows = countryRoutes.ToArray();
        var asnRows = asnRoutes.ToArray();
        if (countryRows.Length > 300 || asnRows.Length > 4096 ||
            countryRows.Any(row => row is null || row.CountryCode is null ||
                row.CountryCode.Length != 2 || !row.CountryCode.All(char.IsAsciiLetter) ||
                !DnsCidrRegionTable.ValidRegion(row.Region)) ||
            asnRows.Any(row => row is null || row.Asn is < 1 or > 4_294_967_295 ||
                !DnsCidrRegionTable.ValidRegion(row.Region)))
            throw new InvalidDataException("Invalid GeoIP country or ASN route map");
        countries = countryRows.ToDictionary(row => row.CountryCode.ToUpperInvariant(),
            row => row.Region, StringComparer.Ordinal);
        autonomousSystems = asnRows.ToDictionary(row => row.Asn, row => row.Region);
        if (countries.Count > 0 && country is null || autonomousSystems.Count > 0 && asn is null)
            throw new InvalidDataException("GeoIP route maps require the matching country/ASN MMDB path");

        if (maxAgeDays > 0)
        {
            // Use the earliest configured database expiry. A monotonic
            // deadline prevents a wall-clock rollback resurrecting stale data.
            var now = this.clock.GetUtcNow().UtcDateTime;
            foreach (var reader in new[] { country, asn })
            {
                if (reader is null) continue;
                var expiry = reader.Metadata.BuildDate.AddDays(maxAgeDays);
                var remaining = expiry - now;
                if (remainingLifetime is null || remaining < remainingLifetime.Value)
                {
                    remainingLifetime = remaining;
                    expiresUtc = expiry;
                }
            }
        }
    }

    public IReadOnlyCollection<string> Regions => countries.Values.Concat(autonomousSystems.Values)
        .Distinct(StringComparer.OrdinalIgnoreCase).ToArray();

    public (string Region, int PrefixLength)? RegionForEcs(IPAddress address, int sourcePrefixLength)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (remainingLifetime is { } lifetime)
        {
            // Either clock can expire the database. Once observed expired,
            // a subsequent wall-clock rollback must not re-enable steering.
            var elapsed = clock.GetElapsedTime(openedAt);
            if (elapsed < TimeSpan.Zero || elapsed >= lifetime ||
                (expiresUtc is { } deadline && clock.GetUtcNow().UtcDateTime >= deadline))
                Interlocked.Exchange(ref expired, 1);
            if (Volatile.Read(ref expired) != 0)
                return null; // Unknown geography: normal healthy-site fallback.
        }
        var maxPrefix = address.GetAddressBytes().Length * 8;
        if (sourcePrefixLength < 0 || sourcePrefixLength > maxPrefix ||
            address.IsIPv4MappedToIPv6 || address.AddressFamily is not
                (System.Net.Sockets.AddressFamily.InterNetwork or System.Net.Sockets.AddressFamily.InterNetworkV6) ||
            (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 && address.ScopeId != 0))
            return null;

        string? countryRegion = null;
        if (country is not null)
        {
            var row = country.Find<GeoIpCountryLookup>(address, out _);
            if (row?.Country?.IsoCode is { } code)
            {
                if (!CoversEntireEcs(row.Network, address, sourcePrefixLength)) return null;
                countries.TryGetValue(code, out countryRegion);
            }
        }

        string? asnRegion = null;
        if (asn is not null)
        {
            var row = asn.Find<GeoIpAsnLookup>(address, out _);
            if (row?.Number is { } number)
            {
                if (!CoversEntireEcs(row.Network, address, sourcePrefixLength)) return null;
                autonomousSystems.TryGetValue(number, out asnRegion);
            }
        }

        return ResolveConfiguredRegions(countryRegion, asnRegion, sourcePrefixLength);
    }

    internal static (string Region, int PrefixLength)? ResolveConfiguredRegions(
        string? countryRegion, string? asnRegion, int sourcePrefixLength)
    {
        if (countryRegion is not null && asnRegion is not null &&
            !countryRegion.Equals(asnRegion, StringComparison.OrdinalIgnoreCase))
            return null; // Conflicting configured signals do not steer DNS.
        var region = countryRegion ?? asnRegion;
        return region is null ? null : (region, sourcePrefixLength);
    }

    private static bool CoversEntireEcs(Network? network, IPAddress address, int sourcePrefixLength)
    {
        if (network is null || network.PrefixLength > sourcePrefixLength ||
            network.NetworkAddress.AddressFamily != address.AddressFamily) return false;
        return DnsCidrRegionTable.PrefixMatches(address.GetAddressBytes(),
            network.NetworkAddress.GetAddressBytes(), network.PrefixLength);
    }
}
