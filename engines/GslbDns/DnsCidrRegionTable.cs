using System.Globalization;
using System.Net;
using System.Net.Sockets;

// Deliberate, administrator-supplied private CIDR routing only.
// No MaxMind / inferred geography, ECS or arbitrary forwarded client headers.
internal sealed record DnsCidrRegionRule(string Cidr, string Region);

internal sealed class DnsCidrRegionTable
{
    private sealed record Entry(IPAddress Network, int PrefixLength, string Region);
    private readonly Entry[] routes;

    public static bool ValidRegion(string? region) =>
        !string.IsNullOrWhiteSpace(region) && region.Length <= 32 &&
        region.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_');

    public DnsCidrRegionTable(IEnumerable<DnsCidrRegionRule> configuration)
    {
        if (configuration is null) throw new ArgumentNullException(nameof(configuration));
        var rules = configuration.ToArray();
        if (rules.Length is < 1 or > 256)
            throw new ArgumentOutOfRangeException(nameof(configuration),
                "CIDR region maps must contain 1..256 routes");
        var entries = new List<Entry>(rules.Length);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var rule in rules)
        {
            if (rule is null || string.IsNullOrWhiteSpace(rule.Cidr) ||
                !ValidRegion(rule.Region))
                throw new ArgumentException("Invalid CIDR region mapping");
            var parts = rule.Cidr.Split('/');
            if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var network) ||
                !int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture,
                    out var bits) ||
                network.IsIPv4MappedToIPv6 ||
                (network.AddressFamily == AddressFamily.InterNetworkV6 && network.ScopeId != 0) ||
                bits < 0 ||
                bits > (network.AddressFamily == AddressFamily.InterNetwork ? 32 : 128) ||
                !CanonicalNetwork(network.GetAddressBytes(), bits))
                throw new ArgumentException("Invalid or noncanonical CIDR network");
            var key = network + "/" + bits;
            if (!seen.Add(key)) throw new ArgumentException("Duplicate CIDR network mapping");
            entries.Add(new Entry(network, bits, rule.Region));
        }
        // Most-specific match wins; configuration order never changes precedence.
        routes = entries.OrderByDescending(x => x.PrefixLength).ToArray();
    }

    public string? RegionFor(IPAddress? resolverAddress)
    {
        if (resolverAddress is null) return null;
        var addr = resolverAddress.IsIPv4MappedToIPv6
            ? resolverAddress.MapToIPv4() : resolverAddress;
        foreach (var rule in routes)
        {
            if (addr.AddressFamily == rule.Network.AddressFamily &&
                PrefixMatches(addr.GetAddressBytes(),rule.Network.GetAddressBytes(),
                    rule.PrefixLength))
                return rule.Region;
        }
        return null; // unknown resolver origin uses original weighted policy
    }

    public IReadOnlyCollection<string> Regions =>
        routes.Select(x => x.Region).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();

    private static bool CanonicalNetwork(byte[] bytes,int bits)
    {
        var full = bits / 8;
        var partial = bits % 8;
        if (partial != 0)
        {
            var mask = (byte)(0xFF << (8 - partial));
            if ((bytes[full] & ~mask) != 0) return false;
            full++;
        }
        for (var i=full;i<bytes.Length;i++)
            if (bytes[i] != 0) return false;
        return true;
    }

    private static bool PrefixMatches(byte[] addr,byte[] network,int bits)
    {
        var full = bits / 8;
        for (var i=0;i<full;i++) if (addr[i] != network[i]) return false;
        var partial = bits % 8;
        if (partial == 0) return true;
        var mask = (byte)(0xFF << (8 - partial));
        return (addr[full] & mask) == (network[full] & mask);
    }
}
