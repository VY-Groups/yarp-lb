using System.Net;
using System.Net.Sockets;
using System.Text.Json;

internal sealed class DnsSourceFirewall
{
    private readonly IPNetwork[] denied;
    internal DnsSourceFirewall(JsonElement configured)
    {
        if (configured.ValueKind == JsonValueKind.Undefined) { denied = []; return; }
        if (configured.ValueKind != JsonValueKind.Array || configured.GetArrayLength() > 128)
            throw new InvalidDataException("Invalid DNS blocked resolver CIDRs.");
        var networks = new HashSet<IPNetwork>();
        foreach (var entry in configured.EnumerateArray())
        {
            if (entry.ValueKind != JsonValueKind.String || !TryNetwork(entry.GetString(), out var network) ||
                !networks.Add(network))
                throw new InvalidDataException("Invalid or duplicate DNS blocked resolver CIDR.");
        }
        denied = networks.ToArray();
    }
    private static bool TryNetwork(string? text, out IPNetwork network)
    {
        network = default;
        return text is { Length: >= 3 and <= 64 } &&
            text.All(c => char.IsAsciiHexDigit(c) || c is '.' or ':' or '/') &&
            IPNetwork.TryParse(text, out network) && network.PrefixLength > 0 &&
            !network.BaseAddress.IsIPv4MappedToIPv6 &&
            (network.BaseAddress.AddressFamily != AddressFamily.InterNetworkV6 || network.BaseAddress.ScopeId == 0);
    }
    internal bool Blocks(IPAddress? peer)
    {
        if (peer is null) return true;
        if (peer.IsIPv4MappedToIPv6) peer = peer.MapToIPv4();
        foreach (var network in denied)
            if (network.BaseAddress.AddressFamily == peer.AddressFamily && network.Contains(peer)) return true;
        return false;
    }
}
