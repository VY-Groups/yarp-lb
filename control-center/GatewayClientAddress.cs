using System.Net;

/// <summary>Resolves the client address for access logs without trusting arbitrary forwarding headers.</summary>
public static class GatewayClientAddress
{
    public static HashSet<string> ParseTrustedProxyAddresses(string? setting)
    {
        var result = new HashSet<string>(StringComparer.Ordinal);
        if (string.IsNullOrWhiteSpace(setting)) return result;
        var entries = setting.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        if (entries.Length > 32)
            throw new InvalidOperationException("At most 32 trusted proxy IP addresses may be configured.");
        foreach (var entry in entries)
        {
            if (!IPAddress.TryParse(entry, out var address) || entry.Contains('/') || !IsUnscoped(address) ||
                address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any))
                throw new InvalidOperationException("Trusted proxies must be explicit, non-wildcard IP addresses.");
            result.Add(Key(Normalize(address)));
        }
        return result;
    }

    public static (IPAddress? Address, string Source) ForAccessLog(
        IPAddress? socketPeer, string? forwardedFor, IReadOnlySet<string> trustedProxyAddresses)
    {
        if (socketPeer is null) return (null, "unknown");
        var peer = Normalize(socketPeer);
        // With no trusted ingress peers configured (the secure default), a
        // forwarded address can never be accepted. Do not materialize a new
        // GetAddressBytes array + hex string for an impossible set lookup on
        // every gateway request. Keep the exact trusted-peer validation path.
        if (trustedProxyAddresses.Count == 0 || !trustedProxyAddresses.Contains(Key(peer)))
            return (peer, "socket");
        if (string.IsNullOrWhiteSpace(forwardedFor) || forwardedFor.Length > 64 ||
            forwardedFor.Contains(',') || !IPAddress.TryParse(forwardedFor.Trim(), out var forwarded) ||
            !IsUnscoped(forwarded) ||
            forwarded.Equals(IPAddress.Any) || forwarded.Equals(IPAddress.IPv6Any))
            return (peer, "trusted-proxy-invalid-forwarded-for");
        return (Normalize(forwarded), "trusted-proxy");
    }

    private static string Key(IPAddress address) => Convert.ToHexString(address.GetAddressBytes());
    private static bool IsUnscoped(IPAddress address) =>
        address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6 || address.ScopeId == 0;
    private static IPAddress Normalize(IPAddress address) =>
        address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
}
