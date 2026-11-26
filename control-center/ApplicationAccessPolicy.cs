using System.Net;
using System.Text.Json.Nodes;

/// <summary>Opt-in route TLS and actual peer-network access, not user authentication.</summary>
public sealed record ApplicationAccessPolicy(bool RequireHttps, IPNetwork[] AllowedNetworks, bool PublicHttpCompression = false, string[]? AllowedMethods = null)
{
    public const string HttpsKey = "ADC.Access.RequireHttps";
    public const string NetworksKey = "ADC.Access.AllowedNetworks";
    public const string CompressionKey = "ADC.Acceleration.PublicHttpCompression";
    public const string MethodsKey = "ADC.Traffic.AllowedMethods";
    public static bool TryParse(IReadOnlyDictionary<string,string>? metadata, out ApplicationAccessPolicy policy)
    {
        policy = new(false, []);
        if (metadata is null) return true;
        if (metadata.Keys.Any(key => key.StartsWith("ADC.Access.", StringComparison.OrdinalIgnoreCase) &&
            key is not (HttpsKey or NetworksKey))) return false;
        if (metadata.Keys.Any(key => key.StartsWith("ADC.Acceleration.", StringComparison.OrdinalIgnoreCase) && key != CompressionKey)) return false;
        if (metadata.Keys.Any(key => key.StartsWith("ADC.Traffic.", StringComparison.OrdinalIgnoreCase) && key != MethodsKey)) return false;
        string[]? methods = null;
        if (metadata.TryGetValue(MethodsKey, out var methodsText))
        {
            if (string.IsNullOrWhiteSpace(methodsText) || methodsText.Length > 64) return false;
            methods = methodsText.Split(',', StringSplitOptions.TrimEntries);
            if (methods.Length is < 1 or > 7 ||
                methods.Distinct(StringComparer.Ordinal).Count() != methods.Length ||
                methods.Any(method => method is not ("GET" or "HEAD" or "POST" or "PUT" or "PATCH" or "DELETE" or "OPTIONS"))) return false;
        }
        bool compress = false;
        if (metadata.TryGetValue(CompressionKey, out var compression))
        {
            if (compression is not ("true" or "false")) return false;
            compress = compression == "true";
        }
        bool tls = false;
        if (metadata.TryGetValue(HttpsKey, out var https))
        {
            if (https is not ("true" or "false")) return false;
            tls = https == "true";
        }
        var networks = new List<IPNetwork>();
        if (metadata.TryGetValue(NetworksKey, out var text))
        {
            if (string.IsNullOrWhiteSpace(text) || text.Length > 2048) return false;
            var parts = text.Split(',', StringSplitOptions.TrimEntries);
            if (parts.Length is < 1 or > 32) return false;
            foreach (var part in parts)
            {
                if (!IPNetwork.TryParse(part, out var network) || network.BaseAddress.IsIPv4MappedToIPv6 ||
                    network.PrefixLength == 0 || network.BaseAddress.IsIPv6Multicast ||
                    (network.BaseAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 &&
                        network.BaseAddress.ScopeId != 0) || networks.Contains(network)) return false;
                networks.Add(network);
            }
        }
        if (tls && compress) return false; // this initial compression profile is HTTP only
        policy = new(tls, networks.ToArray(), compress, methods);
        return true;
    }

    public bool Permits(bool https, IPAddress? peer)
    {
        if (RequireHttps && !https) return false;
        if (AllowedNetworks.Length == 0) return true;
        if (peer is null) return false;
        if (peer.IsIPv4MappedToIPv6) peer = peer.MapToIPv4();
        return AllowedNetworks.Any(network => network.Contains(peer));
    }

    public bool PermitsMethod(string method) => AllowedMethods is null || AllowedMethods.Contains(method, StringComparer.Ordinal);

    public static bool Validate(JsonObject route)
    {
        if (route["Metadata"] is not JsonObject meta) return route["Metadata"] is null;
        var relevant = new Dictionary<string,string>(StringComparer.Ordinal);
        foreach (var (key,node) in meta)
        {
            if (!key.StartsWith("ADC.Access.", StringComparison.OrdinalIgnoreCase) &&
                !key.StartsWith("ADC.Acceleration.", StringComparison.OrdinalIgnoreCase) &&
                !key.StartsWith("ADC.Traffic.", StringComparison.OrdinalIgnoreCase)) continue;
            if (key is not (HttpsKey or NetworksKey or CompressionKey or MethodsKey) || node is not JsonValue value ||
                !value.TryGetValue<string>(out var text) || text is null) return false;
            relevant.Add(key,text);
        }
        return TryParse(relevant,out _);
    }
}
