using System.Net.NetworkInformation;
using System.Net.Sockets;

internal static class LocalNetworkInventory
{
    internal sealed record AddressRow(string Address, int PrefixLength, bool Ready = true);
    internal sealed record InterfaceRow(string Id, string Name, string Type, string Status,
        AddressRow[] Addresses, string[] DefaultGateways, bool Truncated);
    internal sealed record Snapshot(string Scope, string Platform, DateTimeOffset ObservedUtc,
        InterfaceRow[] Interfaces, bool Truncated);
    internal static Snapshot Read()
    {
        const int interfaceLimit = 256, addressLimit = 128, gatewayLimit = 32;
        var interfaces = NetworkInterface.GetAllNetworkInterfaces();
        var linuxIpv6 = VipIpv6Readiness.ReadLinux();
        var rows = interfaces.OrderBy(n => n.Id, StringComparer.Ordinal).Take(interfaceLimit).Select(n =>
        {
            var properties = n.GetIPProperties();
            var addresses = properties.UnicastAddresses
                .Where(x => x.Address.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6)
                .Select(x => new AddressRow(x.Address.ToString(), x.PrefixLength,
                    x.Address.AddressFamily != AddressFamily.InterNetworkV6 ||
                    VipIpv6Readiness.IsReady(x, properties.GetIPv6Properties()?.Index ?? 0, n.Name, linuxIpv6)))
                .OrderBy(x => x.Address, StringComparer.Ordinal).ThenBy(x => x.PrefixLength).ToArray();
            var gateways = properties.GatewayAddresses
                .Select(x => x.Address.ToString()).Distinct(StringComparer.Ordinal)
                .OrderBy(x => x, StringComparer.Ordinal).ToArray();
            return new InterfaceRow(n.Id, n.Name, n.NetworkInterfaceType.ToString(),
                n.OperationalStatus.ToString(), addresses.Take(addressLimit).ToArray(),
                gateways.Take(gatewayLimit).ToArray(), addresses.Length > addressLimit || gateways.Length > gatewayLimit);
        }).ToArray();
        return new("Local OS network interface snapshot; no VLAN, VIP or routing ownership inferred",
            OperatingSystem.IsWindows() ? "Windows" : OperatingSystem.IsLinux() ? "Linux" : "Other",
            DateTimeOffset.UtcNow, rows, interfaces.Length > interfaceLimit || rows.Any(x => x.Truncated));
    }
}
