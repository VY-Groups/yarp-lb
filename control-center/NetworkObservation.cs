using System.Globalization;
using System.Net;

internal static class NetworkObservation
{
    internal sealed record VlanRow(string Interface, int VlanId, string Parent);
    internal sealed record VlanSnapshot(string Status, VlanRow[] Interfaces);
    internal sealed record VirtualAddressRow(string Id, string Ip, int Port, string Protocol,
        string Status, string[] Interfaces);

    // Linux kernel 802.1Q inventory only; no shell commands or interface mutation.
    internal static VlanSnapshot ReadVlans()
    {
        if (!OperatingSystem.IsLinux()) return new("unsupported-platform", []);
        try
        {
            using var file = new StreamReader("/proc/net/vlan/config");
            var buffer = new char[65537];
            int read = file.ReadBlock(buffer, 0, buffer.Length);
            if (read == buffer.Length) return new("truncated", []);
            return ParseVlans(new string(buffer, 0, read));
        }
        catch (FileNotFoundException) { return new("kernel-inventory-unavailable", []); }
        catch (DirectoryNotFoundException) { return new("kernel-inventory-unavailable", []); }
        catch (IOException) { return new("unavailable", []); }
        catch (UnauthorizedAccessException) { return new("unavailable", []); }
    }

    internal static VlanSnapshot ParseVlans(string text)
    {
        if (text.Length > 65536) return new("truncated", []);
        var lines = text.Split('\n', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        if (lines.Length < 2 || !lines[0].Contains("VLAN Dev name", StringComparison.Ordinal) ||
            !lines[1].StartsWith("Name-Type:", StringComparison.Ordinal))
            return new("invalid-kernel-inventory", []);
        var rows = new List<VlanRow>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (string line in lines.Skip(2))
        {
            if (rows.Count == 256) return new("truncated", []);
            var parts = line.Split('|', StringSplitOptions.TrimEntries);
            if (parts.Length != 3 || !ValidName(parts[0]) || !ValidName(parts[2]) ||
                !int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var tag) ||
                tag is < 0 or > 4094 || !seen.Add(parts[0]))
                return new("invalid-kernel-inventory", []);
            rows.Add(new(parts[0], tag, parts[2]));
        }
        return new("observed", rows.OrderBy(x => x.Interface, StringComparer.Ordinal).ToArray());
    }

    private static bool ValidName(string value) =>
        value.Length is > 0 and <= 64 && !value.Any(c => char.IsControl(c) || char.IsWhiteSpace(c));

    internal static VirtualAddressRow ObserveVirtualAddress(string id, string ip, int port, string protocol,
        LocalNetworkInventory.Snapshot snapshot)
    {
        var matching = snapshot.Interfaces.Where(n => n.Addresses.Any(a =>
            IPAddress.TryParse(a.Address, out var observed) && IPAddress.TryParse(ip, out var configured) &&
            configured.Equals(observed))).ToArray();
        string status = matching.Length > 1 ? "multiple-local-interfaces"
            : matching.Length == 1 ? (matching[0].Status == "Up" ? "present-interface-up" : "present-interface-not-up")
            : snapshot.Truncated ? "unknown-truncated" : "not-observed-locally";
        return new(id, ip, port, protocol, status, matching.Select(n => n.Name).ToArray());
    }
}
