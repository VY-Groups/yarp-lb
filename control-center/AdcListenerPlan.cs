using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

/// <summary>Host-provisioned, versioned socket plan shared by the HTTP gateway,
/// independent L4 engine and signed L4 staging. Never provisions IPs or certs.</summary>
public sealed class AdcListenerPlan
{
    public const string EnvironmentKey = "GATEWAYCORE_ADC_LISTENER_PLAN_FILE";
    public sealed record Entry(string Id, string Ip, int Port, string Protocol);
    public sealed record Document(int Version, Entry[] Listeners);
    private readonly Entry[] entries;
    public IReadOnlyList<Entry> Entries => Array.AsReadOnly(entries);
    private AdcListenerPlan(Entry[] rows) => entries = rows;
    public static bool IsL4(Entry entry) => entry.Protocol is "TCP" or "UDP";
    private static bool IsManagement(Entry entry) => entry.Protocol is "ADMIN" or "METRICS";
    private static IPAddress Address(string ip)
    {
        if (!IPAddress.TryParse(ip, out var address) ||
            address.IsIPv4MappedToIPv6 || address.Equals(IPAddress.Any) ||
            address.Equals(IPAddress.IPv6Any) || address.Equals(IPAddress.Broadcast) ||
            address.IsIPv6Multicast || address.IsIPv6LinkLocal ||
            (address.AddressFamily == AddressFamily.InterNetwork && address.GetAddressBytes()[0] >= 224))
            throw new InvalidDataException("ADC listener plan requires explicit unicast IP literals.");
        return address;
    }
    private static Entry Normalize(Entry row)
    {
        if (row is null || row.Id is null || !Regex.IsMatch(row.Id, @"\A[A-Za-z0-9_-]{1,64}\z") ||
            row.Port is < 1 or > 65535 || row.Protocol is not ("HTTP" or "HTTPS" or "HTTPS3" or "TCP" or "UDP" or "ADMIN" or "METRICS"))
            throw new InvalidDataException("Invalid ADC listener ID, port or protocol.");
        var address = Address(row.Ip);
        if (IsL4(row) && (address.AddressFamily != AddressFamily.InterNetwork || row.Port < 1025))
            throw new InvalidDataException("L4 plan must match the supported IPv4 and port contract.");
        return row with { Ip = address.ToString() };
    }
    public static AdcListenerPlan Create(Document document)
    {
        if (document.Version != 1 || document.Listeners is not { Length: >= 4 and <= 56 })
            throw new InvalidDataException("ADC listener plan requires version 1 and 4..56 listeners.");
        var rows = document.Listeners.Select(Normalize).ToArray();
        if (rows.Select(x => x.Id).Distinct(StringComparer.OrdinalIgnoreCase).Count() != rows.Length ||
            rows.Count(x => x.Protocol == "ADMIN") != 1 || rows.Count(x => x.Protocol == "METRICS") != 1 ||
            !rows.Any(x => x.Protocol == "HTTP") || !rows.Any(x => x.Protocol is "HTTPS" or "HTTPS3"))
            throw new InvalidDataException("ADC plan requires unique IDs and gateway traffic/admin/metrics sockets.");
        var management = rows.Where(IsManagement).ToArray();
        if (management[0].Ip != management[1].Ip ||
            rows.Any(x => !IsManagement(x) && x.Ip == management[0].Ip))
            throw new InvalidDataException("ADC data listener overlaps the protected management IP.");
        var bindings = new HashSet<(string, int, string)>();
        foreach (var row in rows)
        {
            if (!bindings.Add((row.Ip, row.Port, row.Protocol == "UDP" ? "UDP" : "TCP")) ||
                (row.Protocol == "HTTPS3" && !bindings.Add((row.Ip, row.Port, "UDP"))))
                throw new InvalidDataException("ADC listener transport conflict (HTTPS3 reserves TCP and UDP).");
        }
        return new AdcListenerPlan(rows);
    }
    public void RequireExact(IEnumerable<Entry> actual, bool l4)
    {
        var observed = actual.Select(Normalize).ToArray();
        var expected = entries.Where(x => IsL4(x) == l4).ToArray();
        if (observed.Length != expected.Length || observed.Distinct().Count() != observed.Length ||
            !observed.ToHashSet().SetEquals(expected))
            throw new InvalidDataException("ADC listener configuration does not match the host-provisioned plan.");
    }
    public void RequireL4(JsonObject config)
    {
        var rows = new List<Entry>();
        foreach (var protocol in new[] { "TCP", "UDP" })
        {
            if (config[protocol == "TCP" ? "Tcp" : "Udp"] is not JsonArray listeners)
                throw new InvalidDataException("Missing L4 listener array.");
            foreach (var item in listeners)
            {
                if (item is not JsonObject row)
                    throw new InvalidDataException("Invalid L4 listener.");
                rows.Add(new Entry(row["Name"]!.GetValue<string>(), row["ListenHost"]!.GetValue<string>(),
                    row["ListenPort"]!.GetValue<int>(), protocol));
            }
        }
        RequireExact(rows, true);
    }
    public static AdcListenerPlan? ReadFromEnvironment()
    {
        var path = Environment.GetEnvironmentVariable(EnvironmentKey);
        if (string.IsNullOrWhiteSpace(path)) return null;
        if (!Path.IsPathFullyQualified(path) || !File.Exists(path) ||
            (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException("ADC listener plan must be an absolute regular host file.");
        using var file = File.OpenRead(path);
        if (file.Length is < 1 or > 65536)
            throw new InvalidDataException("ADC listener plan exceeds its size bound.");
        var document = JsonSerializer.Deserialize<Document>(file, new JsonSerializerOptions(JsonSerializerDefaults.Web)
        { UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow }) ??
            throw new InvalidDataException("Missing ADC listener plan.");
        return Create(document);
    }
    // Capture enforcement from the same manifest read used for validation.
    public static bool AllowsL4(byte[] bytes, bool planRequired = false) =>
        AllowsL4(bytes, planRequired, out _);

    public static bool AllowsL4(byte[] bytes, bool planRequired, out bool planEnforced)
    {
        planEnforced = false;
        try
        {
            var plan = ReadFromEnvironment();
            if (plan is null) return !planRequired;
            planEnforced = true;
            if (JsonNode.Parse(bytes) is not JsonObject candidate) return false;
            plan.RequireL4(candidate);
            return true;
        }
        catch (Exception ex) when (ex is InvalidDataException or IOException or UnauthorizedAccessException or JsonException or
            InvalidOperationException or ArgumentException or FormatException or NullReferenceException)
        { return false; }
    }

    // Store mode with the sequence, not in an optional sidecar: missing or
    // corrupt mode cannot silently turn an enforced transaction into legacy.
    public static string FormatTransactionSequence(long sequence, bool planEnforced) =>
        sequence.ToString(System.Globalization.CultureInfo.InvariantCulture) +
        (planEnforced ? ":plan-required" : ":legacy");

    public static bool TryReadTransactionSequence(string value, bool l4, out long sequence, out bool planRequired)
    {
        sequence = 0;
        planRequired = false;
        if (!l4) return long.TryParse(value, out sequence);
        var parts = value.Split(':');
        if (parts.Length != 2 || parts[1] is not ("plan-required" or "legacy") ||
            !long.TryParse(parts[0], System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture, out sequence) || sequence <= 0)
            return false;
        planRequired = parts[1] == "plan-required";
        return true;
    }
}
