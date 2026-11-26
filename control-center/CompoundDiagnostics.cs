using System.Net.Sockets;
using System.Text.Json.Nodes;

public sealed record CompoundProbeSettings(string Mode, string? SecondaryPath)
{
    public const string ModeKey = "ADC.Diagnostics.CompoundMode";
    public const string SecondaryPathKey = "ADC.Diagnostics.SecondaryPath";

    public static bool TryRead(JsonObject cluster, out CompoundProbeSettings? settings)
    {
        settings = null;
        if (cluster["Metadata"] is not JsonObject metadata) return true;
        if (!metadata.ContainsKey(ModeKey)) return !metadata.ContainsKey(SecondaryPathKey);
        if (metadata[ModeKey] is not JsonValue modeValue ||
            !modeValue.TryGetValue<string>(out var mode) || mode is not ("AND" or "OR"))
            return false;
        var active = (cluster["HealthCheck"] as JsonObject)?["Active"] as JsonObject;
        if (active?["Path"] is not JsonValue primary || !primary.TryGetValue<string>(out var primaryPath) ||
            !ValidPath(primaryPath)) return false;
        string? secondary = null;
        if (metadata.ContainsKey(SecondaryPathKey))
        {
            if (metadata[SecondaryPathKey] is not JsonValue value ||
                !value.TryGetValue<string>(out secondary) || !ValidPath(secondary) ||
                string.Equals(primaryPath, secondary, StringComparison.Ordinal)) return false;
        }
        settings = new(mode, secondary);
        return true;
    }

    public static bool ValidPath(string? path) =>
        !string.IsNullOrEmpty(path) && path.Length <= 300 && path.StartsWith('/') &&
        !path.StartsWith("//", StringComparison.Ordinal) && !path.Contains('\\') &&
        !path.Contains('#') && !path.Any(char.IsControl);

    public static bool TryTarget(Uri origin, string? path, out Uri? target)
    {
        target = null;
        if (!origin.IsAbsoluteUri || origin.Scheme is not ("http" or "https") ||
            origin.UserInfo.Length != 0 || !ValidPath(path)) return false;
        if (!Uri.TryCreate(origin, path, out var candidate) || candidate.Scheme != origin.Scheme ||
            !string.Equals(candidate.IdnHost, origin.IdnHost, StringComparison.OrdinalIgnoreCase) ||
            candidate.Port != origin.Port || candidate.UserInfo.Length != 0) return false;
        target = candidate;
        return true;
    }
}

public sealed record CompoundProbeObservation(string Check, bool Passed, int? HttpStatus);
public sealed record CompoundProbeResult(bool Passed, IReadOnlyList<CompoundProbeObservation> Checks);

public static class CompoundDiagnostics
{
    public static async Task<CompoundProbeResult> EvaluateAsync(HttpClient client, Uri origin, string primaryPath,
        CompoundProbeSettings settings, CancellationToken cancellationToken)
    {
        if (settings.Mode is not ("AND" or "OR") ||
            !CompoundProbeSettings.TryTarget(origin, primaryPath, out var primary) ||
            (settings.SecondaryPath is not null &&
             !CompoundProbeSettings.TryTarget(origin, settings.SecondaryPath, out _)))
            throw new ArgumentException("Invalid compound diagnostic configuration");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(3));
        var tasks = new List<Task<CompoundProbeObservation>>(3)
        {
            TcpAsync(origin, deadline.Token),
            HttpAsync(client, primary!, "http-primary", deadline.Token)
        };
        if (settings.SecondaryPath is not null)
        {
            CompoundProbeSettings.TryTarget(origin, settings.SecondaryPath, out var secondary);
            tasks.Add(HttpAsync(client, secondary!, "http-secondary", deadline.Token));
        }
        var results = await Task.WhenAll(tasks);
        cancellationToken.ThrowIfCancellationRequested();
        return new(settings.Mode == "AND" ? results.All(r => r.Passed) : results.Any(r => r.Passed), results);
    }

    private static async Task<CompoundProbeObservation> TcpAsync(Uri origin, CancellationToken token)
    {
        try
        {
            using var socket = new TcpClient();
            await socket.ConnectAsync(origin.IdnHost, origin.Port, token);
            return new("tcp-connect", true, null);
        }
        catch (Exception e) when (e is SocketException or OperationCanceledException or ArgumentException)
        { return new("tcp-connect", false, null); }
    }

    private static async Task<CompoundProbeObservation> HttpAsync(HttpClient client, Uri uri, string name, CancellationToken token)
    {
        try
        {
            using var response = await client.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, token);
            return new(name, response.IsSuccessStatusCode, (int)response.StatusCode);
        }
        catch (Exception e) when (e is HttpRequestException or OperationCanceledException)
        { return new(name, false, null); }
    }
}

/// <summary>Pure JSON active-health contract shared by controller and signed agent.</summary>
public static class CompoundActiveDraft
{
    private const string ModeKey = "ADC.Health.CompoundMode";
    private const string PathKey = "ADC.Health.SecondaryPath";
    public static bool Validate(JsonObject cluster)
    {
        if (cluster["Metadata"] is not JsonObject metadata) return true;
        if (!metadata.ContainsKey(ModeKey)) return !metadata.ContainsKey(PathKey);
        if (metadata[ModeKey] is not JsonValue mode || !mode.TryGetValue<string>(out var modeText) ||
            metadata[PathKey] is not JsonValue path || !path.TryGetValue<string>(out var pathText) ||
            modeText is null || pathText is null ||
            modeText is not ("AND" or "OR") || !CompoundProbeSettings.ValidPath(pathText)) return false;
        var active = (cluster["HealthCheck"] as JsonObject)?["Active"] as JsonObject;
        if (active?["Enabled"] is not JsonValue enabled || !enabled.TryGetValue<bool>(out var on) || !on ||
            active["Path"] is not JsonValue primary || !primary.TryGetValue<string>(out var primaryPath) ||
            !CompoundProbeSettings.ValidPath(primaryPath) || primaryPath == pathText ||
            cluster["HttpClient"]?["WebProxy"] is not null ||
            cluster["HealthCheck"]?["AvailableDestinationsPolicy"]?.ToString() != "HealthyAndUnknown")
            return false;
        return cluster["Destinations"] is JsonObject destinations &&
            destinations.All(x => x.Value is JsonObject d && d["Health"] is null);
    }
}
