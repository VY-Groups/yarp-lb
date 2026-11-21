using System.Text.Json.Nodes;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace GatewayConfigPlan;

public sealed record PlanChange(string Kind, string Id);
public sealed record ConfigPlan(string Status, IReadOnlyList<PlanChange> Changes, IReadOnlyList<string> Warnings);
public sealed record ConfigValidation(string Status, int SchemaVersion, int RouteCount, int ClusterCount,
    int DestinationCount, IReadOnlyList<string> Warnings);

/// <summary>Offline, read-only planner for the supported YARP routes/clusters subset. It never applies configuration.</summary>
public static class PlanEngine
{
    private static readonly Regex IdPattern = new("^[A-Za-z0-9_-]{1,80}$", RegexOptions.CultureInvariant);
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = false };
    private const int MaxDocumentBytes = 512 * 1024;

    public static ConfigPlan Build(string currentJson, string desiredJson)
    {
        var current = Parse(currentJson, "current");
        var desired = Parse(desiredJson, "desired");
        var changes = new List<PlanChange>();
        Diff("route", current.Routes, desired.Routes, changes);
        Diff("cluster", current.Clusters, desired.Clusters, changes);
        changes.Sort((a, b) => StringComparer.Ordinal.Compare($"{a.Kind}/{a.Id}", $"{b.Kind}/{b.Id}"));
        return new ConfigPlan("valid", changes,
            ["Plan is read-only; it does not write appsettings, approve changes, or deploy a gateway."]);
    }

    /// <summary>Validates one desired document without requiring access to live state.</summary>
    public static ConfigValidation Validate(string desiredJson)
    {
        var desired = Parse(desiredJson, "desired");
        return new ConfigValidation("valid", 1, desired.Routes.Count, desired.Clusters.Count,
            desired.Clusters.Sum(cluster => ((JsonObject)cluster.Value!["Destinations"]!).Count),
            ["Validation is offline and read-only; it does not apply configuration or verify runtime health."]);
    }

    private static DesiredConfig Parse(string json, string label)
    {
        JsonObject root;
        if (System.Text.Encoding.UTF8.GetByteCount(json) > MaxDocumentBytes)
            throw new ArgumentException($"{label} config: input exceeds 512 KiB bound", nameof(json));
        try
        {
            using var document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 24 });
            RejectDuplicateProperties(document.RootElement);
            root = JsonNode.Parse(json)?.AsObject() ??
                throw new FormatException("document must be an object");
        }
        catch (Exception e) when (e is JsonException or InvalidOperationException or
                                    FormatException or ArgumentException)
        {
            // Do not include untrusted backend addresses or secret-bearing JSON
            // fragments in CLI logs and CI check output.
            throw new ArgumentException($"{label} config: invalid or ambiguous JSON", nameof(json));
        }
        var allowed = new HashSet<string>(["schemaVersion", "routes", "clusters"], StringComparer.Ordinal);
        var unknown = root.Select(x => x.Key).Where(k => !allowed.Contains(k)).ToArray();
        if (unknown.Length != 0) throw new ArgumentException($"{label} config: unsupported field(s)", nameof(json));
        if (!TryInt(root["schemaVersion"], out var schemaVersion) || schemaVersion != 1)
            throw new ArgumentException($"{label} config: schemaVersion must be 1", nameof(json));
        var routes = root["routes"] as JsonObject ?? throw new ArgumentException($"{label} config: routes must be an object", nameof(json));
        var clusters = root["clusters"] as JsonObject ?? throw new ArgumentException($"{label} config: clusters must be an object", nameof(json));
        if (routes.Count > 100 || clusters.Count > 100)
            throw new ArgumentException($"{label} config exceeds route or cluster limits", nameof(json));
        foreach (var (id, route) in routes)
        {
            RequireId(id, label, "route");
            if (route is not JsonObject routeObject || !HasOnly(routeObject, "ClusterId", "Match"))
                throw new ArgumentException($"{label} config: route {id} must contain only ClusterId and Match", nameof(json));
            var cluster = TryString(routeObject["ClusterId"]);
            if (string.IsNullOrWhiteSpace(cluster) || !clusters.ContainsKey(cluster))
                throw new ArgumentException($"{label} config: route {id} references a missing cluster", nameof(json));
            var match = routeObject["Match"] as JsonObject;
            if (match is null || !HasOnly(match, "Path"))
                throw new ArgumentException($"{label} config: route {id} Match must contain only Path", nameof(json));
            var path = TryString(match?["Path"]);
            if (path is null || !path.StartsWith('/') || path.Length > 300 || path.Contains('\\'))
                throw new ArgumentException($"{label} config: route {id} has an invalid Match.Path", nameof(json));
        }
        foreach (var (id, cluster) in clusters)
        {
            RequireId(id, label, "cluster");
            if (cluster is not JsonObject obj || !HasOnly(obj, "Destinations") ||
                obj["Destinations"] is not JsonObject destinations || destinations.Count is 0 or > 40)
                throw new ArgumentException($"{label} config: cluster {id} must have 1..40 destinations", nameof(json));
            foreach (var (destinationId, destination) in destinations)
            {
                RequireId(destinationId, label, "destination");
                if (destination is not JsonObject destObj || !HasOnly(destObj, "Address"))
                    throw new ArgumentException($"{label} config: destination {id}/{destinationId} must contain only Address", nameof(json));
                var address = TryString(destObj["Address"]);
                if (!Uri.TryCreate(address, UriKind.Absolute, out var uri) ||
                    uri.Scheme is not ("http" or "https") || string.IsNullOrWhiteSpace(uri.Host) || uri.UserInfo.Length != 0 ||
                    uri.Query.Length != 0 || uri.Fragment.Length != 0 || uri.AbsolutePath != "/")
                    throw new ArgumentException($"{label} config: destination {id}/{destinationId} must use an HTTP(S) origin without path, query, fragment, or userinfo", nameof(json));
            }
        }
        return new(routes, clusters);
    }

    private static void RejectDuplicateProperties(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var property in element.EnumerateObject())
            {
                if (!seen.Add(property.Name))
                    throw new ArgumentException("Duplicate or case-aliased JSON property");
                RejectDuplicateProperties(property.Value);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var value in element.EnumerateArray())
                RejectDuplicateProperties(value);
        }
    }

    private static void RequireId(string id, string label, string kind)
    {
        if (!IdPattern.IsMatch(id)) throw new ArgumentException($"{label} config: invalid {kind} ID", nameof(id));
    }

    private static string? TryString(JsonNode? node) =>
        node is JsonValue value && value.TryGetValue<string>(out var result) ? result : null;

    private static bool HasOnly(JsonObject value, params string[] allowed) =>
        value.All(property => allowed.Contains(property.Key, StringComparer.Ordinal));

    private static bool TryInt(JsonNode? node, out int result)
    {
        if (node is JsonValue value && value.TryGetValue<int>(out result)) return true;
        result = default;
        return false;
    }

    private static void Diff(string kind, JsonObject current, JsonObject desired, List<PlanChange> output)
    {
        foreach (var (id, value) in desired)
        {
            if (!current.TryGetPropertyValue(id, out var old)) output.Add(new("add", $"{kind}:{id}"));
            else if (!JsonNode.DeepEquals(old, value)) output.Add(new("update", $"{kind}:{id}"));
        }
        foreach (var id in current.Select(x => x.Key).Where(id => !desired.ContainsKey(id))) output.Add(new("remove", $"{kind}:{id}"));
    }

    private sealed record DesiredConfig(JsonObject Routes, JsonObject Clusters);
}
