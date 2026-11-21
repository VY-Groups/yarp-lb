using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Text;

namespace GatewayConfigPlan;

/// <summary>Strict offline Gateway API v1 subset. No API credentials, DNS
/// lookup, discovery, status publication, apply or implicit cross-namespace access.</summary>
public static class GatewayApiImport
{
    private static readonly Regex Label = new("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
        RegexOptions.CultureInvariant);
    private static ArgumentException Invalid() => new("Unsupported or invalid Gateway API import document");
    private static JsonObject Object(JsonNode? n, params string[] fields)
    {
        if (n is not JsonObject o || o.Count != fields.Length ||
            fields.Any(f => !o.ContainsKey(f))) throw Invalid();
        return o;
    }
    private static string String(JsonNode? n)
    {
        if (n is not JsonValue v || !v.TryGetValue<string>(out var s) || string.IsNullOrEmpty(s))
            throw Invalid();
        return s;
    }
    private static string Name(JsonNode? n)
    {
        var s = String(n);
        return Label.IsMatch(s) ? s : throw Invalid();
    }
    private static int Port(JsonNode? n)
    {
        if (n is not JsonValue v || !v.TryGetValue<int>(out var port) || port is < 1 or > 65535)
            throw Invalid();
        return port;
    }
    private static JsonArray Array(JsonNode? n, int max)
    {
        if (n is not JsonArray a || a.Count < 1 || a.Count > max) throw Invalid();
        return a;
    }
    private static void Unique(JsonElement e)
    {
        if (e.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var p in e.EnumerateObject())
            {
                if (!names.Add(p.Name)) throw Invalid();
                Unique(p.Value);
            }
        }
        else if (e.ValueKind == JsonValueKind.Array)
            foreach (var item in e.EnumerateArray()) Unique(item);
    }
    private static JsonObject Parse(string json)
    {
        if (Encoding.UTF8.GetByteCount(json) > 524288) throw Invalid();
        try
        {
            using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 24 });
            Unique(doc.RootElement);
            return JsonNode.Parse(json) as JsonObject ?? throw Invalid();
        }
        catch (JsonException) { throw Invalid(); }
    }
    private static JsonObject Resource(JsonNode? n, string version, string kind, bool namespaced)
    {
        var obj = Object(n, "apiVersion", "kind", "metadata", "spec");
        if (String(obj["apiVersion"]) != version || String(obj["kind"]) != kind) throw Invalid();
        var meta = namespaced ? Object(obj["metadata"], "name", "namespace") : Object(obj["metadata"], "name");
        _ = Name(meta["name"]);
        if (namespaced) _ = Name(meta["namespace"]);
        return obj;
    }
    private const string V1 = "gateway.networking.k8s.io/v1";

    // Input is an explicit export bundle, not a Kubernetes List returned by an
    // API server. Service ports and namespace must be included and verified.
    public static JsonObject Translate(string json)
    {
        var parsed = Parse(json);
        // A bundle may declare explicit permission objects, but may never
        // silently drop an unsupported resource or import unknown fields.
        var root = parsed.ContainsKey("referenceGrants")
            ? Object(parsed, "gatewayClass", "gateway", "httpRoutes", "services", "referenceGrants")
            : Object(parsed, "gatewayClass", "gateway", "httpRoutes", "services");
        var cls = Resource(root["gatewayClass"], V1, "GatewayClass", false);
        if (String(Object(cls["spec"], "controllerName")["controllerName"]) != "gatewaycore.example/offline")
            throw Invalid();
        var gateway = Resource(root["gateway"], V1, "Gateway", true);
        var ns = Name(gateway["metadata"]!["namespace"]);
        var gwName = Name(gateway["metadata"]!["name"]);
        var spec = Object(gateway["spec"], "gatewayClassName", "listeners");
        if (Name(spec["gatewayClassName"]) != Name(cls["metadata"]!["name"])) throw Invalid();
        var listener = Object(Array(spec["listeners"], 1)[0], "name", "protocol", "port", "allowedRoutes");
        var listenerName = Name(listener["name"]);
        if (String(listener["protocol"]) != "HTTP" || Port(listener["port"]) != 80 ||
            String(Object(Object(listener["allowedRoutes"], "namespaces")["namespaces"], "from")["from"]) != "Same")
            throw Invalid();
        // Service identity is namespace + name, never just a display name.
        // A cross-namespace Service requires an explicit target-owned grant.
        var services = new Dictionary<string, HashSet<int>>(StringComparer.Ordinal);
        foreach (var n in Array(root["services"], 100))
        {
            var svc = Resource(n, "v1", "Service", true);
            var svcNamespace = Name(svc["metadata"]!["namespace"]);
            var svcName = Name(svc["metadata"]!["name"]);
            var svcSpec = Object(svc["spec"], "type", "ports");
            if (String(svcSpec["type"]) != "ClusterIP") throw Invalid();
            var ports = new HashSet<int>();
            foreach (var entry in Array(svcSpec["ports"], 40))
            {
                var row = Object(entry, "port", "protocol", "appProtocol");
                if (String(row["protocol"]) != "TCP" ||
                    String(row["appProtocol"]) != "http" || !ports.Add(Port(row["port"]))) throw Invalid();
            }
            if (!services.TryAdd(svcNamespace + "/" + svcName, ports)) throw Invalid();
        }
        // ReferenceGrant is owned by the *target* namespace, not the
        // HTTPRoute namespace. The offline subset accepts only a named
        // Service and one explicit HTTPRoute source namespace per grant;
        // broad wildcard grants and unsupported permissions fail closed.
        var grants = new HashSet<string>(StringComparer.Ordinal);
        var grantNames = new HashSet<string>(StringComparer.Ordinal);
        if (root.ContainsKey("referenceGrants"))
        {
            foreach (var item in Array(root["referenceGrants"], 32))
            {
                var grant = Resource(item, V1, "ReferenceGrant", true);
                var targetNamespace = Name(grant["metadata"]!["namespace"]);
                var grantName = Name(grant["metadata"]!["name"]);
                if (!grantNames.Add(targetNamespace + "/" + grantName))
                    throw Invalid();
                var grantSpec = Object(grant["spec"], "from", "to");
                var from = Object(Array(grantSpec["from"], 1)[0], "group", "kind", "namespace");
                var to = Object(Array(grantSpec["to"], 1)[0], "group", "kind", "name");
                if (String(from["group"]) != "gateway.networking.k8s.io" ||
                    String(from["kind"]) != "HTTPRoute" ||
                    Name(from["namespace"]) != ns ||
                    String(to["group"]) != "" ||
                    String(to["kind"]) != "Service")
                    throw Invalid();
                var targetService = Name(to["name"]);
                if (targetNamespace == ns ||
                    !grants.Add(targetNamespace + "/" + ns + "/" + targetService))
                    throw Invalid();
            }
        }
        var routes = new JsonObject();
        var clusters = new JsonObject();
        // YARP path matching differs from Gateway API on some exact/prefix
        // cases. Restrict to root prefix rather than widen route semantics.
        foreach (var n in Array(root["httpRoutes"], 100))
        {
            var route = Resource(n, V1, "HTTPRoute", true);
            if (Name(route["metadata"]!["namespace"]) != ns) throw Invalid();
            var routeName = Name(route["metadata"]!["name"]);
            var routeSpec = Object(route["spec"], "parentRefs", "rules");
            var parent = Object(Array(routeSpec["parentRefs"], 1)[0], "name", "sectionName");
            if (Name(parent["name"]) != gwName || Name(parent["sectionName"]) != listenerName) throw Invalid();
            var rule = Object(Array(routeSpec["rules"], 1)[0], "matches", "backendRefs");
            var match = Object(Array(rule["matches"], 1)[0], "path");
            var path = Object(match["path"], "type", "value");
            var value = String(path["value"]);
            // Prefix "/" matches every absolute path; other prefixes/Exact,
            // hostnames, filters, weights and TLS require runtime conformance.
            if (String(path["type"]) != "PathPrefix" || value != "/") throw Invalid();
            var backendNode = Array(rule["backendRefs"], 1)[0];
            var backend = backendNode is JsonObject candidate && candidate.ContainsKey("namespace")
                ? Object(backendNode, "name", "port", "namespace")
                : Object(backendNode, "name", "port");
            var service = Name(backend["name"]);
            var serviceNamespace = backend.ContainsKey("namespace")
                ? Name(backend["namespace"]) : ns;
            var port = Port(backend["port"]);
            if (!services.TryGetValue(serviceNamespace + "/" + service, out var servicePorts) ||
                !servicePorts.Contains(port)) throw Invalid();
            if (serviceNamespace != ns && !grants.Remove(serviceNamespace + "/" + ns + "/" + service))
                throw Invalid(); // Grant absent, wrong target/source or insufficient scope.
            if (routes.Count != 0) throw Invalid(); // root prefix conflicts with any second route
            var clusterId = "svc-" + service + "-" + port.ToString(System.Globalization.CultureInfo.InvariantCulture);
            routes.Add(routeName, new JsonObject { ["ClusterId"] = clusterId,
                ["Match"] = new JsonObject { ["Path"] = "/{**catch-all}" } });
            clusters.Add(clusterId, new JsonObject { ["Destinations"] = new JsonObject {
                ["service"] = new JsonObject { ["Address"] = $"http://{service}.{serviceNamespace}.svc.cluster.local:{port}/" } } });
        }
        // Unused grants may have been broad/stale or intended for resources
        // not represented by this one-route bundle. Never silently ignore.
        if (grants.Count != 0) throw Invalid();
        var output = new JsonObject { ["schemaVersion"] = 1, ["routes"] = routes, ["clusters"] = clusters };
        _ = PlanEngine.Validate(output.ToJsonString());
        return output;
    }
}
