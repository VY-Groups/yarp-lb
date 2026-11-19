using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

/// <summary>Strict allowlisted engine schemas and engine-ID-bound v2 signatures.
/// The agent uses this only after mandatory TLS client certificate authentication.</summary>
public static class EngineConfigContract
{
    public static bool ValidEngineId(string id) => id is "l4" or "gslb";

    private static JsonObject Envelope(string engineId, JsonObject payload)
    {
        if (!ValidEngineId(engineId)) throw new ArgumentException("Unknown engine");
        return new JsonObject { ["EngineId"] = engineId, ["Config"] = payload.DeepClone() };
    }

    public static FleetConfigSignature.SignedV2 Sign(string privateKey, string engineId,
        string transaction, string revision, JsonObject payload, long expiry, long sequence) =>
        FleetConfigSignature.SignV2(privateKey, transaction, revision,
            Envelope(engineId, payload), expiry, sequence);

    public static bool Verify(IReadOnlyDictionary<string,string> pinnedPublicKeys,
        string engineId, string transaction, string revision, JsonObject payload,
        FleetConfigSignature.SignedV2 signed, long now) =>
        ValidEngineId(engineId) && FleetConfigSignature.VerifyV2(pinnedPublicKeys,
            transaction, revision, Envelope(engineId, payload), signed, now);

    private static bool Str(JsonNode? n, out string value)
    {
        value = "";
        if (n is not JsonValue v || !v.TryGetValue<string>(out var literal) ||
            string.IsNullOrWhiteSpace(literal)) return false;
        value = literal;
        return true;
    }
    private static bool Num(JsonNode? n, int min, int max) =>
        n is JsonValue v && v.TryGetValue<int>(out var num) && num >= min && num <= max;
    private static bool Serial(JsonNode? n, out uint value)
    {
        value = 0;
        return n is JsonValue v && v.TryGetValue<uint>(out value) && value != 0;
    }
    private static bool Bool(JsonNode? n) =>
        n is JsonValue v && v.TryGetValue<bool>(out _);
    private static bool Ip(JsonNode? n, out IPAddress address, bool allowIpv6 = false)
    {
        address = IPAddress.None;
        if (!Str(n, out var literal) || !IPAddress.TryParse(literal, out var parsed) ||
            (parsed.AddressFamily != AddressFamily.InterNetwork &&
             !(allowIpv6 && parsed.AddressFamily == AddressFamily.InterNetworkV6 && !parsed.IsIPv4MappedToIPv6))) return false;
        address = parsed;
        return true;
    }

    public static bool Validate(string engineId, JsonObject config, bool allowPublicBind)
    {
        if (!ValidEngineId(engineId) || config.ToJsonString().Length > 524288) return false;
        if (!Ip(config["ListenHost"], out var bind, allowIpv6: true) && engineId == "gslb") return false;
        if (config["AllowNonLoopbackListeners"] is not null &&
            !Bool(config["AllowNonLoopbackListeners"])) return false;
        var publicOptIn = config["AllowNonLoopbackListeners"] is JsonValue v &&
                          v.TryGetValue<bool>(out var opted) && opted;
        if (engineId == "gslb")
        {
            var listenPortAllowed = Num(config["ListenPort"],1025,65535) ||
                Num(config["ListenPort"],53,53) && allowPublicBind && publicOptIn && !IPAddress.IsLoopback(bind);
            if (!listenPortAllowed ||
                !Num(config["ProbeIntervalSeconds"],1,60) ||
                (config["MaxResponsesPerSecondPerClient"] is not null &&
                 !Num(config["MaxResponsesPerSecondPerClient"],20,20000)) ||
                (!IPAddress.IsLoopback(bind) && (!allowPublicBind || !publicOptIn)) ||
                config["Zones"] is not JsonArray zones || zones.Count is < 1 or > 64)
                return false;
            foreach (var item in zones)
            {
                if (item is not JsonObject zone || !Str(zone["Name"],out var name) ||
                    name.Length > 253 || !Num(zone["TtlSeconds"],5,300) ||
                    (zone["SoaSerial"] is not null && !Serial(zone["SoaSerial"],out _)) ||
                    zone["Sites"] is not JsonArray sites || sites.Count is < 1 or > 16)
                    return false;
                foreach (var s in sites)
                {
                    if (s is not JsonObject site || !Ip(site["Address"],out _, allowIpv6: true) ||
                        !Num(site["Weight"],1,100)) return false;
                    var probeType = "Http";
                    if (site["HealthCheckType"] is not null &&
                        !Str(site["HealthCheckType"], out probeType)) return false;
                    if (probeType == "Tcp")
                    {
                        if (!Num(site["TcpPort"],1,65535) ||
                            (site["HealthUrl"] is not null &&
                             !(site["HealthUrl"] is JsonValue text && text.TryGetValue<string>(out var empty) &&
                               string.IsNullOrWhiteSpace(empty)))) return false;
                    }
                    else if (probeType != "Http" ||
                             (site["TcpPort"] is not null && !Num(site["TcpPort"],0,0)) ||
                             !Str(site["HealthUrl"],out var url) ||
                             !Uri.TryCreate(url,UriKind.Absolute,out var uri) ||
                             (uri.Scheme!="http" && uri.Scheme!="https") ||
                             !string.IsNullOrEmpty(uri.UserInfo)) return false;
                }
            }
            return true;
        }
        if (config["Tcp"] is not JsonArray tcp || config["Udp"] is not JsonArray udp ||
            tcp.Count+udp.Count is < 1 or > 20) return false;
        var used = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var section in new[] {tcp,udp})
        foreach (var item in section)
        {
            if (item is not JsonObject listener ||
                !Str(listener["Name"],out var name) ||
                !Regex.IsMatch(name, "^[A-Za-z0-9_-]{1,64}$") ||
                !used.Add(name) || !Ip(listener["ListenHost"],out var address) ||
                !Num(listener["ListenPort"],1025,65535) ||
                (!IPAddress.IsLoopback(address) && (!allowPublicBind || !publicOptIn)) ||
                (listener["TcpIdleTimeoutSeconds"] is not null &&
                 !Num(listener["TcpIdleTimeoutSeconds"],1,3600)) ||
                (listener.TryGetPropertyValue("UdpIdleTimeoutSeconds", out var udpIdle) &&
                 !Num(udpIdle,1,3600)) ||
                (listener["ProbeIntervalSeconds"] is not null &&
                 !Num(listener["ProbeIntervalSeconds"],1,60)) ||
                (listener["SendProxyProtocolV1"] is not null &&
                 !Bool(listener["SendProxyProtocolV1"])) ||
                listener["Backends"] is not JsonArray backends || backends.Count is < 1 or > 16)
                return false;
            foreach(var b in backends)
            {
                if (b is not JsonObject backend || !Ip(backend["Host"],out _) ||
                    !Num(backend["Port"],1,65535) ||
                    (backend["DrainNewConnections"] is not null &&
                     !Bool(backend["DrainNewConnections"]))) return false;
            }
        }
        return true;
    }

    /// <summary>
    /// Requires an RFC 1982 serial advance when a signed GSLB update changes an
    /// existing authoritative zone. A serial-only update is allowed, but it
    /// cannot move backwards or repeat after changing zone data.
    /// </summary>
    public static bool ValidSoaSerialTransition(JsonObject current, JsonObject candidate)
    {
        if (!TryZones(current, out var oldZones) || !TryZones(candidate, out var newZones))
            return false;
        foreach (var (name, oldZone) in oldZones)
        {
            if (!newZones.TryGetValue(name, out var newZone)) continue;
            if (!HasAuthority(oldZone) && !HasAuthority(newZone)) continue;

            var oldSerial = ReadSerial(oldZone);
            var newSerial = ReadSerial(newZone);
            if (oldSerial is null || newSerial is null) return false;

            var oldData = (JsonObject)oldZone.DeepClone();
            var newData = (JsonObject)newZone.DeepClone();
            oldData.Remove("SoaSerial");
            newData.Remove("SoaSerial");
            var dataChanged = !JsonNode.DeepEquals(oldData, newData);

            if (newSerial.Value != oldSerial.Value && !IsSerialNewer(newSerial.Value, oldSerial.Value))
                return false;
            if (dataChanged && !IsSerialNewer(newSerial.Value, oldSerial.Value))
                return false;
        }
        return true;
    }

    private static bool TryZones(JsonObject config, out Dictionary<string,JsonObject> zones)
    {
        zones = new Dictionary<string,JsonObject>(StringComparer.OrdinalIgnoreCase);
        if (config["Zones"] is not JsonArray rows) return false;
        foreach (var row in rows)
        {
            if (row is not JsonObject zone || !Str(zone["Name"], out var name)) return false;
            var key = name.TrimEnd('.');
            if (key.Length == 0 || !zones.TryAdd(key, zone)) return false;
        }
        return true;
    }

    private static uint? ReadSerial(JsonObject zone)
    {
        if (zone["SoaSerial"] is null) return 1;
        return Serial(zone["SoaSerial"], out var serial) ? serial : null;
    }

    private static bool HasAuthority(JsonObject zone) =>
        zone["NameServers"] is JsonArray { Count: > 0 } ||
        zone["Delegations"] is JsonArray { Count: > 0 };

    private static bool IsSerialNewer(uint candidate, uint current)
    {
        var difference = unchecked(candidate - current);
        return difference is > 0 and < 0x80000000;
    }
}
