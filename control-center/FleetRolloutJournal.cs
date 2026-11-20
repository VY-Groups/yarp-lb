using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

internal static class FleetRolloutJournal
{
    internal static bool IsDigest(string? value) => value is { Length: 64 } &&
        value.All(c => c is >= '0' and <= '9' or >= 'A' and <= 'F');
    internal static bool IsTransaction(string? value) => value is not null &&
        Regex.IsMatch(value, "^rollout_[A-F0-9]{24}$");

    // Old and incomplete records are not silently discarded. A legacy
    // 'rollback-attempted' result did not establish restoration.
    internal static bool HasUnresolved(string folder)
    {
        foreach (var path in Directory.EnumerateFiles(folder, "rollout_*.json"))
        {
            var row = Read(path);
            if (row["status"]?.ToString() is not ("activated-pending-health-validation" or "rollback-verified" or "not-dispatched"))
                return true;
        }
        return false;
    }

    internal static JsonObject Read(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        if (stream.Length is < 1 or > 262144) throw new InvalidDataException("Invalid rollout journal size");
        return JsonNode.Parse(stream)?.AsObject() ?? throw new InvalidDataException("Invalid rollout journal");
    }

    internal static void Write(string path, JsonObject state)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(state);
        if (bytes.Length > 262144) throw new InvalidDataException("Rollout journal exceeds bound");
        var tmp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
            if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            using (var file = new FileStream(tmp, options))
            {
                file.Write(bytes);
                file.Flush(flushToDisk: true);
            }
            File.Move(tmp, path, true);
        }
        finally { if (File.Exists(tmp)) File.Delete(tmp); }
    }

    internal static void Log(string path, JsonObject state, string gateway, string stage, string outcome, string? detail = null)
    {
        ((JsonArray)state["details"]!).Add(new JsonObject { ["utc"] = DateTimeOffset.UtcNow.ToString("O"),
            ["gateway"] = gateway, ["stage"] = stage, ["state"] = outcome, ["detail"] = detail });
        Write(path, state);
    }

    internal static JsonObject[] Targets(JsonObject state) => state["targets"] is JsonArray rows
        ? rows.Select(row => row?.AsObject() ?? throw new InvalidDataException("Invalid target")).ToArray()
        : throw new InvalidDataException("Missing rollout targets");

    internal static bool RecoveryAllowed(JsonObject state, string id, string fleetDigest)
    {
        if (state["schema"]?.GetValue<int>() != 2 || !IsTransaction(id) || state["id"]?.ToString() != id ||
            state["fleetDigest"]?.ToString() != fleetDigest ||
            state["status"]?.ToString() is not ("starting" or "preparing" or "activating" or "manual-intervention-required" or "recovering"))
            return false;
        var rows = Targets(state);
        var ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        return rows.Length is >= 2 and <= 20 && rows.All(r =>
            r["id"]?.ToString() is { Length: > 0 and <= 40 } name && ids.Add(name) &&
            IsDigest(r["originalRevision"]?.ToString()) &&
            r["prepareSent"] is JsonValue pv && pv.TryGetValue<bool>(out _) &&
            r["rollbackVerified"] is JsonValue rv && rv.TryGetValue<bool>(out _));
    }

    internal static bool NeedsRollback(JsonObject target) =>
        target["prepareSent"]!.GetValue<bool>() && !target["rollbackVerified"]!.GetValue<bool>();

    internal static bool CompleteRollback(JsonObject target, string? returnedRevision)
    {
        if (!NeedsRollback(target) || !IsDigest(returnedRevision) ||
            returnedRevision != target["originalRevision"]?.ToString()) return false;
        target["rollbackVerified"] = true;
        return true;
    }
}
