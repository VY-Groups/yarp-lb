using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using GatewayCore.Gslb.Contracts;

internal sealed record AgentTrust(string AgentId, string VantageGroup,
    string[] CertificateSha256, string[] SigningPublicKeyPems);
internal sealed record AgentReportTarget(string Zone, string SiteId, string[] RequiredAgentIds,
    int MinimumHealthyVantageGroups);

/// <summary>
/// Bounded report store. A target requires a configured number of fresh
/// positive, independently declared vantage groups; any fresh negative
/// report remains a veto, and missing/unknown evidence never counts.
/// Replay high-water marks survive DNS process restarts; report health itself
/// does not, so a restarted DNS node waits for fresh reports.
/// </summary>
internal sealed class AgentHealthReportStore : IDisposable
{
    private sealed record ReplayPoint(long Epoch, long Sequence);
    private sealed record ReplayFile(int Version, Dictionary<string, ReplayPoint> Points);
    private sealed record LiveReport(string Verdict, long ExpiresAtTick);
    private sealed record ReportPolicy(string[] AgentIds, int MinimumHealthyVantageGroups);

    private readonly object gate = new();
    private readonly Dictionary<string, AgentTrustEntry> agents;
    private readonly Dictionary<string, ReportPolicy> targets;
    private readonly Dictionary<string, ReplayPoint> highWater;
    private FileStream? stateLock;
    private readonly Dictionary<string, LiveReport> live = new(StringComparer.Ordinal);
    private readonly Dictionary<string, (long WindowStart, int Count)> rates = new(StringComparer.Ordinal);
    private readonly string statePath;
    private readonly int maxTtlSeconds;
    private readonly int maxAgeSeconds;
    private readonly int maxClockSkewSeconds;

    public AgentHealthReportStore(IEnumerable<AgentTrust> configuredAgents,
        IEnumerable<AgentReportTarget> configuredTargets, string replayStatePath,
        int maxTtlSeconds, int maxAgeSeconds, int maxClockSkewSeconds)
    {
        if (!Path.IsPathFullyQualified(replayStatePath) || maxTtlSeconds < 1 ||
            maxAgeSeconds < 1 || maxClockSkewSeconds < 0)
            throw new InvalidDataException("Agent report bounds and absolute replay state path are required");
        this.statePath = replayStatePath;
        this.maxTtlSeconds = maxTtlSeconds;
        this.maxAgeSeconds = maxAgeSeconds;
        this.maxClockSkewSeconds = maxClockSkewSeconds;

        var trust = configuredAgents?.ToArray() ?? throw new InvalidDataException("Agent trust list required");
        if (trust.Length is < 2 or > 64)
            throw new InvalidDataException("Agent trust list must contain 2..64 identities");
        agents = new Dictionary<string, AgentTrustEntry>(StringComparer.Ordinal);
        var usedPins = new HashSet<string>(StringComparer.Ordinal);
        try
        {
            foreach (var item in trust)
            {
                if (item is null || !AgentHealthReportContract.IsValidIdentifier(item.AgentId) ||
                    !AgentHealthReportContract.IsValidIdentifier(item.VantageGroup) ||
                    item.CertificateSha256 is not { Length: >= 1 and <= 4 } ||
                    item.SigningPublicKeyPems is not { Length: >= 1 and <= 4 } ||
                    item.SigningPublicKeyPems.Any(path => !Path.IsPathFullyQualified(path)))
                    throw new InvalidDataException("Invalid agent identity, certificate pin or signing-key path");
                var certPins = item.CertificateSha256.Select(pin =>
                {
                    byte[] bytes;
                    try { bytes = Convert.FromHexString(pin); }
                    catch (FormatException ex) { throw new InvalidDataException("Invalid agent SHA-256 certificate pin", ex); }
                    if (bytes.Length != 32) throw new InvalidDataException("Agent certificate pin must be SHA-256");
                    return bytes;
                }).ToArray();
                if (certPins.Select(Convert.ToHexString).Distinct(StringComparer.Ordinal).Count() != certPins.Length)
                    throw new InvalidDataException("Duplicate agent certificate pin");
                foreach (var pin in certPins)
                    if (!usedPins.Add(Convert.ToHexString(pin)))
                        throw new InvalidDataException("Client certificate pins must identify exactly one agent");
                var publicKeys = new Dictionary<string, byte[]>(StringComparer.Ordinal);
                foreach (var keyPath in item.SigningPublicKeyPems)
                {
                    using var key = ECDsa.Create();
                    key.ImportFromPem(File.ReadAllText(keyPath));
                    if (key.ExportParameters(false).Curve.Oid.Value != "1.2.840.10045.3.1.7")
                        throw new InvalidDataException("Agent report signing keys must use P-256");
                    var encodedKey = key.ExportSubjectPublicKeyInfo();
                    if (!publicKeys.TryAdd(AgentHealthReportContract.KeyId(key), encodedKey))
                        throw new InvalidDataException("Duplicate agent report signing key");
                }
                if (!agents.TryAdd(item.AgentId, new AgentTrustEntry(item.VantageGroup, certPins, publicKeys)))
                    throw new InvalidDataException("Duplicate agent identity");
            }

            var targetRows = configuredTargets?.ToArray() ?? throw new InvalidDataException("Agent report targets required");
            if (targetRows.Length is < 1 or > 1024)
                throw new InvalidDataException("Agent report targets must contain 1..1024 zone/site pairs");
            targets = new Dictionary<string, ReportPolicy>(StringComparer.OrdinalIgnoreCase);
            foreach (var target in targetRows)
            {
                if (target is null || string.IsNullOrWhiteSpace(target.Zone) ||
                    string.IsNullOrWhiteSpace(target.SiteId) ||
                    target.RequiredAgentIds is not { Length: >= 2 and <= 16 } ||
                    target.MinimumHealthyVantageGroups is < 2 or > 16 ||
                    target.MinimumHealthyVantageGroups > target.RequiredAgentIds.Length ||
                    target.RequiredAgentIds.Distinct(StringComparer.Ordinal).Count() != target.RequiredAgentIds.Length ||
                    target.RequiredAgentIds.Any(id => !agents.ContainsKey(id)))
                    throw new InvalidDataException("Each report-gated site needs a bounded agent set and healthy-vantage threshold");
                var vantageGroups = target.RequiredAgentIds.Select(id => agents[id].VantageGroup)
                    .Distinct(StringComparer.Ordinal).Count();
                if (target.MinimumHealthyVantageGroups > vantageGroups)
                    throw new InvalidDataException("Healthy-vantage threshold exceeds distinct configured vantage groups");
                if (!targets.TryAdd(TargetKey(target.Zone, target.SiteId), new ReportPolicy(
                    target.RequiredAgentIds.ToArray(), target.MinimumHealthyVantageGroups)))
                    throw new InvalidDataException("Duplicate report-gated zone/site");
            }
            stateLock = AcquireStateLock(statePath);
            highWater = LoadReplayState(statePath);
            var maximumPoints = targets.Values.Sum(policy => policy.AgentIds.Length);
            var allowedPoints = targets.SelectMany(target => target.Value.AgentIds.Select(agentId =>
                ReplayKey(agentId, target.Key.Split('\n')[0], target.Key.Split('\n')[1])))
                .ToHashSet(StringComparer.Ordinal);
            if (highWater.Count > maximumPoints || highWater.Keys.Any(key => !allowedPoints.Contains(key)))
                throw new InvalidDataException("Replay state exceeds configured report targets");
        }
        catch
        {
            foreach (var entry in agents.Values) entry.Dispose();
            stateLock?.Dispose();
            throw;
        }
    }

    public bool TryAccept(AgentHealthReport report, X509Certificate2 clientCertificate,
        DateTimeOffset now, long nowTick)
    {
        ArgumentNullException.ThrowIfNull(clientCertificate);
        if (!AgentHealthReportContract.IsValid(report, maxTtlSeconds)) return false;
        var agent = agents.GetValueOrDefault(report.AgentId);
        if (agent is null || !targets.TryGetValue(TargetKey(report.Zone, report.SiteId), out var policy) ||
            !policy.AgentIds.Contains(report.AgentId, StringComparer.Ordinal)) return false;

        var nowSeconds = now.ToUnixTimeSeconds();
        if (report.ObservedAtUnixSeconds > nowSeconds + maxClockSkewSeconds ||
            nowSeconds - report.ObservedAtUnixSeconds > maxAgeSeconds ||
            report.ExpiresAtUnixSeconds <= nowSeconds) return false;
        var remainingSeconds = Math.Min(report.ExpiresAtUnixSeconds - nowSeconds, maxTtlSeconds);
        if (remainingSeconds <= 0) return false;

        if (!IsAuthorizedCertificate(clientCertificate, report.AgentId)) return false;
        if (!agent.SigningPublicKeys.TryGetValue(report.KeyId, out var keyBytes)) return false;
        using var key = ECDsa.Create();
        key.ImportSubjectPublicKeyInfo(keyBytes, out _);
        if (!AgentHealthReportContract.Verify(report, key, maxTtlSeconds)) return false;

        var targetKey = TargetKey(report.Zone, report.SiteId);
        var replayKey = ReplayKey(report.AgentId, report.Zone, report.SiteId);
        lock (gate)
        {
            if (highWater.TryGetValue(replayKey, out var previous) &&
                (report.Epoch < previous.Epoch ||
                 (report.Epoch == previous.Epoch && report.Sequence <= previous.Sequence)))
                return false;

            var next = new ReplayPoint(report.Epoch, report.Sequence);
            var old = highWater.GetValueOrDefault(replayKey);
            highWater[replayKey] = next;
            try { PersistReplayState(); }
            catch
            {
                if (old is null) highWater.Remove(replayKey);
                else highWater[replayKey] = old;
                throw;
            }
            live[LiveKey(targetKey, report.AgentId)] = new LiveReport(
                report.Verdict, checked(nowTick + remainingSeconds * 1000));
        }
        return true;
    }

    public bool IsAuthorizedCertificate(X509Certificate2? certificate, string agentId,
        IReadOnlySet<string>? revokedSha256 = null)
    {
        return string.Equals(AgentIdForCertificate(certificate, revokedSha256), agentId,
            StringComparison.Ordinal);
    }

    public string? AgentIdForCertificate(X509Certificate2? certificate,
        IReadOnlySet<string>? revokedSha256 = null)
    {
        if (certificate is null ||
            certificate.NotBefore.ToUniversalTime() > DateTime.UtcNow ||
            certificate.NotAfter.ToUniversalTime() <= DateTime.UtcNow)
            return null;
        var eku = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>()
            .Any(extension => extension.EnhancedKeyUsages.Cast<Oid>()
                .Any(oid => oid.Value == "1.3.6.1.5.5.7.3.2"));
        if (!eku) return null;
        var hash = certificate.GetCertHash(HashAlgorithmName.SHA256);
        var hexHash = Convert.ToHexString(hash);
        if (revokedSha256?.Contains(hexHash) == true) return null;
        foreach (var agent in agents)
            if (agent.Value.CertificateSha256.Any(pin => CryptographicOperations.FixedTimeEquals(hash, pin)))
                return agent.Key;
        return null;
    }

    public bool TryReserveRequest(string agentId, long nowTick, int perMinuteLimit)
    {
        if (perMinuteLimit is < 1 or > 10000 || !agents.ContainsKey(agentId)) return false;
        lock (gate)
        {
            if (!rates.TryGetValue(agentId, out var rate) || nowTick < rate.WindowStart ||
                nowTick - rate.WindowStart >= 60_000)
                rate = (nowTick, 0);
            if (rate.Count >= perMinuteLimit) return false;
            rates[agentId] = (rate.WindowStart, rate.Count + 1);
            return true;
        }
    }

    public bool IsHealthy(string zone, string siteId, long nowTick)
    {
        var targetKey = TargetKey(zone, siteId);
        if (!targets.TryGetValue(targetKey, out var policy)) return true;
        lock (gate)
        {
            var positiveVantages = new HashSet<string>(StringComparer.Ordinal);
            foreach (var agentId in policy.AgentIds)
            {
                if (!live.TryGetValue(LiveKey(targetKey, agentId), out var report) ||
                    nowTick >= report.ExpiresAtTick) continue;
                if (report.Verdict == "unhealthy") return false;
                if (report.Verdict == "healthy") positiveVantages.Add(agents[agentId].VantageGroup);
            }
            return positiveVantages.Count >= policy.MinimumHealthyVantageGroups;
        }
    }

    public (int Healthy, int Unhealthy, int Unknown, int StaleOrMissing) EvidenceCounts(long nowTick)
    {
        lock (gate)
        {
            var healthy = 0;
            var unhealthy = 0;
            var unknown = 0;
            var staleOrMissing = 0;
            foreach (var target in targets)
            foreach (var agentId in target.Value.AgentIds)
            {
                if (!live.TryGetValue(LiveKey(target.Key, agentId), out var report) ||
                    nowTick >= report.ExpiresAtTick)
                {
                    staleOrMissing++;
                    continue;
                }
                switch (report.Verdict)
                {
                    case "healthy": healthy++; break;
                    case "unhealthy": unhealthy++; break;
                    case "unknown": unknown++; break;
                    default: throw new InvalidDataException("Unexpected stored agent report verdict");
                }
            }
            return (healthy, unhealthy, unknown, staleOrMissing);
        }
    }

    private Dictionary<string, ReplayPoint> LoadReplayState(string path)
    {
        if (!File.Exists(path)) return new Dictionary<string, ReplayPoint>(StringComparer.Ordinal);
        EnsurePrivateFile(path);
        var maximumBytes = Math.Max(4096, targets.Values.Sum(policy => policy.AgentIds.Length) * 512);
        if (new FileInfo(path).Length > maximumBytes)
            throw new InvalidDataException("Replay state exceeds configured storage bound");
        var file = JsonSerializer.Deserialize<ReplayFile>(File.ReadAllBytes(path))
            ?? throw new InvalidDataException("Malformed agent replay state");
        if (file.Version != 1 || file.Points is null || file.Points.Any(p =>
            string.IsNullOrWhiteSpace(p.Key) || p.Value is null || p.Value.Epoch <= 0 || p.Value.Sequence <= 0))
            throw new InvalidDataException("Invalid agent replay state");
        return new Dictionary<string, ReplayPoint>(file.Points, StringComparer.Ordinal);
    }

    private void PersistReplayState()
    {
        var temporary = statePath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            var bytes = JsonSerializer.SerializeToUtf8Bytes(new ReplayFile(1,
                new Dictionary<string, ReplayPoint>(highWater, StringComparer.Ordinal)));
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write,
                FileShare.None, 4096, FileOptions.WriteThrough))
            {
                if (!OperatingSystem.IsWindows())
                    File.SetUnixFileMode(temporary, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                stream.Write(bytes);
                stream.Flush(flushToDisk: true);
            }
            File.Move(temporary, statePath, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }

    private static string TargetKey(string zone, string siteId) =>
        zone.TrimEnd('.').ToLowerInvariant() + "\n" + siteId;
    private static string ReplayKey(string agentId, string zone, string siteId) =>
        agentId + "\n" + TargetKey(zone, siteId);
    private static string LiveKey(string targetKey, string agentId) => targetKey + "\n" + agentId;

    private static FileStream AcquireStateLock(string path)
    {
        var parent = Path.GetDirectoryName(path)!;
        var existed = Directory.Exists(parent);
        Directory.CreateDirectory(parent);
        if (!OperatingSystem.IsWindows())
        {
            if (!existed) File.SetUnixFileMode(parent, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            else if ((File.GetUnixFileMode(parent) & (UnixFileMode.GroupRead | UnixFileMode.GroupWrite |
                    UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherWrite |
                    UnixFileMode.OtherExecute)) != 0)
                throw new InvalidDataException("Replay state directory must be private to the DNS service account");
        }
        var lockPath = path + ".lock";
        EnsureNotLink(lockPath);
        EnsureNotLink(path);
        var stream = new FileStream(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(lockPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        return stream;
    }

    private static void EnsurePrivateFile(string path)
    {
        EnsureNotLink(path);
        if (!OperatingSystem.IsWindows() &&
            (File.GetUnixFileMode(path) & (UnixFileMode.GroupRead | UnixFileMode.GroupWrite |
             UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherWrite |
             UnixFileMode.OtherExecute)) != 0)
            throw new InvalidDataException("Replay state file must be private to the DNS service account");
    }

    private static void EnsureNotLink(string path)
    {
        var info = new FileInfo(path);
        if (info.LinkTarget is not null || (info.Exists &&
            (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0))
            throw new InvalidDataException("Replay state paths cannot be symbolic links or reparse points");
    }

    public void Dispose()
    {
        foreach (var entry in agents.Values) entry.Dispose();
        stateLock?.Dispose();
    }

    private sealed class AgentTrustEntry(string vantageGroup, byte[][] certificateSha256,
        Dictionary<string, byte[]> signingPublicKeys) : IDisposable
    {
        public string VantageGroup { get; } = vantageGroup;
        public byte[][] CertificateSha256 { get; } = certificateSha256;
        public Dictionary<string, byte[]> SigningPublicKeys { get; } = signingPublicKeys;
        public void Dispose()
        {
            foreach (var pin in CertificateSha256) CryptographicOperations.ZeroMemory(pin);
            foreach (var key in SigningPublicKeys.Values) CryptographicOperations.ZeroMemory(key);
        }
    }
}
