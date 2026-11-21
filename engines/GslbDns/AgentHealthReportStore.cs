using System.Net.Security;
using System.Security.Cryptography;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.Versioning;
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
    private sealed record LastAccepted(long UnixSeconds, long Tick);
    private sealed record ReportPolicy(string[] AgentIds, int MinimumHealthyVantageGroups);

    private readonly object gate = new();
    private readonly Dictionary<string, AgentTrustEntry> agents;
    private readonly Dictionary<string, ReportPolicy> targets;
    private readonly Dictionary<string, ReplayPoint> highWater;
    private FileStream? stateLock;
    private bool stateFaulted;
    // Digest of the last successfully loaded or atomically persisted replay
    // state. Detect an unexpected replacement, including valid old JSON.
    // Not a cryptographic attestation against a privileged host compromise.
    private byte[]? persistedStateHash;
    private long? lastStateCheckTick;
    private const long StateCheckIntervalMs = 1000;
    private readonly Dictionary<string, LiveReport> live = new(StringComparer.Ordinal);
    private readonly Dictionary<string, LastAccepted> lastAccepted = new(StringComparer.Ordinal);
    private readonly Dictionary<string, int> rejectedByAgent = new(StringComparer.Ordinal);
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
        var usedSigningKeys = new HashSet<string>(StringComparer.Ordinal);
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
                    var keyId = AgentHealthReportContract.KeyId(key);
                    if (!publicKeys.TryAdd(keyId, encodedKey))
                        throw new InvalidDataException("Duplicate agent report signing key");
                    // Distinct identities/vantage groups must not share a signing
                    // credential, including overlapping rotation windows.
                    if (!usedSigningKeys.Add(keyId))
                        throw new InvalidDataException("Agent report signing keys must identify exactly one agent");
                }
                if (!agents.TryAdd(item.AgentId, new AgentTrustEntry(item.VantageGroup, certPins, publicKeys)))
                    throw new InvalidDataException("Duplicate agent identity");
                rejectedByAgent.Add(item.AgentId, 0);
            }

            var targetRows = configuredTargets?.ToArray() ?? throw new InvalidDataException("Agent report targets required");
            if (targetRows.Length is < 1 or > 1024)
                throw new InvalidDataException("Agent report targets must contain 1..1024 zone/site pairs");
            // DNS zone names are canonicalized by TargetKey, but opaque site
            // IDs are case-sensitive in the signed payload and replay keys.
            targets = new Dictionary<string, ReportPolicy>(StringComparer.Ordinal);
            var uniqueTargets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var target in targetRows)
            {
                if (target is null || !AgentHealthReportContract.IsValidZone(target.Zone) ||
                    !AgentHealthReportContract.IsValidIdentifier(target.SiteId) ||
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
                var targetKey = TargetKey(target.Zone, target.SiteId);
                // Preserve rejection of ambiguous case-only configuration duplicates.
                if (!uniqueTargets.Add(targetKey) || !targets.TryAdd(targetKey, new ReportPolicy(
                    target.RequiredAgentIds.ToArray(), target.MinimumHealthyVantageGroups)))
                    throw new InvalidDataException("Duplicate report-gated zone/site");
            }
            stateLock = AcquireStateLock(statePath, out var newLock);
            var stateExists = File.Exists(statePath);
            if (!stateExists && !newLock)
                throw new InvalidDataException("Agent replay state is missing while its durable lock exists");
            highWater = LoadReplayState(statePath);
            var maximumPoints = targets.Values.Sum(policy => policy.AgentIds.Length);
            var allowedPoints = targets.SelectMany(target => target.Value.AgentIds.Select(agentId =>
                ReplayKey(agentId, target.Key.Split('\n')[0], target.Key.Split('\n')[1])))
                .ToHashSet(StringComparer.Ordinal);
            if (highWater.Count > maximumPoints || highWater.Keys.Any(key => !allowedPoints.Contains(key)))
                throw new InvalidDataException("Replay state exceeds configured report targets");
            // Establish an empty durable state on first enrollment, even if
            // no reports arrive before a clean shutdown.
            if (!stateExists) PersistReplayState();
        }
        catch
        {
            foreach (var entry in agents.Values) entry.Dispose();
            stateLock?.Dispose();
            throw;
        }
    }

    // These are the exact public identities used by the verifier, not a
    // second read of externally mutable PEM paths. Return fresh arrays.
    internal sealed record LoadedTrustIdentity(string AgentId, string VantageGroup,
        string[] CertificatePins, string[] SigningKeys);

    internal LoadedTrustIdentity[] GetLoadedTrustIdentity() =>
        agents.OrderBy(row => row.Key, StringComparer.Ordinal)
            .Select(row => new LoadedTrustIdentity(row.Key, row.Value.VantageGroup,
                row.Value.CertificateSha256.Select(Convert.ToHexString).Order(StringComparer.Ordinal).ToArray(),
                row.Value.SigningPublicKeys.Keys.Order(StringComparer.Ordinal).ToArray()))
            .ToArray();

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
        // Admission age is also a live-evidence freshness bound. A delayed
        // observation must not remain eligible until a longer advertised TTL.
        var remainingSeconds = Math.Min(
            Math.Min(report.ExpiresAtUnixSeconds - nowSeconds, maxTtlSeconds),
            Math.Min(report.ObservedAtUnixSeconds + maxAgeSeconds - nowSeconds, maxAgeSeconds));
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
            // Never recreate lost replay state from an incoming report. A
            // detected integrity failure is sticky until operator recovery.
            if (!ReplayStateAvailable(nowTick, force: true)) return false;
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
                stateFaulted = true;
                live.Clear();
                throw;
            }
            live[LiveKey(targetKey, report.AgentId)] = new LiveReport(
                report.Verdict, checked(nowTick + remainingSeconds * 1000));
            lastAccepted[report.AgentId] = new LastAccepted(now.ToUnixTimeSeconds(), nowTick);
        }
        return true;
    }

    // Called only under gate. Bound filesystem checks on the DNS read path;
    // authenticated writes still check immediately. A missing/unreadable
    // path is a sticky fault; restoration alone cannot re-enable evidence.
    private bool ReplayStateAvailable(long nowTick, bool force = false)
    {
        if (stateFaulted) return false;
        if (!force && lastStateCheckTick is { } last && nowTick >= last &&
            (ulong)nowTick - (ulong)last < StateCheckIntervalMs)
            return true;
        lastStateCheckTick = nowTick;
        try
        {
            EnsurePrivateFile(statePath); // Windows ACL and Linux mode.
            // Open and hash the same bounded, no-follow validated file handle.
            // No payload-sized allocations on the DNS eligibility read path.
            var actualHash = PrivateKeyFileSecurity.HashPrivateFileSha256(
                statePath, "GSLB observer replay state", MaximumReplayStateBytes());
            if (persistedStateHash is null ||
                !CryptographicOperations.FixedTimeEquals(actualHash, persistedStateHash))
                throw new InvalidDataException("Replay state changed outside accepted report persistence");
            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or
                                          InvalidDataException or CryptographicException)
        {
            // Never let a valid-looking rollback preserve previously admitted
            // healthy votes. Restoration is deliberately not self-healing.
            stateFaulted = true;
            live.Clear();
            return false;
        }
    }

    public void RecordRejectedReport(string agentId)
    {
        lock (gate)
            if (rejectedByAgent.TryGetValue(agentId, out var count))
                rejectedByAgent[agentId] = SaturatingIncrement(count);
    }

    public IReadOnlyList<AgentReportStatusSnapshot> AgentStatus(long nowTick)
    {
        lock (gate)
        {
            _ = ReplayStateAvailable(nowTick);
            return agents.Keys.Order(StringComparer.Ordinal).Select(agentId =>
            {
                var configured = targets.Count(target =>
                    target.Value.AgentIds.Contains(agentId, StringComparer.Ordinal));
                var fresh = 0;
                foreach (var target in targets)
                {
                    if (!target.Value.AgentIds.Contains(agentId, StringComparer.Ordinal)) continue;
                    if (live.TryGetValue(LiveKey(target.Key, agentId), out var report) &&
                        nowTick < report.ExpiresAtTick)
                        fresh++;
                }
                var staleOrMissing = configured - fresh;
                var last = lastAccepted.GetValueOrDefault(agentId);
                long? ageSeconds = last is null ? null : Math.Max(0, nowTick - last.Tick) / 1000;
                DateTimeOffset? acceptedUtc = last is null
                    ? null : DateTimeOffset.FromUnixTimeSeconds(last.UnixSeconds);
                return new AgentReportStatusSnapshot(agentId, acceptedUtc, ageSeconds,
                    rejectedByAgent[agentId], fresh, staleOrMissing);
            }).ToArray();
        }
    }

    private static int SaturatingIncrement(int value) => value == int.MaxValue ? value : value + 1;

    public bool IsAuthorizedCertificate(X509Certificate2? certificate, string agentId,
        IReadOnlySet<string>? revokedSha256 = null)
    {
        return string.Equals(AgentIdForCertificate(certificate, revokedSha256), agentId,
            StringComparison.Ordinal);
    }

    /// <summary>
    /// A pinned observer transport certificate must itself be a client-auth
    /// signing *leaf*, not a pinned CA, server-only certificate or a leaf whose
    /// permitted key usage cannot perform the TLS client signature.
    /// </summary>
    internal static bool IsValidClientAuthenticationCertificate(X509Certificate2? certificate)
    {
        if (certificate is null ||
            certificate.NotBefore.ToUniversalTime() > DateTime.UtcNow ||
            certificate.NotAfter.ToUniversalTime() <= DateTime.UtcNow)
            return false;
        var basicConstraints = certificate.Extensions.OfType<X509BasicConstraintsExtension>().ToArray();
        var usages = certificate.Extensions.OfType<X509KeyUsageExtension>().ToArray();
        var ekus = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().ToArray();
        return basicConstraints.Length == 1 && !basicConstraints[0].CertificateAuthority &&
            usages.Length == 1 &&
            (usages[0].KeyUsages & X509KeyUsageFlags.DigitalSignature) != 0 &&
            ekus.Length == 1 &&
            ekus[0].EnhancedKeyUsages.Cast<Oid>()
                .Any(oid => oid.Value == "1.3.6.1.5.5.7.3.2");
    }

    public string? AgentIdForCertificate(X509Certificate2? certificate,
        IReadOnlySet<string>? revokedSha256 = null)
    {
        if (!IsValidClientAuthenticationCertificate(certificate)) return null;
        var hash = certificate!.GetCertHash(HashAlgorithmName.SHA256);
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
        // Callers explicitly bypass this store for sites without report policy.
        // Missing policy for a report-gated target must fail closed.
        if (!targets.TryGetValue(targetKey, out var policy)) return false;
        lock (gate)
        {
            if (!ReplayStateAvailable(nowTick)) return false;
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
            _ = ReplayStateAvailable(nowTick);
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

    private int MaximumReplayStateBytes() =>
        Math.Max(4096, targets.Values.Sum(policy => policy.AgentIds.Length) * 512);

    private Dictionary<string, ReplayPoint> LoadReplayState(string path)
    {
        if (!File.Exists(path)) return new Dictionary<string, ReplayPoint>(StringComparer.Ordinal);
        EnsurePrivateFile(path); // Preserve Windows ACL policy.
        var bytes = PrivateKeyFileSecurity.ReadPrivateFileBytes(
            path, "GSLB observer replay state", MaximumReplayStateBytes());
        try
        {
            if (!StrictJsonPropertyNames.HasNoDuplicates(bytes))
                throw new InvalidDataException("Replay state contains invalid or ambiguous JSON");
            var file = JsonSerializer.Deserialize<ReplayFile>(bytes)
                ?? throw new InvalidDataException("Malformed agent replay state");
            if (file.Version != 1 || file.Points is null || file.Points.Any(p =>
                string.IsNullOrWhiteSpace(p.Key) || p.Value is null || p.Value.Epoch <= 0 || p.Value.Sequence <= 0))
                throw new InvalidDataException("Invalid agent replay state");
            persistedStateHash = SHA256.HashData(bytes);
            return new Dictionary<string, ReplayPoint>(file.Points, StringComparer.Ordinal);
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    private void PersistReplayState()
    {
        var temporary = statePath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        var bytes = JsonSerializer.SerializeToUtf8Bytes(new ReplayFile(1,
            new Dictionary<string, ReplayPoint>(highWater, StringComparer.Ordinal)));
        try
        {
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write,
                FileShare.None, 4096, FileOptions.WriteThrough))
            {
                if (!OperatingSystem.IsWindows())
                    File.SetUnixFileMode(temporary, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                else
                    EnsurePrivateWindowsAcl(temporary, isDirectory: false);
                stream.Write(bytes);
                stream.Flush(flushToDisk: true);
            }
            File.Move(temporary, statePath, overwrite: true);
            persistedStateHash = SHA256.HashData(bytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }

    private static string TargetKey(string zone, string siteId) =>
        zone.TrimEnd('.').ToLowerInvariant() + "\n" + siteId;
    private static string ReplayKey(string agentId, string zone, string siteId) =>
        agentId + "\n" + TargetKey(zone, siteId);
    private static string LiveKey(string targetKey, string agentId) => targetKey + "\n" + agentId;

    private static FileStream AcquireStateLock(string path, out bool newLock)
    {
        var parent = Path.GetDirectoryName(path)!;
        if (OperatingSystem.IsLinux())
            PrivateKeyFileSecurity.EnsureLinuxPrivateStateDirectory(
                parent, "GSLB observer replay state");
        else if (OperatingSystem.IsWindows())
        {
            Directory.CreateDirectory(parent);
            EnsurePrivateWindowsAcl(parent, isDirectory: true);
        }
        else throw new PlatformNotSupportedException("Observer replay state supports Windows and Linux only");
        var lockPath = path + ".lock";
        EnsureNotLink(lockPath);
        EnsureNotLink(path);
        FileStream stream;
        try
        {
            stream = new FileStream(lockPath, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None);
            newLock = true;
        }
        catch (IOException) when (File.Exists(lockPath))
        {
            stream = new FileStream(lockPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
            newLock = false;
        }
        try
        {
            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(lockPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            else EnsurePrivateWindowsAcl(lockPath, isDirectory: false);
            return stream;
        }
        catch
        {
            stream.Dispose();
            throw;
        }
    }

    private static void EnsurePrivateFile(string path)
    {
        EnsureNotLink(path);
        if (!OperatingSystem.IsWindows() &&
            (File.GetUnixFileMode(path) & (UnixFileMode.GroupRead | UnixFileMode.GroupWrite |
             UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherWrite |
             UnixFileMode.OtherExecute)) != 0)
            throw new InvalidDataException("Replay state file must be private to the DNS service account");
        else if (OperatingSystem.IsWindows()) EnsurePrivateWindowsAcl(path, isDirectory: false);
    }

    [SupportedOSPlatform("windows")]
    private static void EnsurePrivateWindowsAcl(string path, bool isDirectory)
    {
        if (!OperatingSystem.IsWindows()) return;
        using var identity = WindowsIdentity.GetCurrent();
        var allowed = AllowedWindowsPrincipals(identity);

        FileSystemSecurity security = isDirectory
            ? new DirectoryInfo(path).GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner)
            : new FileInfo(path).GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner);
        var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        if (!IsAllowedWindowsOwner(owner, allowed))
            throw new InvalidDataException("Replay state owner must be the DNS service identity, SYSTEM, Administrators or its service SID");
        var rules = security.GetAccessRules(includeExplicit: true, includeInherited: true,
            targetType: typeof(SecurityIdentifier));
        foreach (FileSystemAccessRule rule in rules)
        {
            if (rule.AccessControlType == AccessControlType.Allow &&
                rule.FileSystemRights != 0 &&
                rule.IdentityReference is SecurityIdentifier sid && !allowed.Contains(sid.Value))
                throw new InvalidDataException("Replay state ACL grants access beyond the DNS service identity, SYSTEM and Administrators");
        }
    }

    [SupportedOSPlatform("windows")]
    internal static HashSet<string> AllowedWindowsPrincipals(WindowsIdentity identity)
    {
        var currentUser = identity.User
            ?? throw new InvalidDataException("Cannot determine DNS service identity for replay state ACL validation");
        var allowed = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            currentUser.Value,
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null).Value,
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null).Value
        };
        var groups = identity.Groups?.Cast<IdentityReference>().OfType<SecurityIdentifier>() ?? [];
        AddTrustedServiceSids(allowed, groups);
        return allowed;
    }

    [SupportedOSPlatform("windows")]
    internal static void AddTrustedServiceSids(ISet<string> allowed,
        IEnumerable<SecurityIdentifier> tokenGroups)
    {
        foreach (var sid in tokenGroups)
            if (IsWindowsServiceSid(sid))
                allowed.Add(sid.Value);
    }

    [SupportedOSPlatform("windows")]
    internal static bool IsAllowedWindowsOwner(SecurityIdentifier? owner, IReadOnlySet<string> allowed) =>
        owner is not null && allowed.Contains(owner.Value);

    [SupportedOSPlatform("windows")]
    internal static bool IsWindowsServiceSid(SecurityIdentifier sid) =>
        sid.Value.StartsWith("S-1-5-80-", StringComparison.OrdinalIgnoreCase);

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

internal sealed record AgentReportStatusSnapshot(string AgentId, DateTimeOffset? LastAcceptedUtc,
    long? LastAcceptedAgeSeconds, int RejectedTotal, int FreshReports, int StaleOrMissingReports);
