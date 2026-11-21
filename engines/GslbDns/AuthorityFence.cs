using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Runtime.Versioning;
using System.Text.Json;
using GatewayCore.Gslb.Contracts;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Https;

internal sealed record AuthorityFencePeerConfig(string NodeId, string Endpoint,
    string[] ServerCertificateSha256, string[] ClientCertificateSha256,
    string SigningPublicKeyPem, string AllowedAddress, int AllowedPort);

internal sealed record AuthorityFenceConfig(string NodeId, string ListenAddress, int ListenPort,
    bool AllowNonLoopbackListener, string ServerCertificatePem, string ServerKeyPem,
    string ClientCertificatePem, string ClientKeyPem, string SigningPrivateKeyPem,
    string EpochStatePath, string ReplayStatePath, int LeaseSeconds, int PublishIntervalSeconds,
    AuthorityFencePeerConfig Peer);

internal sealed record AuthorityFenceTarget(string Zone, string SiteId, Func<long, bool> LocalEligible);

/// <summary>
/// Bounded, read-only state for an operator's private GSLB diagnostics channel.
/// Contains neither addresses, certificate trust pins, signing keys nor raw
/// health reports. Local backend readiness is still independently required
/// by DNS routing after this peer fence is satisfied.
/// </summary>
internal sealed record AuthorityFenceDiagnostics(
    int Version, string AuthorityId, string PeerAuthorityId,
    bool DurableStateTrusted, bool PeerSnapshotFresh, bool PeerAcknowledgementFresh,
    bool PeerFenceReady, int ConfiguredTargets, int EligiblePeerTargets,
    long LocalEpoch, long LastAcceptedPeerEpoch, long LastAcceptedPeerSequence,
    long PeerSnapshotRemainingMilliseconds, long PeerAcknowledgementRemainingMilliseconds);

/// <summary>
/// Opt-in strict two-authority lease fence. DNS admits a target only while its
/// local policy is eligible and the sole configured peer has acknowledged the
/// same configuration fingerprint and a fresh eligible decision.
/// </summary>
internal sealed class AuthorityFenceStore : IDisposable
{
    private sealed record PersistedReplay(int Version, long Epoch, long Sequence);
    private sealed record PersistedEpoch(int Version, long Epoch, bool ReplayInitialized);
    private static readonly byte[] ReplayLockMarker = System.Text.Encoding.ASCII.GetBytes(
        "GatewayCore.AuthorityFence.ReplayState.v1\n");
    private sealed record LiveSnapshot(Dictionary<string, bool> Decisions, long ExpiresAtTick);
    private readonly object gate = new();
    private readonly AuthorityFenceConfig config;
    private readonly string configFingerprint;
    private readonly AuthorityFenceTarget[] targets;
    private readonly HashSet<string> targetKeys;
    private readonly ECDsa localSigner;
    private readonly ECDsa peerVerifier;
    private readonly object verifierGate = new();
    private readonly FileStream epochLock;
    private readonly FileStream replayLock;
    private readonly long localEpoch;
    private readonly string epochStatePath;
    private readonly string replayStatePath;
    private long localSequence;
    private PersistedReplay replay;
    private LiveSnapshot? live;
    private long? outboundAcknowledgedUntilTick;
    private bool durableStateFaulted;
    private long? lastDurableCheckTick;
    private const long DurableCheckIntervalMs = 1000;

    public AuthorityFenceStore(AuthorityFenceConfig config, string configFingerprint,
        IEnumerable<AuthorityFenceTarget> targets)
    {
        ValidateConfig(config);
        this.config = config;
        this.configFingerprint = NormalizeFingerprint(configFingerprint);
        this.targets = targets.OrderBy(t => t.Zone, StringComparer.Ordinal)
            .ThenBy(t => t.SiteId, StringComparer.Ordinal).ToArray();
        if (this.targets.Length is < 1 or > AuthorityFenceContract.MaximumSites ||
            this.targets.Any(t => !AgentHealthReportContract.IsValidIdentifier(t.SiteId) ||
                !DnsWireProtocol.ValidName(t.Zone.TrimEnd('.')) || t.LocalEligible is null))
            throw new InvalidDataException("Authority fence requires 1..1024 uniquely identified zone sites");
        targetKeys = new HashSet<string>(StringComparer.Ordinal);
        foreach (var target in this.targets)
            if (!targetKeys.Add(TargetKey(target.Zone, target.SiteId)))
                throw new InvalidDataException("Authority fence target IDs must be unique per zone");
        var maximumSnapshot = new AuthorityFenceSnapshot(AuthorityFenceContract.CurrentVersion,
            config.NodeId, config.Peer.NodeId, this.configFingerprint, long.MaxValue, long.MaxValue,
            long.MaxValue, 30, this.targets.Select(target => new AuthorityFenceDecision(
                CanonicalZone(target.Zone), target.SiteId, true)).ToArray(), new string('A', 128));
        if (JsonSerializer.SerializeToUtf8Bytes(maximumSnapshot).Length >
            AuthorityFenceContract.MaximumSerializedBytes)
            throw new InvalidDataException("Configured authority fence targets exceed the signed 128 KiB snapshot bound");

        this.epochStatePath = config.EpochStatePath;
        this.replayStatePath = config.ReplayStatePath;
        epochLock = AcquirePrivateLock(epochStatePath, "authority epoch state");
        try
        {
            replayLock = AcquirePrivateLock(replayStatePath, "authority replay state");
        }
        catch { epochLock.Dispose(); throw; }
        try
        {
            if (!File.Exists(epochStatePath) && (File.Exists(replayStatePath) || replayLock.Length != 0))
                throw new InvalidDataException("Authority epoch state is missing while replay state exists");
            localEpoch = StartNewEpoch(epochStatePath);
            replay = InitializeReplayState(replayStatePath, replayLock, epochStatePath, localEpoch);
            localSigner = ECDsa.Create();
            localSigner.ImportFromPem(PrivateKeyFileSecurity.ReadPrivateKeyPem(
                config.SigningPrivateKeyPem, "Authority decision signing key"));
            if (localSigner.ExportParameters(false).Curve.Oid.Value != "1.2.840.10045.3.1.7")
                throw new InvalidDataException("Authority decision signing key must use P-256");
            peerVerifier = ECDsa.Create();
            peerVerifier.ImportFromPem(File.ReadAllText(config.Peer.SigningPublicKeyPem));
            if (peerVerifier.ExportParameters(false).Curve.Oid.Value != "1.2.840.10045.3.1.7")
                throw new InvalidDataException("Trusted authority decision key must use P-256");
        }
        catch
        {
            epochLock.Dispose();
            replayLock.Dispose();
            throw;
        }
    }

    public AuthorityFenceSnapshot CreateSnapshot(long nowTick)
    {
        lock (gate)
            if (!CheckDurableState(nowTick, force: true))
                throw new InvalidDataException("Authority durable state fault; operator recovery required");
        // Local evidence callbacks can perform I/O or take the agent-state
        // lock. Do not hold the authority gate while evaluating them.
        var decisions = targets.Select(target => new AuthorityFenceDecision(
            CanonicalZone(target.Zone), target.SiteId, target.LocalEligible(nowTick))).ToArray();
        lock (gate)
        {
            // A concurrent read or incoming report may have latched a fault
            // while decisions were computed. Never sign after that point.
            if (!CheckDurableState(nowTick, force: true))
                throw new InvalidDataException("Authority durable state fault before signing");
            if (localSequence == long.MaxValue)
                throw new InvalidDataException("Authority sequence exhausted; restart with a new epoch");
            var unsigned = new AuthorityFenceSnapshot(AuthorityFenceContract.CurrentVersion,
                config.NodeId, config.Peer.NodeId, configFingerprint, localEpoch, ++localSequence,
                DateTimeOffset.UtcNow.ToUnixTimeSeconds(), config.LeaseSeconds, decisions, string.Empty);
            return unsigned with { Signature = AuthorityFenceContract.Sign(unsigned, localSigner) };
        }
    }

    public bool IsPeerEligible(string zone, string siteId, long nowTick)
    {
        lock (gate)
        {
            return CheckDurableState(nowTick) &&
                outboundAcknowledgedUntilTick is long outboundDeadline && nowTick < outboundDeadline &&
                live is { } state && nowTick < state.ExpiresAtTick &&
                state.Decisions.TryGetValue(TargetKey(zone, siteId), out var eligible) && eligible;
        }
    }

    /// <summary>
    /// Snapshot evidence under the same durable-state and lease gates as
    /// DNS eligibility. Never evaluates probe callbacks or renews peer leases;
    /// inspection cannot grant authority during a partition or a restore fault.
    /// </summary>
    public AuthorityFenceDiagnostics Inspect(long nowTick)
    {
        lock (gate)
        {
            var durable = CheckDurableState(nowTick);
            var snapshotFresh = durable &&
                live is { } state && nowTick < state.ExpiresAtTick;
            var acknowledged = durable &&
                outboundAcknowledgedUntilTick is long until && nowTick < until;
            var ready = snapshotFresh && acknowledged;
            var peerTargets = ready && live is { } current
                ? current.Decisions.Values.Count(eligible => eligible)
                : 0;
            long Remaining(long? untilTick) => durable && untilTick is long deadline && deadline > nowTick
                ? Math.Min(config.LeaseSeconds * 1000L, deadline - nowTick)
                : 0;
            return new AuthorityFenceDiagnostics(
                1, config.NodeId, config.Peer.NodeId, durable, snapshotFresh,
                acknowledged, ready, targetKeys.Count, peerTargets,
                localEpoch, replay.Epoch, replay.Sequence,
                Remaining(live?.ExpiresAtTick),
                Remaining(outboundAcknowledgedUntilTick));
        }
    }

    // A successful response authenticates acceptance through pinned mTLS.
    // Anchor the local lease at send time, never at delayed response receipt.
    public void RecordPeerAcknowledgement(long sentAtTick, long receivedAtTick)
    {
        lock (gate)
        {
            if (!CheckDurableState(receivedAtTick, force: true)) return;
            var deadline = checked(sentAtTick + config.LeaseSeconds * 1000L);
            if (receivedAtTick >= sentAtTick && receivedAtTick < deadline)
                outboundAcknowledgedUntilTick = Math.Max(outboundAcknowledgedUntilTick ?? long.MinValue, deadline);
        }
    }

    public bool IsAllowedPeerAddress(IPAddress? remoteAddress)
    {
        if (remoteAddress is null) return false;
        if (remoteAddress.IsIPv4MappedToIPv6) remoteAddress = remoteAddress.MapToIPv4();
        return IPAddress.TryParse(config.Peer.AllowedAddress, out var allowedAddress) &&
            remoteAddress.Equals(allowedAddress);
    }

    public bool TryAccept(AuthorityFenceSnapshot? snapshot, X509Certificate2? clientCertificate,
        DateTimeOffset now, long nowTick)
    {
        if (snapshot is null || !IsPinnedCertificate(clientCertificate,
                config.Peer.ClientCertificateSha256, "1.3.6.1.5.5.7.3.2") ||
            snapshot.Version != AuthorityFenceContract.CurrentVersion ||
            snapshot.AuthorityId != config.Peer.NodeId || snapshot.PeerId != config.NodeId ||
            !FingerprintMatches(snapshot.ConfigurationSha256) ||
            snapshot.Epoch <= 0 || snapshot.Sequence <= 0 || snapshot.LeaseSeconds is < 1 or > 30 ||
            snapshot.LeaseSeconds > config.LeaseSeconds ||
            snapshot.IssuedAtUnixSeconds > now.ToUnixTimeSeconds() + 2 ||
            snapshot.IssuedAtUnixSeconds + snapshot.LeaseSeconds <= now.ToUnixTimeSeconds() ||
            snapshot.IssuedAtUnixSeconds < now.ToUnixTimeSeconds() - snapshot.LeaseSeconds ||
            snapshot.Decisions is null || snapshot.Decisions.Length != targetKeys.Count ||
            !VerifyPeerSignature(snapshot))
            return false;

        var decisions = new Dictionary<string, bool>(StringComparer.Ordinal);
        foreach (var decision in snapshot.Decisions)
        {
            if (decision is null || !AgentHealthReportContract.IsValidIdentifier(decision.SiteId) ||
                string.IsNullOrWhiteSpace(decision.Zone) ||
                !DnsWireProtocol.ValidName(decision.Zone.TrimEnd('.')) ||
                !targetKeys.Contains(TargetKey(decision.Zone, decision.SiteId)) ||
                !decisions.TryAdd(TargetKey(decision.Zone, decision.SiteId), decision.Eligible))
                return false;
        }
        if (decisions.Count != targetKeys.Count) return false;

        lock (gate)
        {
            if (!CheckDurableState(nowTick, force: true)) return false;
            if (snapshot.Epoch < replay.Epoch ||
                (snapshot.Epoch == replay.Epoch && snapshot.Sequence <= replay.Sequence))
                return false;
            var next = new PersistedReplay(1, snapshot.Epoch, snapshot.Sequence);
            try { PersistReplay(replayStatePath, next); }
            catch
            {
                LatchDurableStateFault();
                throw;
            }
            replay = next;
            var leaseSeconds = Math.Min(snapshot.LeaseSeconds,
                checked((int)Math.Max(0, snapshot.IssuedAtUnixSeconds + snapshot.LeaseSeconds -
                    now.ToUnixTimeSeconds())));
            live = new LiveSnapshot(decisions, checked(nowTick + leaseSeconds * 1000L));
            return true;
        }
    }

    private bool VerifyPeerSignature(AuthorityFenceSnapshot snapshot)
    {
        // The runtime permits concurrent HTTPS receivers. Do not assume the
        // shared platform ECDsa implementation supports concurrent use.
        lock (verifierGate)
            return AuthorityFenceContract.Verify(snapshot, peerVerifier);
    }

    internal bool CanPublish(long nowTick)
    {
        lock (gate) return CheckDurableState(nowTick, force: true);
    }

    // Only under gate. Verify the same durable replay/epoch contents as
    // authenticated writes. Bound disk reads on the DNS eligibility path.
    private bool CheckDurableState(long nowTick, bool force = false)
    {
        if (durableStateFaulted) return false;
        if (!force && lastDurableCheckTick is { } last && nowTick >= last &&
            (ulong)nowTick - (ulong)last < DurableCheckIntervalMs)
            return true;
        lastDurableCheckTick = nowTick;
        if (ReplayStateIntact(replayStatePath, replayLock, replay, epochStatePath, localEpoch))
            return true;
        LatchDurableStateFault();
        return false;
    }

    private void LatchDurableStateFault()
    {
        durableStateFaulted = true;
        live = null;
        outboundAcknowledgedUntilTick = null;
    }

    public static bool IsPinnedCertificate(X509Certificate2? certificate,
        IReadOnlyCollection<string> pins, string requiredEku)
    {
        if (certificate is null || certificate.NotBefore.ToUniversalTime() > DateTime.UtcNow ||
            certificate.NotAfter.ToUniversalTime() <= DateTime.UtcNow ||
            !certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().Any(extension =>
                extension.EnhancedKeyUsages.Cast<Oid>().Any(oid => oid.Value == requiredEku)))
            return false;
        var hash = certificate.GetCertHash(HashAlgorithmName.SHA256);
        foreach (var pin in pins)
        {
            byte[] bytes;
            try { bytes = Convert.FromHexString(pin); }
            catch (FormatException) { continue; }
            if (bytes.Length == hash.Length && CryptographicOperations.FixedTimeEquals(hash, bytes)) return true;
        }
        return false;
    }

    private static void ValidateConfig(AuthorityFenceConfig config)
    {
        if (config is null || config.Peer is null)
            throw new InvalidDataException("Authority fence config and peer membership are required");
        static bool ValidId(string? value) => !string.IsNullOrEmpty(value) && value.Length <= 48 &&
            value.All(ch => char.IsAsciiLetterOrDigit(ch) || ch is '-' or '_');
        static void ValidatePins(string[]? pins, string name)
        {
            if (pins is not { Length: >= 1 and <= 4 } || pins.Any(pin =>
                string.IsNullOrWhiteSpace(pin) || !TrySha256Pin(pin)))
                throw new InvalidDataException($"Authority fence {name} must contain 1..4 unique SHA-256 pins");
            if (pins.Select(pin => pin.ToUpperInvariant()).Distinct(StringComparer.Ordinal).Count() != pins.Length)
                throw new InvalidDataException($"Authority fence {name} contains duplicate pins");
        }
        if (!ValidId(config.NodeId) || !ValidId(config.Peer.NodeId) || config.NodeId == config.Peer.NodeId ||
            !Uri.TryCreate(config.Peer.Endpoint, UriKind.Absolute, out var endpoint) ||
            endpoint.Scheme != Uri.UriSchemeHttps || !string.IsNullOrEmpty(endpoint.UserInfo) ||
            endpoint.AbsolutePath != "/authority-fence/v1/snapshot" ||
            !string.IsNullOrEmpty(endpoint.Query) || !string.IsNullOrEmpty(endpoint.Fragment) ||
            !IPAddress.TryParse(config.Peer.AllowedAddress, out var peerAddress) ||
            peerAddress.IsIPv4MappedToIPv6 ||
            peerAddress.AddressFamily is not (System.Net.Sockets.AddressFamily.InterNetwork or System.Net.Sockets.AddressFamily.InterNetworkV6) ||
            endpoint.HostNameType is not (UriHostNameType.IPv4 or UriHostNameType.IPv6) ||
            !IPAddress.TryParse(endpoint.IdnHost, out var endpointAddress) ||
            !endpointAddress.Equals(peerAddress) || endpoint.Port != config.Peer.AllowedPort ||
            config.Peer.AllowedPort is < 1025 or > 65535 ||
            !IPAddress.TryParse(config.ListenAddress, out var address) ||
            address.AddressFamily is not (System.Net.Sockets.AddressFamily.InterNetwork or System.Net.Sockets.AddressFamily.InterNetworkV6) ||
            address.IsIPv4MappedToIPv6 ||
            (!IPAddress.IsLoopback(address) && !config.AllowNonLoopbackListener) ||
            (IPAddress.IsLoopback(address) && config.AllowNonLoopbackListener) ||
            config.ListenPort is < 1025 or > 65535 || config.LeaseSeconds is < 2 or > 30 ||
            config.PublishIntervalSeconds is < 1 or > 10 || config.PublishIntervalSeconds * 2 >= config.LeaseSeconds ||
            !Path.IsPathFullyQualified(config.ServerCertificatePem) || !Path.IsPathFullyQualified(config.ServerKeyPem) ||
            !Path.IsPathFullyQualified(config.ClientCertificatePem) || !Path.IsPathFullyQualified(config.ClientKeyPem) ||
            !Path.IsPathFullyQualified(config.SigningPrivateKeyPem) ||
            !Path.IsPathFullyQualified(config.EpochStatePath) || !Path.IsPathFullyQualified(config.ReplayStatePath) ||
            config.EpochStatePath.Equals(config.ReplayStatePath, StringComparison.OrdinalIgnoreCase) ||
            !Path.IsPathFullyQualified(config.Peer.SigningPublicKeyPem))
            throw new InvalidDataException("Invalid bounded two-authority fence configuration");
        ValidatePins(config.Peer.ServerCertificateSha256, "server certificate trust");
        ValidatePins(config.Peer.ClientCertificateSha256, "client certificate trust");
    }

    private static bool TrySha256Pin(string pin)
    {
        try { return Convert.FromHexString(pin).Length == 32; }
        catch (FormatException) { return false; }
    }

    private static string NormalizeFingerprint(string value)
    {
        if (value.Length != 64 || !TrySha256Pin(value))
            throw new InvalidDataException("Authority configuration fingerprint must be SHA-256 hex");
        return value.ToUpperInvariant();
    }

    private bool FingerprintMatches(string? fingerprint)
    {
        if (fingerprint is null || fingerprint.Length != 64) return false;
        try
        {
            return CryptographicOperations.FixedTimeEquals(Convert.FromHexString(fingerprint),
                Convert.FromHexString(configFingerprint));
        }
        catch (FormatException) { return false; }
    }

    private static string CanonicalZone(string zone) => zone.TrimEnd('.').ToLowerInvariant();
    private static string TargetKey(string zone, string siteId) => CanonicalZone(zone) + "\n" + siteId;

    private static FileStream AcquirePrivateLock(string statePath, string purpose)
    {
        var parent = Path.GetDirectoryName(statePath)
            ?? throw new InvalidDataException($"{purpose} needs a parent directory");
        var existed = Directory.Exists(parent);
        Directory.CreateDirectory(parent);
        if (!OperatingSystem.IsWindows() && !existed)
            File.SetUnixFileMode(parent, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        PrivateKeyFileSecurity.ValidateLinuxPrivateStateDirectory(parent, purpose);
        if (OperatingSystem.IsWindows()) EnsurePrivateWindowsAcl(parent, isDirectory: true);
        var lockPath = statePath + ".lock";
        EnsureNotLink(statePath, purpose);
        EnsureNotLink(lockPath, purpose);
        PrivateKeyFileSecurity.ValidateLinuxPrivateStateFile(statePath, purpose);
        PrivateKeyFileSecurity.ValidateLinuxPrivateStateFile(lockPath, purpose);
        var stream = new FileStream(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        try
        {
            if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(lockPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            else EnsurePrivateWindowsAcl(lockPath, isDirectory: false);
            return stream;
        }
        catch { stream.Dispose(); throw; }
    }

    private static long StartNewEpoch(string path)
    {
        var previous = ReadEpoch(path);
        if (previous.Epoch == long.MaxValue) throw new InvalidDataException("Authority epoch exhausted");
        var next = previous.Epoch + 1;
        WriteState(path, JsonSerializer.SerializeToUtf8Bytes(previous with { Epoch = next }));
        return next;
    }

    private static PersistedEpoch ReadEpoch(string path)
    {
        if (!File.Exists(path)) return new PersistedEpoch(1, 0, false);
        var bytes = ReadStrictState(path, "authority epoch state");
        PersistedEpoch? state;
        try { state = JsonSerializer.Deserialize<PersistedEpoch>(bytes); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
        if (state is null || state.Version != 1 || state.Epoch < 0)
            throw new InvalidDataException("Invalid authority epoch state");
        return state;
    }

    private static PersistedReplay InitializeReplayState(string path, FileStream marker,
        string epochPath, long currentEpoch)
    {
        var epoch = ReadEpoch(epochPath);
        if (epoch.Epoch != currentEpoch)
            throw new InvalidDataException("Authority epoch changed during replay initialization");
        marker.Position = 0;
        if (marker.Length > ReplayLockMarker.Length)
            throw new InvalidDataException("Invalid authority replay-state lock marker");
        var markerBytes = new byte[checked((int)marker.Length)];
        _ = marker.Read(markerBytes, 0, markerBytes.Length);
        if (markerBytes.Length != 0 && !markerBytes.AsSpan().SequenceEqual(ReplayLockMarker))
            throw new InvalidDataException("Invalid authority replay-state lock marker");
        var hasMarker = markerBytes.Length != 0;
        if (epoch.ReplayInitialized && (!hasMarker || !File.Exists(path)))
            throw new InvalidDataException("Authority replay high-water state or marker is missing; refusing unsafe reinitialization");
        if (!File.Exists(path))
        {
            if (hasMarker)
                throw new InvalidDataException("Authority replay high-water state is missing; refusing unsafe reinitialization");
            WriteState(path, JsonSerializer.SerializeToUtf8Bytes(new PersistedReplay(1, 0, 0)));
        }
        var replay = ReadReplay(path);
        if (!hasMarker)
        {
            marker.Position = 0;
            marker.SetLength(0);
            marker.Write(ReplayLockMarker);
            marker.Flush(flushToDisk: true);
        }
        if (!epoch.ReplayInitialized)
            WriteState(epochPath, JsonSerializer.SerializeToUtf8Bytes(epoch with { ReplayInitialized = true }));
        return replay;
    }

    private static bool ReplayStateIntact(string path, FileStream marker, PersistedReplay expected,
        string epochPath, long currentEpoch)
    {
        try
        {
            marker.Position = 0;
            if (marker.Length != ReplayLockMarker.Length) return false;
            var markerBytes = new byte[ReplayLockMarker.Length];
            if (marker.Read(markerBytes, 0, markerBytes.Length) != markerBytes.Length ||
                !markerBytes.AsSpan().SequenceEqual(ReplayLockMarker) || !File.Exists(path)) return false;
            var epoch = ReadEpoch(epochPath);
            if (epoch.Epoch != currentEpoch || !epoch.ReplayInitialized) return false;
            var persisted = ReadReplay(path);
            return persisted == expected;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or InvalidDataException)
        {
            return false;
        }
    }

    private static PersistedReplay ReadReplay(string path)
    {
        var bytes = ReadStrictState(path, "authority replay state");
        PersistedReplay? replay;
        try { replay = JsonSerializer.Deserialize<PersistedReplay>(bytes); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
        if (replay is null)
            throw new InvalidDataException("Malformed authority replay state");
        if (replay.Version != 1 || replay.Epoch < 0 || replay.Sequence < 0)
            throw new InvalidDataException("Invalid authority replay state");
        return replay;
    }

    // The authority high-water marks must be parsed from a single, bounded,
    // private, non-symlinked opened file. A duplicate case/escape alias could
    // otherwise make two consumers disagree about the trusted epoch/sequence.
    private static byte[] ReadStrictState(string path, string purpose)
    {
        if (OperatingSystem.IsWindows()) EnsurePrivateWindowsAcl(path, isDirectory: false);
        var bytes = PrivateKeyFileSecurity.ReadPrivateFileBytes(path, purpose, 1024);
        if (StrictJsonPropertyNames.HasNoDuplicates(bytes)) return bytes;
        CryptographicOperations.ZeroMemory(bytes);
        throw new InvalidDataException($"{purpose} has malformed or ambiguous JSON");
    }

    private static void PersistReplay(string path, PersistedReplay replay) =>
        WriteState(path, JsonSerializer.SerializeToUtf8Bytes(replay));

    private static void WriteState(string path, byte[] bytes)
    {
        var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write,
                FileShare.None, 4096, FileOptions.WriteThrough))
            {
                if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(temporary,
                    UnixFileMode.UserRead | UnixFileMode.UserWrite);
                else EnsurePrivateWindowsAcl(temporary, isDirectory: false);
                stream.Write(bytes);
                stream.Flush(flushToDisk: true);
            }
            File.Move(temporary, path, overwrite: true);
            if (OperatingSystem.IsWindows()) EnsurePrivateWindowsAcl(path, isDirectory: false);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }

    private static void EnsureNotLink(string path, string purpose)
    {
        var info = new FileInfo(path);
        if (info.LinkTarget is not null || (info.Exists &&
            (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0))
            throw new InvalidDataException($"{purpose} cannot be a symbolic link or reparse point");
    }

    [SupportedOSPlatform("windows")]
    private static void EnsurePrivateWindowsAcl(string path, bool isDirectory)
    {
        if (!OperatingSystem.IsWindows()) return;
        using var identity = WindowsIdentity.GetCurrent();
        var allowed = AgentHealthReportStore.AllowedWindowsPrincipals(identity);
        FileSystemSecurity security = isDirectory
            ? new DirectoryInfo(path).GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner)
            : new FileInfo(path).GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner);
        var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        if (!AgentHealthReportStore.IsAllowedWindowsOwner(owner, allowed))
            throw new InvalidDataException("Authority fence state owner is not the DNS service identity, SYSTEM, Administrators or its service SID");
        var rules = security.GetAccessRules(includeExplicit: true, includeInherited: true,
            targetType: typeof(SecurityIdentifier));
        foreach (FileSystemAccessRule rule in rules)
            if (rule.AccessControlType == AccessControlType.Allow && rule.FileSystemRights != 0 &&
                rule.IdentityReference is SecurityIdentifier sid && !allowed.Contains(sid.Value))
                throw new InvalidDataException("Authority fence state ACL grants access beyond the DNS service identity, SYSTEM and Administrators");
    }

    public void Dispose()
    {
        localSigner.Dispose();
        peerVerifier.Dispose();
        epochLock.Dispose();
        replayLock.Dispose();
    }
}

internal sealed class AuthorityFenceRuntime : IAsyncDisposable
{
    private readonly AuthorityFenceConfig config;
    private readonly AuthorityFenceStore store;
    private WebApplication? app;
    private X509Certificate2? serverCertificate;
    private X509Certificate2? clientCertificate;
    private HttpClient? client;
    private Task? publisher;
    private CancellationTokenSource? publisherCancellation;
    private readonly SemaphoreSlim requestSlots = new(16, 16);
    private readonly object publisherLock = new();

    public AuthorityFenceRuntime(AuthorityFenceConfig config, AuthorityFenceStore store)
    {
        this.config = config;
        this.store = store;
    }

    public async Task StartAsync(CancellationToken token)
    {
        if (app is not null) throw new InvalidOperationException("Authority fence already started");
        serverCertificate = LoadCertificate(config.ServerCertificatePem, config.ServerKeyPem,
            "Authority fence server TLS certificate");
        clientCertificate = LoadCertificate(config.ClientCertificatePem, config.ClientKeyPem,
            "Authority fence client TLS certificate");
        if (!HasEku(serverCertificate, "1.3.6.1.5.5.7.3.1") ||
            !HasEku(clientCertificate, "1.3.6.1.5.5.7.3.2"))
            throw new InvalidDataException("Authority TLS certificates require serverAuth/clientAuth EKU respectively");

        var listen = IPAddress.Parse(config.ListenAddress);
        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.ConfigureKestrel(kestrel =>
        {
            kestrel.Limits.MaxRequestBodySize = AuthorityFenceContract.MaximumSerializedBytes;
            kestrel.Limits.MaxRequestHeadersTotalSize = 8192;
            kestrel.Limits.MaxConcurrentConnections = 32;
            kestrel.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(5);
            kestrel.Limits.KeepAliveTimeout = TimeSpan.FromSeconds(5);
            kestrel.Listen(listen, config.ListenPort, endpoint => endpoint.UseHttps(https =>
            {
                https.ServerCertificate = serverCertificate;
                https.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
                https.ClientCertificateValidation = (certificate, _, _) =>
                    AuthorityFenceStore.IsPinnedCertificate(certificate,
                        config.Peer.ClientCertificateSha256, "1.3.6.1.5.5.7.3.2");
            }));
        });
        var web = builder.Build();
        web.MapPost("/authority-fence/v1/snapshot", async (HttpContext context) =>
        {
            if (!store.IsAllowedPeerAddress(context.Connection.RemoteIpAddress))
                return Results.StatusCode(StatusCodes.Status403Forbidden);
            if (!await requestSlots.WaitAsync(0, context.RequestAborted))
                return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
            try
            {
                if (context.Request.ContentLength is > AuthorityFenceContract.MaximumSerializedBytes)
                    return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);
                using var body = new MemoryStream();
                var buffer = new byte[8192];
                while (true)
                {
                    var read = await context.Request.Body.ReadAsync(buffer, context.RequestAborted);
                    if (read == 0) break;
                    if (body.Length + read > AuthorityFenceContract.MaximumSerializedBytes)
                        return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);
                    body.Write(buffer, 0, read);
                }
                AuthorityFenceSnapshot? snapshot;
                var payload = body.ToArray();
                if (!StrictJsonPropertyNames.HasNoDuplicates(payload))
                    return Results.BadRequest();
                try { snapshot = JsonSerializer.Deserialize<AuthorityFenceSnapshot>(payload); }
                catch (JsonException) { return Results.BadRequest(); }
                if (snapshot is null) return Results.BadRequest();
                if (!store.TryAccept(snapshot, context.Connection.ClientCertificate,
                        DateTimeOffset.UtcNow, Environment.TickCount64))
                    return Results.StatusCode(StatusCodes.Status409Conflict);
                context.Response.Headers.CacheControl = "no-store";
                return Results.NoContent();
            }
            finally { requestSlots.Release(); }
        });
        app = web;
        try
        {
            await web.StartAsync(token);
            var handler = new HttpClientHandler { AllowAutoRedirect = false, UseProxy = false };
            handler.ClientCertificates.Add(clientCertificate);
            handler.SslProtocols = System.Security.Authentication.SslProtocols.Tls12 |
                System.Security.Authentication.SslProtocols.Tls13;
            handler.ServerCertificateCustomValidationCallback = (_, certificate, _, errors) =>
                (errors & SslPolicyErrors.RemoteCertificateNameMismatch) == 0 &&
                (errors & SslPolicyErrors.RemoteCertificateNotAvailable) == 0 &&
                AuthorityFenceStore.IsPinnedCertificate(certificate,
                    config.Peer.ServerCertificateSha256, "1.3.6.1.5.5.7.3.1");
            client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(2) };
            publisherCancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
            publisher = PublishLoop(publisherCancellation.Token);
        }
        catch
        {
            // Startup can fail after the HTTP client and publisher have been
            // created. Cancel the publisher before disposing its transport;
            // otherwise an in-flight publish can outlive a failed listener.
            publisherCancellation?.Cancel();
            if (publisher is not null)
            {
                try { await publisher; }
                catch (OperationCanceledException) { }
                publisher = null;
            }
            publisherCancellation?.Dispose();
            publisherCancellation = null;
            client?.Dispose();
            client = null;
            app = null;
            await web.DisposeAsync();
            serverCertificate.Dispose(); serverCertificate = null;
            clientCertificate.Dispose(); clientCertificate = null;
            throw;
        }
    }

    private async Task PublishLoop(CancellationToken token)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(config.PublishIntervalSeconds));
        do
        {
            try
            {
                var sentAtTick = Environment.TickCount64;
                var snapshot = store.CreateSnapshot(sentAtTick);
                var payload = JsonSerializer.SerializeToUtf8Bytes(snapshot);
                if (payload.Length > AuthorityFenceContract.MaximumSerializedBytes)
                    throw new InvalidDataException("Authority fence snapshot exceeds 128 KiB bound");
                using var content = new ByteArrayContent(payload);
                content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
                // Last local disk check before handing this request to the
                // transport. An in-flight snapshot cannot be recalled.
                if (!store.CanPublish(Environment.TickCount64))
                    throw new InvalidDataException("Authority durable state fault before publication");
                using var response = await client!.PostAsync(config.Peer.Endpoint, content, token);
                if (response.StatusCode == HttpStatusCode.NoContent)
                    store.RecordPeerAcknowledgement(sentAtTick, Environment.TickCount64);
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested) { break; }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or InvalidDataException) { }
        } while (await timer.WaitForNextTickAsync(token));
    }

    private static X509Certificate2 LoadCertificate(string certificatePem, string keyPem, string purpose)
    {
        var privateKey = PrivateKeyFileSecurity.ReadPrivateKeyPem(keyPem, purpose + " private key");
        using var certificate = X509Certificate2.CreateFromPem(File.ReadAllText(certificatePem), privateKey);
        return X509CertificateLoader.LoadPkcs12(certificate.Export(X509ContentType.Pkcs12), null);
    }

    private static bool HasEku(X509Certificate2 certificate, string eku) =>
        certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().Any(extension =>
            extension.EnhancedKeyUsages.Cast<Oid>().Any(oid => oid.Value == eku));

    public async ValueTask DisposeAsync()
    {
        var running = app;
        app = null;
        // Stop the publisher independently of the caller's startup token.
        // A normal shutdown must not wait indefinitely for the next timer tick
        // when StartAsync was invoked with CancellationToken.None.
        publisherCancellation?.Cancel();
        if (publisher is not null)
        {
            try { await publisher; }
            catch (OperationCanceledException) { }
            publisher = null;
        }
        publisherCancellation?.Dispose();
        publisherCancellation = null;
        if (running is not null)
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            try { await running.StopAsync(timeout.Token); }
            catch (OperationCanceledException) { }
            await running.DisposeAsync();
        }
        client?.Dispose(); client = null;
        clientCertificate?.Dispose(); clientCertificate = null;
        serverCertificate?.Dispose(); serverCertificate = null;
        requestSlots.Dispose();
    }
}
