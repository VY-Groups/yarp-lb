using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;

/// <summary>Bounded, eventually consistent two-node telemetry; never a strict
/// global rate limiter. The Redis atomic quota remains the admission authority.</summary>
public static class PeerStateTableContract
{
    public const string TableId = "hashed-client-minute-request-count";
    public const int TableVersion = 1;
    public const int EntryTtlSeconds = 60;
    public const int MaxEntries = 2048;
    public const int MaxCountPerEntry = 1_000_000;

    public static bool IsSupported(string? tableId, int tableVersion, int entryTtlSeconds) =>
        tableId == TableId && tableVersion == TableVersion && entryTtlSeconds == EntryTtlSeconds;
}

public sealed record PeerStateFrame(string NodeId, long Minute, long Sequence,
    Dictionary<string,int> Counters)
{
    // The receiver deliberately accepts only the protocol version it knows.
    // This is a compatibility fence: rollout must keep both peers on the same
    // version until an explicit negotiation/upgrade protocol is introduced.
    public const int CurrentProtocolVersion = 2;
    [JsonRequired]
    public int ProtocolVersion { get; init; } = CurrentProtocolVersion;

    // Versioned table metadata prevents future peer state from being silently
    // interpreted using this request-counter schema.
    [JsonRequired]
    public string TableId { get; init; } = PeerStateTableContract.TableId;
    [JsonRequired]
    public int TableVersion { get; init; } = PeerStateTableContract.TableVersion;
    [JsonRequired]
    public int EntryTtlSeconds { get; init; } = PeerStateTableContract.EntryTtlSeconds;

    // Boot epoch allows full resynchronization when a peer process restarts.
    public long SourceEpoch { get; init; }
}

public sealed record PeerSyncStatus(bool Enabled, string LocalNode, string RemoteNode,
    int LocalIdentities, long LocalRequests, int RemoteIdentities, long RemoteRequests,
    bool RemoteReportedInCurrentMinute, DateTimeOffset? LastAcceptedUtc, long RemoteSequence,
    long? LastAcceptedAgeSeconds, TimeSpan? LastAcceptedElapsed);

public static class PeerSyncFreshness
{
    public static bool IsRecent(PeerSyncStatus status, TimeSpan tolerance) =>
        status.LastAcceptedElapsed is { } age &&
        age >= TimeSpan.Zero && age <= tolerance;
}

public sealed class PeerStateJournal
{
    private readonly object gate = new();
    private readonly byte[] secret;
    private readonly string localId;
    private readonly string remoteId;
    private readonly int maxIdentities;
    private readonly TimeSpan remoteFreshness;
    private readonly Func<DateTimeOffset> clock;
    private readonly TimeProvider timeProvider;
    private long localMinute = -1, sequence, receivedMinute = -1, receivedSequence = -1;
    private long receivedSourceEpoch;
    private bool remoteExpired;
    private readonly long sourceEpoch = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
    private DateTimeOffset? lastAcceptedUtc;
    private long? lastAcceptedTimestamp;
    private readonly Dictionary<string,int> local = new(StringComparer.Ordinal);
    private Dictionary<string,int> remote = new(StringComparer.Ordinal);

    public PeerStateJournal(string localId, string remoteId, byte[] secret, int capacity,
        TimeSpan? remoteFreshness = null, Func<DateTimeOffset>? clock = null,
        TimeProvider? timeProvider = null)
    {
        if (string.IsNullOrWhiteSpace(localId) || string.IsNullOrWhiteSpace(remoteId) ||
            localId == remoteId || localId.Length > 48 || remoteId.Length > 48)
            throw new ArgumentException("Two distinct nonempty node IDs of at most 48 characters required");
        if (secret.Length < 32 || capacity is < 1 or > PeerStateTableContract.MaxEntries)
            throw new ArgumentException("Peer secret and bounded capacity required");
        this.localId = localId;
        this.remoteId = remoteId;
        this.secret = (byte[])secret.Clone();
        maxIdentities = capacity;
        this.remoteFreshness = remoteFreshness ?? TimeSpan.FromSeconds(60);
        if (this.remoteFreshness < TimeSpan.FromSeconds(1) ||
            this.remoteFreshness > TimeSpan.FromSeconds(60))
            throw new ArgumentOutOfRangeException(nameof(remoteFreshness),
                "Peer telemetry freshness must be 1..60 seconds");
        this.clock = clock ?? (() => DateTimeOffset.UtcNow);
        this.timeProvider = timeProvider ?? TimeProvider.System;
    }

    public static long CurrentMinute() => DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 60;

    public void Observe(IPAddress? ip, long minute)
    {
        if (ip is null) return;
        var normalized = ip.MapToIPv6().GetAddressBytes();
        var salt = Encoding.ASCII.GetBytes("peer-identity-v1");
        var bytes = new byte[salt.Length + normalized.Length];
        salt.CopyTo(bytes, 0);
        normalized.CopyTo(bytes, salt.Length);
        var key = Convert.ToHexString(HMACSHA256.HashData(secret, bytes));
        lock (gate)
        {
            // A late request or backward clock correction must not reset
            // the current minute's counters or its sequence.
            if (minute < localMinute) return;
            if (minute > localMinute)
                ExpireLocalOutsideMinute(minute);
            if (!local.ContainsKey(key) && local.Count >= maxIdentities) return;
            local[key] = local.TryGetValue(key, out var count) ? Math.Min(1_000_000, count + 1) : 1;
        }
    }

    public PeerStateFrame Snapshot(long minute)
    {
        lock (gate)
        {
            // Do not publish a relabelled snapshot during a wall-clock
            // rollback. The publisher's existing bounded interval catches
            // this failure and resumes when the clock reaches the high-water.
            if (minute < localMinute)
                throw new InvalidOperationException("Peer snapshot minute regressed");
            if (minute > localMinute)
                ExpireLocalOutsideMinute(minute);
            sequence++;
            return new PeerStateFrame(localId, minute, sequence,
                new Dictionary<string,int>(local, StringComparer.Ordinal)) { SourceEpoch = sourceEpoch };
        }
    }

    public bool Apply(PeerStateFrame? frame, long currentMinute)
    {
        if (frame is null || frame.ProtocolVersion != PeerStateFrame.CurrentProtocolVersion ||
            !PeerStateTableContract.IsSupported(frame.TableId, frame.TableVersion, frame.EntryTtlSeconds) ||
            frame.NodeId != remoteId ||
            frame.Minute != currentMinute || frame.Sequence <= 0 || frame.SourceEpoch <= 0 ||
            frame.Counters is null || frame.Counters.Count > maxIdentities ||
            frame.Counters.Any(p => p.Key.Length != 64 ||
                !p.Key.All(Uri.IsHexDigit) || p.Value is < 1 or > PeerStateTableContract.MaxCountPerEntry))
            return false;
        lock (gate)
        {
            // A legitimate process restart begins a newer boot epoch, so the
            // first complete signed snapshot can reset its own counters.
            // Older boot epochs never override state after such a reset.
            if (frame.SourceEpoch < receivedSourceEpoch) return false;
            var sameEpoch = frame.SourceEpoch == receivedSourceEpoch;
            // If this receiver's wall clock moved backward, an authenticated
            // delayed frame from an older source minute must not replace newer
            // telemetry that this same source epoch already delivered.
            if (sameEpoch && frame.Minute < receivedMinute) return false;
            if (sameEpoch && frame.Minute == receivedMinute && frame.Sequence <= receivedSequence)
                return false;
            // Within an epoch a higher sequence cannot remove counters.
            if (sameEpoch && frame.Minute == receivedMinute &&
                remote.Any(kv => !frame.Counters.TryGetValue(kv.Key,out var n) || n < kv.Value))
                return false;
            remote = new Dictionary<string,int>(frame.Counters, StringComparer.Ordinal);
            receivedMinute = frame.Minute;
            receivedSequence = frame.Sequence;
            receivedSourceEpoch = frame.SourceEpoch;
            lastAcceptedUtc = clock();
            lastAcceptedTimestamp = timeProvider.GetTimestamp();
            remoteExpired = false;
            return true;
        }
    }

    // Remote state is operational telemetry, not quota authority. Ageing out
    // preserves replay/sequence fencing so an older snapshot cannot resurrect.
    private bool RemoteFresh(long minute)
    {
        if (receivedMinute != minute || lastAcceptedTimestamp is null || remoteExpired)
        {
            remote.Clear();
            if (lastAcceptedTimestamp is not null) remoteExpired = true;
            return false;
        }
        var age = timeProvider.GetElapsedTime(lastAcceptedTimestamp.Value);
        if (age >= TimeSpan.Zero && age <= remoteFreshness) return true;
        // Keep sequence/epoch high-water marks after collection so replayed
        // snapshots cannot repopulate an expired table.
        remote.Clear();
        remoteExpired = true;
        return false;
    }

    public PeerSyncStatus Status(long minute)
    {
        lock (gate)
        {
            if (minute > localMinute) ExpireLocalOutsideMinute(minute);
            var validLocal = localMinute == minute;
            var validRemote = RemoteFresh(minute);
            long? lastAcceptedAgeSeconds = null;
            TimeSpan? lastAcceptedElapsed = null;
            if (lastAcceptedTimestamp is { } acceptedTimestamp)
            {
                var elapsed = timeProvider.GetElapsedTime(acceptedTimestamp);
                if (elapsed >= TimeSpan.Zero)
                {
                    lastAcceptedElapsed = elapsed;
                    lastAcceptedAgeSeconds = (long)Math.Floor(elapsed.TotalSeconds);
                }
            }
            return new PeerSyncStatus(true, localId, remoteId,
                validLocal ? local.Count : 0,
                validLocal ? local.Values.Sum(x => (long)x) : 0,
                validRemote ? remote.Count : 0,
                validRemote ? remote.Values.Sum(x => (long)x) : 0,
                validRemote, lastAcceptedUtc,
                validRemote ? receivedSequence : 0, lastAcceptedAgeSeconds,
                lastAcceptedElapsed);
        }
    }

    public (int identities, long requests) PeerTelemetry(long minute)
    {
        lock (gate)
            return RemoteFresh(minute) ? (remote.Count, remote.Values.Sum(x => (long)x)) : (0, 0);
    }

    internal int RetainedLocalEntries
    {
        get { lock (gate) return local.Count; }
    }

    internal int RetainedRemoteEntries
    {
        get { lock (gate) return remote.Count; }
    }

    private void ExpireLocalOutsideMinute(long minute)
    {
        localMinute = minute;
        sequence = 0;
        local.Clear();
    }
}

public sealed class PeerSignedMessages
{
    private readonly byte[] key;
    private readonly object gate = new();
    private readonly Dictionary<string,long> nonceSeen = new(StringComparer.Ordinal);
    private const int NonceCap = 1024;
    private long latestVerifiedNow = long.MinValue;
    public PeerSignedMessages(byte[] key)
    {
        if (key.Length < 32) throw new ArgumentException("Peer authentication secret requires 32 bytes");
        this.key = (byte[])key.Clone();
    }

    private byte[] Signature(string sender, long seconds, string nonce, ReadOnlySpan<byte> payload)
    {
        var digest = SHA256.HashData(payload);
        var prefix = Encoding.UTF8.GetBytes(sender + "\n" + seconds + "\n" + nonce + "\n");
        var input = new byte[prefix.Length + digest.Length];
        prefix.CopyTo(input, 0);
        digest.CopyTo(input, prefix.Length);
        return HMACSHA256.HashData(key, input);
    }

    public (string nonce,string signature) Sign(string sender,long time,byte[] payload)
    {
        var nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
        return (nonce, Convert.ToBase64String(Signature(sender, time, nonce, payload)));
    }

    public bool Verify(string sender,string expectedSender,long time,string nonce,
        string signature,byte[] payload,long now)
    {
        if (sender != expectedSender ||
            !WithinWindow(time, now) ||
            nonce.Length != 32 || !nonce.All(Uri.IsHexDigit) ||
            signature.Length > 128 || payload.Length > 262144) return false;
        byte[] supplied;
        try { supplied = Convert.FromBase64String(signature); }
        catch(FormatException) { return false; }
        var expected = Signature(sender, time, nonce, payload);
        if (supplied.Length != expected.Length ||
            !CryptographicOperations.FixedTimeEquals(supplied, expected)) return false;
        lock (gate)
        {
            // A forward clock correction may collect old nonces. Never allow
            // a later clock rollback to reopen the already collected window.
            // Advance this fence only for authenticated, time-valid messages.
            var effectiveNow = Math.Max(now, latestVerifiedNow);
            if (!WithinWindow(time, effectiveNow)) return false;
            latestVerifiedNow = effectiveNow;
            foreach (var old in nonceSeen.Where(p => (decimal)effectiveNow - p.Value > 60)
                         .Select(p => p.Key).ToArray())
                nonceSeen.Remove(old);
            var canonicalNonce = nonce.ToUpperInvariant();
            if (nonceSeen.ContainsKey(canonicalNonce) || nonceSeen.Count >= NonceCap) return false;
            nonceSeen.Add(canonicalNonce, effectiveNow);
            return true;
        }
    }

    // Decimal subtraction handles untrusted extreme Int64 timestamps without overflow.
    private static bool WithinWindow(long time, long now) =>
        Math.Abs((decimal)time - (decimal)now) <= 30;
}
