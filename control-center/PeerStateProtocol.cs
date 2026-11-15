using System.Net;
using System.Security.Cryptography;
using System.Text;

/// <summary>Bounded, eventually consistent two-node telemetry; never a strict
/// global rate limiter. The Redis atomic quota remains the admission authority.</summary>
public sealed record PeerStateFrame(string NodeId, long Minute, long Sequence,
    Dictionary<string,int> Counters);

public sealed record PeerSyncStatus(bool Enabled, string LocalNode, string RemoteNode,
    int LocalIdentities, long LocalRequests, int RemoteIdentities, long RemoteRequests,
    bool RemoteReportedInCurrentMinute, DateTimeOffset? LastAcceptedUtc, long RemoteSequence);

public sealed class PeerStateJournal
{
    private readonly object gate = new();
    private readonly byte[] secret;
    private readonly string localId;
    private readonly string remoteId;
    private readonly int maxIdentities;
    private long localMinute = -1, sequence, receivedMinute = -1, receivedSequence = -1;
    private DateTimeOffset? lastAcceptedUtc;
    private readonly Dictionary<string,int> local = new(StringComparer.Ordinal);
    private Dictionary<string,int> remote = new(StringComparer.Ordinal);

    public PeerStateJournal(string localId, string remoteId, byte[] secret, int capacity)
    {
        if (string.IsNullOrWhiteSpace(localId) || string.IsNullOrWhiteSpace(remoteId) ||
            localId == remoteId || localId.Length > 48 || remoteId.Length > 48)
            throw new ArgumentException("Two distinct nonempty node IDs of at most 48 characters required");
        if (secret.Length < 32 || capacity is < 1 or > 2048)
            throw new ArgumentException("Peer secret and bounded capacity required");
        this.localId = localId;
        this.remoteId = remoteId;
        this.secret = (byte[])secret.Clone();
        maxIdentities = capacity;
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
            if (minute != localMinute)
            {
                localMinute = minute;
                sequence = 0;
                local.Clear();
            }
            if (!local.ContainsKey(key) && local.Count >= maxIdentities) return;
            local[key] = local.TryGetValue(key, out var count) ? Math.Min(1_000_000, count + 1) : 1;
        }
    }

    public PeerStateFrame Snapshot(long minute)
    {
        lock (gate)
        {
            if (minute != localMinute)
            {
                localMinute = minute;
                local.Clear();
                sequence = 0;
            }
            sequence++;
            return new PeerStateFrame(localId, minute, sequence,
                new Dictionary<string,int>(local, StringComparer.Ordinal));
        }
    }

    public bool Apply(PeerStateFrame? frame, long currentMinute)
    {
        if (frame is null || frame.NodeId != remoteId ||
            frame.Minute != currentMinute || frame.Sequence <= 0 ||
            frame.Counters is null || frame.Counters.Count > maxIdentities ||
            frame.Counters.Any(p => p.Key.Length != 64 ||
                !p.Key.All(Uri.IsHexDigit) || p.Value is < 1 or > 1_000_000))
            return false;
        lock (gate)
        {
            if (frame.Minute == receivedMinute && frame.Sequence <= receivedSequence) return false;
            // A higher sequence cannot roll back previously observed counters.
            if (frame.Minute == receivedMinute &&
                remote.Any(kv => !frame.Counters.TryGetValue(kv.Key,out var n) || n < kv.Value))
                return false;
            remote = new Dictionary<string,int>(frame.Counters, StringComparer.Ordinal);
            receivedMinute = frame.Minute;
            receivedSequence = frame.Sequence;
            lastAcceptedUtc = DateTimeOffset.UtcNow;
            return true;
        }
    }

    public PeerSyncStatus Status(long minute)
    {
        lock (gate)
        {
            var validLocal = localMinute == minute;
            var validRemote = receivedMinute == minute;
            return new PeerSyncStatus(true, localId, remoteId,
                validLocal ? local.Count : 0,
                validLocal ? local.Values.Sum(x => (long)x) : 0,
                validRemote ? remote.Count : 0,
                validRemote ? remote.Values.Sum(x => (long)x) : 0,
                validRemote, lastAcceptedUtc,
                validRemote ? receivedSequence : 0);
        }
    }

    public (int identities, long requests) PeerTelemetry(long minute)
    {
        lock (gate)
            return receivedMinute == minute ? (remote.Count, remote.Values.Sum(x => (long)x)) : (0, 0);
    }
}

public sealed class PeerSignedMessages
{
    private readonly byte[] key;
    private readonly object gate = new();
    private readonly Dictionary<string,long> nonceSeen = new(StringComparer.Ordinal);
    private const int NonceCap = 1024;
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
        if (sender != expectedSender || time < now - 30 || time > now + 30 ||
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
            foreach (var old in nonceSeen.Where(p => now - p.Value > 60).Select(p=>p.Key).ToArray())
                nonceSeen.Remove(old);
            if (nonceSeen.ContainsKey(nonce) || nonceSeen.Count >= NonceCap) return false;
            nonceSeen.Add(nonce, now);
            return true;
        }
    }
}
