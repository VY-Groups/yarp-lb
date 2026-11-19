using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

internal sealed record AuditIntent(string EventId, string Node, DateTimeOffset Utc);
internal static class AuditContract
{
    internal const int MaxBody = 4096;
    private static readonly string[] Fields =
        ["schema", "eventId", "node", "utc", "actor", "operation", "revision", "targetDigest"];
    internal static bool ValidNode(string s) => s.Length is >= 1 and <= 48 &&
        s.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_');
    private static bool Digest(string? s) => s is { Length: 64 } &&
        s.All(c => c is >= '0' and <= '9' or >= 'A' and <= 'F');
    internal static AuditIntent? Parse(byte[] bytes)
    {
        if (bytes.Length is < 1 or > MaxBody) return null;
        try
        {
            using var doc = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 3 });
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return null;
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var field in root.EnumerateObject())
                if (!Fields.Contains(field.Name, StringComparer.Ordinal) || !names.Add(field.Name)) return null;
            if (names.Count != Fields.Length || root.GetProperty("schema").GetInt32() != 1) return null;
            var id = root.GetProperty("eventId").GetString();
            var node = root.GetProperty("node").GetString();
            var actor = root.GetProperty("actor").GetString();
            if (id is null || !Guid.TryParseExact(id, "N", out var guid) || guid.ToString("N") != id ||
                node is null || !ValidNode(node) || actor is not { Length: >= 1 and <= 256 } ||
                actor.Any(char.IsControl) ||
                root.GetProperty("operation").GetString() is not ("CONFIG_APPLY_INTENT" or "CONFIG_RESTORE_INTENT") ||
                !Digest(root.GetProperty("revision").GetString()) || !Digest(root.GetProperty("targetDigest").GetString()) ||
                !root.GetProperty("utc").TryGetDateTimeOffset(out var utc)) return null;
            return new AuditIntent(id, node, utc);
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or FormatException)
        { return null; }
    }
    internal static byte[] Input(string purpose, string id, byte[] body) =>
        Encoding.ASCII.GetBytes(purpose + "\n" + id + "\n" + Convert.ToHexString(SHA256.HashData(body)));
    internal static bool VerifyMac(string id, byte[] body, string? mac, byte[] key)
    {
        if (mac is not { Length: 44 }) return false;
        Span<byte> decoded = stackalloc byte[32];
        return Convert.TryFromBase64String(mac, decoded, out var n) && n == 32 &&
            CryptographicOperations.FixedTimeEquals(decoded,
                HMACSHA256.HashData(key, Input("GatewayCore-Audit-Intent-v1", id, body)));
    }
}

internal sealed class AuditLedger : IDisposable
{
    private sealed record Entry(long Sequence, string Previous, string Body, string Hash, string Signature);
    internal sealed record Result(int Status, string? Receipt = null);
    private const long MaxBytes = 64L * 1024 * 1024;
    private const int MaxEntries = 100000, MaxLine = 8192;
    private static readonly string Genesis = new('0', 64);
    private readonly object gate = new();
    private readonly FileStream stream;
    private readonly string path;
    private readonly RSA signer;
    private readonly IAuditRetention? retention;
    private readonly FileStream? pending;
    private readonly string? pendingPath;
    private byte[]? lastRecord;
    private readonly HashSet<string> seen = new(StringComparer.Ordinal);
    private string head = Genesis;
    private long length;
    private bool faulted;
    internal int Count => seen.Count;
    internal string Head => head;

    internal AuditLedger(string path, RSA signer, IAuditRetention? retention = null, string? pendingPath = null)
    {
        this.path = path;
        this.signer = signer;
        this.retention = retention;
        this.pendingPath = pendingPath;
        if ((retention is null) != (pendingPath is null))
            throw new InvalidDataException("Retention and pre-provisioned pending file must be paired");
        stream = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.Read);
        try
        {
            if (pendingPath is not null)
            {
                if (Path.GetFullPath(pendingPath) == Path.GetFullPath(path))
                    throw new InvalidDataException("Pending path must differ from ledger");
                pending = new FileStream(pendingPath, FileMode.Open, FileAccess.ReadWrite, FileShare.Read);
            }
            Recover();
            // Validate the signed pending record before serving any traffic.
            if (pending is not null && pending.Length != 0) ReadPending();
        }
        catch { pending?.Dispose(); stream.Dispose(); throw; }
    }
    private static byte[] ChainInput(long seq, string previous, byte[] body) =>
        Encoding.ASCII.GetBytes("GatewayCore-Audit-Chain-v1\n" +
            seq.ToString(CultureInfo.InvariantCulture) + "\n" + previous + "\n" +
            Convert.ToHexString(SHA256.HashData(body)));
    private void Recover()
    {
        if (stream.Length > MaxBytes) throw new InvalidDataException("Ledger exceeds configured bounded storage");
        length = stream.Length;
        using var reader = new StreamReader(stream, new UTF8Encoding(false, true), false, 4096, leaveOpen: true);
        var line = new StringBuilder();
        int ch;
        while ((ch = reader.Read()) != -1)
        {
            if (ch != '\n')
            {
                if (line.Length >= MaxLine) throw new InvalidDataException("Oversized ledger line");
                line.Append((char)ch);
                continue;
            }
            var raw = line.ToString();
            var entry = JsonSerializer.Deserialize<Entry>(raw) ??
                throw new InvalidDataException("Missing ledger entry");
            line.Clear();
            if (entry.Sequence != seen.Count + 1L || seen.Count >= MaxEntries ||
                entry.Previous != head || entry.Body is null || entry.Hash is null || entry.Signature is null)
                throw new InvalidDataException("Ledger sequence or chain mismatch");
            var body = Convert.FromBase64String(entry.Body);
            var intent = AuditContract.Parse(body);
            var input = ChainInput(entry.Sequence, head, body);
            if (intent is null || !seen.Add(intent.EventId) ||
                Convert.ToHexString(SHA256.HashData(input)) != entry.Hash ||
                !signer.VerifyData(input, Convert.FromBase64String(entry.Signature),
                    HashAlgorithmName.SHA256, RSASignaturePadding.Pss))
                throw new InvalidDataException("Ledger body or signature mismatch");
            head = entry.Hash;
            lastRecord = Encoding.UTF8.GetBytes(raw + "\n");
        }
        if (line.Length != 0) throw new InvalidDataException("Incomplete ledger record; operator recovery required");
        stream.Position = length;
    }
    // A single pre-existing, bounded write-ahead slot. Exact bytes are retained
    // until the external locked object and the local append are both confirmed.
    private (Entry Entry, byte[] Bytes, AuditIntent Intent) ReadPending()
    {
        if (pending is null || pending.Length is < 1 or > MaxLine)
            throw new InvalidDataException("Pending audit record size invalid");
        var bytes = new byte[(int)pending.Length];
        pending.Position = 0;
        pending.ReadExactly(bytes);
        using (var current = new FileStream(pendingPath!, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
        {
            if (current.Length != bytes.Length) throw new IOException("Pending record path changed");
            var observed = new byte[bytes.Length];
            current.ReadExactly(observed);
            if (!bytes.AsSpan().SequenceEqual(observed)) throw new IOException("Pending record path changed");
        }
        if (bytes[^1] != (byte)'\n') throw new InvalidDataException("Partial pending audit record");
        var entry = JsonSerializer.Deserialize<Entry>(bytes) ?? throw new InvalidDataException("Missing pending record");
        var body = Convert.FromBase64String(entry.Body);
        var intent = AuditContract.Parse(body) ?? throw new InvalidDataException("Invalid pending intent");
        var input = ChainInput(entry.Sequence, entry.Previous, body);
        if (Convert.ToHexString(SHA256.HashData(input)) != entry.Hash ||
            !signer.VerifyData(input, Convert.FromBase64String(entry.Signature), HashAlgorithmName.SHA256, RSASignaturePadding.Pss))
            throw new InvalidDataException("Pending record signature mismatch");
        var next = entry.Sequence == seen.Count + 1L && entry.Previous == head && !seen.Contains(intent.EventId);
        var committed = entry.Sequence == seen.Count && lastRecord is not null && bytes.AsSpan().SequenceEqual(lastRecord);
        if (!next && !committed) throw new InvalidDataException("Pending record is not a valid continuation");
        return (entry, bytes, intent);
    }

    private void CheckLocal()
    {
        if (!File.Exists(path) || (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0 ||
            new FileInfo(path).Length != length || stream.Length != length)
            throw new IOException("Ledger state changed");
    }

    private void Commit(Entry entry, byte[] bytes, string id)
    {
        CheckLocal();
        stream.Position = length;
        stream.Write(bytes);
        stream.Flush(flushToDisk: true);
        length += bytes.Length;
        head = entry.Hash;
        seen.Add(id);
        lastRecord = bytes;
    }

    private bool DrainPending()
    {
        if (pending is null) return true;
        if (!File.Exists(pendingPath) || (File.GetAttributes(pendingPath!) & FileAttributes.ReparsePoint) != 0 ||
            new FileInfo(pendingPath!).Length != pending.Length)
            throw new IOException("Pending audit record path lost or replaced");
        if (pending.Length == 0) return true;
        CheckLocal();
        var record = ReadPending();
        var required = retention!.RequiredUntil(record.Intent.Utc.UtcDateTime);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        // Dedicated collector only; the gateway proxy never enters this lock.
        if (!retention.ConfirmAsync(record.Entry.Sequence, record.Bytes, required, deadline.Token)
                .GetAwaiter().GetResult()) return false;
        if (!File.Exists(pendingPath) || (File.GetAttributes(pendingPath!) & FileAttributes.ReparsePoint) != 0 ||
            !ReadPending().Bytes.AsSpan().SequenceEqual(record.Bytes))
            throw new IOException("Pending record changed before commit");
        if (record.Entry.Sequence == seen.Count + 1L)
            Commit(record.Entry, record.Bytes, record.Intent.EventId);
        pending.Position = 0;
        pending.SetLength(0);
        pending.Flush(flushToDisk: true);
        return true;
    }

    internal bool RetryPending()
    {
        lock (gate)
        {
            if (faulted) return false;
            try { return DrainPending(); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or CryptographicException or JsonException or FormatException)
            { faulted = true; return false; }
        }
    }

    internal Result Append(string id, byte[] body)
    {
        lock (gate)
        {
            if (faulted) return new(503);
            try
            {
                CheckLocal();
                // Never stack another sequence behind an unresolved write.
                if (!DrainPending()) return new(503);
                if (seen.Contains(id)) return new(409);
                if (seen.Count >= MaxEntries) return new(503);
                var seq = seen.Count + 1L;
                var input = ChainInput(seq, head, body);
                var hash = Convert.ToHexString(SHA256.HashData(input));
                var entry = new Entry(seq, head, Convert.ToBase64String(body), hash,
                    Convert.ToBase64String(signer.SignData(input, HashAlgorithmName.SHA256, RSASignaturePadding.Pss)));
                var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(entry) + "\n");
                if (bytes.Length > MaxLine || length + bytes.Length > MaxBytes) return new(503);
                // Prepare receipt; return it ONLY after durable append succeeds.
                var receipt = Convert.ToBase64String(signer.SignData(
                    AuditContract.Input("GatewayCore-Audit-Receipt-v1", id, body),
                    HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
                if (pending is not null)
                {
                    pending.Position = 0;
                    pending.Write(bytes);
                    pending.Flush(flushToDisk: true);
                    if (!DrainPending()) return new(503);
                }
                else Commit(entry, bytes, id);
                return new(201, receipt);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or CryptographicException or JsonException or FormatException)
            {
                faulted = true;
                return new(503);
            }
        }
    }
    public void Dispose() { pending?.Dispose(); stream.Dispose(); }
}
