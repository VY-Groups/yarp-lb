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
    private readonly HashSet<string> seen = new(StringComparer.Ordinal);
    private string head = Genesis;
    private long length;
    private bool faulted;
    internal int Count => seen.Count;
    internal string Head => head;

    internal AuditLedger(string path, RSA signer)
    {
        this.path = path;
        this.signer = signer;
        stream = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.Read);
        try { Recover(); }
        catch { stream.Dispose(); throw; }
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
            var entry = JsonSerializer.Deserialize<Entry>(line.ToString()) ??
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
        }
        if (line.Length != 0) throw new InvalidDataException("Incomplete ledger record; operator recovery required");
        stream.Position = length;
    }
    internal Result Append(string id, byte[] body)
    {
        lock (gate)
        {
            if (faulted) return new(503);
            if (seen.Contains(id)) return new(409);
            if (seen.Count >= MaxEntries) return new(503);
            try
            {
                if (!File.Exists(path) || (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0 ||
                    new FileInfo(path).Length != length || stream.Length != length)
                    throw new IOException("Ledger state changed");
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
                stream.Position = length;
                stream.Write(bytes);
                stream.Flush(flushToDisk: true);
                length += bytes.Length;
                head = hash;
                seen.Add(id);
                return new(201, receipt);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or CryptographicException)
            {
                faulted = true;
                return new(503);
            }
        }
    }
    public void Dispose() => stream.Dispose();
}
