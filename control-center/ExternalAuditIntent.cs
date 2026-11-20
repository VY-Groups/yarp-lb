using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

/// <summary>Opt-in pre-mutation evidence gate. A trusted external collector must
/// persist the exact intent before returning its independently signed receipt.
/// A receipt is not itself proof of WORM retention.</summary>
internal sealed class ExternalAuditIntent : IDisposable
{
    private readonly Uri endpoint;
    private readonly string node;
    private readonly byte[] senderKey;
    private readonly RSA collectorKey;
    private readonly HttpClient client;
    private readonly object verifyGate = new();

    internal const string RequestSignature = "X-GC-Audit-Signature";
    internal const string ReceiptSignature = "X-GC-Audit-Receipt";
    internal const string EventIdHeader = "X-GC-Audit-Event-Id";

    internal ExternalAuditIntent(Uri endpoint, string node, byte[] senderKey,
        string collectorPublicKeyPem, HttpClient client)
    {
        if (endpoint.Scheme != Uri.UriSchemeHttps || !string.IsNullOrEmpty(endpoint.UserInfo) ||
            !string.IsNullOrEmpty(endpoint.Query) || !string.IsNullOrEmpty(endpoint.Fragment) ||
            endpoint.AbsolutePath != "/audit/v1/intents")
            throw new InvalidOperationException("External audit requires an exact HTTPS /audit/v1/intents endpoint");
        if (node.Length is < 1 or > 48 || !node.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_') ||
            senderKey.Length != 32)
            throw new InvalidOperationException("External audit requires a bounded ASCII node ID and 32-byte sender key");
        // Only a public verification key is permitted on the gateway.
        if (!collectorPublicKeyPem.Trim().StartsWith("-----BEGIN PUBLIC KEY-----", StringComparison.Ordinal) ||
            !collectorPublicKeyPem.Trim().EndsWith("-----END PUBLIC KEY-----", StringComparison.Ordinal))
            throw new InvalidOperationException("External audit requires a collector RSA public key");
        collectorKey = RSA.Create();
        try
        {
            collectorKey.ImportFromPem(collectorPublicKeyPem);
            if (collectorKey.KeySize < 2048 || collectorKey.KeySize > 4096)
                throw new InvalidOperationException("Collector RSA key must be 2048..4096 bits");
        }
        catch { collectorKey.Dispose(); throw; }
        this.endpoint = endpoint;
        this.node = node;
        this.senderKey = (byte[])senderKey.Clone();
        this.client = client;
    }

    internal static ExternalAuditIntent? FromEnvironment(string? url, string? node,
        string? senderKeyFile, string? collectorPublicKeyFile)
    {
        if (url is null && node is null && senderKeyFile is null && collectorPublicKeyFile is null) return null;
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || node is null ||
            senderKeyFile is null || collectorPublicKeyFile is null)
            throw new InvalidOperationException("External audit configuration must be complete");
        static byte[] ReadBounded(string file, int max, bool secret)
        {
            if (!Path.IsPathFullyQualified(file) || !File.Exists(file) ||
                (File.GetAttributes(file) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidOperationException("External audit requires absolute, non-symlinked key files");
            if (secret && !OperatingSystem.IsWindows() &&
                (File.GetUnixFileMode(file) & (UnixFileMode.GroupRead | UnixFileMode.GroupWrite |
                UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherWrite |
                UnixFileMode.OtherExecute)) != 0)
                throw new InvalidOperationException("External audit sender key requires owner-only access");
            using var f = File.OpenRead(file);
            if (f.Length is < 1 || f.Length > max)
                throw new InvalidOperationException("External audit key file exceeds allowed size");
            var bytes = new byte[(int)f.Length];
            f.ReadExactly(bytes);
            if (f.ReadByte() != -1) throw new InvalidOperationException("External audit key changed during read");
            return bytes;
        }
        var sender = ReadBounded(senderKeyFile, 32, secret: true);
        var collector = Encoding.ASCII.GetString(ReadBounded(collectorPublicKeyFile, 4096, secret: false));
        var http = new HttpClient(new SocketsHttpHandler
        {
            AllowAutoRedirect = false, UseCookies = false, UseProxy = false,
            ConnectTimeout = TimeSpan.FromSeconds(3)
        }) { Timeout = Timeout.InfiniteTimeSpan };
        try { return new ExternalAuditIntent(uri, node, sender, collector, http); }
        catch { http.Dispose(); throw; }
        finally { CryptographicOperations.ZeroMemory(sender); }
    }

    private static byte[] SignatureInput(string purpose, string id, byte[] body) =>
        Encoding.ASCII.GetBytes(purpose + "\n" + id + "\n" + Convert.ToHexString(SHA256.HashData(body)));

    // Separate purpose strings prevent reflecting a sender MAC as a receipt.
    internal static byte[] ReceiptInput(string id, byte[] body) =>
        SignatureInput("GatewayCore-Audit-Receipt-v1", id, body);

    internal async Task<bool> ConfirmAsync(string actor, string operation, string revision,
        string targetDigest, CancellationToken cancellationToken)
    {
        if (cancellationToken.IsCancellationRequested || actor.Length is < 1 or > 256 || actor.Any(char.IsControl) || operation is not ("CONFIG_APPLY_INTENT" or "CONFIG_RESTORE_INTENT" or "USER_CREATE_INTENT" or "USER_PASSWORD_RESET_INTENT" or "USER_DISABLE_INTENT" or "USER_ENABLE_INTENT" or "INVENTORY_ADD_INTENT" or "INVENTORY_DELETE_INTENT" or "FLEET_REGISTER_INTENT" or "FLEET_UNREGISTER_INTENT" or "MAIL_SETTINGS_INTENT" or "MAIL_PROOF_INTENT" or "DIRECTORY_SETTINGS_INTENT" or "TOPOLOGY_DRAFT_INTENT" or "TOPOLOGY_CONFIRM_INTENT" or "CHANGE_REQUEST_INTENT" or "CHANGE_REJECT_INTENT" or "FLEET_ROLLOUT_INTENT" or "FLEET_RECOVERY_INTENT") ||
            !IsDigest(revision) || !IsDigest(targetDigest))
            return false;
        var id = Guid.NewGuid().ToString("N");
        var payload = JsonSerializer.SerializeToUtf8Bytes(new
        {
            schema = 1, eventId = id, node, utc = DateTimeOffset.UtcNow,
            actor, operation, revision, targetDigest
        });
        using var request = new HttpRequestMessage(HttpMethod.Post, endpoint);
        request.Content = new ByteArrayContent(payload);
        request.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
        request.Headers.Add(EventIdHeader, id);
        request.Headers.Add(RequestSignature, Convert.ToBase64String(HMACSHA256.HashData(senderKey,
            SignatureInput("GatewayCore-Audit-Intent-v1", id, payload))));
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(5));
        try
        {
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token);
            if (response.StatusCode != HttpStatusCode.Created ||
                !response.Headers.TryGetValues(ReceiptSignature, out var receipts))
                return false;
            var values = receipts.Take(2).ToArray();
            if (values.Length != 1 || values[0].Length > 1024) return false;
            var signature = Convert.FromBase64String(values[0]);
            lock (verifyGate)
                return !deadline.IsCancellationRequested &&
                    collectorKey.VerifyData(ReceiptInput(id, payload), signature,
                        HashAlgorithmName.SHA256, RSASignaturePadding.Pss) &&
                    !deadline.IsCancellationRequested;
        }
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException
                                   or FormatException or CryptographicException or IOException)
        {
            return false;
        }
    }

    private static bool IsDigest(string value) =>
        value.Length == 64 && value.All(c => c is >= '0' and <= '9' or >= 'A' and <= 'F');

    public void Dispose()
    {
        client.Dispose();
        collectorKey.Dispose();
        CryptographicOperations.ZeroMemory(senderKey);
    }
}
