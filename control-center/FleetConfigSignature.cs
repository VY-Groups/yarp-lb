using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

/// <summary>
/// Sign per-gateway config prepares with an offline-provisioned ECDSA P-256 private key.
/// Controller client mTLS remains mandatory. The public key is pinned on each gateway.
/// </summary>
public static class FleetConfigSignature
{
    public static bool ValidExpiration(long expiresUnixSeconds, long nowUnixSeconds) =>
        expiresUnixSeconds > nowUnixSeconds && expiresUnixSeconds <= nowUnixSeconds + 300;

    public static byte[] SigningBytes(string transactionId, string expectedRevision,
        JsonObject reverseProxy, long expiresUnixSeconds)
    {
        var canonical = Canonicalize(reverseProxy);
        var digest = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
        return Encoding.UTF8.GetBytes("yarp-control-center-fleet-v1\n" +
            transactionId + "\n" + expectedRevision.ToUpperInvariant() + "\n" +
            expiresUnixSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture) + "\n" + digest);
    }

    public static string Sign(string privateKeyPem, string transactionId, string expectedRevision,
        JsonObject proxy, long expiresUnixSeconds)
    {
        using var key = ECDsa.Create();
        key.ImportFromPem(privateKeyPem);
        return Convert.ToBase64String(key.SignData(SigningBytes(transactionId, expectedRevision, proxy, expiresUnixSeconds),
            HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
    }

    public static bool Verify(string publicKeyPem, string transactionId, string expectedRevision,
        JsonObject proxy, long expiresUnixSeconds, string? signature, long nowUnixSeconds)
    {
        if (!ValidExpiration(expiresUnixSeconds, nowUnixSeconds) || string.IsNullOrWhiteSpace(signature) ||
            string.IsNullOrWhiteSpace(transactionId) || string.IsNullOrWhiteSpace(expectedRevision)) return false;
        try
        {
            using var key = ECDsa.Create();
            key.ImportFromPem(publicKeyPem);
            return key.VerifyData(SigningBytes(transactionId, expectedRevision, proxy, expiresUnixSeconds),
                Convert.FromBase64String(signature), HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException or ArgumentException)
        { return false; }
    }


    // Version 2 binds a *monotonic sequence number* and named signing key to every
    // prepared configuration. V1 remains only for existing legacy unit-test compatibility;
    // the agent never accepts V1 messages.
    public sealed record SignedV2(string KeyId, long Sequence, long ExpiresUnixSeconds, string Signature);

    public static string KeyIdFromPublicKey(string publicKeyPem)
    {
        using var key = ECDsa.Create();
        key.ImportFromPem(publicKeyPem);
        return Convert.ToHexString(SHA256.HashData(key.ExportSubjectPublicKeyInfo()))[..32];
    }

    private static byte[] SigningBytesV2(string transactionId, string expectedRevision,
        JsonObject proxy, long expires, long sequence, string keyId)
    {
        var contentHash = Convert.ToHexString(SHA256.HashData(
            Encoding.UTF8.GetBytes(Canonicalize(proxy))));
        return Encoding.UTF8.GetBytes(string.Join("\n", "yarp-control-fleet-v2",
            keyId, sequence.ToString(System.Globalization.CultureInfo.InvariantCulture),
            transactionId, expectedRevision.ToUpperInvariant(),
            expires.ToString(System.Globalization.CultureInfo.InvariantCulture), contentHash));
    }

    public static SignedV2 SignV2(string privatePem, string transactionId,
        string expectedRevision, JsonObject proxy, long expiresUnixSeconds, long sequence)
    {
        if (sequence < 1) throw new ArgumentOutOfRangeException(nameof(sequence));
        using var key = ECDsa.Create();
        key.ImportFromPem(privatePem);
        var keyId = Convert.ToHexString(SHA256.HashData(key.ExportSubjectPublicKeyInfo()))[..32];
        var sig = key.SignData(SigningBytesV2(transactionId, expectedRevision, proxy,
            expiresUnixSeconds, sequence, keyId), HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        return new SignedV2(keyId, sequence, expiresUnixSeconds, Convert.ToBase64String(sig));
    }

    public static bool VerifyV2(IReadOnlyDictionary<string, string> trustedKeys,
        string transactionId, string expectedRevision, JsonObject proxy,
        SignedV2 envelope, long nowUnixSeconds)
    {
        if (envelope.Sequence < 1 || !ValidExpiration(envelope.ExpiresUnixSeconds, nowUnixSeconds) ||
            !trustedKeys.TryGetValue(envelope.KeyId, out var publicPem) ||
            string.IsNullOrWhiteSpace(transactionId) || string.IsNullOrWhiteSpace(expectedRevision))
            return false;
        try
        {
            using var key = ECDsa.Create();
            key.ImportFromPem(publicPem);
            return key.VerifyData(SigningBytesV2(transactionId, expectedRevision, proxy,
                envelope.ExpiresUnixSeconds, envelope.Sequence, envelope.KeyId),
                Convert.FromBase64String(envelope.Signature), HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException or ArgumentException)
        { return false; }
    }

    // Sort object keys and retain array order. Prevents insignificant property order changes
    // during JSON transfer from invalidating a verified digest.
    private static string Canonicalize(JsonNode? value) => value switch
    {
        null => "null",
        JsonObject obj => "{" + string.Join(",", obj.OrderBy(p => p.Key, StringComparer.Ordinal)
            .Select(p => JsonSerializer.Serialize(p.Key) + ":" + Canonicalize(p.Value))) + "}",
        JsonArray array => "[" + string.Join(",", array.Select(Canonicalize)) + "]",
        _ => value.ToJsonString()
    };
}
