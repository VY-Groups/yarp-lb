using System.Security.Cryptography;
using System.Text;

namespace GatewayCore.Licensing;

public sealed record ActivationRequest(string InstallationKeySha256, string RequestId, byte[] PublicKey);

public static class OfflineActivationRequest
{
    // Exact signed GCR1 envelope. The random request ID is intended for
    // issuer-side durable deduplication. It is not a freshness guarantee.
    internal static byte[] Create(ECDsa installation)
    {
        var prefix = "GCR1." + Encode(installation.ExportSubjectPublicKeyInfo()) +
            "." + Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        return Sign(prefix, installation);
    }

    public static ActivationRequest Verify(ReadOnlySpan<byte> file)
    {
        var parts = Split(file, 4096, 4, "GCR1");
        var spki = Decode(parts[1], 256);
        var nonce = parts[2];
        if (nonce.Length != 64 || nonce.Any(c => !IsHex(c))) throw new InvalidDataException("Invalid request ID.");
        using var key = ECDsa.Create();
        key.ImportSubjectPublicKeyInfo(spki, out var read);
        if (read != spki.Length || key.ExportParameters(false).Curve.Oid.Value != "1.2.840.10045.3.1.7")
            throw new CryptographicException("Invalid installation public key.");
        VerifySignature(parts, key);
        return new(Convert.ToHexString(SHA256.HashData(spki)), nonce, spki);
    }

    internal static byte[] Sign(string prefix, ECDsa key) => Encoding.ASCII.GetBytes(prefix + "." +
        Encode(key.SignData(Encoding.ASCII.GetBytes(prefix), HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation)));

    internal static void VerifySignature(string[] parts, ECDsa key)
    {
        var signature = Decode(parts[^1], 64);
        if (signature.Length != 64 || !key.VerifyData(
            Encoding.ASCII.GetBytes(string.Join(".", parts, 0, parts.Length - 1)), signature,
            HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
            throw new CryptographicException("Installation signature invalid.");
    }

    internal static string[] Split(ReadOnlySpan<byte> file, int max, int count, string prefix)
    {
        if (file.Length is < 1 || file.Length > max) throw new InvalidDataException("Envelope size invalid.");
        foreach (var b in file)
            if (b is < 33 or > 126) throw new InvalidDataException("Envelope is not exact printable ASCII.");
        var parts = Encoding.ASCII.GetString(file).Split('.');
        if (parts.Length != count || parts[0] != prefix) throw new InvalidDataException("Envelope format invalid.");
        return parts;
    }

    internal static bool IsHex(char c) => c is >= '0' and <= '9' or >= 'A' and <= 'F';
    internal static string Encode(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    internal static byte[] Decode(string text, int max)
    {
        if (text.Length < 1 || text.Length > ((max + 2) / 3) * 4 ||
            text.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('-' or '_')))
            throw new InvalidDataException("Invalid encoding.");
        var bytes = Convert.FromBase64String(text.Replace('-', '+').Replace('_', '/').PadRight((text.Length + 3) / 4 * 4, '='));
        if (bytes.Length > max || Encode(bytes) != text) throw new InvalidDataException("Noncanonical encoding.");
        return bytes;
    }
}
