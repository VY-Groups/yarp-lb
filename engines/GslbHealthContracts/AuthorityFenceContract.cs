using System.Security.Cryptography;
using System.Text.Json;

namespace GatewayCore.Gslb.Contracts;

/// <summary>A complete two-authority health decision snapshot. A receiver never
/// merges partial site lists; every configured site must be present exactly once.</summary>
public sealed record AuthorityFenceDecision(string Zone, string SiteId, bool Eligible);

public sealed record AuthorityFenceSnapshot(int Version, string AuthorityId, string PeerId,
    string ConfigurationSha256, long Epoch, long Sequence, long IssuedAtUnixSeconds,
    int LeaseSeconds, AuthorityFenceDecision[] Decisions, string Signature);

public static class AuthorityFenceContract
{
    public const int CurrentVersion = 1;
    public const int MaximumSites = 1024;
    public const int MaximumSerializedBytes = 131072;

    public static byte[] SerializeUnsigned(AuthorityFenceSnapshot snapshot) =>
        JsonSerializer.SerializeToUtf8Bytes(snapshot with { Signature = string.Empty });

    public static string Sign(AuthorityFenceSnapshot snapshot, ECDsa privateKey) =>
        Convert.ToBase64String(privateKey.SignData(SerializeUnsigned(snapshot), HashAlgorithmName.SHA256,
            DSASignatureFormat.Rfc3279DerSequence));

    public static bool Verify(AuthorityFenceSnapshot snapshot, ECDsa publicKey)
    {
        if (string.IsNullOrEmpty(snapshot.Signature) || snapshot.Signature.Length is < 80 or > 128) return false;
        byte[] signature;
        try { signature = Convert.FromBase64String(snapshot.Signature); }
        catch (FormatException) { return false; }
        return publicKey.VerifyData(SerializeUnsigned(snapshot), signature, HashAlgorithmName.SHA256,
            DSASignatureFormat.Rfc3279DerSequence);
    }
}
