using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

internal sealed record FleetTlsGrant(string Purpose, string EvidenceSha256, string KeyId, long Sequence,
    long ExpiresUnixSeconds, string Signature);

internal sealed record FleetTlsPlan(string Scope, string Installation, string ActiveDigest,
    string CandidateDigest, string PeerEvidenceSha256, string Nonce, string TransactionId, long Epoch)
{
    internal static bool Hex(string? value, int length = 64) => value is not null &&
        value.Length == length && value.All(c => c is >= 'A' and <= 'F' or >= '0' and <= '9');

    internal static FleetTlsPlan Create(string scope, string installation, string active, string candidate,
        string peerEvidence, string nonce)
    {
        if (!Hex(scope) || !Hex(installation) || !Hex(active) || !Hex(candidate) ||
            !Hex(peerEvidence) || !Hex(nonce, 32) || active == candidate)
            throw new ArgumentException("Invalid fleet certificate plan.");
        var canonical = string.Join("\n", "gatewaycore-fleet-tls-plan-v1", scope, installation,
            active, candidate, peerEvidence, nonce);
        var tx = "rollout_" + Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes(canonical)))[..24];
        return new(scope, installation, active, candidate, peerEvidence, nonce, tx, 0);
    }

    internal bool Valid()
    {
        try { return Epoch >= 0 && Create(Scope, Installation, ActiveDigest, CandidateDigest,
            PeerEvidenceSha256, Nonce).TransactionId == TransactionId; }
        catch (ArgumentException) { return false; }
    }

    internal JsonObject Payload(string purpose, string evidence) => new()
    {
        ["Purpose"] = "gatewaycore-fleet-tls-v1:" + purpose,
        ["Scope"] = Scope, ["Installation"] = Installation, ["Nonce"] = Nonce,
        ["ActiveDigest"] = ActiveDigest, ["CandidateDigest"] = CandidateDigest,
        ["PeerEvidenceSha256"] = PeerEvidenceSha256, ["EvidenceSha256"] = evidence
    };

    internal bool Verify(FleetTlsGrant grant, string publicPem, long now)
    {
        if (!Valid() || Epoch < 1 || grant.Sequence != Epoch ||
            grant.Purpose is not ("activate" or "activated" or "rolled-back") ||
            (grant.Purpose == "activate" ? grant.EvidenceSha256 != "" : !Hex(grant.EvidenceSha256)) ||
            !Hex(grant.KeyId, 32) || grant.Signature is not { Length: 88 }) return false;
        try
        {
            using var key = ECDsa.Create();
            key.ImportFromPem(publicPem);
            if (key.KeySize != 256 || FleetConfigSignature.KeyIdFromPublicKey(publicPem) != grant.KeyId)
                return false;
            return FleetConfigSignature.VerifyV2(new Dictionary<string,string> { [grant.KeyId] = publicPem },
                TransactionId, ActiveDigest, Payload(grant.Purpose, grant.EvidenceSha256),
                new(grant.KeyId, grant.Sequence, grant.ExpiresUnixSeconds, grant.Signature), now);
        }
        catch (Exception ex) when (ex is ArgumentException or CryptographicException) { return false; }
    }
}
