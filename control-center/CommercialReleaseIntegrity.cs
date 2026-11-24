#if GATEWAYCORE_COMMERCIAL && GATEWAYCORE_RELEASE_PACKAGE
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using GatewayCore.Licensing;

internal static class CommercialReleaseIntegrity
{
    internal static string Verify()
    {
        var assembly = Assembly.GetExecutingAssembly();
        var releaseKeys = ReadTrust(assembly, "GatewayCore.ReleaseTrust");
        var entitlementKeys = ReadTrust(assembly, "GatewayCore.CommercialTrust");
        // Compare normalized public key fingerprints, not just key identifiers.
        var entitlementFingerprints = entitlementKeys.Values.Select(Fingerprint).ToHashSet(StringComparer.Ordinal);
        if (releaseKeys.Values.Any(key => entitlementFingerprints.Contains(Fingerprint(key))))
            throw new CryptographicException("Release trust must be independent of entitlement trust.");
        var commit = assembly.GetCustomAttributes<AssemblyMetadataAttribute>()
            .Single(x => x.Key == "GatewayCoreReleaseSourceCommit").Value
            ?? throw new InvalidDataException("Missing pinned release source.");
        return new ReleaseIntegrityVerifier(releaseKeys).Verify(AppContext.BaseDirectory, commit);
    }

    private static string Fingerprint(byte[] value)
    {
        using var key = ECDsa.Create();
        key.ImportSubjectPublicKeyInfo(value, out var read);
        if (read != value.Length) throw new CryptographicException("Invalid public key.");
        return Convert.ToHexString(SHA256.HashData(key.ExportSubjectPublicKeyInfo()));
    }

    private static Dictionary<string,byte[]> ReadTrust(Assembly assembly, string resource)
    {
        using var stream = assembly.GetManifestResourceStream(resource)
            ?? throw new InvalidDataException("Missing pinned public trust resource.");
        if (stream.Length is < 1 or > 16384) throw new InvalidDataException("Invalid public trust size.");
        return JsonSerializer.Deserialize<Dictionary<string,byte[]>>(stream)
            ?? throw new InvalidDataException("Missing public trust keys.");
    }
}
#endif
