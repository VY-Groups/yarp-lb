using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using Yarp.ReverseProxy.Forwarder;

/// <summary>
/// Secure outbound certificate identity for a YARP CLUSTER, backed by the local
/// OS certificate store. No PFX/private key passwords or insecure TLS bypass in config.
/// </summary>
public static class BackendMutualTls
{
    public const string MetadataKey = "BackendClientCertificateThumbprint";

    public static bool TryNormalizeThumbprint(string? raw, out string normalized)
    {
        normalized = raw?.Replace(" ", "", StringComparison.Ordinal)
            .Replace(":", "", StringComparison.Ordinal).ToUpperInvariant() ?? "";
        return Regex.IsMatch(normalized, "^[A-F0-9]{40}$", RegexOptions.CultureInvariant);
    }

    public static X509Certificate2 Resolve(string thumbprint)
    {
        if (!TryNormalizeThumbprint(thumbprint, out var canonical))
            throw new InvalidOperationException("Client certificate thumbprint must contain 40 hex characters.");
        using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadOnly);
        var found = store.Certificates.Find(X509FindType.FindByThumbprint, canonical, validOnly: true);
        if (found.Count != 1 || !found[0].HasPrivateKey)
            throw new InvalidOperationException("Client certificate missing, invalid, untrusted or lacks private key.");
        var certificate = found[0];
        if (certificate.NotBefore.ToUniversalTime() > DateTime.UtcNow ||
            certificate.NotAfter.ToUniversalTime() <= DateTime.UtcNow)
            throw new InvalidOperationException("Backend client certificate expired or not yet valid.");
        var eku = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().ToArray();
        if (eku.Length == 0 || !eku.Any(x => x.EnhancedKeyUsages.Cast<Oid>()
            .Any(y => y.Value == "1.3.6.1.5.5.7.3.2")))
            throw new InvalidOperationException("Backend identity certificate requires Client Authentication EKU.");
        return certificate;
    }

    public static void Configure(ForwarderHttpClientContext context, SocketsHttpHandler handler)
    {
        if (context.NewMetadata is null ||
            !context.NewMetadata.TryGetValue(MetadataKey, out var thumbprint) ||
            string.IsNullOrWhiteSpace(thumbprint)) return;
        // Recreates the per-cluster handler on metadata changes, retaining inbound
        // traffic independence. Existing data-plane trust rules remain intact.
        var cert = Resolve(thumbprint);
        handler.SslOptions.ClientCertificates ??= new X509CertificateCollection();
        handler.SslOptions.ClientCertificates.Add(cert);
    }
}
