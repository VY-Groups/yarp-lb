using System.Security.Cryptography.X509Certificates;

/// <summary>Temporarily trusts only the generated CA used by Windows CRL socket acceptance.</summary>
public static class WindowsCrlTestRootStore
{
    private const string TestRootSubject = "CN=GatewayCore disposable CRL root";

    public static void Add(string certificatePath)
    {
        using var certificate = X509CertificateLoader.LoadCertificateFromFile(certificatePath);
        if (certificate.HasPrivateKey || certificate.Subject != TestRootSubject ||
            !certificate.Extensions.OfType<X509BasicConstraintsExtension>()
                .Any(extension => extension.CertificateAuthority))
            throw new InvalidOperationException("Only the public disposable GatewayCore CRL test root may be installed");
        using var store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadWrite);
        store.Add(certificate);
    }

    public static void Remove(string thumbprint)
    {
        var normalized = thumbprint.Replace(" ", "", StringComparison.Ordinal).ToUpperInvariant();
        if (normalized.Length != 40 || normalized.Any(c => !Uri.IsHexDigit(c)))
            throw new ArgumentException("Invalid disposable test-root thumbprint", nameof(thumbprint));

        using var store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadWrite);
        var matches = store.Certificates.Find(X509FindType.FindByThumbprint, normalized, validOnly: false);
        foreach (var certificate in matches)
        {
            if (certificate.HasPrivateKey || certificate.Subject != TestRootSubject)
                throw new InvalidOperationException("Refusing to remove a certificate other than the disposable GatewayCore CRL test root");
            store.Remove(certificate);
        }
    }
}
