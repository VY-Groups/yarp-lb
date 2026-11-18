using System.Security.Cryptography.X509Certificates;

/// <summary>Temporarily trusts only the generated CA used by Windows CRL socket acceptance.</summary>
public static class WindowsCrlTestRootStore
{
    private const string TestRootSubject = "CN=GatewayCore disposable CRL root";

    public static void Add(string certificatePath)
    {
        Console.WriteLine("CRL test root add: loading generated public CA");
        using var certificate = X509CertificateLoader.LoadCertificateFromFile(certificatePath);
        if (certificate.HasPrivateKey || certificate.Subject != TestRootSubject ||
            !certificate.Extensions.OfType<X509BasicConstraintsExtension>()
                .Any(extension => extension.CertificateAuthority))
            throw new InvalidOperationException("Only the public disposable GatewayCore CRL test root may be installed");
        Console.WriteLine("CRL test root add: opening CurrentUser Root store");
        using var store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadWrite);
        Console.WriteLine("CRL test root add: adding generated public CA");
        store.Add(certificate);
        Console.WriteLine("CRL test root add: store.Add completed");
    }

    public static int Remove(string thumbprint)
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
        return matches.Count;
    }
}
