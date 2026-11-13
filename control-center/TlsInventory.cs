using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Authorization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

/// <summary>
/// Read-only, authenticated certificate and Kestrel listener readiness inventory.
/// Never reveals certificate private keys or changes running TLS configuration.
/// </summary>
public static class TlsInventory
{
    public static string ExpiryState(DateTime expiryUtc, DateTime nowUtc) =>
        expiryUtc <= nowUtc ? "expired" :
        expiryUtc <= nowUtc.AddDays(30) ? "expiring-within-30-days" : "valid-date-only";

    public static void MapTlsInventory(this WebApplication app)
    {
        app.MapGet("/admin/api/tls/inventory", (IConfiguration cfg) =>
        {
            var endpoints = cfg.GetSection("Kestrel:Endpoints").GetChildren().Select(x => new
            {
                name = x.Key,
                scheme = (x["Url"] ?? "").StartsWith("https://", StringComparison.OrdinalIgnoreCase)
                    ? "https" : "other-or-http",
                certificateReferenceConfigured = x.GetSection("Certificate").GetChildren().Any() ||
                    cfg.GetSection("Kestrel:Certificates:Default").GetChildren().Any()
            }).ToArray();
            var certificates = new List<object>();
            var storeState = "available";
            try
            {
                using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
                store.Open(OpenFlags.ReadOnly);
                foreach (var cert in store.Certificates.Cast<X509Certificate2>().OrderBy(x => x.NotAfter).Take(250))
                {
                    certificates.Add(new
                    {
                        subject = cert.Subject,
                        issuer = cert.Issuer,
                        thumbprint = cert.Thumbprint,
                        serialNumber = cert.SerialNumber,
                        notBeforeUtc = cert.NotBefore.ToUniversalTime(),
                        notAfterUtc = cert.NotAfter.ToUniversalTime(),
                        expiryState = ExpiryState(cert.NotAfter.ToUniversalTime(), DateTime.UtcNow),
                        privateKeyAvailable = cert.HasPrivateKey,
                        serverAuthenticationEku = !cert.Extensions.OfType<X509EnhancedKeyUsageExtension>().Any() ||
                            cert.Extensions.OfType<X509EnhancedKeyUsageExtension>().Any(eku =>
                                eku.EnhancedKeyUsages.Cast<Oid>().Any(oid => oid.Value == "1.3.6.1.5.5.7.3.1"))
                    });
                }
            }
            catch (Exception ex) when (ex is CryptographicException or PlatformNotSupportedException or UnauthorizedAccessException)
            { storeState = "unavailable"; }
            return Results.Ok(new
            {
                scope = "local-machine certificate store read only; no chain validation, renewal or private key export",
                gateway = Environment.MachineName,
                timestampUtc = DateTimeOffset.UtcNow,
                storeState,
                certificates,
                configuredEndpoints = endpoints,
                acmeIntegration = "not-implemented",
                backendMutualTlsProvisioning = "not-implemented"
            });
        }).RequireAuthorization(p => p.RequireRole("Administrator", "Operator"));
    }
}
