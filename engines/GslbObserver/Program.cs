using System.Net;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.AspNetCore.Server.Kestrel.Https;

// One operator-configured service per observer instance.
if (args.Length != 1) throw new ArgumentException("Expected an observer JSON configuration path");
var config = System.Text.Json.JsonSerializer.Deserialize<ObserverConfig>(File.ReadAllText(args[0]))
    ?? throw new InvalidDataException("Missing observer configuration");
var bind = IPAddress.Parse(config.ListenAddress);
if (bind.Equals(IPAddress.Any) || bind.Equals(IPAddress.IPv6Any) ||
    config.Port is < 1025 or > 65535 || config.PublicUrl.Scheme != "https" ||
    config.PublicUrl.AbsolutePath != "/ready" || config.PublicUrl.Query.Length != 0 ||
    config.PublicUrl.Fragment.Length != 0 || config.PublicUrl.UserInfo.Length != 0 ||
    config.HealthUrl.Scheme is not ("http" or "https") || config.HealthUrl.UserInfo.Length != 0 ||
    config.HealthUrl.Fragment.Length != 0)
    throw new InvalidDataException("Invalid observer listener, public URL or readiness URL");
var pins = config.AllowedClientSha256.Select(Convert.FromHexString).ToArray();
if (pins.Length is < 1 or > 16 || pins.Any(pin => pin.Length != 32))
    throw new InvalidDataException("Expected 1-16 SHA-256 client certificate fingerprints");
using var pem = X509Certificate2.CreateFromPemFile(config.ServerCertificatePem, config.ServerKeyPem);
using var serverCert = X509CertificateLoader.LoadPkcs12(pem.Export(X509ContentType.Pkcs12), null);
using var signer = ECDsa.Create();
signer.ImportFromPem(File.ReadAllText(config.SigningKeyPem));
if (signer.ExportParameters(false).Curve.Oid.Value != "1.2.840.10045.3.1.7")
    throw new InvalidDataException("A P-256 signing key is required");
// Verify signing capability before advertising readiness.
_ = signer.SignData(Array.Empty<byte>(), HashAlgorithmName.SHA256);
var builder = WebApplication.CreateSlimBuilder();
builder.WebHost.ConfigureKestrel(k =>
{
    k.Limits.MaxConcurrentConnections = 64;
    k.Limits.MaxRequestHeadersTotalSize = 8192;
    k.Listen(bind, config.Port, endpoint => endpoint.UseHttps(options =>
    {
        options.ServerCertificate = serverCert;
        options.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
        options.ClientCertificateValidation = (cert, _, errors) =>
            errors == SslPolicyErrors.None &&
            pins.Any(pin => CryptographicOperations.FixedTimeEquals(pin, cert.GetCertHash(HashAlgorithmName.SHA256)));
    }));
});
await using var app = builder.Build();
using var client = new HttpClient(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false,
    UseCookies = false }) { Timeout = TimeSpan.FromMilliseconds(900) };
using var slots = new SemaphoreSlim(8);
app.MapGet("/ready", async (HttpContext context) =>
{
    var challenge = context.Request.Headers["Gslb-Challenge"].ToString();
    if (context.Request.QueryString.HasValue || challenge.Length != 64 ||
        challenge.Any(ch => ch is not (>= '0' and <= '9' or >= 'A' and <= 'F')))
        return Results.BadRequest();
    if (!slots.Wait(0)) return Results.StatusCode(503);
    try
    {
        using var probe = new HttpRequestMessage(HttpMethod.Get, config.HealthUrl);
        probe.Headers.CacheControl = new() { NoCache = true, NoStore = true };
        using var response = await client.SendAsync(probe, HttpCompletionOption.ResponseHeadersRead, context.RequestAborted);
        if (!response.IsSuccessStatusCode) return Results.StatusCode(503);
        var message = Encoding.UTF8.GetBytes($"GatewayCore.Health.v1\n{config.PublicUrl.AbsoluteUri}\n{challenge}\n200");
        byte[] signature;
        lock (signer) signature = signer.SignData(message, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        context.Response.Headers["Gslb-Signature"] = Convert.ToBase64String(signature);
        context.Response.Headers.CacheControl = "no-store";
        return Results.Ok();
    }
    catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException)
    {
        return Results.StatusCode(503);
    }
    finally { slots.Release(); }
});
await app.RunAsync();

sealed record ObserverConfig(string ListenAddress, int Port, Uri PublicUrl, Uri HealthUrl,
    string ServerCertificatePem, string ServerKeyPem, string SigningKeyPem, string[] AllowedClientSha256);
