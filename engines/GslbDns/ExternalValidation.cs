using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Security.Cryptography.X509Certificates;

internal sealed class ExternalValidation : IDisposable
{
    private readonly X509Certificate2 certificate;
    private readonly HttpClient client;

    private readonly Dictionary<string, byte[]> signingKeys = new(StringComparer.OrdinalIgnoreCase);

    public static Uri[] Parse(string[]? values)
    {
        if (values is null) return [];
        if (values.Length != 2) throw new InvalidDataException("Exactly two validators required");
        var urls = values.Select(value =>
        {
            if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.Scheme != "https" ||
                uri.UserInfo.Length != 0 || uri.Fragment.Length != 0)
                throw new InvalidDataException("Invalid external validator URL");
            return uri;
        }).ToArray();
        if (urls[0].Authority.Equals(urls[1].Authority, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Validators require distinct origins");
        return urls;
    }

    public ExternalValidation(IEnumerable<Uri> urls)
    {
        var allowed = (Environment.GetEnvironmentVariable("GSLB_VALIDATOR_ORIGINS") ?? "")
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (urls.Any(url => !allowed.Contains(url.GetLeftPart(UriPartial.Authority))))
            throw new InvalidDataException("Validator origin not allowed by local operator");
        var pins = JsonSerializer.Deserialize<Dictionary<string, string>>(
            Environment.GetEnvironmentVariable("GSLB_VALIDATOR_SIGNING_KEYS") ?? "{}")
            ?? throw new InvalidDataException("Missing validator signing keys");
        var identities = new HashSet<string>(StringComparer.Ordinal);
        foreach (var origin in urls.Select(url => url.GetLeftPart(UriPartial.Authority)).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (!pins.TryGetValue(origin, out var path) || !Path.IsPathFullyQualified(path))
                throw new InvalidDataException("Missing pinned signing key for " + origin);
            using var key = ECDsa.Create();
            key.ImportFromPem(File.ReadAllText(path));
            if (key.ExportParameters(false).Curve.Oid.Value != "1.2.840.10045.3.1.7")
                throw new InvalidDataException("Observer signing key must be P-256");
            var publicKey = key.ExportSubjectPublicKeyInfo();
            if (!identities.Add(Convert.ToBase64String(publicKey)))
                throw new InvalidDataException("Distinct validator origins must have distinct signing keys");
            signingKeys.Add(origin, publicKey);
        }
        var certPath = Environment.GetEnvironmentVariable("GSLB_VALIDATOR_CERT_PEM");
        var keyPath = Environment.GetEnvironmentVariable("GSLB_VALIDATOR_KEY_PEM");
        if (!Path.IsPathFullyQualified(certPath ?? "") || !Path.IsPathFullyQualified(keyPath ?? ""))
            throw new InvalidDataException("Absolute validator credential paths required");
        using var pem = X509Certificate2.CreateFromPemFile(certPath!, keyPath!);
        // Schannel requires a persisted key handle for TLS client authentication.
        certificate = X509CertificateLoader.LoadPkcs12(pem.Export(X509ContentType.Pkcs12), null,
            X509KeyStorageFlags.DefaultKeySet);
        var handler = new HttpClientHandler { UseProxy = false, AllowAutoRedirect = false,
            UseCookies = false, ClientCertificateOptions = ClientCertificateOption.Manual };
        handler.ClientCertificates.Add(certificate);
        client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(1.5) };
    }

    public async Task<bool> ConfirmAsync(Uri[] urls, CancellationToken token)
    {
        var results = await Task.WhenAll(urls.Select(url => CheckAsync(url, token)));
        return results.All(success => success);
    }

    private async Task<bool> CheckAsync(Uri url, CancellationToken token)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            var challenge = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
            request.Headers.Add("Gslb-Challenge", challenge);
            request.Headers.CacheControl = new() { NoCache = true, NoStore = true };
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, token);
            if (!response.IsSuccessStatusCode ||
                !response.Headers.TryGetValues("Gslb-Signature", out var values)) return false;
            var signatures = values.Take(2).ToArray();
            if (signatures.Length != 1 || signatures[0].Length > 96) return false;
            var signature = Convert.FromBase64String(signatures[0]);
            var message = Encoding.UTF8.GetBytes(FormattableString.Invariant(
                $"GatewayCore.Health.v1\n{url.AbsoluteUri}\n{challenge}\n{(int)response.StatusCode}"));
            using var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(signingKeys[url.GetLeftPart(UriPartial.Authority)], out _);
            return key.VerifyData(message, signature, HashAlgorithmName.SHA256,
                DSASignatureFormat.Rfc3279DerSequence);
        }
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException or FormatException or CryptographicException)
        {
            return false;
        }
    }

    public void Dispose()
    {
        client.Dispose();
        certificate.Dispose();
    }
}
