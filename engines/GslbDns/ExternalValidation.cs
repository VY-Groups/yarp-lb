using System.Security.Cryptography.X509Certificates;

internal sealed class ExternalValidation : IDisposable
{
    private readonly X509Certificate2 certificate;
    private readonly HttpClient client;

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
            request.Headers.CacheControl = new() { NoCache = true, NoStore = true };
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, token);
            return response.IsSuccessStatusCode;
        }
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException)
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
