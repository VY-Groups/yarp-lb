using System.Net;
using System.Net.Http;
using System.Net.Quic;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.Versioning;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.Logging;

internal static class TrafficHttp3Acceptance
{
    private sealed class TestCertificate : IDisposable
    {
        public X509Certificate2 Certificate { get; }
        private readonly ECDsa signingKey;
        private readonly string? cngUniqueName;
        private readonly CngProvider? cngProvider;

        public TestCertificate(X509Certificate2 certificate, ECDsa signingKey)
        {
            Certificate = certificate;
            this.signingKey = signingKey;
            if (signingKey is ECDsaCng cng)
            {
                cngUniqueName = cng.Key.UniqueName;
                cngProvider = cng.Key.Provider;
            }
        }

        public void Dispose()
        {
            Certificate.Dispose();
            signingKey.Dispose();
            if (!OperatingSystem.IsWindows() || cngUniqueName is null || cngProvider is null) return;
            DeleteWindowsKey(cngUniqueName, cngProvider);
        }

        [SupportedOSPlatform("windows")]
        private static void DeleteWindowsKey(string name, CngProvider provider)
        {
            using var key = CngKey.Open(name, provider, CngKeyOpenOptions.UserKey);
            key.Delete();
        }
    }

    public static async Task RunAsync()
    {
        static void Check(bool condition, string message)
        {
            if (!condition) throw new Exception("FAIL: " + message);
        }

        Check(TrafficHttpProtocols.Parse("1.1") == Microsoft.AspNetCore.Server.Kestrel.Core.HttpProtocols.Http1,
            "legacy HTTP/1.1 mode remains unchanged");
        Check(TrafficHttpProtocols.Parse("2") == Microsoft.AspNetCore.Server.Kestrel.Core.HttpProtocols.Http2,
            "legacy HTTP/2 mode remains unchanged");
        Check(TrafficHttpProtocols.Parse("3") == Microsoft.AspNetCore.Server.Kestrel.Core.HttpProtocols.Http1AndHttp2AndHttp3,
            "HTTP/3 mode retains HTTP/1.1 and HTTP/2 over TCP");
        try
        {
            _ = TrafficHttpProtocols.Parse("invalid");
            throw new Exception("FAIL: invalid listener protocol was accepted");
        }
        catch (InvalidOperationException) { }

        if (!QuicConnection.IsSupported)
        {
            Console.WriteLine("SKIP: real QUIC protocol requests require MsQuic, which is unavailable on this runner; H1/H2/H3 configuration parser checks passed");
            return;
        }

        int GetAvailableDualTransportPort()
        {
            for (var attempt = 0; attempt < 8; attempt++)
            {
                using var tcp = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                tcp.Bind(new IPEndPoint(IPAddress.Loopback, 0));
                var port = ((IPEndPoint)tcp.LocalEndPoint!).Port;
                using var udp = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                try
                {
                    udp.Bind(new IPEndPoint(IPAddress.Loopback, port));
                    return port;
                }
                catch (SocketException) when (attempt < 7) { }
            }
            throw new SocketException((int)SocketError.AddressAlreadyInUse);
        }

        var key = OperatingSystem.IsWindows()
            ? CreatePersistedWindowsKey()
            : ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=localhost", key, HashAlgorithmName.SHA256);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("localhost");
        san.AddIpAddress(IPAddress.Loopback);
        request.CertificateExtensions.Add(san.Build());
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        var eku = new OidCollection { new("1.3.6.1.5.5.7.3.1") };
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(eku, true));
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(2));
        using var testCertificate = new TestCertificate(certificate, key);

        var builder = WebApplication.CreateBuilder();
        builder.Logging.SetMinimumLevel(LogLevel.Warning);
        var port = GetAvailableDualTransportPort();
        builder.WebHost.ConfigureKestrel(options => options.Listen(IPAddress.Loopback, port, listen =>
        {
            listen.Protocols = TrafficHttpProtocols.Parse("3");
            listen.UseHttps(new HttpsConnectionAdapterOptions
            {
                ServerCertificate = testCertificate.Certificate,
                SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                HandshakeTimeout = TimeSpan.FromSeconds(10)
            });
        }));
        await using var app = builder.Build();
        app.MapGet("/protocol", (HttpContext context) => Results.Text(context.Request.Protocol));
        await app.StartAsync();
        using var handler = new SocketsHttpHandler
        {
            UseProxy = false,
            SslOptions = new SslClientAuthenticationOptions
            {
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                RemoteCertificateValidationCallback = (_, _, _, _) => true
            }
        };
        using var client = new HttpClient(handler);
        var endpoint = new Uri($"https://127.0.0.1:{port}/protocol");

        async Task AssertProtocolAsync(Version version, string expected)
        {
            using var message = new HttpRequestMessage(HttpMethod.Get, endpoint)
            {
                Version = version,
                VersionPolicy = HttpVersionPolicy.RequestVersionExact
            };
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            using var response = await client.SendAsync(message, timeout.Token);
            var actual = await response.Content.ReadAsStringAsync(timeout.Token);
            Check(response.IsSuccessStatusCode && response.Version == version && actual == expected,
                $"configured listener negotiates {expected}; status={response.StatusCode}, version={response.Version}, body={actual}");
            Check(response.Headers.TryGetValues("Alt-Svc", out var headers) &&
                headers.Any(value => value == $"h3=\":{port}\""),
                $"{expected} response advertises HTTP/3 on the configured TLS port; received={string.Join("|", response.Headers.SelectMany(header => header.Value.Select(value => header.Key + ":" + value)))}");
        }

        await AssertProtocolAsync(HttpVersion.Version11, "HTTP/1.1");
        await AssertProtocolAsync(HttpVersion.Version20, "HTTP/2");
        await AssertProtocolAsync(HttpVersion.Version30, "HTTP/3");
        Console.WriteLine("PASS: real TLS listener accepted HTTP/1.1, HTTP/2 and QUIC HTTP/3");
    }

    [SupportedOSPlatform("windows")]
    private static ECDsa CreatePersistedWindowsKey()
    {
        var parameters = new CngKeyCreationParameters
        {
            Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider,
            KeyUsage = CngKeyUsages.Signing
        };
        var key = CngKey.Create(CngAlgorithm.ECDsaP256, "GatewayCore-HTTP3-" + Guid.NewGuid().ToString("N"), parameters);
        return new ECDsaCng(key);
    }
}
