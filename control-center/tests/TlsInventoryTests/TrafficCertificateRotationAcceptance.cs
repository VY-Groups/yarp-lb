using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

internal static class TrafficCertificateRotationAcceptance
{
    public static async Task RunAsync()
    {
        static void Check(bool condition, string message)
        {
            if (!condition) throw new Exception("FAIL: " + message);
        }

        var rootDir = Path.Combine(Path.GetTempPath(), "gatewaycore-cert-rotation-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(rootDir);
        var keyBaseline = TrafficCertificateRotation.ActiveWindowsKeyContainerCount;
        try
        {
            if (OperatingSystem.IsLinux()) File.SetUnixFileMode(rootDir, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            var pfxPath = Path.Combine(rootDir, "traffic.pfx");
            var passwordPath = Path.Combine(rootDir, "traffic.pwd");
            const string password = "disposable-test-password";
            await File.WriteAllTextAsync(passwordPath, password);
            if (OperatingSystem.IsLinux()) File.SetUnixFileMode(passwordPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);

            using var rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var rootRequest = new CertificateRequest("CN=Rotation Test Root", rootKey, HashAlgorithmName.SHA256);
            rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            rootRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            rootRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(rootRequest.PublicKey, false));
            using var root = rootRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-30), DateTimeOffset.UtcNow.AddDays(30));
            var testChainPolicy = new X509ChainPolicy
            {
                TrustMode = X509ChainTrustMode.CustomRootTrust,
                RevocationMode = X509RevocationMode.NoCheck
            };
            testChainPolicy.CustomTrustStore.Add(root);

            X509Certificate2 CreateLeaf(string commonName, string dnsName, DateTimeOffset notBefore, DateTimeOffset notAfter)
            {
                using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                var request = new CertificateRequest($"CN={commonName}", key, HashAlgorithmName.SHA256);
                var san = new SubjectAlternativeNameBuilder();
                san.AddDnsName(dnsName);
                request.CertificateExtensions.Add(san.Build());
                var eku = new OidCollection { new("1.3.6.1.5.5.7.3.1") };
                request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(eku, true));
                request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
                var serial = RandomNumberGenerator.GetBytes(16);
                using var publicCert = request.Create(root, notBefore, notAfter, serial);
                return publicCert.CopyWithPrivateKey(key);
            }

            void WritePfx(string targetPath, X509Certificate2 leaf)
            {
                var collection = new X509Certificate2Collection { leaf, root };
                File.WriteAllBytes(targetPath, collection.Export(X509ContentType.Pkcs12, password)!);
                if (OperatingSystem.IsLinux()) File.SetUnixFileMode(targetPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }

            var first = CreateLeaf("api.example.test", "api.example.test", DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(10));
            var second = CreateLeaf("api.example.test", "api.example.test", DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(10));
            var third = CreateLeaf("api.example.test", "api.example.test", DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(10));
            var wrongName = CreateLeaf("wrong.example.test", "wrong.example.test", DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(10));
            var expired = CreateLeaf("api.example.test", "api.example.test", DateTimeOffset.UtcNow.AddDays(-10), DateTimeOffset.UtcNow.AddDays(-1));
            WritePfx(pfxPath, first);
            var stagePfx = Path.Combine(rootDir, "traffic.next");

            using var rotation = new TrafficCertificateRotation(pfxPath, passwordPath,
                ["api.example.test"], testChainPolicy);
            Check(rotation.Current.Thumbprint == first.Thumbprint, "initial PFX is loaded");
            Check(rotation.Select("api.example.test")?.Thumbprint == first.Thumbprint, "configured SNI selects active cert");
            Check(rotation.Select("other.example.test") is null, "unknown SNI has no certificate fallback");

            var builder = WebApplication.CreateBuilder();
            builder.Logging.SetMinimumLevel(LogLevel.Warning);
            // The shipping host registers the isolated listener by factory, so the
            // container disposes its certificate rotation and persisted key handles.
            builder.Services.AddSingleton<TrafficCertificateRotation>(_ => rotation);
            builder.WebHost.ConfigureKestrel(options => options.Listen(IPAddress.Loopback, 0, listen =>
                listen.UseHttps(new HttpsConnectionAdapterOptions
                {
                    HandshakeTimeout = TimeSpan.FromSeconds(10),
                    ServerCertificateSelector = (_, name) => rotation.Select(name)
                })));
            await using var app = builder.Build();
            app.MapGet("/", () => Results.Ok());
            await app.StartAsync();
            Check(ReferenceEquals(app.Services.GetRequiredService<TrafficCertificateRotation>(), rotation),
                "host owns the registered traffic certificate rotation instance");
            var address = app.Services.GetRequiredService<Microsoft.AspNetCore.Hosting.Server.IServer>()
                .Features.Get<Microsoft.AspNetCore.Hosting.Server.Features.IServerAddressesFeature>()!
                .Addresses.Single(address => address.StartsWith("https://", StringComparison.OrdinalIgnoreCase));
            var port = new Uri(address).Port;

            async Task<string> GetPeerThumbprintAsync()
            {
                string? thumbprint = null;
                using var client = new TcpClient();
                await client.ConnectAsync(IPAddress.Loopback, port);
                using var tls = new SslStream(client.GetStream(), leaveInnerStreamOpen: false,
                    (_, certificate, _, _) =>
                    {
                        thumbprint = certificate?.GetCertHashString();
                        return true; // Disposable test chain; the server validates its candidate.
                    });
                await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    TargetHost = "api.example.test"
                });
                return thumbprint ?? throw new Exception("TLS peer certificate was not observed");
            }

            Check(await GetPeerThumbprintAsync() == first.Thumbprint, "first live Kestrel TLS handshake uses original cert");
            WritePfx(stagePfx, second);
            File.Move(stagePfx, pfxPath, overwrite: true);
            using (var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(8)))
            {
                while (rotation.Current.Thumbprint != second.Thumbprint)
                    await Task.Delay(50, timeout.Token);
            }
            Check(await GetPeerThumbprintAsync() == second.Thumbprint, "new Kestrel TLS handshakes use rotated cert without restart");
            Check(rotation.RetiredCertificateCount <= 4, "retired certificate handle count remains bounded");

            // A valid update inside the minimum-rotation interval must be queued and
            // applied after the bound, rather than left stranded on disk.
            await Task.Delay(TimeSpan.FromMilliseconds(750));
            WritePfx(stagePfx, third);
            File.Move(stagePfx, pfxPath, overwrite: true);
            using (var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10)))
            {
                while (rotation.Current.Thumbprint != third.Thumbprint)
                    await Task.Delay(50, timeout.Token);
            }
            Check(await GetPeerThumbprintAsync() == third.Thumbprint, "a repeated renewal switches later handshakes");

            async Task AssertRejectedCandidateAndKeepsLastGoodAsync(string name, X509Certificate2? candidate)
            {
                var lastGoodThumbprint = rotation.Current.Thumbprint;
                var priorRejections = rotation.RejectedCandidateCount;
                if (candidate is not null) WritePfx(stagePfx, candidate);
                else await File.WriteAllTextAsync(stagePfx, "not-a-pkcs12-file");
                if (OperatingSystem.IsLinux()) File.SetUnixFileMode(stagePfx, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                File.Move(stagePfx, pfxPath, overwrite: true);
                using (var rejectionTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(5)))
                {
                    while (rotation.RejectedCandidateCount == priorRejections)
                        await Task.Delay(50, rejectionTimeout.Token);
                }
                var expectedFailure = candidate is null ? "CryptographicException" : "InvalidOperationException";
                Check(rotation.LastRejectedCandidateFailure == expectedFailure,
                    $"{name} candidate is rejected by its expected validation path");
                Check(rotation.Current.Thumbprint == lastGoodThumbprint, $"{name} candidate retains last-good certificate");
                Check(await GetPeerThumbprintAsync() == lastGoodThumbprint, $"live Kestrel continues serving last-good after {name} candidate");
            }

            await AssertRejectedCandidateAndKeepsLastGoodAsync("malformed", null);
            await AssertRejectedCandidateAndKeepsLastGoodAsync("wrong-SAN", wrongName);
            await AssertRejectedCandidateAndKeepsLastGoodAsync("expired", expired);

            await app.StopAsync();
            await app.DisposeAsync();
            if (OperatingSystem.IsWindows())
                Check(TrafficCertificateRotation.ActiveWindowsKeyContainerCount == keyBaseline,
                    "host shutdown removes all temporary Windows user key containers");
            first.Dispose(); second.Dispose(); third.Dispose(); wrongName.Dispose(); expired.Dispose();
            Console.WriteLine("PASS: live Kestrel TLS rotation, last-good rollback and host key cleanup");
        }
        finally
        {
            if (Directory.Exists(rootDir)) Directory.Delete(rootDir, recursive: true);
        }
    }
}
