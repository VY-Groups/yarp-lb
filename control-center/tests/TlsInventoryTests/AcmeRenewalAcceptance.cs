using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Certes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.DependencyInjection;

internal static class AcmeRenewalAcceptance
{
    private const string DnsName = "api.example.com";
    private const string DirectoryUrl = "https://acme-staging-v02.api.letsencrypt.org/directory";

    public static async Task RunAsync()
    {
        static void Check(bool condition, string message)
        {
            if (!condition) throw new Exception("FAIL: " + message);
        }

        var rootDir = Path.Combine(Path.GetTempPath(), "gatewaycore-acme-renewal-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(rootDir);
        if (OperatingSystem.IsLinux()) File.SetUnixFileMode(rootDir,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        const string password = "fake-ca-pfx-password";
        var passwordPath = Path.Combine(rootDir, "traffic.pwd");
        var activePfxPath = Path.Combine(rootDir, "traffic.pfx");
        await File.WriteAllTextAsync(passwordPath, password);
        SetPrivate(passwordPath);

        using var rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var rootRequest = new CertificateRequest("CN=Deterministic ACME Test CA", rootKey, HashAlgorithmName.SHA256);
        rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        using var root = rootRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-2), DateTimeOffset.UtcNow.AddDays(180));
        var chainPolicy = new X509ChainPolicy
        {
            TrustMode = X509ChainTrustMode.CustomRootTrust,
            RevocationMode = X509RevocationMode.NoCheck
        };
        chainPolicy.CustomTrustStore.Add(root);

        X509Certificate2 CreateLeaf(string dns, DateTimeOffset notAfter)
        {
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var request = new CertificateRequest("CN=" + dns, key, HashAlgorithmName.SHA256);
            var san = new SubjectAlternativeNameBuilder();
            san.AddDnsName(dns);
            request.CertificateExtensions.Add(san.Build());
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                new OidCollection { new("1.3.6.1.5.5.7.3.1") }, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
            using var issued = request.Create(root, DateTimeOffset.UtcNow.AddMinutes(-2), notAfter,
                RandomNumberGenerator.GetBytes(16));
            return issued.CopyWithPrivateKey(key);
        }

        byte[] ToPfx(X509Certificate2 leaf)
        {
            var collection = new X509Certificate2Collection { leaf, root };
            return collection.Export(X509ContentType.Pkcs12, password)!;
        }

        using var activeLeaf = CreateLeaf(DnsName, DateTimeOffset.UtcNow.AddDays(5));
        using var replacementLeaf = CreateLeaf(DnsName, DateTimeOffset.UtcNow.AddDays(90));
        using var wrongNameLeaf = CreateLeaf("other.example.com", DateTimeOffset.UtcNow.AddDays(90));
        await File.WriteAllBytesAsync(activePfxPath, ToPfx(activeLeaf));
        SetPrivate(activePfxPath);
        var settingsPath = Path.Combine(rootDir, "acme.json");
        await File.WriteAllTextAsync(settingsPath, System.Text.Json.JsonSerializer.Serialize(
            new AcmeRenewalSettings(DirectoryUrl, DnsName, "admin@example.com", activePfxPath,
                passwordPath, RenewalWindowDays: 30, AgreeToTermsOfService: true)));
        SetPrivate(settingsPath);
        var settings = AcmeRenewalSettings.Load(settingsPath, activePfxPath, passwordPath, [DnsName]);
        Check(settings.DnsName == DnsName && settings.RenewalWindowDays == 30,
            "strict ACME configuration binds to the configured listener hostname and PFX paths");
        await File.WriteAllTextAsync(settingsPath, System.Text.Json.JsonSerializer.Serialize(settings with
        {
            DirectoryUrl = "https://acme-v02.api.letsencrypt.org/directory",
            AllowProductionCa = false
        }));
        SetPrivate(settingsPath);
        var productionRejected = false;
        try { _ = AcmeRenewalSettings.Load(settingsPath, activePfxPath, passwordPath, [DnsName]); }
        catch (InvalidOperationException) { productionRejected = true; }
        Check(productionRejected, "production ACME directory is blocked until explicitly enabled");
        await File.WriteAllTextAsync(settingsPath, System.Text.Json.JsonSerializer.Serialize(settings with
        {
            AgreeToTermsOfService = false
        }));
        SetPrivate(settingsPath);
        var termsRejected = false;
        try { _ = AcmeRenewalSettings.Load(settingsPath, activePfxPath, passwordPath, [DnsName]); }
        catch (InvalidOperationException) { termsRejected = true; }
        Check(termsRejected, "ACME renewal requires explicit terms-of-service acknowledgment");
        await File.WriteAllTextAsync(settingsPath, System.Text.Json.JsonSerializer.Serialize(settings));
        SetPrivate(settingsPath);

        // The account key remains decryptable across provider re-creation, and disk stores
        // only protected ciphertext rather than the ACME private-key PEM.
        var dataProtectionPath = Path.Combine(rootDir, "test-dpkeys");
        Directory.CreateDirectory(dataProtectionPath);
        if (OperatingSystem.IsLinux()) File.SetUnixFileMode(dataProtectionPath,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        var dataProtection = DataProtectionProvider.Create(new DirectoryInfo(dataProtectionPath));
        var keyPath = Path.Combine(rootDir, "acme-account.bin");
        var firstKey = new AcmeAccountKeyStore(keyPath, dataProtection.CreateProtector("acceptance")).LoadOrCreate();
        var accountPem = firstKey.ToPem();
        var storedBytes = await File.ReadAllBytesAsync(keyPath);
        Check(!Encoding.UTF8.GetString(storedBytes).Contains("BEGIN PRIVATE KEY", StringComparison.Ordinal),
            "account private key is encrypted at rest");
        var restartedDataProtection = DataProtectionProvider.Create(new DirectoryInfo(dataProtectionPath));
        var secondKey = new AcmeAccountKeyStore(keyPath, restartedDataProtection.CreateProtector("acceptance")).LoadOrCreate();
        Check(secondKey.ToPem() == accountPem, "persisted ACME account key survives a store restart");

        var challengeStore = new AcmeHttp01ChallengeStore();
        var httpPort = -1;
        TrafficCertificateRotation? rotation = null;
        WebApplication? app = null;
        try
        {
            rotation = new TrafficCertificateRotation(activePfxPath, passwordPath, [DnsName], chainPolicy);
            var builder = WebApplication.CreateBuilder();
            builder.Services.AddSingleton(challengeStore);
            builder.WebHost.ConfigureKestrel(options =>
            {
                options.Listen(IPAddress.Loopback, 0, listen => listen.Protocols = Microsoft.AspNetCore.Server.Kestrel.Core.HttpProtocols.Http1);
                options.Listen(IPAddress.Loopback, 0, listen => listen.UseHttps(new HttpsConnectionAdapterOptions
                {
                    ServerCertificateSelector = (_, name) => rotation.Select(name)
                }));
            });
            app = builder.Build();
            app.MapGet("/", () => Results.Ok());
            app.MapHttp01Challenge(true, context => AcmeHttp01Endpoint.IsPublicTrafficHttpListener(
                context, IPAddress.Loopback, httpPort));
            await app.StartAsync();
            var addresses = app.Services.GetRequiredService<Microsoft.AspNetCore.Hosting.Server.IServer>()
                .Features.Get<Microsoft.AspNetCore.Hosting.Server.Features.IServerAddressesFeature>()!.Addresses;
            var httpAddress = addresses.Single(value => value.StartsWith("http://", StringComparison.OrdinalIgnoreCase));
            var httpsAddress = addresses.Single(value => value.StartsWith("https://", StringComparison.OrdinalIgnoreCase));
            httpPort = new Uri(httpAddress).Port;
            var challengeStoreUrl = new Uri(httpAddress);

            var fakeCa = new DeterministicFakeAcmeCa(challengeStoreUrl, DnsName, ToPfx(replacementLeaf));
            var clock = new ManualTimeProvider(DateTimeOffset.UtcNow);
            var coordinator = new AcmeRenewalCoordinator(fakeCa, challengeStore, clock, chainPolicy,
                thumbprint => rotation is not null && string.Equals(rotation.Current.Thumbprint,
                    thumbprint, StringComparison.OrdinalIgnoreCase));
            var result = await coordinator.RenewIfDueAsync(DirectoryUrl, DnsName, "admin@example.com",
                publicHttp01Enabled: true, activePfxPath, passwordPath, TimeSpan.FromDays(30), CancellationToken.None);
            Check(result.Renewed && result.NotAfter > DateTimeOffset.UtcNow.AddDays(80),
                "due certificate renews through fake ACME and installs the longer-lived chain");
            Check(fakeCa.IssuanceCount == 1 && fakeCa.ChallengeServed,
                "fake CA retrieves the actual HTTP-01 key authorization from the live GatewayCore endpoint");
            Check(!challengeStore.TryGet(DnsName, fakeCa.LastToken, out _),
                "HTTP-01 token is removed after the fake CA issues the certificate");

            using (var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(8)))
            {
                while (!string.Equals(rotation.Current.Thumbprint, replacementLeaf.Thumbprint,
                           StringComparison.OrdinalIgnoreCase))
                    await Task.Delay(50, timeout.Token);
            }
            Check(await GetPeerThumbprintAsync(new Uri(httpsAddress)) == replacementLeaf.Thumbprint,
                "new real TLS handshakes serve the renewed certificate without restarting Kestrel");

            var callsBeforeNotDue = fakeCa.IssuanceCount;
            var notDue = await coordinator.RenewIfDueAsync(DirectoryUrl, DnsName, "admin@example.com", true,
                activePfxPath, passwordPath, TimeSpan.FromDays(30), CancellationToken.None);
            Check(!notDue.Renewed && fakeCa.IssuanceCount == callsBeforeNotDue,
                "a certificate outside its renewal window does not create another ACME order");

            var activeBytesBeforeReject = await File.ReadAllBytesAsync(activePfxPath);
            fakeCa.NextPfx = ToPfx(wrongNameLeaf);
            clock.Advance(TimeSpan.FromDays(61));
            var rejected = false;
            try
            {
                await coordinator.RenewIfDueAsync(DirectoryUrl, DnsName, "admin@example.com", true,
                    activePfxPath, passwordPath, TimeSpan.FromDays(30), CancellationToken.None);
            }
            catch (InvalidOperationException) { rejected = true; }
            Check(rejected && (await File.ReadAllBytesAsync(activePfxPath)).SequenceEqual(activeBytesBeforeReject),
                "wrong-SAN fake CA response fails closed without replacing the active certificate");
            Check(!Directory.EnumerateFiles(rootDir, ".gatewaycore-acme-*.pfx").Any(),
                "failed candidate validation removes staged PFX files");
            Console.WriteLine("PASS: deterministic fake-CA HTTP-01 renewal, protected account key and live TLS rotation");
        }
        finally
        {
            if (app is not null) await app.DisposeAsync();
            rotation?.Dispose();
            if (Directory.Exists(rootDir)) Directory.Delete(rootDir, recursive: true);
        }
    }

    private static async Task<string> GetPeerThumbprintAsync(Uri httpsAddress)
    {
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, httpsAddress.Port);
        using var tls = new SslStream(client.GetStream(), leaveInnerStreamOpen: false,
            (_, certificate, _, _) => certificate is not null);
        await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = DnsName });
        return tls.RemoteCertificate?.GetCertHashString() ?? throw new Exception("TLS peer certificate missing");
    }

    private static void SetPrivate(string path)
    {
        if (OperatingSystem.IsLinux()) File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }

    private sealed class ManualTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        private DateTimeOffset current = utcNow;
        public override DateTimeOffset GetUtcNow() => current;
        public void Advance(TimeSpan duration) => current += duration;
    }

    private sealed class DeterministicFakeAcmeCa(Uri challengeEndpoint, string dnsName, byte[] initialPfx)
        : IAcmeCertificateIssuer
    {
        private int issuanceCount;
        public int IssuanceCount => Volatile.Read(ref issuanceCount);
        public bool ChallengeServed { get; private set; }
        public string LastToken { get; private set; } = string.Empty;
        public byte[] NextPfx { get; set; } = initialPfx;

        public async Task<AcmeIssuedCertificate> IssueHttp01Async(string directoryUrl, string requestedDns,
            string contactEmail, string pfxPassword, AcmeHttp01ChallengeStore challenges,
            CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref issuanceCount);
            if (!string.Equals(requestedDns, dnsName, StringComparison.Ordinal))
                throw new InvalidOperationException("Fake CA received an unexpected DNS identifier.");
            var token = "fake-ca-token-0123456789";
            var keyAuthorization = token + "." + new string('A', 43);
            LastToken = token;
            if (!challenges.TryPublish(dnsName, token, keyAuthorization, TimeSpan.FromMinutes(2)))
                throw new InvalidOperationException("Fake CA challenge publication failed.");
            try
            {
                using var client = new HttpClient { BaseAddress = challengeEndpoint };
                using var request = new HttpRequestMessage(HttpMethod.Get,
                    "/.well-known/acme-challenge/" + token);
                request.Headers.Host = dnsName;
                using var response = await client.SendAsync(request, cancellationToken);
                var body = await response.Content.ReadAsStringAsync(cancellationToken);
                ChallengeServed = response.StatusCode == HttpStatusCode.OK && body == keyAuthorization;
                if (!ChallengeServed) throw new CryptographicException("Fake CA challenge validation failed.");
                return new AcmeIssuedCertificate(NextPfx.ToArray(), dnsName);
            }
            finally { challenges.Remove(dnsName, token); }
        }
    }
}
