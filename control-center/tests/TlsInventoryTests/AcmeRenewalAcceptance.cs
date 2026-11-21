using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Certes;
using Certes.Acme.Resource;
using Directory = System.IO.Directory;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
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

        await VerifyBoundedRevocationHttpAsync((condition, message) => Check(condition, message));

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
        // Keep the test CA valid beyond every leaf generated below. The next leaf
        // intentionally lasts 180 days; matching the CA lifetime can put its
        // notAfter a few milliseconds beyond the issuer on slower runners.
        using var root = rootRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-2), DateTimeOffset.UtcNow.AddDays(365));
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
        using var nextLeaf = CreateLeaf(DnsName, DateTimeOffset.UtcNow.AddDays(180));
        using var wrongNameLeaf = CreateLeaf("other.example.com", DateTimeOffset.UtcNow.AddDays(90));
        await File.WriteAllBytesAsync(activePfxPath, ToPfx(activeLeaf));
        SetPrivate(activePfxPath);
        if (OperatingSystem.IsLinux())
        {
            var linkedPfx = Path.Combine(rootDir, "linked-traffic.pfx");
            File.CreateSymbolicLink(linkedPfx, activePfxPath);
            var linkedPfxRejected = false;
            try
            {
                try { using var linkedRotation = new TrafficCertificateRotation(linkedPfx, passwordPath, [DnsName]); }
                catch (InvalidDataException) { linkedPfxRejected = true; }
            }
            finally { File.Delete(linkedPfx); }
            Check(linkedPfxRejected, "live certificate loader rejects a linked PFX leaf");

            File.SetUnixFileMode(activePfxPath, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead);
            var exposedPfxRejected = false;
            try
            {
                try { using var exposedRotation = new TrafficCertificateRotation(activePfxPath, passwordPath, [DnsName]); }
                catch (InvalidDataException) { exposedPfxRejected = true; }
            }
            finally { SetPrivate(activePfxPath); }
            Check(exposedPfxRejected, "live certificate loader rejects a group-readable PFX");

            var linkedPassword = Path.Combine(rootDir, "linked-traffic.pwd");
            File.CreateSymbolicLink(linkedPassword, passwordPath);
            var linkedPasswordRejected = false;
            try
            {
                try { using var linkedRotation = new TrafficCertificateRotation(activePfxPath, linkedPassword, [DnsName]); }
                catch (InvalidDataException) { linkedPasswordRejected = true; }
            }
            finally { File.Delete(linkedPassword); }
            Check(linkedPasswordRejected, "live certificate loader rejects a linked password leaf");
        }
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

        // A reviewed ACME target/issuer must not silently change through
        // duplicate or case/Unicode-aliased JSON keys.
        var validSettingsJson = System.Text.Json.JsonSerializer.Serialize(settings);
        bool RejectedConfiguration()
        {
            try { _ = AcmeRenewalSettings.Load(settingsPath, activePfxPath, passwordPath, [DnsName]); return false; }
            catch (InvalidOperationException) { return true; }
            catch (InvalidDataException) { return true; }
        }
        foreach (var duplicate in new[]
        {
            validSettingsJson[..^1] + ",\"DirectoryUrl\":\"https://acme-v02.api.letsencrypt.org/directory\"}",
            validSettingsJson[..^1] + ",\"directoryUrl\":\"https://acme-v02.api.letsencrypt.org/directory\"}",
            validSettingsJson[..^1] + ",\"Dir\\u0065ctoryUrl\":\"https://acme-v02.api.letsencrypt.org/directory\"}"
        })
        {
            await File.WriteAllTextAsync(settingsPath, duplicate);
            SetPrivate(settingsPath);
            Check(RejectedConfiguration(),
                "duplicate and case/escaped ACME directory aliases are refused");
        }
        await File.WriteAllTextAsync(settingsPath, new string(' ', 16 * 1024 + 1));
        SetPrivate(settingsPath);
        Check(RejectedConfiguration(), "oversized ACME config rejected before JSON parsing");
        await File.WriteAllBytesAsync(settingsPath, [0xC3, 0x28]); // Malformed UTF-8.
        SetPrivate(settingsPath);
        Check(RejectedConfiguration(), "invalid UTF-8 ACME config rejected");
        if (OperatingSystem.IsLinux())
        {
            await File.WriteAllTextAsync(settingsPath, validSettingsJson);
            SetPrivate(settingsPath);
            var alias = Path.Combine(rootDir, "acme-linked-parent");
            Directory.CreateSymbolicLink(alias, rootDir);
            var linkedSettingsPath = Path.Combine(alias, "acme.json");
            var ancestorDenied = false;
            try { _ = AcmeRenewalSettings.Load(linkedSettingsPath, activePfxPath, passwordPath, [DnsName]); }
            catch (InvalidDataException) { ancestorDenied = true; }
            catch (IOException) { ancestorDenied = true; }
            Check(ancestorDenied, "ACME config through symlinked parent fails closed");
        }
        await File.WriteAllTextAsync(settingsPath, validSettingsJson);
        SetPrivate(settingsPath);
        Check(AcmeRenewalSettings.Load(settingsPath, activePfxPath, passwordPath, [DnsName]).DnsName == DnsName,
            "valid ACME configuration remains compatible after negative tests");

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

        var accountStore = new AcmeAccountKeyStore(keyPath, restartedDataProtection.CreateProtector("acceptance"));
        if (OperatingSystem.IsLinux())
        {
            var privateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
            File.SetUnixFileMode(rootDir, privateMode | UnixFileMode.GroupRead);
            try
            {
                var unsafeDirectoryRejected = false;
                try { _ = accountStore.LoadOrCreate(); }
                catch (InvalidOperationException) { unsafeDirectoryRejected = true; }
                Check(unsafeDirectoryRejected, "existing account key below a nonprivate directory is rejected");
            }
            finally { File.SetUnixFileMode(rootDir, privateMode); }

            var linkedDirectory = Path.Combine(rootDir, "linked-account-directory");
            Directory.CreateSymbolicLink(linkedDirectory, rootDir);
            try
            {
                var linkRejected = false;
                try
                {
                    _ = new AcmeAccountKeyStore(Path.Combine(linkedDirectory, "acme-account.bin"),
                        restartedDataProtection.CreateProtector("acceptance")).LoadOrCreate();
                }
                catch (InvalidOperationException) { linkRejected = true; }
                Check(linkRejected, "existing account key through a linked directory is rejected");
            }
            finally { Directory.Delete(linkedDirectory); }
        }

        // A corrupted or oversized existing file must not trigger silent key
        // regeneration, which would lose the ACME account identity.
        var invalidKey = Path.Combine(rootDir, "invalid-account.bin");
        foreach (var invalidBytes in new[] { new byte[32], new byte[16_385], new byte[256] })
        {
            await File.WriteAllBytesAsync(invalidKey, invalidBytes);
            SetPrivate(invalidKey);
            var rejected = false;
            try
            {
                _ = new AcmeAccountKeyStore(invalidKey,
                    restartedDataProtection.CreateProtector("acceptance")).LoadOrCreate();
            }
            catch (CryptographicException) { rejected = true; }
            Check(rejected && (await File.ReadAllBytesAsync(invalidKey)).SequenceEqual(invalidBytes),
                "invalid account ciphertext rejected without changing the existing file");
        }
        File.Delete(invalidKey);
        Check(accountStore.LoadOrCreate().ToPem() == accountPem,
            "original ACME account remains readable after rejected unsafe state");

        var challengeStore = new AcmeHttp01ChallengeStore();
        var lifecycleGate = new AcmeCertificateLifecycleGate();
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
                    thumbprint, StringComparison.OrdinalIgnoreCase), lifecycleGate);
            if (OperatingSystem.IsLinux())
            {
                var linkedPfx = Path.Combine(rootDir, "renewal-linked.pfx");
                File.CreateSymbolicLink(linkedPfx, activePfxPath);
                var linkedPfxRejected = false;
                try
                {
                    try
                    {
                        await coordinator.RenewIfDueAsync(DirectoryUrl, DnsName, "admin@example.com", true,
                            linkedPfx, passwordPath, TimeSpan.FromDays(30), CancellationToken.None);
                    }
                    catch (InvalidDataException) { linkedPfxRejected = true; }
                }
                finally { File.Delete(linkedPfx); }
                Check(linkedPfxRejected && fakeCa.IssuanceCount == 0,
                    "ACME renewal rejects a linked PFX before contacting the issuer");

                var linkedPassword = Path.Combine(rootDir, "renewal-linked.pwd");
                File.CreateSymbolicLink(linkedPassword, passwordPath);
                var linkedPasswordRejected = false;
                try
                {
                    try
                    {
                        await coordinator.RenewIfDueAsync(DirectoryUrl, DnsName, "admin@example.com", true,
                            activePfxPath, linkedPassword, TimeSpan.FromDays(30), CancellationToken.None);
                    }
                    catch (InvalidDataException) { linkedPasswordRejected = true; }
                }
                finally { File.Delete(linkedPassword); }
                Check(linkedPasswordRejected && fakeCa.IssuanceCount == 0,
                    "ACME renewal rejects a linked password before contacting the issuer");

                File.SetUnixFileMode(passwordPath,
                    UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead);
                var exposedPasswordRejected = false;
                try
                {
                    try
                    {
                        await coordinator.RenewIfDueAsync(DirectoryUrl, DnsName, "admin@example.com", true,
                            activePfxPath, passwordPath, TimeSpan.FromDays(30), CancellationToken.None);
                    }
                    catch (InvalidDataException) { exposedPasswordRejected = true; }
                }
                finally { SetPrivate(passwordPath); }
                Check(exposedPasswordRejected && fakeCa.IssuanceCount == 0,
                    "ACME renewal rejects a group-readable password before contacting the issuer");
            }
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

            var revocation = new AcmeRevocationCoordinator(fakeCa, DirectoryUrl, DnsName,
                "admin@example.com", thumbprint => string.Equals(rotation.Current.Thumbprint,
                    thumbprint, StringComparison.OrdinalIgnoreCase), lifecycleGate);
            static AcmeRevocationRequest RevocationInput(X509Certificate2 certificate, string reason,
                string? confirmation = null) =>
                new(Convert.ToBase64String(certificate.Export(X509ContentType.Cert)),
                    certificate.Thumbprint.ToUpperInvariant(),
                    confirmation ?? "REVOKE " + certificate.Thumbprint.ToUpperInvariant(), reason);

            var currentCertificateRejected = false;
            try
            {
                await revocation.RevokeAsync(RevocationInput(replacementLeaf, "Superseded"), CancellationToken.None);
            }
            catch (AcmeActiveCertificateRevocationException) { currentCertificateRejected = true; }
            Check(currentCertificateRejected && fakeCa.RevocationCount == 0,
                "currently served certificate cannot be revoked");

            var wrongConfirmationRejected = false;
            try
            {
                await revocation.RevokeAsync(RevocationInput(activeLeaf, "Superseded", "REVOKE WRONG"),
                    CancellationToken.None);
            }
            catch (ArgumentException) { wrongConfirmationRejected = true; }
            Check(wrongConfirmationRejected && fakeCa.RevocationCount == 0,
                "prior certificate revocation requires exact typed thumbprint confirmation");

            var wrongNameRejected = false;
            try { await revocation.RevokeAsync(RevocationInput(wrongNameLeaf, "Superseded"), CancellationToken.None); }
            catch (ArgumentException) { wrongNameRejected = true; }
            Check(wrongNameRejected && fakeCa.RevocationCount == 0,
                "certificate for a different DNS name cannot be revoked through this endpoint");

            var unsupportedReasonRejected = false;
            try { await revocation.RevokeAsync(RevocationInput(activeLeaf, "CACompromise"), CancellationToken.None); }
            catch (ArgumentException) { unsupportedReasonRejected = true; }
            Check(unsupportedReasonRejected && fakeCa.RevocationCount == 0,
                "unsupported high-impact revocation reasons are rejected");

            var revoked = await revocation.RevokeAsync(RevocationInput(activeLeaf, "Superseded"),
                CancellationToken.None);
            Check(fakeCa.RevocationCount == 1 &&
                  fakeCa.LastRevokedThumbprint == activeLeaf.Thumbprint.ToUpperInvariant() &&
                  fakeCa.LastRevocationReason == RevocationReason.Superseded &&
                  revoked.Thumbprint == activeLeaf.Thumbprint.ToUpperInvariant(),
                "confirmed prior TLS leaf is sent once to the deterministic ACME issuer with the selected reason");

            clock.Advance(TimeSpan.FromDays(61));
            var beforeIssuerFailure = await File.ReadAllBytesAsync(activePfxPath);
            var timestampBeforeIssuerFailure = File.GetLastWriteTimeUtc(activePfxPath);
            var unavailableIssuer = new ThrowingIssuer();
            var unavailableCoordinator = new AcmeRenewalCoordinator(unavailableIssuer, challengeStore, clock, chainPolicy);
            var issuerFailureRejected = false;
            try
            {
                await unavailableCoordinator.RenewIfDueAsync(DirectoryUrl, DnsName, "admin@example.com", true,
                    activePfxPath, passwordPath, TimeSpan.FromDays(30), CancellationToken.None);
            }
            catch (HttpRequestException) { issuerFailureRejected = true; }
            Check(issuerFailureRejected &&
                  (await File.ReadAllBytesAsync(activePfxPath)).SequenceEqual(beforeIssuerFailure) &&
                  File.GetLastWriteTimeUtc(activePfxPath) == timestampBeforeIssuerFailure,
                "an issuer failure before certificate replacement leaves active PFX bytes and file metadata untouched");

            // Simulate an operator replacing the active PFX while an ACME
            // order is outstanding. Re-exporting the same leaf produces new
            // encrypted bytes without changing the current listener identity.
            var manualPfx = ToPfx(replacementLeaf);
            Check(!manualPfx.SequenceEqual(beforeIssuerFailure), "manual replacement fixture has distinct PFX bytes");
            fakeCa.NextPfx = ToPfx(nextLeaf);
            var replacingIssuer = new CallbackIssuer(fakeCa, async () =>
            {
                var temporary = activePfxPath + ".manual";
                await File.WriteAllBytesAsync(temporary, manualPfx);
                SetPrivate(temporary);
                File.Move(temporary, activePfxPath, overwrite: true);
            });
            var staleCoordinator = new AcmeRenewalCoordinator(replacingIssuer, challengeStore, clock, chainPolicy);
            var staleRejected = false;
            try
            {
                await staleCoordinator.RenewIfDueAsync(DirectoryUrl, DnsName, "admin@example.com", true,
                    activePfxPath, passwordPath, TimeSpan.FromDays(30), CancellationToken.None);
            }
            catch (InvalidOperationException ex) when (ex.Message.Contains("refusing stale replacement")) { staleRejected = true; }
            Check(staleRejected && (await File.ReadAllBytesAsync(activePfxPath)).SequenceEqual(manualPfx),
                "outstanding ACME order cannot overwrite a newer manual PFX");

            var beforeActivationFailure = await File.ReadAllBytesAsync(activePfxPath);
            fakeCa.NextPfx = ToPfx(nextLeaf);
            var activationFailureCoordinator = new AcmeRenewalCoordinator(fakeCa, challengeStore, clock, chainPolicy,
                _ => throw new InvalidOperationException("simulated listener activation failure"));
            var activationFailureRejected = false;
            try
            {
                await activationFailureCoordinator.RenewIfDueAsync(DirectoryUrl, DnsName, "admin@example.com", true,
                    activePfxPath, passwordPath, TimeSpan.FromDays(30), CancellationToken.None);
            }
            catch (InvalidOperationException) { activationFailureRejected = true; }
            Check(activationFailureRejected &&
                  (await File.ReadAllBytesAsync(activePfxPath)).SequenceEqual(beforeActivationFailure),
                "a post-replacement listener activation failure restores the last-good PFX");

            var activeBytesBeforeReject = await File.ReadAllBytesAsync(activePfxPath);
            fakeCa.NextPfx = ToPfx(wrongNameLeaf);
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

            // Hold the CA revocation response open while renewal tries to replace the
            // active PFX. The shared gate must keep the listener leaf and file unchanged.
            var blockingIssuer = new BlockingRevocationIssuer(fakeCa);
            var blockingRevocation = new AcmeRevocationCoordinator(blockingIssuer, DirectoryUrl, DnsName,
                "admin@example.com", thumbprint => string.Equals(rotation.Current.Thumbprint,
                    thumbprint, StringComparison.OrdinalIgnoreCase), lifecycleGate);
            var revokeInFlight = blockingRevocation.RevokeAsync(
                RevocationInput(activeLeaf, "Superseded"), CancellationToken.None);
            await blockingIssuer.RevocationStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
            var pfxBeforeConcurrentRenewal = await File.ReadAllBytesAsync(activePfxPath);
            var issuanceBeforeConcurrentRenewal = fakeCa.IssuanceCount;
            fakeCa.NextPfx = ToPfx(nextLeaf);
            var renewalInFlight = coordinator.RenewIfDueAsync(DirectoryUrl, DnsName, "admin@example.com", true,
                activePfxPath, passwordPath, TimeSpan.FromDays(30), CancellationToken.None);
            using (var gateTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(10)))
            {
                while (fakeCa.IssuanceCount <= issuanceBeforeConcurrentRenewal ||
                       lifecycleGate.WaitingCount == 0)
                    await Task.Delay(20, gateTimeout.Token);
            }
            Check(!renewalInFlight.IsCompleted &&
                  (await File.ReadAllBytesAsync(activePfxPath)).SequenceEqual(pfxBeforeConcurrentRenewal) &&
                  rotation.Current.Thumbprint == replacementLeaf.Thumbprint,
                "renewal cannot replace or activate a certificate while a prior-leaf revocation is in flight");
            blockingIssuer.AllowRevocation.TrySetResult(true);
            await revokeInFlight;
            var concurrentRenewalResult = await renewalInFlight;
            Check(concurrentRenewalResult.Renewed && rotation.Current.Thumbprint == nextLeaf.Thumbprint,
                "certificate rotation proceeds after the serialized revocation transaction completes");
            Console.WriteLine("PASS: bounded HTTP revocation body, serialized ACME certificate lifecycle, deterministic fake-CA renewal and revocation");
        }
        finally
        {
            if (app is not null) await app.DisposeAsync();
            rotation?.Dispose();
            if (Directory.Exists(rootDir)) Directory.Delete(rootDir, recursive: true);
        }
    }

    private static async Task VerifyBoundedRevocationHttpAsync(Action<bool, string> check)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.ConfigureKestrel(options => options.Listen(IPAddress.Loopback, 0,
            listen => listen.Protocols = Microsoft.AspNetCore.Server.Kestrel.Core.HttpProtocols.Http1));
        await using var app = builder.Build();
        var parsed = 0;
        app.MapPost("/admin/api/tls/acme/revoke", async (HttpContext context) =>
        {
            try
            {
                _ = await AcmeRevocationRequestReader.ReadAsync(context.Request, context.RequestAborted);
                Interlocked.Increment(ref parsed);
                return Results.Ok();
            }
            catch (AcmeRevocationRequestTooLargeException)
            {
                return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);
            }
            catch (InvalidDataException)
            {
                return Results.BadRequest();
            }
        }).WithMetadata(new RequestSizeLimitAttribute(AcmeRevocationRequestReader.MaxRequestBytes));
        await app.StartAsync();
        try
        {
            var address = app.Services.GetRequiredService<Microsoft.AspNetCore.Hosting.Server.IServer>()
                .Features.Get<Microsoft.AspNetCore.Hosting.Server.Features.IServerAddressesFeature>()!
                .Addresses.Single(value => value.StartsWith("http://", StringComparison.OrdinalIgnoreCase));
            using var client = new HttpClient { BaseAddress = new Uri(address) };
            var acceptedBody = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(
                new AcmeRevocationRequest("AA==", new string('A', 40), "REVOKE " + new string('A', 40), "Superseded"));
            using (var accepted = new HttpRequestMessage(HttpMethod.Post, "/admin/api/tls/acme/revoke")
            {
                Content = new ByteArrayContent(acceptedBody)
            })
            {
                accepted.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
                using var response = await client.SendAsync(accepted);
                check(response.StatusCode == HttpStatusCode.OK, "bounded JSON revocation request reaches the handler");
            }

            var oversizedBody = Enumerable.Repeat((byte)' ', AcmeRevocationRequestReader.MaxRequestBytes + 1).ToArray();
            using (var fixedLength = new HttpRequestMessage(HttpMethod.Post, "/admin/api/tls/acme/revoke")
            {
                Content = new ByteArrayContent(oversizedBody)
            })
            {
                fixedLength.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
                // A 413 may terminate the HTTP/1.1 connection without draining the
                // rejected body. Do not reuse that socket for the chunked probe.
                fixedLength.Headers.ConnectionClose = true;
                fixedLength.Headers.ExpectContinue = true;
                using var response = await client.SendAsync(fixedLength);
                check(response.StatusCode == HttpStatusCode.RequestEntityTooLarge,
                    "Kestrel rejects an oversized Content-Length revocation body before JSON parsing");
            }

            using (var chunked = new HttpRequestMessage(HttpMethod.Post, "/admin/api/tls/acme/revoke")
            {
                Content = new StreamContent(new NonSeekableReadStream(oversizedBody))
            })
            {
                chunked.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
                chunked.Headers.TransferEncodingChunked = true;
                chunked.Headers.ConnectionClose = true;
                using var chunkedClient = new HttpClient { BaseAddress = new Uri(address) };
                using var response = await chunkedClient.SendAsync(chunked);
                check(response.StatusCode == HttpStatusCode.RequestEntityTooLarge,
                    "Kestrel rejects an oversized chunked revocation body");
            }
            check(Volatile.Read(ref parsed) == 1,
                "oversized fixed-length and chunked requests are rejected before JSON parsing");

            foreach (var status in new[] { StatusCodes.Status413PayloadTooLarge, StatusCodes.Status400BadRequest })
            {
                var syntheticRequest = new DefaultHttpContext().Request;
                syntheticRequest.ContentType = "application/json";
                syntheticRequest.Body = new RejectedBodyStream(status);
                var mappedToSizeLimit = false;
                var otherTransportFailurePreserved = false;
                try { _ = await AcmeRevocationRequestReader.ReadAsync(syntheticRequest, CancellationToken.None); }
                catch (AcmeRevocationRequestTooLargeException) { mappedToSizeLimit = true; }
                catch (BadHttpRequestException ex) when (ex.StatusCode == status)
                { otherTransportFailurePreserved = true; }
                check(status == StatusCodes.Status413PayloadTooLarge
                      ? mappedToSizeLimit && !otherTransportFailurePreserved
                      : !mappedToSizeLimit && otherTransportFailurePreserved,
                    "only Kestrel's 413 transport rejection maps to the bounded revocation response");
            }
        }
        finally { await app.StopAsync(); }
    }

    private sealed class RejectedBodyStream(int statusCode) : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            ValueTask.FromException<int>(new BadHttpRequestException("Rejected by the HTTP transport", statusCode));
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private sealed class NonSeekableReadStream(byte[] bytes) : Stream
    {
        private int offset;
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int bufferOffset, int count)
        {
            var take = Math.Min(count, bytes.Length - offset);
            bytes.AsSpan(offset, take).CopyTo(buffer.AsSpan(bufferOffset, take));
            offset += take;
            return take;
        }
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var take = Math.Min(buffer.Length, bytes.Length - offset);
            bytes.AsMemory(offset, take).CopyTo(buffer);
            offset += take;
            return ValueTask.FromResult(take);
        }
        public override Task<int> ReadAsync(byte[] buffer, int bufferOffset, int count,
            CancellationToken cancellationToken) =>
            Task.FromResult(Read(buffer, bufferOffset, count));
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int bufferOffset, int count) => throw new NotSupportedException();
    }

    private sealed class BlockingRevocationIssuer(IAcmeCertificateIssuer inner) : IAcmeCertificateIssuer
    {
        public TaskCompletionSource<bool> RevocationStarted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource<bool> AllowRevocation { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task<AcmeIssuedCertificate> IssueHttp01Async(string directoryUrl, string dnsName,
            string contactEmail, string pfxPassword, AcmeHttp01ChallengeStore challenges,
            CancellationToken cancellationToken) =>
            inner.IssueHttp01Async(directoryUrl, dnsName, contactEmail, pfxPassword, challenges, cancellationToken);

        public async Task RevokeCertificateAsync(string directoryUrl, string contactEmail, byte[] certificateDer,
            RevocationReason reason, CancellationToken cancellationToken)
        {
            RevocationStarted.TrySetResult(true);
            await AllowRevocation.Task.WaitAsync(cancellationToken);
            await inner.RevokeCertificateAsync(directoryUrl, contactEmail, certificateDer, reason, cancellationToken);
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

    private sealed class CallbackIssuer(IAcmeCertificateIssuer inner, Func<Task> afterIssue) : IAcmeCertificateIssuer
    {
        public async Task<AcmeIssuedCertificate> IssueHttp01Async(string directoryUrl, string dnsName,
            string contactEmail, string pfxPassword, AcmeHttp01ChallengeStore challenges,
            CancellationToken cancellationToken)
        {
            var issued = await inner.IssueHttp01Async(directoryUrl, dnsName, contactEmail, pfxPassword,
                challenges, cancellationToken);
            await afterIssue();
            return issued;
        }
        public Task RevokeCertificateAsync(string directoryUrl, string contactEmail, byte[] certificateDer,
            RevocationReason reason, CancellationToken cancellationToken) =>
            inner.RevokeCertificateAsync(directoryUrl, contactEmail, certificateDer, reason, cancellationToken);
    }

    private sealed class ThrowingIssuer : IAcmeCertificateIssuer
    {
        public Task<AcmeIssuedCertificate> IssueHttp01Async(string directoryUrl, string dnsName,
            string contactEmail, string pfxPassword, AcmeHttp01ChallengeStore challenges,
            CancellationToken cancellationToken) =>
            throw new HttpRequestException("simulated ACME service unavailable");

        public Task RevokeCertificateAsync(string directoryUrl, string contactEmail, byte[] certificateDer,
            RevocationReason reason, CancellationToken cancellationToken) =>
            throw new HttpRequestException("simulated ACME service unavailable");
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
        private int revocationCount;
        public int IssuanceCount => Volatile.Read(ref issuanceCount);
        public int RevocationCount => Volatile.Read(ref revocationCount);
        public string LastRevokedThumbprint { get; private set; } = string.Empty;
        public RevocationReason LastRevocationReason { get; private set; }
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

        public Task RevokeCertificateAsync(string directoryUrl, string contactEmail, byte[] certificateDer,
            RevocationReason reason, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            using var certificate = new X509Certificate2(certificateDer);
            LastRevokedThumbprint = certificate.Thumbprint.ToUpperInvariant();
            LastRevocationReason = reason;
            Interlocked.Increment(ref revocationCount);
            return Task.CompletedTask;
        }
    }
}
