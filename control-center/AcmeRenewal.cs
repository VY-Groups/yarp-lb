using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Certes;
using Certes.Acme.Resource;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

/// <summary>Issued leaf and chain in a password-protected PKCS#12 container.</summary>
public sealed record AcmeIssuedCertificate(byte[] Pfx, string DnsName);

/// <summary>ACME issuance boundary. Test implementations stand in for a deterministic CA.</summary>
public interface IAcmeCertificateIssuer
{
    Task<AcmeIssuedCertificate> IssueHttp01Async(string directoryUrl, string dnsName,
        string contactEmail, string pfxPassword, AcmeHttp01ChallengeStore challenges,
        CancellationToken cancellationToken);
}

/// <summary>
/// RFC 8555 v2 HTTP-01 issuer. The library handles signed ACME requests; this adapter
/// owns only the challenge lifetime and the certificate export boundary.
/// </summary>
public sealed class CertesAcmeCertificateIssuer(AcmeAccountKeyStore accountKeys,
    bool agreeToTermsOfService, TimeProvider? timeProvider = null) : IAcmeCertificateIssuer
{
    private static readonly TimeSpan ChallengeLifetime = TimeSpan.FromMinutes(8);
    private static readonly TimeSpan AuthorizationTimeout = TimeSpan.FromMinutes(5);
    private readonly TimeProvider clock = timeProvider ?? TimeProvider.System;

    public async Task<AcmeIssuedCertificate> IssueHttp01Async(string directoryUrl, string dnsName,
        string contactEmail, string pfxPassword, AcmeHttp01ChallengeStore challenges,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(challenges);
        if (!Uri.TryCreate(directoryUrl, UriKind.Absolute, out var directory) ||
            !AcmeTargetPolicy.Validate(directoryUrl, dnsName, http01: true,
                publicChallengeEntrypointEnabled: true).Allowed)
            throw new InvalidOperationException("ACME directory and public DNS target must pass the configured target policy.");
        if (string.IsNullOrWhiteSpace(contactEmail) || contactEmail.Length > 254 ||
            contactEmail.Contains('@') is false || contactEmail.Any(char.IsControl) ||
            string.IsNullOrEmpty(pfxPassword))
            throw new InvalidOperationException("ACME account email and a nonempty PFX password are required.");

        var accountKey = accountKeys.LoadOrCreate();
        var context = new AcmeContext(directory, accountKey);
        // Reusing the same account key allows the ACME server to return the existing
        // account on repeated calls instead of generating one key per renewal.
        _ = await context.NewAccount(contactEmail, termsOfServiceAgreed: agreeToTermsOfService).WaitAsync(cancellationToken);
        var order = await context.NewOrder([AcmeTargetPolicy.ValidateDnsName(dnsName).NormalizedDnsName!])
            .WaitAsync(cancellationToken);
        var authorization = await order.Authorization(AcmeTargetPolicy.ValidateDnsName(dnsName).NormalizedDnsName!)
            .WaitAsync(cancellationToken);
        var challenge = await authorization.Http().WaitAsync(cancellationToken);
        if (!challenges.TryPublish(dnsName, challenge.Token, challenge.KeyAuthz, ChallengeLifetime))
            throw new InvalidOperationException("ACME HTTP-01 challenge could not be published within the bounded challenge store.");

        try
        {
            await challenge.Validate().WaitAsync(cancellationToken);
            var deadline = clock.GetUtcNow() + AuthorizationTimeout;
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var status = (await authorization.Resource().WaitAsync(cancellationToken)).Status;
                if (status == AuthorizationStatus.Valid) break;
                if (status == AuthorizationStatus.Invalid)
                    throw new CryptographicException("ACME authority rejected the HTTP-01 authorization.");
                if (clock.GetUtcNow() >= deadline)
                    throw new TimeoutException("ACME HTTP-01 authorization did not become valid within five minutes.");
                await Task.Delay(TimeSpan.FromSeconds(1), timeProvider: clock, cancellationToken);
            }

            var certificateKey = KeyFactory.NewKey(KeyAlgorithm.RS256);
            var chain = await order.Generate(new CsrInfo { CommonName = dnsName }, certificateKey)
                .WaitAsync(cancellationToken);
            var pfx = chain.ToPfx(certificateKey).Build(dnsName, pfxPassword);
            if (pfx.Length is < 512 or > 1_048_576)
                throw new CryptographicException("ACME returned a PKCS#12 payload outside the 512-byte to 1-MiB bound.");
            return new AcmeIssuedCertificate(pfx, dnsName);
        }
        finally { challenges.Remove(dnsName, challenge.Token); }
    }
}

/// <summary>Persists one ACME account key as Data Protection ciphertext, never as plaintext PEM.</summary>
public sealed class AcmeAccountKeyStore
{
    private const string Purpose = "GatewayCore.AcmeAccountKey.v1";
    private readonly string keyPath;
    private readonly IDataProtector protector;
    private readonly object gate = new();

    public AcmeAccountKeyStore(string path, IDataProtector protector)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path))
            throw new InvalidOperationException("ACME account key path must be absolute.");
        keyPath = Path.GetFullPath(path);
        this.protector = (protector ?? throw new ArgumentNullException(nameof(protector))).CreateProtector(Purpose);
    }

    public IKey LoadOrCreate()
    {
        lock (gate)
        {
            if (File.Exists(keyPath)) return LoadExisting();
            var directory = Path.GetDirectoryName(keyPath)!;
            var createPrivateDirectory = !System.IO.Directory.Exists(directory);
            System.IO.Directory.CreateDirectory(directory);
            if (OperatingSystem.IsLinux())
            {
                if (createPrivateDirectory)
                    File.SetUnixFileMode(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
                var mode = File.GetUnixFileMode(directory);
                if ((mode & (UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
                             UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute)) != 0)
                    throw new InvalidOperationException("ACME account key directory must be private (mode 0700 or stricter).");
            }
            var key = KeyFactory.NewKey(KeyAlgorithm.ES256);
            var ciphertext = protector.Protect(Encoding.UTF8.GetBytes(key.ToPem()));
            var temporary = Path.Combine(directory, ".acme-key-" + Guid.NewGuid().ToString("N") + ".tmp");
            try
            {
                using (var file = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write,
                           FileShare.None, 4096, FileOptions.WriteThrough))
                {
                    if (OperatingSystem.IsLinux())
                        File.SetUnixFileMode(temporary, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                    file.Write(ciphertext);
                    file.Flush(flushToDisk: true);
                }
                try { File.Move(temporary, keyPath, overwrite: false); }
                catch (IOException) when (File.Exists(keyPath)) { return LoadExisting(); }
                return key;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(ciphertext);
                try { File.Delete(temporary); } catch (IOException) { }
            }
        }
    }

    private IKey LoadExisting()
    {
        if ((File.GetAttributes(keyPath) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException("ACME account key store may not be a symbolic link.");
        if (OperatingSystem.IsLinux())
        {
            var mode = File.GetUnixFileMode(keyPath);
            if ((mode & (UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
                         UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute)) != 0 ||
                (mode & (UnixFileMode.UserRead | UnixFileMode.UserWrite)) !=
                (UnixFileMode.UserRead | UnixFileMode.UserWrite))
                throw new InvalidOperationException("ACME account key ciphertext must have mode 0600.");
        }
        var ciphertext = File.ReadAllBytes(keyPath);
        if (ciphertext.Length is < 64 or > 16_384)
            throw new CryptographicException("ACME account key ciphertext length is outside its accepted bound.");
        try
        {
            var pem = protector.Unprotect(ciphertext);
            try { return KeyFactory.FromPem(Encoding.UTF8.GetString(pem)); }
            finally { CryptographicOperations.ZeroMemory(pem); }
        }
        finally { CryptographicOperations.ZeroMemory(ciphertext); }
    }
}

public sealed record AcmeRenewalResult(bool Renewed, DateTimeOffset? NotAfter, string Reason);

/// <summary>
/// Runs a bounded renewal transaction. A new certificate is staged beside the live
/// PFX, validated through the same TLS rotation checks, then atomically installed.
/// </summary>
public sealed class AcmeRenewalCoordinator(IAcmeCertificateIssuer issuer,
    AcmeHttp01ChallengeStore challenges, TimeProvider? timeProvider = null,
    X509ChainPolicy? testChainPolicy = null, Func<string, bool>? isCertificateActive = null)
{
    private readonly TimeProvider clock = timeProvider ?? TimeProvider.System;
    private readonly SemaphoreSlim renewalGate = new(1, 1);
    private readonly X509ChainPolicy? validationPolicy = testChainPolicy;
    private readonly Func<string, bool>? activeCertificateCheck = isCertificateActive;

    public async Task<AcmeRenewalResult> RenewIfDueAsync(string directoryUrl, string dnsName,
        string contactEmail, bool publicHttp01Enabled, string activePfxPath,
        string passwordFilePath, TimeSpan renewBeforeExpiry, CancellationToken cancellationToken)
    {
        if (renewBeforeExpiry <= TimeSpan.Zero || renewBeforeExpiry > TimeSpan.FromDays(60))
            throw new ArgumentOutOfRangeException(nameof(renewBeforeExpiry), "Renewal window must be in (0, 60 days].");
        var target = AcmeTargetPolicy.Validate(directoryUrl, dnsName, http01: true,
            publicChallengeEntrypointEnabled: publicHttp01Enabled);
        if (!target.Allowed) throw new InvalidOperationException("ACME target rejected: " + target.Reason);
        if (!Path.IsPathFullyQualified(activePfxPath) || !Path.IsPathFullyQualified(passwordFilePath) ||
            !File.Exists(activePfxPath) || !File.Exists(passwordFilePath))
            throw new InvalidOperationException("ACME renewal requires existing absolute active PFX and password files.");

        await renewalGate.WaitAsync(cancellationToken);
        using var transactionTimeout = new CancellationTokenSource(TimeSpan.FromMinutes(10), clock);
        using var operationCancellation = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken, transactionTimeout.Token);
        var operationToken = operationCancellation.Token;
        string? stagePath = null;
        string? rollbackPath = null;
        byte[]? activePfxBackup = null;
        try
        {
            var activeInfo = new FileInfo(activePfxPath);
            if (activeInfo.Length is < 512 or > 1_048_576)
                throw new CryptographicException("Active traffic PFX is outside the configured size bound.");
            activePfxBackup = await File.ReadAllBytesAsync(activePfxPath, operationToken);
            var activeCertificate = LoadActiveCertificate(activePfxPath, passwordFilePath);
            using (activeCertificate)
            {
                var notAfter = new DateTimeOffset(activeCertificate.NotAfter.ToUniversalTime());
                if (notAfter - clock.GetUtcNow() > renewBeforeExpiry)
                    return new AcmeRenewalResult(false, notAfter, "certificate-is-outside-renewal-window");
            }

            var password = File.ReadAllText(passwordFilePath).TrimEnd('\r', '\n');
            if (password.Length == 0) throw new InvalidOperationException("Traffic PFX password cannot be empty.");
            var issued = await issuer.IssueHttp01Async(directoryUrl, target.NormalizedDnsName!,
                contactEmail, password, challenges, operationToken).WaitAsync(operationToken);
            if (!string.Equals(issued.DnsName, target.NormalizedDnsName, StringComparison.Ordinal) ||
                issued.Pfx.Length is < 512 or > 1_048_576)
                throw new CryptographicException("ACME issuer returned an invalid identity or bounded PFX payload.");

            var directory = Path.GetDirectoryName(Path.GetFullPath(activePfxPath))!;
            stagePath = Path.Combine(directory, ".gatewaycore-acme-" + Guid.NewGuid().ToString("N") + ".pfx");
            await WritePrivatePfxAsync(stagePath, issued.Pfx, operationToken);
            using (var validated = new TrafficCertificateRotation(stagePath, passwordFilePath,
                       [target.NormalizedDnsName!], validationPolicy))
            {
                var leaf = validated.Current;
                var notAfter = new DateTimeOffset(leaf.NotAfter.ToUniversalTime());
                var renewedThumbprint = leaf.Thumbprint;
                // A CA that returns the same leaf is not treated as successful renewal.
                using var active = LoadActiveCertificate(activePfxPath, passwordFilePath);
                if (string.Equals(leaf.Thumbprint, active.Thumbprint, StringComparison.OrdinalIgnoreCase))
                    throw new CryptographicException("ACME renewal returned the currently active certificate.");
                File.Move(stagePath, activePfxPath, overwrite: true);
                stagePath = null;
                if (activeCertificateCheck is not null)
                {
                    using var activationTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(10), clock);
                    using var linked = CancellationTokenSource.CreateLinkedTokenSource(operationToken, activationTimeout.Token);
                    while (!activeCertificateCheck(renewedThumbprint))
                        await Task.Delay(TimeSpan.FromMilliseconds(50), clock, linked.Token);
                    if (!activeCertificateCheck(renewedThumbprint))
                        throw new TimeoutException("Traffic listener did not activate the renewed certificate within ten seconds.");
                }
                return new AcmeRenewalResult(true, notAfter, "renewed-and-atomically-installed");
            }
        }
        catch
        {
            // If runtime activation is wired and failed after the atomic swap, put the
            // last-good encrypted PFX back and let the same watcher restore it.
            if (stagePath is null && activePfxBackup is not null && File.Exists(activePfxPath))
            {
                var directory = Path.GetDirectoryName(Path.GetFullPath(activePfxPath))!;
                rollbackPath = Path.Combine(directory, ".gatewaycore-acme-rollback-" + Guid.NewGuid().ToString("N") + ".pfx");
                try
                {
                    await WritePrivatePfxAsync(rollbackPath, activePfxBackup, CancellationToken.None);
                    File.Move(rollbackPath, activePfxPath, overwrite: true);
                    rollbackPath = null;
                }
                catch (Exception rollbackError)
                {
                    throw new InvalidOperationException("ACME renewal failed and restoring the last-good PFX also failed.", rollbackError);
                }
            }
            throw;
        }
        finally
        {
            if (stagePath is not null) try { File.Delete(stagePath); } catch (IOException) { }
            if (rollbackPath is not null) try { File.Delete(rollbackPath); } catch (IOException) { }
            if (activePfxBackup is not null) CryptographicOperations.ZeroMemory(activePfxBackup);
            renewalGate.Release();
        }
    }

    private static X509Certificate2 LoadActiveCertificate(string pfxPath, string passwordPath)
    {
        var password = File.ReadAllText(passwordPath).TrimEnd('\r', '\n');
        var flags = OperatingSystem.IsWindows() ? X509KeyStorageFlags.UserKeySet : X509KeyStorageFlags.EphemeralKeySet;
        return X509CertificateLoader.LoadPkcs12FromFile(pfxPath, password, flags);
    }

    private static async Task WritePrivatePfxAsync(string path, byte[] pfx, CancellationToken cancellationToken)
    {
        if (pfx.Length is < 512 or > 1_048_576) throw new CryptographicException("PFX payload is outside its size bound.");
        await using var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None,
            16_384, FileOptions.Asynchronous | FileOptions.WriteThrough);
        if (OperatingSystem.IsLinux()) File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        await file.WriteAsync(pfx, cancellationToken);
        await file.FlushAsync(cancellationToken);
        file.Flush(flushToDisk: true);
    }
}

public sealed record AcmeRenewalSettings(string DirectoryUrl, string DnsName, string ContactEmail,
    string PfxPath, string PfxPasswordFile, int RenewalWindowDays = 30,
    bool AllowProductionCa = false, bool AgreeToTermsOfService = false)
{
    public static AcmeRenewalSettings Load(string path, string trafficPfxPath,
        string trafficPfxPasswordFile, IReadOnlyList<string>? trafficCertificateDnsNames)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path) || !File.Exists(path) ||
            (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException("ACME configuration must be an existing absolute non-symlink file.");
        if (OperatingSystem.IsLinux())
        {
            var mode = File.GetUnixFileMode(path);
            if ((mode & (UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
                         UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute)) != 0)
                throw new InvalidOperationException("ACME configuration must have mode 0600 or stricter.");
        }
        var options = new System.Text.Json.JsonSerializerOptions(System.Text.Json.JsonSerializerDefaults.Web)
        {
            UnmappedMemberHandling = System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow
        };
        var value = System.Text.Json.JsonSerializer.Deserialize<AcmeRenewalSettings>(File.ReadAllText(path), options)
            ?? throw new InvalidOperationException("ACME configuration is empty.");
        var target = AcmeTargetPolicy.Validate(value.DirectoryUrl, value.DnsName, http01: true,
            publicChallengeEntrypointEnabled: true);
        var productionDirectory = Uri.TryCreate(value.DirectoryUrl, UriKind.Absolute, out var directory) &&
            string.Equals(directory.IdnHost, "acme-v02.api.letsencrypt.org", StringComparison.OrdinalIgnoreCase);
        if (!target.Allowed || value.RenewalWindowDays is < 1 or > 60 ||
            string.IsNullOrWhiteSpace(value.ContactEmail) || value.ContactEmail.Length > 254 ||
            !value.ContactEmail.Contains('@') || value.ContactEmail.Any(char.IsControl) ||
            !value.AgreeToTermsOfService || (productionDirectory && !value.AllowProductionCa))
            throw new InvalidOperationException("ACME configuration has an invalid directory, public DNS name, contact, or renewal window.");
        var comparer = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        if (!Path.GetFullPath(value.PfxPath).Equals(Path.GetFullPath(trafficPfxPath), comparer) ||
            !Path.GetFullPath(value.PfxPasswordFile).Equals(Path.GetFullPath(trafficPfxPasswordFile), comparer) ||
            trafficCertificateDnsNames is not { Count: > 0 } names ||
            !names.Any(name => string.Equals(AcmeTargetPolicy.ValidateDnsName(name).NormalizedDnsName,
                target.NormalizedDnsName, StringComparison.Ordinal)))
            throw new InvalidOperationException("ACME target and PFX paths must match the isolated traffic listener's rotation configuration.");
        return value with { DnsName = target.NormalizedDnsName!, RenewalWindowDays = value.RenewalWindowDays };
    }
}

/// <summary>Opt-in renewal scheduler. It is never registered unless an ACME config path is set.</summary>
public sealed class AcmeRenewalBackgroundService(AcmeRenewalSettings settings,
    AcmeRenewalCoordinator coordinator, TimeProvider? timeProvider,
    ILogger<AcmeRenewalBackgroundService> logger) : BackgroundService
{
    private readonly TimeProvider clock = timeProvider ?? TimeProvider.System;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Spread initial orders across a few minutes when several gateway nodes start together.
        await Task.Delay(TimeSpan.FromSeconds(RandomNumberGenerator.GetInt32(0, 181)), clock, stoppingToken);
        var backoff = TimeSpan.FromMinutes(1);
        while (!stoppingToken.IsCancellationRequested)
        {
            TimeSpan nextDelay;
            try
            {
                await coordinator.RenewIfDueAsync(settings.DirectoryUrl, settings.DnsName, settings.ContactEmail,
                    publicHttp01Enabled: true, settings.PfxPath, settings.PfxPasswordFile,
                    TimeSpan.FromDays(settings.RenewalWindowDays), stoppingToken);
                backoff = TimeSpan.FromMinutes(1);
                nextDelay = TimeSpan.FromHours(6);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception ex)
            {
                // Avoid logging directory responses, DNS data, paths, credentials, or PFX details.
                logger.LogError("ACME renewal attempt failed ({FailureType}); retry is bounded with backoff.", ex.GetType().Name);
                var jitter = 0.8 + Random.Shared.NextDouble() * 0.4;
                nextDelay = TimeSpan.FromMilliseconds(Math.Min(TimeSpan.FromHours(6).TotalMilliseconds,
                    backoff.TotalMilliseconds * jitter));
                backoff = TimeSpan.FromMilliseconds(Math.Min(TimeSpan.FromHours(6).TotalMilliseconds,
                    backoff.TotalMilliseconds * 2));
            }
            await Task.Delay(nextDelay, clock, stoppingToken);
        }
    }
}
