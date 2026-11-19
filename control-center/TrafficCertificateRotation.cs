using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

/// <summary>
/// Opt-in hot reload of an explicitly named public traffic certificate. Producers must
/// atomically replace the PFX; a bad candidate never displaces the active certificate.
/// Old certificate objects are retained for a grace window covering Kestrel's bounded
/// handshake, then disposed; rapid rotations are rate-limited and retention is capped.
/// </summary>
public sealed class TrafficCertificateRotation : IDisposable
{
    private const string ServerAuthenticationOid = "1.3.6.1.5.5.7.3.1";
    private static readonly TimeSpan RotationGrace = TimeSpan.FromSeconds(20);
    private static readonly TimeSpan MinimumRotationInterval = TimeSpan.FromSeconds(5);
    private const int MaximumRetiredCertificates = 4;
    private static int activeWindowsKeyContainerCount;
    internal static int ActiveWindowsKeyContainerCount => Volatile.Read(ref activeWindowsKeyContainerCount);
    private readonly string pfxPath;
    private readonly string passwordPath;
    private readonly string[] dnsNames;
    private readonly X509ChainPolicy? testChainPolicy;
    private readonly FileSystemWatcher watcher;
    private readonly SemaphoreSlim reloadGate = new(1, 1);
    private readonly object scheduleGate = new();
    private readonly List<(ManagedCertificate Certificate, DateTimeOffset RetiredAt)> retired = [];
    private CancellationTokenSource? scheduledReload;
    private ManagedCertificate current;
    private DateTimeOffset lastRotationUtc = DateTimeOffset.MinValue;
    private long rejectedCandidateCount;
    private string? lastRejectedCandidateFailure;
    private bool disposed;

    public X509Certificate2 Current => Volatile.Read(ref current).Certificate;

    public X509Certificate2? Select(string? serverName)
    {
        if (string.IsNullOrWhiteSpace(serverName)) return null;
        var certificate = Current;
        return dnsNames.Any(name => string.Equals(name, serverName, StringComparison.OrdinalIgnoreCase)) &&
            certificate.MatchesHostname(serverName) ? certificate : null;
    }

    public TrafficCertificateRotation(string pfxPath, string passwordPath, string[] dnsNames)
        : this(pfxPath, passwordPath, dnsNames, null) { }

    // A custom chain policy is only exposed internally for deterministic tests. Shipping
    // construction always uses the operating system trust and revocation policy.
    internal TrafficCertificateRotation(string pfxPath, string passwordPath, string[] dnsNames,
        X509ChainPolicy? testChainPolicy)
    {
        this.pfxPath = Path.GetFullPath(pfxPath);
        this.passwordPath = Path.GetFullPath(passwordPath);
        this.dnsNames = NormalizeDnsNames(dnsNames);
        this.testChainPolicy = testChainPolicy;
        current = LoadAndValidateCandidate();
        var directory = Path.GetDirectoryName(this.pfxPath)
            ?? throw new InvalidOperationException("Traffic PFX path must have a parent directory");
        watcher = new FileSystemWatcher(directory, Path.GetFileName(this.pfxPath))
        {
            NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size,
            IncludeSubdirectories = false,
            EnableRaisingEvents = false
        };
        watcher.Changed += OnCandidateChanged;
        watcher.Created += OnCandidateChanged;
        watcher.Renamed += OnCandidateRenamed;
        watcher.EnableRaisingEvents = true;
    }

    private static string[] NormalizeDnsNames(string[]? names)
    {
        if (names is null || names.Length == 0)
            throw new InvalidOperationException("Traffic certificate rotation requires explicit DNS names");
        var idn = new System.Globalization.IdnMapping();
        var normalized = names.Select(name => idn.GetAscii(name.Trim().TrimEnd('.')).ToLowerInvariant()).ToArray();
        if (normalized.Any(name => name.Length == 0 || name.Contains('*') ||
            Uri.CheckHostName(name) != UriHostNameType.Dns) ||
            normalized.Distinct(StringComparer.OrdinalIgnoreCase).Count() != normalized.Length)
            throw new InvalidOperationException("Traffic certificate DNS names must be unique explicit DNS names; wildcards are not supported");
        return normalized;
    }

    private void OnCandidateChanged(object sender, FileSystemEventArgs args) => ScheduleReload();
    private void OnCandidateRenamed(object sender, RenamedEventArgs args) => ScheduleReload();

    private void ScheduleReload()
    {
        lock (scheduleGate)
        {
            if (disposed) return;
            scheduledReload?.Cancel();
            scheduledReload?.Dispose();
            scheduledReload = new CancellationTokenSource();
            _ = ReloadAfterDebounceAsync(scheduledReload.Token);
        }
    }

    private async Task ReloadAfterDebounceAsync(CancellationToken cancellationToken)
    {
        try
        {
            await Task.Delay(TimeSpan.FromMilliseconds(400), cancellationToken).ConfigureAwait(false);
            await reloadGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                // Atomic rename avoids partial writes; short retries tolerate filesystem
                // watcher delivery just before the replacement becomes visible.
                for (var attempt = 0; attempt < 5; attempt++)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    try
                    {
                        var candidate = LoadAndValidateCandidate();
                        if (string.Equals(candidate.Certificate.Thumbprint, Current.Thumbprint, StringComparison.OrdinalIgnoreCase))
                        {
                            candidate.Dispose();
                            return;
                        }
                        var now = DateTimeOffset.UtcNow;
                        RetireExpired(now);
                        var rotationDelay = MinimumRotationInterval - (now - lastRotationUtc);
                        if (rotationDelay > TimeSpan.Zero)
                        {
                            candidate.Dispose();
                            await Task.Delay(rotationDelay, cancellationToken).ConfigureAwait(false);
                            continue;
                        }
                        if (RetiredCount >= MaximumRetiredCertificates)
                        {
                            candidate.Dispose();
                            DateTimeOffset oldestRetired;
                            lock (retired) oldestRetired = retired.Min(entry => entry.RetiredAt);
                            var capacityDelay = RotationGrace - (now - oldestRetired);
                            if (capacityDelay > TimeSpan.Zero)
                            {
                                await Task.Delay(capacityDelay, cancellationToken).ConfigureAwait(false);
                                continue;
                            }
                            throw new InvalidOperationException("Traffic certificate retirement capacity remains full; retaining active certificate");
                        }
                        var previous = Interlocked.Exchange(ref current, candidate);
                        lock (retired) retired.Add((previous, now));
                        lastRotationUtc = now;
                        _ = ExpireRetiredAsync(previous, now);
                        return;
                    }
                    catch (Exception ex) when (attempt < 4 &&
                        ex is IOException or UnauthorizedAccessException or CryptographicException or InvalidOperationException)
                    {
                        await Task.Delay(TimeSpan.FromMilliseconds(200), cancellationToken).ConfigureAwait(false);
                    }
                }
            }
            finally { reloadGate.Release(); }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            Interlocked.Increment(ref rejectedCandidateCount);
            Volatile.Write(ref lastRejectedCandidateFailure, ex.GetType().Name);
            // Keep the last-good certificate. Diagnostics are deliberately limited to
            // exception type; never log passwords or PFX contents.
            Console.Error.WriteLine($"Traffic TLS certificate rotation rejected candidate ({ex.GetType().Name}); retaining active certificate.");
        }
    }

    private int RetiredCount { get { lock (retired) return retired.Count; } }
    internal int RetiredCertificateCount => RetiredCount;
    internal long RejectedCandidateCount => Interlocked.Read(ref rejectedCandidateCount);
    internal string? LastRejectedCandidateFailure => Volatile.Read(ref lastRejectedCandidateFailure);

    private void RetireExpired(DateTimeOffset now)
    {
        List<ManagedCertificate> expired;
        lock (retired)
        {
            expired = retired.Where(entry => now - entry.RetiredAt >= RotationGrace)
                .Select(entry => entry.Certificate).ToList();
            retired.RemoveAll(entry => now - entry.RetiredAt >= RotationGrace);
        }
        foreach (var certificate in expired) certificate.Dispose();
    }

    private async Task ExpireRetiredAsync(ManagedCertificate certificate, DateTimeOffset retiredAt)
    {
        await Task.Delay(RotationGrace).ConfigureAwait(false);
        var removed = false;
        lock (retired)
        {
            var index = retired.FindIndex(entry => ReferenceEquals(entry.Certificate, certificate) && entry.RetiredAt == retiredAt);
            if (index >= 0) { retired.RemoveAt(index); removed = true; }
        }
        if (removed) certificate.Dispose();
    }

    private ManagedCertificate LoadAndValidateCandidate()
    {
        CheckPrivateFile(pfxPath);
        CheckPrivateFile(passwordPath);
        var password = File.ReadAllText(passwordPath).TrimEnd('\r', '\n');
        if (password.Length == 0) throw new InvalidOperationException("Traffic PFX password cannot be empty");
        var flags = OperatingSystem.IsWindows()
            ? X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.PersistKeySet
            : X509KeyStorageFlags.EphemeralKeySet;
        var certificate = X509CertificateLoader.LoadPkcs12FromFile(pfxPath, password, flags);
        ManagedCertificate managed;
        try { managed = ManagedCertificate.Create(certificate); }
        catch { certificate.Dispose(); throw; }
        try
        {
            var now = DateTime.UtcNow;
            if (!certificate.HasPrivateKey || certificate.NotBefore.ToUniversalTime() > now.AddMinutes(5) ||
                certificate.NotAfter.ToUniversalTime() <= now.AddDays(1))
                throw new InvalidOperationException("Traffic certificate must have a private key, be currently valid, and have more than one day remaining");

            var eku = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().SingleOrDefault();
            if (eku is null || !eku.EnhancedKeyUsages.Cast<Oid>().Any(oid => oid.Value == ServerAuthenticationOid))
                throw new InvalidOperationException("Traffic certificate must include the TLS server-authentication EKU");
            if (!certificate.Extensions.Cast<X509Extension>().Any(extension => extension.Oid?.Value == "2.5.29.17"))
                throw new InvalidOperationException("Traffic certificate must contain a subject alternative name extension");
            if (dnsNames.Any(name => !certificate.MatchesHostname(name)))
                throw new InvalidOperationException("Traffic certificate SAN does not cover every configured DNS name");

            using var chain = new X509Chain();
            if (testChainPolicy is not null) chain.ChainPolicy = ClonePolicy(testChainPolicy);
            chain.ChainPolicy.ApplicationPolicy.Add(new Oid(ServerAuthenticationOid));
            if (testChainPolicy is null)
            {
                chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
                chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(5);
            }
            if (!chain.Build(certificate))
                throw new CryptographicException("Traffic certificate chain validation failed");
            return managed;
        }
        catch { managed.Dispose(); throw; }
    }

    private static X509ChainPolicy ClonePolicy(X509ChainPolicy source)
    {
        var copy = new X509ChainPolicy
        {
            RevocationMode = source.RevocationMode,
            RevocationFlag = source.RevocationFlag,
            VerificationFlags = source.VerificationFlags,
            VerificationTime = source.VerificationTime,
            UrlRetrievalTimeout = source.UrlRetrievalTimeout,
            TrustMode = source.TrustMode
        };
        foreach (var cert in source.CustomTrustStore) copy.CustomTrustStore.Add(cert);
        foreach (var cert in source.ExtraStore) copy.ExtraStore.Add(cert);
        foreach (var oid in source.ApplicationPolicy) copy.ApplicationPolicy.Add(oid);
        foreach (var oid in source.CertificatePolicy) copy.CertificatePolicy.Add(oid);
        return copy;
    }

    private static void CheckPrivateFile(string path)
    {
        if (!File.Exists(path) || (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException("Traffic certificate and password files must exist and may not be symbolic links");
        if (OperatingSystem.IsLinux())
        {
            var mode = File.GetUnixFileMode(path);
            if ((mode & (UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
                          UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute)) != 0 ||
                (mode & (UnixFileMode.UserRead | UnixFileMode.UserWrite)) !=
                (UnixFileMode.UserRead | UnixFileMode.UserWrite))
                throw new InvalidOperationException("Traffic PFX and password files must be mode 0600");
        }
    }

    private sealed class ManagedCertificate : IDisposable
    {
        public X509Certificate2 Certificate { get; }
        private readonly string? keyName;
        private readonly CngProvider? provider;
        private readonly IDisposable? persistedPrivateKeyLease;
        private int disposed;

        private ManagedCertificate(X509Certificate2 certificate, string? keyName, CngProvider? provider,
            IDisposable? persistedPrivateKeyLease = null)
        {
            Certificate = certificate;
            this.keyName = keyName;
            this.provider = provider;
            this.persistedPrivateKeyLease = persistedPrivateKeyLease;
        }

        public static ManagedCertificate Create(X509Certificate2 certificate)
        {
            if (!OperatingSystem.IsWindows()) return new ManagedCertificate(certificate, null, null);
            using var ecdsa = certificate.GetECDsaPrivateKey();
            if (ecdsa is ECDsaCng ecdsaCng)
            {
                var name = ecdsaCng.Key.UniqueName;
                var keyProvider = ecdsaCng.Key.Provider;
                if (string.IsNullOrWhiteSpace(name) || keyProvider is null)
                    throw new CryptographicException("Imported CNG key has no unique cleanup identity");
                Interlocked.Increment(ref activeWindowsKeyContainerCount);
                return new ManagedCertificate(certificate, name, keyProvider);
            }
            var rsa = certificate.GetRSAPrivateKey();
            if (rsa is RSACng rsaCng)
            {
                var name = rsaCng.Key.UniqueName;
                var keyProvider = rsaCng.Key.Provider;
                if (string.IsNullOrWhiteSpace(name) || keyProvider is null)
                    throw new CryptographicException("Imported CNG key has no unique cleanup identity");
                rsa.Dispose();
                Interlocked.Increment(ref activeWindowsKeyContainerCount);
                return new ManagedCertificate(certificate, name, keyProvider);
            }
            if (rsa is RSACryptoServiceProvider rsaCsp)
            {
                rsaCsp.PersistKeyInCsp = false;
                return new ManagedCertificate(certificate, null, null, rsaCsp);
            }
            rsa?.Dispose();
            certificate.Dispose();
            throw new CryptographicException("Windows traffic certificate rotation requires a CNG RSA/ECDSA or deletable RSA CSP key");
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref disposed, 1) != 0) return;
            Certificate.Dispose();
            persistedPrivateKeyLease?.Dispose();
            if (keyName is null || provider is null) return;
            try
            {
                if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
                DeleteCngKey(keyName, provider);
                Interlocked.Decrement(ref activeWindowsKeyContainerCount);
            }
            catch (CryptographicException ex)
            {
                if (!OperatingSystem.IsWindows() || CngKeyExists(keyName, provider)) throw;
                Interlocked.Decrement(ref activeWindowsKeyContainerCount);
                Console.Error.WriteLine($"Temporary TLS private key is absent after cleanup ({ex.GetType().Name}).");
            }
        }

        [System.Runtime.Versioning.SupportedOSPlatform("windows")]
        private static void DeleteCngKey(string name, CngProvider keyProvider)
        {
            using var key = CngKey.Open(name, keyProvider, CngKeyOpenOptions.UserKey);
            key.Delete();
        }

        [System.Runtime.Versioning.SupportedOSPlatform("windows")]
        private static bool CngKeyExists(string name, CngProvider keyProvider) =>
            CngKey.Exists(name, keyProvider, CngKeyOpenOptions.UserKey);
    }

    public void Dispose()
    {
        lock (scheduleGate)
        {
            if (disposed) return;
            disposed = true;
            scheduledReload?.Cancel();
            scheduledReload?.Dispose();
            watcher.Dispose();
        }
        reloadGate.Wait();
        try
        {
            var active = Interlocked.Exchange(ref current, null!);
            active.Dispose();
            lock (retired)
            {
                foreach (var entry in retired) entry.Certificate.Dispose();
                retired.Clear();
            }
        }
        finally { reloadGate.Release(); reloadGate.Dispose(); }
    }
}
