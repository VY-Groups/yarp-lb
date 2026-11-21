using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using GatewayCore.Gslb.Contracts;

/// <summary>
/// Explicit, operator-provisioned RFC 2136 DNS-01 writer. The installed,
/// SHA-256-pinned nsupdate binary performs authenticated TCP/53 TSIG updates
/// using a private, owner-only BIND-style key file. Never pass a shared secret
/// through command-line args, logs, environment variables or a public API.
/// Only an AcmeDns01WireVerifiedPublisher may supply DNS readiness evidence.
/// </summary>
public sealed record AcmeDns01NsupdateOptions(string ZoneName, IPAddress UpdateServer,
    string ExecutablePath, string ExecutableSha256, string TsigKeyFilePath);

public sealed class AcmeDns01NsupdateWriter : IAcmeDns01Publisher
{
    private readonly AcmeDns01NsupdateOptions options;
    private static readonly Regex KeyFileContract = new(
        "^\\s*key\\s+\"[A-Za-z0-9_.-]{1,128}\"\\s*\\{\\s*algorithm\\s+hmac-sha256\\s*;\\s*secret\\s+\"(?<secret>[A-Za-z0-9+/=]{16,512})\"\\s*;\\s*\\}\\s*;\\s*$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant |
        RegexOptions.IgnoreCase | RegexOptions.Singleline,
        TimeSpan.FromMilliseconds(250));

    public AcmeDns01NsupdateWriter(AcmeDns01NsupdateOptions options)
    {
        this.options = options ?? throw new ArgumentNullException(nameof(options));
        var zone = AcmeTargetPolicy.ValidateDnsName(options.ZoneName);
        if (!zone.Allowed || !string.Equals(zone.NormalizedDnsName, options.ZoneName,
                StringComparison.Ordinal) ||
            options.UpdateServer is null ||
            options.UpdateServer.IsIPv4MappedToIPv6 ||
            options.UpdateServer.AddressFamily is not
                (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6) ||
            options.UpdateServer.Equals(IPAddress.Any) ||
            options.UpdateServer.Equals(IPAddress.IPv6Any) ||
            options.UpdateServer.IsIPv6Multicast ||
            IPAddress.IsLoopback(options.UpdateServer) ||
            string.IsNullOrWhiteSpace(options.ExecutablePath) ||
            !Path.IsPathFullyQualified(options.ExecutablePath) ||
            string.IsNullOrWhiteSpace(options.TsigKeyFilePath) ||
            !Path.IsPathFullyQualified(options.TsigKeyFilePath) ||
            options.ExecutableSha256 is not { Length: 64 } ||
            options.ExecutableSha256.Any(c =>
                c is not (>= '0' and <= '9' or >= 'A' and <= 'F')))
            throw new InvalidOperationException("DNS-01 RFC2136 writer requires pinned executable, private TSIG and canonical public zone");
    }

    public Task<IAcmeDns01PublicationLease> AcquirePublicationLeaseAsync(
        string fqdn, string txtValue, TimeSpan lifetime, CancellationToken cancellationToken)
    {
        ValidateOwnerAndValue(fqdn, txtValue);
        if (lifetime < TimeSpan.FromSeconds(10) || lifetime > TimeSpan.FromMinutes(10))
            throw new InvalidOperationException("DNS-01 publication lifetime outside allowed bound");
        cancellationToken.ThrowIfCancellationRequested();
        // This cleanup handle exists before nsupdate can perform any side effect.
        return Task.FromResult<IAcmeDns01PublicationLease>(
            new TxtLease(this, fqdn, txtValue));
    }

    // Concrete compatibility helper used by the local writer acceptance only.
    // Production issuance uses the pre-acquired IAcmeDns01PublicationLease.
    public async Task<IAsyncDisposable> PublishAsync(string fqdn, string txtValue,
        TimeSpan lifetime, CancellationToken cancellationToken)
    {
        var lease = await AcquirePublicationLeaseAsync(
            fqdn, txtValue, lifetime, cancellationToken);
        try
        {
            await lease.PublishAsync(cancellationToken);
            return lease;
        }
        catch
        {
            try { await lease.DisposeAsync(); }
            catch { /* preserve the original update failure */ }
            throw;
        }
    }

    public Task<IReadOnlyList<AcmeDns01AuthorityObservation>> ProbeAuthoritativeAsync(
        string fqdn, string txtValue, CancellationToken cancellationToken) =>
        throw new InvalidOperationException(
            "The DNS update writer cannot attest its own propagation; wrap with pinned DNS TCP authority verification");

    private sealed class TxtLease(AcmeDns01NsupdateWriter writer, string owner,
        string value) : IAcmeDns01PublicationLease
    {
        private readonly SemaphoreSlim gate = new(1, 1);
        private bool publishAttempted;
        private bool released;

        public async Task PublishAsync(CancellationToken cancellationToken)
        {
            await gate.WaitAsync(cancellationToken);
            try
            {
                if (released)
                    throw new InvalidOperationException("DNS-01 publication lease was already released");
                if (publishAttempted)
                    throw new InvalidOperationException("DNS-01 publication lease may publish only once");
                // Mark before I/O: a timeout can occur after the authoritative
                // server applied the update, so disposal must compensate.
                publishAttempted = true;
                await writer.ApplyAsync(owner, value, delete: false, cancellationToken);
            }
            finally { gate.Release(); }
        }

        public async ValueTask DisposeAsync()
        {
            await gate.WaitAsync();
            try
            {
                if (released) return;
                // An ACME caller cancellation must not skip cleanup. The
                // subprocess always has its own independent 12-second timeout.
                if (publishAttempted)
                    await writer.ApplyAsync(owner, value, delete: true, CancellationToken.None);
                released = true;
            }
            finally { gate.Release(); }
        }
    }

    private void ValidateOwnerAndValue(string fqdn, string txtValue)
    {
        const string challengePrefix = "_acme-challenge.";
        if (string.IsNullOrEmpty(fqdn) ||
            !fqdn.StartsWith(challengePrefix, StringComparison.Ordinal) ||
            !string.Equals(AcmeDns01Publication.ChallengeOwner(
                    fqdn[challengePrefix.Length..]), fqdn, StringComparison.Ordinal) ||
            !fqdn.EndsWith("." + options.ZoneName, StringComparison.Ordinal) ||
            !AcmeDns01Publication.IsDns01Value(txtValue))
            throw new InvalidOperationException("DNS-01 record outside configured zone or digest contract");
    }

    internal static string RenderUpdateScript(AcmeDns01NsupdateOptions options,
        string fqdn, string txtValue, bool delete)
    {
        // Used only after ValidateOwnerAndValue in production. The result
        // contains no TSIG credentials, and the exact single-record delete
        // preserves unrelated ACME orders sharing the TXT owner.
        var operation = delete
            ? $"update delete {fqdn}. TXT \"{txtValue}\""
            : $"update add {fqdn}. 30 TXT \"{txtValue}\"";
        return $"server {options.UpdateServer} 53\n" +
               $"zone {options.ZoneName}.\n" +
               operation + "\nsend\n";
    }

    private async Task ApplyAsync(string fqdn, string txtValue, bool delete,
        CancellationToken cancellationToken)
    {
        ValidateOwnerAndValue(fqdn, txtValue);
        ValidateToolsAndKey();
        var psi = new ProcessStartInfo(options.ExecutablePath)
        {
            UseShellExecute = false, RedirectStandardInput = true,
            RedirectStandardOutput = true, RedirectStandardError = true,
            CreateNoWindow = true
        };
        psi.ArgumentList.Add("-v"); // force TCP, never an unauthenticated UDP fallback
        psi.ArgumentList.Add("-t");
        psi.ArgumentList.Add("8");
        psi.ArgumentList.Add("-k"); // filename only; no TSIG shared secret in argv
        psi.ArgumentList.Add(options.TsigKeyFilePath);
        using var process = new Process { StartInfo = psi };
        using var bounded = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        bounded.CancelAfter(TimeSpan.FromSeconds(12));
        var started = false;
        try
        {
            started = process.Start();
            if (!started)
                throw new InvalidOperationException("Could not start approved DNS-01 updater");
            // Drain without buffering; never include tool output in exceptions,
            // HTTP responses, logs or telemetry (it may contain TSIG material).
            var stdout = process.StandardOutput.BaseStream.CopyToAsync(Stream.Null, bounded.Token);
            var stderr = process.StandardError.BaseStream.CopyToAsync(Stream.Null, bounded.Token);
            var script = RenderUpdateScript(options, fqdn, txtValue, delete);
            await process.StandardInput.WriteAsync(script.AsMemory(), bounded.Token);
            await process.StandardInput.FlushAsync(bounded.Token);
            process.StandardInput.Close();
            await process.WaitForExitAsync(bounded.Token);
            await Task.WhenAll(stdout, stderr);
            if (process.ExitCode != 0)
                throw new InvalidOperationException("Authenticated DNS-01 dynamic update rejected");
        }
        finally
        {
            if (started)
            {
                try
                {
                    if (!process.HasExited) process.Kill(entireProcessTree: true);
                }
                catch (InvalidOperationException) { }
            }
        }
    }

    // Only privileged configuration can call this at service startup:
    // no CA order or DNS write may begin with a missing or replaced updater
    // or an unsafe TSIG file.
    internal void VerifyPreflight() => ValidateToolsAndKey();

    private void ValidateToolsAndKey()
    {
        // Check the executable before every update and cleanup, not only at
        // startup, so a binary replacement cannot silently downgrade TSIG
        // protocol behavior during a long-running renewal service.
        if ((File.GetAttributes(options.ExecutablePath) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException("DNS-01 update executable must not be a symlink");
        if (OperatingSystem.IsLinux())
        {
            var mode = File.GetUnixFileMode(options.ExecutablePath);
            if ((mode & (UnixFileMode.GroupWrite | UnixFileMode.OtherWrite)) != 0)
                throw new InvalidOperationException("DNS-01 update executable is writable by other identities");
            PrivateKeyFileSecurity.ValidateLinuxTrustedExecutableDirectory(
                Path.GetDirectoryName(options.ExecutablePath)!,
                "DNS-01 executable directory");
        }
        using (var executable = new FileStream(options.ExecutablePath, FileMode.Open,
                   FileAccess.Read, FileShare.Read))
        {
            var actual = SHA256.HashData(executable);
            if (!CryptographicOperations.FixedTimeEquals(actual,
                    Convert.FromHexString(options.ExecutableSha256)))
                throw new InvalidOperationException("DNS-01 updater binary digest mismatch");
        }

        // The tool itself reads the private key. Verify file ownership/mode
        // and exactly one hmac-sha256 key declaration before launching it.
        // No secret bytes are persisted in the application.
        var bytes = PrivateKeyFileSecurity.ReadPrivateFileBytes(
            options.TsigKeyFilePath, "DNS-01 RFC2136 TSIG secret", 8192);
        try
        {
            var text = new UTF8Encoding(false, true).GetString(bytes);
            var match = KeyFileContract.Match(text);
            if (!match.Success)
                throw new InvalidOperationException("DNS-01 TSIG file requires one strict hmac-sha256 key");
            byte[] secret;
            try { secret = Convert.FromBase64String(match.Groups["secret"].Value); }
            catch (FormatException ex)
            {
                throw new InvalidOperationException("DNS-01 TSIG key base64 rejected", ex);
            }
            try
            {
                if (secret.Length is < 32 or > 64)
                    throw new InvalidOperationException("DNS-01 TSIG secret must contain 32..64 random bytes");
            }
            finally { CryptographicOperations.ZeroMemory(secret); }
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
}
