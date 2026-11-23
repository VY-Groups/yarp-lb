using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using GatewayCore.Gslb.Contracts;

// Read-only recovery inventory + private, signed checkpoint issuance.
// Never installs or rewraps keys and never reads plaintext DP master keys.
try
{
    if (!OperatingSystem.IsLinux())
        throw new PlatformNotSupportedException("Linux recovery signer is Linux-only");
    var allowed = new HashSet<string>(StringComparer.Ordinal)
    {
        "--ring", "--revision", "--signing-key", "--trust-public-key",
        "--minimum-revision-file", "--manifest"
    };
    if (args.Length != allowed.Count * 2)
        throw new ArgumentException("Exactly six offline signer options required");
    var options = new Dictionary<string, string>(StringComparer.Ordinal);
    for (var index = 0; index < args.Length; index += 2)
    {
        if (!allowed.Contains(args[index]) ||
            string.IsNullOrWhiteSpace(args[index + 1]) ||
            !options.TryAdd(args[index], args[index + 1]))
            throw new ArgumentException("Invalid or duplicate offline signer option");
    }
    foreach (var key in allowed)
        if (!options.ContainsKey(key))
            throw new ArgumentException("Missing offline signer option");
    var ring = Absolute(options["--ring"]);
    var signingKeyPath = Absolute(options["--signing-key"]);
    var publicKeyPath = Absolute(options["--trust-public-key"]);
    var minimumPath = Absolute(options["--minimum-revision-file"]);
    var manifestPath = Absolute(options["--manifest"]);
    if (!long.TryParse(options["--revision"], NumberStyles.None,
            CultureInfo.InvariantCulture, out var revision) || revision < 1)
        throw new ArgumentException("Revision must be an unsigned positive long");
    var stateRoot = Path.GetDirectoryName(ring)
        ?? throw new ArgumentException("Missing state root");
    if (!string.Equals(Path.GetFileName(ring), "data-protection-keys",
            StringComparison.Ordinal))
        throw new ArgumentException("Expected exact restored DP key-ring directory");
    foreach (var external in new[] { signingKeyPath, publicKeyPath,
                                     minimumPath, manifestPath })
    {
        var relative = Path.GetRelativePath(stateRoot, external);
        if (relative == "." || (!Path.IsPathRooted(relative) &&
            relative != ".." && !relative.StartsWith("../", StringComparison.Ordinal)))
            throw new ArgumentException("Independent trust inputs must be outside DP state");
    }
    var minimumRaw = PrivateKeyFileSecurity.ReadPrivateFileBytes(
        minimumPath, "Independently protected DP revision floor", 64,
        requireSingleLink: true);
    long minimum;
    try
    {
        var minimumText = new UTF8Encoding(false, true)
            .GetString(minimumRaw).TrimEnd('\n');
        if (minimumText.Length == 0 || minimumText[0] == '0' ||
            !minimumText.All(char.IsAsciiDigit) ||
            !long.TryParse(minimumText, NumberStyles.None,
                CultureInfo.InvariantCulture, out minimum) || minimum < 1)
            throw new InvalidDataException("Invalid independently held revision floor");
    }
    finally { CryptographicOperations.ZeroMemory(minimumRaw); }
    if (revision <= minimum)
        throw new InvalidOperationException("Recovery revision must exceed independent floor");

    var inventorySha256 = LinuxDpRecoveryEvidence.ComputeInventoryDigest(ring);
    var privateBytes = PrivateKeyFileSecurity.ReadPrivateFileBytes(
        signingKeyPath, "DP offline checkpoint signing private key", 32768,
        requireSingleLink: true);
    using var signer = ECDsa.Create();
    try
    {
        var chars = new UTF8Encoding(false, true).GetChars(privateBytes);
        try { signer.ImportFromPem(chars); }
        finally { CryptographicOperations.ZeroMemory(
            MemoryMarshal.AsBytes(chars.AsSpan())); }
    }
    finally { CryptographicOperations.ZeroMemory(privateBytes); }
    if (signer.ExportParameters(false).Curve.Oid.Value != "1.2.840.10045.3.1.7")
        throw new InvalidOperationException("Recovery checkpoint requires P-256 signer");
    var publicPem = PrivateKeyFileSecurity.ReadPrivateFileBytes(
        publicKeyPath, "Independently trusted DP signing public key", 16384,
        allowGroupOrOtherRead: true, requireSingleLink: true);
    using var verifier = ECDsa.Create();
    try
    {
        var chars = new UTF8Encoding(false, true).GetChars(publicPem);
        try { verifier.ImportFromPem(chars); }
        finally { CryptographicOperations.ZeroMemory(
            MemoryMarshal.AsBytes(chars.AsSpan())); }
    }
    finally { CryptographicOperations.ZeroMemory(publicPem); }
    if (verifier.ExportParameters(false).Curve.Oid.Value != "1.2.840.10045.3.1.7")
        throw new InvalidOperationException("Trust anchor must be P-256");

    var message = LinuxDpRecoveryEvidence.CanonicalPayload(revision, inventorySha256);
    byte[] signature;
    try
    {
        signature = signer.SignData(message, HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        if (signature.Length != 64 ||
            !verifier.VerifyData(message, signature, HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
            throw new InvalidOperationException("Signing key does not match independent trust key");
    }
    finally { CryptographicOperations.ZeroMemory(message); }
    string signatureBase64;
    try { signatureBase64 = Convert.ToBase64String(signature); }
    finally { CryptographicOperations.ZeroMemory(signature); }
    var manifest = new LinuxDpRecoveryManifest(
        1, revision, inventorySha256, signatureBase64);
    var serialized = JsonSerializer.SerializeToUtf8Bytes(manifest);
    var parent = Path.GetDirectoryName(manifestPath)
        ?? throw new ArgumentException("Missing checkpoint parent");
    PrivateKeyFileSecurity.ValidateLinuxPrivateStateDirectory(
        parent, "Offline DP checkpoint output parent");
    // Protect the output from a permissive umask before its first byte is
    // written. CreateNew and non-overwriting Move reject existing checkpoints.
    var temporary = Path.Combine(parent, "." + Path.GetFileName(manifestPath) +
        "." + Guid.NewGuid().ToString("N") + ".tmp");
    var created = false;
    try
    {
        using (var stream = new FileStream(temporary, new FileStreamOptions
        {
            Mode = FileMode.CreateNew, Access = FileAccess.Write,
            Share = FileShare.None, Options = FileOptions.WriteThrough,
            UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite
        }))
        {
            created = true;
            stream.Write(serialized);
            stream.Flush(flushToDisk: true);
        }
        File.Move(temporary, manifestPath, overwrite: false);
        created = false;
    }
    finally
    {
        CryptographicOperations.ZeroMemory(serialized);
        if (created) File.Delete(temporary);
    }
    // The trusted recovery floor is deliberately NOT advanced: only the
    // independently authorized deployment/restore coordinator may do that.
    Console.WriteLine("PASS: private Linux DP checkpoint created for revision " +
        revision.ToString(CultureInfo.InvariantCulture));
    return 0;
}
catch (Exception error) when (error is ArgumentException or InvalidOperationException
    or IOException or UnauthorizedAccessException or CryptographicException
    or DecoderFallbackException or JsonException or PlatformNotSupportedException)
{
    Console.Error.WriteLine("FAIL: offline DP recovery checkpoint refused");
    return 1;
}

static string Absolute(string path)
{
    if (!Path.IsPathFullyQualified(path))
        throw new ArgumentException("Absolute offline recovery path required");
    return Path.GetFullPath(path);
}
