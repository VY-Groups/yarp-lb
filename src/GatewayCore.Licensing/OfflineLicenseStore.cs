using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace GatewayCore.Licensing;

// Explicitly provisioned, service-owned local directory. No automatic reset
// or re-creation of a missing/corrupt identity or activated state.
// Signed state protects against edits without the installation key, not full
// snapshot rollback by an administrator with access to the software key.
public sealed class OfflineLicenseStore
{
    private const string KeyFile = "installation.key";
    private const string StateFile = "license.state";
    private const string LockFile = "license.lock";
    private readonly string directory;
    private readonly OfflineLicenseVerifier verifier;
    private const UnixFileMode PrivateFile = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    private const UnixFileMode PrivateDirectory = PrivateFile | UnixFileMode.UserExecute;

    public OfflineLicenseStore(string directory, OfflineLicenseVerifier verifier)
    {
        this.directory = Path.GetFullPath(directory);
        this.verifier = verifier ?? throw new ArgumentNullException(nameof(verifier));
    }

    // Windows: caller MUST provision ACLs for this directory and run under
    // the permanent service account. Linux: enforce exact 0700/0600 modes.
    public void Initialize()
    {
        if (OperatingSystem.IsWindows()) Directory.CreateDirectory(directory);
        else if (OperatingSystem.IsLinux()) Directory.CreateDirectory(directory, PrivateDirectory);
        else throw new PlatformNotSupportedException();
        using var gate = Enter();
        if (Directory.EnumerateFileSystemEntries(directory).Any(p => Path.GetFileName(p) != LockFile))
            throw new InvalidOperationException("Installation already exists or directory contains recovery material.");
        using var installation = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var raw = installation.ExportPkcs8PrivateKey();
        try
        {
            var protectedKey = OperatingSystem.IsWindows()
                ? WindowsInstallationProtection.Transform(raw, true) : raw;
            try { WriteNew(KeyFile, protectedKey); }
            finally { if (!ReferenceEquals(raw, protectedKey)) CryptographicOperations.ZeroMemory(protectedKey); }
        }
        finally { CryptographicOperations.ZeroMemory(raw); }
        // If initialization is interrupted between writes, require operator
        // recovery; never regenerate the key automatically.
        WriteState(installation, new State(0, null));
    }

    public byte[] ExportActivationRequest()
    {
        using var gate = Enter();
        using var key = OpenKey();
        _ = ReadState(key);
        return OfflineActivationRequest.Create(key);
    }

    public VerifiedLicense? Inspect(DateTimeOffset now)
    {
        using var gate = Enter();
        using var key = OpenKey();
        var state = ReadState(key);
        var effective = EffectiveTime(state, now);
        var license = ReadLicense(state, key, effective);
        if (license is not null && effective.ToUnixTimeSeconds() > state.HighestUtc)
            WriteState(key, state with { HighestUtc = effective.ToUnixTimeSeconds() });
        return license;
    }

    public VerifiedLicense Import(ReadOnlySpan<byte> file, DateTimeOffset now)
    {
        using var gate = Enter();
        using var key = OpenKey();
        var state = ReadState(key);
        var effective = EffectiveTime(state, now);
        var previous = ReadLicense(state, key, effective);
        if (previous?.Validity == LicenseValidity.Revoked)
            throw new CryptographicException("Allocation is permanently revoked.");
        var next = verifier.Verify(file, Binding(key), effective, previous?.Checkpoint);
        if (next.Validity != LicenseValidity.Active)
            throw new InvalidDataException("Only currently active entitlements can be imported.");
        // Copy only after complete verification; license and high-water
        // checkpoint are published together in one atomic file replacement.
        WriteState(key, new State(effective.ToUnixTimeSeconds(), Convert.ToBase64String(file)));
        return next;
    }

    public VerifiedLicense ImportRevocation(ReadOnlySpan<byte> file, DateTimeOffset now)
    {
        using var gate = Enter();
        using var key = OpenKey();
        var state = ReadState(key);
        var effective = EffectiveTime(state, now);
        var existing = ReadLicense(state, key, effective) ?? throw new InvalidOperationException("No allocation to revoke.");
        verifier.VerifyRevocation(file, existing);
        if (state.Revocation is null)
            WriteState(key, state with { Revocation = Convert.ToBase64String(file), HighestUtc = effective.ToUnixTimeSeconds() });
        return existing with { Validity = LicenseValidity.Revoked };
    }

    private sealed record State(long HighestUtc, string? License, string? Revocation = null);

    private VerifiedLicense? ReadLicense(State state, ECDsa key, DateTimeOffset effective)
    {
        if (state.License is null) return null;
        var license = verifier.Verify(Convert.FromBase64String(state.License), Binding(key), effective);
        if (state.Revocation is null) return license;
        verifier.VerifyRevocation(Convert.FromBase64String(state.Revocation), license);
        return license with { Validity = LicenseValidity.Revoked };
    }

    private static string Binding(ECDsa key) => Convert.ToHexString(SHA256.HashData(key.ExportSubjectPublicKeyInfo()));

    private static DateTimeOffset EffectiveTime(State state, DateTimeOffset now)
    {
        var actual = now.ToUnixTimeSeconds();
        if (actual < 0 || actual > 4102444800L || state.HighestUtc < 0 || state.HighestUtc > 4102444800L)
            throw new InvalidDataException("Invalid licensing time.");
        if (actual < state.HighestUtc - 300)
            throw new CryptographicException("Clock rollback detected; authorized recovery required.");
        return DateTimeOffset.FromUnixTimeSeconds(Math.Max(actual, state.HighestUtc));
    }

    private ECDsa OpenKey()
    {
        var bytes = ReadBounded(KeyFile, 16384);
        byte[]? raw = null;
        var key = ECDsa.Create();
        try
        {
            raw = OperatingSystem.IsWindows()
                ? WindowsInstallationProtection.Transform(bytes, false) : bytes;
            key.ImportPkcs8PrivateKey(raw, out var read);
            if (read != raw.Length || key.ExportParameters(false).Curve.Oid.Value != "1.2.840.10045.3.1.7")
                throw new CryptographicException("Invalid installation key.");
            return key;
        }
        catch { key.Dispose(); throw; }
        finally
        {
            if (raw is not null) CryptographicOperations.ZeroMemory(raw);
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private State ReadState(ECDsa key)
    {
        var parts = OfflineActivationRequest.Split(ReadBounded(StateFile, 65536), 65536, 3, "GCS1");
        OfflineActivationRequest.VerifySignature(parts, key);
        var payload = OfflineActivationRequest.Decode(parts[1], 48000);
        var state = JsonSerializer.Deserialize<State>(payload) ?? throw new InvalidDataException("Missing state.");
        if (state.HighestUtc < 0 || (state.License is null && (state.HighestUtc != 0 || state.Revocation is not null)) ||
            state.Revocation is { Length: > 11000 } ||
            (state.License is not null && (state.HighestUtc == 0 || state.License.Length > 22000)))
            throw new InvalidDataException("Invalid signed state.");
        return state;
    }

    private void WriteState(ECDsa key, State state)
    {
        var bytes = OfflineActivationRequest.Sign("GCS1." +
            OfflineActivationRequest.Encode(JsonSerializer.SerializeToUtf8Bytes(state)), key);
        var temp = ".state-" + Guid.NewGuid().ToString("N");
        try
        {
            WriteNew(temp, bytes);
            var destination = Path.Combine(directory, StateFile);
            if (File.Exists(destination)) CheckFile(destination);
            File.Move(Path.Combine(directory, temp), destination, true);
        }
        finally { if (File.Exists(Path.Combine(directory, temp))) File.Delete(Path.Combine(directory, temp)); }
    }

    private FileStream Enter()
    {
        if (!OperatingSystem.IsWindows() && !OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        var info = new DirectoryInfo(directory);
        if (!info.Exists || (info.Attributes & FileAttributes.ReparsePoint) != 0 ||
            (!OperatingSystem.IsWindows() && File.GetUnixFileMode(directory) != PrivateDirectory))
            throw new InvalidDataException("License directory must be private and not a link.");
        var path = Path.Combine(directory, LockFile);
        if (File.Exists(path)) CheckFile(path);
        var options = Options(FileMode.OpenOrCreate);
        var gate = new FileStream(path, options);
        try { CheckFile(path); return gate; }
        catch { gate.Dispose(); throw; }
    }

    private static FileStreamOptions Options(FileMode mode)
    {
        var options = new FileStreamOptions { Mode = mode, Access = FileAccess.ReadWrite, Share = FileShare.None };
        if (!OperatingSystem.IsWindows() && mode is FileMode.CreateNew or FileMode.OpenOrCreate)
            options.UnixCreateMode = PrivateFile;
        return options;
    }
    private static void CheckFile(string path)
    {
        var attr = File.GetAttributes(path);
        if ((attr & (FileAttributes.ReparsePoint | FileAttributes.Directory)) != 0 ||
            (!OperatingSystem.IsWindows() && File.GetUnixFileMode(path) != PrivateFile))
            throw new InvalidDataException("Unsafe licensing state file.");
    }
    private byte[] ReadBounded(string name, int max)
    {
        var path = Path.Combine(directory, name);
        CheckFile(path);
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length is < 1 || stream.Length > max) throw new InvalidDataException("Invalid state file size.");
        var bytes = new byte[(int)stream.Length];
        stream.ReadExactly(bytes);
        if (stream.ReadByte() != -1) throw new InvalidDataException("State changed while reading.");
        return bytes;
    }
    private void WriteNew(string name, byte[] value)
    {
        using var stream = new FileStream(Path.Combine(directory, name), Options(FileMode.CreateNew));
        stream.Write(value);
        stream.Flush(flushToDisk: true);
    }
}
