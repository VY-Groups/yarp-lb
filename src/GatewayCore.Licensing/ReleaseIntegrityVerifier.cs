using System.Security.Cryptography;
using System.Text.Json;

namespace GatewayCore.Licensing;

// Release trust must be independent of the entitlement signing key set.
// This validates a complete immutable package, not mutable operator state.
// It cannot prevent an administrator from patching the verifier itself.
public sealed class ReleaseIntegrityVerifier
{
    public const string ManifestName = "gatewaycore.integrity";
    private const int MaxManifest = 8 * 1024 * 1024;
    private const int MaxFiles = 20000;
    private readonly Dictionary<string, byte[]> keys = new(StringComparer.Ordinal);

    public ReleaseIntegrityVerifier(IReadOnlyDictionary<string, byte[]> publicKeys)
    {
        ArgumentNullException.ThrowIfNull(publicKeys);
        if (publicKeys.Count is < 1 or > 16) throw new ArgumentException("Missing release trust.");
        foreach (var (id, value) in publicKeys)
        {
            if (id.Length is < 1 or > 80 || id.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('-' or '_')) ||
                value.Length is < 1 or > 256) throw new ArgumentException("Invalid release trust.");
            var copy = value.ToArray();
            using var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(copy, out var read);
            if (read != copy.Length || key.ExportParameters(false).Curve.Oid.Value != "1.2.840.10045.3.1.7")
                throw new CryptographicException("Invalid release verification key.");
            keys.Add(id, copy);
        }
    }

    public string Verify(string packageRoot, string expectedSourceCommit)
    {
        var root = Path.GetFullPath(packageRoot);
        CheckRegular(root, directory: true);
        if (expectedSourceCommit.Length != 40 || expectedSourceCommit.Any(c => !char.IsAsciiHexDigit(c)))
            throw new ArgumentException("Expected source commit must be a full Git SHA.");
        var manifest = Path.Combine(root, ManifestName);
        CheckRegular(manifest, directory: false);
        using var input = new FileStream(manifest, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (input.Length is < 1 or > MaxManifest) throw new InvalidDataException("Invalid signed manifest size.");
        var bytes = new byte[(int)input.Length];
        input.ReadExactly(bytes);
        if (input.ReadByte() != -1) throw new InvalidDataException("Manifest changed during read.");
        var parts = OfflineActivationRequest.Split(bytes, MaxManifest, 4, "GCM1");
        if (!keys.TryGetValue(parts[1], out var spki)) throw new CryptographicException("Unknown release signer.");
        using (var key = ECDsa.Create())
        {
            key.ImportSubjectPublicKeyInfo(spki, out _);
            OfflineActivationRequest.VerifySignature(parts, key);
        }

        using var document = JsonDocument.Parse(OfflineActivationRequest.Decode(parts[2], 6 * 1024 * 1024),
            new JsonDocumentOptions { MaxDepth = 4 });
        var payload = document.RootElement;
        ExactFields(payload, "schemaVersion", "product", "sourceCommit", "files");
        if (payload.GetProperty("schemaVersion").GetRawText() != "1" ||
            Text(payload, "product") != "GatewayCore" ||
            !string.Equals(Text(payload, "sourceCommit"), expectedSourceCommit, StringComparison.Ordinal))
            throw new CryptographicException("Manifest source or product mismatch.");
        var rows = payload.GetProperty("files");
        if (rows.ValueKind != JsonValueKind.Array || rows.GetArrayLength() is < 1 or > MaxFiles)
            throw new InvalidDataException("Invalid release inventory.");
        var expected = new Dictionary<string, (long Size, string Hash)>(StringComparer.Ordinal);
        var folded = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var row in rows.EnumerateArray())
        {
            ExactFields(row, "path", "size", "sha256");
            var path = Text(row, "path");
            ValidatePath(path);
            var hash = Text(row, "sha256");
            var size = row.GetProperty("size");
            if (path.Equals(ManifestName, StringComparison.OrdinalIgnoreCase) || !folded.Add(path) ||
                hash.Length != 64 || hash.Any(c => !OfflineActivationRequest.IsHex(c)) ||
                size.ValueKind != JsonValueKind.Number || !size.TryGetInt64(out var length) ||
                length < 0 || length > 2L * 1024 * 1024 * 1024)
                throw new InvalidDataException("Invalid manifest file record.");
            expected.Add(path, (length, hash));
        }

        var pending = new Stack<string>();
        pending.Push(root);
        var seen = 0;
        while (pending.Count > 0)
        {
            var directory = pending.Pop();
            CheckRegular(directory, directory: true);
            foreach (var item in Directory.EnumerateFileSystemEntries(directory))
            {
                if (++seen > MaxFiles * 2) throw new InvalidDataException("Unexpected package inventory size.");
                var attr = File.GetAttributes(item);
                if ((attr & FileAttributes.ReparsePoint) != 0) throw new InvalidDataException("Package links forbidden.");
                if ((attr & FileAttributes.Directory) != 0)
                {
                    pending.Push(item);
                    continue;
                }
                var relative = Path.GetRelativePath(root, item).Replace(Path.DirectorySeparatorChar, '/');
                if (relative == ManifestName) continue;
                ValidatePath(relative);
                if (!expected.Remove(relative, out var row))
                    throw new CryptographicException("Unexpected package file.");
                using var file = new FileStream(item, FileMode.Open, FileAccess.Read, FileShare.Read);
                if (file.Length != row.Size ||
                    !CryptographicOperations.FixedTimeEquals(SHA256.HashData(file), Convert.FromHexString(row.Hash)))
                    throw new CryptographicException("Package file integrity mismatch.");
            }
        }
        if (expected.Count != 0) throw new CryptographicException("Package file missing.");
        return expectedSourceCommit;
    }

    private static void ExactFields(JsonElement value, params string[] names)
    {
        if (value.ValueKind != JsonValueKind.Object) throw new InvalidDataException("Expected object.");
        var remaining = names.ToHashSet(StringComparer.Ordinal);
        foreach (var property in value.EnumerateObject())
            if (!remaining.Remove(property.Name)) throw new InvalidDataException("Unexpected or duplicate field.");
        if (remaining.Count != 0) throw new InvalidDataException("Missing field.");
    }

    private static string Text(JsonElement value, string name) =>
        value.GetProperty(name).ValueKind == JsonValueKind.String
            ? value.GetProperty(name).GetString()! : throw new InvalidDataException("Expected string.");

    private static void ValidatePath(string path)
    {
        if (path.Length is < 1 or > 240 || path.Split('/').Any(part =>
            part.Length is < 1 or > 120 || part is "." or ".." || part.EndsWith('.') ||
            part.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('.' or '-' or '_' or '+'))))
            throw new InvalidDataException("Invalid relative package path.");
    }

    private static void CheckRegular(string path, bool directory)
    {
        var attributes = File.GetAttributes(path);
        if ((attributes & FileAttributes.ReparsePoint) != 0 ||
            ((attributes & FileAttributes.Directory) != 0) != directory)
            throw new InvalidDataException("Unsafe package path.");
    }
}
