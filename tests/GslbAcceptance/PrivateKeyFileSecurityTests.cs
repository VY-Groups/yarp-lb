using GatewayCore.Gslb.Contracts;

internal static class PrivateKeyFileSecurityTests
{
    public static void Run()
    {
        const uint serviceUid = 1001;
        static uint Mode(UnixFileMode mode) => (uint)mode;
        static void MustReject(Action action, string label)
        {
            try { action(); }
            catch (InvalidDataException) { return; }
            throw new Exception("FAIL: accepted " + label);
        }

        PrivateKeyFileSecurity.ValidateLinuxPathObject(0, Mode(UnixFileMode.UserRead),
            serviceUid, isDirectory: false, "test key");
        PrivateKeyFileSecurity.ValidateLinuxPathObject(serviceUid,
            Mode(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute),
            serviceUid, isDirectory: true, "test directory");
        PrivateKeyFileSecurity.ValidateLinuxPathObject(0,
            Mode(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute |
                 UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
                 UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute |
                 UnixFileMode.StickyBit),
            serviceUid, isDirectory: true, "sticky temporary directory");

        MustReject(() => PrivateKeyFileSecurity.ValidateLinuxPathObject(2002,
            Mode(UnixFileMode.UserRead), serviceUid, isDirectory: false, "test key"),
            "key owned by an unrelated identity");
        MustReject(() => PrivateKeyFileSecurity.ValidateLinuxPathObject(2002,
            Mode(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute),
            serviceUid, isDirectory: true, "test directory"),
            "parent directory owned by an unrelated identity");
        MustReject(() => PrivateKeyFileSecurity.ValidateLinuxPathObject(0,
            Mode(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute |
                 UnixFileMode.OtherWrite),
            serviceUid, isDirectory: true, "test directory"),
            "non-sticky world-writable parent directory");
        MustReject(() => PrivateKeyFileSecurity.ValidateLinuxPathObject(serviceUid,
            Mode(UnixFileMode.UserWrite),
            serviceUid, isDirectory: false, "test key"),
            "key without owner-read permission");

        var root = Path.Combine(Path.GetTempPath(), "gslb-state-hash-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        if (OperatingSystem.IsLinux())
            File.SetUnixFileMode(root, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        try
        {
            var file = Path.Combine(root, "state.json");
            var payload = System.Text.Encoding.ASCII.GetBytes("bounded test replay state");
            File.WriteAllBytes(file, payload);
            if (OperatingSystem.IsLinux())
                File.SetUnixFileMode(file, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            var hash = PrivateKeyFileSecurity.HashPrivateFileSha256(file, "observer replay", 4096);
            if (!hash.AsSpan().SequenceEqual(System.Security.Cryptography.SHA256.HashData(payload)))
                throw new Exception("FAIL: opened-handle digest differs from SHA-256 payload");
            MustReject(() => PrivateKeyFileSecurity.HashPrivateFileSha256(file, "observer replay", 4),
                "oversized replay file in bounded hash");
            File.WriteAllText(trustedPem, publicPem);
            if (OperatingSystem.IsLinux())
            {
                File.SetUnixFileMode(trustedPem, UnixFileMode.UserRead | UnixFileMode.UserWrite |
                    UnixFileMode.GroupRead | UnixFileMode.OtherRead);
                if (PrivateKeyFileSecurity.ReadTrustedPublicKeyPem(trustedPem, "trusted signing key") != publicPem)
                    throw new Exception("FAIL: read-only 0644 trust anchor was rejected");
                File.SetUnixFileMode(trustedPem, UnixFileMode.UserRead | UnixFileMode.UserWrite |
                    UnixFileMode.GroupRead);
                if (PrivateKeyFileSecurity.ReadTrustedPublicKeyPem(trustedPem, "trusted signing key") != publicPem)
                    throw new Exception("FAIL: read-only 0640 trust anchor was rejected");
                File.SetUnixFileMode(trustedPem, UnixFileMode.UserRead | UnixFileMode.UserWrite |
                    UnixFileMode.GroupRead | UnixFileMode.GroupWrite);
                MustReject(() => PrivateKeyFileSecurity.ReadTrustedPublicKeyPem(
                    trustedPem, "trusted signing key"), "group-writable trust anchor");
            }

            if (OperatingSystem.IsLinux())
            {
                var linkedParent = Path.Combine(root, "linked-parent");
                Directory.CreateSymbolicLink(linkedParent, root);
                var linkedPath = Path.Combine(linkedParent, "state.json");
                MustReject(() => PrivateKeyFileSecurity.HashPrivateFileSha256(linkedPath, "observer replay", 4096),
                    "linked parent during periodic replay hashing");
                MustReject(() => PrivateKeyFileSecurity.ReadPrivateFileBytes(linkedPath, "observer replay", 4096),
                    "linked parent during observer restart");
                var linkedLeaf = Path.Combine(root, "linked-leaf.json");
                File.CreateSymbolicLink(linkedLeaf, file);
                MustReject(() => PrivateKeyFileSecurity.HashPrivateFileSha256(linkedLeaf, "observer replay", 4096),
                    "linked replay file leaf");
            }
        }
        finally { Directory.Delete(root, recursive: true); }
        Console.WriteLine("PASS: Linux key trust and bounded no-follow replay-state hashing");
    }
}
