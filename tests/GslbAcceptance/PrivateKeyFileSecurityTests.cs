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

        Console.WriteLine("PASS: Linux key owner and parent-directory trust rules");
    }
}
