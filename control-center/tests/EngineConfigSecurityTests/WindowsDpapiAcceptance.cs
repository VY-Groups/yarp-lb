using System.Security.Cryptography;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Runtime.Versioning;
using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;

/// <summary>Exercises Windows' shipping DPAPI LocalMachine key-ring protection on disposable state.</summary>
public static class WindowsDpapiAcceptance
{
    private static void Must(bool condition, string message)
    {
        if (!condition) throw new Exception("FAIL: " + message);
        Console.WriteLine("PASS: " + message);
    }

    [SupportedOSPlatform("windows")]
    private static ServiceProvider CreateProvider(string keyDirectory)
    {
        var services = new ServiceCollection();
        services.AddDataProtection()
            .SetApplicationName("GatewayCoreWindowsDpapiAcceptance.v1")
            .PersistKeysToFileSystem(new DirectoryInfo(keyDirectory))
            .ProtectKeysWithDpapi(protectToLocalMachine: true);
        return services.BuildServiceProvider();
    }

    public static void Run()
    {
        if (!OperatingSystem.IsWindows())
        {
            Console.WriteLine("SKIP: Windows DPAPI acceptance on non-Windows host");
            return;
        }

        var root = Path.Combine(Path.GetTempPath(), "gatewaycore-windows-dp-" + Guid.NewGuid().ToString("N"));
        var stateDirectory = Path.Combine(root, "ControlPlane");
        WindowsStateProtection.InitializeStateDirectory(
            root, stateDirectory);
        var keyDirectory = Path.Combine(stateDirectory, "data-protection-keys");
        try
        {
            const string payload = "windows-dpapi-session-survives-restart";
            string ciphertext;
            using (var provider = CreateProvider(keyDirectory))
            {
                ciphertext = provider.GetRequiredService<IDataProtectionProvider>()
                    .CreateProtector("session-probe").Protect(payload);
            }

            var keyFiles = Directory.GetFiles(keyDirectory, "key-*.xml");
            Must(keyFiles.Length > 0, "Windows DPAPI persists a Data Protection key XML file");
            var keyAcl = new FileInfo(keyFiles[0]).GetAccessControl(AccessControlSections.Access);
            var keyRules = keyAcl.GetAccessRules(includeExplicit: true, includeInherited: true,
                targetType: typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToArray();
            var broadSids = new[]
            {
                new SecurityIdentifier(WellKnownSidType.WorldSid, null),
                new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null),
                new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null)
            };
            Must(keyRules.All(rule => rule.AccessControlType != AccessControlType.Allow ||
                    !broadSids.Contains((SecurityIdentifier)rule.IdentityReference)),
                "Windows DPAPI key file ACL excludes Everyone, Authenticated Users, and Users");
            WindowsStateProtection.InitializeStateDirectory(root, stateDirectory);
            Must(true, "existing Windows state with the approved ACL is accepted without ACL changes");
            var originalXml = File.ReadAllText(keyFiles[0]);
            Must(originalXml.Contains("<encryptedSecret", StringComparison.Ordinal) &&
                 !originalXml.Contains("<masterKey", StringComparison.Ordinal),
                "Windows key-ring XML stores DPAPI-wrapped key material, not plaintext master keys");

            using (var restarted = CreateProvider(keyDirectory))
            {
                var recovered = restarted.GetRequiredService<IDataProtectionProvider>()
                    .CreateProtector("session-probe").Unprotect(ciphertext);
                Must(recovered == payload,
                    "Windows DPAPI decrypts a protected session with the persisted key ring after provider restart");
            }

            try
            {
                var document = XDocument.Load(keyFiles[0]);
                var encryptedSecret = document.Descendants()
                    .Single(element => element.Name.LocalName == "encryptedSecret");
                encryptedSecret.Value = Convert.ToBase64String([1, 2, 3, 4]);
                document.Save(keyFiles[0]);
                using var tamperedProvider = CreateProvider(keyDirectory);
                try
                {
                    _ = tamperedProvider.GetRequiredService<IDataProtectionProvider>()
                        .CreateProtector("session-probe").Unprotect(ciphertext);
                    throw new Exception("FAIL: tampered DPAPI key was accepted");
                }
                catch (CryptographicException)
                {
                    Console.WriteLine("PASS: tampered DPAPI key cannot decrypt existing protected session data");
                }
            }
            catch (InvalidDataException)
            {
                Console.WriteLine("PASS: malformed DPAPI key material is rejected");
            }
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }

        var unsafeProduct = Path.Combine(Path.GetTempPath(), "gatewaycore-windows-acl-reject-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(unsafeProduct);
        try
        {
            var unsafeAcl = new DirectoryInfo(unsafeProduct).GetAccessControl();
            unsafeAcl.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            unsafeAcl.AddAccessRule(new FileSystemAccessRule(
                WindowsIdentity.GetCurrent().User!, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None, AccessControlType.Allow));
            unsafeAcl.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None, AccessControlType.Allow));
            unsafeAcl.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None, AccessControlType.Allow));
            unsafeAcl.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(WellKnownSidType.WorldSid, null), FileSystemRights.ReadAndExecute,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None, AccessControlType.Allow));
            new DirectoryInfo(unsafeProduct).SetAccessControl(unsafeAcl);
            var before = new DirectoryInfo(unsafeProduct).GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.Access);
            var refused = false;
            try
            {
                WindowsStateProtection.InitializeStateDirectory(unsafeProduct,
                    Path.Combine(unsafeProduct, "ControlPlane"));
            }
            catch (InvalidOperationException)
            {
                refused = true;
            }
            var after = new DirectoryInfo(unsafeProduct).GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.Access);
            Must(refused && before == after && !Directory.Exists(Path.Combine(unsafeProduct, "ControlPlane")),
                "existing broadly accessible Windows state is rejected without ACL rewrite or key-ring mutation");
        }
        finally
        {
            Directory.Delete(unsafeProduct, recursive: true);
        }

        var unsafeKeyProduct = Path.Combine(Path.GetTempPath(), "gatewaycore-windows-key-acl-reject-" + Guid.NewGuid().ToString("N"));
        var unsafeKeyState = Path.Combine(unsafeKeyProduct, "ControlPlane");
        WindowsStateProtection.InitializeStateDirectory(unsafeKeyProduct, unsafeKeyState);
        try
        {
            var unsafeKeyFile = Path.Combine(unsafeKeyState, "data-protection-keys", "key-test.xml");
            File.WriteAllText(unsafeKeyFile, "<key />");
            var fileAcl = new FileInfo(unsafeKeyFile).GetAccessControl();
            fileAcl.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(WellKnownSidType.WorldSid, null), FileSystemRights.Read,
                AccessControlType.Allow));
            new FileInfo(unsafeKeyFile).SetAccessControl(fileAcl);
            var before = new FileInfo(unsafeKeyFile).GetAccessControl()
                .GetSecurityDescriptorSddlForm(AccessControlSections.Access);
            var refused = false;
            try
            {
                WindowsStateProtection.InitializeStateDirectory(unsafeKeyProduct, unsafeKeyState);
            }
            catch (InvalidOperationException)
            {
                refused = true;
            }
            var after = new FileInfo(unsafeKeyFile).GetAccessControl()
                .GetSecurityDescriptorSddlForm(AccessControlSections.Access);
            Must(refused && before == after && File.ReadAllText(unsafeKeyFile) == "<key />",
                "existing broadly accessible DPAPI key file is rejected without ACL or key material rewrite");
        }
        finally
        {
            Directory.Delete(unsafeKeyProduct, recursive: true);
        }
    }
}
