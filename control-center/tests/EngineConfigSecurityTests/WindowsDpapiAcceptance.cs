using System.Security.Cryptography;
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
        var keyDirectory = Path.Combine(root, "keys");
        Directory.CreateDirectory(keyDirectory);
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
    }
}
