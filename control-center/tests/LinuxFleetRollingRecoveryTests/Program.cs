using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.DependencyInjection;

const UnixFileMode DirMode =
    UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
const UnixFileMode FileModePrivate =
    UnixFileMode.UserRead | UnixFileMode.UserWrite;
const string AppName = "GatewayCore.FleetRotationSoftware.v1";
const string Purpose = "authentication-cookie";

static void Check(bool ok, string label)
{
    if (!ok) throw new InvalidOperationException("FAIL: " + label);
    Console.WriteLine("PASS: " + label);
}

static void Configure(string state, string currentPfx, string currentPassword,
                      string? priorPfx, string? priorPassword)
{
    Environment.SetEnvironmentVariable("YARP_CONTROL_PLANE_DIR", state);
    Environment.SetEnvironmentVariable("YARP_LINUX_DP_CERT_PFX_PATH", currentPfx);
    Environment.SetEnvironmentVariable("YARP_LINUX_DP_CERT_PASSWORD_FILE", currentPassword);
    Environment.SetEnvironmentVariable("YARP_LINUX_DP_OLD_CERT_PFX_PATH", priorPfx);
    Environment.SetEnvironmentVariable("YARP_LINUX_DP_OLD_CERT_PASSWORD_FILE", priorPassword);
    foreach (var setting in new[] {
        LinuxDpRecoveryEvidence.ManifestEnv,
        LinuxDpRecoveryEvidence.PublicKeyEnv,
        LinuxDpRecoveryEvidence.MinimumRevisionEnv,
        LinuxDpRecoveryEvidence.MinimumRevisionFileEnv,
        LinuxDpRecoveryEvidence.RequireEvidenceEnv
    })
        Environment.SetEnvironmentVariable(setting, null);
}

static ServiceProvider OpenProvider(string state, string app)
{
    LinuxKeyProtection.InitializeStateDirectory();
    var services = new ServiceCollection();
    var builder = services.AddDataProtection()
        .SetApplicationName(app)
        .PersistKeysToFileSystem(
            new DirectoryInfo(Path.Combine(state, "data-protection-keys")));
    LinuxKeyProtection.Configure(builder, state);
    return services.BuildServiceProvider();
}

static int Child(string[] a)
{
    try
    {
        if (a.Length != 8 || a[0] != "child" ||
            a[1] is not ("mint" or "verify" or "rotate") ||
            (a[6] == "-" ^ a[7] == "-"))
            return 2;
        Configure(a[2], a[3], a[4],
            a[6] == "-" ? null : a[6],
            a[7] == "-" ? null : a[7]);
        using var provider = OpenProvider(a[2], a[5]);
        var protection = provider.GetRequiredService<IDataProtectionProvider>()
            .CreateProtector(Purpose);
        if (a[1] == "rotate")
        {
            // Only the designated writer explicitly rotates. All other
            // instances are readers until the encrypted ring is replicated.
            provider.GetRequiredService<IKeyManager>().CreateNewKey(
                DateTimeOffset.UtcNow.AddSeconds(1),
                DateTimeOffset.UtcNow.AddDays(14));
            return 0;
        }
        if (a[1] == "mint")
        {
            var content = Console.In.ReadLine();
            if (content is not ("old-session" or "new-session"))
                return 2;
            Console.WriteLine(protection.Protect(content));
            return 0;
        }
        var cookie = Console.In.ReadLine();
        var expected = Console.In.ReadLine();
        return cookie is not null && expected is not null &&
            protection.Unprotect(cookie) == expected ? 0 : 3;
    }
    catch (Exception)
    {
        // All failure reporting is through numeric exit codes only; never
        // print private PFX paths, passwords, cookies or XML contents.
        return 3;
    }
}

static (string Pfx, string Password) CreateCert(string directory, string name)
{
    using var rsa = RSA.Create(3072);
    var request = new CertificateRequest("CN=Disposable GatewayCore " + name,
        rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    request.CertificateExtensions.Add(
        new X509BasicConstraintsExtension(false, false, 0, true));
    request.CertificateExtensions.Add(
        new X509KeyUsageExtension(X509KeyUsageFlags.KeyEncipherment, true));
    using var certificate = request.CreateSelfSigned(
        DateTimeOffset.UtcNow.AddDays(-1),
        DateTimeOffset.UtcNow.AddDays(30));
    var password = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
    var pfx = Path.Combine(directory, name + ".pfx");
    var secret = Path.Combine(directory, name + ".password");
    var bytes = certificate.Export(X509ContentType.Pkcs12, password);
    try { File.WriteAllBytes(pfx, bytes); }
    finally { CryptographicOperations.ZeroMemory(bytes); }
    File.WriteAllText(secret, password);
    File.SetUnixFileMode(pfx, FileModePrivate);
    File.SetUnixFileMode(secret, FileModePrivate);
    return (pfx, secret);
}

static (string Pfx, string Password) CopyCert(
    (string Pfx, string Password) from, string directory, string label)
{
    var pfx = Path.Combine(directory, label + ".pfx");
    var password = Path.Combine(directory, label + ".password");
    File.Copy(from.Pfx, pfx);
    File.Copy(from.Password, password);
    File.SetUnixFileMode(pfx, FileModePrivate);
    File.SetUnixFileMode(password, FileModePrivate);
    return (pfx, password);
}

static void ReplicateOnlyNewEncryptedKeys(string from, string to)
{
    foreach (var file in Directory.GetFiles(
                 Path.Combine(from, "data-protection-keys"), "*.xml"))
    {
        var dest = Path.Combine(to, "data-protection-keys",
                                Path.GetFileName(file));
        if (File.Exists(dest))
        {
            if (!CryptographicOperations.FixedTimeEquals(
                SHA256.HashData(File.ReadAllBytes(file)),
                SHA256.HashData(File.ReadAllBytes(dest))))
                throw new InvalidOperationException(
                    "Refuse divergent existing fleet ring XML");
        }
        else
        {
            File.Copy(file, dest, overwrite: false);
            File.SetUnixFileMode(dest, FileModePrivate);
        }
    }
}

static (int Exit, string Output) RunChild(
    string mode, string state, (string Pfx, string Password) current,
    (string Pfx, string Password)? old, string app, params string[] stdin)
{
    var start = new ProcessStartInfo("dotnet")
    {
        UseShellExecute = false, RedirectStandardInput = true,
        RedirectStandardOutput = true, RedirectStandardError = true,
        CreateNoWindow = true
    };
    foreach (var a in new[] {
        System.Reflection.Assembly.GetExecutingAssembly().Location, "child",
        mode, state, current.Pfx, current.Password, app,
        old?.Pfx ?? "-", old?.Password ?? "-"
    })
        start.ArgumentList.Add(a);
    using var process = Process.Start(start) ??
        throw new InvalidOperationException("Cannot launch disposable fleet node");
    foreach (var value in stdin) process.StandardInput.WriteLine(value);
    process.StandardInput.Close();
    var result = process.StandardOutput.ReadToEnd().Trim();
    // Never surface the child stdout (it can contain a disposable cookie)
    // or stderr; only expose fixed source-authored acceptance stage names.
    if (!process.WaitForExit(60000))
    {
        process.Kill(entireProcessTree: true);
        throw new InvalidOperationException("Disposable fleet node timed out");
    }
    return (process.ExitCode, result);
}

if (args.Length > 0 && args[0] == "child")
    return Child(args);

if (!OperatingSystem.IsLinux() ||
    Environment.GetEnvironmentVariable("GITHUB_ACTIONS") != "true" ||
    Environment.GetEnvironmentVariable("RUNNER_OS") != "Linux")
    throw new InvalidOperationException(
        "REFUSED: real rotation/DR acceptance requires disposable Linux GitHub CI");

var root = Path.Combine(Path.GetTempPath(),
    "dp-fleet-rolling-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(root, DirMode);
try
{
    var nodeA = Path.Combine(root, "gateway-a");
    var nodeB = Path.Combine(root, "gateway-b");
    var escrow = Path.Combine(root, "independent-escrow");
    foreach (var path in new[] {nodeA,nodeB,escrow})
        Directory.CreateDirectory(path, DirMode);
    var secretsA = Path.Combine(nodeA, "secrets");
    var secretsB = Path.Combine(nodeB, "secrets");
    Directory.CreateDirectory(secretsA, DirMode);
    Directory.CreateDirectory(secretsB, DirMode);
    var oldA = CreateCert(secretsA, "old");
    var nextA = CreateCert(secretsA, "new");
    var oldB = CopyCert(oldA, secretsB, "old");
    var nextB = CopyCert(nextA, secretsB, "new");
    // Independent custody is an offline encrypted PFX escrow with separate
    // private files, not keys read from a restored application state root.
    var archivedOldB = CopyCert(oldA, escrow, "approved-old-recovery");

    foreach (var state in new[] {nodeA,nodeB})
    {
        Configure(state, oldA.Pfx, oldA.Password, null, null);
        LinuxKeyProtection.InitializeStateDirectory();
    }
    var mintOld = RunChild("mint", nodeA, oldA, null, AppName, "old-session");
    Check(mintOld.Exit == 0 && !string.IsNullOrEmpty(mintOld.Output),
          "independent node A minted encrypted old-session cookie");
    ReplicateOnlyNewEncryptedKeys(nodeA, nodeB);
    Check(RunChild("verify", nodeB, oldB, null, AppName,
                   mintOld.Output, "old-session").Exit == 0,
          "node B independently decrypts old cookie using encrypted shared ring");

    // Prepare B's new + previous identity while A still serves old. Before
    // a fresh rotation key is published, every node must pass this preflight.
    Check(RunChild("verify", nodeB, nextB, oldB, AppName,
                   mintOld.Output, "old-session").Exit == 0 &&
          RunChild("verify", nodeA, oldA, null, AppName,
                   mintOld.Output, "old-session").Exit == 0,
          "rolling pre-stage keeps previous authentication active on both nodes");
    Check(RunChild("verify", nodeA, nextA, oldA, AppName,
                   mintOld.Output, "old-session").Exit == 0,
          "both fleet nodes can decrypt previous sessions before key activation");

    var before = Directory.GetFiles(Path.Combine(nodeA,"data-protection-keys"),
                                    "key-*.xml").Length;
    Check(RunChild("rotate", nodeA, nextA, oldA, AppName).Exit == 0,
          "designated source writer explicitly created new certificate-wrapped key");
    Check(Directory.GetFiles(Path.Combine(nodeA,"data-protection-keys"),
                             "key-*.xml").Length == before + 1,
          "rotation added precisely one new encrypted key without replacing old keys");
    ReplicateOnlyNewEncryptedKeys(nodeA, nodeB);
    // An explicitly issued key does not become the active encrypting key
    // until its scheduled activation has elapsed on independently restarted
    // service instances.
    Thread.Sleep(TimeSpan.FromSeconds(2));
    var mintNew = RunChild("mint", nodeA, nextA, oldA, AppName, "new-session");
    Check(mintNew.Exit == 0 && !string.IsNullOrEmpty(mintNew.Output),
          "new session minted after rotation in a fresh service process");
    var oldPayload = Microsoft.AspNetCore.WebUtilities.WebEncoders.Base64UrlDecode(
        mintOld.Output);
    var newPayload = Microsoft.AspNetCore.WebUtilities.WebEncoders.Base64UrlDecode(
        mintNew.Output);
    Check(oldPayload.Length >= 20 && newPayload.Length >= 20 &&
          !oldPayload.AsSpan(4, 16).SequenceEqual(newPayload.AsSpan(4, 16)),
          "new session is protected by an actually different rotated DP key");
    foreach (var (state, now, old) in new[] {
        (nodeA, nextA, oldA), (nodeB, nextB, oldB)
    })
        Check(RunChild("verify", state, now, old, AppName,
                       mintOld.Output, "old-session").Exit == 0 &&
              RunChild("verify", state, now, old, AppName,
                       mintNew.Output, "new-session").Exit == 0,
              "separate fleet node retains both old and newly rotated sessions");

    // A secure rollback *retains* both identities to avoid invalidating
    // sessions issued during the new-key period.
    Check(RunChild("verify", nodeA, oldA, nextA, AppName,
                   mintNew.Output, "new-session").Exit == 0 &&
          RunChild("verify", nodeA, oldA, nextA, AppName,
                   mintOld.Output, "old-session").Exit == 0,
          "safe rollback configuration retains both session generations");

    // Simulate loss of a previously trusted private wrapping key, then
    // restore only the protected PFX from independently held escrow.
    File.Delete(oldB.Pfx);
    Check(RunChild("verify", nodeB, nextB, oldB, AppName,
                   mintOld.Output, "old-session").Exit != 0,
          "lost previous wrapping key fails closed, not plaintext or silent fallback");
    File.Copy(archivedOldB.Pfx, oldB.Pfx, overwrite: false);
    File.SetUnixFileMode(oldB.Pfx, FileModePrivate);
    Check(RunChild("verify", nodeB, nextB, oldB, AppName,
                   mintOld.Output, "old-session").Exit == 0 &&
          RunChild("verify", nodeB, nextB, oldB, AppName,
                   mintNew.Output, "new-session").Exit == 0,
          "independently custodied private-key recovery restores both sessions");

    Check(RunChild("verify", nodeB, nextB, oldB, "OtherTenant.v1",
                   mintOld.Output, "old-session").Exit != 0,
          "cross-tenant Data Protection application boundary rejects old session");
    Console.WriteLine(
        "PASS: real separate-process two-node rolling certificate and lost-key DR software rehearsal");
}
finally
{
    // The whole disposable subtree is owner-only and contains only
    // ephemeral self-signed keys/cookies created by this test.
    if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
}

return 0;
