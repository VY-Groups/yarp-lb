using System.Net;
using System.Security.Cryptography;
using System.Text;

internal static class AcmeDns01NsupdateAcceptance
{
    private const string Owner = "_acme-challenge.api.example.com";
    private const string Txt = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    public static async Task RunAsync()
    {
        static void Must(bool condition, string message)
        {
            if (!condition) throw new Exception("FAIL: " + message);
        }
        static async Task MustRejectAsync(Func<Task> action, string message)
        {
            try { await action(); }
            catch (InvalidOperationException) { return; }
            throw new Exception("FAIL: accepted " + message);
        }
        var example = new AcmeDns01NsupdateOptions(
            "example.com", IPAddress.Parse("192.0.2.53"),
            Path.Combine(Path.GetTempPath(), "nsupdate"),
            new string('A', 64), Path.Combine(Path.GetTempPath(), "tsig.key"));
        var update = AcmeDns01NsupdateWriter.RenderUpdateScript(example, Owner, Txt, delete: false);
        var remove = AcmeDns01NsupdateWriter.RenderUpdateScript(example, Owner, Txt, delete: true);
        Must(update == "server 192.0.2.53 53\nzone example.com.\n" +
                  $"update add {Owner}. 30 TXT \"{Txt}\"\nsend\n" &&
             remove == "server 192.0.2.53 53\nzone example.com.\n" +
                  $"update delete {Owner}. TXT \"{Txt}\"\nsend\n" &&
             !remove.Contains($"update delete {Owner}.\n"),
            "RFC2136 update adds or deletes exactly the owned TXT without clearing the RRset");

        var writer = new AcmeDns01NsupdateWriter(example);
        await MustRejectAsync(async () =>
        {
            await writer.ProbeAuthoritativeAsync(Owner, Txt, CancellationToken.None);
        }, "nsupdate writer self-reported propagated DNS evidence");
        await MustRejectAsync(async () =>
        {
            await using var lease = await writer.PublishAsync(
                "_acme-challenge.bad.example.com\nupdate delete example.com. A",
                Txt, TimeSpan.FromMinutes(1), CancellationToken.None);
        }, "line-injection challenge owner");

        foreach (var invalid in new[]
        {
            example with {ZoneName="api.example.com."},
            example with {ZoneName="internal.test"},
            example with {UpdateServer=IPAddress.Loopback},
            example with {ExecutableSha256=new string('a',64)},
            example with {ExecutableSha256=new string('A',63)}
        })
        {
            var rejected = false;
            try { _ = new AcmeDns01NsupdateWriter(invalid); }
            catch (InvalidOperationException) { rejected = true; }
            Must(rejected, "unsafe DNS update options fail construction");
        }

        if (!OperatingSystem.IsLinux())
        {
            Console.WriteLine("PASS: cross-platform RFC2136 script and configuration guards; Linux process fixture skipped");
            return;
        }

        const UnixFileMode privateDir=UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.UserExecute;
        const UnixFileMode privateFile=UnixFileMode.UserRead|UnixFileMode.UserWrite;
        var root=Path.Combine(Path.GetTempPath(),
            "gateway-acme-update-"+Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root,privateDir);
        try
        {
            var key=Path.Combine(root,"tsig.key");
            var keySecret=Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
            File.WriteAllText(key,$"key \"gateway-acme\" {{\n algorithm hmac-sha256;\n secret \"{keySecret}\";\n}};\n");
            File.SetUnixFileMode(key,privateFile);
            var trace=Path.Combine(root,"commands.log");
            var binary=Path.Combine(root,"nsupdate-test");
            void WriteTool(int exitCode)
            {
                // Disposable test helper only; the product never launches a shell.
                File.WriteAllText(binary,
                    "#!/bin/sh\ncat >> '"+trace+"'\nprintf '\\n--end--\\n' >> '"+trace+"'\nexit "+exitCode+"\n");
                File.SetUnixFileMode(binary,privateDir);
            }
            AcmeDns01NsupdateWriter TestedWriter(int exitCode)
            {
                WriteTool(exitCode);
                var hash=Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(binary)));
                return new AcmeDns01NsupdateWriter(example with
                {
                    ExecutablePath=binary, ExecutableSha256=hash, TsigKeyFilePath=key
                });
            }
            var working=TestedWriter(exitCode:0);
            await using (var lease=await working.PublishAsync(
                Owner,Txt,TimeSpan.FromMinutes(8),CancellationToken.None))
            {
                var commands=File.ReadAllText(trace);
                Must(commands.Contains($"update add {Owner}. 30 TXT \"{Txt}\"") &&
                    !commands.Contains("update delete",StringComparison.Ordinal),
                    "RFC2136 TSIG update invoked with exact 30-second TTL and no broad cleanup");
                Must(!commands.Contains(keySecret,StringComparison.Ordinal),
                    "RFC2136 update script never contains the TSIG shared secret");
            }
            var logged=File.ReadAllText(trace);
            Must(logged.Contains($"update delete {Owner}. TXT \"{Txt}\"") &&
                 logged.Split("--end--").Length==3 &&
                 !logged.Contains("update delete example.com.",StringComparison.Ordinal),
                "lease disposal deletes only its own value and runs one cleanup command");

            File.Delete(trace);
            var failing=TestedWriter(exitCode:17);
            await MustRejectAsync(async () =>
            {
                await using var lease=await failing.PublishAsync(
                    Owner,Txt,TimeSpan.FromMinutes(8),CancellationToken.None);
            }, "rejected TSIG DNS update");
            var recovery=File.ReadAllText(trace);
            Must(recovery.Contains($"update add {Owner}. 30 TXT") &&
                recovery.Contains($"update delete {Owner}. TXT") &&
                recovery.Split("--end--").Length==3,
                "failed or ambiguous update attempts exact-value compensating cleanup");

            var staleBinary=TestedWriter(exitCode:0);
            File.AppendAllText(binary,"# modified after digest was pinned\n");
            await MustRejectAsync(async () =>
            {
                await using var lease=await staleBinary.PublishAsync(
                    Owner,Txt,TimeSpan.FromMinutes(8),CancellationToken.None);
            }, "changed executable after it was approved");
            var installedTools = Path.Combine(root,"installed-tools");
            Directory.CreateDirectory(installedTools,privateDir);
            File.SetUnixFileMode(installedTools,
                UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.UserExecute|
                UnixFileMode.GroupRead|UnixFileMode.GroupExecute|
                UnixFileMode.OtherRead|UnixFileMode.OtherExecute);
            GatewayCore.Gslb.Contracts.PrivateKeyFileSecurity
                .ValidateLinuxTrustedExecutableDirectory(installedTools,"approved updater");
            var installedExe=Path.Combine(installedTools,"nsupdate");
            File.Copy(binary,installedExe);
            File.SetUnixFileMode(installedExe,
                UnixFileMode.UserRead|UnixFileMode.UserExecute|
                UnixFileMode.GroupRead|UnixFileMode.GroupExecute|
                UnixFileMode.OtherRead|UnixFileMode.OtherExecute);
            var trustedInstalled=new AcmeDns01NsupdateWriter(example with
            {
                ExecutablePath=installedExe,
                ExecutableSha256=Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(installedExe))),
                TsigKeyFilePath=key
            });
            trustedInstalled.VerifyPreflight();
            await using(var lease=await trustedInstalled.PublishAsync(
                Owner,Txt,TimeSpan.FromMinutes(8),CancellationToken.None))
                Must(File.ReadAllText(trace).Contains("update add "+Owner, StringComparison.Ordinal),
                    "system-style executable directory with 0755 permissions supports TSIG publishing");

            var groupWritableTools=Path.Combine(root,"writable-tools");
            Directory.CreateDirectory(groupWritableTools,privateDir);
            File.SetUnixFileMode(groupWritableTools,
                UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.UserExecute|
                UnixFileMode.GroupRead|UnixFileMode.GroupWrite|UnixFileMode.GroupExecute);
            var untrustedExecutableDirectoryRejected=false;
            try
            {
                GatewayCore.Gslb.Contracts.PrivateKeyFileSecurity
                    .ValidateLinuxTrustedExecutableDirectory(groupWritableTools,"untrusted updater");
            }
            catch(InvalidDataException) {untrustedExecutableDirectoryRejected=true;}
            Must(untrustedExecutableDirectoryRejected,
                "group-writable installed executable directory fails before process launch");

            var link=Path.Combine(root,"linked-tools");
            Directory.CreateSymbolicLink(link,installedTools);
            var linkRejected=false;
            try
            {
                GatewayCore.Gslb.Contracts.PrivateKeyFileSecurity
                    .ValidateLinuxTrustedExecutableDirectory(link,"linked updater");
            }
            catch(InvalidDataException) {linkRejected=true;}
            finally { Directory.Delete(link); }
            Must(linkRejected,"symlinked executable directory is rejected even when target is trusted");
            Console.WriteLine("PASS: real Linux nsupdate subprocess, binary pin, TSIG privacy and exact-value cleanup");
        }
        finally { Directory.Delete(root,recursive:true); }
    }
}
