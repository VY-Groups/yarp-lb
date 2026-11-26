using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;

internal static class FleetTlsSignerAcceptance
{
    internal static async Task RunAsync()
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        var script = Path.GetFullPath(Path.Combine(Directory.GetCurrentDirectory(), "..", "ops", "fleet", "sign_fleet_tls_grant.py"));
        if (!File.Exists(script))
            throw new FileNotFoundException("Run fleet TLS signer acceptance from control-center.");
        var root = Directory.CreateTempSubdirectory("fleet-tls-signer-").FullName;
        try
        {
            File.SetUnixFileMode(root, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            var planFile = Path.Combine(root, "plan.json");
            var keyFile = Path.Combine(root, "fixture.key");
            var plan = FleetTlsPlan.Create(new string('A',64), new string('B',64),
                new string('C',64), new string('D',64), new string('E',64), new string('F',32)) with { Epoch = 17 };
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            await File.WriteAllTextAsync(keyFile, key.ExportECPrivateKeyPem());
            File.SetUnixFileMode(keyFile, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            var json = new JsonSerializerOptions(JsonSerializerDefaults.Web);
            var planJson = JsonSerializer.Serialize(plan, json);
            await File.WriteAllTextAsync(planFile, planJson);
            async Task<(int Exit, string Output)> Sign(string purpose, string evidence)
            {
                var info = new ProcessStartInfo("python3")
                {
                    UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true
                };
                foreach (var arg in new[] {script, "--plan", planFile, "--key", keyFile,
                    "--purpose", purpose, "--evidence", evidence}) info.ArgumentList.Add(arg);
                using var process = Process.Start(info) ?? throw new InvalidOperationException("Unable to start signer.");
                var output = process.StandardOutput.ReadToEndAsync();
                var error = process.StandardError.ReadToEndAsync();
                using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
                try { await process.WaitForExitAsync(deadline.Token); }
                catch (OperationCanceledException)
                {
                    if (!process.HasExited) process.Kill(entireProcessTree:true);
                    throw;
                }
                _ = await error; // never dump operator diagnostics or key file contents
                return (process.ExitCode, await output);
            }
            var publicPem = key.ExportSubjectPublicKeyInfoPem();
            foreach (var purpose in new[] {"activate", "activated", "rolled-back"})
            {
                var evidence = purpose == "activate" ? "" : new string('9',64);
                var result = await Sign(purpose,evidence);
                var grant = result.Exit == 0
                    ? JsonSerializer.Deserialize<FleetTlsGrant>(result.Output,json) : null;
                if (grant is null || grant.Purpose != purpose || grant.EvidenceSha256 != evidence ||
                    !plan.Verify(grant,publicPem,DateTimeOffset.UtcNow.ToUnixTimeSeconds()) ||
                    (plan with {Epoch=18}).Verify(grant,publicPem,DateTimeOffset.UtcNow.ToUnixTimeSeconds()))
                    throw new Exception("FAIL: independent OpenSSL signer and .NET fleet grant interoperability.");
            }
            if ((await Sign("activated","")).Exit == 0)
                throw new Exception("FAIL: completion signature without independent evidence.");
            await File.WriteAllTextAsync(planFile, planJson.Insert(1, "\"Scope\":\"" + plan.Scope + "\","));
            if ((await Sign("activate","")).Exit == 0)
                throw new Exception("FAIL: signer accepted aliased plan property.");
            Console.WriteLine("PASS: independent OpenSSL signer interoperates with .NET activation and completion grants; wrong epoch, missing evidence and duplicate aliases refused");
        }
        finally { Directory.Delete(root, recursive:true); }
    }
}
