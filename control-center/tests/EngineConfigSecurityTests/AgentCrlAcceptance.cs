using System.Diagnostics;

/// <summary>Runs the real production-mode Agent CRL test on disposable CI hosts.</summary>
public static class AgentCrlAcceptance
{
    public static async Task RunAsync()
    {
        var script = Path.Combine(Directory.GetCurrentDirectory(), "tests",
            "EngineConfigSecurityTests", "agent_crl_acceptance.py");
        if (!File.Exists(script))
            throw new FileNotFoundException("Build/run from the control-center root", script);
        var cleanupFile = Path.Combine(Path.GetTempPath(), "gatewaycore-crl-root-" + Guid.NewGuid().ToString("N") + ".txt");

        var start = new ProcessStartInfo(OperatingSystem.IsWindows() ? "python" : "python3")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = Directory.GetCurrentDirectory()
        };
        start.Environment["GATEWAY_CRL_TEST_ROOT_THUMBPRINT_FILE"] = cleanupFile;
        start.ArgumentList.Add(script);
        try
        {
            using var process = Process.Start(start)
                ?? throw new InvalidOperationException("Could not start disposable CRL acceptance");
            var stdout = process.StandardOutput.ReadToEndAsync();
            var stderr = process.StandardError.ReadToEndAsync();
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(90));
            try
            {
                await process.WaitForExitAsync(timeout.Token);
            }
            catch (OperationCanceledException)
            {
                process.Kill(entireProcessTree: true);
                await process.WaitForExitAsync();
                _ = await stdout;
                _ = await stderr;
                throw new TimeoutException("Disposable CRL acceptance exceeded 90 seconds");
            }

            var output = await stdout;
            var errors = await stderr;
            Console.Write(output);
            if (process.ExitCode != 0)
                throw new InvalidOperationException(
                    $"Disposable production-mode CRL acceptance failed ({process.ExitCode}):\n{errors}");
        }
        finally
        {
            if (OperatingSystem.IsWindows() && File.Exists(cleanupFile))
            {
                var thumbprint = (await File.ReadAllTextAsync(cleanupFile)).Trim();
                if (thumbprint.Length != 0)
                    await RemoveWindowsTestRootAsync(thumbprint);
                File.Delete(cleanupFile);
            }
        }
    }

    private static async Task RemoveWindowsTestRootAsync(string thumbprint)
    {
        var testHost = Path.Combine(Directory.GetCurrentDirectory(), "tests",
            "EngineConfigSecurityTests", "bin", "Release", "net10.0", "EngineConfigSecurityTests.dll");
        if (!File.Exists(testHost))
            throw new FileNotFoundException("Build EngineConfigSecurityTests before trust-store cleanup", testHost);
        var start = new ProcessStartInfo("dotnet")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = Directory.GetCurrentDirectory()
        };
        start.ArgumentList.Add(testHost);
        start.ArgumentList.Add("--crl-test-root-remove");
        start.ArgumentList.Add(thumbprint);
        using var process = Process.Start(start)
            ?? throw new InvalidOperationException("Could not start bounded CRL trust-root cleanup");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        try
        {
            await process.WaitForExitAsync(timeout.Token);
        }
        catch (OperationCanceledException)
        {
            process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync();
            throw new TimeoutException("Windows CRL test-root cleanup exceeded 20 seconds");
        }
        var output = await stdout;
        var errors = await stderr;
        Console.Write(output);
        if (process.ExitCode != 0)
            throw new InvalidOperationException($"Windows CRL test-root cleanup failed:\n{errors}");
    }
}
