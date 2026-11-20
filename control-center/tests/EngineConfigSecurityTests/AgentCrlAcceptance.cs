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
        var start = new ProcessStartInfo(OperatingSystem.IsWindows() ? "python" : "python3")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = Directory.GetCurrentDirectory()
        };
        start.ArgumentList.Add(script);
        start.Environment["GATEWAY_FLEET_RECOVERY_TEST_DLL"] = typeof(AgentCrlAcceptance).Assembly.Location;
        using var process = Process.Start(start)
            ?? throw new InvalidOperationException("Could not start disposable CRL acceptance");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(240));
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
            throw new TimeoutException("Disposable CRL acceptance exceeded 240 seconds");
        }
        var output = await stdout;
        var errors = await stderr;
        Console.Write(output);
        if (process.ExitCode != 0)
            throw new InvalidOperationException(
                $"Disposable production-mode CRL acceptance failed ({process.ExitCode}):\n{errors}");
    }
}
