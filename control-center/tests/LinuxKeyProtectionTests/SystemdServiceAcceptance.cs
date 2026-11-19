using System.Diagnostics;

internal static class SystemdServiceAcceptance
{
    public static async Task RunTerminationCleanupContractAsync()
    {
        var marker = Path.Combine(Path.GetTempPath(), $"gatewaycore-termination-cleanup-{Guid.NewGuid():N}");
        var (process, processGroupId, pidFile) = await StartSessionProcessAsync(
            "bash", ["-c", "trap 'printf cleaned > \"$1\"' EXIT; trap 'exit 143' TERM; sleep 60", "systemd-cleanup-contract", marker],
            Environment.CurrentDirectory);
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        try
        {
            await StopProcessGroupAsync(process, processGroupId, TimeSpan.FromSeconds(10));
            await stdout;
            await stderr;
            if (!File.Exists(marker) || File.ReadAllText(marker) != "cleaned")
                throw new InvalidOperationException("Graceful process-group termination did not run the EXIT cleanup trap.");
            Console.WriteLine("PASS: systemd acceptance timeout signaling preserves shell EXIT cleanup");
        }
        finally
        {
            if (!process.HasExited)
            {
                try { process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
                await process.WaitForExitAsync();
            }
            process.Dispose();
            File.Delete(pidFile);
            File.Delete(marker);
        }
    }

    public static async Task RunFromGitHubLinuxAsync()
    {
        if (!OperatingSystem.IsLinux() ||
            !string.Equals(Environment.GetEnvironmentVariable("GITHUB_ACTIONS"), "true", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        var (process, processGroupId, pidFile) = await StartSessionProcessAsync(
            "sudo", ["-n", "bash", "tests/LinuxKeyProtectionTests/systemd_service_acceptance.sh"], Environment.CurrentDirectory);
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(5));
        try
        {
            await process.WaitForExitAsync(timeout.Token);
        }
        catch (OperationCanceledException)
        {
            var exitedGracefully = await StopProcessGroupAsync(process, processGroupId, TimeSpan.FromSeconds(15));
            var timedOutOutput = await stdout;
            var timedOutError = await stderr;
            if (!string.IsNullOrWhiteSpace(timedOutOutput)) Console.Write(timedOutOutput);
            if (!string.IsNullOrWhiteSpace(timedOutError)) Console.Error.Write(timedOutError);
            if (!exitedGracefully)
                Console.Error.WriteLine("Systemd acceptance required forced termination after its cleanup grace period.");
            process.Dispose();
            File.Delete(pidFile);
            throw new TimeoutException("Linux systemd acceptance exceeded five minutes.");
        }

        var output = await stdout;
        var error = await stderr;
        var exitCode = process.ExitCode;
        process.Dispose();
        File.Delete(pidFile);
        if (!string.IsNullOrWhiteSpace(output)) Console.Write(output);
        if (!string.IsNullOrWhiteSpace(error)) Console.Error.Write(error);
        if (exitCode != 0)
        {
            throw new InvalidOperationException($"Linux systemd acceptance failed with exit code {exitCode}.");
        }
    }

    private static async Task<(Process Process, int ProcessGroupId, string PidFile)> StartSessionProcessAsync(
        string executable, IReadOnlyList<string> arguments, string workingDirectory)
    {
        var pidFile = Path.Combine(Path.GetTempPath(), $"gatewaycore-session-pid-{Guid.NewGuid():N}");
        var start = new ProcessStartInfo("setsid")
        {
            WorkingDirectory = workingDirectory,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };
        start.ArgumentList.Add("--wait");
        start.ArgumentList.Add("bash");
        start.ArgumentList.Add("-c");
        start.ArgumentList.Add("pid_file=$1; shift; printf '%s\\n' \"$$\" > \"$pid_file\"; exec \"$@\"");
        start.ArgumentList.Add("gatewaycore-session-wrapper");
        start.ArgumentList.Add(pidFile);
        start.ArgumentList.Add(executable);
        foreach (var argument in arguments) start.ArgumentList.Add(argument);

        var process = Process.Start(start) ?? throw new InvalidOperationException("Could not start the isolated Linux acceptance process.");
        try
        {
            for (var attempt = 0; attempt < 100 && !File.Exists(pidFile); attempt++)
            {
                if (process.HasExited) throw new InvalidOperationException("The isolated Linux acceptance process exited before reporting its process-group ID.");
                await Task.Delay(20);
            }
            if (!File.Exists(pidFile)) throw new TimeoutException("The isolated Linux acceptance process did not report its process-group ID.");
            if (!int.TryParse(await File.ReadAllTextAsync(pidFile), out var processGroupId) || processGroupId <= 0)
                throw new InvalidOperationException("The isolated Linux acceptance process reported an invalid process-group ID.");
            return (process, processGroupId, pidFile);
        }
        catch
        {
            try { process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
            await process.WaitForExitAsync();
            process.Dispose();
            File.Delete(pidFile);
            throw;
        }
    }

    private static async Task<bool> StopProcessGroupAsync(Process process, int processGroupId, TimeSpan grace)
    {
        if (process.HasExited) return true;

        var signal = new ProcessStartInfo("kill")
        {
            UseShellExecute = false
        };
        signal.ArgumentList.Add("-TERM");
        signal.ArgumentList.Add("--");
        signal.ArgumentList.Add("-" + processGroupId);
        using (var sender = Process.Start(signal))
        {
            if (sender is not null) await sender.WaitForExitAsync();
        }

        using var timeout = new CancellationTokenSource(grace);
        try
        {
            await process.WaitForExitAsync(timeout.Token);
            return true;
        }
        catch (OperationCanceledException)
        {
            process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync();
            return false;
        }
    }
}
