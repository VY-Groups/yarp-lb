using System.Diagnostics;

internal static class GslbServiceRestart
{
    // No request data enters the process name, service name or arguments.
    private const string WindowsCommand =
        "$ErrorActionPreference='Stop'; " +
        "$s=Get-Service -Name 'GatewayCoreGslb'; " +
        "if ($s.Status -ne 'Running') { throw 'DNS service is not running' }; " +
        "Stop-Service -Name 'GatewayCoreGslb' -ErrorAction Stop; " +
        "$s.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped,[TimeSpan]::FromSeconds(20)); " +
        "Start-Service -Name 'GatewayCoreGslb' -ErrorAction Stop; " +
        "$s.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running,[TimeSpan]::FromSeconds(20)); " +
        "exit 0";

    internal static ProcessStartInfo? ForHost()
    {
        var windows = OperatingSystem.IsWindows();
        if (!windows && !OperatingSystem.IsLinux()) return null;
        var executable = windows
            ? Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe")
            : "/usr/bin/systemctl";
        if (!File.Exists(executable)) return null;
        return Build(windows, executable);
    }

    internal static ProcessStartInfo Build(bool windows, string executable)
    {
        var result = new ProcessStartInfo(executable) { UseShellExecute = false, CreateNoWindow = true };
        foreach (var value in windows
            ? new[] { "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", WindowsCommand }
            : new[] { "--no-ask-password", "restart", "gatewaycore-gslb.service" })
            result.ArgumentList.Add(value);
        return result;
    }

    internal static async Task<bool> RunAsync(ProcessStartInfo command, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        using var process = Process.Start(command) ?? throw new InvalidOperationException("DNS restart launch failed");
        try { await process.WaitForExitAsync(token); }
        catch (OperationCanceledException)
        {
            // A stop/start may already have reached SCM/systemd. The agent's
            // durable intent remains; killing the client never proves rollback.
            try { if (!process.HasExited) process.Kill(entireProcessTree: true); }
            catch (InvalidOperationException) { }
            catch (System.ComponentModel.Win32Exception) { }
            throw;
        }
        return process.ExitCode == 0;
    }
}
