using System.Diagnostics;
using System.Globalization;
using System.Text;

/// <summary>
/// Diagnostics only: an independent 100ms managed-timer heartbeat in EACH
/// HA lab process. This is never enabled for ordinary L7 or product runs.
/// A missed heartbeat is evidence of a scheduling/pause gap, NOT by itself
/// proof of either a YARP defect or a hosted-runner defect.
/// </summary>
public sealed class HaProcessHeartbeat : IDisposable
{
    private readonly CancellationTokenSource stop = new();
    private readonly StreamWriter writer;
    private readonly Task runner;
    private readonly string role;
    private int disposed;

    private HaProcessHeartbeat(StreamWriter writer, string role)
    {
        this.writer = writer;
        this.role = role;
        runner = Task.Run(PumpAsync);
    }

    public static HaProcessHeartbeat? StartFromEnvironment()
    {
        var file = Environment.GetEnvironmentVariable("YARP_HA_HEARTBEAT_FILE");
        if (string.IsNullOrWhiteSpace(file)) return null;
        var role = Environment.GetEnvironmentVariable("YARP_HA_HEARTBEAT_ROLE");
        if (string.IsNullOrWhiteSpace(role))
            throw new InvalidOperationException("Heartbeat output requires a process role");
        return Start(file, role);
    }

    public static HaProcessHeartbeat Start(string file, string role)
    {
        if (!Path.IsPathFullyQualified(file) || string.IsNullOrWhiteSpace(role) ||
            role.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '-'))
            throw new ArgumentException("Heartbeat requires an absolute path and simple role");
        Directory.CreateDirectory(Path.GetDirectoryName(file)!);
        var fs = new FileStream(file, FileMode.Create, FileAccess.Write, FileShare.ReadWrite, 4096);
        var writer = new StreamWriter(fs, new UTF8Encoding(false)) { AutoFlush = true };
        writer.WriteLine("role,pid,utc_unix_ms,monotonic_ticks,stopwatch_frequency,threadpool_threads,pending_work_items,cpu_total_ms");
        return new HaProcessHeartbeat(writer, role);
    }

    private async Task PumpAsync()
    {
        try
        {
            using var proc = Process.GetCurrentProcess();
            using var interval = new PeriodicTimer(TimeSpan.FromMilliseconds(100));
            void WriteSample()
            {
                var timestamp = Stopwatch.GetTimestamp();
                var cpu = proc.TotalProcessorTime.TotalMilliseconds.ToString("F2", CultureInfo.InvariantCulture);
                writer.WriteLine(string.Join(",",
                    role, Environment.ProcessId,
                    DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    timestamp, Stopwatch.Frequency,
                    ThreadPool.ThreadCount, ThreadPool.PendingWorkItemCount, cpu));
            }
            WriteSample();
            while (await interval.WaitForNextTickAsync(stop.Token))
                WriteSample();
        }
        catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
        catch (Exception ex)
        {
            // Never let a diagnostic writer crash the gateway or change
            // request/health logic; the analyzer flags the missing samples.
            Console.Error.WriteLine("HA HEARTBEAT DIAGNOSTIC FAILED: " + ex);
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        stop.Cancel();
        try { runner.GetAwaiter().GetResult(); }
        catch (OperationCanceledException) { }
        writer.Dispose();
        stop.Dispose();
    }
}
