using System.Diagnostics;
using System.Globalization;
using System.Text;

/// <summary>
/// Diagnostic-only heartbeat on a DEDICATED OS thread, independent of the
/// request-handling ThreadPool. Enabled only by the disposable HA harness.
/// A missed tick is not automatically a gateway fault or host-wide pause.
/// </summary>
public sealed class HaProcessHeartbeat : IDisposable
{
    private readonly ManualResetEventSlim stopping = new(false);
    private readonly StreamWriter writer;
    private readonly Thread thread;
    private readonly string role;
    private int disposed;

    private HaProcessHeartbeat(StreamWriter writer, string role)
    {
        this.writer = writer;
        this.role = role;
        // ThreadPool tasks can themselves starve under HA request load,
        // producing false "runner paused" conclusions. An independent
        // dedicated thread keeps sampling during ThreadPool backpressure.
        thread = new Thread(Pump)
        {
            IsBackground = true,
            Name = "ha-heartbeat-" + role,
        };
        thread.Start();
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

    private void Pump()
    {
        try
        {
            using var proc = Process.GetCurrentProcess();
            do
            {
                var timestamp = Stopwatch.GetTimestamp();
                var cpu = proc.TotalProcessorTime.TotalMilliseconds.ToString("F2", CultureInfo.InvariantCulture);
                writer.WriteLine(string.Join(",",
                    role, Environment.ProcessId,
                    DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    timestamp, Stopwatch.Frequency,
                    ThreadPool.ThreadCount, ThreadPool.PendingWorkItemCount, cpu));
            }
            while (!stopping.Wait(100)); // 100 ms; not scheduled via ThreadPool.
        }
        catch (Exception ex)
        {
            // Diagnostics must never terminate a gateway or change routing.
            Console.Error.WriteLine("HA HEARTBEAT DIAGNOSTIC FAILED: " + ex);
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        stopping.Set();
        thread.Join();
        writer.Dispose();
        stopping.Dispose();
    }
}
