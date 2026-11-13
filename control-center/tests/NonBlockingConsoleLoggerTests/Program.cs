using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Text;
using Microsoft.Extensions.Logging;

static void Must(bool condition, string description)
{
    if (!condition) throw new Exception("FAIL: "+description);
    Console.WriteLine("PASS: "+description);
}

using var hold = new ManualResetEventSlim(false);
using var entered = new ManualResetEventSlim(false);
using var writer = new BlockedWriter(hold, entered);
using var provider = new NonBlockingConsoleLoggerProvider(writer, capacity: 32, maxLineChars: 128);
var logger = provider.CreateLogger("test");
logger.LogWarning("first queued item");
Must(entered.Wait(TimeSpan.FromSeconds(3)), "background writer enters simulated blocked stdout");
var stopwatch = Stopwatch.StartNew();
for (var i = 0; i < 15000; i++)
    logger.LogWarning("overload {Index}", i);
stopwatch.Stop();
Must(stopwatch.Elapsed < TimeSpan.FromSeconds(5),
    "15,000 log calls do not wait on blocked stdout");
Must(provider.DroppedMessages > 0,
    "explicit monotonically increasing dropped message counter under backpressure");
Must(provider.QueuedMessages <= 32, "bounded queue never exceeds 32 messages");
var dropped = provider.DroppedMessages;
for (var i = 0; i < 1000; i++) logger.LogWarning("more {Index}",i);
Must(provider.DroppedMessages > dropped, "drop count increases while stdout stays blocked");
var reported = false;
using(var listener = new MeterListener())
{
    listener.InstrumentPublished = (inst,l) =>
    {
        if (inst.Name == "yarp_logging_dropped_total") l.EnableMeasurementEvents(inst);
    };
    listener.SetMeasurementEventCallback<long>((inst,measurement,tags,state) =>
    {
        if (inst.Name == "yarp_logging_dropped_total" &&
            measurement == provider.DroppedMessages) reported=true;
    });
    listener.Start();
    listener.RecordObservableInstruments();
}
Must(reported, "OpenTelemetry Meter exposes the actual dropped message total");
hold.Set();
await Task.Delay(100);
Must(writer.LinesWritten > 0, "queued output resumes when stdout is unblocked");
Console.WriteLine("PRODUCT BOUNDED CONSOLE LOGGING ACCEPTANCE PASSED");

sealed class BlockedWriter : TextWriter
{
    private readonly ManualResetEventSlim release;
    private readonly ManualResetEventSlim entered;
    private int lines;
    public BlockedWriter(ManualResetEventSlim release, ManualResetEventSlim entered) =>
        (this.release,this.entered) = (release,entered);
    public override Encoding Encoding => Encoding.UTF8;
    public int LinesWritten => Volatile.Read(ref lines);
    public override void WriteLine(string? value)
    {
        entered.Set();
        release.Wait();
        Interlocked.Increment(ref lines);
    }
}
