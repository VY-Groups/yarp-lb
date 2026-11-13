using System.Collections.Concurrent;
using System.Diagnostics.Metrics;
using System.Text;
using Microsoft.Extensions.Logging;

/// <summary>
/// Bounded logging sink for the real Control Center gateway. The request/logging
/// thread never waits for stdout; only the dedicated background writer may block
/// on a broken pipe or slow collector. Audit records MUST remain independent.
/// </summary>
public sealed class NonBlockingConsoleLoggerProvider : ILoggerProvider, ISupportExternalScope
{
    private readonly BlockingCollection<string> queue;
    private readonly TextWriter output;
    private readonly Thread worker;
    private readonly Meter meter;
    private readonly int maxLineChars;
    private IExternalScopeProvider scopes = new LoggerExternalScopeProvider();
    private long dropped;
    private long written;
    private long writeErrors;
    private long enqueued;

    public NonBlockingConsoleLoggerProvider(TextWriter output, int capacity = 1024, int maxLineChars = 4096)
    {
        if (capacity is < 1 or > 65536 || maxLineChars is < 64 or > 65536)
            throw new ArgumentOutOfRangeException(nameof(capacity), "Invalid logging bound");
        this.output = output ?? throw new ArgumentNullException(nameof(output));
        this.maxLineChars = maxLineChars;
        queue = new BlockingCollection<string>(new ConcurrentQueue<string>(), capacity);
        meter = new Meter("SpeedSignYarp.Logging", "0.1");
        meter.CreateObservableCounter<long>("yarp_logging_dropped_total",
            () => DroppedMessages, "messages", "Console log messages discarded when the bounded writer queue is full");
        meter.CreateObservableCounter<long>("yarp_logging_write_errors_total",
            () => WriteErrors, "messages", "Console log records lost on output writer failure");
        worker = new Thread(WriteLoop) { IsBackground = true, Name = "YarpBoundedConsoleWriter" };
        worker.Start();
    }

    public int Capacity => queue.BoundedCapacity;
    public int QueuedMessages => queue.Count;
    public long DroppedMessages => Interlocked.Read(ref dropped);
    public long EnqueuedMessages => Interlocked.Read(ref enqueued);
    public long WrittenMessages => Interlocked.Read(ref written);
    public long WriteErrors => Interlocked.Read(ref writeErrors);

    public ILogger CreateLogger(string categoryName) => new Logger(this, categoryName);

    public void SetScopeProvider(IExternalScopeProvider scopeProvider) =>
        scopes = scopeProvider ?? throw new ArgumentNullException(nameof(scopeProvider));

    internal IDisposable? BeginScope<TState>(TState state) where TState : notnull => scopes.Push(state);

    internal void Enqueue<TState>(string category, LogLevel level, EventId id, TState state,
        Exception? exception, Func<TState, Exception?, string> formatter)
    {
        if (queue.IsAddingCompleted) return;
        // Do not format messages when there is already no capacity. A full queue
        // must not force expensive per-request exception stringification.
        if (queue.Count >= Capacity)
        {
            Interlocked.Increment(ref dropped);
            return;
        }
        string message;
        try { message = formatter(state, exception) ?? ""; }
        catch (Exception e) { message = "[log formatter failed: " + e.GetType().Name + "]"; }
        var line = $"{DateTimeOffset.UtcNow:O} {level} {category}[{id.Id}] {message}";
        if (exception is not null) line += " " + exception;
        if (line.Length > maxLineChars)
            line = line[..(maxLineChars - 13)] + "[TRUNCATED]";
        try
        {
            if (queue.TryAdd(line)) Interlocked.Increment(ref enqueued);
            else Interlocked.Increment(ref dropped);
        }
        catch (InvalidOperationException) { Interlocked.Increment(ref dropped); }
    }

    private void WriteLoop()
    {
        foreach (var line in queue.GetConsumingEnumerable())
        {
            try
            {
                output.WriteLine(line);
                Interlocked.Increment(ref written);
            }
            catch (IOException) { Interlocked.Increment(ref writeErrors); }
            catch (ObjectDisposedException) { Interlocked.Increment(ref writeErrors); }
            // Do not log failures back through ILogger (would recurse).
        }
    }

    public void Dispose()
    {
        queue.CompleteAdding();
        // Never block shutdown indefinitely because the host stdout pipe is stuck.
        worker.Join(100);
        meter.Dispose();
        // The process owns the output stream; never dispose Console.Out.
    }

    private sealed class Logger : ILogger
    {
        private readonly NonBlockingConsoleLoggerProvider owner;
        private readonly string category;

        public Logger(NonBlockingConsoleLoggerProvider owner, string category) =>
            (this.owner, this.category) = (owner, category);

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull =>
            owner.BeginScope(state);

        public bool IsEnabled(LogLevel logLevel) => logLevel != LogLevel.None;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state,
            Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (IsEnabled(logLevel)) owner.Enqueue(category, logLevel, eventId, state, exception, formatter);
        }
    }
}
