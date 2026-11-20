using System.Text.Json;

/// <summary>Single gateway process, bounded persistent queue of authenticated
/// historical events. Never queues or retries a mutation-authorizing intent.</summary>
internal sealed class DurableAuditOutbox : IDisposable
{
    private const int MaxEntryBytes = 8192;
    private const int MaxEntries = 4096;
    private readonly string directory;
    private readonly ExternalAuditIntent transport;
    private readonly FileStream ownership;
    private readonly object gate = new();
    private readonly SemaphoreSlim delivery = new(1, 1);
    private bool storageFault;
    private bool deliveryBlocked;

    internal DurableAuditOutbox(string directory, ExternalAuditIntent transport)
    {
        if (!Path.IsPathFullyQualified(directory) || !Directory.Exists(directory))
            throw new InvalidDataException("Audit outbox requires an existing absolute private directory");
        this.directory = directory;
        this.transport = transport;
        CheckDirectory();
        var ownerPath = Path.Combine(directory, "owner.lock");
        if (File.Exists(ownerPath)) CheckFile(ownerPath);
        var options = new FileStreamOptions { Mode = FileMode.OpenOrCreate, Access = FileAccess.ReadWrite, Share = FileShare.None };
        if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        ownership = new FileStream(ownerPath, options);
        try
        {
            var paths = Entries();
            if (paths.Length > MaxEntries) throw new InvalidDataException("Audit outbox exceeds capacity");
            foreach (var path in paths) Read(path);
        }
        catch { ownership.Dispose(); throw; }
    }

    private static void CheckPrivate(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0 ||
            (!OperatingSystem.IsWindows() && (File.GetUnixFileMode(path) &
                (UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
                 UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute)) != 0))
            throw new InvalidDataException("Audit outbox requires private non-link state");
    }
    private void CheckDirectory()
    {
        if (!Directory.Exists(directory)) throw new IOException("Audit outbox directory missing");
        CheckPrivate(directory);
    }
    private static void CheckFile(string path)
    {
        if (!File.Exists(path)) throw new IOException("Audit queue entry missing");
        CheckPrivate(path);
    }
    private string[] Entries()
    {
        CheckDirectory();
        CheckFile(Path.Combine(directory, "owner.lock"));
        var paths = new List<string>();
        foreach (var path in Directory.EnumerateFileSystemEntries(directory))
        {
            var name = Path.GetFileName(path);
            if (name == "owner.lock") { CheckFile(path); continue; }
            // A crash before the atomic rename leaves an ambiguous temporary
            // record. Never silently discard it or claim the queue is empty.
            if (!name.EndsWith(".event", StringComparison.Ordinal) || !Guid.TryParseExact(name[..^6], "N", out _))
                throw new InvalidDataException("Unknown or incomplete audit outbox file; reconcile before retry");
            CheckFile(path);
            paths.Add(path);
            if (paths.Count > MaxEntries) throw new InvalidDataException("Audit outbox capacity exceeded");
        }
        return paths.OrderBy(p => p, StringComparer.Ordinal).ToArray();
    }
    private ExternalAuditIntent.QueuedEvent Read(string path)
    {
        CheckFile(path);
        using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (file.Length is < 1 or > MaxEntryBytes) throw new InvalidDataException("Invalid audit outbox record size");
        var bytes = new byte[(int)file.Length];
        file.ReadExactly(bytes);
        var row = JsonSerializer.Deserialize<ExternalAuditIntent.QueuedEvent>(bytes)
            ?? throw new InvalidDataException("Invalid audit outbox record");
        if (Path.GetFileName(path) != row.Id + ".event" || !transport.ValidEvent(row))
            throw new InvalidDataException("Audit outbox record authentication failed");
        return row;
    }

    internal void Enqueue(string actor, string action, DateTimeOffset utc, string digest, string? intentId = null)
    {
        lock (gate)
        {
            if (storageFault) throw new IOException("Audit outbox storage fault is latched");
            try
            {
                if (Entries().Length >= MaxEntries) throw new QueueFullException();
                var row = transport.CreateEvent(actor, action, utc, digest, intentId);
                var target = Path.Combine(directory, row.Id + ".event");
                var bytes = JsonSerializer.SerializeToUtf8Bytes(row);
                if (bytes.Length > MaxEntryBytes) throw new InvalidDataException("Audit queue record too large");
                var temp = target + ".tmp";
                var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
                if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
                using (var file = new FileStream(temp, options))
                {
                    file.Write(bytes);
                    file.Flush(flushToDisk: true);
                }
                File.Move(temp, target, overwrite: false);
            }
            catch (QueueFullException) { throw; }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or InvalidOperationException or InvalidDataException)
            { storageFault = true; throw; }
        }
    }

    private sealed class QueueFullException() : IOException("Audit outbox full; no event discarded") { }

    internal async Task<bool> DeliverOneAsync(CancellationToken ct)
    {
        if (!await delivery.WaitAsync(0, ct)) return false;
        try
        {
            string path;
            ExternalAuditIntent.QueuedEvent row;
            lock (gate)
            {
                if (storageFault) return false;
                try
                {
                    var paths = Entries();
                    if (paths.Length == 0) { deliveryBlocked = false; return false; }
                    // GUID order is intentionally not an occurrence-order claim.
                    path = paths[0];
                    row = Read(path);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or InvalidOperationException or InvalidDataException)
                { storageFault = true; return false; }
            }
            var received = await transport.DeliverEventAsync(row, ct);
            lock (gate)
            {
                deliveryBlocked = !received;
                if (!received || ct.IsCancellationRequested || storageFault) return false;
                try
                {
                    var current = Read(path);
                    if (current.Mac != row.Mac || !current.Payload.AsSpan().SequenceEqual(row.Payload))
                        throw new InvalidDataException("Audit queue changed during receipt");
                    File.Delete(path);
                    return true;
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or InvalidOperationException or InvalidDataException)
                { storageFault = true; return false; }
            }
        }
        finally { delivery.Release(); }
    }

    internal (int Pending, bool StorageFault, bool DeliveryBlocked) Status()
    {
        lock (gate)
        {
            try { return (Entries().Length, storageFault, deliveryBlocked); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or InvalidDataException)
            { storageFault = true; return (-1, true, deliveryBlocked); }
        }
    }
    public void Dispose() { ownership.Dispose(); delivery.Dispose(); }
}
