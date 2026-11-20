using System.Text.Json;
using System.Text.Json.Nodes;

/// <summary>Single-process serialization of the existing local audit log.
/// Not an immutable, multi-process or externally durable audit sink.</summary>
internal sealed class LocalAdminAudit
{
    private readonly string path;
    private readonly SemaphoreSlim gate = new(1, 1);

    private readonly DurableAuditOutbox? outbox;
    public LocalAdminAudit(string path, DurableAuditOutbox? outbox = null) { this.path = path; this.outbox = outbox; }

    public async Task AppendAsync(string actor, string action, object? details = null, string? intentId = null)
    {
        var utc = DateTimeOffset.UtcNow;
        var line = intentId is null
            ? JsonSerializer.Serialize(new { utc, actor, action, details })
            : JsonSerializer.Serialize(new { utc, actor, action, details, intentId });
        await gate.WaitAsync().ConfigureAwait(false);
        try
        {
            try
            {
                outbox?.Enqueue(actor, action, utc, Convert.ToHexString(
                    System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(line))), intentId);
            }
            finally
            {
                // Keep the local evidence even when the external queue is full
                // or damaged; propagate the queue error to the caller.
                await File.AppendAllTextAsync(path, line + Environment.NewLine).ConfigureAwait(false);
            }
        }
        finally { gate.Release(); }
    }

    public async Task<JsonNode?[]> ReadRecentAsync()
    {
        await gate.WaitAsync().ConfigureAwait(false);
        try
        {
            return File.Exists(path)
                ? File.ReadLines(path).TakeLast(80).Reverse().Select(line => JsonNode.Parse(line)).ToArray()
                : [];
        }
        finally { gate.Release(); }
    }
}
