using System.Text.Json;
using System.Text.Json.Nodes;

/// <summary>Single-process serialization of the existing local audit log.
/// Not an immutable, multi-process or externally durable audit sink.</summary>
internal sealed class LocalAdminAudit
{
    private readonly string path;
    private readonly SemaphoreSlim gate = new(1, 1);

    public LocalAdminAudit(string path) => this.path = path;

    public async Task AppendAsync(string actor, string action, object? details = null)
    {
        var line = JsonSerializer.Serialize(new { utc = DateTimeOffset.UtcNow, actor, action, details });
        await gate.WaitAsync().ConfigureAwait(false);
        try
        {
            await File.AppendAllTextAsync(path, line + Environment.NewLine).ConfigureAwait(false);
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
