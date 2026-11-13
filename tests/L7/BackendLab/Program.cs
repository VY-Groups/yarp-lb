using System.Net;

if (args.Length != 2 || !int.TryParse(args[0], out var port) ||
    port is < 1025 or > 65535 || args[1] is not ("A" or "B"))
    throw new ArgumentException("BackendLab requires port and node A|B");

var node = args[1];
var state = new LabBackendState();
var builder = WebApplication.CreateBuilder(Array.Empty<string>());
// Keep synthetic backend output bounded under millions of proxy requests.
builder.Logging.AddFilter((provider, category, level) => level >= LogLevel.Warning);
builder.WebHost.UseUrls($"http://127.0.0.1:{port}");
var app = builder.Build();

bool IsLoopback(HttpContext ctx) =>
    ctx.Connection.RemoteIpAddress is { } ip && IPAddress.IsLoopback(ip);

app.MapGet("/health/ready", () =>
    state.Ready ? (IResult)Results.Ok(new { ready = true, node }) : Results.StatusCode(503));
app.MapGet("/api/identity", () => Results.Ok(new { node }));
app.MapGet("/api/payload/{bytes:int}", (int bytes) =>
    bytes is >= 1 and <= 65536
        ? (IResult)Results.Bytes(new byte[bytes], "application/octet-stream")
        : Results.BadRequest(new { error = "Payload size must be 1..65536" }));
app.MapGet("/lab/inflight", () => Results.Ok(new { count = Volatile.Read(ref state.InFlight) }));
app.MapPost("/lab/ready/{enabled:bool}", (HttpContext ctx, bool enabled) =>
{
    if (!IsLoopback(ctx)) return Results.StatusCode(403);
    state.Ready = enabled;
    return Results.Ok(new { ready = enabled, node });
});
app.MapGet("/kill/slow", async (HttpContext ctx) =>
{
    Interlocked.Increment(ref state.InFlight);
    try
    {
        await Task.Delay(TimeSpan.FromSeconds(12), ctx.RequestAborted);
        return Results.Ok(new { node, finished = true });
    }
    finally { Interlocked.Decrement(ref state.InFlight); }
});

app.Run();
sealed class LabBackendState
{
    public volatile bool Ready = true;
    public int InFlight;
}
