using System.Net;
var port = args.Length > 0 && int.TryParse(args[0], out var p) ? p : 18081;
var name = args.Length > 1 ? args[1] : "node-a";
if (port is < 1025 or > 65535 || name.Length > 40) throw new ArgumentException("Invalid lab-only backend arguments");
var builder = WebApplication.CreateBuilder(args);
builder.WebHost.UseUrls($"http://127.0.0.1:{port}");
var app = builder.Build();
var ready = true;
app.MapGet("/health/ready", () => ready ? (IResult)Results.Ok(new { ready = true, node = name }) : Results.StatusCode(503));
app.MapGet("/api/identity", () => Results.Ok(new { node = name, serverTimeUtc = DateTimeOffset.UtcNow }));
// Test-only toggles restricted to loopback. Never deploy this mock to production.
app.MapPost("/test/ready/{value}", (HttpContext ctx, bool value) => {
 if (ctx.Connection.RemoteIpAddress is null || !IPAddress.IsLoopback(ctx.Connection.RemoteIpAddress))
     return Results.StatusCode(403);
 ready = value;
 return Results.Ok(new { ready, node = name });
});
Console.WriteLine($"MOCK ONLY: {name} at http://127.0.0.1:{port}/");
app.Run();
