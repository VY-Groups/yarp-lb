using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;

internal static class AcmeHttp01Acceptance
{
    public static async Task RunAsync()
    {
        static void Check(bool condition, string message)
        {
            if (!condition) throw new Exception("FAIL: " + message);
        }

        var clock = new ManualTimeProvider(DateTimeOffset.Parse("2026-11-19T12:00:00Z"));
        var store = new AcmeHttp01ChallengeStore(clock);
        const string token = "0123456789abcdefABC_-";
        var authorization = token + "." + new string('A', 43);
        Check(store.TryPublish(token, authorization, TimeSpan.FromMinutes(2)), "valid HTTP-01 challenge is published");
        Check(!store.TryPublish("short", "short." + new string('A', 43), TimeSpan.FromMinutes(2)),
            "short challenge tokens are rejected");
        Check(!store.TryPublish(token, "different." + new string('A', 43), TimeSpan.FromMinutes(2)),
            "key authorization must bind the requested token");
        Check(!store.TryPublish(token, token + "." + new string('A', 42), TimeSpan.FromMinutes(2)),
            "key authorization must contain a SHA-256 thumbprint");
        Check(!store.TryPublish(token, authorization, TimeSpan.FromHours(1)), "challenge lifetime is bounded");

        var trafficHttpPort = -1;
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.ConfigureKestrel(options => options.Listen(IPAddress.Loopback, 0,
            listen => listen.Protocols = HttpProtocols.Http1));
        builder.Services.AddSingleton(store);
        await using var app = builder.Build();
        app.MapHttp01Challenge(publicChallengeEntrypointEnabled: true,
            context => AcmeHttp01Endpoint.IsPublicTrafficHttpListener(context, IPAddress.Loopback, trafficHttpPort));
        await app.StartAsync();
        try
        {
            var address = app.Services.GetRequiredService<Microsoft.AspNetCore.Hosting.Server.IServer>()
                .Features.Get<Microsoft.AspNetCore.Hosting.Server.Features.IServerAddressesFeature>()!
                .Addresses.Single(value => value.StartsWith("http://", StringComparison.OrdinalIgnoreCase));
            trafficHttpPort = new Uri(address).Port;
            DefaultHttpContext ListenerContext(string scheme, IPAddress localIp, int localPort) => new()
            {
                Request = { Scheme = scheme },
                Connection = { LocalIpAddress = localIp, LocalPort = localPort }
            };
            Check(AcmeHttp01Endpoint.IsPublicTrafficHttpListener(
                ListenerContext("http", IPAddress.Loopback, trafficHttpPort), IPAddress.Loopback, trafficHttpPort),
                "configured traffic HTTP socket is eligible for HTTP-01");
            Check(!AcmeHttp01Endpoint.IsPublicTrafficHttpListener(
                ListenerContext("https", IPAddress.Loopback, trafficHttpPort), IPAddress.Loopback, trafficHttpPort),
                "HTTPS traffic listener cannot serve HTTP-01 tokens");
            Check(!AcmeHttp01Endpoint.IsPublicTrafficHttpListener(
                ListenerContext("http", IPAddress.Loopback, trafficHttpPort + 1), IPAddress.Loopback, trafficHttpPort),
                "a separate management socket cannot serve HTTP-01 tokens");
            Check(!AcmeHttp01Endpoint.IsPublicTrafficHttpListener(
                ListenerContext("http", IPAddress.Parse("127.0.0.2"), trafficHttpPort), IPAddress.Loopback, trafficHttpPort),
                "a listener on another local address cannot serve HTTP-01 tokens");
            using var client = new HttpClient { BaseAddress = new Uri(address) };
            using var response = await client.GetAsync("/.well-known/acme-challenge/" + token);
            Check(response.StatusCode == HttpStatusCode.OK, "enabled exact HTTP challenge path responds");
            Check(response.Headers.CacheControl?.NoStore == true, "challenge response is not cached");
            Check(response.Headers.Contains("X-Content-Type-Options"), "challenge response disables MIME sniffing");
            Check(await response.Content.ReadAsStringAsync() == authorization, "response body is the published key authorization");
            using var unknown = await client.GetAsync("/.well-known/acme-challenge/0123456789abcdefunknown");
            Check(unknown.StatusCode == HttpStatusCode.NotFound, "unknown tokens are not disclosed");

            clock.AdjustUtc(TimeSpan.FromHours(12));
            Check(store.TryGet(token, out _), "forward wall-clock correction does not prematurely expire a challenge");
            clock.AdjustUtc(TimeSpan.FromHours(-24));
            clock.Advance(TimeSpan.FromMinutes(2) - TimeSpan.FromTicks(1));
            Check(store.TryGet(token, out _), "challenge is valid immediately before its monotonic deadline");
            clock.Advance(TimeSpan.FromTicks(1));
            Check(!store.TryGet(token, out _), "challenge expires at its monotonic deadline despite wall-clock rollback");
            clock.AdjustUtc(TimeSpan.FromHours(-12));
            Check(!store.TryGet(token, out _), "a further wall-clock rollback cannot resurrect an expired challenge");
            using var expired = await client.GetAsync("/.well-known/acme-challenge/" + token);
            Check(expired.StatusCode == HttpStatusCode.NotFound, "expired challenge no longer responds");
        }
        finally { await app.StopAsync(); }

        var disabledBuilder = WebApplication.CreateBuilder();
        disabledBuilder.WebHost.ConfigureKestrel(options => options.Listen(IPAddress.Loopback, 0,
            listen => listen.Protocols = HttpProtocols.Http1));
        disabledBuilder.Services.AddSingleton(store);
        await using var disabledApp = disabledBuilder.Build();
        disabledApp.MapHttp01Challenge(publicChallengeEntrypointEnabled: false,
            _ => throw new Exception("disabled challenge route must not inspect listener identity"));
        await disabledApp.StartAsync();
        try
        {
            var address = disabledApp.Services.GetRequiredService<Microsoft.AspNetCore.Hosting.Server.IServer>()
                .Features.Get<Microsoft.AspNetCore.Hosting.Server.Features.IServerAddressesFeature>()!
                .Addresses.Single(value => value.StartsWith("http://", StringComparison.OrdinalIgnoreCase));
            using var client = new HttpClient { BaseAddress = new Uri(address) };
            using var response = await client.GetAsync("/.well-known/acme-challenge/" + token);
            Check(response.StatusCode == HttpStatusCode.NotFound, "disabled public challenge entrypoint does not respond");
        }
        finally { await disabledApp.StopAsync(); }

        var bounded = new AcmeHttp01ChallengeStore(clock);
        for (var index = 0; index < AcmeHttp01ChallengeStore.MaximumEntries; index++)
        {
            var itemToken = "challenge-token-" + index.ToString("D4");
            Check(bounded.TryPublish(itemToken, itemToken + "." + new string('B', 43), TimeSpan.FromMinutes(1)),
                "challenge capacity accepts entries up to its bound");
        }
        Check(!bounded.TryPublish("challenge-token-overflow", "challenge-token-overflow." + new string('C', 43), TimeSpan.FromMinutes(1)),
            "challenge table fails closed at its fixed capacity");
        clock.AdjustUtc(TimeSpan.FromDays(-1));
        clock.Advance(TimeSpan.FromMinutes(2));
        Check(bounded.TryPublish("challenge-token-after-expiry", "challenge-token-after-expiry." + new string('D', 43), TimeSpan.FromMinutes(1)),
            "expired entries are reclaimed before enforcing capacity");

        Console.WriteLine("PASS: opt-in HTTP-01 response, token binding, expiry and bounded storage");
    }

    private sealed class ManualTimeProvider(DateTimeOffset now) : TimeProvider
    {
        private DateTimeOffset current = now;
        private long timestamp;
        public override DateTimeOffset GetUtcNow() => current;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => timestamp;
        public void AdjustUtc(TimeSpan duration) => current += duration;
        public void Advance(TimeSpan duration)
        {
            current += duration;
            timestamp += duration.Ticks;
        }
    }
}
