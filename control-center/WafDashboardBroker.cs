using System.Net.Sockets;
using System.Text;
using System.Text.Json;

// Fixed local transport. The independently administered Linux broker owns
// trust, signatures, credentials and authority; the gateway only requests
// an exact approved revision. Never accept a socket path from HTTP input.
internal sealed class WafDashboardBroker(string socketPath)
{
    internal static WafDashboardBroker? FromEnvironment()
    {
        var path = Environment.GetEnvironmentVariable("YARP_WAF_DASHBOARD_SOCKET");
        if (!OperatingSystem.IsLinux() || string.IsNullOrWhiteSpace(path)) return null;
        if (!Path.IsPathFullyQualified(path) || Encoding.UTF8.GetByteCount(path) > 100)
            throw new InvalidOperationException("WAF broker requires a fixed absolute Unix socket.");
        return new(path);
    }

    internal async Task<string> RequestAsync(WafDashboardRequest request, CancellationToken token)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
        timeout.CancelAfter(TimeSpan.FromMinutes(5));
        using var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        await socket.ConnectAsync(new UnixDomainSocketEndPoint(socketPath), timeout.Token);
        await using var stream = new NetworkStream(socket, ownsSocket: false);
        var payload = JsonSerializer.SerializeToUtf8Bytes(new { operation = request.Operation, revision = request.Revision, digest = request.Digest });
        await stream.WriteAsync(payload, timeout.Token);
        await stream.WriteAsync(new byte[] { 10 }, timeout.Token);
        var data = new byte[64];
        for (var offset = 0; offset < data.Length; offset++)
        {
            if (await stream.ReadAsync(data.AsMemory(offset, 1), timeout.Token) != 1)
                throw new IOException("WAF broker outcome missing.");
            if (data[offset] != 10) continue;
            var result = Encoding.ASCII.GetString(data, 0, offset);
            if (result == "refused-or-failed" ||
                (request.Operation == "preflight" && result == "preflight-only") ||
                (request.Operation == "execute" && result == "applied-uncommitted")) return result;
            throw new IOException("Invalid WAF broker outcome.");
        }
        throw new IOException("Oversized WAF broker outcome.");
    }
}
internal sealed record WafDashboardRequest(string? Operation, long Revision, string? Digest, string? Confirmation);
