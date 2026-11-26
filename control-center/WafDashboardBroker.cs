using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

// Only host-configured endpoints and credentials. Browser inputs never choose
// the transport, address, certificate, policy file, command or quorum authority.
internal sealed class WafDashboardBroker(string? socketPath, Uri? remote, string? serverPin, string? clientThumbprint)
{
    internal static WafDashboardBroker? FromEnvironment(string prefix = "YARP_WAF_DASHBOARD")
    {
        if (prefix is not ("YARP_WAF_DASHBOARD" or "YARP_GSLB_DASHBOARD"))
            throw new ArgumentException("Unknown specialist broker.");
        var path = Environment.GetEnvironmentVariable(prefix + "_SOCKET");
        var address = Environment.GetEnvironmentVariable(prefix + "_TLS");
        var pin = Environment.GetEnvironmentVariable(prefix + "_SERVER_SHA256");
        var client = Environment.GetEnvironmentVariable(prefix + "_CLIENT_THUMBPRINT");
        if (string.IsNullOrWhiteSpace(path) && string.IsNullOrWhiteSpace(address))
        {
            if (!string.IsNullOrWhiteSpace(pin) || !string.IsNullOrWhiteSpace(client))
                throw new InvalidOperationException("Incomplete specialist broker configuration.");
            return null;
        }
        if (!string.IsNullOrWhiteSpace(path))
        {
            if (!OperatingSystem.IsLinux() || prefix != "YARP_WAF_DASHBOARD" ||
                !string.IsNullOrWhiteSpace(address) || !string.IsNullOrWhiteSpace(pin) ||
                !string.IsNullOrWhiteSpace(client) || !Path.IsPathFullyQualified(path) ||
                Encoding.UTF8.GetByteCount(path) > 100)
                throw new InvalidOperationException("Invalid fixed local WAF socket configuration.");
            return new(path, null, null, null);
        }
        if (!Uri.TryCreate(address, UriKind.Absolute, out var target) ||
            target.Scheme != "tls" || target.Port is < 1 or > 65535 ||
            target.Host.Length == 0 || target.UserInfo.Length != 0 ||
            target.AbsolutePath is not ("" or "/") || target.Query.Length != 0 ||
            target.Fragment.Length != 0 || pin is null || client is null ||
            !Regex.IsMatch(pin, "^[A-F0-9]{64}$") ||
            !Regex.IsMatch(client, "^[A-F0-9]{40}$"))
            throw new InvalidOperationException("Specialist broker requires fixed TLS origin, server SHA-256 and installed client thumbprint.");
        return new(null, target, pin, client);
    }

    internal async Task<string> RequestAsync(WafDashboardRequest request, CancellationToken token)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
        timeout.CancelAfter(TimeSpan.FromMinutes(5));
        if (socketPath is not null)
        {
            using var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            await socket.ConnectAsync(new UnixDomainSocketEndPoint(socketPath), timeout.Token);
            await using var local = new NetworkStream(socket, ownsSocket: false);
            return await ExchangeAsync(local, request, timeout.Token);
        }
        using var store = new X509Store(StoreName.My, OperatingSystem.IsWindows() ? StoreLocation.LocalMachine : StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly);
        var matches = store.Certificates.Find(X509FindType.FindByThumbprint, clientThumbprint!, validOnly: true);
        try
        {
            if (matches.Count != 1 || !matches[0].HasPrivateKey)
                throw new InvalidOperationException("Missing or ambiguous specialist broker client identity.");
            using var tcp = new TcpClient();
            await tcp.ConnectAsync(remote!.DnsSafeHost, remote.Port, timeout.Token);
            await using var tls = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false);
            await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = remote.DnsSafeHost,
                ClientCertificates = new X509CertificateCollection { matches[0] },
                CertificateRevocationCheckMode = X509RevocationMode.Online,
                RemoteCertificateValidationCallback = (_, certificate, _, errors) =>
                    errors == SslPolicyErrors.None && certificate is not null &&
                    Convert.ToHexString(SHA256.HashData(certificate.GetRawCertData())) == serverPin
            }, timeout.Token);
            if (!tls.IsMutuallyAuthenticated)
                throw new IOException("Specialist broker mutual TLS was not established.");
            return await ExchangeAsync(tls, request, timeout.Token);
        }
        finally { foreach (var certificate in matches) certificate.Dispose(); }
    }

    private static async Task<string> ExchangeAsync(Stream stream, WafDashboardRequest request, CancellationToken token)
    {
        var payload = JsonSerializer.SerializeToUtf8Bytes(new { operation = request.Operation, revision = request.Revision, digest = request.Digest });
        await stream.WriteAsync(payload, token);
        await stream.WriteAsync(new byte[] { 10 }, token);
        await stream.FlushAsync(token);
        var data = new byte[64];
        for (var offset = 0; offset < data.Length; offset++)
        {
            if (await stream.ReadAsync(data.AsMemory(offset, 1), token) != 1)
                throw new IOException("Specialist broker outcome missing.");
            if (data[offset] != 10) continue;
            var result = Encoding.ASCII.GetString(data, 0, offset);
            if (result == "refused-or-failed" ||
                (request.Operation == "preflight" && result == "preflight-only") ||
                (request.Operation == "execute" && result == "applied-uncommitted")) return result;
            throw new IOException("Invalid specialist broker outcome.");
        }
        throw new IOException("Oversized specialist broker outcome.");
    }
}
internal sealed record WafDashboardRequest(string? Operation, long Revision, string? Digest, string? Confirmation);
