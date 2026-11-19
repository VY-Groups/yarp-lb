using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

internal static class ExternalAuditIntentTests
{
    public static async Task RunAsync()
    {
        static void Check(bool ok, string message)
        {
            if (!ok) throw new Exception("FAIL: " + message);
            Console.WriteLine("PASS: " + message);
        }
        using var signer = RSA.Create(2048);
        var key = RandomNumberGenerator.GetBytes(32);
        var endpoint = new Uri("https://audit.example.invalid/audit/v1/intents");
        var digest = new string('A', 64);
        var target = new string('B', 64);
        using var handler = new Collector(signer, key);
        using var gate = new ExternalAuditIntent(endpoint, "node-a", key, signer.ExportSubjectPublicKeyInfoPem(),
            new HttpClient(handler, disposeHandler: false));
        Check(ExternalAuditIntent.FromEnvironment(null, null, null, null) is null,
            "external intent gate disabled when unconfigured");
        Check(await gate.ConfirmAsync("reviewer", "CONFIG_APPLY_INTENT", digest, target, CancellationToken.None) &&
              handler.Calls == 1 && handler.Authenticated && handler.BoundIntent,
            "collector receipt bound to authenticated actor, operation, revision and exact target digest");
        handler.Mode = "replay";
        Check(!await gate.ConfirmAsync("reviewer", "CONFIG_APPLY_INTENT", digest, target, CancellationToken.None),
            "previous valid receipt cannot authorize a new intent");
        handler.Mode = "forged";
        Check(!await gate.ConfirmAsync("reviewer", "CONFIG_RESTORE_INTENT", digest, target, CancellationToken.None),
            "forged collector signature fails closed");
        handler.Mode = "duplicate";
        Check(!await gate.ConfirmAsync("reviewer", "CONFIG_APPLY_INTENT", digest, target, CancellationToken.None),
            "ambiguous receipt headers fail closed");
        handler.Mode = "missing";
        Check(!await gate.ConfirmAsync("reviewer", "CONFIG_APPLY_INTENT", digest, target, CancellationToken.None),
            "HTTP success without signed receipt fails closed");
        handler.Mode = "redirect";
        Check(!await gate.ConfirmAsync("reviewer", "CONFIG_APPLY_INTENT", digest, target, CancellationToken.None),
            "redirect is not a persistence receipt");
        handler.Mode = "unavailable";
        Check(!await gate.ConfirmAsync("reviewer", "CONFIG_APPLY_INTENT", digest, target, CancellationToken.None),
            "collector unavailable fails closed");
        handler.Mode = "throw";
        Check(!await gate.ConfirmAsync("reviewer", "CONFIG_APPLY_INTENT", digest, target, CancellationToken.None),
            "collector network failure fails closed");
        handler.Mode = "cancel";
        using var cancel = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
        Check(!await gate.ConfirmAsync("reviewer", "CONFIG_APPLY_INTENT", digest, target, cancel.Token),
            "canceled external request fails closed");
        var count = handler.Calls;
        Check(!await gate.ConfirmAsync("reviewer", "UNSUPPORTED", digest, target, CancellationToken.None) &&
              handler.Calls == count, "invalid operation not submitted");
        handler.Mode = "valid";
        Check(await gate.ConfirmAsync("reviewer", "CONFIG_RESTORE_INTENT", digest, target, CancellationToken.None),
            "fresh verified receipt restores administrative availability");
        try
        {
            using var invalid = new ExternalAuditIntent(new Uri("http://audit.example.invalid/audit/v1/intents"),
                "node-a", key, signer.ExportSubjectPublicKeyInfoPem(), new HttpClient());
            throw new Exception("HTTP endpoint unexpectedly accepted");
        }
        catch (InvalidOperationException) { Console.WriteLine("PASS: plaintext audit endpoint rejected"); }
        CryptographicOperations.ZeroMemory(key);
    }

    private sealed class Collector(RSA signer, byte[] key) : HttpMessageHandler
    {
        public int Calls;
        public bool Authenticated, BoundIntent;
        public string Mode = "valid";
        private string? previousReceipt;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage req, CancellationToken ct)
        {
            Calls++;
            var body = await req.Content!.ReadAsByteArrayAsync(ct);
            var id = req.Headers.GetValues(ExternalAuditIntent.EventIdHeader).Single();
            var prefix = Encoding.ASCII.GetBytes("GatewayCore-Audit-Intent-v1\n" + id + "\n" +
                Convert.ToHexString(SHA256.HashData(body)));
            Authenticated = CryptographicOperations.FixedTimeEquals(
                HMACSHA256.HashData(key, prefix), Convert.FromBase64String(
                    req.Headers.GetValues(ExternalAuditIntent.RequestSignature).Single()));
            using var doc = JsonDocument.Parse(body);
            var e = doc.RootElement;
            BoundIntent = req.Method == HttpMethod.Post && req.RequestUri?.AbsolutePath == "/audit/v1/intents" &&
                e.GetProperty("eventId").GetString() == id && e.GetProperty("actor").GetString() == "reviewer" &&
                e.GetProperty("operation").GetString() == "CONFIG_APPLY_INTENT" &&
                e.GetProperty("revision").GetString() == new string('A', 64) &&
                e.GetProperty("targetDigest").GetString() == new string('B', 64);
            if (Mode == "throw") throw new HttpRequestException("disposable network failure");
            if (Mode == "cancel") await Task.Delay(Timeout.InfiniteTimeSpan, ct);
            var status = Mode switch {
                "redirect" => HttpStatusCode.Redirect,
                "unavailable" => HttpStatusCode.ServiceUnavailable,
                _ => HttpStatusCode.Created
            };
            var result = new HttpResponseMessage(status);
            if (Mode is "missing" or "redirect" or "unavailable") return result;
            var receipt = Convert.ToBase64String(signer.SignData(
                ExternalAuditIntent.ReceiptInput(id, body), HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
            if (Mode == "replay") receipt = previousReceipt!;
            if (Mode == "forged") receipt = Convert.ToBase64String(new byte[256]);
            result.Headers.TryAddWithoutValidation(ExternalAuditIntent.ReceiptSignature,
                Mode == "duplicate" ? new[] { receipt, receipt } : new[] { receipt });
            if (Mode == "valid") previousReceipt = receipt;
            return result;
        }
    }
}
