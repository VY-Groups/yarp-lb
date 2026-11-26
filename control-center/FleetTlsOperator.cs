#if GATEWAYCORE_COMMERCIAL
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;
using GatewayCore.Gslb.Contracts;

// The local operator and authenticated dashboard share an exclusive host
// lock. Global ownership remains in authenticated persistent quorum;
// there is no auto-release, replay, or HTTP endpoint for acquiring it.
internal static class FleetTlsOperator
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        UnmappedMemberHandling = System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow
    };
    private static string PlanPath(string dir) => Path.Combine(dir, "fleet-tls-plan.json");
    private static string EpochPath(string dir) => Path.Combine(dir, "fleet-tls-epoch.txt");
    private static FileStreamOptions PrivateOptions(FileMode mode)
    {
        var options = new FileStreamOptions { Mode = mode, Access = FileAccess.ReadWrite, Share = FileShare.None };
        if (OperatingSystem.IsLinux()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        return options;
    }
    internal static FileStream OpenExclusive(string dir) =>
        new(Path.Combine(dir, "fleet-tls-operation.lock"), PrivateOptions(FileMode.OpenOrCreate));

    private static T Read<T>(string path) where T : class
    {
        var raw = PrivateKeyFileSecurity.ReadPrivateFileBytes(path, "Fleet TLS authority", 16384,
            requireSingleLink: true);
        if (!StrictJsonPropertyNames.HasNoDuplicates(raw)) throw new InvalidDataException("Duplicate fleet TLS properties.");
        return JsonSerializer.Deserialize<T>(raw, Json) ?? throw new InvalidDataException("Missing fleet TLS record.");
    }

    private static FleetTlsPlan ReadPlan(string dir, CommercialLicenseRuntime license)
    {
        var plan = Read<FleetTlsPlan>(PlanPath(dir));
        var identity = license.CertificateFleetIdentity();
        if (!plan.Valid() || identity.Scope != plan.Scope || identity.Installation != plan.Installation)
            throw new InvalidOperationException("Fleet TLS plan differs from licensed installation.");
        return plan;
    }
    private static FleetTlsGrant Grant(string dir, FleetTlsPlan plan, bool completion)
    {
        var grant = Read<FleetTlsGrant>(Path.Combine(dir, completion ? "fleet-tls-completion.json" : "fleet-tls-approval.json"));
        var pem = PrivateKeyFileSecurity.ReadTrustedPublicKeyPem(
            Environment.GetEnvironmentVariable("YARP_FLEET_TLS_SIGNER_PUBLIC_KEY"), "Fleet TLS reviewer");
        if ((completion ? grant.Purpose is not ("activated" or "rolled-back") : grant.Purpose != "activate") ||
            !plan.Verify(grant, pem, DateTimeOffset.UtcNow.ToUnixTimeSeconds()))
            throw new CryptographicException("Independent certificate approval invalid or expired.");
        return grant;
    }

    internal static FleetTlsPlan ReadActivation(string dir, CommercialLicenseRuntime license, string active, string candidate)
    {
        var plan = ReadPlan(dir, license);
        if (plan.Epoch < 1 || plan.ActiveDigest != active || plan.CandidateDigest != candidate ||
            plan.Epoch <= FleetSequenceState.Read(EpochPath(dir)))
            throw new InvalidOperationException("Fleet TLS plan mismatched, stale or consumed.");
        _ = Grant(dir, plan, false);
        return plan;
    }

    internal static async Task ConsumeAsync(string dir, CommercialLicenseRuntime license, FleetQuorum quorum,
        FleetTlsPlan expected, CancellationToken token)
    {
        var plan = ReadActivation(dir, license, expected.ActiveDigest, expected.CandidateDigest);
        if (plan != expected || quorum.Scope != plan.Scope)
            throw new InvalidOperationException("Fleet TLS authority changed.");
        await quorum.Assert(plan.TransactionId, plan.Epoch, token);
        if (ReadActivation(dir, license, plan.ActiveDigest, plan.CandidateDigest) != plan)
            throw new InvalidOperationException("Fleet TLS approval changed after quorum.");
        token.ThrowIfCancellationRequested();
        FleetSequenceState.Accept(EpochPath(dir), plan.Epoch);
    }

    private static void Persist(string dir, FleetTlsPlan plan)
    {
        FleetRolloutJournal.Write(PlanPath(dir), JsonSerializer.SerializeToNode(plan, Json)!.AsObject());
    }

    internal static async Task<int> RunAsync(string[] args, string dir, CommercialLicenseRuntime license, FleetQuorum? quorum)
    {
        try
        {
            if (quorum is null) throw new InvalidOperationException("Authenticated quorum required.");
            using var hostLock = OpenExclusive(dir);
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(40));
            var token = deadline.Token;
            var identity = license.CertificateFleetIdentity();
            if (quorum.Scope != identity.Scope) throw new InvalidOperationException("Wrong fleet quorum scope.");
            if (args.Length == 5 && args[1] == "acquire")
            {
                var plan = FleetTlsPlan.Create(identity.Scope, identity.Installation, args[2], args[3], args[4],
                    Convert.ToHexString(RandomNumberGenerator.GetBytes(16)));
                // Durable intent before the compare-and-swap; no overwrite.
                using (var intent = new FileStream(PlanPath(dir), PrivateOptions(FileMode.CreateNew)))
                {
                    JsonSerializer.Serialize(intent, plan, Json);
                    intent.Flush(flushToDisk: true);
                }
                var owned = await quorum.Acquire(plan.TransactionId, FleetSequenceState.Read(EpochPath(dir)), token);
                plan = plan with { Epoch = owned.Epoch };
                Persist(dir, plan);
                Console.WriteLine(JsonSerializer.Serialize(plan, Json));
                return 0;
            }
            if (args.Length == 2 && args[1] == "recover")
            {
                var plan = ReadPlan(dir, license);
                var epoch = await quorum.RecoverOwnEpoch(plan.TransactionId, token);
                if (plan.Epoch != 0 && plan.Epoch != epoch)
                    throw new InvalidOperationException("Recovered quorum epoch differs from intent.");
                plan = plan with { Epoch = epoch };
                Persist(dir, plan);
                Console.WriteLine(JsonSerializer.Serialize(plan, Json));
                return 0;
            }
            if (args.Length == 2 && args[1] == "release")
            {
                var plan = ReadPlan(dir, license);
                var grant = Grant(dir, plan, true);
                var expected = grant.Purpose == "activated" ? plan.CandidateDigest : plan.ActiveDigest;
                if (grant.Purpose == "activated" && FleetSequenceState.Read(EpochPath(dir)) != plan.Epoch)
                    throw new InvalidOperationException("No consumed activation epoch.");
                await VerifyLiveAsync(expected, token);
                // Receipt is independently signed, and the local file and
                // actual TLS peer were verified. Release is idempotent only
                // for the original exact transaction/outcome.
                if (Grant(dir, plan, true) != grant || ReadPlan(dir, license) != plan)
                    throw new InvalidOperationException("Completion authority changed.");
                await quorum.Release(plan.TransactionId, plan.Epoch, grant.Purpose, token);
                var archive = Path.Combine(dir, "fleet-tls-" + plan.TransactionId + ".json");
                File.Move(PlanPath(dir), archive);
                Console.WriteLine("FLEET_TLS_COMPLETION_CONFIRMED");
                return 0;
            }
            Console.Error.WriteLine("Usage: --fleet-tls-lock acquire <activeSHA256> <candidateSHA256> <peerEvidenceSHA256> | recover | release");
            return 64;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("Fleet TLS operation refused or unconfirmed: " + ex.GetType().Name + ". Preserve the plan; reconcile the original fence.");
            return 78;
        }
    }

    private static async Task VerifyLiveAsync(string expected, CancellationToken token)
    {
        var cfg = GatewayListenerIsolation.ReadSettingsFromEnvironment()
            ?? throw new InvalidOperationException("Isolated TLS listener configuration required.");
        if (cfg.TrafficCertificateDnsNames is not { Length: > 0 } ||
            !IPAddress.TryParse(cfg.TrafficIp, out var address) || IPAddress.Any.Equals(address) ||
            IPAddress.IPv6Any.Equals(address) || cfg.TrafficHttpsPort is < 1 or > 65535)
            throw new InvalidOperationException("Explicit TLS listener address/name required.");
        var bytes = await AcmeRenewalCoordinator.ReadBoundedPfxAsync(cfg.TrafficPfxPath, token);
        try
        {
            if (Convert.ToHexString(SHA256.HashData(bytes)) != expected)
                throw new CryptographicException("Active PFX digest does not match plan outcome.");
            var password = await AcmeRenewalCoordinator.ReadBoundedPasswordAsync(cfg.TrafficPfxPasswordFile, token);
            using var certificate = X509CertificateLoader.LoadPkcs12(bytes, password, X509KeyStorageFlags.EphemeralKeySet);
            foreach (var dnsName in cfg.TrafficCertificateDnsNames)
            {
                using var client = new TcpClient(address.AddressFamily);
                await client.ConnectAsync(address, cfg.TrafficHttpsPort, token);
                await using var stream = new SslStream(client.GetStream());
                await stream.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    TargetHost = dnsName, CertificateRevocationCheckMode = X509RevocationMode.Online
                }, token);
                if (stream.RemoteCertificate is not { } peer ||
                    !CryptographicOperations.FixedTimeEquals(SHA256.HashData(peer.GetRawCertData()), SHA256.HashData(certificate.RawData)))
                    throw new CryptographicException("Actual traffic leaf differs from planned active certificate.");
            }
            if (!await AcmeRenewalCoordinator.MatchesActiveAsync(cfg.TrafficPfxPath, cfg.TrafficPfxPasswordFile, bytes, password, token))
                throw new CryptographicException("Active file changed during TLS verification.");
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
}
#endif
