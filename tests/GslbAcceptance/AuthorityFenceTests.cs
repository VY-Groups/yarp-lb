using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.AccessControl;
using System.Security.Principal;
using GatewayCore.Gslb.Contracts;

internal static class AuthorityFenceTests
{
    public static void Run()
    {
        var root = Path.Combine(Path.GetTempPath(), "gslb-authority-fence-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(root, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        else
        {
            using var identity = WindowsIdentity.GetCurrent();
            var user = identity.User ?? throw new InvalidOperationException("Test identity has no SID");
            var security = new DirectoryInfo(root).GetAccessControl();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            security.AddAccessRule(new FileSystemAccessRule(user, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None, AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None, AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None, AccessControlType.Allow));
            new DirectoryInfo(root).SetAccessControl(security);
        }
        try
        {
            using var tlsAKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var tlsBKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var tlsA = CreateCertificate("authority-a", tlsAKey);
            using var tlsB = CreateCertificate("authority-b", tlsBKey);
            using var signerA = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var signerB = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var files = new Dictionary<string, string>(StringComparer.Ordinal);
            string Write(string name, string text)
            {
                var path = Path.Combine(root, name);
                File.WriteAllText(path, text);
                if (!OperatingSystem.IsWindows())
                    File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                files[name] = path;
                return path;
            }
            var certA = Write("a-cert.pem", tlsA.ExportCertificatePem());
            var keyA = Write("a-tls.key", tlsAKey.ExportPkcs8PrivateKeyPem());
            var certB = Write("b-cert.pem", tlsB.ExportCertificatePem());
            var keyB = Write("b-tls.key", tlsBKey.ExportPkcs8PrivateKeyPem());
            var signerAPath = Write("a-signing.key", signerA.ExportPkcs8PrivateKeyPem());
            var signerBPath = Write("b-signing.key", signerB.ExportPkcs8PrivateKeyPem());
            var publicAPath = Write("a-signing.pub", signerA.ExportSubjectPublicKeyInfoPem());
            var publicBPath = Write("b-signing.pub", signerB.ExportSubjectPublicKeyInfoPem());
            var pinA = Convert.ToHexString(tlsA.GetCertHash(HashAlgorithmName.SHA256));
            var pinB = Convert.ToHexString(tlsB.GetCertHash(HashAlgorithmName.SHA256));
            var fingerprint = new string('A', 64);
            var localHealthy = true;
            var target = new AuthorityFenceTarget("fence.example.test", "primary", _ => localHealthy);
            AuthorityFenceConfig Config(string node, string peer, string serverCert, string serverKey,
                string clientCert, string clientKey, string signerPath, string peerSigner,
                string localPin, string peerPin, string prefix, int port, int peerPort) => new(node,
                    "127.0.0.1", port, false, serverCert, serverKey, clientCert, clientKey,
                    signerPath, Path.Combine(root, prefix + "-epoch.json"),
                    Path.Combine(root, prefix + "-replay.json"), 5, 1,
                    new AuthorityFencePeerConfig(peer,
                        $"https://127.0.0.1:{peerPort}/authority-fence/v1/snapshot",
                        [peerPin], [peerPin], peerSigner, "127.0.0.1", peerPort));
            var configA = Config("authority-a", "authority-b", certA, keyA, certA, keyA,
                signerAPath, publicBPath, pinA, pinB, "a", 16651, 16652);
            var configB = Config("authority-b", "authority-a", certB, keyB, certB, keyB,
                signerBPath, publicAPath, pinB, pinA, "b", 16652, 16651);
            Check(ThrowsInvalid(() => new AuthorityFenceStore(configA with
                    { Peer = configA.Peer with { AllowedAddress = "127.0.0.2" } }, fingerprint, [target])),
                "peer HTTPS destination must match an explicitly allowlisted IP");
            Check(ThrowsInvalid(() => new AuthorityFenceStore(configA with
                    { Peer = configA.Peer with { AllowedPort = 16653 } }, fingerprint, [target])),
                "peer HTTPS destination port must match the explicitly allowlisted port");
            Check(ThrowsInvalid(() => new AuthorityFenceStore(configA with { ListenAddress = "0.0.0.0" },
                    fingerprint, [target])),
                "wildcard fence listener requires explicit non-loopback binding opt-in");
            Check(ThrowsInvalid(() => new AuthorityFenceStore(configA with { ListenAddress = "192.0.2.44" },
                    fingerprint, [target])),
                "specific non-loopback fence listener requires explicit opt-in");
            var fingerprintZone = new DnsZone("fence.example.test", 5,
                [new DnsSite("192.0.2.1", "https://app.example.test/ready", 1)
                    { AuthorityFenceSiteId = "primary", AgentSiteId = "service",
                      RequiredAgentIds = ["observer-a", "observer-b"], MinimumHealthyAgentReports = 2 }], true);
            var baselineDigest = AuthorityFenceFingerprint.Compute([fingerprintZone], null);
            Check(baselineDigest != AuthorityFenceFingerprint.Compute(
                    [fingerprintZone with { FailureThreshold = 2 }], null) &&
                  baselineDigest != AuthorityFenceFingerprint.Compute(
                    [fingerprintZone with { SuccessThreshold = 2 }], null),
                "authority fingerprint binds local health failure and recovery thresholds");
            Check(baselineDigest != AuthorityFenceFingerprint.Compute([fingerprintZone], null, 2, 1) &&
                  baselineDigest != AuthorityFenceFingerprint.Compute([fingerprintZone], null, 1, 2),
                "authority fingerprint binds probe interval and concurrency policy");
            Check(baselineDigest != AuthorityFenceFingerprint.Compute(
                    [fingerprintZone with { SoaContact = "ops.fence.example.test" }], null),
                "authority fingerprint binds SOA contact");
            Check(baselineDigest == AuthorityFenceFingerprint.Compute(
                    [fingerprintZone with { SoaContact = "HOSTMASTER.FENCE.EXAMPLE.TEST." }], null),
                "explicit and implicit canonical SOA contact have equal fingerprints");
            var delegation = new DnsDelegationConfig("child.fence.example.test",
                [new DnsNameServerConfig("ns.child.fence.example.test", "192.0.2.53"),
                 new DnsNameServerConfig("ns2.child.fence.example.test", "192.0.2.54")]);
            var delegatedZone = fingerprintZone with { Delegations = [delegation] };
            var delegatedDigest = AuthorityFenceFingerprint.Compute([delegatedZone], null);
            Check(delegatedDigest != baselineDigest &&
                  delegatedDigest != AuthorityFenceFingerprint.Compute(
                    [delegatedZone with { Delegations = [delegation with {
                        NameServers = [new DnsNameServerConfig("ns.child.fence.example.test", "192.0.2.55"),
                                       delegation.NameServers[1]] }] }], null),
                "authority fingerprint binds delegation membership and glue");
            Check(delegatedDigest == AuthorityFenceFingerprint.Compute(
                    [delegatedZone with { Delegations = [delegation with {
                        NameServers = delegation.NameServers.Reverse().ToArray() }] }], null),
                "equivalent delegation ordering has equal fingerprints");
            AgentReportServerConfig TrustPolicy(string vantage) => new("127.0.0.1", 16660, false,
                certA, keyA, Path.Combine(root, "trust-replay.json"), 10, 10, 2, 100, [],
                [new AgentTrust("observer-a", vantage, [pinA], [publicAPath]),
                 new AgentTrust("observer-b", "zone-b", [pinB], [publicBPath])]);
            var trustedDigest = AuthorityFenceFingerprint.Compute([fingerprintZone], TrustPolicy("zone-a"));
            Check(trustedDigest != AuthorityFenceFingerprint.Compute([fingerprintZone], TrustPolicy("zone-changed")),
                "authority fingerprint binds global observer identity and vantage trust policy");
            var now = DateTimeOffset.UtcNow;
            AuthorityFenceSnapshot initial;
            using (var source = new AuthorityFenceStore(configA, fingerprint, [target]))
            using (var receiver = new AuthorityFenceStore(configB, fingerprint, [target]))
            {
                initial = source.CreateSnapshot(100);
                Check(receiver.TryAccept(initial, tlsA, now, 100), "peer accepts authenticated signed decision snapshot");
                Check(receiver.IsAllowedPeerAddress(IPAddress.Loopback) &&
                      receiver.IsAllowedPeerAddress(IPAddress.Parse("::ffff:127.0.0.1")),
                    "inbound peer IP allowlist accepts the configured address and mapped IPv4 form");
                Check(!receiver.IsAllowedPeerAddress(IPAddress.Parse("127.0.0.2")) &&
                      !receiver.IsAllowedPeerAddress(null),
                    "inbound peer IP allowlist rejects wrong or missing source addresses");
                Check(receiver.IsPeerEligible("fence.example.test.", "primary", 101),
                    "fresh matching eligible peer lease opens the fence");
                Check(!receiver.TryAccept(initial, tlsA, now, 102), "duplicate authority snapshot is replay rejected");
                Check(receiver.IsPeerEligible("fence.example.test", "primary", 102),
                    "rejected replay does not clear current lease");
                Check(!receiver.TryAccept(source.CreateSnapshot(103), tlsB, now, 103),
                    "mTLS certificate identity must match configured authority peer");
                localHealthy = false;
                var negative = source.CreateSnapshot(104);
                Check(receiver.TryAccept(negative, tlsA, now, 104) &&
                      !receiver.IsPeerEligible("fence.example.test", "primary", 105),
                    "authenticated negative peer decision keeps DNS fence closed");
                localHealthy = true;
            }
            using (var restartedReceiver = new AuthorityFenceStore(configB, fingerprint, [target]))
            using (var restartedSource = new AuthorityFenceStore(configA, fingerprint, [target]))
            {
                Check(!restartedReceiver.TryAccept(initial, tlsA, now, 200),
                    "durable receiver high-water rejects a pre-restart snapshot replay");
                var recovered = restartedSource.CreateSnapshot(201);
                Check(recovered.Epoch > initial.Epoch &&
                      restartedReceiver.TryAccept(recovered, tlsA, now, 201) &&
                      restartedReceiver.IsPeerEligible("fence.example.test", "primary", 202),
                    "new sender epoch provides fresh recovery after authority restart");
                Check(!restartedReceiver.IsPeerEligible("fence.example.test", "primary", 5202),
                    "peer eligibility expires at the bounded monotonic lease");
                Check(!restartedReceiver.TryAccept(recovered with { Signature = "A" }, tlsA, now, 5203),
                    "tampered authority signature is rejected");
            }
            using (var mismatched = new AuthorityFenceStore(configB, new string('B', 64), [target]))
            using (var source = new AuthorityFenceStore(configA, fingerprint, [target]))
                Check(!mismatched.TryAccept(source.CreateSnapshot(300), tlsA, now, 300),
                    "different routing configuration fingerprint cannot form agreement");
            var deletionConfig = configB with
            {
                EpochStatePath = Path.Combine(root, "deletion-epoch.json"),
                ReplayStatePath = Path.Combine(root, "deletion-replay.json")
            };
            using (var deletionReceiver = new AuthorityFenceStore(deletionConfig, fingerprint, [target]))
            using (var deletionSource = new AuthorityFenceStore(configA, fingerprint, [target]))
            {
                Check(deletionReceiver.TryAccept(deletionSource.CreateSnapshot(400), tlsA, now, 400),
                    "replay state initializes once for a new authority pair");
                Check(deletionReceiver.IsPeerEligible("fence.example.test", "primary", 400),
                    "valid lease initially authorizes a target before durable state loss");
                File.Delete(deletionConfig.ReplayStatePath);
                Check(!deletionReceiver.TryAccept(deletionSource.CreateSnapshot(401), tlsA, now, 401),
                    "missing replay high-water state fails closed while authority is running");
                Check(!deletionReceiver.IsPeerEligible("fence.example.test", "primary", 402),
                    "detected durable state loss withdraws an existing positive lease immediately");
            }
            File.Delete(deletionConfig.ReplayStatePath + ".lock");
            Check(ThrowsInvalid(() => new AuthorityFenceStore(deletionConfig, fingerprint, [target])),
                "deleting replay file and lock marker still fails closed after restart");
            Console.WriteLine("PASS: authority 2-of-2 fence signature, membership, config, lease, replay and restart contracts");
        }
        finally { Directory.Delete(root, recursive: true); }

        static X509Certificate2 CreateCertificate(string commonName, ECDsa key)
        {
            var request = new CertificateRequest("CN=" + commonName, key, HashAlgorithmName.SHA256);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection
            {
                new("1.3.6.1.5.5.7.3.1"), new("1.3.6.1.5.5.7.3.2")
            }, true));
            var san = new SubjectAlternativeNameBuilder();
            san.AddIpAddress(IPAddress.Loopback);
            request.CertificateExtensions.Add(san.Build());
            return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
        }

        static void Check(bool condition, string name)
        {
            if (!condition) throw new Exception("FAIL: " + name);
            Console.WriteLine("PASS: " + name);
        }

        static bool ThrowsInvalid(Action action)
        {
            try { action(); return false; }
            catch (InvalidDataException) { return true; }
        }
    }
}
