using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using GatewayCore.Gslb.Contracts;

internal static class AuthorityFenceTests
{
    public static void Run()
    {
        ProtocolMutationTests.Run();
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
            using var tlsAKey = RSA.Create(2048);
            using var tlsBKey = RSA.Create(2048);
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
            var nsConfig = new[] {
                new DnsNameServerConfig("ns1.fence.example.test", "192.0.2.53"),
                new DnsNameServerConfig("ns2.fence.example.test", "192.0.2.54") };
            var nsZone = fingerprintZone with { NameServers = nsConfig };
            Check(AuthorityFenceFingerprint.Compute([nsZone], null) !=
                  AuthorityFenceFingerprint.Compute([nsZone with { NameServers = nsConfig.Reverse().ToArray() }], null),
                "SOA primary name server order is bound to authority fingerprint");
            var loadedNs = nsConfig.Select(ns => new DnsNameServer(ns.Host, IPAddress.Parse(ns.Address))).ToArray();
            var secureZone = nsZone with { DnssecPrivateKeyPath = signerAPath };
            using var dnssecA = new DnssecZoneSigner(secureZone.Name, 5, signerAPath,
                "hostmaster.fence.example.test", 1, loadedNs, [], true, false);
            using var dnssecB = new DnssecZoneSigner(secureZone.Name, 5, signerBPath,
                "hostmaster.fence.example.test", 1, loadedNs, [], true, false);
            using var dnssecOverlap = new DnssecZoneSigner(secureZone.Name, 5, signerAPath,
                "hostmaster.fence.example.test", 1, loadedNs, [], true, false,
                prepublishPublicKeyPaths: [publicBPath]);
            using var dnssecDual = new DnssecZoneSigner(secureZone.Name, 5, signerAPath,
                "hostmaster.fence.example.test", 1, loadedNs, [], true, false,
                additionalSigningKeyPaths: [signerBPath]);
            string SignedDigest(DnsZone zone, DnssecZoneSigner signer) =>
                AuthorityFenceFingerprint.Compute([zone], null, loadedSigners:
                    new Dictionary<string, DnssecZoneSigner> { [zone.Name] = signer });
            var secureDigest = SignedDigest(secureZone, dnssecA);
            Check(secureDigest != SignedDigest(secureZone, dnssecB) &&
                  secureDigest != AuthorityFenceFingerprint.Compute([nsZone], null),
                "authority fingerprint distinguishes loaded DNSSEC key and unsigned zone");
            Check(secureDigest == SignedDigest(secureZone with { DnssecPrivateKeyPath = "other-local-path.pem" }, dnssecA),
                "authority fingerprint uses loaded public material rather than local key paths");
            Check(SignedDigest(secureZone, dnssecOverlap) != SignedDigest(secureZone, dnssecDual),
                "authority fingerprint distinguishes prepublication from dual signing");
            using var dnssecNsec3 = new DnssecZoneSigner(secureZone.Name, 5, signerAPath,
                "hostmaster.fence.example.test", 1, loadedNs, [], true, false,
                denialMode: "Nsec3", nsec3SaltHex: "0011223344556677", nsec3Iterations: 1);
            Check(secureDigest != SignedDigest(secureZone with { DnssecDenialMode = "Nsec3",
                    DnssecNsec3SaltHex = "0011223344556677", DnssecNsec3Iterations = 1 }, dnssecNsec3),
                "authority fingerprint binds DNSSEC denial policy");
            Check(ThrowsInvalid(() => AuthorityFenceFingerprint.Compute([secureZone], null)),
                "signed zone fingerprint cannot omit its loaded signer");
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
            var ds = new DnsDsRecordConfig(12345, 13, 2, new string('a', 64));
            var signedDelegation = delegation with { DsRecords = [ds] };
            var signedDelegatedZone = delegatedZone with { Delegations = [signedDelegation] };
            var signedDigest = AuthorityFenceFingerprint.Compute([signedDelegatedZone], null);
            Check(signedDigest != delegatedDigest &&
                  signedDigest != AuthorityFenceFingerprint.Compute(
                    [signedDelegatedZone with { Delegations = [signedDelegation with {
                        DsRecords = [ds with { DigestHex = new string('B', 64) }] }] }], null),
                "authority fingerprint binds signed child delegation DS records");
            Check(signedDigest == AuthorityFenceFingerprint.Compute(
                    [signedDelegatedZone with { Delegations = [signedDelegation with {
                        DsRecords = [ds with { DigestHex = ds.DigestHex.ToUpperInvariant() }] }] }], null),
                "case-equivalent DS digest hex has equal fingerprints");
            AgentReportServerConfig TrustPolicy(string vantage) => new("127.0.0.1", 16660, false,
                certA, keyA, Path.Combine(root, "trust-replay.json"), 10, 10, 2, 100, [],
                [new AgentTrust("observer-a", vantage, [pinA], [publicAPath]),
                 new AgentTrust("observer-b", "zone-b", [pinB], [publicBPath])]);
            var trust = TrustPolicy("zone-a");
            var reportTargets = new[] { new AgentReportTarget(fingerprintZone.Name, "service",
                ["observer-a", "observer-b"], 2) };
            AgentHealthReportStore LoadTrust(AgentReportServerConfig cfg) => new(
                cfg.Agents, reportTargets, Path.Combine(root, Guid.NewGuid().ToString("N") + "-observer-replay.json"),
                cfg.MaxTtlSeconds, cfg.MaxAgeSeconds, cfg.MaxClockSkewSeconds);
            string TrustDigest(AgentReportServerConfig cfg, AgentHealthReportStore store) =>
                AuthorityFenceFingerprint.Compute([fingerprintZone], cfg, loadedAgentStore: store);
            Check(ThrowsInvalid(() => AuthorityFenceFingerprint.Compute([fingerprintZone], trust)),
                "observer trust fingerprint cannot omit actual loaded store");
            using (var loaded = LoadTrust(trust))
            {
                var trustedDigest = TrustDigest(trust, loaded);
                var changedVantage = TrustPolicy("zone-changed");
                using (var changed = LoadTrust(changedVantage))
                    Check(trustedDigest != TrustDigest(changedVantage, changed),
                        "authority fingerprint binds actual observer identity and vantage trust");
                var originalPem = File.ReadAllText(publicAPath);
                try
                {
                    // Equivalent PEM representation does not change loaded key identity.
                    File.WriteAllText(publicAPath, originalPem.TrimEnd() + "\n\n");
                    using (var equivalent = LoadTrust(trust))
                        Check(trustedDigest == TrustDigest(trust, equivalent),
                            "equivalent public key encoding keeps canonical authority fingerprint");
                    using var replacementKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                    File.WriteAllText(publicAPath, replacementKey.ExportSubjectPublicKeyInfoPem());
                    using var replacementStore = LoadTrust(trust);
                    Check(trustedDigest == TrustDigest(trust, loaded),
                        "changing PEM on disk cannot relabel already loaded observer trust");
                    Check(trustedDigest != TrustDigest(trust, replacementStore),
                        "newly loaded replacement key changes authority fingerprint");
                    // Even disappearance of a formerly loaded path must not
                    // substitute unverified trust data in the fingerprint.
                    File.Delete(publicAPath);
                    Check(trustedDigest == TrustDigest(trust, loaded),
                        "loaded fingerprint does not depend on a second file read");
                }
                finally { File.WriteAllText(publicAPath, originalPem); }
            }
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
                Check(!receiver.IsPeerEligible("fence.example.test", "primary", 101),
                    "inbound lease alone cannot authorize a one-way partition");
                receiver.RecordPeerAcknowledgement(100, 101);
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
                restartedReceiver.RecordPeerAcknowledgement(201, 202);
                Check(recovered.Epoch > initial.Epoch &&
                      restartedReceiver.TryAccept(recovered, tlsA, now, 201) &&
                      restartedReceiver.IsPeerEligible("fence.example.test", "primary", 202),
                    "new sender epoch provides fresh recovery after authority restart");
                var freshInbound = restartedSource.CreateSnapshot(5200);
                Check(restartedReceiver.TryAccept(freshInbound, tlsA, now, 5200),
                    "fresh inbound report during one-way outage accepted as evidence");
                Check(!restartedReceiver.IsPeerEligible("fence.example.test", "primary", 5202),
                    "fresh inbound evidence cannot extend expired outbound acknowledgement");
                restartedReceiver.RecordPeerAcknowledgement(201, 5202);
                Check(!restartedReceiver.IsPeerEligible("fence.example.test", "primary", 5202),
                    "delayed acknowledgement cannot resurrect expired outbound lease");
                restartedReceiver.RecordPeerAcknowledgement(5202, 5203);
                Check(restartedReceiver.IsPeerEligible("fence.example.test", "primary", 5203),
                    "fresh outbound acknowledgement restores bidirectional eligibility");
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
                deletionReceiver.RecordPeerAcknowledgement(400, 400);
                Check(deletionReceiver.IsPeerEligible("fence.example.test", "primary", 400),
                    "valid lease initially authorizes a target before durable state loss");
                var savedReplay = File.ReadAllBytes(deletionConfig.ReplayStatePath);
                File.Delete(deletionConfig.ReplayStatePath);
                Check(!deletionReceiver.IsPeerEligible("fence.example.test", "primary", 1400),
                    "DNS read detects durable state loss without another incoming snapshot, before lease expiry");
                Check(ThrowsInvalid(() => deletionReceiver.CreateSnapshot(1401)),
                    "faulted authority cannot publish a new positive decision");
                File.WriteAllBytes(deletionConfig.ReplayStatePath, savedReplay);
                if (!OperatingSystem.IsWindows())
                    File.SetUnixFileMode(deletionConfig.ReplayStatePath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                deletionReceiver.RecordPeerAcknowledgement(1402, 1402);
                Check(!deletionReceiver.TryAccept(deletionSource.CreateSnapshot(1402), tlsA, now, 1402) &&
                      !deletionReceiver.IsPeerEligible("fence.example.test", "primary", 1403) &&
                      ThrowsInvalid(() => deletionReceiver.CreateSnapshot(1403)),
                    "restored state cannot clear a latched runtime authority fault");
                File.Delete(deletionConfig.ReplayStatePath);
            }
            File.Delete(deletionConfig.ReplayStatePath + ".lock");
            Check(ThrowsInvalid(() => new AuthorityFenceStore(deletionConfig, fingerprint, [target])),
                "deleting replay file and lock marker still fails closed after restart");
            // Equivalent, valid-looking replay JSON containing case aliases
            // must never be accepted, even if the typed value is unchanged.
            // This is a local security contract: an attacker should not be
            // able to induce last-value-wins interpretation of high-water state.
            var ambiguousConfig = configB with
            {
                EpochStatePath = Path.Combine(root, "ambiguous-epoch.json"),
                ReplayStatePath = Path.Combine(root, "ambiguous-replay.json")
            };
            using (var initialStore = new AuthorityFenceStore(ambiguousConfig, fingerprint, [target])) { }
            var cleanEpoch = File.ReadAllText(ambiguousConfig.EpochStatePath);
            var cleanReplay = File.ReadAllText(ambiguousConfig.ReplayStatePath);
            static void WritePrivateTestState(string path, string json)
            {
                File.WriteAllText(path, json);
                if (!OperatingSystem.IsWindows())
                    File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
            var ambiguousEpoch = cleanEpoch.Replace("\"Epoch\":", "\"ePoCh\":0,\"Epoch\":", StringComparison.Ordinal);
            Check(ambiguousEpoch != cleanEpoch, "epoch test fixture contains expected serialized field");
            WritePrivateTestState(ambiguousConfig.EpochStatePath, ambiguousEpoch);
            Check(ThrowsInvalid(() => new AuthorityFenceStore(ambiguousConfig, fingerprint, [target])),
                "restart refuses case-aliased duplicate persisted authority epoch");
            WritePrivateTestState(ambiguousConfig.EpochStatePath, cleanEpoch);
            var ambiguousReplay = cleanReplay.Replace("\"Sequence\":", "\"SEQUENCE\":0,\"Sequence\":", StringComparison.Ordinal);
            Check(ambiguousReplay != cleanReplay, "replay test fixture contains expected serialized field");
            WritePrivateTestState(ambiguousConfig.ReplayStatePath, ambiguousReplay);
            Check(ThrowsInvalid(() => new AuthorityFenceStore(ambiguousConfig, fingerprint, [target])),
                "restart refuses case-aliased duplicate persisted peer sequence");
            WritePrivateTestState(ambiguousConfig.ReplayStatePath, cleanReplay);
            using (var liveStore = new AuthorityFenceStore(ambiguousConfig, fingerprint, [target]))
            using (var source = new AuthorityFenceStore(configA, fingerprint, [target]))
            {
                Check(liveStore.TryAccept(source.CreateSnapshot(4000), tlsA, now, 4000),
                    "authority can accept signed peer decision before state mutation");
                liveStore.RecordPeerAcknowledgement(4000, 4001);
                Check(liveStore.IsPeerEligible("fence.example.test", "primary", 4001),
                    "authority begins with valid protected state");
                var pristine = File.ReadAllText(ambiguousConfig.ReplayStatePath);
                var ambiguous = pristine.Replace("\"Sequence\":", "\"seQUENCE\":0,\"Sequence\":", StringComparison.Ordinal);
                WritePrivateTestState(ambiguousConfig.ReplayStatePath, ambiguous);
                Check(!liveStore.IsPeerEligible("fence.example.test", "primary", 5100) &&
                      ThrowsInvalid(() => liveStore.CreateSnapshot(5100)),
                    "live ambiguous replay state immediately fences DNS eligibility and publication");
                WritePrivateTestState(ambiguousConfig.ReplayStatePath, pristine);
                Check(!liveStore.IsPeerEligible("fence.example.test", "primary", 5101) &&
                      !liveStore.CanPublish(5101),
                    "restoring unambiguous replay file does not clear sticky runtime fault");
            }
            Console.WriteLine("PASS: authority epoch/sequence JSON aliases and live state tampering fail closed");
            // Simulate loss exactly while the snapshot is evaluating local
            // eligibility: the initial durable check has already completed.
            var signingConfig = configB with
            {
                EpochStatePath = Path.Combine(root, "signing-epoch.json"),
                ReplayStatePath = Path.Combine(root, "signing-replay.json")
            };
            var loseDuringEvaluation = false;
            var signingTarget = new AuthorityFenceTarget("fence.example.test", "primary", _ =>
            {
                if (loseDuringEvaluation) File.Delete(signingConfig.ReplayStatePath);
                return true;
            });
            using (var signingStore = new AuthorityFenceStore(signingConfig, fingerprint, [signingTarget]))
            {
                Check(signingStore.CreateSnapshot(1500).Decisions.Single().Eligible,
                    "authority signs eligible decision with intact durable state");
                loseDuringEvaluation = true;
                Check(ThrowsInvalid(() => signingStore.CreateSnapshot(1501)),
                    "state loss during local evidence evaluation prevents signing a positive snapshot");
                Check(!signingStore.CanPublish(1501),
                    "fault detected during evaluation blocks publication");
            }
            // A snapshot can be signed while state is intact but not yet handed
            // to HTTPS. That separate race must fail closed at publication.
            var sendConfig = configB with
            {
                EpochStatePath = Path.Combine(root, "send-epoch.json"),
                ReplayStatePath = Path.Combine(root, "send-replay.json")
            };
            using (var sendStore = new AuthorityFenceStore(sendConfig, fingerprint, [target]))
            using (var sendSource = new AuthorityFenceStore(configA, fingerprint, [target]))
            {
                Check(sendStore.TryAccept(sendSource.CreateSnapshot(1600), tlsA, now, 1600),
                    "publication fixture receives a valid inbound lease");
                Check(sendStore.CreateSnapshot(1600).Decisions.Single().Eligible && sendStore.CanPublish(1600),
                    "intact state permits prepared publication");
                var replayBytes = File.ReadAllBytes(sendConfig.ReplayStatePath);
                File.Delete(sendConfig.ReplayStatePath);
                sendStore.RecordPeerAcknowledgement(1600, 1601);
                Check(!sendStore.IsPeerEligible("fence.example.test", "primary", 1601),
                    "acknowledgement rechecks durable state even inside cached read interval");
                Check(!sendStore.CanPublish(1601),
                    "durable loss after preparation prevents transmission");
                File.WriteAllBytes(sendConfig.ReplayStatePath, replayBytes);
                if (!OperatingSystem.IsWindows())
                    File.SetUnixFileMode(sendConfig.ReplayStatePath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                Check(!sendStore.CanPublish(1602) &&
                      ThrowsInvalid(() => sendStore.CreateSnapshot(1602)),
                    "restoring replay file cannot reopen a faulted publication gate");
            }
            VerifyHttpsIngress(configA, configB, fingerprint, target, tlsA, pinB);
            Console.WriteLine("PASS: authority 2-of-2 fence signature, membership, config, lease, replay and restart contracts");
        }
        finally { Directory.Delete(root, recursive: true); }

        static X509Certificate2 CreateCertificate(string commonName, RSA key)
        {
            var request = new CertificateRequest("CN=" + commonName, key, HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
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

        static void VerifyHttpsIngress(AuthorityFenceConfig sourceConfig, AuthorityFenceConfig receiverConfig,
            string digest, AuthorityFenceTarget target, X509Certificate2 clientCertificate, string receiverPin)
        {
            using var probe = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
            probe.Start();
            var port = ((IPEndPoint)probe.LocalEndpoint).Port;
            probe.Stop();
            var liveConfig = receiverConfig with { ListenPort = port };
            using var receiver = new AuthorityFenceStore(liveConfig, digest, [target]);
            using var source = new AuthorityFenceStore(sourceConfig, digest, [target]);
            using var cancellation = new CancellationTokenSource();
            var runtime = new AuthorityFenceRuntime(liveConfig, receiver);
            runtime.StartAsync(cancellation.Token).GetAwaiter().GetResult();
            try
            {
                using var sslClientCertificate = X509CertificateLoader.LoadPkcs12(
                    clientCertificate.Export(X509ContentType.Pkcs12), null,
                    X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
                var endpoint = new Uri($"https://127.0.0.1:{port}/authority-fence/v1/snapshot");
                var sequence = Math.Max(Environment.TickCount64, 10_000_000);
                var signed = source.CreateSnapshot(sequence);
                var json = JsonSerializer.Serialize(signed);
                var propertyStart = json.IndexOf("\"sequence\":", StringComparison.OrdinalIgnoreCase);
                var propertyEnd = propertyStart < 0 ? -1 : json.IndexOf(',', propertyStart);
                if (propertyEnd < 0) propertyEnd = json.IndexOf('}', propertyStart);
                Check(propertyStart >= 0 && propertyEnd > propertyStart,
                    "signed HTTPS fixture contains sequence property");
                var marker = json[propertyStart..propertyEnd];
                var signedSequence = long.Parse(marker[(marker.IndexOf(':') + 1)..],
                    System.Globalization.CultureInfo.InvariantCulture);
                var conflictingBefore = json.Replace(marker,
                    $"\"Sequence\":{signedSequence + 1},{marker}", StringComparison.Ordinal);
                var duplicateAfter = json.Replace(marker,
                    $"{marker},\"Sequence\":{signedSequence}", StringComparison.Ordinal);

                int Post(string payload)
                {
                    // A 413 can terminate the HTTP/1.1 connection while the
                    // oversized body is still being sent. Use a fresh TLS
                    // connection for each security assertion, so a closed
                    // transport is not mistaken for replay-state corruption.
                    using var handler = new HttpClientHandler { UseProxy = false };
                    handler.ClientCertificates.Add(sslClientCertificate);
                    handler.ServerCertificateCustomValidationCallback = (_, certificate, _, _) =>
                        AuthorityFenceStore.IsPinnedCertificate(certificate, [receiverPin], "1.3.6.1.5.5.7.3.1");
                    using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(3) };
                    using var content = new StringContent(payload, Encoding.UTF8, "application/json");
                    using var response = client.PostAsync(endpoint, content).GetAwaiter().GetResult();
                    return (int)response.StatusCode;
                }

                Check(Post(conflictingBefore) == 400,
                    "mTLS authority ingress rejects valid signed snapshot with conflicting case-alias before signed property");
                Check(Post(duplicateAfter) == 400,
                    "mTLS authority ingress rejects valid signed snapshot with duplicate property after signed value");
                // An oversized authenticated frame must be rejected before it can
                // advance the durable replay high-water mark. Keep the payload
                // bounded above the contract without constructing a large fixture.
                var oversized = json + new string(' ', AuthorityFenceContract.MaximumSerializedBytes);
                Check(Post(oversized) == 413,
                    "mTLS authority ingress rejects oversized snapshot without accepting it");
                Check(Post(json) == 204,
                    "mTLS authority ingress accepts clean signed snapshot after malformed and oversized frames without advancing replay state");
                Check(Post(json) == 409, "mTLS authority ingress rejects replay of accepted signed snapshot");
            }
            finally
            {
                // The publisher must stop on disposal even if the caller's
                // startup token is still live (as with service shutdown).
                var stop = runtime.DisposeAsync().AsTask();
                if (!stop.Wait(TimeSpan.FromSeconds(4)))
                {
                    cancellation.Cancel(); // unblock an older broken runtime
                    stop.GetAwaiter().GetResult();
                    throw new Exception("FAIL: authority publisher disposal requires external cancellation");
                }
                stop.GetAwaiter().GetResult();
                Check(!cancellation.IsCancellationRequested,
                    "authority HTTPS publisher shuts down without caller cancellation");
            }
        }
    }
}
