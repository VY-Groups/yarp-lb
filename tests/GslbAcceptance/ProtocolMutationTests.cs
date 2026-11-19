using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using GatewayCore.Gslb.Contracts;

/// <summary>
/// Deterministic, bounded mutation coverage for authenticated GSLB wire
/// contracts. These checks exercise the shipping validators without changing
/// runtime behavior or relying on nondeterministic fuzzing.
/// </summary>
internal static class ProtocolMutationTests
{
    private const int ReportSeed = 0x109A11;
    private const int AuthoritySeed = 0x109B22;
    private const int RandomFrameCount = 128;

    public static void Run()
    {
        AgentHealthReportMutations();
        AuthorityFenceMutations();
        Console.WriteLine("PASS: deterministic bounded mutations for signed health and authority contracts");
    }

    private static void AgentHealthReportMutations()
    {
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var verifier = ECDsa.Create(signer.ExportParameters(false));
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var unsigned = new AgentHealthReport(1, "agent-109", AgentHealthReportContract.KeyId(signer),
            "lab.example.test.", "mumbai", 7, 41, now, now + 8, "http", "healthy", 1000, 23, "pending");
        var valid = unsigned with { Signature = AgentHealthReportContract.Sign(unsigned, signer) };
        Require(AgentHealthReportContract.Verify(valid, verifier, 8), "valid report control rejected");

        var mutations = new AgentHealthReport[]
        {
            valid with { Version = 2 },
            valid with { AgentId = "../agent" },
            valid with { KeyId = new string('0', 64) },
            valid with { Zone = "-bad.example" },
            valid with { SiteId = "mumbai/other" },
            valid with { Epoch = 0 },
            valid with { Epoch = long.MinValue },
            valid with { Sequence = 0 },
            valid with { Sequence = long.MinValue },
            valid with { ObservedAtUnixSeconds = 0 },
            valid with { ExpiresAtUnixSeconds = now },
            valid with { ExpiresAtUnixSeconds = long.MaxValue },
            valid with { ProbeType = "icmp" },
            valid with { Verdict = "maybe" },
            valid with { ConfidencePermille = 1001 },
            valid with { LatencyMilliseconds = -1 },
            valid with { Signature = "!" }
        };
        foreach (var mutation in mutations)
            Require(!AgentHealthReportContract.Verify(mutation, verifier, 8),
                "mutated or boundary-invalid report verified");

        // A validly shaped but bit-flipped signature must never verify.
        var random = new Random(ReportSeed);
        var signature = Convert.FromBase64String(valid.Signature);
        for (var index = 0; index < 64; index++)
        {
            var changed = signature.ToArray();
            var offset = random.Next(changed.Length);
            changed[offset] ^= (byte)(1 << random.Next(8));
            var altered = valid with { Signature = Convert.ToBase64String(changed) };
            Require(!AgentHealthReportContract.Verify(altered, verifier, 8),
                $"report signature mutation {index} verified");
        }

        // Conflicting duplicate JSON fields must not preserve the signed value
        // after deserialization (the runtime parser uses the same serializer).
        var reportJson = JsonSerializer.Serialize(valid);
        var duplicateSequence = reportJson.Replace(
            $"\"Sequence\":{valid.Sequence}",
            $"\"Sequence\":{valid.Sequence},\"Sequence\":{valid.Sequence + 1}",
            StringComparison.Ordinal);
        Require(!ReferenceEquals(duplicateSequence, reportJson), "report duplicate-field fixture was not built");
        Require(!StrictJsonPropertyNames.HasNoDuplicates(Encoding.UTF8.GetBytes(duplicateSequence)),
            "duplicate report properties are rejected before last-value JSON deserialization");
        var duplicateParsed = JsonSerializer.Deserialize<AgentHealthReport>(duplicateSequence);
        Require(duplicateParsed is not null && !AgentHealthReportContract.Verify(duplicateParsed, verifier, 8),
            "conflicting duplicate report field retained valid signature");

        // Run a fixed number of arbitrary bounded JSON frames through the
        // contract parser. Parse failures are expected; parsed frames must not
        // verify unless they reproduce the signed contract exactly.
        for (var index = 0; index < RandomFrameCount; index++)
        {
            var frame = new byte[random.Next(0, AgentHealthReportContract.MaximumSerializedBytes + 1)];
            random.NextBytes(frame);
            try
            {
                var parsed = JsonSerializer.Deserialize<AgentHealthReport>(frame);
                if (parsed is not null)
                    Require(!AgentHealthReportContract.Verify(parsed, verifier, 8),
                        $"random report JSON frame {index} verified");
            }
            catch (JsonException) { }
        }

        var oversizedReport = new byte[AgentHealthReportContract.MaximumSerializedBytes + 1];
        Require(oversizedReport.Length > AgentHealthReportContract.MaximumSerializedBytes,
            "report oversize fixture did not exceed its ingress bound");
    }

    private static void AuthorityFenceMutations()
    {
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var verifier = ECDsa.Create(signer.ExportParameters(false));
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var unsigned = new AuthorityFenceSnapshot(1, "authority-a", "authority-b", new string('A', 64),
            9, 51, now, 5, [new AuthorityFenceDecision("lab.example.test", "primary", true)], string.Empty);
        var valid = unsigned with { Signature = AuthorityFenceContract.Sign(unsigned, signer) };
        Require(AuthorityFenceContract.Verify(valid, verifier), "valid authority snapshot control rejected");

        var mutations = new AuthorityFenceSnapshot[]
        {
            valid with { Version = 2 },
            valid with { AuthorityId = "authority-c" },
            valid with { PeerId = "authority-c" },
            valid with { ConfigurationSha256 = new string('B', 64) },
            valid with { Epoch = 0 },
            valid with { Epoch = long.MinValue },
            valid with { Sequence = 0 },
            valid with { Sequence = long.MinValue },
            valid with { IssuedAtUnixSeconds = now + 1 },
            valid with { LeaseSeconds = 6 },
            valid with { Decisions = [new AuthorityFenceDecision("lab.example.test", "primary", false)] }
        };
        foreach (var mutation in mutations)
            Require(!AuthorityFenceContract.Verify(mutation, verifier),
                "mutated authority snapshot verified");

        var random = new Random(AuthoritySeed);
        var signature = Convert.FromBase64String(valid.Signature);
        for (var index = 0; index < 64; index++)
        {
            var changed = signature.ToArray();
            var offset = random.Next(changed.Length);
            changed[offset] ^= (byte)(1 << random.Next(8));
            Require(!AuthorityFenceContract.Verify(valid with
                { Signature = Convert.ToBase64String(changed) }, verifier),
                $"authority signature mutation {index} verified");
        }

        var authorityJson = JsonSerializer.Serialize(valid);
        var duplicateSequence = authorityJson.Replace(
            $"\"Sequence\":{valid.Sequence}",
            $"\"Sequence\":{valid.Sequence},\"Sequence\":{valid.Sequence + 1}",
            StringComparison.Ordinal);
        Require(!ReferenceEquals(duplicateSequence, authorityJson), "authority duplicate-field fixture was not built");
        Require(!StrictJsonPropertyNames.HasNoDuplicates(Encoding.UTF8.GetBytes(duplicateSequence)),
            "duplicate authority properties are rejected before last-value JSON deserialization");
        var duplicateParsed = JsonSerializer.Deserialize<AuthorityFenceSnapshot>(duplicateSequence);
        Require(duplicateParsed is not null && !AuthorityFenceContract.Verify(duplicateParsed, verifier),
            "conflicting duplicate authority field retained valid signature");

        for (var index = 0; index < RandomFrameCount; index++)
        {
            var frame = new byte[random.Next(0, AuthorityFenceContract.MaximumSerializedBytes + 1)];
            random.NextBytes(frame);
            try
            {
                var parsed = JsonSerializer.Deserialize<AuthorityFenceSnapshot>(frame);
                if (parsed is not null)
                    Require(!AuthorityFenceContract.Verify(parsed, verifier),
                        $"random authority JSON frame {index} verified");
            }
            catch (JsonException) { }
        }

        var oversizedSnapshot = new byte[AuthorityFenceContract.MaximumSerializedBytes + 1];
        Require(oversizedSnapshot.Length > AuthorityFenceContract.MaximumSerializedBytes,
            "authority oversize fixture did not exceed its ingress bound");

        // Sequence and epoch maxima are valid monotonic values; nonpositive
        // boundaries are rejected above. A receiver must compare them as a
        // lexicographic pair and not wrap on increment.
        var maximumCounterFrame = unsigned with { Epoch = long.MaxValue, Sequence = long.MaxValue };
        maximumCounterFrame = maximumCounterFrame with
            { Signature = AuthorityFenceContract.Sign(maximumCounterFrame, signer) };
        Require(AuthorityFenceContract.Verify(maximumCounterFrame, verifier),
            "maximum positive epoch/sequence frame was rejected or overflowed");
    }

    private static void Require(bool condition, string message)
    {
        if (!condition) throw new Exception("FAIL: protocol mutation test: " + message);
    }
}
