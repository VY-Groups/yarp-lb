using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

/// <summary>
/// Pure deterministic selection primitives. No access to YARP or HTTP types, so they
/// can be exercised in an offline console test project.
/// </summary>
public static class LoadBalancingCore
{
    public const int MinWeight = 1;
    public const int MaxWeight = 100;

    public static bool TrySlowStartSeconds(string? raw, out int seconds)
    {
        seconds = 0;
        return raw is null || (int.TryParse(raw, NumberStyles.None, CultureInfo.InvariantCulture, out seconds)
            && seconds is >= 0 and <= 600);
    }

    public static int RampedWeight(int configuredWeight, double elapsedSeconds, int slowStartSeconds)
    {
        if (configuredWeight is < MinWeight or > MaxWeight) throw new ArgumentOutOfRangeException(nameof(configuredWeight));
        if (slowStartSeconds is < 0 or > 600) throw new ArgumentOutOfRangeException(nameof(slowStartSeconds));
        if (slowStartSeconds == 0 || elapsedSeconds >= slowStartSeconds) return configuredWeight;
        if (double.IsNaN(elapsedSeconds) || elapsedSeconds <= 0) return 1;
        return Math.Clamp((int)Math.Floor(configuredWeight * elapsedSeconds / slowStartSeconds), 1, configuredWeight);
    }

    public static bool TryWeight(string? raw, out int weight)
    {
        weight = 1;
        if (raw is null) return true;
        return int.TryParse(raw, NumberStyles.None, CultureInfo.InvariantCulture, out weight)
               && weight is >= MinWeight and <= MaxWeight;
    }

    // Compare projected outstanding HTTP requests per unit of capacity.
    // Cross multiplication avoids rounding and int overflow. Equal scores
    // are explicitly a tie, resolved by the caller with reservoir sampling.
    public static int CompareProjectedLoad(int outstanding, int weight, int otherOutstanding, int otherWeight)
    {
        if (outstanding < 0 || otherOutstanding < 0)
            throw new ArgumentOutOfRangeException(nameof(outstanding));
        if (weight is < MinWeight or > MaxWeight || otherWeight is < MinWeight or > MaxWeight)
            throw new ArgumentOutOfRangeException(nameof(weight));
        return (((long)outstanding + 1) * otherWeight)
            .CompareTo(((long)otherOutstanding + 1) * weight);
    }

    public static int PickWeightedIndex(IReadOnlyList<int> weights, int ticket)
    {
        if (weights.Count == 0) return -1;
        var total = 0;
        foreach (var weight in weights)
        {
            if (weight is < MinWeight or > MaxWeight) throw new ArgumentOutOfRangeException(nameof(weights));
            total = checked(total + weight);
        }
        if (ticket < 0 || ticket >= total) throw new ArgumentOutOfRangeException(nameof(ticket));
        for (var i = 0; i < weights.Count; i++)
        {
            if (ticket < weights[i]) return i;
            ticket -= weights[i];
        }
        throw new InvalidOperationException("Weighted selection failed");
    }

    public static int PickRendezvousIndex(string clientKey, IReadOnlyList<string> ids, IReadOnlyList<int> weights)
    {
        if (string.IsNullOrEmpty(clientKey)) throw new ArgumentException("Missing client key", nameof(clientKey));
        if (ids.Count != weights.Count) throw new ArgumentException("ID/weight lengths differ");
        return PickRendezvousIndex(clientKey, ids, weights, ids.Count);
    }

    // The count overload permits bounded, pooled destination snapshots whose
    // backing arrays may have *different* capacities. Never hash uninitialized
    // pool tails; the ordinary overload retains its strict equal-size contract.
    public static int PickRendezvousIndex(string clientKey, IReadOnlyList<string> ids,
        IReadOnlyList<int> weights, int candidateCount)
    {
        if (string.IsNullOrEmpty(clientKey)) throw new ArgumentException("Missing client key", nameof(clientKey));
        if (candidateCount < 0 || candidateCount > ids.Count || candidateCount > weights.Count)
            throw new ArgumentOutOfRangeException(nameof(candidateCount));
        // Preserve the exact hash input, tie-breaking and selection semantics.
        // Long inputs allocate at most one scratch byte[] per selection.
        var keyBytesRequired = Encoding.UTF8.GetByteCount(clientKey);
        var maxInputBytes = checked(keyBytesRequired + 1);
        for (var i = 0; i < candidateCount; i++)
        {
            var id = ids[i];
            if (string.IsNullOrEmpty(id)) throw new ArgumentOutOfRangeException(nameof(ids));
            maxInputBytes = checked(Math.Max(maxInputBytes,
                keyBytesRequired + 1 + Encoding.UTF8.GetByteCount(id)));
        }
        Span<byte> input = maxInputBytes <= 1024
            ? stackalloc byte[maxInputBytes]
            : new byte[maxInputBytes];
        var keyBytes = Encoding.UTF8.GetBytes(clientKey, input);
        input[keyBytes] = 0x1f;
        Span<byte> digest = stackalloc byte[32];
        var bestScore = double.PositiveInfinity;
        var bestIndex = -1;
        for (var i = 0; i < candidateCount; i++)
        {
            if (weights[i] is < MinWeight or > MaxWeight || string.IsNullOrEmpty(ids[i]))
                throw new ArgumentOutOfRangeException(nameof(weights));
            // Weighted rendezvous: smaller -ln(U)/weight wins. A deterministic hash
            // of the client and destination gives minimal remapping on node changes.
            var idBytes = Encoding.UTF8.GetBytes(ids[i], input[(keyBytes + 1)..]);
            SHA256.HashData(input[..(keyBytes + 1 + idBytes)], digest);
            var hash = BinaryPrimitives.ReadUInt64BigEndian(digest[..8]);
            var u = Math.Clamp((hash + 0.5) / 18446744073709551616.0, double.Epsilon, Math.BitDecrement(1.0));
            var score = -Math.Log(u) / weights[i];
            if (score < bestScore || (score == bestScore && (bestIndex < 0 ||
                string.CompareOrdinal(ids[i], ids[bestIndex]) < 0)))
            {
                bestScore = score;
                bestIndex = i;
            }
        }
        return bestIndex;
    }
}
