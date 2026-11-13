using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

/// <summary>Pure deterministic selection primitives used by the YARP policy extensions.</summary>
public static class LoadBalancingCore
{
    public const int MinWeight = 1;
    public const int MaxWeight = 100;

    public static bool TryWeight(string? raw, out int weight)
    {
        weight = 1;
        if (raw is null) return true;
        return int.TryParse(raw, NumberStyles.None, CultureInfo.InvariantCulture, out weight)
               && weight is >= MinWeight and <= MaxWeight;
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
        var bestScore = double.PositiveInfinity;
        var bestIndex = -1;
        for (var i = 0; i < ids.Count; i++)
        {
            if (weights[i] is < MinWeight or > MaxWeight || string.IsNullOrEmpty(ids[i]))
                throw new ArgumentOutOfRangeException(nameof(weights));
            // Weighted rendezvous: lower -ln(U)/weight score wins.
            var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(clientKey + "\u001f" + ids[i]));
            var hash = BinaryPrimitives.ReadUInt64BigEndian(bytes.AsSpan(0, 8));
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
