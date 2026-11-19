/// <summary>
/// Pure, deterministic primary selection helper for an opt-in HAProxy-style
/// primary/backup routing policy. It neither retries nor replays HTTP requests.
/// </summary>
public static class PrimaryBackupCore
{
    public static bool HasSuccessfulActiveCheck(string? activeHealthState) =>
        string.Equals(activeHealthState, "Healthy", StringComparison.Ordinal);

    public static bool TryBackupRole(string? value, out bool backup)
    {
        backup = false;
        if (value is null || string.Equals(value, "primary", StringComparison.OrdinalIgnoreCase))
            return true;
        if (string.Equals(value, "backup", StringComparison.OrdinalIgnoreCase))
        {
            backup = true;
            return true;
        }
        return false;
    }

    public static int PrimaryWeightTotal(ReadOnlySpan<int> weights)
    {
        var total = 0;
        foreach (var weight in weights)
        {
            if (weight is < 0 or > 100)
                throw new ArgumentOutOfRangeException(nameof(weights),
                    "Primary weights must be 0 for ineligible, or 1..100");
            total = checked(total + weight);
        }
        return total;
    }

    // ticket is a uniform integer in [0, PrimaryWeightTotal(weights)).
    public static int PickPrimaryIndex(ReadOnlySpan<int> weights, int ticket)
    {
        var total = PrimaryWeightTotal(weights);
        if (total == 0) return -1;
        if (ticket < 0 || ticket >= total) throw new ArgumentOutOfRangeException(nameof(ticket));
        for (var i = 0; i < weights.Length; i++)
        {
            if (ticket < weights[i]) return i;
            ticket -= weights[i];
        }
        throw new InvalidOperationException("Primary/backup weighted selection is inconsistent");
    }
}
