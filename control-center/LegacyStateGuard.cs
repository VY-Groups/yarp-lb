using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

/// <summary>
/// Prevents a renamed Windows control plane from silently bootstrapping an
/// unrelated, empty identity store while a prior YARP installation has users
/// or protected secrets in a sibling ProgramData directory.
/// This is a detection gate, NOT a migration or a data-copy mechanism.
/// </summary>
public static class LegacyStateGuard
{
    public static IReadOnlyList<string> FindPriorWindowsStores(string activeDirectory)
    {
        if (string.IsNullOrWhiteSpace(activeDirectory))
            throw new ArgumentException("Active state directory must be explicit", nameof(activeDirectory));
        var current = Path.TrimEndingDirectorySeparator(Path.GetFullPath(activeDirectory));
        if (!string.Equals(Path.GetFileName(current), "ControlPlane", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Windows control plane must use the ControlPlane directory");

        var productDir = Directory.GetParent(current)
            ?? throw new InvalidOperationException("Invalid Windows product state directory");
        var programData = productDir.Parent?.FullName
            ?? throw new InvalidOperationException("Invalid Windows ProgramData layout");

        if (!Directory.Exists(programData)) return Array.Empty<string>();
        var stores = new List<string>();
        foreach (var sibling in Directory.EnumerateDirectories(programData))
        {
            // Classify other YARP installs by a neutral product-family suffix;
            // never embed an old organization or product identity in the code.
            if (!Path.GetFileName(sibling).EndsWith("Yarp", StringComparison.OrdinalIgnoreCase))
                continue;
            var state = Path.Combine(sibling, "ControlPlane");
            if (string.Equals(
                Path.TrimEndingDirectorySeparator(Path.GetFullPath(state)), current,
                StringComparison.OrdinalIgnoreCase))
                continue;
            if (File.Exists(Path.Combine(state, "admin-users.json")) ||
                File.Exists(Path.Combine(state, "mail-settings.json")) ||
                File.Exists(Path.Combine(state, "directory-settings.json")) ||
                Directory.Exists(Path.Combine(state, "data-protection-keys")))
                stores.Add(state);
        }
        return stores;
    }

    public static void RejectUnmigratedWindowsState(string activeDirectory)
    {
        // A previously initialized neutral installation can legitimately
        // coexist with a retained, offline rollback backup of the old service.
        // Never replace, copy, erase or relabel either state directory.
        if (File.Exists(Path.Combine(activeDirectory, "admin-users.json")))
            return;

        var existing = FindPriorWindowsStores(activeDirectory);
        if (existing.Count == 0) return;
        throw new InvalidOperationException(
            "Previous YARP control-plane state detected: " + string.Join("; ", existing) +
            ". Stopping before any new state is created. The renamed application " +
            "cannot automatically decrypt previous protected SMTP or directory " +
            "credentials. Preserve the original state and keys; use an isolated " +
            "fresh test host or an independently approved migration and rollback. " +
            "Do not copy old ciphertext or delete the old state to bypass this check.");
    }
}
