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

    public static void RejectUnmigratedWindowsState(string activeDirectory, IReadOnlyCollection<string>? approvedResidualStores = null)
    {
        // A previously initialized neutral installation can legitimately
        // coexist with a retained, offline rollback backup of the old service.
        // Never replace, copy, erase or relabel either state directory.
        if (File.Exists(Path.Combine(activeDirectory, "admin-users.json")))
            return;

        var existing = FindPriorWindowsStores(activeDirectory);
        if (existing.Count == 0) return;
        if (approvedResidualStores is not null && existing.All(store => approvedResidualStores.Contains(store, StringComparer.OrdinalIgnoreCase)))
        {
            foreach (var store in existing)
            {
                RejectLink(Directory.GetParent(store)!.FullName);
                RejectLink(store);
                // Recheck anything readable. The elevated Setup preflight
                // classified the exact path; the service must not gain read
                // rights to inaccessible old key material just to start.
                // Never accept known identity/credential files as residual.
                if (File.Exists(Path.Combine(store, "admin-users.json")) ||
                    File.Exists(Path.Combine(store, "mail-settings.json")) ||
                    File.Exists(Path.Combine(store, "directory-settings.json")))
                    throw new InvalidOperationException("Previous YARP control-plane state detected: legacy identity or credentials require reviewed migration.");
                try { ValidateResidualStore(store); }
                catch (UnauthorizedAccessException) { /* administrator-approved isolation, no legacy read grant */ }
            }
            return;
        }
        throw new InvalidOperationException(
            "Previous YARP control-plane state detected: " + string.Join("; ", existing) +
            ". Stopping before any new state is created. The renamed application " +
            "cannot automatically decrypt previous protected SMTP or directory " +
            "credentials. Preserve the original state and keys; use an isolated " +
            "fresh test host or an independently approved migration and rollback. " +
            "Do not copy old ciphertext or delete the old state to bypass this check.");
    }

    // Called by elevated, ordinary lab Setup only. Do not import, rename,
    // decrypt or alter a former installation. Unknown files, directories
    // and reparse points require a separately reviewed migration.
    public static IReadOnlyList<string> ClassifyResidualWindowsStores(string activeDirectory)
    {
        var current = Path.TrimEndingDirectorySeparator(Path.GetFullPath(activeDirectory));
        var root = Directory.GetParent(current)?.Parent?.FullName
            ?? throw new InvalidOperationException("Invalid Windows ProgramData layout");
        var residual = new List<string>();
        foreach (var sibling in Directory.EnumerateDirectories(root))
        {
            if (!Path.GetFileName(sibling).EndsWith("Yarp", StringComparison.OrdinalIgnoreCase))
                continue;
            var state = Path.Combine(sibling, "ControlPlane");
            if (string.Equals(state, current, StringComparison.OrdinalIgnoreCase))
                continue;
            RejectLink(sibling);
            if (!Directory.Exists(state))
            {
                if (File.Exists(state) || new DirectoryInfo(state).LinkTarget is not null)
                    throw new InvalidOperationException("Legacy state requires reviewed migration: " + state);
                continue;
            }
            ValidateResidualStore(state);
            if (Directory.Exists(Path.Combine(state, "data-protection-keys")))
                residual.Add(state);
        }
        return residual;
    }

    private static void ValidateResidualStore(string state)
    {
        RejectLink(state);
        foreach (var entry in Directory.EnumerateFileSystemEntries(state))
        {
            RejectLink(entry);
            var name = Path.GetFileName(entry);
            if (!Directory.Exists(entry))
                throw new InvalidOperationException("Legacy state requires reviewed migration: " + state);
            if (name.Equals("data-protection-keys", StringComparison.OrdinalIgnoreCase))
            {
                foreach (var key in Directory.EnumerateFileSystemEntries(entry))
                {
                    RejectLink(key);
                    var file = Path.GetFileName(key);
                    if (!File.Exists(key) || !file.StartsWith("key-", StringComparison.OrdinalIgnoreCase)
                        || !file.EndsWith(".xml", StringComparison.OrdinalIgnoreCase)
                        || !Guid.TryParseExact(file[4..^4], "D", out _))
                        throw new InvalidOperationException("Legacy state requires reviewed migration: " + state);
                }
            }
            else if (!(new[] { "change-requests", "config-backups", "fleet-rollouts" }).Contains(name, StringComparer.OrdinalIgnoreCase)
                     || Directory.EnumerateFileSystemEntries(entry).Any())
                throw new InvalidOperationException("Legacy state requires reviewed migration: " + state);
        }

    }

    private static void RejectLink(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException("Legacy state requires reviewed migration: reparse point detected.");
    }

}
