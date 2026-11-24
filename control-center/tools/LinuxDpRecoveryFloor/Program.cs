using System.Globalization;

// OFFLINE only. Stop the authorized gateway and fence its backup/recovery
// coordinator before committing a new signed Linux DP inventory revision.
// This tool never modifies encrypted keys, manifests or production servers.
try
{
    if (!OperatingSystem.IsLinux())
        throw new PlatformNotSupportedException("Linux-only recovery authority");
    var names = new HashSet<string>(StringComparer.Ordinal) {
        "--ring", "--checkpoint", "--trusted-public-key", "--revision-floor-file"
    };
    if (args.Length != 8)
        throw new ArgumentException("Exactly four recovery coordinator options required");
    var parameters = new Dictionary<string, string>(StringComparer.Ordinal);
    for (int i = 0; i < args.Length; i += 2)
    {
        if (!names.Contains(args[i]) || !Path.IsPathFullyQualified(args[i + 1]) ||
            !parameters.TryAdd(args[i], args[i + 1]))
            throw new ArgumentException("Unsafe or duplicate recovery coordinator option");
    }
    if (!names.SetEquals(parameters.Keys))
        throw new ArgumentException("Incomplete recovery coordinator inputs");
    var revision = LinuxDpRecoveryFloor.CommitVerifiedOfflineRecovery(
        parameters["--ring"], parameters["--checkpoint"],
        parameters["--trusted-public-key"], parameters["--revision-floor-file"]);
    Console.WriteLine("PASS: independently anchored Linux DP revision " +
        revision.ToString(CultureInfo.InvariantCulture) +
        "; ring unchanged; NOT a fleet recovery or live deployment");
    return 0;
}
catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or
    IOException or UnauthorizedAccessException or System.Security.Cryptography.CryptographicException or
    System.Text.Json.JsonException or PlatformNotSupportedException)
{
    // Never print paths, cookies, plaintext secrets, signer material or raw XML.
    Console.Error.WriteLine("FAIL: independent Linux DP revision commitment refused");
    return 1;
}
