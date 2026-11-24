using System.Globalization;

/// <summary>
/// OFFLINE ONLY. An authorized independent coordinator MUST fence/stop key
/// writers, provision protected external trust material and secure custody of
/// the RSA wrapping certificate outside this software. Never auto-restore a
/// running state root or bypass the independent revision floor.
/// </summary>
try
{
    if (!OperatingSystem.IsLinux())
        throw new PlatformNotSupportedException("Encrypted snapshots require Linux");
    if (args.Length < 1 || args[0] is not ("capture" or "restore"))
        throw new ArgumentException("Exactly capture or restore is required");

    var capture = args[0] == "capture";
    var permitted = capture
        ? new HashSet<string>(StringComparer.Ordinal) {
            "--ring", "--archive-root", "--label" }
        : new HashSet<string>(StringComparer.Ordinal) {
            "--archive", "--state-root", "--checkpoint", "--trusted-public-key",
            "--minimum-revision-file" };
    if (args.Length != 1 + 2 * permitted.Count)
        throw new ArgumentException("Missing or extra encrypted snapshot arguments");
    var parameters = new Dictionary<string, string>(StringComparer.Ordinal);
    for (int i = 1; i < args.Length; i += 2)
    {
        if (!permitted.Contains(args[i]) ||
            !parameters.TryAdd(args[i], args[i + 1]) ||
            (args[i] != "--label" && !Path.IsPathFullyQualified(args[i + 1])))
            throw new ArgumentException("Invalid encrypted snapshot option");
    }
    if (!permitted.SetEquals(parameters.Keys))
        throw new ArgumentException("Incomplete encrypted snapshot configuration");

    string digest;
    if (capture)
    {
        digest = LinuxDpEncryptedSnapshot.Capture(
            parameters["--ring"], parameters["--archive-root"], parameters["--label"]);
        Console.WriteLine("PASS: owner-only encrypted DP backup staged sha256=" + digest +
            "; NOT a signed restore or a production backup-custody attestation");
    }
    else
    {
        var destinationRing = Path.Combine(parameters["--state-root"], "data-protection-keys");
        var floor = LinuxDpRecoveryFloor.ReadExternalFloor(
            destinationRing, parameters["--minimum-revision-file"]);
        digest = LinuxDpEncryptedSnapshot.RestoreOffline(
            parameters["--archive"], parameters["--state-root"],
            parameters["--checkpoint"], parameters["--trusted-public-key"], floor);
        Console.WriteLine("PASS: verified and non-overwritten DP ciphertext restore sha256=" +
            digest + " revisionFloor=" + floor.ToString(CultureInfo.InvariantCulture) +
            "; service remains offline until operator acceptance");
    }
    return 0;
}
catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or
    IOException or UnauthorizedAccessException or PlatformNotSupportedException or
    System.Security.Cryptography.CryptographicException or
    System.Text.Json.JsonException or System.Xml.XmlException)
{
    // Never print filesystem paths, private keys, auth cookies or XML bodies.
    Console.Error.WriteLine("FAIL: offline encrypted DP snapshot/restore refused");
    return 1;
}
