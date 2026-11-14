using System;
using System.IO;
using System.Linq;

var root = Path.Combine(Path.GetTempPath(), "gatewaycore-state-guard-" + Guid.NewGuid().ToString("N"));
try
{
    var current = Path.Combine(root, "GatewayCoreYarp", "ControlPlane");
    var previous = Path.Combine(root, "FormerYarp", "ControlPlane");
    Directory.CreateDirectory(current);

    Assert(LegacyStateGuard.FindPriorWindowsStores(current).Count == 0,
        "A clean install must not report earlier state");
    LegacyStateGuard.RejectUnmigratedWindowsState(current);
    Assert(!File.Exists(Path.Combine(current, "admin-users.json")),
        "A clean preflight must not silently bootstrap an admin");

    Directory.CreateDirectory(previous);
    Assert(LegacyStateGuard.FindPriorWindowsStores(current).Count == 0,
        "An empty YARP directory is not a migrated installation");
    var previousUsers = Path.Combine(previous, "admin-users.json");
    File.WriteAllText(previousUsers, "[{\"Username\":\"previous-admin\"}]");
    var existingBytes = File.ReadAllBytes(previousUsers);
    Assert(LegacyStateGuard.FindPriorWindowsStores(current).Count == 1,
        "An installed previous YARP user store must be detected");
    ExpectRejection(() => LegacyStateGuard.RejectUnmigratedWindowsState(current));
    Assert(!Directory.Exists(Path.Combine(current, "data-protection-keys")),
        "Rejected startup must not create new key-ring");
    Assert(!File.Exists(Path.Combine(current, "admin-users.json")),
        "Rejected startup must not create a new administrator");
    Assert(File.ReadAllBytes(previousUsers).SequenceEqual(existingBytes),
        "Detection must preserve previous user database verbatim");

    File.WriteAllText(Path.Combine(current, "admin-users.json"), "[{\"Username\":\"new-admin\"}]");
    LegacyStateGuard.RejectUnmigratedWindowsState(current); // pre-existing neutral test lab
    Assert(File.ReadAllBytes(previousUsers).SequenceEqual(existingBytes),
        "An initialized test lab must not erase its retained rollback store");

    File.Delete(Path.Combine(current, "admin-users.json"));
    File.Delete(previousUsers);
    Directory.CreateDirectory(Path.Combine(previous, "data-protection-keys"));
    ExpectRejection(() => LegacyStateGuard.RejectUnmigratedWindowsState(current));
    Directory.Delete(Path.Combine(previous, "data-protection-keys"));

    var unrelated = Path.Combine(root, "UnrelatedApplication", "ControlPlane");
    Directory.CreateDirectory(unrelated);
    File.WriteAllText(Path.Combine(unrelated, "admin-users.json"), "[]");
    LegacyStateGuard.RejectUnmigratedWindowsState(current);

    Console.WriteLine("PASS: legacy YARP state is detected before bootstrap; old users/keys preserved; initialized neutral lab still starts.");
}
finally
{
    if (Directory.Exists(root)) Directory.Delete(root, true);
}

static void Assert(bool condition, string description)
{
    if (!condition) throw new Exception(description);
}

static void ExpectRejection(Action action)
{
    try { action(); }
    catch (InvalidOperationException ex) when (
        ex.Message.Contains("Previous YARP control-plane state detected", StringComparison.Ordinal))
    { return; }
    throw new Exception("Expected explicit fail-closed migration rejection");
}
