using Yarp.ReverseProxy.Health;

public static class RecoveryHealthGateTests
{
    public static void Run()
    {
        static void Check(bool actual, bool expected, string name)
        {
            if (actual != expected) throw new Exception("FAIL: " + name);
            Console.WriteLine("PASS: " + name);
        }

        Check(RecoveryHealthGate.Eligible(DestinationHealth.Healthy, DestinationHealth.Unknown, false),
            true, "healthy active + passive unknown permits recovery");
        Check(RecoveryHealthGate.Eligible(DestinationHealth.Healthy, DestinationHealth.Healthy, false),
            true, "healthy active + passive healthy permits recovery");
        Check(RecoveryHealthGate.Eligible(DestinationHealth.Healthy, DestinationHealth.Unhealthy, false),
            false, "passive ejection blocks false active-only recovery");
        Check(RecoveryHealthGate.Eligible(DestinationHealth.Unhealthy, DestinationHealth.Healthy, false),
            false, "unhealthy active blocks recovery");
        Check(RecoveryHealthGate.Eligible(DestinationHealth.Unknown, DestinationHealth.Healthy, false),
            false, "unknown active does not qualify as a good probe");
        Check(RecoveryHealthGate.Eligible(DestinationHealth.Healthy, DestinationHealth.Healthy, true),
            false, "draining backend excluded");
    }
}
