using Yarp.ReverseProxy.Health;

/// <summary>
/// The autonomous recovery observer may restart a ramp only for a destination
/// confirmed healthy by active probes and NOT passively ejected or draining.
/// Unknown active health is not affirmative recovery evidence.
/// </summary>
public static class RecoveryHealthGate
{
    public static bool Eligible(DestinationHealth active, DestinationHealth passive, bool draining) =>
        !draining && active == DestinationHealth.Healthy && passive != DestinationHealth.Unhealthy;
}
