public static class RecoveryHealthGateTests
{
    public static void Run()
    {
        static void Check(bool actual, bool expected, string name)
        {
            if (actual != expected) throw new Exception("FAIL: " + name);
            Console.WriteLine("PASS: " + name);
        }

        Check(RecoveryHealthGate.Eligible(true, false, false),
            true, "affirmative active health and non-ejected destination permits recovery");
        Check(RecoveryHealthGate.Eligible(true, true, false),
            false, "passive ejection blocks false active-only recovery");
        Check(RecoveryHealthGate.Eligible(false, false, false),
            false, "unhealthy or unknown active health blocks recovery");
        Check(RecoveryHealthGate.Eligible(false, true, false),
            false, "two unhealthy signals block recovery");
        Check(RecoveryHealthGate.Eligible(true, false, true),
            false, "draining destination excluded");
        Check(RecoveryHealthGate.Eligible(true, true, true),
            false, "draining and passively ejected destination excluded");
    }
}
