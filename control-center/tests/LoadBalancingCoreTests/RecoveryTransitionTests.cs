public static class RecoveryTransitionTests
{
    public static void Run()
    {
        static void Check(bool actual, bool expected, string scenario)
        {
            if (actual != expected) throw new Exception("FAIL: " + scenario);
            Console.WriteLine("PASS: " + scenario);
        }
        Check(RecoveryTransition.ShouldRestartRamp(false,true,30,30),true,"first eligible edge");
        Check(RecoveryTransition.ShouldRestartRamp(true,true,30,30),false,"steady healthy does not reset ramp");
        Check(RecoveryTransition.ShouldRestartRamp(true,false,30,30),false,"unhealthy does not start ramp");
        Check(RecoveryTransition.ShouldRestartRamp(false,true,30,30),true,"recovered after observed unhealthy");
        Check(RecoveryTransition.ShouldRestartRamp(true,true,30,60),true,"changed slow-start duration restarts");
        Check(RecoveryTransition.ShouldRestartRamp(false,true,0,0),false,"disabled slow-start skips");
        Check(RecoveryTransition.ShouldRestartRamp(true,true,30,0),false,"turn off slow-start");
        Check(RecoveryTransition.ShouldRestartRamp(false,true,0,30),true,"enabling warmup triggers ramp");
    }
}
