public static class RiseFallTests
{
    public static void Run()
    {
        static void Eq(bool observed, bool wanted, string name)
        {
            if (observed != wanted) throw new Exception("FAIL: " + name);
            Console.WriteLine("PASS: " + name);
        }
        var counter = new RiseFallCounter(2, 3);
        Eq(counter.Observe(true), false, "first rise probe stays down");
        Eq(counter.Observe(true), true, "second rise probe marks healthy");
        Eq(counter.Observe(false), true, "first failure retains healthy");
        Eq(counter.Observe(false), true, "second failure retains healthy");
        Eq(counter.Observe(true), true, "success resets fall streak");
        Eq(counter.Observe(false), true, "failure streak restarted");
        Eq(counter.Observe(false), true, "second consecutive failure");
        Eq(counter.Observe(false), false, "third consecutive failure marks down");
        Eq(counter.Observe(true), false, "first recovery probe does not recover");
        Eq(counter.Observe(false), false, "interleaved failure resets rise streak");
        Eq(counter.Observe(true), false, "new first recovery probe");
        Eq(counter.Observe(true), true, "second consecutive recovery probe");
        counter.Configure(3, 2);
        Eq(counter.Healthy, false, "changed policy fails closed");
        Eq(counter.Observe(true), false, "new threshold first probe");
        Eq(counter.Observe(true), false, "new threshold second probe");
        Eq(counter.Observe(true), true, "new threshold third probe");
        foreach(var bad in new[] {0,11,-1})
        {
            var rejected = false;
            try { counter.Configure(bad,2); } catch(ArgumentOutOfRangeException) { rejected=true; }
            Eq(rejected,true,"bad rise rejected");
        }
    }
}
