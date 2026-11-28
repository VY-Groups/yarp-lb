internal static class AdcListenerPlanTests
{
    public static void Run()
    {
        static void Reject(Action action, string label)
        {
            try { action(); } catch (InvalidDataException) { Console.WriteLine("PASS: "+label); return; }
            throw new Exception("FAIL: "+label);
        }
        AdcListenerPlan.Entry[] gateway =
        [
            new("gateway-http","127.0.0.1",18080,"HTTP"),
            new("gateway-https","127.0.0.1",18443,"HTTPS3"),
            new("gateway-admin","127.0.0.2",19443,"ADMIN"),
            new("gateway-metrics","127.0.0.2",19444,"METRICS")
        ];
        AdcListenerPlan.Entry[] l4 =
        [
            new("stream","127.0.0.1",19000,"TCP"),
            new("datagram","127.0.0.1",19000,"UDP")
        ];
        var plan=AdcListenerPlan.Create(new(1,[..gateway,..l4]));
        plan.RequireExact(gateway,false);
        plan.RequireExact(l4,true);
        Reject(()=>plan.RequireExact(l4.Take(1),true),"omitted listener rejected");
        Reject(()=>plan.RequireExact([l4[0] with {Port=19001},l4[1]],true),"drift rejected");
        Reject(()=>AdcListenerPlan.Create(new(1,[..gateway,new("collision","127.0.0.1",18080,"TCP")])),"HTTP and TCP collision");
        Reject(()=>AdcListenerPlan.Create(new(1,[..gateway,new("collision","127.0.0.1",18443,"UDP")])),"HTTPS3 reserves UDP");
        Reject(()=>AdcListenerPlan.Create(new(1,[..gateway,new("collision","127.0.0.2",19000,"TCP")])),"management IP protected on all ports");
        Reject(()=>AdcListenerPlan.Create(new(1,[..gateway,new("wild","0.0.0.0",19000,"TCP")])),"wildcard refused");
        Reject(()=>AdcListenerPlan.Create(new(1,[..gateway,new("mapped","::ffff:127.0.0.1",19000,"TCP")])),"mapped address refused");
        Reject(()=>AdcListenerPlan.Create(new(1,[..gateway,new("GATEWAY-HTTP","127.0.0.1",19000,"TCP")])),"case insensitive identity collision");
        VerifyTransactionMode(gateway, l4);
        Console.WriteLine("PASS: unified TCP/UDP distinct transport sharing and exact gateway/L4 binding contract");
    }

    private static void VerifyTransactionMode(AdcListenerPlan.Entry[] gateway, AdcListenerPlan.Entry[] l4)
    {
        static void Check(bool result, string label)
        {
            if (!result) throw new Exception("FAIL: " + label);
            Console.WriteLine("PASS: " + label);
        }
        var previous = Environment.GetEnvironmentVariable(AdcListenerPlan.EnvironmentKey);
        var path = Path.Combine(Path.GetTempPath(), "adc-plan-" + Guid.NewGuid().ToString("N") + ".json");
        var bytes = System.Text.Encoding.UTF8.GetBytes("""
            {"Tcp":[{"Name":"stream","ListenHost":"127.0.0.1","ListenPort":19000}],
             "Udp":[{"Name":"datagram","ListenHost":"127.0.0.1","ListenPort":19000}]}
            """);
        void WritePlan(AdcListenerPlan.Entry[] rows) => File.WriteAllText(path,
            System.Text.Json.JsonSerializer.Serialize(new AdcListenerPlan.Document(1, rows),
                new System.Text.Json.JsonSerializerOptions(System.Text.Json.JsonSerializerDefaults.Web)));
        try
        {
            Environment.SetEnvironmentVariable(AdcListenerPlan.EnvironmentKey, path);
            WritePlan([..gateway,..l4]);
            Check(AdcListenerPlan.AllowsL4(bytes, false, out var enforced) && enforced, "prepare captures enforced plan");
            var persisted = AdcListenerPlan.FormatTransactionSequence(42, enforced);
            Check(AdcListenerPlan.TryReadTransactionSequence(persisted, true, out var sequence, out var required)
                && sequence == 42 && required, "enforced mode survives transaction reload");
            Environment.SetEnvironmentVariable(AdcListenerPlan.EnvironmentKey, null);
            Check(!AdcListenerPlan.AllowsL4(bytes, required), "enforced transaction rejects absent plan on activate/rollback");
            Check(AdcListenerPlan.AllowsL4(bytes, false, out var legacyEnforced) && !legacyEnforced,
                "legacy preparation remains allowed");
            Check(AdcListenerPlan.TryReadTransactionSequence(AdcListenerPlan.FormatTransactionSequence(43, legacyEnforced),
                true, out sequence, out var legacyRequired) && sequence == 43 && !legacyRequired &&
                AdcListenerPlan.AllowsL4(bytes, legacyRequired), "explicit legacy mode survives reload without plan");
            Environment.SetEnvironmentVariable(AdcListenerPlan.EnvironmentKey, path);
            Check(AdcListenerPlan.AllowsL4(bytes, required) && AdcListenerPlan.AllowsL4(bytes, legacyRequired),
                "compatible restored or newly configured plan allowed");
            WritePlan([..gateway,l4[0] with {Port=19001},l4[1]]);
            Check(!AdcListenerPlan.AllowsL4(bytes, required) && !AdcListenerPlan.AllowsL4(bytes, legacyRequired),
                "incompatible current plan rejected in both modes");
            File.WriteAllText(path, "invalid JSON");
            Check(!AdcListenerPlan.AllowsL4(bytes, required), "invalid plan rejected");
            File.Delete(path);
            Check(!AdcListenerPlan.AllowsL4(bytes, required), "configured but missing file rejected");
            Check(!AdcListenerPlan.TryReadTransactionSequence("42", true, out _, out _) &&
                !AdcListenerPlan.TryReadTransactionSequence("42:unknown", true, out _, out _) &&
                !AdcListenerPlan.TryReadTransactionSequence("", true, out _, out _),
                "missing or corrupt L4 transaction mode rejected");
            Check(AdcListenerPlan.TryReadTransactionSequence("42", false, out sequence, out _) && sequence == 42,
                "non-L4 sequence format unchanged");
        }
        finally
        {
            Environment.SetEnvironmentVariable(AdcListenerPlan.EnvironmentKey, previous);
            File.Delete(path);
        }
    }
}
