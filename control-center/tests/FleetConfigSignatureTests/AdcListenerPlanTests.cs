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
        Console.WriteLine("PASS: unified TCP/UDP distinct transport sharing and exact gateway/L4 binding contract");
    }
}
