using System.Text.Json.Nodes;
internal static class ServiceGroupCatalogTests
{
    public static void Run()
    {
        static void Check(bool ok, string label)
        {
            if (!ok) throw new Exception("Service group: " + label);
            Console.WriteLine("PASS: " + label);
        }
        var current = JsonNode.Parse("""
        {"AdminRealServers":{"app-01":{},"app-02":{}},"AdminMonitorProfiles":{"health":{}}}
        """)!.AsObject();
        var payload = JsonNode.Parse("""
        {"serviceGroups":{"apps":{"Policy":"PrimaryBackup","MonitorProfile":"health","Members":{"app-01":{"Weight":"10","TrafficRole":"primary"},"app-02":{"Weight":"1","TrafficRole":"backup"}}}}}
        """)!.AsObject();
        Check(ServiceGroupCatalog.Validate(payload,current) is null,"valid group references existing catalog");
        var group=payload["serviceGroups"]!["apps"]!.AsObject();
        group["Members"]!["app-01"]!["TrafficRole"]="backup";
        Check(ServiceGroupCatalog.Validate(payload,current) is not null,"reject missing primary");
        group["Members"]!["app-01"]!["TrafficRole"]="primary";
        group["MonitorProfile"]="";
        Check(ServiceGroupCatalog.Validate(payload,current) is not null,"reject missing PrimaryBackup monitor");
        group["MonitorProfile"]="health";
        group["Members"]!["app-01"]!["Weight"]="101";
        Check(ServiceGroupCatalog.Validate(payload,current) is not null,"reject invalid weight");
        group["Members"]!["app-01"]!["Weight"]="10";
        current["AdminServiceGroups"]=payload["serviceGroups"]!.DeepClone();
        Check(ServiceGroupCatalog.Validate(new JsonObject(),current) is null,"legacy draft preserves group");
        Check(ServiceGroupCatalog.Validate(new JsonObject { ["realServers"]=new JsonObject() },current) is not null,"reject referenced server deletion");
        Check(ServiceGroupCatalog.Validate(new JsonObject { ["monitorProfiles"]=new JsonObject() },current) is not null,"reject referenced monitor deletion");
        Check(ServiceGroupCatalog.Validate(new JsonObject { ["serviceGroups"]=new JsonObject(),["realServers"]=new JsonObject() },current) is null,"atomic removal allowed");
        var linked = JsonNode.Parse("""
        {"realServers":{"app":{"Address":"https://app.invalid/","Description":""}},
         "serviceGroups":{"web":{"Policy":"RoundRobin","MonitorProfile":"","Members":{"app":{"Weight":"3","TrafficRole":"primary"}}}}}
        """)!.AsObject();
        var clusters = JsonNode.Parse("""
        {"pool":{"LoadBalancingPolicy":"RoundRobin","Metadata":{"ADC.ServiceGroupTemplate":"web"},
          "Destinations":{"app":{"Address":"https://app.invalid/","Metadata":{"Weight":"3","TrafficRole":"primary","TrafficState":"draining"}}}}}
        """)!.AsObject();
        var disabled = new JsonObject();
        Check(ServiceGroupCatalog.ValidateLinked(clusters,disabled,linked,new()) is null,"linked snapshot matches catalog");
        linked["realServers"]!["app"]!["Address"]="https://changed.invalid/";
        Check(ServiceGroupCatalog.ValidateLinked(clusters,disabled,linked,new()) is not null,"reject stale linked origin");
        clusters["pool"]!["Destinations"]!["app"]!["Address"]="https://changed.invalid/";
        Check(ServiceGroupCatalog.ValidateLinked(clusters,disabled,linked,new()) is null,"explicit same-draft synchronization accepted");
        disabled["pool::app"]=clusters["pool"]!["Destinations"]!["app"]!.DeepClone();
        Check(ServiceGroupCatalog.ValidateLinked(clusters,disabled,linked,new()) is not null,"reject duplicate enabled and disabled member");
        clusters["pool"]!["Destinations"]!.AsObject().Remove("app");
        Check(ServiceGroupCatalog.ValidateLinked(clusters,disabled,linked,new()) is null,"disabled member retains catalog identity");
        linked["serviceGroups"]=new JsonObject();
        Check(ServiceGroupCatalog.ValidateLinked(clusters,disabled,linked,new()) is not null,"reject deletion of linked template");
        clusters["pool"]!["Metadata"]!.AsObject().Remove(ServiceGroupCatalog.LinkKey);
        Check(ServiceGroupCatalog.ValidateLinked(clusters,disabled,linked,new()) is null,"explicit unlink preserves independent materialization");
    }
}
