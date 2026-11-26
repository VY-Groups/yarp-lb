using System.Text.Json.Nodes;
internal static class SecureAffinityContractTests
{
    public static void Run()
    {
        static void Check(bool ok, string label)
        {
            if (!ok) throw new Exception("Secure affinity: " + label);
            Console.WriteLine("PASS: " + label);
        }
        var clusters = JsonNode.Parse("""
        {"app":{"Metadata":{"ADC.Persistence.Profile":"SecureCookie"},"SessionAffinity":{"Enabled":true,"Policy":"Cookie","FailurePolicy":"Redistribute","AffinityKeyName":"__Host-GatewayCore-app","Cookie":{"Path":"/","HttpOnly":true,"SecurePolicy":"Always","SameSite":"Lax","MaxAge":"00:30:00"}}}}
        """)!.AsObject();
        Check(SecureAffinityContract.Validate(clusters) is null, "valid encrypted HTTPS cookie profile");
        var cookie=clusters["app"]!["SessionAffinity"]!["Cookie"]!.AsObject();
        cookie["SecurePolicy"]="None";
        Check(SecureAffinityContract.Validate(clusters) is not null,"reject insecure cookie");
        cookie["SecurePolicy"]="Always";
        cookie["Domain"]="example.invalid";
        Check(SecureAffinityContract.Validate(clusters) is not null,"reject domain cookie");
        cookie.Remove("Domain");
        cookie["MaxAge"]="2.00:00:00";
        Check(SecureAffinityContract.Validate(clusters) is not null,"reject excessive browser lifetime");
        cookie["MaxAge"]="00:30:00";
        clusters["app"]!["Metadata"]!.AsObject().Clear();
        Check(SecureAffinityContract.Validate(clusters) is not null,"reserved namespace cannot bypass validation");
        clusters["app"]!["SessionAffinity"]!["AffinityKeyName"]="legacy";
        Check(SecureAffinityContract.Validate(clusters) is null,"legacy configuration unchanged");
    }
}
