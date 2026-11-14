using System.Text.Json;

static void Check(bool ok,string description)
{
    if (!ok) throw new Exception("FAIL: "+description);
    Console.WriteLine("PASS: "+description);
}
var keys=new[] {
    "GITHUB_ACTIONS","CI","YARP_EC2_LAB_MODE","YARP_EC2_LAB_ALLOW_INSECURE_BACKEND_TLS",
    "YARP_EC2_LAB_TLS_RISK_ACK","YARP_EC2_LAB_PRIVATE_DIR","ASPNETCORE_URLS",
    "BACKEND_A_HOST","BACKEND_B_HOST"
};
var original=keys.ToDictionary(k=>k,k=>Environment.GetEnvironmentVariable(k));
var current=Directory.GetCurrentDirectory();
var dir=Path.Combine(Path.GetTempPath(),"ec2-guard-"+Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(dir);
try
{
    Directory.SetCurrentDirectory(dir);
    void Set(string name,string? value) => Environment.SetEnvironmentVariable(name,value);
    Set("GITHUB_ACTIONS","true");
    Set("CI","true");
    Set("YARP_EC2_LAB_MODE","1");
    Set("ASPNETCORE_URLS","http://127.0.0.1:18088");
    Set("BACKEND_A_HOST",Ec2WorkflowLab.HostA);
    Set("BACKEND_B_HOST",Ec2WorkflowLab.HostB);
    Set("YARP_EC2_LAB_PRIVATE_DIR",Path.Combine(dir,"private"));
    Ec2WorkflowLab.RequireIsolatedRunner();
    Check(Ec2WorkflowLab.PrivateDirectory()==Path.Combine(dir,"private"),
        "explicit private workspace is accepted for isolated loopback CI");
    Set("YARP_EC2_LAB_MODE",null);
    var blocked=false;
    try { Ec2WorkflowLab.RequireIsolatedRunner(); }
    catch (InvalidOperationException) { blocked=true; }
    Check(blocked,"cannot activate lab mode outside explicit enable");
    Set("YARP_EC2_LAB_MODE","1");
    Set("ASPNETCORE_URLS","http://0.0.0.0:18088");
    blocked=false;
    try { Ec2WorkflowLab.RequireIsolatedRunner(); }
    catch (InvalidOperationException) {blocked=true;}
    Check(blocked,"cannot expose lab mode on public wildcard listener");
    Set("ASPNETCORE_URLS","http://127.0.0.1:18088");
    Set("BACKEND_B_HOST","example.org");
    blocked=false;
    try { Ec2WorkflowLab.RequireIsolatedRunner(); }
    catch (InvalidOperationException) {blocked=true;}
    Check(blocked,"cannot redirect lab to a non-allowlisted EC2 backend");
    Set("BACKEND_B_HOST",Ec2WorkflowLab.HostB);
    Check(!Ec2WorkflowLab.RelaxedBackendTls(),"upstream TLS verification ON by default");

    Set("YARP_EC2_LAB_ALLOW_INSECURE_BACKEND_TLS","1");
    blocked=false;
    try { Ec2WorkflowLab.RelaxedBackendTls(); }
    catch (InvalidOperationException) {blocked=true;}
    Check(blocked,"TLS bypass requires a separate explicit risk acknowledgment");
    Set("YARP_EC2_LAB_TLS_RISK_ACK","1");
    void Config(string a,string b)
    {
        File.WriteAllText("appsettings.json", JsonSerializer.Serialize(new {
            ReverseProxy = new {
                Clusters=new Dictionary<string,object> {
                    ["ec2"]= new {
                        Destinations=new Dictionary<string,object> {
                            ["A"]=new {Address=a},
                            ["B"]=new {Address=b}
                        }
                    }
                }
            }
        }));
    }
    Config("https://"+Ec2WorkflowLab.HostA+"/","https://"+Ec2WorkflowLab.HostB+"/");
    Check(Ec2WorkflowLab.RelaxedBackendTls(),
        "explicit ack + GitHub runner + exactly two known EC2 HTTPS roots accepted");
    Config("https://example.org/","https://"+Ec2WorkflowLab.HostB+"/");
    blocked=false;
    try {Ec2WorkflowLab.RelaxedBackendTls();}
    catch (InvalidOperationException) {blocked=true;}
    Check(blocked,"test-only TLS bypass refuses any arbitrary destination");
    Config("https://"+Ec2WorkflowLab.HostA+"/","http://"+Ec2WorkflowLab.HostB+"/");
    blocked=false;
    try {Ec2WorkflowLab.RelaxedBackendTls();}
    catch (InvalidOperationException) {blocked=true;}
    Check(blocked,"test-only TLS bypass refuses HTTP/mixed-scheme config");
    Console.WriteLine("EC2 LAB SAFETY CONTRACT PASSED");
}
finally
{
    Directory.SetCurrentDirectory(current);
    foreach (var (k,v) in original) Environment.SetEnvironmentVariable(k,v);
    Directory.Delete(dir,recursive:true);
}
