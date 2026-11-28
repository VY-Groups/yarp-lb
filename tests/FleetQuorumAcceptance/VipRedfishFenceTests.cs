using System.Net;
using System.Text.Json;
using System.Text;

internal static class VipRedfishFenceTests
{
    private sealed class Bmc:HttpMessageHandler
    {
        internal readonly Guid Id=Guid.NewGuid();
        internal string Power="On",Policy="AlwaysOff";
        internal bool CanOff=true,CanOn=true,Stuck=false;
        internal int Posts;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken token)
        {
            if(request.Method==HttpMethod.Post)
            {
                if(request.RequestUri!.AbsolutePath!="/redfish/v1/Systems/1/Actions/ComputerSystem.Reset")
                    throw new Exception("Wrong BMC action.");
                using var payload=JsonDocument.Parse(await request.Content!.ReadAsStringAsync(token));
                var operation=payload.RootElement.GetProperty("ResetType").GetString();
                if(operation is not ("ForceOff" or "On"))throw new Exception("Wrong power action.");
                Posts++;if(!Stuck)Power=operation=="On"?"On":"Off";
                return new(HttpStatusCode.Accepted);
            }
            if(request.RequestUri!.AbsolutePath!="/redfish/v1/Systems/1")throw new Exception("Wrong BMC system.");
            var body=new Dictionary<string,object>{
                ["@odata.id"]="/redfish/v1/Systems/1",["UUID"]=Id.ToString(),["PowerState"]=Power,
                ["PowerRestorePolicy"]=Policy,["Actions"]=new Dictionary<string,object>{
                    ["#ComputerSystem.Reset"]=new Dictionary<string,object>{
                        ["target"]="/redfish/v1/Systems/1/Actions/ComputerSystem.Reset",
                        ["ResetType@Redfish.AllowableValues"]=(CanOff?new[]{"ForceOff"}:new[]{"GracefulShutdown"}).Concat(CanOn?new[]{"On"}:Array.Empty<string>()).ToArray()
                    }}};
            return new(HttpStatusCode.OK){Content=new StringContent(JsonSerializer.Serialize(body),Encoding.UTF8,"application/json")};
        }
    }
    internal static async Task Run()
    {
        async Task Refuse(Func<Task> action)
        {try{await action();throw new Exception("Unsafe fencing accepted.");}catch(InvalidDataException){}}
        var uri=new Uri("https://bmc.example.invalid/redfish/v1/Systems/1");
        var bmc=new Bmc();
        int checks=0;
        Task Assert(CancellationToken t){checks++;return Task.CompletedTask;}
        using var fence=new VipRedfishFence(new HttpClient(bmc),uri,bmc.Id);
        await fence.ConfirmOff(Assert,default);
        if(bmc.Power!="Off"||bmc.Posts!=1||checks<3)throw new Exception("Fence not independently confirmed.");
        await fence.ConfirmOff(Assert,default);
        if(bmc.Posts!=1)throw new Exception("Already off caused another mutation.");
        bmc.Power="On";bmc.Policy="AlwaysOn";
        await Refuse(()=>fence.ConfirmOff(Assert,default));
        bmc.Policy="AlwaysOff";bmc.CanOff=false;
        await Refuse(()=>fence.ConfirmOff(Assert,default));
        bmc.CanOff=true;
        await Refuse(()=>fence.ConfirmOff(_=>throw new InvalidDataException("Wrong quorum revision."),default));
        using(var wrong=new VipRedfishFence(new HttpClient(bmc,false),uri,Guid.NewGuid()))
            await Refuse(()=>wrong.ConfirmOff(Assert,default));
        if(bmc.Posts!=1)throw new Exception("Unsafe BMC request issued.");
        bmc.Stuck=true;
        using var deadline=new CancellationTokenSource(TimeSpan.FromMilliseconds(200));
        try{await fence.ConfirmOff(Assert,deadline.Token);throw new Exception("False power-off acknowledgement accepted.");}
        catch(OperationCanceledException){}
        if(bmc.Posts!=2||bmc.Power!="On")throw new Exception("Unexpected unconfirmed BMC state.");
        bmc.Stuck=false;bmc.Power="Off";bmc.CanOn=false;
        await Refuse(()=>fence.ConfirmOn(Assert,default));
        bmc.CanOn=true;
        await Refuse(()=>fence.ConfirmOn(_=>throw new InvalidDataException("Wrong owner epoch."),default));
        if(bmc.Posts!=2)throw new Exception("Unsafe power-on issued.");
        await fence.ConfirmOn(Assert,default);
        await fence.ConfirmOn(Assert,default);
        if(bmc.Posts!=3||bmc.Power!="On")throw new Exception("Rearm was not idempotent.");
        Console.WriteLine("PASS: Redfish rearm checks owner, advertised action and actual power state; no duplicate power-on.");
        Console.WriteLine("PASS: Redfish exact BMC identity, persistent power policy, real action contract, no blind retry and unconfirmed power-off rejection.");
    }
}
