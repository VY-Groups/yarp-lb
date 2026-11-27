using System.Net.NetworkInformation;
static void Must(bool ok,string label){if(!ok)throw new Exception(label);Console.WriteLine("PASS: "+label);}
static void Refused(Action work){try{work();}catch(InvalidDataException){return;}throw new Exception("Expected refusal");}
var steps=new List<string>();
Task Step(string name,CancellationToken token){steps.Add(name);return Task.CompletedTask;}
Task<bool> Owned(long epoch,CancellationToken token){steps.Add("owner");return Task.FromResult(epoch==5);}
Task<bool> Health(CancellationToken token){steps.Add("health");return Task.FromResult(true);}
await VipNodeLifecycle.Activate(5,Owned,t=>Step("reconcile",t),t=>Step("start",t),Health,
    t=>Step("stop",t),t=>Step("withdraw",t),default);
Must(steps.SequenceEqual(new[]{"owner","reconcile","owner","start","owner","health","owner"}),
    "node startup checks exact ownership around every activation stage");
steps.Clear();
try
{
    await VipNodeLifecycle.Activate(4,Owned,t=>Step("reconcile",t),t=>Step("start",t),Health,
        t=>Step("stop",t),t=>Step("withdraw",t),default);
    throw new Exception("Stale activation accepted");
}
catch(InvalidDataException){}
Must(steps.SequenceEqual(new[]{"owner"}),"stale activation causes no service or address mutation");
steps.Clear();
try
{
    await VipNodeLifecycle.Activate(5,Owned,t=>Step("reconcile",t),t=>Step("start",t),_=>Task.FromResult(false),
        t=>Step("stop",t),t=>Step("withdraw",t),default);
    throw new Exception("Failed application health accepted");
}
catch(InvalidOperationException){}
Must(steps.TakeLast(2).SequenceEqual(new[]{"stop","withdraw"}),"failed real health compensates service then address");
steps.Clear();
try
{
    await VipNodeLifecycle.StopAndWithdraw(_=>throw new InvalidOperationException("stop failed"),t=>Step("withdraw",t),default);
    throw new Exception("Unconfirmed stop accepted");
}
catch(InvalidOperationException){}
Must(steps.SequenceEqual(new[]{"withdraw"}),"withdrawal still attempted after failed service stop");
var dir=Directory.CreateTempSubdirectory("gc-vip-journal-");
try
{
    var path=Path.Combine(dir.FullName,"state");
    using(var j=new VipAddressJournal(path,"scope","nic","192.0.2.10"))
    {
        Refused(()=>j.Append(1,"assigned"));
        j.Append(1,"assign-intent");
    }
    using(var j=new VipAddressJournal(path,"scope","nic","192.0.2.10"))
    {
        Must(j.Last?.Phase=="assign-intent","durable uncertain intent survives restart");
        Refused(()=>j.Append(1,"withdraw-intent"));
        j.Append(1,"assigned");j.Append(1,"withdraw-intent");j.Append(1,"withdrawn");
        Refused(()=>j.Append(1,"assign-intent"));
        j.Append(2,"assign-intent");j.Append(2,"assigned");
    }
    Refused(()=>{using var j=new VipAddressJournal(path,"scope","other","192.0.2.10");});
    using(var reader=new VipAddressJournal(path,"scope","nic","192.0.2.10",readOnly:true))
        Must(reader.Last?.Epoch==2&&reader.Last.Phase=="assigned","read-only runtime journal binding");
    var recoveryPath=Path.Combine(dir.FullName,"recovery");
    using(var j=new VipAddressJournal(recoveryPath,"scope","nic","192.0.2.10"))
    {
        bool present=false,owner=true;long observedEpoch=10;
        VipHostAddressPlatform.Observation Inspect()=>new("nic","eth0",2,present,present);
        Task Change(VipHostAddressPlatform.Observation before,bool add,CancellationToken t)
        {if(before.Present==add)throw new Exception("unexpected mutation");present=add;return Task.CompletedTask;}
        Task<bool> Owner(long e,CancellationToken t)=>Task.FromResult(owner&&e==observedEpoch);
        await VipLocalReconcile.Run(j,10,true,Inspect,Change,Owner,default);
        Must(present&&j.Last?.Epoch==10&&j.Last.Phase=="assigned","new owner reconciles address");
        await VipLocalReconcile.Run(j,10,true,Inspect,Change,Owner,default);
        present=false;
        await VipLocalReconcile.Run(j,10,true,Inspect,Change,Owner,default);
        Must(present&&j.Last?.Phase=="assigned","same owner recovers absent address after restart");
        owner=false;observedEpoch=11;
        await VipLocalReconcile.Run(j,11,false,Inspect,Change,Owner,default);
        Must(!present&&j.Last?.Phase=="withdrawn","revoked owner withdraws");
        owner=true;observedEpoch=12;
        await VipLocalReconcile.Run(j,12,true,Inspect,Change,Owner,default);
        Must(present&&j.Last?.Epoch==12,"newer failback epoch reconciles");
        try{await VipLocalReconcile.Run(j,10,true,Inspect,Change,Owner,default);throw new Exception("stale revision accepted");}
        catch(InvalidDataException){}
        Must(present&&j.Last?.Epoch==12,"stale revision leaves current address intact");
    }
    File.AppendAllText(path,"partial");
    Refused(()=>{using var j=new VipAddressJournal(path,"scope","nic","192.0.2.10");});
    Refused(()=>VipHostAddressPlatform.Parse("127.0.0.1"));
    Refused(()=>VipHostAddressPlatform.Parse("224.0.0.1"));
    Refused(()=>VipHostAddressPlatform.Parse("::1"));
    Must(VipHostAddressPlatform.Parse("192.0.2.10").ToString()=="192.0.2.10","canonical address contract");
    Refused(()=>VipHostAddressPlatform.Parse("fe80::1"));
    Refused(()=>VipHostAddressPlatform.Parse("ff02::1"));
    Refused(()=>VipHostAddressPlatform.Parse("::ffff:192.0.2.10"));
    Refused(()=>VipHostAddressPlatform.Parse("2001:db8::1%3"));
    var v6=VipHostAddressPlatform.Parse("2001:db8::10");
    Must(v6.ToString()=="2001:db8::10","canonical IPv6 contract");
    var kernel="20010db8000000000000000000000010 02 80 00 ";
    Must(VipIpv6Readiness.LinuxReady(kernel+"80 gc-vip0",v6,2,"gc-vip0"),"preferred IPv6");
    foreach(var flags in new[]{"40","08","20","04"})
        Must(!VipIpv6Readiness.LinuxReady(kernel+flags+" gc-vip0",v6,2,"gc-vip0"),"non-ready IPv6 flags "+flags);
    Must(!VipIpv6Readiness.LinuxReady(null,v6,2,"gc-vip0"),"missing readiness denied");
    Must(!VipIpv6Readiness.LinuxReady(kernel+"80 gc-vip0",v6,3,"gc-vip0"),"wrong index denied");
    if(args.Length==2 && args[0]=="--isolated-windows-adapter")
    {
        if(!OperatingSystem.IsWindows()||Environment.GetEnvironmentVariable("GITHUB_ACTIONS")!="true"||
            Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT")!="github-hosted"||!Guid.TryParse(args[1],out var guid))
            throw new InvalidOperationException("Disposable hosted Windows CI only.");
        var nic=NetworkInterface.GetAllNetworkInterfaces().Single(n=>Guid.TryParse(n.Id,out var id)&&id==guid);
        foreach(var ip in new[]{VipHostAddressPlatform.Parse("192.0.2.10"),v6})
        {
            var before=VipHostAddressPlatform.Inspect(nic.Id,ip);
            Must(!before.Present,"exact disposable adapter starts without "+ip);
            try
            {
                using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(30));
                await VipHostAddressPlatform.Change(before,ip,true,deadline.Token);
                var assigned=VipHostAddressPlatform.Inspect(nic.Id,ip);
                Must(assigned.Present&&assigned.Ready,"real Windows exact-prefix address assigned and ready: "+ip);
                // Bind the actual address and exchange data over a local TCP
                // connection rather than treating inventory as traffic evidence.
                using var listener=new System.Net.Sockets.TcpListener(ip,0);
                // Windows may briefly report Preferred before Winsock can bind.
                // Retry only WSAEADDRNOTAVAIL, with exact identity and readiness
                // rechecked; no wildcard bind or skipped traffic assertion.
                for(int attempt=0;;attempt++)
                {
                    deadline.Token.ThrowIfCancellationRequested();
                    try {listener.Start();break;}
                    catch(System.Net.Sockets.SocketException e) when(
                        e.SocketErrorCode==System.Net.Sockets.SocketError.AddressNotAvailable && attempt<19)
                    {
                        var retry=VipHostAddressPlatform.Inspect(nic.Id,ip);
                        if(!retry.Ready||retry.Index!=assigned.Index||retry.Name!=assigned.Name)throw;
                        await Task.Delay(250,deadline.Token);
                    }
                }
                // SkipAsSource intentionally prevents implicit source selection. Bind the
                // local smoke-test client to the exact VIP rather than an unrelated NIC.
                using var client=new System.Net.Sockets.TcpClient(new System.Net.IPEndPoint(ip,0));
                var endpoint=(System.Net.IPEndPoint)listener.LocalEndpoint;
                await client.ConnectAsync(ip,endpoint.Port,deadline.Token);
                using var accepted=await listener.AcceptTcpClientAsync(deadline.Token);
                var sent=new byte[]{0x47,0x43};
                await client.GetStream().WriteAsync(sent,deadline.Token);
                var received=new byte[sent.Length];
                await accepted.GetStream().ReadExactlyAsync(received,deadline.Token);
                Must(received.SequenceEqual(sent)&&((System.Net.IPEndPoint)accepted.Client.LocalEndPoint!).Address.Equals(ip),
                    "real Windows local TCP exchange uses exact assigned VIP: "+ip);
            }
            finally
            {
                var current=VipHostAddressPlatform.Inspect(nic.Id,ip);
                if(current.Present)
                {
                    using var cleanup=new CancellationTokenSource(TimeSpan.FromSeconds(30));
                    await VipHostAddressPlatform.Change(current,ip,false,cleanup.Token);
                }
            }
            Must(!VipHostAddressPlatform.Inspect(nic.Id,ip).Present,"real Windows VIP withdrawn: "+ip);
        }
    }
    if(args.Length==1 && args[0]=="--isolated-linux-veth")
    {
        if(!OperatingSystem.IsLinux()||Environment.GetEnvironmentVariable("GITHUB_ACTIONS")!="true")
            throw new InvalidOperationException("Disposable CI only.");
        var nic=NetworkInterface.GetAllNetworkInterfaces().Single(n=>n.Name=="gc-vip0");
        var ip=VipHostAddressPlatform.Parse("192.0.2.10");
        var before=VipHostAddressPlatform.Inspect(nic.Id,ip);
        Must(!before.Present,"fixture starts without VIP");
        using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(20));
        await VipHostAddressPlatform.Change(before,ip,true,deadline.Token);
        try {Must(VipHostAddressPlatform.Inspect(nic.Id,ip).Present,"real kernel /32 assigned");}
        finally {await VipHostAddressPlatform.Change(VipHostAddressPlatform.Inspect(nic.Id,ip),ip,false,deadline.Token);}
        Must(!VipHostAddressPlatform.Inspect(nic.Id,ip).Present,"real kernel /32 withdrawn");
        using var ipv6Deadline=new CancellationTokenSource(TimeSpan.FromSeconds(20));
        await VipHostAddressPlatform.Change(VipHostAddressPlatform.Inspect(nic.Id,v6),v6,true,ipv6Deadline.Token);
        try {Must(VipHostAddressPlatform.Inspect(nic.Id,v6).Ready,"real kernel /128 assigned and DAD ready");}
        finally {await VipHostAddressPlatform.Change(VipHostAddressPlatform.Inspect(nic.Id,v6),v6,false,ipv6Deadline.Token);}
        Must(!VipHostAddressPlatform.Inspect(nic.Id,v6).Present,"real kernel /128 withdrawn");
    }
}
finally{dir.Delete(true);}
