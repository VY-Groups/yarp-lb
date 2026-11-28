using System.Net.NetworkInformation;
static void Must(bool ok,string label){if(!ok)throw new Exception(label);Console.WriteLine("PASS: "+label);}
static void Refused(Action work){try{work();}catch(InvalidDataException){return;}throw new Exception("Expected refusal");}
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
    File.AppendAllText(path,"partial");
    Refused(()=>{using var j=new VipAddressJournal(path,"scope","nic","192.0.2.10");});
    Refused(()=>VipHostAddressPlatform.Parse("127.0.0.1"));
    Refused(()=>VipHostAddressPlatform.Parse("224.0.0.1"));
    Refused(()=>VipHostAddressPlatform.Parse("::1"));
    Must(VipHostAddressPlatform.Parse("192.0.2.10").ToString()=="192.0.2.10","canonical address contract");
    if(args.Length==2 && args[0]=="--isolated-windows-adapter")
    {
        if(!OperatingSystem.IsWindows()||Environment.GetEnvironmentVariable("GITHUB_ACTIONS")!="true"||
            Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT")!="github-hosted"||!Guid.TryParse(args[1],out var guid))
            throw new InvalidOperationException("Disposable hosted Windows CI only.");
        var nic=NetworkInterface.GetAllNetworkInterfaces().Single(n=>Guid.TryParse(n.Id,out var id)&&id==guid);
        foreach(var ip in new[]{VipHostAddressPlatform.Parse("192.0.2.10")})
        {
            bool Ready()=>NetworkInterface.GetAllNetworkInterfaces().Single(n=>n.Id==nic.Id)
                .GetIPProperties().UnicastAddresses.Any(entry=>entry.Address.Equals(ip)&&
                    entry.DuplicateAddressDetectionState==DuplicateAddressDetectionState.Preferred);
            var before=VipHostAddressPlatform.Inspect(nic.Id,ip);
            Must(!before.Present,"exact disposable adapter starts without "+ip);
            try
            {
                using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(30));
                await VipHostAddressPlatform.Change(before,ip,true,deadline.Token);
                var assigned=VipHostAddressPlatform.Inspect(nic.Id,ip);
                for(int attempt=0;attempt<20&&!Ready();attempt++)
                    await Task.Delay(250,deadline.Token);
                Must(assigned.Present&&Ready(),"real Windows exact-prefix address assigned and ready: "+ip);
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
                        if(!Ready()||retry.Index!=assigned.Index||retry.Name!=assigned.Name)throw;
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
    }
}
finally{dir.Delete(true);}
