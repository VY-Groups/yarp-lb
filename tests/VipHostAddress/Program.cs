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
