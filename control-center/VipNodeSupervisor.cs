using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using GatewayCore.Gslb.Contracts;

internal static class VipNodeSupervisor
{
    private sealed record Settings(string Scope,string ServiceId,string ServiceName,string ListenerConfig,
        string ProbePath,string ProbeCaFile,string ProbeLeafSha256,string ProbeBodySha256);
    private static readonly JsonSerializerOptions Json=new(JsonSerializerDefaults.Web)
        {UnmappedMemberHandling=JsonUnmappedMemberHandling.Disallow};
    internal static async Task<int> Run(string[] args,string? requiredScope=null,string? requiredPin=null,
        string? expectedOwner=null,CancellationToken externalToken=default)
    {
        try
        {
            bool inspect=args.Length==3&&args[2]=="inspect";
            long epoch=0;
            if(!inspect&&(args.Length!=4||args[2] is not ("activate" or "stop-withdraw" or "owner-check" or "standby-check")||
                !long.TryParse(args[3],NumberStyles.None,CultureInfo.InvariantCulture,out epoch)||epoch<1))
                throw new InvalidDataException("Usage: --vip-node <private-config> inspect | activate|stop-withdraw <epoch>");
            var config=FleetQuorum.FilePath(args[1],16384,true);
            var directory=Path.GetDirectoryName(config)!;
            if(OperatingSystem.IsLinux())PrivateKeyFileSecurity.ValidateLinuxPrivateStateDirectory(directory,"VIP node supervisor");
            else if(OperatingSystem.IsWindows())WindowsStateProtection.ValidateOfflineKeyRingDirectory(directory);
            else throw new PlatformNotSupportedException();
            using var exclusive=inspect?null:new FileStream(config+".lock",FileMode.OpenOrCreate,FileAccess.ReadWrite,FileShare.None);
            var s=JsonSerializer.Deserialize<Settings>(File.ReadAllBytes(config),Json)??throw new InvalidDataException("Missing supervisor configuration.");
            if(!VipFenceProvider.Pin(s.Scope)||!VipFenceProvider.Pin(s.ProbeLeafSha256)||!VipFenceProvider.Pin(s.ProbeBodySha256)||
                !Regex.IsMatch(s.ServiceName??"",@"\A[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\z")||
                (OperatingSystem.IsLinux()&&!s.ServiceName.EndsWith(".service",StringComparison.Ordinal))||
                (OperatingSystem.IsWindows()&&s.ServiceName!="GatewayCoreYarp")||
                s.ProbePath is not {Length:>1 and <=256}||!s.ProbePath.StartsWith('/')||s.ProbePath.StartsWith("//")||
                s.ProbePath.Any(c=>char.IsControl(c)||c is '\\' or '?' or '#' or '%')||
                s.ProbePath.StartsWith("/admin",StringComparison.OrdinalIgnoreCase)||
                s.ProbePath.StartsWith("/gateway",StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Exact service identity and safe application probe required.");
            var listenerFile=FleetQuorum.FilePath(s.ListenerConfig,65536,true);
            Environment.SetEnvironmentVariable("YARP_LISTENERS_CONFIG_FILE",listenerFile);
            using var listeners=GatewayListenerIsolation.FromEnvironment()??throw new InvalidDataException("Reviewed listener configuration required.");
            var service=listeners.VirtualServices.SingleOrDefault(x=>x.Id==s.ServiceId)
                ??throw new InvalidDataException("Unknown virtual service.");
            if(service.Protocol!="HTTPS"||service.VipJournalDirectory is null||service.VipInterfaceId is null||
                service.VipQuorumConfigPath is null||listeners.VirtualServices.Any(x=>x.Ip!=service.Ip||
                    x.VipJournalDirectory!=service.VipJournalDirectory||x.VipQuorumConfigPath!=service.VipQuorumConfigPath))
                throw new InvalidDataException("Dedicated single-address journal-bound HTTPS gateway required.");
            var address=VipHostAddressPlatform.Parse(service.Ip);
            var management=IPAddress.Parse(listeners.Config.ManagementIp);
            if(FleetQuorum.VipScope(service.VipFleetId!,service.Ip)!=s.Scope)
                throw new InvalidDataException("Supervisor scope mismatch.");
            using var authority=FleetQuorum.OpenVip(service.VipQuorumConfigPath,s.Scope);
            if((requiredScope is not null&&s.Scope!=requiredScope)||(requiredPin is not null&&authority.VipReaderPin!=requiredPin))
                throw new InvalidDataException("Agent and supervisor identity mismatch.");
            using var ca=X509CertificateLoader.LoadCertificateFromFile(FleetQuorum.FilePath(s.ProbeCaFile,65536));
            if(inspect)
            {
                VipServiceSecurity.Quorum(service.VipQuorumConfigPath);
                VipServiceSecurity.Directory(service.VipJournalDirectory);
                // Local interface inspection is read-only and requires the same
                // exact dedicated identity and prefix constraints as activation.
                _=VipHostAddressPlatform.Inspect(service.VipInterfaceId,address,management);
                return 0;
            }
            using var handler=new HttpClientHandler{UseProxy=false,AllowAutoRedirect=false,UseCookies=false};
            byte[] pin=Convert.FromHexString(s.ProbeLeafSha256),bodyHash=Convert.FromHexString(s.ProbeBodySha256);
            handler.ServerCertificateCustomValidationCallback=(_,leaf,_,errors)=>
            {
                if(leaf is null||(errors&(SslPolicyErrors.RemoteCertificateNameMismatch|SslPolicyErrors.RemoteCertificateNotAvailable))!=0||
                    !CryptographicOperations.FixedTimeEquals(SHA256.HashData(leaf.RawData),pin))return false;
                using var chain=new X509Chain();
                chain.ChainPolicy.TrustMode=X509ChainTrustMode.CustomRootTrust;
                chain.ChainPolicy.CustomTrustStore.Add(ca);
                chain.ChainPolicy.RevocationMode=X509RevocationMode.NoCheck;
                chain.ChainPolicy.DisableCertificateDownloads=true;
                chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1"));
                return chain.Build(leaf);
            };
            using var client=new HttpClient(handler){Timeout=TimeSpan.FromSeconds(3),MaxResponseContentBufferSize=16384};
            var uri=new UriBuilder("https",address.ToString(),service.Port,s.ProbePath).Uri;
            string[] AddressArgs(string action)=>["--vip-address",service.VipJournalDirectory,service.Id,service.VipInterfaceId,action];
            bool bindingReady()
            {
                try
                {
                    var binding=new VipJournalBinding(service,management);
                    return binding.Epoch==epoch&&binding.Current();
                }
                catch(Exception e) when(e is IOException or InvalidDataException or InvalidOperationException or UnauthorizedAccessException or JsonException)
                {return false;}
            }
            async Task Reconcile(CancellationToken token)
            {
                token.ThrowIfCancellationRequested();
                if(await VipHostAddressCommand.Run(AddressArgs("reconcile"),epoch,token)!=0||!bindingReady())
                    throw new InvalidOperationException("Local journal reconciliation not confirmed.");
            }
            async Task StopExact(CancellationToken token)
            {
                // Never compensate against a newer local journal, even if a
                // stale activation has timed out while another owner recovered.
                var journalFile=Path.Combine(service.VipJournalDirectory,Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes(address.ToString())))+".journal");
                if(File.Exists(journalFile))
                {
                    using var journal=new VipAddressJournal(journalFile,s.Scope,service.VipInterfaceId,address.ToString(),readOnly:true);
                    if(journal.Last?.Epoch>epoch)throw new InvalidDataException("Newer local owner must not be stopped.");
                }
                await Service(s.ServiceName,false,token);
            }
            async Task Withdraw(CancellationToken token)
            {
                token.ThrowIfCancellationRequested();
                if(await VipHostAddressCommand.Run(AddressArgs("withdraw"),epoch,token)!=0||
                    VipHostAddressPlatform.Inspect(service.VipInterfaceId,address,management).Present)
                    throw new InvalidOperationException("Local withdrawal not confirmed.");
            }
            async Task<bool> Serving(CancellationToken token,int attempts=12)
            {
                for(int i=0;i<attempts;i++)
                {
                    token.ThrowIfCancellationRequested();
                    if(!bindingReady()||!await authority.IsVipOwner(epoch,token))return false;
                    try
                    {
                        using var response=await client.GetAsync(uri,token);
                        if(response.StatusCode==HttpStatusCode.OK&&
                            CryptographicOperations.FixedTimeEquals(SHA256.HashData(await response.Content.ReadAsByteArrayAsync(token)),bodyHash))
                            return true;
                    }
                    catch(HttpRequestException){}
                    catch(OperationCanceledException) when(!token.IsCancellationRequested){}
                    await Task.Delay(500,token);
                }
                return false;
            }
            using var deadline=CancellationTokenSource.CreateLinkedTokenSource(externalToken);
            deadline.CancelAfter(TimeSpan.FromSeconds(90));
            if(expectedOwner is not null&&await authority.ReadVipState(deadline.Token)!=new FleetQuorum.Fence("vip_"+expectedOwner,epoch))
                throw new InvalidDataException("Agent request ownership changed.");
            if(args[2]=="owner-check")
            {
                if(!await authority.IsVipOwner(epoch,deadline.Token))throw new InvalidDataException("Owner check identity mismatch.");
                return await Serving(deadline.Token,1)?0:1;
            }
            if(args[2]=="standby-check")
            {
                if(expectedOwner is null||expectedOwner==authority.VipReaderPin)
                    throw new InvalidDataException("Standby check requires the exact peer owner.");
                var observed=VipHostAddressPlatform.Inspect(service.VipInterfaceId,address,management);
                if(observed.Present)return 1;
                var journalFile=Path.Combine(service.VipJournalDirectory,Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes(address.ToString())))+".journal");
                if(File.Exists(journalFile))
                {
                    using var journal=new VipAddressJournal(journalFile,s.Scope,service.VipInterfaceId,address.ToString(),readOnly:true);
                    if(journal.Last?.Phase is "assign-intent" or "reassign-intent" || (journal.Last?.Epoch??0)>=epoch)return 1;
                }
                await Service(s.ServiceName,false,deadline.Token,checkOnly:true);
                return 0;
            }
            if(args[2]=="activate")
            {
                await VipNodeLifecycle.Activate(epoch,authority.IsVipOwner,Reconcile,
                    token=>Service(s.ServiceName,true,token),token=>Serving(token),
                    StopExact,Withdraw,deadline.Token);
            }
            else
            {
                // Stop/withdraw is only for the same journal epoch; never stop
                // a newer owner in response to a delayed management action.
                var state=await authority.ObserveVipReader(deadline.Token);
                if(state.Epoch<epoch||state.Own&&state.Epoch!=epoch||!bindingReady())
                    throw new InvalidDataException("Local service epoch is not the requested stop epoch.");
                await VipNodeLifecycle.StopAndWithdraw(StopExact,Withdraw,deadline.Token);
            }
            Console.WriteLine(JsonSerializer.Serialize(new {scope=s.Scope,epoch,action=args[2],confirmed=true}));
            return 0;
        }
        catch(Exception error) when(error is IOException or InvalidDataException or UnauthorizedAccessException or
            InvalidOperationException or ArgumentException or CryptographicException or JsonException or HttpRequestException or
            OperationCanceledException or System.ComponentModel.Win32Exception or PlatformNotSupportedException)
        {Console.Error.WriteLine("VIP node lifecycle refused or unconfirmed: "+error.GetType().Name);return 78;}
    }

    private static async Task Service(string name,bool start,CancellationToken token,bool checkOnly=false)
    {
        ProcessStartInfo info;
        if(OperatingSystem.IsLinux())
        {
            const string tool="/usr/bin/systemctl";
            PrivateKeyFileSecurity.ValidateLinuxTrustedExecutableDirectory(Path.GetDirectoryName(tool)!,"VIP service tool");
            if(!File.Exists(tool)||(File.GetAttributes(tool)&FileAttributes.ReparsePoint)!=0||
                (File.GetUnixFileMode(tool)&(UnixFileMode.GroupWrite|UnixFileMode.OtherWrite))!=0)
                throw new InvalidDataException("Trusted systemctl unavailable.");
            info=new ProcessStartInfo(tool);
            foreach(var arg in checkOnly?new[]{"show","--property=ActiveState,UnitFileState,LoadState","--",name}:
                new[]{start?"start":"stop","--",name})info.ArgumentList.Add(arg);
        }
        else
        {
            const string script="""
                $ErrorActionPreference='Stop'
                $s=Get-Service -Name $env:GC_VIP_SERVICE
                if($env:GC_VIP_CHECK -eq '1'){
                  if($s.Status -ne 'Stopped' -or $s.StartType -ne 'Manual'){throw 'Standby service must be stopped and manual'}
                } elseif($env:GC_VIP_START -eq '1'){
                  Start-Service -InputObject $s
                  $s.WaitForStatus('Running',[TimeSpan]::FromSeconds(20))
                } else {
                  Stop-Service -InputObject $s
                  $s.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(20))
                }
                """;
            info=new ProcessStartInfo(Path.Combine(Environment.SystemDirectory,"WindowsPowerShell","v1.0","powershell.exe"));
            foreach(var arg in new[]{"-NoProfile","-NonInteractive","-EncodedCommand",Convert.ToBase64String(Encoding.Unicode.GetBytes(script))})
                info.ArgumentList.Add(arg);
            info.Environment["GC_VIP_SERVICE"]=name;
            info.Environment["GC_VIP_START"]=start?"1":"0";
            info.Environment["GC_VIP_CHECK"]=checkOnly?"1":"0";
        }
        info.UseShellExecute=false;info.CreateNoWindow=true;info.RedirectStandardOutput=true;info.RedirectStandardError=true;
        using var process=Process.Start(info)??throw new InvalidOperationException("Service action unavailable.");
        var output=process.StandardOutput.ReadToEndAsync();var error=process.StandardError.ReadToEndAsync();
        try{await process.WaitForExitAsync(token);}
        catch(OperationCanceledException)
        {
            try{process.Kill(entireProcessTree:true);}catch(InvalidOperationException){}
            await process.WaitForExitAsync();throw;
        }
        await Task.WhenAll(output,error);
        if(process.ExitCode!=0)throw new InvalidOperationException("Service transition not confirmed.");
        if(checkOnly&&OperatingSystem.IsLinux())
        {
            var lines=(await output).Split('\n',StringSplitOptions.TrimEntries|StringSplitOptions.RemoveEmptyEntries);
            if(!lines.Contains("ActiveState=inactive")||!lines.Contains("LoadState=loaded")||
                !(lines.Contains("UnitFileState=disabled")||lines.Contains("UnitFileState=static")))
                throw new InvalidOperationException("Standby service must be installed, stopped and not automatically enabled.");
        }
    }
}
