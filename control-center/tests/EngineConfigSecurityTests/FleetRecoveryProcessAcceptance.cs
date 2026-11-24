using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;

internal static class FleetRecoveryProcessAcceptance
{
    // Invoked in a new test executable process for each recovery attempt.
    // Production helper and normal HTTPS transport; no product test bypass.
    internal static async Task RunAsync(string[] args)
    {
        if (args.Length != 8 || args[0] is not ("prepare" or "recover" or "verify" or "install-client" or "remove-client" or "install-root" or "remove-root"))
            throw new ArgumentException("Expected operation, root, cert, key, server cert, two ports and journal path");
        var (mode, root, certPath, keyPath, serverPath, firstPort, secondPort, path) =
            (args[0],args[1],args[2],args[3],args[4],int.Parse(args[5]),int.Parse(args[6]),args[7]);
        if (mode is "install-root" or "remove-root")
        {
            // Use the elevated hosted runner's machine Root store rather
            // than CurrentUser Root, whose trust-consent UI can hang CI.
            if (!OperatingSystem.IsWindows() ||
                Environment.GetEnvironmentVariable("GITHUB_ACTIONS") != "true" ||
                Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT") != "github-hosted")
                throw new InvalidOperationException("Temporary root provisioning requires Windows GitHub-hosted CI");
            using var ca = X509CertificateLoader.LoadCertificateFromFile(Path.Combine(root,"fleet-root.cer"));
            if (!ca.Subject.Contains("CN=GatewayCore disposable CRL root",StringComparison.Ordinal) ||
                ca.Subject != ca.Issuer || !ca.Extensions.OfType<X509BasicConstraintsExtension>().Any(x=>x.CertificateAuthority))
                throw new InvalidDataException("Unexpected disposable root certificate");
            using var roots = new X509Store(StoreName.Root,StoreLocation.LocalMachine);
            roots.Open(OpenFlags.ReadWrite);
            if (mode == "install-root")
            {
                roots.Add(ca);
                if (roots.Certificates.Find(X509FindType.FindByThumbprint,ca.Thumbprint,false).Count != 1)
                    throw new InvalidOperationException("Temporary root installation not observed");
                Console.WriteLine("PASS: disposable Windows machine root installed");
            }
            else
            {
                foreach (var match in roots.Certificates.Find(X509FindType.FindByThumbprint,ca.Thumbprint,false))
                    using (match) roots.Remove(match);
                if (roots.Certificates.Find(X509FindType.FindByThumbprint,ca.Thumbprint,false).Count != 0)
                    throw new InvalidOperationException("Temporary root was not removed");
                Console.WriteLine("PASS: disposable Windows machine root removed");
            }
            return;
        }
        using var pem = X509Certificate2.CreateFromPemFile(certPath,keyPath);
        using var controller = X509CertificateLoader.LoadPkcs12(pem.Export(X509ContentType.Pkcs12),null,
            OperatingSystem.IsWindows() ? X509KeyStorageFlags.UserKeySet : X509KeyStorageFlags.EphemeralKeySet);
        if (mode is "install-client" or "remove-client")
        {
            // Only the disposable Linux runner's current-user certificate store.
            if (!OperatingSystem.IsLinux() || Environment.GetEnvironmentVariable("GITHUB_ACTIONS") != "true" ||
                Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT") != "github-hosted")
                throw new InvalidOperationException("Fixture store provisioning is restricted to Linux CI");
            using var store = new X509Store(StoreName.My,StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadWrite);
            if (mode == "install-client") store.Add(controller);
            else foreach (var match in store.Certificates.Find(X509FindType.FindByThumbprint,controller.Thumbprint,false))
                using (match) store.Remove(match);
            return;
        }
        using var server = X509CertificateLoader.LoadCertificateFromFile(serverPath);
        (Uri Origin,HttpClient Client) Connect(string id)
        {
            var origin = new Uri($"https://127.0.0.1:{(id == "one" ? firstPort : id == "two" ? secondPort : throw new InvalidDataException())}/");
            var handler = new HttpClientHandler { UseProxy = false, AllowAutoRedirect = false };
            handler.ClientCertificates.Add(controller);
            // Fixture pins the exact generated HTTPS server leaf. The running
            // agent independently uses production client-chain/CRL validation.
            handler.ServerCertificateCustomValidationCallback = (_,leaf,_,_) =>
                leaf?.Thumbprint == server.Thumbprint;
            return (origin,new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(4),MaxResponseContentBufferSize = 65536 });
        }
        async Task<JsonObject> Call(string id,string suffix,object? body = null)
        {
            var (origin,client) = Connect(id);
            using (client)
            using (var response = body is null ? await client.GetAsync(new Uri(origin,suffix)) :
                await client.PostAsJsonAsync(new Uri(origin,suffix),body))
            {
                response.EnsureSuccessStatusCode();
                return JsonNode.Parse(await response.Content.ReadAsStringAsync())!.AsObject();
            }
        }
        static void Must(bool condition,string message)
        {
            if (!condition) throw new InvalidOperationException("FAIL: "+message);
            Console.WriteLine("PASS: "+message);
        }
        const string tx = "rollout_AAAAAAAAAAAAAAAAAAAAAAAA";
        var inventory = Path.Combine(root,"fleet-controller","state","fleet-gateways.json");
        var digest = File.Exists(inventory) ? Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(inventory))) : new string('D',64);
        if(mode == "prepare")
        {
            var rows = new JsonArray();
            long sequence=1;
            foreach(var id in new[]{"one","two"})
            {
                var status=await Call(id,"agent/v1/status");
                var revision=status["revision"]!.GetValue<string>();
                Must(FleetRolloutJournal.IsDigest(revision),"real authenticated agent revision available");
                sequence=Math.Max(sequence,checked(status["highestAcceptedSequence"]!.GetValue<long>()+1));
                rows.Add(new JsonObject { ["id"]=id,["originalRevision"]=revision,
                    ["prepareSent"]=false,["activateSent"]=false,["rollbackVerified"]=false });
            }
            var journal = new JsonObject {["schema"]=2,["id"]=tx,["fleetDigest"]=digest,
                ["status"]="preparing",["sequence"]=sequence,["details"]=new JsonArray(),["targets"]=rows};
            FleetRolloutJournal.Write(path,journal);
            var proxy=JsonNode.Parse("""{"Routes":{},"Clusters":{},"fixture":"candidate"}""")!.AsObject();
            var signingKey=File.ReadAllText(Path.Combine(root,"fleet-private.pem"));
            foreach(var target in FleetRolloutJournal.Targets(journal))
            {
                var id=target["id"]!.GetValue<string>();var revision=target["originalRevision"]!.GetValue<string>();
                var signed=FleetConfigSignature.SignV2(signingKey,tx,revision,proxy,DateTimeOffset.UtcNow.AddMinutes(2).ToUnixTimeSeconds(),sequence);
                target["prepareSent"]=true;
                FleetRolloutJournal.Log(path,journal,id,"prepare","dispatching");
                var result=await Call(id,"agent/v1/config/prepare",new {TransactionId=tx,ExpectedRevision=revision,ReverseProxy=proxy,
                    signed.ExpiresUnixSeconds,signed.Sequence,signed.KeyId,signed.Signature});
                target["preparedRevision"]=result["preparedRevision"]!.GetValue<string>();
                FleetRolloutJournal.Log(path,journal,id,"prepare","ok");
            }
            var first=FleetRolloutJournal.Targets(journal)[0];
            journal["status"]="activating";first["activateSent"]=true;
            FleetRolloutJournal.Log(path,journal,"one","activate","dispatching");
            var activated=await Call("one","agent/v1/config/activate",new {TransactionId=tx,PreparedRevision=first["preparedRevision"]!.GetValue<string>()});
            Must(activated["revision"]!.GetValue<string>()==first["preparedRevision"]!.GetValue<string>(),
                "first agent really activated; second remains prepared");
            // Exit without recording activation ACK or starting compensation:
            // reproduces lost response/process interruption at durable boundary.
            return;
        }
        var recovered=FleetRolloutJournal.Read(path);
        if (mode == "recover")
            Must(FleetRolloutJournal.HasUnresolved(Path.GetDirectoryName(path)!) &&
                FleetRolloutJournal.RecoveryAllowed(recovered,tx,digest),"restarted recovery reads persisted unfinished plan");
        var errors = mode == "recover" ? await FleetRolloutJournal.RollbackAttemptedAsync(path,recovered,Connect) : new List<string>();
        var targets=FleetRolloutJournal.Targets(recovered);
        if(errors.Count!=0)
        {
            Must(errors.Count==1 && errors[0].StartsWith("two:",StringComparison.Ordinal) &&
                targets[0]["rollbackVerified"]!.GetValue<bool>() && !targets[1]["rollbackVerified"]!.GetValue<bool>() &&
                FleetRolloutJournal.HasUnresolved(Path.GetDirectoryName(path)!),
                "unreachable second agent keeps rollout blocked; first rollback persists");
            Console.WriteLine("FLEET_RECOVERY_PARTIAL");
            return;
        }
        Must(recovered["status"]!.GetValue<string>()=="rollback-verified" &&
             !FleetRolloutJournal.HasUnresolved(Path.GetDirectoryName(path)!),"recovery clears fence only after both original revisions verified");
        foreach(var target in targets)
        {
            var id=target["id"]!.GetValue<string>();
            var status=await Call(id,"agent/v1/status");
            Must(status["revision"]!.GetValue<string>()==target["originalRevision"]!.GetValue<string>() &&
                 status["highestAcceptedSequence"]!.GetValue<long>()==(recovered["sequence"]?.GetValue<long>()??1),"original revision and sequence high-water retained");
            var (origin,client)=Connect(id);
            using(client)
            using(var late=await client.PostAsJsonAsync(new Uri(origin,"agent/v1/config/activate"),
                new {TransactionId=tx,PreparedRevision=target["preparedRevision"]!.GetValue<string>()}))
            {
                var revoked=Environment.GetEnvironmentVariable("GC_TEST_EXPECT_REVOKED")=="true";
                Must(late.StatusCode==(revoked?HttpStatusCode.PaymentRequired:HttpStatusCode.Conflict),
                    "late activation rejected after rollback");
                if(revoked)
                    Must(File.Exists(Path.Combine(root,id=="one"?"recovery-node-0":"recovery-node-1","stage",tx,"rollback-fence")),
                        "durable rollback fence exists even in revoked recovery-only agent");
            }
        }
        Console.WriteLine("FLEET_RECOVERY_COMPLETE");
    }
}
