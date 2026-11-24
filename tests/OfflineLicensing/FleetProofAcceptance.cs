using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using GatewayCore.Licensing;

internal static class FleetProofAcceptance
{
    internal static void Run()
    {
        var now=DateTimeOffset.UtcNow;
        using var issuer=ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var verifier=new OfflineLicenseVerifier(new Dictionary<string,byte[]>{["fleet-ci"]=issuer.ExportSubjectPublicKeyInfo()});
        var root=Path.Combine(Path.GetTempPath(),"gc-fleet-proof-"+Guid.NewGuid().ToString("N"));
        var dirs=Enumerable.Range(0,4).Select(i=>root+"-"+i).ToArray();
        static string B64(byte[] bytes)=>Convert.ToBase64String(bytes).TrimEnd('=').Replace('+','-').Replace('/','_');
        static void Check(bool ok,string label)
        {if(!ok)throw new Exception("FAIL: "+label);Console.WriteLine("PASS: "+label);}
        static void Reject(Action action,string label)
        {
            try{action();}
            catch(Exception e) when(e is CryptographicException or InvalidDataException or ArgumentException)
            {Check(true,label);return;}
            throw new Exception("FAIL: "+label);
        }
        try
        {
            var stores=dirs.Select(d=>new OfflineLicenseStore(d,verifier)).ToArray();
            foreach(var store in stores)store.Initialize();
            var bindings=stores.Select(x=>OfflineActivationRequest.Verify(x.ExportActivationRequest()).InstallationKeySha256).ToArray();
            byte[] Signed(int index,string site,int nodes=2,int sites=2,string deployment="fleet-deployment",bool dcdr=true,int rev=1)
            {
                var payload=JsonSerializer.SerializeToUtf8Bytes(new {schemaVersion=2,product="GatewayCore",
                    licenseId="fleet-license",customerId="fleet-customer",deploymentId=deployment,
                    allocationId="node-"+index,installationKeySha256=bindings[index],edition="enterprise",
                    revision=rev,maxNodes=nodes,maxSites=sites,siteId=site,
                    issuedAt=now.AddMinutes(-1).ToUnixTimeSeconds(),notBefore=now.AddMinutes(-1).ToUnixTimeSeconds(),
                    expiresAt=now.AddDays(1).ToUnixTimeSeconds(),
                    features=dcdr?new[]{"l7","ha","fleet","dc-dr"}:new[]{"l7","ha","fleet"}});
                var prefix="GCL1.fleet-ci."+B64(payload);
                return Encoding.ASCII.GetBytes(prefix+"."+B64(issuer.SignData(Encoding.ASCII.GetBytes(prefix),HashAlgorithmName.SHA256,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation)));
            }
            var local=stores[0].Import(Signed(0,"dc"),now);
            var second=stores[1].Import(Signed(1,"dr"),now);
            var third=stores[2].Import(Signed(2,"dr"),now);
            var foreign=stores[3].Import(Signed(3,"dr",deployment:"foreign"),now);
            var challenge=Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
            var proof=stores[1].CreateInstallationProof(challenge,now);
            var verified=verifier.VerifyInstallationProof(proof,challenge,now);
            Check(verified.SiteId=="dr" && verified.AllocationId==second.AllocationId,"issuer-signed site and live installation proof");
            FleetLicensePolicy.Validate(local,new[]{local,verified},now);
            Check(true,"two allocated DC/DR installations, controller counted once");
            Reject(()=>verifier.VerifyInstallationProof(proof,Convert.ToHexString(RandomNumberGenerator.GetBytes(32)),now),"replayed peer challenge");
            var tampered=proof.ToArray();tampered[^2]=tampered[^2]==(byte)'A'?(byte)'B':(byte)'A';
            Reject(()=>verifier.VerifyInstallationProof(tampered,challenge,now),"tampered peer proof");
            Reject(()=>FleetLicensePolicy.Validate(local,new[]{verified,verified},now),"duplicated allocation across two targets");
            Reject(()=>FleetLicensePolicy.Validate(local,new[]{verified,third},now),"controller plus two peers exceeds two nodes");
            Reject(()=>FleetLicensePolicy.Validate(local,new[]{foreign},now),"foreign deployment");
            Reject(()=>FleetLicensePolicy.Validate(local,new[]{verified with {SiteId=null}},now),"legacy site-less fleet entitlement");
            Reject(()=>FleetLicensePolicy.Validate(local with {MaxSites=1},new[]{verified with {MaxSites=1}},now),"signed site limit exceeded");
            var noDrLocal=local with {Features=System.Collections.Frozen.FrozenSet.ToFrozenSet(new[]{"l7","ha","fleet"},StringComparer.Ordinal)};
            var noDrPeer=verified with {Features=noDrLocal.Features};
            Reject(()=>FleetLicensePolicy.Validate(noDrLocal,new[]{noDrPeer},now),"DC-DR feature required for distinct sites");
            Reject(()=>verifier.VerifyInstallationProof(proof,challenge,now.AddDays(2)),"expired peer proof");
            var revocationPayload=JsonSerializer.SerializeToUtf8Bytes(new{schemaVersion=1,product="GatewayCore",licenseId=second.LicenseId,
                customerId=second.CustomerId,deploymentId=second.DeploymentId,allocationId=second.AllocationId,
                installationKeySha256=bindings[1],revokedAt=now.ToUnixTimeSeconds()});
            var revocationPrefix="GCV1.fleet-ci."+B64(revocationPayload);
            var revocation=Encoding.ASCII.GetBytes(revocationPrefix+"."+B64(issuer.SignData(Encoding.ASCII.GetBytes(revocationPrefix),
                HashAlgorithmName.SHA256,DSASignatureFormat.IeeeP1363FixedFieldConcatenation)));
            stores[1].ImportRevocation(revocation,now);
            Reject(()=>stores[1].CreateInstallationProof(Convert.ToHexString(RandomNumberGenerator.GetBytes(32)),now),"revoked installation cannot answer fresh proof");
            Console.WriteLine("SITE_BOUND_FLEET_PROOF_ACCEPTANCE_PASS");
        }
        finally{foreach(var d in dirs)if(Directory.Exists(d))Directory.Delete(d,true);}
    }
}
