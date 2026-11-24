using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using GatewayCore.LicenseAuthority;
using GatewayCore.Licensing;
using Npgsql;

namespace GatewayCore.LicenseIssuerWorker;

// Separate company-side signer. PostgreSQL is the authoritative ledger.
// All issuance and renewal changes for one subscription serialize on its row.
// No private key or issuance capability belongs in the operator web process.
public sealed class ApprovedJobExecutor(NpgsqlDataSource db, ECDsa signer, string keyId)
{
    public async Task<string?> Execute(Guid jobId, DateTimeOffset now)
    {
        var pub = signer.ExportSubjectPublicKeyInfo();
        var verifier = new OfflineLicenseVerifier(new Dictionary<string, byte[]> { [keyId] = pub });
        var keyHash = Convert.ToHexString(SHA256.HashData(pub));
        await using var conn = await db.OpenConnectionAsync();
        await using var tx = await conn.BeginTransactionAsync();

        async Task<object?> Scalar(string sql, params object[] values)
        {
            await using var cmd = new NpgsqlCommand(sql, conn, tx);
            foreach (var value in values) cmd.Parameters.AddWithValue(value);
            return await cmd.ExecuteScalarAsync();
        }
        async Task<int> Change(string sql, params object[] values)
        {
            await using var cmd = new NpgsqlCommand(sql, conn, tx);
            foreach(var value in values) cmd.Parameters.AddWithValue(value);
            return await cmd.ExecuteNonQueryAsync();
        }
        async Task<object?[]?> Row(string sql, params object[] values)
        {
            await using var cmd = new NpgsqlCommand(sql, conn, tx);
            foreach(var value in values) cmd.Parameters.AddWithValue(value);
            await using var reader = await cmd.ExecuteReaderAsync();
            if (!await reader.ReadAsync()) return null;
            var data = new object?[reader.FieldCount];
            for (var i=0;i<data.Length;i++) data[i]=reader.IsDBNull(i)?null:reader.GetValue(i);
            return data;
        }

        var job = await Row("""
            SELECT subscription_id,kind,site_id,request_file,allocation_id,request_id,installation_hash,
            expected_terms_revision,proposed_terms::text FROM gc_license_jobs
            WHERE id=$1 AND state='approved' AND approved_by<>requested_by AND approved_at IS NOT NULL
            """,jobId) ?? throw new InvalidOperationException("No independently approved job.");
        var id=(string)job[0]!;
        var sub=await Row("""
            SELECT customer_id,deployment_id,edition,max_nodes,max_sites,extract(epoch from expires_at)::bigint,
            features,terms_revision FROM gc_subscriptions WHERE id=$1 FOR UPDATE
            """,id) ?? throw new InvalidOperationException("Unknown subscription.");
        var committed=await Row("SELECT envelope FROM gc_issuer_results WHERE job_id=$1",jobId);
        if(committed is not null){await tx.CommitAsync();return (string?)committed[0];}
        if((long)sub[7]! != (long)job[7]!) throw new InvalidOperationException("Subscription changed; request new approval.");
        var terms=new Subscription(id,(string)sub[0]!, (string)sub[1]!, (string)sub[2]!,
            (int)sub[3]!, (int)sub[4]!, (long)sub[5]!, (string[])sub[6]!);
        // Existing allocations cannot silently switch to another signer.
        await Change("INSERT INTO gc_issuer_authority(subscription_id,key_id,public_key_hash) VALUES($1,$2,$3) ON CONFLICT DO NOTHING",id,keyId,keyHash);
        var authority=await Row("SELECT key_id,public_key_hash FROM gc_issuer_authority WHERE subscription_id=$1",id);
        if(authority is null || (string?)authority[0]!=keyId || (string?)authority[1]!=keyHash)
            throw new CryptographicException("Issuer authority mismatch; approved rotation required.");

        string? result=null;
        var kind=(string)job[1]!;
        if(kind=="issue")
        {
            if(job[3] is not string requestFile || requestFile.Length>4096 ||
                requestFile.Any(c=>c is < (char)33 or > (char)126))
                throw new InvalidDataException("Invalid approved request.");
            var request=OfflineActivationRequest.Verify(Encoding.ASCII.GetBytes(requestFile));
            if(request.RequestId!=(string?)job[5] || request.InstallationKeySha256!=(string?)job[6])
                throw new CryptographicException("Approved request identity mismatch.");
            var site=(string)job[2]!;
            var old=await Row("""
                SELECT allocation_id,site_id,revision,revocation_envelope
                FROM gc_issuer_allocations WHERE subscription_id=$1 AND installation_hash=$2
                """,id,request.InstallationKeySha256);
            string allocation;
            long revision;
            if(old is null)
            {
                var seats=(long)(await Scalar("SELECT count(*) FROM gc_issuer_allocations WHERE subscription_id=$1",id))!;
                var sites=(long)(await Scalar("SELECT count(DISTINCT site_id) FROM gc_issuer_allocations WHERE subscription_id=$1",id))!;
                var inSite=(long)(await Scalar("SELECT count(*) FROM gc_issuer_allocations WHERE subscription_id=$1 AND site_id=$2",id,site))!;
                if(seats>=terms.MaxNodes || (sites>=terms.MaxSites && inSite==0))
                    throw new InvalidOperationException("Purchased allocation exhausted.");
                allocation="node-"+Guid.NewGuid().ToString("N");revision=1;
            }
            else
            {
                if(old[3] is not null || (string?)old[1]!=site) throw new InvalidOperationException("Revoked allocation or unauthorized site transfer.");
                allocation=(string)old[0]!;revision=checked((long)old[2]!+1);
            }
            var utc=now.ToUnixTimeSeconds();
            result=Sign("GCL1",new {schemaVersion=1,product="GatewayCore",licenseId=id,customerId=terms.CustomerId,
                deploymentId=terms.DeploymentId,allocationId=allocation,installationKeySha256=request.InstallationKeySha256,
                edition=terms.Edition,revision,maxNodes=terms.MaxNodes,maxSites=terms.MaxSites,issuedAt=utc,notBefore=utc,
                expiresAt=terms.ExpiresAt,features=terms.Features});
            if(verifier.Verify(Encoding.ASCII.GetBytes(result),request.InstallationKeySha256,now).Validity!=LicenseValidity.Active)
                throw new InvalidOperationException("Cannot issue inactive license.");
            if(old is null)
                await Change("""
                    INSERT INTO gc_issuer_allocations(subscription_id,allocation_id,site_id,installation_hash,revision,last_expiry)
                    VALUES($1,$2,$3,$4,$5,$6)
                    """,id,allocation,site,request.InstallationKeySha256,revision,DateTimeOffset.FromUnixTimeSeconds(terms.ExpiresAt));
            else
                await Change("""
                    UPDATE gc_issuer_allocations SET revision=$1,last_expiry=greatest(last_expiry,$2)
                    WHERE subscription_id=$3 AND installation_hash=$4
                    """,revision,DateTimeOffset.FromUnixTimeSeconds(terms.ExpiresAt),id,request.InstallationKeySha256);
        }
        else if(kind=="revoke")
        {
            var allocation=(string)job[4]!;
            var old=await Row("SELECT installation_hash,revocation_envelope FROM gc_issuer_allocations WHERE subscription_id=$1 AND allocation_id=$2",id,allocation)
                ?? throw new InvalidOperationException("Unknown allocation.");
            result=(string?)old[1]??Sign("GCV1",new{schemaVersion=1,product="GatewayCore",licenseId=id,customerId=terms.CustomerId,
                deploymentId=terms.DeploymentId,allocationId=allocation,installationKeySha256=(string)old[0]!,revokedAt=now.ToUnixTimeSeconds()});
            await Change("UPDATE gc_issuer_allocations SET revocation_envelope=$1 WHERE subscription_id=$2 AND allocation_id=$3",result,id,allocation);
        }
        else if(kind=="renew_terms")
        {
            var next=JsonSerializer.Deserialize<Subscription>((string)job[8]!)??throw new InvalidDataException("Missing approved terms.");
            var seats=(long)(await Scalar("SELECT count(*) FROM gc_issuer_allocations WHERE subscription_id=$1",id))!;
            var sites=(long)(await Scalar("SELECT count(DISTINCT site_id) FROM gc_issuer_allocations WHERE subscription_id=$1",id))!;
            if(next.LicenseId!=id || next.CustomerId!=terms.CustomerId || next.DeploymentId!=terms.DeploymentId ||
                next.MaxNodes<seats || next.MaxSites<sites) throw new InvalidOperationException("Terms conflict with committed allocation.");
            // Use the same cryptographic schema validation as actual licenses.
            var hash=new string('A',64);var utc=now.ToUnixTimeSeconds();
            var test=Sign("GCL1",new{schemaVersion=1,product="GatewayCore",licenseId=id,customerId=next.CustomerId,
                deploymentId=next.DeploymentId,allocationId="validation",installationKeySha256=hash,edition=next.Edition,revision=1,
                maxNodes=next.MaxNodes,maxSites=next.MaxSites,issuedAt=utc,notBefore=utc,expiresAt=next.ExpiresAt,features=next.Features});
            if(verifier.Verify(Encoding.ASCII.GetBytes(test),hash,now).Validity!=LicenseValidity.Active)
                throw new InvalidOperationException("Inactive renewal.");
            await Change("""
                UPDATE gc_subscriptions SET edition=$1,max_nodes=$2,max_sites=$3,expires_at=$4,features=$5,terms_revision=terms_revision+1 WHERE id=$6
                """,next.Edition,next.MaxNodes,next.MaxSites,DateTimeOffset.FromUnixTimeSeconds(next.ExpiresAt),next.Features,id);
        }
        else throw new InvalidOperationException("Unknown job kind.");
        await using(var save=new NpgsqlCommand("INSERT INTO gc_issuer_results(job_id,envelope) VALUES($1,$2)",conn,tx))
        {
            save.Parameters.AddWithValue(jobId);
            save.Parameters.Add(new NpgsqlParameter{NpgsqlDbType=NpgsqlTypes.NpgsqlDbType.Text,Value=(object?)result??DBNull.Value});
            await save.ExecuteNonQueryAsync();
        }
        await Change("INSERT INTO gc_portal_audit(actor,action,subject) VALUES($1,$2,$3)","issuer-"+keyId,"job_executed",jobId.ToString());
        await tx.CommitAsync();
        return result;
    }

    private string Sign(string format,object payload)
    {
        static string B64(byte[] bytes)=>Convert.ToBase64String(bytes).TrimEnd('=').Replace('+','-').Replace('/','_');
        var prefix=format+"."+keyId+"."+B64(JsonSerializer.SerializeToUtf8Bytes(payload));
        return prefix+"."+B64(signer.SignData(Encoding.ASCII.GetBytes(prefix),HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
    }
}
