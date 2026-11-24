using System.Security.Cryptography;
using GatewayCore.LicenseIssuerWorker;
using Npgsql;

if(args.Length!=3 || !Guid.TryParse(args[0],out var id) || Console.IsInputRedirected)
{
    Console.Error.WriteLine("Usage: LicenseIssuerWorker APPROVED_JOB_ID KEY_ID ENCRYPTED_PKCS8_PEM");
    return 2;
}
try
{
    var connection=Environment.GetEnvironmentVariable("GATEWAYCORE_ISSUER_DB")??
        throw new InvalidOperationException("Issuer-only database connection required.");
    Console.Error.Write("Signing key passphrase: ");
    var password=new List<char>();
    while(true)
    {
        var ch=Console.ReadKey(true);
        if(ch.Key==ConsoleKey.Enter)break;
        if(ch.Key==ConsoleKey.Backspace){if(password.Count>0)password.RemoveAt(password.Count-1);}
        else if(!char.IsControl(ch.KeyChar)&&password.Count<1024)password.Add(ch.KeyChar);
    }
    Console.Error.WriteLine();
    using var signer=ECDsa.Create();
    var secret=password.ToArray();
    try{signer.ImportFromEncryptedPem(File.ReadAllText(args[2]),secret);}
    finally{Array.Clear(secret);for(var i=0;i<password.Count;i++)password[i]='\0';password.Clear();}
    await using var db=NpgsqlDataSource.Create(connection);
    await new ApprovedJobExecutor(db,signer,args[1]).Execute(id,DateTimeOffset.UtcNow);
    Console.WriteLine("Approved job committed. Retrieve result in portal.");
    return 0;
}
catch(Exception e){Console.Error.WriteLine("Issuer job failed: "+e.GetType().Name);return 1;}
