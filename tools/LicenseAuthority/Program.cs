using System.Security.Cryptography;
using System.Text.Json;
using GatewayCore.LicenseAuthority;

// Local issuer operator CLI. Provision an encrypted PKCS#8 PEM out of band.
// No private key generation or key material in command arguments or source.
if (args.Length < 4 || args[0] is not ("init" or "renew" or "issue" or "revoke"))
{
    Console.Error.WriteLine("Usage: LicenseAuthority init|renew LEDGER KEY_ID ENCRYPTED_KEY_PEM TERMS_JSON");
    Console.Error.WriteLine("       LicenseAuthority issue LEDGER KEY_ID ENCRYPTED_KEY_PEM REQUEST_GCR SITE OUTPUT_LIC");
    Console.Error.WriteLine("       LicenseAuthority revoke LEDGER KEY_ID ENCRYPTED_KEY_PEM ALLOCATION_ID OUTPUT_GCV");
    return 2;
}
try
{
    if (args.Length != (args[0] == "issue" ? 7 : args[0] == "revoke" ? 6 : 5)) throw new ArgumentException("Incorrect argument count.");
    if (Console.IsInputRedirected) throw new InvalidOperationException("Use a local interactive issuer console.");
    Console.Error.Write("Signing key passphrase: ");
    var password = new List<char>();
    while (true)
    {
        var ch = Console.ReadKey(intercept: true);
        if (ch.Key == ConsoleKey.Enter) break;
        if (ch.Key == ConsoleKey.Backspace) { if (password.Count > 0) password.RemoveAt(password.Count - 1); }
        else if (!char.IsControl(ch.KeyChar) && password.Count < 1024) password.Add(ch.KeyChar);
    }
    Console.Error.WriteLine();
    using var signer = ECDsa.Create();
    var secret = password.ToArray();
    try { signer.ImportFromEncryptedPem(File.ReadAllText(args[3]), secret); }
    finally { Array.Clear(secret); for (int i = 0; i < password.Count; i++) password[i] = '\0'; password.Clear(); }
    var authority = new OfflineIssuer(args[1], signer, args[2]);
    var now = DateTimeOffset.UtcNow;
    if (args[0] == "issue")
    {
        var requestInfo = new FileInfo(args[4]);
        if (requestInfo.Length is < 1 or > 4096) throw new InvalidDataException("Invalid request size.");
        var license = authority.Issue(File.ReadAllBytes(args[4]), args[5], now);
        // Never overwrite an arbitrary output file.
        using var output = new FileStream(args[6], FileMode.CreateNew, FileAccess.Write, FileShare.None);
        output.Write(license);
        output.Flush(true);
    }
    else if (args[0] == "revoke")
    {
        var revocation = authority.Revoke(args[4], now);
        using var output = new FileStream(args[5], FileMode.CreateNew, FileAccess.Write, FileShare.None);
        output.Write(revocation);
        output.Flush(true);
    }
    else
    {
        var terms = JsonSerializer.Deserialize<Subscription>(File.ReadAllBytes(args[4]))
            ?? throw new InvalidDataException("Missing subscription terms.");
        if (args[0] == "init") authority.Initialize(terms, now);
        else authority.RenewSubscription(terms, now);
    }
    Console.WriteLine("Operation committed.");
    return 0;
}
catch (Exception ex)
{
    Console.Error.WriteLine("Issuer operation failed: " + ex.GetType().Name);
    return 1;
}
