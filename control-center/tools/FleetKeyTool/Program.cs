using System.Security.Cryptography;
if (args.Length != 2 || !Path.IsPathFullyQualified(args[0]) || !Path.IsPathFullyQualified(args[1]))
{
    Console.Error.WriteLine("Usage: dotnet run --project tools/FleetKeyTool -- <absolute-private-key-path> <absolute-public-key-path>");
    return 2;
}
if (File.Exists(args[0]) || File.Exists(args[1]))
{
    Console.Error.WriteLine("Refusing to overwrite an existing signing identity.");
    return 3;
}
Directory.CreateDirectory(Path.GetDirectoryName(args[0])!);
Directory.CreateDirectory(Path.GetDirectoryName(args[1])!);
using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
await File.WriteAllTextAsync(args[0], key.ExportPkcs8PrivateKeyPem());
await File.WriteAllTextAsync(args[1], key.ExportSubjectPublicKeyInfoPem());
Console.WriteLine("A new P-256 signing pair was generated. Restrict the private key to the controller service identity.");
Console.WriteLine("Copy ONLY the public PEM to each agent and configure ControllerSigningPublicKeyPath.");
return 0;
