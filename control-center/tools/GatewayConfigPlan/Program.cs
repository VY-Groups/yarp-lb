using System.Text.Json;
using GatewayConfigPlan;

if (args.Length == 2 && args[0] == "import-gateway-api")
{
    try
    {
        // Bound the input before reading it, and recheck the decoded size in
        // the importer. Output deliberately contains desired route values;
        // unlike plan/validate, redirect it only to a protected file.
        using var stream = new FileStream(args[1], FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length is < 1 or > 524288) throw new ArgumentException("Import exceeds input bound");
        var bytes = new byte[(int)stream.Length];
        stream.ReadExactly(bytes);
        if (stream.ReadByte() != -1) throw new ArgumentException("Import changed during read");
        var json = new System.Text.UTF8Encoding(false, true).GetString(bytes);
        var result = GatewayApiImport.Translate(json);
        Console.WriteLine(result.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
        return 0;
    }
    catch (Exception ex) when (ex is ArgumentException or IOException or UnauthorizedAccessException)
    {
        Console.Error.WriteLine("Gateway API import rejected; check supported schema and input file.");
        return 1;
    }
}

if (args.Length == 2 && args[0] == "validate")
{
    try
    {
        var result = PlanEngine.Validate(await ReadBoundedJsonAsync(args[1]));
        Console.WriteLine(JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true }));
        return 0;
    }
    catch (Exception ex) when (ex is ArgumentException or IOException)
    {
        Console.Error.WriteLine(ex.Message);
        return 1;
    }
}

if (args.Length != 3 || args[0] != "plan")
{
    Console.Error.WriteLine("Usage: GatewayConfigPlan validate <desired.json> | plan <current.json> <desired.json> | import-gateway-api <bundle.json>");
    return 2;
}

try
{
    var result = PlanEngine.Build(await ReadBoundedJsonAsync(args[1]), await ReadBoundedJsonAsync(args[2]));
    Console.WriteLine(JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true }));
    return 0;
}
catch (Exception ex) when (ex is ArgumentException or IOException)
{
    Console.Error.WriteLine(ex.Message);
    return 1;
}

static async Task<string> ReadBoundedJsonAsync(string path)
{
    using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
    if (stream.Length is < 1 or > 512 * 1024)
        throw new ArgumentException("Planner input must be between 1 byte and 512 KiB");
    var bytes = new byte[checked((int)stream.Length)];
    try
    {
        await stream.ReadExactlyAsync(bytes);
        if (stream.ReadByte() != -1)
            throw new ArgumentException("Planner input changed during read");
        return new System.Text.UTF8Encoding(false, true).GetString(bytes);
    }
    finally
    {
        System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes);
    }
}
