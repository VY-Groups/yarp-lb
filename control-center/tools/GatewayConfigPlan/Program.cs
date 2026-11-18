using System.Text.Json;
using GatewayConfigPlan;

if (args.Length != 3 || args[0] != "plan")
{
    Console.Error.WriteLine("Usage: GatewayConfigPlan plan <current.json> <desired.json>");
    return 2;
}

try
{
    var result = PlanEngine.Build(await File.ReadAllTextAsync(args[1]), await File.ReadAllTextAsync(args[2]));
    Console.WriteLine(JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true }));
    return 0;
}
catch (Exception ex) when (ex is ArgumentException or IOException)
{
    Console.Error.WriteLine(ex.Message);
    return 1;
}
