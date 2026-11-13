using Yarp.ReverseProxy.LoadBalancing;

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.UseUrls("http://127.0.0.1:18080");

var configPath = Path.Combine(AppContext.BaseDirectory, "lab.json");
builder.Configuration.AddJsonFile(configPath, optional: false, reloadOnChange: true);
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));
builder.Services.AddSingleton<ILoadBalancingPolicy, WeightedRandomPolicy>();
builder.Services.AddSingleton<ILoadBalancingPolicy, SourceIpHashPolicy>();

var app = builder.Build();
app.MapGet("/lab/ping", () => Results.Ok(new { lab = true }));
app.MapReverseProxy();
app.Run();
