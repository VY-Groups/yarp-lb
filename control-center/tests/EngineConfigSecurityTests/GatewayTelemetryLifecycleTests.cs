using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Http;

internal static class GatewayTelemetryLifecycleTests
{
    public static void Run()
    {
        var stopped = new ConcurrentQueue<Activity>();
        using var listener = new ActivityListener
        {
            ShouldListenTo = source => source.Name == GatewayOpenTelemetry.ActivitySourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) =>
                ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = activity => stopped.Enqueue(activity)
        };
        ActivitySource.AddActivityListener(listener);

        var context = new DefaultHttpContext();
        context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
        var activity = GatewayOpenTelemetry.StartProxyActivity(context);
        if (activity is null)
            throw new InvalidOperationException("Proxy telemetry listener did not create an activity");

        GatewayOpenTelemetry.CompleteProxyActivity(activity, context, "backend_a");

        if (activity.Duration <= TimeSpan.Zero || activity.Status != ActivityStatusCode.Error ||
            activity.GetTagItem("gateway.destination.id") as string != "backend_a" ||
            stopped.Count != 1 || !ReferenceEquals(stopped.Single(), activity))
            throw new InvalidOperationException("Proxy telemetry completion must tag and stop its activity once");

        Console.WriteLine("PASS: proxy telemetry activity is tagged and stopped once");
        VerifyConfigurationReloadNotifications();
    }

    private static void VerifyConfigurationReloadNotifications()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["fixture"] = "initial" })
            .Build();
        long observed = 0;
        var observedTags = -1;
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, current) =>
        {
            if (instrument.Meter.Name == GatewayOpenTelemetry.ActivitySourceName &&
                instrument.Name == "gateway.configuration.reload_notifications")
                current.EnableMeasurementEvents(instrument);
        };
        listener.SetMeasurementEventCallback<long>((_, value, tags, _) =>
        {
            Interlocked.Add(ref observed, value);
            Volatile.Write(ref observedTags, tags.Length);
        });
        listener.Start();

        using (GatewayOpenTelemetry.WatchConfigurationReloads(configuration))
        {
            configuration.Reload();
            if (Interlocked.Read(ref observed) != 1 || Volatile.Read(ref observedTags) != 0)
                throw new InvalidOperationException("A real configuration reload must emit exactly one identity-free notification");
        }

        configuration.Reload();
        if (Interlocked.Read(ref observed) != 1)
            throw new InvalidOperationException("Disposed configuration reload telemetry must stop observing changes");
        Console.WriteLine("PASS: configuration reload notifications are counted without labels and stop on disposal");
    }
}
