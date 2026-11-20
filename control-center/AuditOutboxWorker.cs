internal sealed class AuditOutboxWorker(DurableAuditOutbox outbox, ILogger<AuditOutboxWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(2));
        bool previouslyBlocked = false;
        try
        {
            do
            {
                // Bounded batch, no network I/O on the local audit writer or proxy thread.
                for (int i = 0; i < 16 && !stoppingToken.IsCancellationRequested; i++)
                    if (!await outbox.DeliverOneAsync(stoppingToken)) break;
                var status = outbox.Status();
                bool blocked = status.StorageFault || status.DeliveryBlocked;
                if (blocked && !previouslyBlocked)
                    logger.LogWarning("External audit delivery blocked; inspect authenticated audit delivery status");
                else if (!blocked && previouslyBlocked)
                    logger.LogInformation("External audit delivery no longer blocked");
                previouslyBlocked = blocked;
            } while (await timer.WaitForNextTickAsync(stoppingToken));
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
    }
}
