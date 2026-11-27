// Privileged lifecycle orchestration is deliberately outside the gateway
// worker and its request path. All operations bind to the exact expected epoch.
internal static class VipNodeLifecycle
{
    internal static async Task Activate(long epoch,Func<long,CancellationToken,Task<bool>> owner,
        Func<CancellationToken,Task> reconcile,Func<CancellationToken,Task> start,
        Func<CancellationToken,Task<bool>> serving,Func<CancellationToken,Task> stop,
        Func<CancellationToken,Task> withdraw,CancellationToken token)
    {
        async Task AssertOwner()
        {
            token.ThrowIfCancellationRequested();
            if(!await owner(epoch,token))throw new InvalidDataException("Exact local VIP authority not confirmed.");
        }
        if(epoch<1)throw new InvalidDataException("Expected positive owner epoch required.");
        // No side effects at all for a request with stale or unknown ownership.
        await AssertOwner();
        bool touched=false;
        try
        {
            touched=true;
            await reconcile(token);
            await AssertOwner();
            await start(token);
            await AssertOwner();
            if(!await serving(token))throw new InvalidOperationException("Real VIP serving check failed.");
            await AssertOwner();
        }
        catch
        {
            if(touched)
            {
                // Do not let request cancellation suppress compensation.
                using var stopDeadline=new CancellationTokenSource(TimeSpan.FromSeconds(30));
                try{await stop(stopDeadline.Token);}
                finally
                {
                    using var withdrawDeadline=new CancellationTokenSource(TimeSpan.FromSeconds(30));
                    await withdraw(withdrawDeadline.Token);
                }
            }
            throw;
        }
    }
    internal static async Task StopAndWithdraw(Func<CancellationToken,Task> stop,
        Func<CancellationToken,Task> withdraw,CancellationToken token)
    {
        try{await stop(token);}
        finally
        {
            using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(30));
            await withdraw(deadline.Token);
        }
    }
}
