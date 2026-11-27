using System.Security.Principal;
using System.ServiceProcess;

// CI-only executable, never compiled into the shipping gateway.
if (!OperatingSystem.IsWindows() ||
    args.Length != 5 ||
    args[0] is not ("GatewayCoreVipFenceProvider" or "GatewayCoreVipController"))
    return 78;
ServiceBase.Run(new RoleProbe(args));
return 0;

sealed class RoleProbe : ServiceBase
{
    private readonly string[] options;
    internal RoleProbe(string[] options)
    {
        this.options = options;
        ServiceName = options[0];
    }
    protected override void OnStart(string[] args)
    {
        var name = options[0];
        var expectedSid = options[1];
        var own = options[2];
        var peer = options[3];
        var result = options[4];
        string outcome;
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            if (identity.User?.Value != expectedSid)
                throw new InvalidOperationException("Service identity mismatch");
            using (var stream = File.Open(own, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                if (stream.Length == 0) throw new InvalidOperationException("Own credential empty");
            bool denied = false;
            try { using var stream = File.Open(peer, FileMode.Open, FileAccess.Read, FileShare.ReadWrite); }
            catch (UnauthorizedAccessException) { denied = true; }
            if (!denied) throw new InvalidOperationException("Peer credential accessible");
            outcome = "PASS " + name + " " + expectedSid;
        }
        catch (Exception error)
        {
            outcome = "FAIL " + name + " " + error.GetType().Name;
        }
        using var file = new FileStream(result, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
        using var writer = new StreamWriter(file);
        writer.Write(outcome);
    }
}
