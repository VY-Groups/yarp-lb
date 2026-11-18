using System.Text.Json;

/// <summary>Durable sender epoch/sequence; increment is persisted before use.</summary>
internal sealed class AgentReportSequenceState : IDisposable
{
    private sealed record State(int Version, long Epoch, long Sequence);
    private readonly string path;
    private readonly object gate = new();
    private long epoch;
    private long sequence;
    private readonly FileStream stateLock;

    public AgentReportSequenceState(string path)
    {
        if (!Path.IsPathFullyQualified(path))
            throw new InvalidDataException("Agent report sequence path must be absolute");
        this.path = path;
        stateLock = AcquireStateLock(path);
        try
        {
            State previous;
            if (File.Exists(path))
            {
                EnsurePrivateFile(path);
                if (new FileInfo(path).Length > 1024)
                    throw new InvalidDataException("Persisted agent sequence state exceeds its storage bound");
                previous = JsonSerializer.Deserialize<State>(File.ReadAllBytes(path))
                    ?? throw new InvalidDataException("Malformed persisted agent epoch");
                if (previous.Version != 1 || previous.Epoch < 0 || previous.Sequence < 0)
                    throw new InvalidDataException("Invalid persisted agent epoch or sequence");
            }
            else previous = new State(1, 0, 0);
            if (previous.Epoch == long.MaxValue)
                throw new InvalidDataException("Agent epoch exhausted; re-enroll with a new identity");
            epoch = previous.Epoch + 1;
            sequence = 0;
            Persist();
        }
        catch { stateLock.Dispose(); throw; }
    }

    public (long Epoch, long Sequence) Next()
    {
        lock (gate)
        {
            if (sequence == long.MaxValue)
                throw new InvalidDataException("Agent sequence exhausted; restart with a new epoch");
            sequence++;
            Persist();
            return (epoch, sequence);
        }
    }

    private void Persist()
    {
        var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            var bytes = JsonSerializer.SerializeToUtf8Bytes(new State(1, epoch, sequence));
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write,
                FileShare.None, 1024, FileOptions.WriteThrough))
            {
                if (!OperatingSystem.IsWindows())
                    File.SetUnixFileMode(temporary, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                stream.Write(bytes);
                stream.Flush(flushToDisk: true);
            }
            File.Move(temporary, path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }

    private static FileStream AcquireStateLock(string path)
    {
        var parent = Path.GetDirectoryName(path)!;
        var existed = Directory.Exists(parent);
        Directory.CreateDirectory(parent);
        if (!OperatingSystem.IsWindows())
        {
            if (!existed) File.SetUnixFileMode(parent, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            GatewayCore.Gslb.Contracts.PrivateKeyFileSecurity.ValidateLinuxPrivateStateDirectory(
                parent, "Agent sequence state");
        }
        EnsureNotLink(path);
        var lockPath = path + ".lock";
        EnsureNotLink(lockPath);
        GatewayCore.Gslb.Contracts.PrivateKeyFileSecurity.ValidateLinuxPrivateStateFile(
            path, "Agent sequence state file");
        GatewayCore.Gslb.Contracts.PrivateKeyFileSecurity.ValidateLinuxPrivateStateFile(
            lockPath, "Agent sequence lock file");
        var stream = new FileStream(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(lockPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        return stream;
    }

    private static void EnsurePrivateFile(string file)
    {
        EnsureNotLink(file);
        if (!OperatingSystem.IsWindows() &&
            (File.GetUnixFileMode(file) & (UnixFileMode.GroupRead | UnixFileMode.GroupWrite |
             UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherWrite |
             UnixFileMode.OtherExecute)) != 0)
            throw new InvalidDataException("Agent sequence file must be private to the service account");
    }

    private static void EnsureNotLink(string file)
    {
        var info = new FileInfo(file);
        if (info.LinkTarget is not null || (info.Exists &&
            (File.GetAttributes(file) & FileAttributes.ReparsePoint) != 0))
            throw new InvalidDataException("Agent sequence path cannot be a symbolic link or reparse point");
    }

    public void Dispose() => stateLock.Dispose();
}
