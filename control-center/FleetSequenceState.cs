using System.Globalization;
using System.Text;

/// <summary>
/// Monotonic per-controller/per-agent revision counter, independent of config rollbacks.
/// Lock externally around read/modify/write; this is a single-process state store, not
/// a multi-controller consensus service. Protect the state file with OS ACLs.
/// </summary>
public static class FleetSequenceState
{
    public static long Read(string path)
    {
        if (!File.Exists(path)) return 0;
        var data = File.ReadAllText(path, Encoding.ASCII).Trim();
        if (!long.TryParse(data, NumberStyles.None, CultureInfo.InvariantCulture, out var sequence) ||
            sequence < 1)
            throw new InvalidDataException("Signed rollout sequence state invalid; fail closed.");
        return sequence;
    }

    public static long AllocateNext(string path)
    {
        var next = checked(Read(path) + 1);
        Write(path, next);
        return next;
    }

    public static void Accept(string path, long incoming)
    {
        if (incoming < 1 || incoming <= Read(path))
            throw new InvalidOperationException("Stale or replayed signed config sequence.");
        Write(path, incoming);
    }

    private static void Write(string path, long sequence)
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(path))!;
        Directory.CreateDirectory(directory);
        var temp = Path.Combine(directory, ".fleet-seq-" + Guid.NewGuid().ToString("N"));
        try
        {
            using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                var bytes = Encoding.ASCII.GetBytes(sequence.ToString(CultureInfo.InvariantCulture) + "\n");
                stream.Write(bytes);
                stream.Flush(flushToDisk: true);
            }
            File.Move(temp, path, true);
        }
        finally { if (File.Exists(temp)) File.Delete(temp); }
    }
}
