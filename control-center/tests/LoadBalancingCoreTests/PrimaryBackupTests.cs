public static class PrimaryBackupTests
{
    public static void Run()
    {
        static void Verify(bool condition, string title)
        {
            if (!condition) throw new Exception("FAIL: " + title);
            Console.WriteLine("PASS: " + title);
        }
        Verify(PrimaryBackupCore.TryBackupRole(null, out var missing) && !missing,
            "unconfigured destinations are primaries, preserving all existing routes");
        Verify(PrimaryBackupCore.TryBackupRole("primary", out var primary) && !primary,
            "primary role recognized");
        Verify(PrimaryBackupCore.TryBackupRole("backup", out var backup) && backup,
            "explicit backup role recognized");
        Verify(PrimaryBackupCore.TryBackupRole("BACKUP", out var upper) && upper,
            "backup role case-insensitive without broad parsing");
        foreach (var invalid in new[]{"", "secondary", " standby", "backup ", "yes", "primary/backup"})
            Verify(!PrimaryBackupCore.TryBackupRole(invalid, out _),
                "invalid backend role rejected: " + invalid);

        var healthy = new int[]{80,20,0}; // zero is drained/unavailable or backup
        Verify(PrimaryBackupCore.PrimaryWeightTotal(healthy)==100,
            "backup or drained candidate never consumes a primary ticket");
        var counts=new int[3];
        for (var ticket=0;ticket<100;ticket++)
        {
            var chosen=PrimaryBackupCore.PickPrimaryIndex(healthy,ticket);
            counts[chosen]++;
        }
        Verify(counts[0]==80 && counts[1]==20 && counts[2]==0,
            "weighted active primaries preserve exact 80/20 ticket coverage");
        Verify(PrimaryBackupCore.PickPrimaryIndex(new int[]{0,0},0)==-1,
            "no available primary activates explicit fallback selector");
        Verify(PrimaryBackupCore.PickPrimaryIndex(new int[]{1,0,0},0)==0,
            "single available primary always preferred over backups");
        foreach (var invalid in new[]{-1,101,int.MaxValue})
        {
            var rejected=false;
            try { PrimaryBackupCore.PrimaryWeightTotal(new int[]{10,invalid}); }
            catch(ArgumentOutOfRangeException) { rejected=true; }
            Verify(rejected,"invalid active weight fails closed "+invalid);
        }
        foreach (var ticket in new[]{-1,100,int.MaxValue})
        {
            var rejected=false;
            try { PrimaryBackupCore.PickPrimaryIndex(healthy,ticket); }
            catch(ArgumentOutOfRangeException) { rejected=true; }
            Verify(rejected, "out-of-bounds uniform ticket refused " + ticket);
        }
        Span<int> noStale = stackalloc int[40];
        noStale.Fill(70);
        noStale.Clear();
        Verify(PrimaryBackupCore.PrimaryWeightTotal(noStale)==0,
            "stack-allocated candidate weights require explicit initialization");
    }
}
