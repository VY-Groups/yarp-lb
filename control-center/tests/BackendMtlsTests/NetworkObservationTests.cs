internal static class NetworkObservationTests
{
    internal static void Run()
    {
        static void Must(bool ok, string label)
        {
            if (!ok) throw new Exception("Network observation: " + label);
            Console.WriteLine("PASS: " + label);
        }
        const string header = "VLAN Dev name | VLAN ID\nName-Type: VLAN_NAME_TYPE_RAW_PLUS_VID_NO_PAD\n";
        var observed = NetworkObservation.ParseVlans(header + "eth0.12 | 12 | eth0\neth0.4094 | 4094 | eth0\n");
        Must(observed.Status == "observed" && observed.Interfaces.Length == 2 &&
             observed.Interfaces[0].Parent == "eth0" && observed.Interfaces[0].VlanId == 12,
             "kernel VLAN rows parsed without name inference");
        Must(NetworkObservation.ParseVlans(header).Status == "observed", "empty kernel inventory distinguished from unavailable");
        Must(NetworkObservation.ParseVlans(header + "eth0.1 | 4095 | eth0").Status == "invalid-kernel-inventory", "reserved VLAN rejected");
        Must(NetworkObservation.ParseVlans(header + "vlan | 1 | eth0\nvlan | 2 | eth1").Status == "invalid-kernel-inventory", "duplicate VLAN rejected");
        Must(NetworkObservation.ParseVlans(new string('x',65537)).Status == "truncated", "bounded VLAN input");
        var row = new LocalNetworkInventory.InterfaceRow("fixture","eth0","Ethernet","Up",
            [new("192.0.2.10",24),new("2001:db8::10",64)],[],false);
        var snapshot = new LocalNetworkInventory.Snapshot("fixture","Linux",DateTimeOffset.UnixEpoch,[row],false);
        Must(NetworkObservation.ObserveVirtualAddress("a","192.0.2.10",443,"HTTPS",snapshot).Status == "present-interface-up", "local IPv4 address present");
        Must(NetworkObservation.ObserveVirtualAddress("a","2001:0db8::10",443,"HTTPS",snapshot).Status == "present-interface-up", "canonical IPv6 comparison");
        Must(NetworkObservation.ObserveVirtualAddress("a","192.0.2.11",443,"HTTPS",snapshot).Status == "not-observed-locally", "absent address distinguished");
        Must(NetworkObservation.ObserveVirtualAddress("a","192.0.2.11",443,"HTTPS",snapshot with { Truncated=true }).Status == "unknown-truncated", "incomplete snapshot cannot prove absence");
        Must(NetworkObservation.ObserveVirtualAddress("a","192.0.2.10",443,"HTTPS",snapshot with { Interfaces=[row,row with { Name="eth1" }] }).Status == "multiple-local-interfaces", "duplicate local assignment reported");
        Must(NetworkObservation.ObserveVirtualAddress("a","192.0.2.10",443,"HTTPS",snapshot with { Interfaces=[row with { Status="Down" }] }).Status == "present-interface-not-up", "down interface distinguished");
    }
}
