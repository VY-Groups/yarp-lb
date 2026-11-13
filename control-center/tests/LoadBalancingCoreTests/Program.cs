using System;
using System.Linq;
using System.Collections.Generic;

static void Check(bool condition, string label)
{
    if (!condition) throw new Exception("FAIL: " + label);
    Console.WriteLine("PASS: " + label);
}

Check(LoadBalancingCore.TryWeight(null, out var missing) && missing == 1, "default weight");
Check(LoadBalancingCore.TryWeight("100", out var maximum) && maximum == 100, "max weight");
foreach (var invalid in new [] {"0", "101", "1.5", "-2", "oops", " 10"})
    Check(!LoadBalancingCore.TryWeight(invalid, out _), "reject invalid " + invalid);
var weights = new[] {1,3,6};
Check(LoadBalancingCore.PickWeightedIndex(weights,0) == 0, "ticket first bound");
Check(LoadBalancingCore.PickWeightedIndex(weights,1) == 1, "ticket second bound");
Check(LoadBalancingCore.PickWeightedIndex(weights,4) == 2, "ticket third bound");
Check(LoadBalancingCore.PickWeightedIndex(weights,9) == 2, "ticket last bound");
Check(LoadBalancingCore.PickWeightedIndex(Array.Empty<int>(),0) == -1, "empty set");
var weightedCounts = new []{0,0};
for (var ticket = 0; ticket < 100; ticket++)
    weightedCounts[LoadBalancingCore.PickWeightedIndex(new[]{80,20}, ticket)]++;
Check(weightedCounts[0] == 80 && weightedCounts[1] == 20, "weighted tickets give exact 80/20 coverage");
var ids2 = new [] { "gw-a", "gw-b" };
var ids3 = new [] { "gw-a", "gw-b", "gw-c" };
var w2 = new [] {1,1};
var w3 = new [] {1,1,1};
var moves = 0;
for(var i = 0; i < 2000; i++)
{
    var user = "client-"+i;
    var first = LoadBalancingCore.PickRendezvousIndex(user,ids2,w2);
    var second = LoadBalancingCore.PickRendezvousIndex(user,ids2,w2);
    if(first != second) throw new Exception("Unstable client hash: "+i);
    var increased = LoadBalancingCore.PickRendezvousIndex(user,ids3,w3);
    if (ids2[first] != ids3[increased]) moves++;
}
Check(moves > 300 && moves < 1000, "rendezvous remapping only a fraction when adding node");
var skew = 0;
for(var i = 0; i < 2000; i++)
{
    var result=LoadBalancingCore.PickRendezvousIndex("weighted-"+i, ids2, new[] {1,10});
    if(result == 1)skew++;
}
Check(skew > 1400, "weights bias rendezvous distribution");
Check(LoadBalancingCore.PickRendezvousIndex("user",Array.Empty<string>(),Array.Empty<int>()) == -1,"no destinations");
Console.WriteLine($"PASS: all offline algorithm tests. Remapped {moves}/2000; weighted favored B {skew}/2000.");
