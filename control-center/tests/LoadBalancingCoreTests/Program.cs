using System;
using System.Linq;
using System.Collections.Generic;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

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
Check(LoadBalancingCore.TrySlowStartSeconds(null, out var ss0) && ss0 == 0, "slow-start disabled by default");
Check(LoadBalancingCore.TrySlowStartSeconds("600", out var ss600) && ss600 == 600, "slow-start maximum");
foreach (var invalid in new [] { "-1", "601", "1.5", "n/a" })
    Check(!LoadBalancingCore.TrySlowStartSeconds(invalid, out _), "slow-start rejects " + invalid);
Check(LoadBalancingCore.RampedWeight(80, 0, 10) == 1, "warmup first weight");
Check(LoadBalancingCore.RampedWeight(80, 5, 10) == 40, "warmup midway");
Check(LoadBalancingCore.RampedWeight(80, 10, 10) == 80, "warmup complete");
Check(LoadBalancingCore.RampedWeight(80, 0, 0) == 80, "warmup disabled");
// Characterization BEFORE claiming lower allocations: keep a copied original
// oracle strictly inside tests. The production result must match byte-for-byte
// for Unicode identities, long names, weights, and destination ordering.
static int OriginalRendezvous(string key, IReadOnlyList<string> ids, IReadOnlyList<int> weights)
{
    if (string.IsNullOrEmpty(key)) throw new ArgumentException(nameof(key));
    if (ids.Count != weights.Count) throw new ArgumentException("Lengths differ");
    var best=double.PositiveInfinity;
    var bestIndex=-1;
    for (var i=0; i<ids.Count; i++)
    {
        if (weights[i] is < 1 or > 100 || string.IsNullOrEmpty(ids[i]))
            throw new ArgumentOutOfRangeException(nameof(weights));
        var bytes=SHA256.HashData(Encoding.UTF8.GetBytes(key+"\\u001f"+ids[i]));
        var hash=BinaryPrimitives.ReadUInt64BigEndian(bytes.AsSpan(0,8));
        var u=Math.Clamp((hash+0.5)/18446744073709551616.0,double.Epsilon,Math.BitDecrement(1.0));
        var score=-Math.Log(u)/weights[i];
        if(score<best || (score==best && (bestIndex<0 ||
            string.CompareOrdinal(ids[i],ids[bestIndex])<0)))
        {best=score;bestIndex=i;}
    }
    return bestIndex;
}
var candidateIds = new[]{ "gw-a", "gw-🔥-b", "bravo-gateway-" + new string('é',450), "edge/3" };
var candidateWeights = new[]{ 1,5,100,11 };
var keys=Enumerable.Range(0,2000).Select(i=>"src:" + i + "-東京-🛡️").ToArray();
foreach(var key in keys)
    Check(OriginalRendezvous(key,candidateIds,candidateWeights) ==
          LoadBalancingCore.PickRendezvousIndex(key,candidateIds,candidateWeights),
          "rendezvous exact legacy hash and tie semantics "+key);
for(var i=0;i<1000;i++)
{
    OriginalRendezvous(keys[i],candidateIds,candidateWeights);
    LoadBalancingCore.PickRendezvousIndex(keys[i],candidateIds,candidateWeights);
}
const int runs=10_000;
GC.Collect();GC.WaitForPendingFinalizers();GC.Collect();
var before=GC.GetAllocatedBytesForCurrentThread();
for(var i=0;i<runs;i++) _=OriginalRendezvous(keys[i%keys.Length],candidateIds,candidateWeights);
var legacyBytes=GC.GetAllocatedBytesForCurrentThread()-before;
before=GC.GetAllocatedBytesForCurrentThread();
for(var i=0;i<runs;i++) _=LoadBalancingCore.PickRendezvousIndex(keys[i%keys.Length],candidateIds,candidateWeights);
var optimizedBytes=GC.GetAllocatedBytesForCurrentThread()-before;
Console.WriteLine($"RENDEZVOUS_ALLOCATION_COMPARE iterations={runs} legacy={legacyBytes} optimized={optimizedBytes} legacy_per_pick={(double)legacyBytes/runs:F1} optimized_per_pick={(double)optimizedBytes/runs:F1}");
Check(optimizedBytes < legacyBytes/2, "rendezvous helper allocations cut by >50% in warmed synchronous comparison");
Console.WriteLine($"PASS: all offline algorithm tests. Remapped {moves}/2000; weighted favored B {skew}/2000.");
