static void Check(bool condition, string description)
{
    if (!condition) throw new Exception("FAILED: " + description);
    Console.WriteLine("PASS: " + description);
}
const string thumb = "0123456789abcdef0123456789abcdef01234567";
Check(BackendMutualTls.TryNormalizeThumbprint(thumb, out var uppercase) &&
    uppercase == thumb.ToUpperInvariant(), "lowercase certificate SHA1 normalized");
Check(BackendMutualTls.TryNormalizeThumbprint(
    "01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67",
    out var separated) && separated == uppercase, "separated thumbprint normalized");
Check(!BackendMutualTls.TryNormalizeThumbprint("", out _), "empty cert thumbprint rejected");
Check(!BackendMutualTls.TryNormalizeThumbprint("ZZ" + thumb[2..], out _), "non-hex thumbprint rejected");
Check(!BackendMutualTls.TryNormalizeThumbprint(thumb[..^1], out _), "truncated thumbprint rejected");
Console.WriteLine("BACKEND MTLS CONFIG CONTRACT TESTS PASSED");
