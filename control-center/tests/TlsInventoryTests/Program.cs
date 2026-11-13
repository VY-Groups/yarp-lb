var now = new DateTime(2026,11,13,12,0,0,DateTimeKind.Utc);
if (TlsInventory.ExpiryState(now.AddDays(-1),now) != "expired") throw new Exception("expired state");
if (TlsInventory.ExpiryState(now.AddDays(10),now) != "expiring-within-30-days") throw new Exception("warning state");
if (TlsInventory.ExpiryState(now.AddDays(60),now) != "valid-date-only") throw new Exception("valid state");
Console.WriteLine("PASS: TLS certificate expiry boundaries");
