internal static class GslbAgentReportStatusParserTests
{
    public static void Run()
    {
        const string valid = """{"type":"loopback-gslb-agent-report-status","checkedUtc":"2026-11-18T10:00:00+00:00","agents":[{"agentId":"agent-1","lastAcceptedUtc":"2026-11-18T09:59:00+00:00","lastAcceptedAgeSeconds":60,"rejectedTotal":1,"freshReports":2,"staleOrMissingReports":0},{"agentId":"agent-2","lastAcceptedUtc":null,"lastAcceptedAgeSeconds":null,"rejectedTotal":0,"freshReports":0,"staleOrMissingReports":2}]}""";
        if (!GslbAgentReportStatusParser.TryParse(valid, out var parsed) || parsed is null ||
            parsed.Agents.Count != 2 || parsed.Agents[0].AgentId != "agent-1" ||
            parsed.Agents[0].LastAcceptedAgeSeconds != 60 || parsed.Agents[1].LastAcceptedUtc is not null)
            throw new Exception("FAIL: valid bounded GSLB observer status summary rejected");

        static string Replace(string source, string oldValue, string newValue) =>
            source.Replace(oldValue, newValue, StringComparison.Ordinal);
        var duplicateId = Replace(valid, "\"agentId\":\"agent-2\"", "\"agentId\":\"agent-1\"");
        var invalidId = Replace(valid, "\"agentId\":\"agent-1\"", "\"agentId\":\"../agent\"");
        var secretField = Replace(valid, "\"agentId\":\"agent-1\"",
            "\"agentId\":\"agent-1\",\"clientIp\":\"203.0.113.10\"");
        var badAge = Replace(valid, "\"lastAcceptedAgeSeconds\":60", "\"lastAcceptedAgeSeconds\":-1");
        var inconsistent = Replace(valid, "\"lastAcceptedAgeSeconds\":null", "\"lastAcceptedAgeSeconds\":0");
        var tooManyAgents = "{\"type\":\"loopback-gslb-agent-report-status\",\"checkedUtc\":\"2026-11-18T10:00:00+00:00\",\"agents\":[" +
            string.Join(',', Enumerable.Range(0, 65).Select(index =>
                $"{{\"agentId\":\"agent-{index}\",\"lastAcceptedUtc\":null,\"lastAcceptedAgeSeconds\":null,\"rejectedTotal\":0,\"freshReports\":0,\"staleOrMissingReports\":0}}")) + "]}";
        if (GslbAgentReportStatusParser.TryParse(duplicateId, out _) ||
            GslbAgentReportStatusParser.TryParse(secretField, out _) ||
            GslbAgentReportStatusParser.TryParse(invalidId, out _) ||
            GslbAgentReportStatusParser.TryParse(badAge, out _) ||
            GslbAgentReportStatusParser.TryParse(inconsistent, out _) ||
            GslbAgentReportStatusParser.TryParse(valid + new string(' ', 16_384), out _) ||
            GslbAgentReportStatusParser.TryParse(tooManyAgents, out _))
            throw new Exception("FAIL: malformed, duplicate, secret-bearing or inconsistent GSLB status accepted");

        var maxAgentRows = Enumerable.Range(0, 64).Select(index => new
        {
            agentId = $"a{index:D2}" + new string('x', 61),
            lastAcceptedUtc = DateTimeOffset.UtcNow,
            lastAcceptedAgeSeconds = long.MaxValue,
            rejectedTotal = int.MaxValue,
            freshReports = 1024,
            staleOrMissingReports = 0
        });
        var maximumContract = System.Text.Json.JsonSerializer.Serialize(new
        {
            type = "loopback-gslb-agent-report-status",
            checkedUtc = DateTimeOffset.UtcNow,
            agents = maxAgentRows
        });
        if (System.Text.Encoding.UTF8.GetByteCount(maximumContract) > 16_384 ||
            !GslbAgentReportStatusParser.TryParse(maximumContract, out var maximumParsed) ||
            maximumParsed?.Agents.Count != 64)
            throw new Exception("FAIL: maximum bounded GSLB observer status exceeded the existing relay size limit");

        Console.WriteLine("PASS: bounded GSLB agent status parser rejects duplicate IDs, private fields and invalid counters");
    }
}
