#!/usr/bin/env python3
"""CI-only synthetic WAF container resource-counter contract tests."""
import copy
import unittest
import docker_resource_sample as stats

CID = "a" * 64


def sample(cpu, mem=42_000_000, timestamp=1):
    return {"schemaVersion": 1, "container": CID, "cpuNanoseconds": cpu,
            "memoryBytes": mem, "observedAtMonotonicNs": timestamp}


def bench(phase="blocking"):
    return {"phase": phase, "complete": True, "requests": 120,
            "successes": 120, "elapsedSeconds": 4.8}


class ResourceContractTests(unittest.TestCase):
    def test_exact_bracketed_cpu_and_memory(self):
        result = stats.summarize(sample(1_000_000_000), sample(
            1_600_000_000, 45_000_000, 5), "blocking", bench())
        self.assertEqual(result["wafCpuSeconds"], 0.6)
        self.assertEqual(result["wafCpuMillisecondsPerRequest"], 5.0)
        self.assertEqual(result["wafMemoryStartBytes"], 42_000_000)
        self.assertEqual(result["wafMemoryEndBytes"], 45_000_000)
        self.assertIsNone(result["managedAllocationsBytes"])
        self.assertNotIn(CID, str(result))
        self.assertIn("synthetic-disposable", result["scope"])

    def test_idle_direct_waf_zero_cpu_is_not_fake_failure(self):
        report = stats.summarize(sample(100), sample(100, 42000000, 2),
                                 "direct", bench("direct"))
        self.assertEqual(report["wafCpuSeconds"], 0)

    def test_invalid_snapshot_container_mismatch_or_counter_reset(self):
        good = sample(300, timestamp=2)
        invalids = [
            (sample(500), good),
            (sample(100), sample(200, timestamp=1)),
            (sample(100), {**good, "container": "b" * 64}),
            (sample(100), {**good, "memoryBytes": 0}),
            ({**sample(100), "schemaVersion": True}, good),
            ({**sample(100), "unexpected": 1}, good),
            ({**sample(100), "cpuNanoseconds": -1}, good),
            ({**sample(100), "cpuNanoseconds": 100.5}, good),
        ]
        for before, after in invalids:
            with self.subTest(before=before, after=after), self.assertRaises(ValueError):
                stats.summarize(before, after, "blocking", bench())

    def test_unmatched_or_failed_benchmark_is_not_resource_acceptance(self):
        failures = [
            {**bench(), "phase": "direct"},
            {**bench(), "complete": False},
            {**bench(), "successes": 119},
            {**bench(), "requests": 0},
            {**bench(), "elapsedSeconds": 0},
        ]
        for failed in failures:
            with self.subTest(failed=failed), self.assertRaises(ValueError):
                stats.summarize(sample(100), sample(200, timestamp=2),
                                "blocking", failed)
        with self.assertRaises(ValueError):
            stats.summarize(sample(100), sample(200, timestamp=2),
                            "unapproved", bench())

    def test_rejects_short_container_id_and_bool_counters(self):
        self.assertIsNone(stats.CONTAINER_ID.fullmatch("abc123"))
        with self.assertRaises(ValueError):
            stats.summarize({**sample(100), "memoryBytes": True},
                            sample(200, timestamp=2), "blocking", bench())


if __name__ == "__main__":
    unittest.main()
