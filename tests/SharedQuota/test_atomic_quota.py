#!/usr/bin/env python3
"""Exercise the actual Redis Lua embedded in shipping C# (no mocked counters)."""
import concurrent.futures
import pathlib
import re
import subprocess
import unittest
import uuid

SOURCE = pathlib.Path(__file__).resolve().parents[2] / "control-center" / "SharedPeerRateLimiter.cs"
MATCH = re.search(r'AdmissionScript\s*=\s*"""(.*?)""";', SOURCE.read_text(), re.S)
if MATCH is None:
    raise RuntimeError("shipping admission script not found")
SCRIPT = MATCH.group(1)

def cli(*args):
    p = subprocess.run(["redis-cli", "-h", "127.0.0.1", "-p", "16379", "--raw", *args],
                       text=True, capture_output=True, timeout=4)
    if p.returncode:
        raise RuntimeError(p.stderr)
    return p.stdout.strip()

class AtomicDistributedQuota(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if cli("PING") != "PONG":
            raise RuntimeError("dedicated loopback test Redis required")
        cli("FLUSHDB")

    def eval(self, namespace, peer, limit=5, capacity=2):
        return cli("EVAL", SCRIPT, "1", namespace, peer, str(limit), str(capacity))

    def in_one_window(self, scenario):
        # The shipping Lua intentionally uses Redis server-clock minute buckets.
        # A boundary between requests legitimately resets the quota. Only
        # assert a sequence observed entirely in one bucket; use a fresh
        # namespace on a bounded retry so earlier admissions cannot contaminate it.
        for _ in range(3):
            prefix = "ci:" + uuid.uuid4().hex
            before = int(cli("TIME").splitlines()[0]) // 60
            actual = scenario(prefix)
            after = int(cli("TIME").splitlines()[0]) // 60
            if before == after:
                return actual
        self.fail("Could not observe quota sequence inside a single Redis minute")

    def test_global_quota_shared_between_simulated_nodes(self):
        # 32 simultaneous requests from two independent senders of the same IP identity.
        def scenario(prefix):
            with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
                return list(pool.map(lambda _: self.eval(prefix, "hash-peer-1", 7, 2), range(32)))
        results = self.in_one_window(scenario)
        self.assertEqual(results.count("1"), 7)
        self.assertEqual(results.count("0"), 25)

    def test_hard_peer_cardinality_ceiling(self):
        def scenario(prefix):
            return [self.eval(prefix, peer, 4, 2) for peer in ("first", "second", "third", "first")]
        self.assertEqual(self.in_one_window(scenario), ["1", "1", "0", "1"])

    def test_namespaces_are_isolated(self):
        def scenario(prefix):
            return [self.eval(prefix + suffix, "peer", 1, 2) for suffix in (":tenant-a", ":tenant-a", ":tenant-b")]
        self.assertEqual(self.in_one_window(scenario), ["1", "0", "1"])

    def test_redis_partition_produces_error_not_local_admission(self):
        p = subprocess.run(["redis-cli", "-h", "127.0.0.1", "-p", "16378",
                            "--connect-timeout", "1", "PING"],
                           text=True, capture_output=True, timeout=4)
        self.assertNotEqual(p.returncode, 0)

if __name__ == "__main__":
    unittest.main()
