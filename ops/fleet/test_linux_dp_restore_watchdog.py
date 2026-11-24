"""Real process and fault-injection contract for pinned DP quorum watchdog."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

import linux_dp_restore_watchdog as watchdog


class Authority:
    def __init__(self, revoke_after=None, remaining=60.0):
        self.calls = []
        self.revoke_after = revoke_after
        self.remaining = remaining

    def remaining_seconds(self):
        return self.remaining

    def current(self, phase):
        self.calls.append(phase)
        return self.revoke_after is None or len(self.calls) < self.revoke_after


class RealRestoreSupervisorTests(unittest.TestCase):
    def setUp(self):
        handle = tempfile.TemporaryDirectory(prefix="dp-watchdog-")
        self.addCleanup(handle.cleanup)
        self.root = Path(handle.name)
        self.root.chmod(0o700)
        self.env = {"PATH": "/usr/bin:/bin"}

    def run_code(self, source, fence=None, limit=12.0, proof=None):
        return watchdog.run_fenced_restore(
            [sys.executable, "-c", source], self.env,
            fence or Authority(),
            proof or (lambda: True), limit)

    def test_real_success_requires_pre_and_post_quorum(self):
        fence = Authority()
        self.assertEqual(self.run_code("pass", fence), 0)
        self.assertGreaterEqual(fence.calls.count("before-signed-restore"), 1)
        self.assertEqual(fence.calls[-1], "after-signed-restore")

    def test_missing_quorum_refused_before_creating_child(self):
        sentinel = self.root/"should-not-run"
        fence = Authority(revoke_after=1)
        with self.assertRaises(ValueError):
            self.run_code(
                "from pathlib import Path; Path(" +
                repr(str(sentinel)) + ").write_text('not allowed')",
                fence)
        self.assertFalse(sentinel.exists())
        self.assertEqual(fence.calls, ["before-signed-restore"])

    def test_expired_runway_refused_before_spawn(self):
        sentinel = self.root/"should-not-run"
        with self.assertRaises(ValueError):
            self.run_code(
                "from pathlib import Path; Path(" +
                repr(str(sentinel)) + ").write_text('not allowed')",
                Authority(remaining=watchdog.MIN_RUNWAY_SECONDS))
        self.assertFalse(sentinel.exists())

    def test_receipt_invalid_before_spawn_refused(self):
        sentinel = self.root/"should-not-run"
        with self.assertRaises(ValueError):
            self.run_code(
                "from pathlib import Path; Path(" +
                repr(str(sentinel)) + ").write_text('not allowed')",
                proof=lambda: False)
        self.assertFalse(sentinel.exists())

    def test_live_revocation_kills_real_child_before_it_writes(self):
        marker = self.root/"unauthorized-after-revocation"
        code = ("import time; from pathlib import Path; time.sleep(3); " +
                "Path(" + repr(str(marker)) + ").write_text('wrong')")
        fence = Authority(revoke_after=2)
        begun = time.monotonic()
        with self.assertRaises(ValueError):
            self.run_code(code, fence)
        self.assertLess(time.monotonic() - begun, 2.75)
        # Give an orphaned child a chance to prove that cancellation failed.
        time.sleep(2.3)
        self.assertFalse(marker.exists(),
                         "revoked subprocess must not outlive authority")

    def test_real_subprocess_nonzero_exit_refused(self):
        with self.assertRaises(ValueError):
            self.run_code("raise SystemExit(7)")

    def test_bounded_deadline_kills_real_running_child(self):
        marker = self.root/"unauthorized-after-timeout"
        code = ("import time; from pathlib import Path; time.sleep(2); " +
                "Path(" + repr(str(marker)) + ").write_text('wrong')")
        with self.assertRaises(ValueError):
            self.run_code(code, limit=.25)
        time.sleep(2.1)
        self.assertFalse(marker.exists(), "timed-out .NET process kept running")

    def test_blocking_real_quorum_read_cannot_keep_restore_running(self):
        # A partitioned member may hang inside sequential HTTPS reads.
        # The parent must kill the child by a fixed independent deadline,
        # not block waiting for all TLS and etcd socket timeouts.
        marker = self.root/"stale-partition-process-wrote"
        code = ("import time; from pathlib import Path; time.sleep(1.3); " +
                "Path(" + repr(str(marker)) + ").write_text('wrong')")

        class SlowAuthority(Authority):
            def current(self, phase):
                self.calls.append(phase)
                if len(self.calls) >= 2:
                    time.sleep(4)
                return True

        fence = SlowAuthority()
        with mock.patch.object(watchdog, "ATTEST_TIMEOUT_SECONDS", .2), \
             mock.patch.object(watchdog, "CHECK_INTERVAL", .2):
            started = time.monotonic()
            with self.assertRaises(ValueError):
                self.run_code(code, fence, limit=10)
            self.assertLess(time.monotonic() - started, 1.0)
        time.sleep(1.3)
        self.assertFalse(marker.exists(),
                         "TLS/etcd timeout left signed restore running")
        self.assertGreaterEqual(len(fence.calls), 2)

    def test_escaped_child_cannot_outlive_successful_direct_restore(self):
        # A helper whose parent exits normally is still in the restore
        # session/process group. Neither success nor failure may allow that
        # helper to continue writing after receipt validation.
        marker = self.root/"orphan-after-parent-success"
        helper = ("import time; from pathlib import Path; time.sleep(1); " +
                  "Path(" + repr(str(marker)) + ").write_text('wrong')")
        parent = ("import subprocess,sys;subprocess.Popen(" +
                  "[sys.executable,'-c'," + repr(helper) + "])")
        self.assertEqual(self.run_code(parent), 0)
        time.sleep(1.25)
        self.assertFalse(marker.exists(),
                         "direct restore exit left descendant key writer alive")

    def test_missing_or_nonfinite_lease_is_fail_closed(self):
        for value in (0, -1, float("nan"), float("inf")):
            with self.subTest(remaining=value):
                with self.assertRaises(ValueError):
                    self.run_code("pass", Authority(remaining=value))


if __name__ == "__main__":
    unittest.main()
