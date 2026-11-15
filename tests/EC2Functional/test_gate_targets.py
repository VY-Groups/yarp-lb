"""Executable contracts for the optional EC2 live-backend gate (no network)."""
import os
import pathlib
import subprocess
import tempfile
import unittest

GATE = pathlib.Path(__file__).with_name("gate_targets.sh")


class TargetGateTests(unittest.TestCase):
    def run_gate(self, event, host_a="", host_b=""):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            output = root / "output"
            summary = root / "summary"
            env = {
                **os.environ,
                "GITHUB_OUTPUT": "output",
                "GITHUB_STEP_SUMMARY": "summary",
                "GITHUB_EVENT_NAME": event,
                "BACKEND_A_HOST": host_a,
                "BACKEND_B_HOST": host_b,
            }
            proc = subprocess.run(["bash"], cwd=tmp, env=env,
                                  input=GATE.read_text(encoding="utf-8"),
                                  text=True, capture_output=True, check=False)
            return (
                proc,
                output.read_text() if output.exists() else "",
                summary.read_text() if summary.exists() else "",
                (root / "artifacts/ec2/not-tested.txt").exists(),
            )

    def test_schedule_without_targets_is_not_tested(self):
        proc, out, summary, sentinel = self.run_gate("schedule")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("enabled=false", out)
        self.assertIn("NOT TESTED", summary)
        self.assertTrue(sentinel)

    def test_schedule_with_one_target_is_not_tested(self):
        proc, out, summary, sentinel = self.run_gate("schedule", "host-a")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("enabled=false", out)
        self.assertTrue(sentinel)
        self.assertIn("NOT TESTED", summary)

    def test_manual_without_targets_fails_closed(self):
        proc, out, summary, sentinel = self.run_gate("workflow_dispatch")
        self.assertNotEqual(proc.returncode, 0)
        self.assertNotIn("enabled=true", out)
        self.assertTrue(sentinel)
        self.assertIn("NOT TESTED", summary)

    def test_two_targets_admit_preflight_without_claiming_success(self):
        proc, out, summary, sentinel = self.run_gate("workflow_dispatch", "host-a", "host-b")
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(out.strip(), "enabled=true")
        self.assertFalse(sentinel)
        self.assertNotIn("PASS", summary)


if __name__ == "__main__":
    unittest.main()
