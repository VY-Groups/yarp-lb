"""Prevent reintroducing a nightly integration run against deleted EC2 hosts."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/ec2-real-control-center.yml"
HARNESS = ROOT / "tests/EC2Functional/ec2_functional.py"
GUARD = ROOT / "control-center/Ec2WorkflowLab.cs"


class RetiredEc2ScheduleContracts(unittest.TestCase):
    def test_live_integration_is_manual_only(self):
        content = WORKFLOW.read_text(encoding="utf-8")
        self.assertRegex(content, r"(?m)^on:\s*$")
        self.assertRegex(content, r"(?m)^  workflow_dispatch:\s*$")
        self.assertNotRegex(content, r"(?m)^  schedule:\s*$")
        self.assertNotRegex(content, r"(?m)^  push:\s*$")
        self.assertNotRegex(content, r"(?m)^  pull_request:\s*$")

    def test_replacement_hosts_are_validated_before_live_traffic(self):
        py = HARNESS.read_text(encoding="utf-8")
        cs = GUARD.read_text(encoding="utf-8")
        self.assertIn("approved_ec2_host(a) and approved_ec2_host(b)", py)
        self.assertIn("IsApprovedEc2Host(a) || !IsApprovedEc2Host(b)", cs)
        self.assertIn("seenHosts.Count != 2", cs)
        for removed in (
            "ec2-3-108-65-15.ap-south-1.compute.amazonaws.com",
            "ec2-65-0-11-186.ap-south-1.compute.amazonaws.com",
        ):
            self.assertNotIn(removed, py)
            self.assertNotIn(removed, cs)


if __name__ == "__main__":
    unittest.main()
