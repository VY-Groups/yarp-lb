from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "ec2-real-control-center.yml"


class WorkflowSafetyContract(unittest.TestCase):
    def test_triggers_and_readonly_scopes(self):
        content = WORKFLOW.read_text(encoding="utf-8")
        self.assertRegex(content, r"(?m)^  workflow_dispatch:\s*$")
        self.assertRegex(content, r"(?m)^  schedule:\s*$")
        for forbidden in ("push:", "pull_request:", "pull_request_target:",
                          "repository_dispatch:", "workflow_run:", "issue_comment:"):
            self.assertNotRegex(content, r"(?m)^  " + re.escape(forbidden))
        self.assertRegex(content, r"(?m)^permissions:\s*\n  contents: read$")
        self.assertIn("cancel-in-progress: false", content)
        self.assertIn("group: ec2-control-center-live-readonly", content)
        self.assertIn("vars.BACKEND_A_HOST", content)
        self.assertIn("vars.BACKEND_B_HOST", content)
        self.assertNotIn("secrets.", content)
        self.assertNotIn("aws-actions/", content)
        self.assertNotRegex(content.lower(), r"ssh\s|ssh-action|scp-action")
        self.assertIn("if: always()", content)
        self.assertIn("dotnet build control-center/SpeedSignYarp.csproj", content)
        self.assertNotIn("GatewayLab", content)

    def test_budget_and_timeout_are_failclosed(self):
        source = (Path(__file__).with_name("ec2_functional.py")).read_text()
        self.assertIn("REQUEST_CAP = 8000", source)
        self.assertIn("TEST_CAP = 1000", source)
        self.assertIn("MAX_CONCURRENCY = 8", source)
        self.assertIn("MAX_REQUEST_SECONDS = 15", source)
        self.assertIn("BACKEND_UNREACHABLE:", source)
        self.assertIn("T6_weight_change", source)


if __name__ == "__main__":
    unittest.main()
