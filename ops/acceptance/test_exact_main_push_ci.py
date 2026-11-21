"""Offline contract tests for exact-main push CI evidence (no GitHub credentials)."""
import importlib.util
import pathlib
import unittest
from unittest.mock import patch

SCRIPT = pathlib.Path(__file__).with_name("exact_main_push_ci.py")
spec = importlib.util.spec_from_file_location("exact_main_push_ci", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class EvidenceTests(unittest.TestCase):
    def test_exact_main_only_and_job_failure_retained(self):
        def fake(path, token):
            if "/actions/runs?" in path:
                return {"workflow_runs": [
                    {"id": 1, "head_sha": "a" * 40, "head_branch": "main",
                     "event": "push", "status": "completed", "conclusion": "success"},
                    {"id": 2, "head_sha": "a" * 40, "head_branch": "feature",
                     "event": "push"},
                    {"id": 3, "head_sha": "b" * 40, "head_branch": "main",
                     "event": "push"}]}
            return {"jobs": [{"id": 9, "status": "completed",
                              "conclusion": "failure",
                              "steps": [{"name": "Compile", "number": 4,
                                         "conclusion": "failure"}]}]}
        with patch.object(module, "get_json", side_effect=fake):
            rows = module.collect("VY-Groups/yarp-lb", "a" * 40, "fake")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["jobs"][0]["failed_steps"][0]["name"], "Compile")

    def test_malformed_api_collection_rejected(self):
        with patch.object(module, "get_json", return_value={"workflow_runs": [None]}):
            with self.assertRaisesRegex(ValueError, "Malformed"):
                module.paged("/repos/VY-Groups/yarp-lb/actions/runs", "fake")

    def test_invalid_run_id_rejected_before_jobs_query(self):
        with patch.object(module, "get_json", return_value={
            "workflow_runs": [{"id": -1, "head_sha": "a" * 40,
                               "head_branch": "main", "event": "push"}]
        }):
            with self.assertRaisesRegex(ValueError, "Invalid GitHub Actions run id"):
                module.collect("VY-Groups/yarp-lb", "a" * 40, "fake")

    def test_pending_job_is_not_a_success(self):
        def fake(path, token):
            if "/actions/runs?" in path:
                return {"workflow_runs": [{"id": 1, "head_sha": "a" * 40,
                                            "head_branch": "main", "event": "push",
                                            "status": "completed", "conclusion": "success"}]}
            return {"jobs": [{"id": 7, "status": "in_progress", "conclusion": None}]}
        with patch.object(module, "get_json", side_effect=fake):
            rows = module.collect("VY-Groups/yarp-lb", "a" * 40, "fake")
        self.assertNotEqual(rows[0]["jobs"][0]["conclusion"], "success")

    def test_no_runs_is_failure(self):
        with patch.object(module, "collect", return_value=[]), patch.dict(
            module.os.environ, {"GH_TOKEN": "fake"}
        ):
            self.assertEqual(module.main(["--repo", "VY-Groups/yarp-lb",
                                          "--sha", "a" * 40]), 1)

    def test_missing_credentials_is_not_success(self):
        with patch.dict(module.os.environ, {"GH_TOKEN": "", "GITHUB_TOKEN": ""}):
            with self.assertRaises(SystemExit):
                module.main(["--repo", "VY-Groups/yarp-lb", "--sha", "a" * 40])


if __name__ == "__main__":
    unittest.main()
