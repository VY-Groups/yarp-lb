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
            if "/git/ref/heads/main" in path:
                return {"object": {"sha": "a" * 40}}
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
            rows = module.collect("example/repo", "a" * 40, "fake")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["jobs"][0]["failed_steps"][0]["name"], "Compile")

    def test_old_green_sha_is_not_current_main_acceptance(self):
        with patch.object(module, "get_json", return_value={
            "object": {"sha": "b" * 40}
        }):
            with self.assertRaisesRegex(ValueError, "not the current main"):
                module.collect("example/repo", "a" * 40, "fake")

    def test_missing_main_ref_fails_closed(self):
        with patch.object(module, "get_json", return_value={}):
            with self.assertRaisesRegex(ValueError, "not the current main"):
                module.collect("example/repo", "a" * 40, "fake")

    def test_main_advancing_during_collection_fails_closed(self):
        main_reads = 0
        def fake(path, token):
            nonlocal main_reads
            if "/git/ref/heads/main" in path:
                main_reads += 1
                return {"object": {"sha": ("a" if main_reads == 1 else "b") * 40}}
            if "/actions/runs?" in path:
                return {"workflow_runs": [{
                    "id": 1, "head_sha": "a" * 40, "head_branch": "main",
                    "event": "push", "status": "completed", "conclusion": "success"
                }]}
            return {"jobs": [{
                "id": 7, "status": "completed", "conclusion": "success",
                "steps": []
            }]}
        with patch.object(module, "get_json", side_effect=fake):
            with self.assertRaisesRegex(ValueError, "changed during"):
                module.collect("example/repo", "a" * 40, "fake")
        self.assertEqual(main_reads, 2)

    def test_malformed_api_collection_rejected(self):
        with patch.object(module, "get_json", return_value={"workflow_runs": [None]}):
            with self.assertRaisesRegex(ValueError, "Malformed"):
                module.paged("/repos/example/repo/actions/runs", "fake")

    def test_invalid_run_id_rejected_before_jobs_query(self):
        def fake(path, token):
            if "/git/ref/heads/main" in path:
                return {"object": {"sha": "a" * 40}}
            return {"workflow_runs": [{"id": -1, "head_sha": "a" * 40,
                                      "head_branch": "main", "event": "push"}]}
        with patch.object(module, "get_json", side_effect=fake):
            with self.assertRaisesRegex(ValueError, "Invalid GitHub Actions run id"):
                module.collect("example/repo", "a" * 40, "fake")

    def test_invalid_job_id_never_counts_as_verified_evidence(self):
        for invalid in (None, 0, -1, True, "9"):
            def fake(path, token):
                if "/git/ref/heads/main" in path:
                    return {"object": {"sha": "a" * 40}}
                if "/actions/runs?" in path:
                    return {"workflow_runs": [{"id": 1, "head_sha": "a" * 40,
                                               "head_branch": "main", "event": "push",
                                               "status": "completed", "conclusion": "success"}]}
                return {"jobs": [{"id": invalid, "status": "completed",
                                  "conclusion": "success", "steps": []}]}
            with self.subTest(invalid=invalid):
                with patch.object(module, "get_json", side_effect=fake):
                    with self.assertRaisesRegex(ValueError, "Invalid GitHub Actions job id"):
                        module.collect("example/repo", "a" * 40, "fake")

    def test_pending_job_is_not_a_success(self):
        def fake(path, token):
            if "/git/ref/heads/main" in path:
                return {"object": {"sha": "a" * 40}}
            if "/actions/runs?" in path:
                return {"workflow_runs": [{"id": 1, "head_sha": "a" * 40,
                                            "head_branch": "main", "event": "push",
                                            "status": "completed", "conclusion": "success"}]}
            return {"jobs": [{"id": 7, "status": "in_progress", "conclusion": None}]}
        with patch.object(module, "get_json", side_effect=fake):
            rows = module.collect("example/repo", "a" * 40, "fake")
        self.assertNotEqual(rows[0]["jobs"][0]["conclusion"], "success")

    def test_no_runs_is_failure(self):
        with patch.object(module, "collect", return_value=[]), patch.dict(
            module.os.environ, {"GH_TOKEN": "fake"}
        ):
            self.assertEqual(module.main(["--repo", "example/repo",
                                          "--sha", "a" * 40]), 1)

    def test_missing_credentials_is_not_success(self):
        with patch.dict(module.os.environ, {"GH_TOKEN": "", "GITHUB_TOKEN": ""}):
            with self.assertRaises(SystemExit):
                module.main(["--repo", "example/repo", "--sha", "a" * 40])


if __name__ == "__main__":
    unittest.main()
