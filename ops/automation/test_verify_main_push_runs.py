"""Offline regression tests: python -m unittest discover -s ops/automation -p 'test_verify_main_push_runs.py'"""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "verify_main_push_runs", Path(__file__).with_name("verify_main_push_runs.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
SHA = "a" * 40
RUN = {"id": 123, "name": "Required", "head_sha": SHA, "event": "push", "head_branch": "main",
       "status": "completed", "conclusion": "success", "html_url": "https://github.com/example/r/actions/runs/123"}
JOB = {"id": 456, "name": "build", "status": "completed", "conclusion": "success",
       "html_url": "https://github.com/example/r/actions/runs/123/job/456"}


class EvidenceTests(unittest.TestCase):
    def verify(self, runs=None, jobs=None, final=SHA, required=("Required",)):
        refs = iter([SHA, final])

        def get(path, token):
            self.assertEqual(token, "")
            if "/git/ref/heads/main" in path:
                return {"object": {"sha": next(refs)}}
            raise AssertionError(path)

        def pages(path, key, token):
            if key == "workflow_runs":
                return [RUN] if runs is None else runs
            return [JOB] if jobs is None else jobs

        with patch.object(module, "get_json", side_effect=get), patch.object(
            module, "pages", side_effect=pages
        ):
            return module.collect("example/r", SHA, required, "")

    def test_green_exact_push_and_jobs(self):
        self.assertTrue(self.verify()["accepted"])

    def test_missing_required_workflow_fails(self):
        self.assertFalse(self.verify(required=("Required", "Security"))["accepted"])

    def test_same_sha_non_main_push_is_never_evidence(self):
        matching_sha_from_feature = {**RUN, "head_branch": "feature"}
        self.assertFalse(self.verify(runs=[matching_sha_from_feature])["accepted"])

    def test_only_required_main_push_is_counted(self):
        feature = {**RUN, "id": 124, "head_branch": "feature",
                   "conclusion": "failure"}
        self.assertTrue(self.verify(runs=[feature, RUN])["accepted"])

    def test_same_sha_non_main_success_cannot_hide_missing_main_workflow(self):
        feature = {**RUN, "name": "Security", "head_branch": "feature"}
        self.assertFalse(self.verify(runs=[RUN, feature],
                                     required=("Required", "Security"))["accepted"])

    def test_empty_required_workflows_are_rejected(self):
        for invalid in ((), ("",), ("  ",), ("Required", "")):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(ValueError, "required workflow"):
                    self.verify(required=invalid)

    def test_completed_run_without_jobs_fails(self):
        self.assertFalse(self.verify(jobs=[])["accepted"])

    def test_no_push_runs_fails(self):
        self.assertFalse(self.verify(runs=[])["accepted"])

    def test_failed_job_fails_even_when_run_says_success(self):
        failed = {**JOB, "conclusion": "failure"}
        self.assertFalse(self.verify(jobs=[failed])["accepted"])

    def test_queued_run_fails(self):
        queued = {**RUN, "status": "in_progress", "conclusion": None}
        self.assertFalse(self.verify(runs=[queued])["accepted"])

    def test_main_moved_during_evidence_fails(self):
        self.assertFalse(self.verify(final="b" * 40)["accepted"])

    def test_invalid_sha_fails(self):
        with self.assertRaises(ValueError):
            module.collect("example/r", "short", [], "")


if __name__ == "__main__":
    unittest.main()
