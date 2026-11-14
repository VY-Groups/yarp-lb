import json
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from assess_ci import evaluate, REQUIRED

SHA = "a" * 40
def sample(name, status="completed", conclusion="success", sha=SHA, run_id=2, created_at="2026-11-14T10:00:00Z"):
    return {"name":name,"status":status,"conclusion":conclusion,"head_sha":sha,"id":run_id,
            "created_at":created_at,"html_url":f"https://github.com/example/repo/actions/runs/{run_id}"}
class ReleaseEvidence(unittest.TestCase):
    def full(self):
        return {"workflow_runs":[sample(n) for n in REQUIRED]}
    def test_14_exact_sha_green_is_only_ci_go(self):
        result=evaluate(self.full(),SHA)
        self.assertEqual(result["ci_v01"],"GO")
        self.assertEqual(result["production"],"NO-GO")
        self.assertEqual(result["completed_success"],14)
    def test_wrong_commit_never_counts(self):
        self.assertEqual(evaluate(self.full(),"b"*40)["ci_v01"],"PENDING")
    def test_failed_workflow_never_counts(self):
        obj=self.full()
        obj["workflow_runs"][2]["conclusion"]="failure"
        self.assertEqual(evaluate(obj,SHA)["ci_v01"],"NO-GO")
    def test_pending_workflow_never_counts(self):
        obj=self.full()
        obj["workflow_runs"][0]["status"]="in_progress"
        obj["workflow_runs"][0]["conclusion"]=None
        self.assertEqual(evaluate(obj,SHA)["ci_v01"],"PENDING")
    def test_missing_workflow_never_counts(self):
        obj=self.full()
        obj["workflow_runs"].pop()
        self.assertEqual(evaluate(obj,SHA)["ci_v01"],"PENDING")
    def test_later_failure_cannot_hide_behind_older_success(self):
        obj=self.full()
        obj["workflow_runs"].append(sample(REQUIRED[1],conclusion="failure",
            created_at="2026-11-14T10:01:00Z",run_id=20))
        self.assertEqual(evaluate(obj,SHA)["ci_v01"],"NO-GO")
    def test_incorrect_sha_and_data_rejected(self):
        with self.assertRaises(ValueError):evaluate(self.full(),"1234")
        with self.assertRaises(ValueError):evaluate({},SHA)
if __name__=="__main__":unittest.main()
