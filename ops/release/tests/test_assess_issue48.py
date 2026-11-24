import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from assess_issue48 import DP_REQUIRED,audit
from assess_ci import REQUIRED

SHA="a"*40
REPO="example/gateway"
def run(name,path,**extra):
    return dict(name=name,path=".github/workflows/"+path,head_sha=SHA,
                head_branch="main",event="workflow_dispatch",
                head_repository={"full_name":REPO},status="completed",
                conclusion="success",created_at="2026-11-24T00:00:00Z",
                id=1,run_attempt=1,**{}) | extra

class Issue48Evidence(unittest.TestCase):
    def full(self):
        return [run(n,"baseline-"+str(i)+".yml") for i,n in enumerate(REQUIRED)]+[
            run(n,p) for p,n in DP_REQUIRED.items()]
    def assess(self,runs):
        return audit({"workflow_runs":runs},SHA,REPO)
    def test_green_only_ci_candidate(self):
        result=self.assess(self.full())
        self.assertEqual(result["ci_candidate"],"CI-GO")
        self.assertEqual(result["production"],"NO-GO")
        self.assertEqual(result["issue_48_closure"],"NOT ASSERTED")
    def test_missing_each_dp_workflow_blocks(self):
        for path in DP_REQUIRED:
            with self.subTest(path=path):
                self.assertEqual(self.assess([r for r in self.full()
                    if r["path"]!=".github/workflows/"+path])["ci_candidate"],"PENDING")
    def test_wrong_branch_event_sha_repo_and_path_do_not_count(self):
        path="waf-etcd-quorum.yml"
        for change in ({"head_branch":"topic"},{"event":"pull_request"},
                       {"head_sha":"b"*40},{"head_repository":{"full_name":"fork/repo"}},
                       {"path":".github/workflows/imitator.yml"}):
            with self.subTest(change=change):
                runs=self.full()
                runs[-1]=runs[-1] # keep other evidence
                target=next(r for r in runs if r["path"].endswith("/"+path))
                target.update(change)
                self.assertEqual(self.assess(runs)["ci_candidate"],"PENDING")
    def test_latest_failed_or_pending_attempt_blocks(self):
        path="waf-etcd-quorum.yml"
        for status,conclusion,wanted in (("completed","failure","NO-GO"),
                ("in_progress",None,"PENDING"),("completed","skipped","NO-GO")):
            runs=self.full()+[run(DP_REQUIRED[path],path,run_attempt=2,
                                  status=status,conclusion=conclusion)]
            self.assertEqual(self.assess(runs)["ci_candidate"],wanted)
    def test_original_baseline_must_not_be_weakened(self):
        runs=[r for r in self.full() if r["name"]!=REQUIRED[0]]
        self.assertEqual(self.assess(runs)["ci_candidate"],"PENDING")
