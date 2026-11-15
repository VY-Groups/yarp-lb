import json
import tempfile
import unittest
from pathlib import Path
from throughput_probe import accept
from verify_two_evidence import check

class TwoVmEvidenceTests(unittest.TestCase):
    def report(self,site,hostname,sha="abc",strict=False,minutes=1,mbps=800):
        windows=[{"index":i,"seconds":60 if strict else 15,
                  "body_mbps":mbps,"p99_ms":25,"requests":200,"errors":0}
                 for i in range(minutes)]
        return {"site":site,"runner_hostname":hostname,"head_sha":sha,
                "strict":strict,"status":"PASS","total_requests":minutes*200,
                "total_errors":0,"target_body_mbps":750,"p99_limit_ms":250,
                "windows":windows}

    def check_reports(self,a,b,strict=False):
        with tempfile.TemporaryDirectory() as tmp:
            files=[Path(tmp)/"a.json",Path(tmp)/"b.json"]
            for path, report in zip(files,[a,b]):
                path.write_text(json.dumps(report))
            return check(files,"abc",strict)

    def test_two_distinct_vms_pass_without_fake_physical_claim(self):
        result=self.check_reports(self.report("node-a","vm-a"),
                                  self.report("node-b","vm-b"))
        self.assertTrue(result["two_distinct_cloud_vms"])
        self.assertFalse(result["on_prem_hardware_verified"])
        self.assertFalse(result["actual_network_failover_verified"])

    def test_duplicate_runner_rejected(self):
        with self.assertRaises(ValueError):
            self.check_reports(self.report("node-a","same"),
                               self.report("node-b","same"))

    def test_wrong_source_commit_rejected(self):
        with self.assertRaises(ValueError):
            self.check_reports(self.report("node-a","vm-a"),
                               self.report("node-b","vm-b",sha="other"))

    def test_strict_one_hour_requires_sixty_complete_windows(self):
        with self.assertRaises(ValueError):
            self.check_reports(self.report("node-a","vm-a",strict=True,minutes=59),
                               self.report("node-b","vm-b",strict=True,minutes=60),strict=True)

    def test_strict_each_minute_underfloor_rejected(self):
        with self.assertRaises(ValueError):
            self.check_reports(self.report("node-a","vm-a",strict=True,minutes=60,mbps=749),
                               self.report("node-b","vm-b",strict=True,minutes=60),strict=True)

    def test_strict_both_sixty_minute_reports_pass(self):
        r=self.check_reports(self.report("node-a","vm-a",strict=True,minutes=60),
                             self.report("node-b","vm-b",strict=True,minutes=60),strict=True)
        self.assertEqual(r["decision"],"CLOUD_SYNTHETIC_PASS_NOT_PHYSICAL_GO")

    def test_probe_short_mode_does_not_claim_threshold(self):
        windows=[{"seconds":15,"body_mbps":20,"p99_ms":1000,"errors":0,"requests":10}]
        yes,_=accept({"windows":windows,"total_requests":10,"total_errors":0},750,250,False)
        self.assertTrue(yes)
        no,_=accept({"windows":windows,"total_requests":10,"total_errors":0},750,250,True)
        self.assertFalse(no)

    def test_errors_fail_even_smoke(self):
        windows=[{"seconds":15,"body_mbps":800,"p99_ms":2,"errors":1,"requests":10}]
        yes,_=accept({"windows":windows,"total_requests":10,"total_errors":1},750,250,False)
        self.assertFalse(yes)


if __name__=="__main__":
    unittest.main()
