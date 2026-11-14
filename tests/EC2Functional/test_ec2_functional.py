import importlib.util
import os
from pathlib import Path
from unittest import TestCase, main
from unittest.mock import patch

path = Path(__file__).with_name("ec2_functional.py")
spec = importlib.util.spec_from_file_location("ec2_functional", path)
ec2 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ec2)


class SafetyContract(TestCase):
    def test_hard_budget(self):
        used = ec2.Budget(initial=10)
        for _ in range(1000):
            used.consume("T1")
        self.assertEqual(used.by_test["T1"], 1000)
        with self.assertRaisesRegex(ec2.Failure, "REQUEST_CAP_EXCEEDED"):
            used.consume("T1")
        self.assertEqual(used.total, 1010)
        cap = ec2.Budget(initial=8000)
        with self.assertRaisesRegex(ec2.Failure, "REQUEST_CAP_EXCEEDED"):
            cap.consume("anything")

    def test_strict_preflight_vars(self):
        env = {"GITHUB_ACTIONS":"true", "CI":"true",
               "BACKEND_A_HOST":ec2.HOST_A, "BACKEND_B_HOST":ec2.HOST_B}
        with patch.dict(os.environ, env, clear=True):
            self.assertEqual(ec2.prerequisites(), (ec2.HOST_A, ec2.HOST_B))
        env["BACKEND_B_HOST"] = "example.com"
        with patch.dict(os.environ, env, clear=True):
            with self.assertRaisesRegex(ec2.Failure, "variables missing"):
                ec2.prerequisites()

    def test_identity_parser(self):
        self.assertEqual(ec2.BODY_PATTERN.search(
            "<p>backend ip-172-31-1-2 2026-11-14T00:00:00Z</p>").group(1), "ip-172-31-1-2")
        self.assertIsNone(ec2.BODY_PATTERN.search("A generic index page"))
        self.assertTrue(ec2.identity_ok({
            "status":200,"backend":"host-a","error":""
        },{"host-a"}))
        self.assertFalse(ec2.identity_ok({
            "status":200,"backend":"host-b","error":""
        },{"host-a"}))

    def test_actual_gateway_config_contains_load_balancing_and_live_route(self):
        settings = ec2.config({"A":"http://a/","B":"http://b/"},
                              policy="SourceIpHash",weights={"A":70,"B":30})
        rp = settings["ReverseProxy"]
        self.assertEqual(rp["Clusters"]["ec2"]["LoadBalancingPolicy"], "SourceIpHash")
        self.assertEqual(rp["Clusters"]["ec2"]["Destinations"]["A"]["Metadata"]["Weight"],"70")
        self.assertEqual(rp["Routes"]["ec2"]["Match"]["Path"],"/ec2/{**catch-all}")
        self.assertEqual(rp["Routes"]["ec2"]["Transforms"][0]["PathRemovePrefix"],"/ec2")
        self.assertFalse(rp["Clusters"]["ec2"]["HealthCheck"]["Active"]["Enabled"])

    def test_distribution_rejects_bad_status_or_wrong_backend(self):
        names = {"A":"a","B":"b"}
        rows = [{"status":200,"backend":"a","error":"","latency_ms":1.0} for _ in range(500)]
        rows += [{"status":200,"backend":"b","error":"","latency_ms":2.0} for _ in range(500)]
        result = ec2.distribution(rows,names,.45,.55,"equal")
        self.assertEqual(result["A"],500)
        rows[0]["status"] = 502
        with self.assertRaisesRegex(ec2.Failure,"invalid responses"):
            ec2.distribution(rows,names,.45,.55,"equal")

    def test_per_request_curl_timeout_and_source_bind(self):
        from subprocess import CompletedProcess
        response=b"backend test-host 2026-11-14\n__EC2_META__200|0.0123\n"
        with patch.object(ec2.subprocess, "run",
                          return_value=CompletedProcess([],0,response,b"")) as run:
            result=ec2.curl("http://127.0.0.1:18088/ec2/",
                            client="127.0.0.22",xff="203.0.113.2")
        self.assertEqual(result["status"],200)
        self.assertEqual(result["backend"],"test-host")
        self.assertEqual(result["latency_ms"],12.3)
        argv = run.call_args.args[0]
        self.assertEqual(argv[argv.index("--max-time")+1],"15")
        self.assertEqual(argv[argv.index("--interface")+1],"127.0.0.22")
        self.assertIn("X-Forwarded-For: 203.0.113.2",argv)
        self.assertFalse("--insecure" in argv)


if __name__ == "__main__":
    main()
