import json
from pathlib import Path
import tempfile
import unittest

from compare import summarize


class CompareContract(unittest.TestCase):
    def test_comparison_and_failclosed(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            metrics = {
                "http_reqs":{"count":60000},
                "http_req_failed":{"value":0},
                "checks":{"value":1},
                "http_req_duration":{"p(95)":15,"p(99)":45},
            }
            for mode, a, b in [("direct",100,200),("proxy",200,600000)]:
                base={"processId":123,"allocatedBytesTotal":a,
                      "gc2Collections":0,"processWorkingSetBytes":9000000}
                end={**base,"allocatedBytesTotal":b,"gc2Collections":1}
                (root/f"{mode}-before.json").write_text(json.dumps(base))
                (root/f"{mode}-after.json").write_text(json.dumps(end))
                (root/f"{mode}-k6.json").write_text(json.dumps({"metrics":metrics}))
                (root/f"{mode}-start-ms.txt").write_text("100000")
                (root/f"{mode}-end-ms.txt").write_text("145000")
            result=summarize(root)
            self.assertEqual(result["proxy"]["http_requests"],60000)
            self.assertGreater(
                result["estimated_additional_gateway_allocated_bytes_per_proxied_request"],9.9)
            self.assertLess(
                result["estimated_additional_gateway_allocated_bytes_per_proxied_request"],10.1)
            (root/"proxy-after.json").write_text(json.dumps({
                "processId":456,"allocatedBytesTotal":600000,"gc2Collections":1,
                "processWorkingSetBytes":9000000}))
            with self.assertRaisesRegex(ValueError,"restarted"):
                summarize(root)


if __name__=="__main__":
    unittest.main()
