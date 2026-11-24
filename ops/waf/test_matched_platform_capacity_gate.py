"""Synthetic-only test of strict per-platform full-hour WAF evidence gate.

No sample here is genuine performance evidence or a production threshold.
"""
import copy
import datetime as dt
import tempfile
import unittest
from pathlib import Path
import json

import matched_platform_capacity_gate as gated

S="a"*40
I="owasp/modsecurity-crs@sha256:"+"b"*64
D="C"*64


def policy():
    return {
        "schemaVersion":1, "sourceSha":S,"wafImageDigest":I,
        "trafficProfileSha256":D,
        "httpVersion":"1.1", "keepalive":True,
        "concurrency":75, "windowSeconds":60, "windowCount":60,
        "peakBodyGbps":0.5, "headroom":0.3,
        "maxP95Ms":200, "maxP99Ms":500,
        "maxWafP99Multiplier":2.0,
        "maxCpuUtilizationPercent":80,
        "maxAllocatedBytesPerRequest":300000,
        "maxGcPauseMsPerWindow":100,
        "allowedHttpStatus":[200]
    }


def evidence():
    rows={}
    count=0
    at=dt.datetime(2026,11,24,tzinfo=dt.timezone.utc)
    for platform in gated.PLATFORMS:
        rows[platform]={}
        for path in gated.PATHS:
            samples=[]
            for minute in range(60):
                first=at+dt.timedelta(minutes=minute)
                last=first+dt.timedelta(minutes=1)
                count+=1
                samples.append({
                    "index":minute,
                    "startUtc":first.isoformat(timespec="seconds").replace("+00:00","Z"),
                    "endUtc":last.isoformat(timespec="seconds").replace("+00:00","Z"),
                    "requests":100000,
                    "errors":0,"unexpectedStatuses":0,
                    "responseBodyBytes":5_100_000_000,
                    "p95Ms":10, "p99Ms":20 if path!="yarp_waf" else 30,
                    "cpuSeconds":12,
                    "allocatedBytes":None if path=="direct" else 10_000_000_000,
                    "gcPauseMs":None if path=="direct" else 10,
                    "rawWindowSha256":f"{count:064X}"
                })
            rows[platform][path]={
                "platform":platform, "path":path,
                "sourceSha":S,"trafficProfileSha256":D,
                "wafImageDigest":I if path=="yarp_waf" else None,
                "httpVersion":"1.1", "keepalive":True,
                "concurrency":75, "windowSeconds":60,"hostCpuCores":8,
                "windows":samples
            }
    return {"schemaVersion":1,"runs":rows}


class MatchedCapacityEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.p=policy()
        self.e=evidence()

    def test_complete_synthetic_envelope_proves_only_measured_policy_pass(self):
        result=gated.gate(self.p,self.e)
        self.assertEqual(result["decision"],"GO")
        self.assertAlmostEqual(result["requiredBodyGbps"],.65)
        self.assertEqual(result["runs"]["windows"]["yarp_waf"]["windows"],60)
        self.assertEqual(result["runs"]["linux"]["yarp"]["observedSeconds"],3600)

    def test_no_shorter_than_one_hour_or_missing_path_platform(self):
        for mutate in (
            lambda x: x["runs"]["linux"].pop("yarp_waf"),
            lambda x: x["runs"].pop("windows"),
            lambda x: x["runs"]["windows"]["direct"]["windows"].pop(),
            lambda x: x["runs"]["linux"]["yarp"]["windows"][7].update(
                {"endUtc":"2026-11-24T00:07:01Z"}),
            lambda x: x["runs"]["windows"]["yarp"]["windows"][3].update(
                {"startUtc":"2026-11-24T00:00:00Z"})
        ):
            c=copy.deepcopy(self.e)
            mutate(c)
            with self.assertRaises(ValueError):
                gated.gate(self.p,c)

    def test_zero_error_p99_cpu_allocations_headroom_are_gated(self):
        cases=[
            ("errors",1),
            ("unexpectedStatuses",2),
            ("p99Ms",600),
            ("p95Ms",220),
            ("responseBodyBytes",2_000_000_000),
            ("cpuSeconds",420),
            ("allocatedBytes",100_000_000_000),
            ("gcPauseMs",200)
        ]
        for field,value in cases:
            e=copy.deepcopy(self.e)
            window=e["runs"]["linux"]["yarp_waf"]["windows"][10]
            window[field]=value
            if field=="p95Ms":
                # Preserve valid percentile ordering, exceed ONLY the
                # independently preapproved p95 policy threshold.
                window["p99Ms"]=230
            with self.subTest(field=field):
                self.assertEqual(gated.gate(self.p,e)["decision"],"NO-GO")
        e=copy.deepcopy(self.e)
        for minute in e["runs"]["windows"]["yarp_waf"]["windows"]:
            minute["p99Ms"]=100
        self.assertEqual(gated.gate(self.p,e)["decision"],"NO-GO")

    def test_no_fabricated_resource_and_platform_data(self):
        cases=[
            lambda x: x["runs"]["linux"]["direct"]["windows"][0].update(
                {"allocatedBytes":0}),
            lambda x: x["runs"]["windows"]["yarp"]["windows"][0].update(
                {"allocatedBytes":None}),
            lambda x: x["runs"]["windows"]["yarp"]["windowSeconds"].__class__,
            lambda x: x["runs"]["windows"]["yarp"].update(
                {"httpVersion":"2"}),
            lambda x: x["runs"]["linux"]["yarp_waf"].update(
                {"wafImageDigest":None}),
            lambda x: x["runs"]["linux"]["yarp"]["windows"][0].update(
                {"rawWindowSha256":x["runs"]["windows"]["direct"]["windows"][0]["rawWindowSha256"]})
        ]
        for i,mutate in enumerate(cases):
            e=copy.deepcopy(self.e)
            if i==2:
                e["runs"]["windows"]["yarp"]["windowSeconds"]=30
            else:
                mutate(e)
            with self.subTest(i=i), self.assertRaises(ValueError):
                gated.gate(self.p,e)

    def test_policy_cannot_be_derived_from_truncated_evidence(self):
        for edit in (
            {"windowCount":1}, {"windowSeconds":30},
            {"headroom":0.0},{"maxP99Ms":0},
            {"peakBodyGbps":0},{"concurrency":True},
            {"httpVersion":"2","keepalive":False},
            {"allowedHttpStatus":[200,403]},
            {"wafImageDigest":"unversioned"},
        ):
            p={**self.p,**edit}
            with self.subTest(edit=edit), self.assertRaises(ValueError):
                gated.gate(p,self.e)

    def test_strict_json_fails_duplicate_keys_nonfinite_and_invalid_shapes(self):
        for raw in (
            b'{"schemaVersion":1,"schemaVersion":2}',
            b'{"n":NaN}',
            b'[]',
            b'invalid'
        ):
            with self.subTest(raw=raw),self.assertRaises(ValueError):
                gated.parse_strict_json(raw)

    def test_cli_private_output_is_new_only_and_never_claims_production_go(self):
        with tempfile.TemporaryDirectory() as directory:
            d=Path(directory)
            d.chmod(0o700)
            import os
            priv=d/"private"
            priv.mkdir(mode=0o700)
            p=priv/"policy.json"
            e=priv/"evidence.json"
            out=priv/"report.json"
            p.write_text(json.dumps(self.p),encoding="utf-8")
            e.write_text(json.dumps(self.e),encoding="utf-8")
            self.assertEqual(gated.main(["--policy",str(p),"--evidence",str(e),
                                        "--out",str(out)]),0)
            record=json.loads(out.read_text(encoding="utf-8"))
            self.assertTrue(record["measurementPolicyPass"])
            self.assertFalse(record["productionGo"])
            self.assertFalse(record["sourceCustodyVerified"])
            if os.name=="posix":
                self.assertEqual(out.stat().st_mode & 0o077,0)
            self.assertEqual(gated.main(["--policy",str(p),"--evidence",str(e),
                                        "--out",str(out)]),1)
            self.assertTrue(out.exists())


if __name__ == "__main__":
    unittest.main()
