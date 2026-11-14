import csv
import datetime as dt
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

BASE=Path(__file__).resolve().parents[1]
REPORT=BASE/"report.py"
LIMITS=BASE/"limits.py"

class CapacityEvidence(unittest.TestCase):
    def setUp(self):
        self.root=tempfile.TemporaryDirectory()
        self.addCleanup(self.root.cleanup)
        self.p=Path(self.root.name)
        self.scenario={
            "peak_gbps":0.01,"peak_rps":1000,"peak_concurrent_connections":1000,
            "new_connections_per_second":20,"https_share":0,"link_gbps":10,
            "server_specs":{"cpu_model":"CI fake","cpu_cores":4,"ram_gb":8,
                            "nic_model":"CI fake","nic_speed_gbps":10},
            "response_mix":[
                {"name":"small","url":"http://127.0.0.1:8080/bench/1024","response_bytes":1024,"weight":0.5},
                {"name":"large","url":"http://127.0.0.1:8080/bench/4096","response_bytes":4096,"weight":0.5}],
            "headroom":0.5,"max_p99_ms":100,"hosts":["h1","h2"],
            "gateway_nodes":["node-1"],"isolated_gateway":"node-1",
            "window_seconds":60,"windows":60,"http_version":"1.1","baseline_alpn":"http/1.1",
            "keepalive":True,"baseline_keepalive":True,"allowed_status":[200]}
        self.first=dt.datetime(2026,11,14,tzinfo=dt.timezone.utc)
        self.write_scenario()
        for host in self.scenario["hosts"]:
            folder=self.p/"results"/host;folder.mkdir(parents=True)
            manifest={"engine":"oha","host_id":host,"scenario":self.scenario,"windows":[]}
            for i in range(60):
                start=self.first+dt.timedelta(minutes=i)
                manifest["windows"].append({"index":i,"start_utc":start.isoformat(),"end_utc":(start+dt.timedelta(seconds=60)).isoformat(),
                    "wall_seconds":60.0,"returncode":0,"artifact":f"window-{i:03d}.json"})
                data={"summary":{"total":60,"requestsPerSec":800,"totalData":122880000,"successRate":1},
                      "latencyPercentiles":{"p50":0.01,"p95":0.025,"p99":0.05},
                      "statusCodeDistribution":{"200":48000},"errorDistribution":{},
                      "perProfile":[{"name":"small","url":"http://127.0.0.1:8080/bench/1024",
                                    "count":24000,"body_bytes":24576000},
                                   {"name":"large","url":"http://127.0.0.1:8080/bench/4096",
                                    "count":24000,"body_bytes":98304000}]}
                (folder/f"window-{i:03d}.json").write_text(json.dumps(data))
            (folder/"manifest.json").write_text(json.dumps(manifest))
        self.csv=self.p/"node-1.csv"
        with self.csv.open("w",newline="") as out:
            keys=("gateway_node","process_id","process_start_utc","timestamp_utc","gc_prometheus_raw",
                  "logs_prometheus_raw","rss_bytes","threads","rx_dropped","tx_dropped","process_cpu_seconds")
            writer=csv.DictWriter(out,fieldnames=keys);writer.writeheader()
            for i in range(721):
                writer.writerow({"gateway_node":"node-1","process_id":"200",
                    "process_start_utc":(self.first-dt.timedelta(hours=1)).isoformat(),
                    "timestamp_utc":(self.first+dt.timedelta(seconds=i*5)).isoformat(),
                    "gc_prometheus_raw":'yarp_control_gc_collections_total{generation="2"} 0\n'
                                        'yarp_control_gc_heap_bytes 2000000',
                    "logs_prometheus_raw":"yarp_logging_dropped_total 0\n"
                                       "yarp_logging_dropped_high_priority_total 0\n"
                                       "yarp_logging_write_errors_total 0",
                    "rss_bytes":25000000,"threads":20,"rx_dropped":0,"tx_dropped":0,
                    "process_cpu_seconds":i})
    def write_scenario(self):
        self.scenario_path=self.p/"scenario.json";self.scenario_path.write_text(json.dumps(self.scenario))
        for host in self.scenario.get("hosts",[]):
            file=self.p/"results"/host/"manifest.json"
            if file.exists():
                doc=json.loads(file.read_text());doc["scenario"]=self.scenario;file.write_text(json.dumps(doc))
    def report(self):
        self.write_scenario()
        out=self.p/"report.json"
        r=subprocess.run([sys.executable,str(REPORT),"--scenario",str(self.scenario_path),
          "--results",str(self.p/"results"),"--gateway-csv",str(self.csv),"--out",str(out)],
          capture_output=True,text=True)
        return r,json.loads(out.read_text()) if out.exists() else {}
    def test_synthetic_full_hour_go(self):
        r,d=self.report();self.assertEqual(r.returncode,0,r.stdout+r.stderr)
        self.assertEqual(d["decision"],"GO");self.assertEqual(len(d["window_results"]),60)
        self.assertEqual(d["overlapping_seconds"],3600)
    def test_gbps_floor_fails_even_with_rps(self):
        self.scenario["peak_gbps"]=.04
        r,d=self.report();self.assertNotEqual(r.returncode,0)
        self.assertIn("BODY_GBPS",str(d["error_reasons"]))
    def test_infeasible_10gbe_link(self):
        self.scenario["peak_gbps"]=8
        r,d=self.report();self.assertNotEqual(r.returncode,0)
        self.assertIn("INFEASIBLE_LINK",str(d["error_reasons"]))
    def test_missing_measured_traffic_fails(self):
        self.scenario.pop("new_connections_per_second")
        r,d=self.report();self.assertNotEqual(r.returncode,0)
        self.assertIn("REQUIRED_INPUT",str(d["error_reasons"]))
    def test_missing_hardware_fails(self):
        self.scenario["server_specs"].pop("cpu_model")
        r,d=self.report();self.assertNotEqual(r.returncode,0)
        self.assertIn("REQUIRED_INPUT",str(d["error_reasons"]))
    def test_mixed_profile_size_tamper(self):
        f=self.p/"results"/"h1"/"window-005.json";doc=json.loads(f.read_text())
        doc["perProfile"][0]["body_bytes"]-=1;f.write_text(json.dumps(doc))
        r,d=self.report();self.assertNotEqual(r.returncode,0)
        self.assertIn("mixed body/count",str(d["error_reasons"]))
    def test_http_502_fails(self):
        f=self.p/"results"/"h1"/"window-006.json";doc=json.loads(f.read_text())
        doc["statusCodeDistribution"]["502"]=1;f.write_text(json.dumps(doc))
        r,d=self.report();self.assertNotEqual(r.returncode,0)
        self.assertIn("HTTP/transport errors",str(d["error_reasons"]))
    def test_alpn_drift_fails(self):
        self.scenario["baseline_alpn"]="h2"
        r,d=self.report();self.assertNotEqual(r.returncode,0)
        self.assertIn("BASELINE_MISMATCH",str(d["error_reasons"]))
    def test_two_nodes_cannot_claim_single_survivor(self):
        self.scenario["gateway_nodes"]=["node-1","node-2"]
        r,d=self.report();self.assertNotEqual(r.returncode,0)
        self.assertIn("ONE_NODE_REQUIRED",str(d["error_reasons"]))
    def test_weighted_oha_commands_are_parallel_profiles(self):
        self.scenario["requests_per_second_per_host"]=1600
        self.scenario["connections_per_host"]=128
        self.scenario["threads"]=4
        self.write_scenario()
        r=subprocess.run([sys.executable,str(BASE/"run_oha.py"),"--scenario",str(self.scenario_path),
             "--host-id","h1","--out",str(self.p/"dry"),"--dry-run"],
             capture_output=True,text=True)
        self.assertEqual(r.returncode,0,r.stderr)
        out=json.loads(r.stdout)
        self.assertEqual(len(out["commands"]),2)
        self.assertEqual(sum(out["rates"]),1600)
        self.assertEqual(sum(out["connections"]),128)
        self.assertTrue(all("oha"==x[0] for x in out["commands"]))
        self.assertTrue(all('--wait-ongoing-requests-after-deadline' in x for x in out['commands']))
        self.assertEqual({x[-1] for x in out["commands"]},{m["url"] for m in self.scenario["response_mix"]})
    def test_oha_missing_rate_fails_closed(self):
        self.scenario["connections_per_host"]=128
        self.scenario["threads"]=4
        self.write_scenario()
        r=subprocess.run([sys.executable,str(BASE/"run_oha.py"),"--scenario",str(self.scenario_path),
             "--host-id","h1","--out",str(self.p/"dry"),"--dry-run"],
             capture_output=True,text=True)
        self.assertNotEqual(r.returncode,0)
        self.assertIn("requests_per_second_per_host",r.stderr)

    def test_nofile_ceil_and_kestrel_ceil(self):
        f=self.p/"actual.json";f.write_text(json.dumps({"kestrel_max_concurrent_connections":1500,"limit_nofile":7846}))
        out=self.p/"limits.json";self.write_scenario()
        cmd=[sys.executable,str(LIMITS),"--scenario",str(self.scenario_path),"--profile",str(f),"--out",str(out)]
        r=subprocess.run(cmd,capture_output=True,text=True)
        self.assertEqual(r.returncode,0,r.stdout+r.stderr)
        self.assertEqual(json.loads(out.read_text())["decision"],"GO")
    def test_nofile_below_required(self):
        f=self.p/"actual.json";f.write_text(json.dumps({"kestrel_max_concurrent_connections":2000,"limit_nofile":9095}))
        self.write_scenario();out=self.p/"limits.json"
        r=subprocess.run([sys.executable,str(LIMITS),"--scenario",str(self.scenario_path),
          "--profile",str(f),"--out",str(out)],capture_output=True,text=True)
        self.assertNotEqual(r.returncode,0)
        self.assertIn("LIMIT_NOFILE_TOO_LOW",str(json.loads(out.read_text())))
if __name__=="__main__":unittest.main()
