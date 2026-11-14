import json
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import tempfile
import unittest
from pathlib import Path
from check_canary import evaluate

class Canary(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder=Path(self.tmp.name)
        self.body={'summary':{'total':20,'totalData':1907 * 1048576,
            'requestsPerSec':1907/20,'successRate':1},
            'statusCodeDistribution':{'200':1907},
            'errorDistribution':{},'latencyPercentiles':{'p99':.037}}
        for name in ('backend-a','gateway-a'):
            (self.folder/(name+'.json')).write_text(json.dumps(self.body))
    def test_750mbps_from_raw_bytes(self):
        result=evaluate(self.folder,.75)
        self.assertEqual(result['canary'],'PASS')
        self.assertAlmostEqual(result['results']['gateway-a']['body_gbps'],1907*1048576*8/(20*1e9))
        self.assertEqual(result['production_gate'],'NOT_RUN')
    def test_below_target_fails(self):
        obj=dict(self.body)
        obj['summary']=dict(self.body['summary'],totalData=1_000_000_000)
        (self.folder/'gateway-a.json').write_text(json.dumps(obj))
        with self.assertRaises(AssertionError): evaluate(self.folder,.75)
    def test_http_error_fails(self):
        obj=dict(self.body,statusCodeDistribution={'200':1906,'502':1})
        (self.folder/'gateway-a.json').write_text(json.dumps(obj))
        self.assertEqual(evaluate(self.folder,.75)['canary'],'FAIL')
    def test_transport_error_fails(self):
        obj=dict(self.body,errorDistribution={'ConnectionReset':1})
        (self.folder/'backend-a.json').write_text(json.dumps(obj))
        self.assertEqual(evaluate(self.folder,.75)['canary'],'FAIL')
if __name__=='__main__':unittest.main()
