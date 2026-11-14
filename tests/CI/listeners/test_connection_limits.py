import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
GATE = ROOT / 'control-center/ops/systemd/check_connection_limits.py'

class ConnectionGateTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.scenario = root/'scenario.json'
        self.listeners = root/'listeners.json'
        self.unit = root/'limits.conf'
        self.out = root/'gate.json'
        self.scenario.write_text(json.dumps({'peak_concurrent_connections': 100}))
        self.listeners.write_text(json.dumps({'maxConcurrentConnections': 150}))
        self.unit.write_text('[Service]\nLimitNOFILE=4471\n')

    def execute(self):
        result = subprocess.run([sys.executable,str(GATE),'--scenario',str(self.scenario),
            '--listeners',str(self.listeners),'--limits-dropin',str(self.unit),
            '--out',str(self.out)],text=True,capture_output=True)
        return result, json.loads(self.out.read_text())

    def test_exact_bounds_pass(self):
        proc, result = self.execute()
        self.assertEqual(proc.returncode, 0,proc.stderr)
        self.assertEqual(result['minimum_kestrel_connections'],150)
        self.assertEqual(result['minimum_limit_nofile'],4471)

    def test_insufficient_kestrel_fails(self):
        self.listeners.write_text(json.dumps({'maxConcurrentConnections':149}))
        proc, result=self.execute()
        self.assertNotEqual(proc.returncode,0)
        self.assertIn('CONNECTION_CAP_INSUFFICIENT',str(result))

    def test_insufficient_nofile_fails(self):
        self.unit.write_text('[Service]\nLimitNOFILE=4470\n')
        proc,result=self.execute()
        self.assertNotEqual(proc.returncode,0)
        self.assertIn('NOFILE_INSUFFICIENT',str(result))

    def test_no_measured_peak_fails(self):
        self.scenario.write_text('{}')
        proc,result=self.execute()
        self.assertNotEqual(proc.returncode,0)
        self.assertIn('REQUIRED_INPUT',str(result))

    def test_missing_nofile_fails(self):
        self.unit.write_text('[Service]\n')
        proc,result=self.execute()
        self.assertNotEqual(proc.returncode,0)
        self.assertIn('REQUIRED_INPUT',str(result))

if __name__=='__main__':
    unittest.main()
