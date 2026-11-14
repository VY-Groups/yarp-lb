import json
import sys
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from contract import validate

class EodScenario(unittest.TestCase):
    def setUp(self):
        self.scenario=json.loads((ROOT/'scenario.500mbps.eod.template.json').read_text())
    def test_reported_peak_not_link_rating(self):
        self.assertEqual(self.scenario['peak_gbps'],.5)
        self.assertEqual(self.scenario['link_gbps'],10)
        self.assertEqual(self.scenario['headroom'],.5)
        self.assertEqual(self.scenario['peak_gbps']*(1+self.scenario['headroom']),.75)
        self.assertLessEqual(.75,.9*self.scenario['link_gbps'])
    def test_unknown_workload_fails_closed(self):
        with self.assertRaisesRegex(ValueError,'REQUIRED_INPUT'):
            validate(self.scenario)
    def test_megabyte_not_accepted_as_megabit(self):
        # If 500 MBps is measured, convert to 4 Gbps; 50% implies 6 Gbps.
        self.assertEqual((500*8/1000)*(1+self.scenario['headroom']),6)
if __name__=='__main__':unittest.main()
