import sys
import json
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parent))
from check_metric_contract import evaluate
CONTRACT=(Path(__file__).parents[3]/'control-center/ops/prometheus/METRIC_CONTRACT.md').read_text()
ALERTS=(Path(__file__).parents[3]/'control-center/ops/prometheus/gateway-alerts.yml').read_text()
DASH=(Path(__file__).parents[3]/'tests/CI/stack/grafana/dashboard.json').read_text()
required=[
'yarp_control_http_requests_total','yarp_control_http_responses_total',
'yarp_control_http_duration_seconds_bucket','yarp_control_http_duration_seconds_count',
'yarp_control_http_duration_seconds_sum','yarp_control_process_working_set_bytes',
'yarp_control_gc_heap_bytes','yarp_control_gc_collections_total',
'yarp_control_destination_inflight_requests','yarp_control_destination_active_health',
'yarp_logging_dropped_total','yarp_logging_dropped_high_priority_total',
'yarp_logging_write_errors_total']
FIXTURE='\\n'.join(item+' 0' for item in required)+'\\n'
class ContractTests(unittest.TestCase):
    def test_realistic_fixture_go(self): self.assertEqual(evaluate(FIXTURE,CONTRACT,ALERTS,DASH)['decision'],'GO')
    def test_missing_exporter_metric_no_go(self):
        self.assertIn('MISSING_REAL_SERIES:yarp_logging_dropped_total',evaluate(FIXTURE.replace('yarp_logging_dropped_total 0\\n',''),CONTRACT,ALERTS,DASH)['errors'])
    def test_unimplemented_alert_metric_no_go(self):
        changed=ALERTS+'\\n    - alert: Fake\\n      expr: yarp_missing_metric_total > 0\\n'
        self.assertIn('UNDEFINED_ALERT_OR_DASHBOARD_SERIES:yarp_missing_metric_total',evaluate(FIXTURE,CONTRACT,changed,DASH)['errors'])
    def test_unimplemented_dashboard_metric_no_go(self):
        d=json.loads(DASH)
        d['panels'][0]['targets'][0]['expr']='rate(yarp_fake_gateway_bps_total[1m])'
        self.assertIn('UNDEFINED_ALERT_OR_DASHBOARD_SERIES:yarp_fake_gateway_bps_total',evaluate(FIXTURE,CONTRACT,ALERTS,json.dumps(d))['errors'])
    def test_unapproved_external_series_no_go(self):
        changed=ALERTS+'\\n    - alert: Fake\\n      expr: probe_unknown_certificate_metric > 0\\n'
        self.assertIn('UNDEFINED_ALERT_OR_DASHBOARD_SERIES:probe_unknown_certificate_metric',evaluate(FIXTURE,CONTRACT,changed,DASH)['errors'])
if __name__=='__main__':unittest.main()
