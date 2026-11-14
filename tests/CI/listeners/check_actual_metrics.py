#!/usr/bin/env python3
"""Fail CI if the ACTUAL product /gateway/metrics diverges from declared series, or
if alerts/Grafana reference missing shipping metrics. External blackbox is explicit.
"""
import argparse
import json
import re
import sys
from pathlib import Path
parser=argparse.ArgumentParser()
parser.add_argument('--metrics',type=Path,required=True)
parser.add_argument('--contract',type=Path,required=True)
parser.add_argument('--alerts',type=Path,required=True)
parser.add_argument('--dashboard',type=Path,required=True)
args=parser.parse_args()

contract=args.contract.read_text()
m=re.search(r'```metrics\n(.*?)\n```',contract,re.S)
if not m: raise SystemExit('FAIL: contract has no machine-readable metrics block')
expected=set(x.strip() for x in m.group(1).splitlines() if x.strip())
actual=set(re.findall(r'^# TYPE (\S+) ',args.metrics.read_text(),re.M))
errors=[]
missing=expected-actual;extra=actual-expected
if missing:errors.append('MISSING_FROM_REAL_EXPORTER '+str(sorted(missing)))
if extra:errors.append('UNDECLARED_REAL_EXPORTER '+str(sorted(extra)))

sampled=set(re.findall(r'^(yarp_[A-Za-z0-9_]+)(?:\{|\s)',args.metrics.read_text(),re.M))
unsampled={name for name in expected if name not in sampled and not (name+'_bucket' in sampled or name+'_count' in sampled)}
if unsampled:errors.append('MISSING_REAL_SAMPLE '+str(sorted(unsampled)))
alert_refs=set(re.findall(r'\b(yarp_[A-Za-z0-9_]+|probe_[A-Za-z0-9_]+)\b',args.alerts.read_text()))
dashboard=json.loads(args.dashboard.read_text())
expressions=' '.join(t.get('expr','') for panel in dashboard['panels'] for t in panel.get('targets',[]))
dashboard_refs=set(re.findall(r'\b(yarp_[A-Za-z0-9_]+|probe_[A-Za-z0-9_]+)\b',expressions))
allowed_external={'probe_ssl_earliest_cert_expiry','probe_success'}
for source,refs in [('ALERT',alert_refs),('DASHBOARD',dashboard_refs)]:
    # Histogram suffixes are samples of the # TYPE family; do not invent separate TYPE entries.
    unknown={name for name in refs if name not in actual and name not in allowed_external and
             not (name.endswith('_bucket') and name[:-7] in actual)}
    if unknown:errors.append('UNKNOWN_'+source+'_METRIC '+str(sorted(unknown)))
    missing_shipping={x for x in refs if x.startswith('yarp_') and x not in sampled and
                      not (x.endswith('_bucket') and x in sampled)}
    if missing_shipping:errors.append('UNEMITTED_'+source+'_METRIC '+str(sorted(missing_shipping)))
report={'result':'PASS' if not errors else 'FAIL','real_series_count':len(actual),
  'contract_series_count':len(expected),'alert_references':sorted(alert_refs),
  'dashboard_references':sorted(dashboard_refs),'external_probe_not_product':sorted(allowed_external),
  'errors':errors}
print(json.dumps(report,indent=2))
sys.exit(bool(errors))
