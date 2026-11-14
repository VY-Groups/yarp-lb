#!/usr/bin/env python3
"""Fail-closed real-scrape to source contract and PromQL metric name reconciliation."""
import argparse
import json
import re
from pathlib import Path

REQUIRED_TYPE = re.compile(r'^# TYPE ([a-zA-Z_:][a-zA-Z0-9_:]*)\s', re.M)
SERIES = re.compile(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)\s*(?:\{|\s)', re.M)
PROMQL_YARP = re.compile(r'\b(yarp_[a-zA-Z0-9_:]+)\b')
PROMQL_EXTERNAL = re.compile(r'\b(probe_[a-zA-Z0-9_:]+)\b')

def parse_contract(source):
    required=set(re.findall(r'^- \x60(yarp_[a-zA-Z0-9_]+)\x60$',source,re.M))
    external=set(re.findall(r'^- \x60(probe_[a-zA-Z0-9_]+|up)\x60$',source,re.M))
    if len(required)<10:raise ValueError('METRIC_CONTRACT is incomplete: expected >=10 real metrics')
    if not external:raise ValueError('METRIC_CONTRACT missing explicitly scoped external series')
    return required,external

def evaluate(metrics,contract,alerts,dashboard):
    expected,external=parse_contract(contract)
    actual=set()
    for raw in metrics.splitlines():
        line=raw.strip()
        if not line or line.startswith('#'):continue
        m=re.match(r'([a-zA-Z_:][a-zA-Z0-9_:]*)\s*(?:\{|\s)',line)
        if m:actual.add(m.group(1))
    missing=sorted(expected-actual)
    unapproved=set()
    queried=set()
    for line in alerts.splitlines():
        if not line.lstrip().startswith('expr:'):continue
        expr=line.split('expr:',1)[1]
        queried.update(PROMQL_YARP.findall(expr))
        for name in PROMQL_EXTERNAL.findall(expr):
            if name not in external:unapproved.add(name)
    try:
        dash=json.loads(dashboard)
        panels=dash.get('panels',[])
        if not panels:raise ValueError('no panels')
        for panel in panels:
            for query in panel.get('targets',[]):
                queried.update(PROMQL_YARP.findall(query.get('expr','')))
                for name in PROMQL_EXTERNAL.findall(query.get('expr','')):
                    if name not in external:unapproved.add(name)
    except (ValueError,TypeError,KeyError) as e:
        return {'decision':'NO-GO','errors':['DASHBOARD_INVALID:'+str(e)]}
    unknown=sorted((queried-expected)|unapproved)
    # A typo in a rule cannot silently suppress the alert; the exporter itself
    # and the contract must agree, not just source text.
    errors=['MISSING_REAL_SERIES:'+x for x in missing] + ['UNDEFINED_ALERT_OR_DASHBOARD_SERIES:'+x for x in unknown]
    if not queried:errors.append('ALERT_METRICS_EMPTY')
    return {'decision':'GO' if not errors else 'NO-GO','metric_count':len(actual),
            'contract_count':len(expected),'queried_series':sorted(queried),'external_series':sorted(external),'errors':errors}

def main():
    parser=argparse.ArgumentParser()
    for key in ('metrics','contract','alerts','dashboard','out'):
        parser.add_argument('--'+key.replace('_','-'),type=Path,required=True)
    a=parser.parse_args()
    try: result=evaluate(a.metrics.read_text(),a.contract.read_text(),a.alerts.read_text(),a.dashboard.read_text())
    except (OSError,ValueError) as exc:result={'decision':'NO-GO','errors':['MISSING_OR_INVALID_INPUT:'+str(exc)]}
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
    if result['decision']!='GO':raise SystemExit(1)

if __name__=='__main__':main()
