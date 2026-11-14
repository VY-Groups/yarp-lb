#!/usr/bin/env python3
"""20-second CI single-gateway diagnostic; never awards physical 1-hour release GO."""
import argparse
import json
import math
from pathlib import Path

def read_one(path):
    raw=json.loads(path.read_text())
    summary=raw['summary']
    duration=float(summary['total'])
    body=float(summary['totalData'])
    rps=float(summary['requestsPerSec'])
    codes=raw['statusCodeDistribution']
    errors=raw['errorDistribution']
    good=int(codes.get('200',0))
    bad=sum(int(value) for status,value in codes.items() if status != '200')
    transport=sum(int(value) for value in errors.values())
    assert duration>0 and math.isfinite(duration) and body>0 and math.isfinite(body)
    assert good>0 and bad>=0 and transport>=0 and math.isfinite(rps)
    assert int(summary['successRate']==1) == 1, 'successRate is not 100%'
    return {'duration_seconds':duration,'body_bytes':body,
            'body_gbps':body*8/(duration*1e9),'rps':rps,'http_2xx':good,
            'http_non200':bad,'transport_failures':transport,
            'p99_ms':float(raw['latencyPercentiles']['p99'])*1000}

def evaluate(folder,minimum):
    values={}
    for target in ('backend-a','gateway-a'):
        values[target]=read_one(folder/(target+'.json'))
    errors=[]
    for target,row in values.items():
        if row['http_non200'] or row['transport_failures']:
            errors.append(target+': errors are never allowed in this diagnostic')
        if row['body_gbps']<minimum:
            errors.append(target+': body throughput below diagnostic floor')
    return {'diagnostic':'CI 20-second 1MiB fixed-body, not actual mix or physical 1h',
            'required_body_gbps':minimum, 'results':values,
            'canary':'PASS' if not errors else 'FAIL','production_gate':'NOT_RUN','errors':errors}

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--folder',type=Path,required=True)
    p.add_argument('--required-gbps',type=float,required=True)
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args()
    result={'canary':'FAIL','production_gate':'NOT_RUN'}
    try:
        if not math.isfinite(a.required_gbps) or a.required_gbps<=0:raise ValueError('invalid minimum')
        result=evaluate(a.folder,a.required_gbps)
    except (OSError,KeyError,ValueError,TypeError,AssertionError) as exc:
        result={'canary':'FAIL','production_gate':'NOT_RUN','errors':[str(exc)]}
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
    if result['canary']!='PASS':raise SystemExit(1)

if __name__=='__main__':main()
