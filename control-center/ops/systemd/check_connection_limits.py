#!/usr/bin/env python3
"""Fail-closed check of measured concurrency, real listener limit and systemd NOFILE."""
import argparse, json, math, re, sys
from pathlib import Path
p=argparse.ArgumentParser()
p.add_argument('--scenario',type=Path,required=True)
p.add_argument('--listeners',type=Path,required=True)
p.add_argument('--limits-dropin',type=Path,required=True)
p.add_argument('--out',type=Path,required=True)
a=p.parse_args()
errors=[]
try:
    scenario=json.loads(a.scenario.read_text())
    listeners=json.loads(a.listeners.read_text())
    peak=scenario.get('peak_concurrent_connections')
    maxcon=listeners.get('maxConcurrentConnections')
    assert type(peak) is int and peak>0, 'REQUIRED_INPUT peak_concurrent_connections'
    assert type(maxcon) is int and maxcon>0, 'REQUIRED_INPUT maxConcurrentConnections'
    required_concurrency=math.ceil(1.5*peak)
    if maxcon<required_concurrency:errors.append(f'CONNECTION_CAP_INSUFFICIENT:{maxcon} < {required_concurrency}')
    matches=re.findall(r'^LimitNOFILE=(\d+)$',a.limits_dropin.read_text(),re.M)
    assert len(matches)==1, 'REQUIRED_INPUT systemd LimitNOFILE exactly once'
    nofile=int(matches[0])
    required_nofile=math.ceil(2.5*maxcon+4096)
    if nofile<required_nofile:errors.append(f'NOFILE_INSUFFICIENT:{nofile} < {required_nofile}')
    report={'decision':'GO' if not errors else 'NO-GO','minimum_kestrel_connections':required_concurrency,
       'configured_kestrel_connections':maxcon,'minimum_limit_nofile':required_nofile,
       'configured_limit_nofile':nofile,'errors':errors}
except (OSError,ValueError,TypeError,KeyError,AssertionError) as e:
    report={'decision':'NO-GO','errors':errors+['MISSING_OR_INVALID_INPUT:'+str(e)]}
a.out.parent.mkdir(parents=True,exist_ok=True)
a.out.write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
sys.exit(0 if report['decision']=='GO' else 1)
