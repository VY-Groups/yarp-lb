#!/usr/bin/env python3
"""One-hour weighted oha traffic generator for ops/capacity/report.py.

Executes all weighted URLs concurrently in every 60s window, retains one raw
JSON per profile, and records an aggregate conservatively. Never fabricates
or suppresses failures. Run on independent real generator hosts (NOT CI).
"""
import argparse
import datetime as dt
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit
from contract import validate

p=argparse.ArgumentParser()
p.add_argument('--scenario',type=Path,required=True)
p.add_argument('--host-id',required=True)
p.add_argument('--out',type=Path,required=True)
p.add_argument('--start-at-utc')
p.add_argument('--dry-run',action='store_true')
args=p.parse_args()
scenario=json.loads(args.scenario.read_text())
validate(scenario)
if scenario.get('tool','oha')!='oha':p.error('oha only')
if args.host_id not in scenario['hosts']:p.error('generator host identity mismatch')
for key in ('requests_per_second_per_host','connections_per_host','threads'):
    v=scenario.get(key)
    if type(v) is not int or v<1:p.error('REQUIRED_INPUT '+key)
mix=scenario['response_mix']

def allocate(total):
    portions=[int(total*x['weight']) for x in mix]
    rest=total-sum(portions)
    for i in sorted(range(len(mix)),key=lambda i:-(total*mix[i]['weight']-portions[i]))[:rest]:
        portions[i]+=1
    if any(v<1 for v in portions):p.error('insufficient rate/connections for all weighted profiles')
    return portions

rates=allocate(scenario['requests_per_second_per_host'])
connections=allocate(scenario['connections_per_host'])
commands=[]
for profile,rate,conn in zip(mix,rates,connections):
    cmd=['oha','--no-tui','--output-format','json','--latency-correction','--disable-compression',
         '-z',str(scenario['window_seconds'])+'s','-q',str(rate),'-c',str(conn),
         '--worker-threads',str(scenario['threads']),
         '--http-version',scenario['http_version']]
    if not scenario['keepalive']:cmd.append('--disable-keepalive')
    if urlsplit(profile['url']).scheme=='https':cmd+=['--cacert',scenario['tls_ca_file']]
    cmd.append(profile['url'])
    commands.append(cmd)
if args.dry_run:
    print(json.dumps({'host_id':args.host_id,'rates':rates,'connections':connections,
          'commands':commands,'windows':scenario['windows']},indent=2))
    sys.exit(0)
if not shutil.which('oha'):sys.exit('NOT RUN: install oha on the approved generator')
if args.start_at_utc:
    start=dt.datetime.fromisoformat(args.start_at_utc.replace('Z','+00:00'))
    if start.tzinfo is None:p.error('start timestamp requires UTC offset')
    wait=(start-dt.datetime.now(dt.timezone.utc)).total_seconds()
    if wait < -2:p.error('start already passed; clock drift')
    if wait>0:time.sleep(wait)
args.out.mkdir(parents=True,exist_ok=True)
manifest={'host_id':args.host_id,'scenario':scenario,'engine':'oha',
          'command_matrix':commands,'windows':[]}
for index in range(scenario['windows']):
    launches=[]
    for j,cmd in enumerate(commands):
        started=dt.datetime.now(dt.timezone.utc)
        mono=time.monotonic()
        proc=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        launches.append((j,proc,started,mono))
    data=[];times=[];parts=[];fatal=0
    for j,proc,started,mono in launches:
        stdout,stderr=proc.communicate()
        ended=dt.datetime.now(dt.timezone.utc)
        raw_name=f'window-{index:03d}-profile-{mix[j]["name"]}.json'
        (args.out/raw_name).write_text(stdout)
        (args.out/(raw_name+'.stderr')).write_text(stderr)
        part={'name':mix[j]['name'],'raw':raw_name,'returncode':proc.returncode,
              'start_utc':started.isoformat(),'end_utc':ended.isoformat(),
              'elapsed_seconds':time.monotonic()-mono}
        parts.append(part);times.append((started,ended))
        fatal=max(fatal,abs(proc.returncode))
        try:data.append(json.loads(stdout))
        except json.JSONDecodeError:
            fatal=1;data.append(None)
    began=min(x[0] for x in times);ended=max(x[1] for x in times)
    wall=(ended-began).total_seconds()
    if fatal==0:
        summaries=[x['summary'] for x in data]
        statuses={};errors={};per=[]
        for j,raw in enumerate(data):
            for code,n in raw['statusCodeDistribution'].items():statuses[code]=statuses.get(code,0)+n
            for reason,n in raw['errorDistribution'].items():errors[reason]=errors.get(reason,0)+n
            count=sum(raw['statusCodeDistribution'].values())
            per.append({'name':mix[j]['name'],'url':mix[j]['url'],'count':count,
                        'body_bytes':raw['summary']['totalData'],
                        'raw_artifact':parts[j]['raw']})
        duration=max(x['total'] for x in summaries)
        responses=sum(x['count'] for x in per)
        agg={'summary':{'total':duration,'requestsPerSec':responses/duration,
               'totalData':sum(x['body_bytes'] for x in per),
               'successRate':min(x['successRate'] for x in summaries)},
             'latencyPercentiles':{key:max(x['latencyPercentiles'][key] for x in data)
                   for key in ('p50','p95','p99')},
             'statusCodeDistribution':statuses,'errorDistribution':errors,
             'perProfile':per}
        (args.out/f'window-{index:03d}.json').write_text(json.dumps(agg,indent=2))
    item={'index':index,'start_utc':began.isoformat(),'end_utc':ended.isoformat(),
          'wall_seconds':wall,'returncode':fatal,'artifact':f'window-{index:03d}.json',
          'profiles':parts}
    manifest['windows'].append(item)
    (args.out/'manifest.json').write_text(json.dumps(manifest,indent=2))
    print(json.dumps({'index':index,'returncode':fatal,'profiles':parts}),flush=True)
    if fatal:
        sys.exit('NO-GO: weighted oha subprofile failed; raw stderr retained')
print('Completed all weighted windows; evaluate report.py with real gateway CSV')
