#!/usr/bin/env python3
"""Real socket validation of the shipping .NET 10 Control Center; disposable CI only."""
import argparse
import json
import os
import secrets
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.request import build_opener, ProxyHandler, HTTPSHandler, Request
from urllib.error import HTTPError, URLError

parser = argparse.ArgumentParser()
parser.add_argument('--dll', type=Path, required=True)
parser.add_argument('--out', type=Path, required=True)
args=parser.parse_args()
args.out.mkdir(parents=True,exist_ok=True)
evidence=[]
def check(ok,name,detail=None):
    evidence.append({'name':name,'passed':bool(ok),'detail':detail})
    if not ok: raise AssertionError(name+': '+str(detail))
def run(*cmd):
    return subprocess.run(cmd,check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
def chmod(path): path.chmod(0o600)
def req(url,context=None,method='GET'):
    opener=build_opener(ProxyHandler({}),HTTPSHandler(context=context or ssl.create_default_context()))
    try:
        with opener.open(Request(url,method=method),timeout=3) as response:
            return response.status,response.read()
    except HTTPError as error:
        return error.code,error.read()
def available(ip):
    with socket.socket() as sock:
        sock.bind((ip,0));return sock.getsockname()[1]
def denied(ip,port):
    try:
        with socket.create_connection((ip,port),timeout=0.7): return False
    except OSError: return True
def generate_signed(root,name,subject,san,usage,ca_key,ca_crt):
    key=root/(name+'.key');csr=root/(name+'.csr');crt=root/(name+'.crt')
    run('openssl','req','-new','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes',
        '-subj','/CN='+subject,'-keyout',str(key),'-out',str(csr))
    ext=root/(name+'.ext');ext.write_text('subjectAltName='+san+'\nextendedKeyUsage='+usage+'\n')
    run('openssl','x509','-req','-in',str(csr),'-CA',str(ca_crt),'-CAkey',str(ca_key),
        '-CAcreateserial','-days','2','-sha256','-extfile',str(ext),'-out',str(crt))
    chmod(key)
    return key,crt
def pfx(root,name,key,crt,ca):
    output=root/(name+'.pfx');passfile=root/(name+'.password')
    passfile.write_text(secrets.token_hex(20));chmod(passfile)
    run('openssl','pkcs12','-export','-in',str(crt),'-inkey',str(key),
        '-certfile',str(ca),'-out',str(output),'-passout','file:'+str(passfile))
    chmod(output);return output,passfile

class Backend(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/health/ready': status,body=200,b'ok'
        elif self.path == '/api/identity': status,body=200,b'{"node":"CI"}'
        else: status,body=404,b'not found'
        self.send_response(status);self.send_header('Content-Length',str(len(body)))
        self.end_headers();self.wfile.write(body)
    def log_message(self,*_args): pass

failure=None
with tempfile.TemporaryDirectory(prefix='gateway-sockets-') as td:
    root=Path(td);state=root/'state';state.mkdir(mode=0o700)
    cfg=state/'config';cfg.mkdir(mode=0o700)
    appconfig=cfg/'appsettings.json'
    with ThreadingHTTPServer(('127.0.0.1',0),Backend) as backend:
        threading.Thread(target=backend.serve_forever,daemon=True).start()
        backend_port=backend.server_address[1]
        appconfig.write_text(json.dumps({'Logging':{'LogLevel':{'Default':'Warning'}},
          'ReverseProxy':{'Routes':{'api':{'ClusterId':'api','Match':{'Path':'/api/{**catch-all}'}}},
          'Clusters':{'api':{'HealthCheck':{'AvailableDestinationsPolicy':'HealthyAndUnknown',
          'Active':{'Enabled':True,'Interval':'00:00:01','Timeout':'00:00:01',
          'Policy':'ConsecutiveFailures','Path':'/health/ready'}},
          'Destinations':{'A':{'Address':f'http://127.0.0.1:{backend_port}/'}}}}}}))
        chmod(appconfig)
        ca_key=root/'ca.key';ca_crt=root/'ca.crt'
        run('openssl','req','-new','-x509','-nodes','-newkey','rsa:3072',
            '-sha256','-days','3','-subj','/CN=Disposable-0.1-Lab-CA',
            '-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=keyCertSign,cRLSign',
            '-keyout',str(ca_key),'-out',str(ca_crt))
        traffic_key,traffic_crt=generate_signed(root,'traffic','127.0.0.2','IP:127.0.0.2','serverAuth',ca_key,ca_crt)
        mgmt_key,mgmt_crt=generate_signed(root,'management','127.0.0.1','IP:127.0.0.1','serverAuth',ca_key,ca_crt)
        client_key,client_crt=generate_signed(root,'client','ci-operator','DNS:ci-operator','clientAuth',ca_key,ca_crt)
        traffic_pfx,traffic_password=pfx(root,'traffic',traffic_key,traffic_crt,ca_crt)
        mgmt_pfx,mgmt_password=pfx(root,'mgmt',mgmt_key,mgmt_crt,ca_crt)
        dp_key=root/'dp.key';dp_crt=root/'dp.crt'
        run('openssl','req','-new','-x509','-nodes','-newkey','rsa:3072','-sha256',
            '-days','7','-subj','/CN=CI-DP','-keyout',str(dp_key),'-out',str(dp_crt))
        dp_pfx,dp_password=pfx(root,'dp',dp_key,dp_crt,ca_crt)
        thumb=run('openssl','x509','-in',str(client_crt),'-fingerprint','-sha1','-noout').stdout.split('=',1)[1].strip().replace(':','')
        ports=[available('127.0.0.2') for _ in range(2)]+[available('127.0.0.1') for _ in range(2)]
        while len(set(ports))!=4:ports=[available('127.0.0.2') for _ in range(2)]+[available('127.0.0.1') for _ in range(2)]
        settings={'trafficIp':'127.0.0.2','trafficHttpPort':ports[0],'trafficHttpsPort':ports[1],
                  'managementIp':'127.0.0.1','adminPort':ports[2],'metricsPort':ports[3],
                  'trafficPfxPath':str(traffic_pfx),'trafficPfxPasswordFile':str(traffic_password),
                  'managementPfxPath':str(mgmt_pfx),'managementPfxPasswordFile':str(mgmt_password),
                  'clientCaPemPath':str(ca_crt),'clientThumbprints':[thumb],
                  'allowedAdminCidrs':['127.0.0.1/32'],'maxConcurrentConnections':1500,'httpVersion':'1.1'}
        config=root/'listeners.json'
        def write_config(payload):
            config.write_text(json.dumps(payload));chmod(config)
        write_config(settings)
        env=os.environ.copy()
        env.update({'ASPNETCORE_ENVIRONMENT':'Production',
        'YARP_CONTROL_PLANE_DIR':str(state),'YARP_RUNTIME_CONFIG_PATH':str(appconfig),
        'YARP_LINUX_DP_CERT_PFX_PATH':str(dp_pfx),'YARP_LINUX_DP_CERT_PASSWORD_FILE':str(dp_password),
        'YARP_LISTENERS_CONFIG_FILE':str(config)})
        env.pop('YARP_EC2_LAB_MODE',None)
        proc=subprocess.Popen(['dotnet',str(args.dll.resolve())],env=env,
            cwd=str(Path(__file__).resolve().parents[3] / 'control-center'),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        ca_context=ssl.create_default_context(cafile=str(ca_crt))
        client_context=ssl.create_default_context(cafile=str(ca_crt))
        client_context.load_cert_chain(str(client_crt),str(client_key))
        ready_url=f'http://127.0.0.2:{ports[0]}/gateway/health/ready'
        try:
            ok=False
            for _ in range(130):
                if proc.poll() is not None:break
                try:
                    status,_=req(ready_url)
                    if status==200:ok=True;break
                except (URLError,TimeoutError,ConnectionError,OSError):pass
                time.sleep(0.2)
            check(ok,'real shipping gateway ready on data-plane IP',{'port':ports[0],'exited':proc.poll()})
            status,_=req(f'http://127.0.0.2:{ports[0]}/api/identity')
            check(status==200,'YARP forwards over dedicated traffic HTTP listener',status)
            status,_=req(f'https://127.0.0.2:{ports[1]}/api/identity',ca_context)
            check(status==200,'P-256 HTTPS data listener validates server chain and SAN',status)
            check(denied('127.0.0.2',ports[2]),'admin socket unreachable on data-plane IP')
            check(denied('127.0.0.2',ports[3]),'metrics socket unreachable on data-plane IP')
            check(denied('127.0.0.1',ports[0]),'traffic socket unreachable on management IP')
            status,_=req(f'http://127.0.0.2:{ports[0]}/dashboard')
            check(status==403,'data listener cannot reach admin UI',status)
            status,_=req(f'http://127.0.0.2:{ports[0]}/gateway/metrics')
            check(status==403,'data listener cannot fetch metrics',status)
            no_client_denied=False
            try:
                status,_=req(f'https://127.0.0.1:{ports[2]}/dashboard',ca_context)
                no_client_denied=status==403
            except (ssl.SSLError,URLError,ConnectionResetError,OSError):no_client_denied=True
            check(no_client_denied,'admin refuses missing client certificate')
            status,_=req(f'https://127.0.0.1:{ports[2]}/dashboard',client_context)
            check(status==200,'allowed management client certificate and source IP admitted',status)
            status,body=req(f'https://127.0.0.1:{ports[3]}/gateway/metrics',client_context)
            check(status==200,'mTLS metrics listener reachable on management IP',status)
            text=body.decode('utf-8')
            check('yarp_control_http_requests_total ' in text and
                  'yarp_control_gc_collections_total{generation="2"}' in text,
                  'real HTTP and GC product metrics exported')
            (args.out/'metrics.txt').write_text(text)
        except Exception as error: failure=str(error)
        finally:
            proc.terminate()
            try: _,stderr=proc.communicate(timeout=8)
            except subprocess.TimeoutExpired:
                proc.kill();_,stderr=proc.communicate(timeout=5)
            (args.out/'product-stderr.txt').write_text(stderr[-6000:])
        if failure is None:
            bad=dict(settings);bad['managementIp']='0.0.0.0';write_config(bad)
            badproc=subprocess.Popen(['dotnet',str(args.dll.resolve())],cwd=str(Path(__file__).resolve().parents[3] / 'control-center'),
                env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            try:
                _,baderr=badproc.communicate(timeout=12)
                check(badproc.returncode!=0 and 'wildcard' in baderr.lower(),
                      'wildcard management and metrics address rejected before startup',
                      baderr[-450:])
            except subprocess.TimeoutExpired:
                badproc.kill();badproc.communicate()
                check(False,'wildcard listener unexpectedly remained running')
        else:
            evidence.append({'name':'fatal','passed':False,'detail':failure})

result={'decision':'PASS' if failure is None and all(x['passed'] for x in evidence) else 'FAIL',
        'checks':evidence,'note':'Single disposable runner; no physical host, line rate or production CA contacted'}
(args.out/'socket-results.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
if result['decision']!='PASS':raise SystemExit(1)
