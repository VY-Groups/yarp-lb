#!/usr/bin/env python3
"""Real socket validation of the shipping .NET 10 Control Center; disposable CI only."""
import argparse
import http.client
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
from urllib.request import build_opener, ProxyHandler, HTTPSHandler, HTTPCookieProcessor, Request
from http.cookiejar import CookieJar
from urllib.error import HTTPError, URLError

parser = argparse.ArgumentParser()
parser.add_argument('--dll', type=Path, required=True)
parser.add_argument('--out', type=Path, required=True)
parser.add_argument('--exercise-vip-address-transition', action='store_true', help='disposable Linux CI only: temporarily add/remove 127.0.0.4/32 on lo')
args=parser.parse_args()
args.out.mkdir(parents=True,exist_ok=True)
evidence=[]
def check(ok,name,detail=None):
    evidence.append({'name':name,'passed':bool(ok),'detail':detail})
    if not ok: raise AssertionError(name+': '+str(detail))
def run(*cmd):
    return subprocess.run(cmd,check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
def chmod(path): path.chmod(0o600)
def req(url,context=None,method='GET',headers=None):
    opener=build_opener(ProxyHandler({}),HTTPSHandler(context=context or ssl.create_default_context()))
    try:
        with opener.open(Request(url,method=method,headers=headers or {}),timeout=3) as response:
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
    release_stream=threading.Event()
    def do_GET(self):
        if self.path == '/api/virtual-stream':
            self.send_response(200);self.send_header('Content-Length','10');self.end_headers()
            try:
                self.wfile.write(b'first');self.wfile.flush()
                self.release_stream.wait(15)
                self.wfile.write(b'last!');self.wfile.flush()
            except (BrokenPipeError,ConnectionResetError):pass
            return
        if self.path == '/health/ready': status,body=200,b'ok'
        elif self.path == '/api/identity': status,body=200,b'{"node":"CI"}'
        elif self.path == '/api/virtual-http': status,body=200,b'virtual-http'
        elif self.path == '/api/virtual-https': status,body=200,b'virtual-https'
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
          'ReverseProxy':{'Routes':{
              'api':{'ClusterId':'api','Match':{'Path':'/api/{**catch-all}'}},
              'virtual-http':{'ClusterId':'api','Match':{'Path':'/api/{**catch-all}'},
                  'Metadata':{'ADC.VirtualServer.Id':'vip-http'},'Transforms':[{'PathSet':'/api/virtual-http'}]},
              'virtual-https':{'ClusterId':'api','Match':{'Path':'/api/{**catch-all}'},
                  'Metadata':{'ADC.VirtualServer.Id':'vip-https'},'Transforms':[{'PathSet':'/api/virtual-https'}]},
              'restricted':{'ClusterId':'api','Match':{'Path':'/restricted'},
                  'Metadata':{'ADC.Access.RequireHttps':'true','ADC.Access.AllowedNetworks':'127.0.0.1/32'},
                  'Transforms':[{'PathSet':'/api/identity'}]},
              'denied':{'ClusterId':'api','Match':{'Path':'/denied'},
                  'Metadata':{'ADC.Access.AllowedNetworks':'192.0.2.0/24'},
                  'Transforms':[{'PathSet':'/api/identity'}]},
              'legacy-only':{'ClusterId':'api','Match':{'Path':'/legacy-only'},'Transforms':[{'PathSet':'/api/identity'}]},
              'virtual-only':{'ClusterId':'api','Match':{'Path':'/virtual-only'},
                  'Metadata':{'ADC.VirtualServer.Id':'vip-http'},'Transforms':[{'PathSet':'/api/virtual-http'}]}},
          'Clusters':{'api':{'HealthCheck':{'AvailableDestinationsPolicy':'HealthyAndUnknown',
          'Active':{'Enabled':True,'Interval':'00:00:01','Timeout':'00:00:01',
          'Policy':'ConsecutiveFailures','Path':'/health/ready'}},
          'Destinations':{'A':{'Address':f'http://127.0.0.1:{backend_port}/','Metadata':{
              'GatewayCore.Admission.MaxInFlight':'8',
              'GatewayCore.Admission.MaxPending':'4',
              'GatewayCore.Admission.QueueTimeoutMs':'1000'}}}}}}}))
        if args.exercise_vip_address_transition:
            fixture=json.loads(appconfig.read_text())
            fixture['ReverseProxy']['Routes']['guarded-vip']={'ClusterId':'api',
                'Match':{'Path':'/api/{**catch-all}'},'Metadata':{'ADC.VirtualServer.Id':'vip-guarded'},
                'Transforms':[{'PathSet':'/api/virtual-http'}]}
            fixture['ReverseProxy']['Routes']['guarded-stream']={'ClusterId':'api',
                'Match':{'Path':'/stream'},'Metadata':{'ADC.VirtualServer.Id':'vip-guarded'},
                'Transforms':[{'PathSet':'/api/virtual-stream'}]}
            fixture['ReverseProxy']['Routes']['guarded-second']={'ClusterId':'api',
                'Match':{'Path':'/api/{**catch-all}'},'Metadata':{'ADC.VirtualServer.Id':'vip-guarded-second'},
                'Transforms':[{'PathSet':'/api/virtual-http'}]}
            appconfig.write_text(json.dumps(fixture))
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
            '-days','7','-subj','/CN=CI-DP',
            '-addext','basicConstraints=critical,CA:FALSE',
            '-addext','keyUsage=critical,keyEncipherment',
            '-keyout',str(dp_key),'-out',str(dp_crt))
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
        vip_http=available('127.0.0.3')
        vip_https=available('127.0.0.2')
        while vip_https in ports or vip_https==vip_http: vip_https=available('127.0.0.2')
        settings['virtualServices']=[{'id':'vip-http','ip':'127.0.0.3','port':vip_http,'protocol':'HTTP'},
            {'id':'vip-https','ip':'127.0.0.2','port':vip_https,'protocol':'HTTPS'}]
        if args.exercise_vip_address_transition:
            existing=json.loads(run('ip','-j','address','show','dev','lo').stdout)
            check(not any(a.get('local')=='127.0.0.4' for i in existing for a in i.get('addr_info',[])),
                  'disposable VIP fixture address initially absent')
            guarded_port=available('127.0.0.4')
            settings['virtualServices'].append({'id':'vip-guarded','ip':'127.0.0.4',
                'port':guarded_port,'protocol':'HTTP','requireLocalAddressPresence':True})
            guarded_second_port=available('127.0.0.4')
            while guarded_second_port==guarded_port:guarded_second_port=available('127.0.0.4')
            settings['virtualServices'].append({'id':'vip-guarded-second','ip':'127.0.0.4',
                'port':guarded_second_port,'protocol':'HTTP','requireLocalAddressPresence':True})
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
            status,body=req(f'http://127.0.0.3:{vip_http}/api/identity')
            check(status==200 and body==b'virtual-http','overlapping route selected by real HTTP virtual socket')
            status,body=req(f'https://127.0.0.2:{vip_https}/api/identity',ca_context)
            check(status==200 and body==b'virtual-https','overlapping route selected by real TLS virtual socket')
            if args.exercise_vip_address_transition:
                guarded_url=f'http://127.0.0.4:{guarded_port}/api/identity'
                def await_status(expected):
                    deadline=time.monotonic()+10
                    status,body=None,None
                    while time.monotonic()<deadline:
                        status,body=req(guarded_url)
                        if status==expected:return status,body
                        time.sleep(.2)
                    return status,body
                check(await_status(503)[0]==503,'guarded virtual socket refuses unassigned loopback IP')
                run('sudo','-n','ip','address','add','127.0.0.4/32','dev','lo')
                connection=http.client.HTTPConnection('127.0.0.4',guarded_port,timeout=7)
                try:
                    try:
                        status,body=await_status(200)
                        check(status==200 and body==b'virtual-http','fresh assigned local VIP admits real proxy traffic')
                        # Exercise the real authenticated management workflow before emergency withdrawal.
                        admin_base=f'https://127.0.0.1:{ports[2]}'
                        opener=build_opener(ProxyHandler({}),HTTPSHandler(context=client_context),HTTPCookieProcessor(CookieJar()))
                        csrf=None
                        def admin(method,path,payload=None,expected=200,include_csrf=True):
                            headers={'Accept':'application/json'}
                            if payload is not None:headers['Content-Type']='application/json'
                            if csrf and include_csrf:headers['X-CSRF-Token']=csrf
                            data=None if payload is None else json.dumps(payload).encode()
                            try:
                                with opener.open(Request(admin_base+path,data=data,method=method,headers=headers),timeout=5) as reply:
                                    code,raw=reply.status,reply.read()
                            except HTTPError as error:code,raw=error.code,error.read()
                            check(code==expected,'administrator '+method+' '+path+' status',code)
                            return json.loads(raw) if code==200 else None
                        admin('POST','/admin/api/bootstrap',{'username':'vip-ci-admin',
                            'password':secrets.token_hex(24),'email':'vip-ci@example.invalid'})
                        session=admin('GET','/admin/api/session')
                        csrf=session['csrf']
                        if not session['privacyAccepted']:
                            admin('POST','/admin/api/privacy/accept',{'version':session['privacyVersion']})
                        check(session['role']=='Administrator' and bool(csrf),'real mTLS administrator session')
                        policy_path='/admin/api/network/virtual-services/ha-policy'
                        policy={'version':1,'scope':'A'*64,'preferredPin':'B'*64,'otherPin':'C'*64,
                                'failbackEnabled':False,'rearmEnabled':False,'pollSeconds':5,
                                'failureSamples':3,'failureSeconds':10,'failbackEligibleSeconds':120,
                                'minimumOwnerSeconds':300}
                        # A local-only VIP cannot export a distributed HA policy;
                        # valid administrator credentials do not bypass scope checks.
                        admin('POST',policy_path,policy,expected=403,include_csrf=False)
                        admin('POST',policy_path,policy,expected=400)
                        drain_path='/admin/api/network/virtual-services/vip-guarded/drain'
                        drain={'draining':True,'reason':'Disposable planned drain acceptance'}
                        second_url=f'http://127.0.0.4:{guarded_second_port}/api/identity'
                        check(req(second_url)[0]==200,'second socket shares same active VIP')
                        admin('POST',drain_path,drain,expected=403,include_csrf=False)
                        connection.request('GET','/stream')
                        response=connection.getresponse()
                        check(response.status==200 and response.read(5)==b'first','real stream active before planned drain')
                        result=admin('POST',drain_path,drain)
                        check(result['plannedDrain'] and result['activeGuardedRequests']>=1,
                              'drain preserves already-admitted stream')
                        check(req(guarded_url)[0]==503 and req(second_url)[0]==503,
                              'planned drain denies both sockets on the same address')
                        Backend.release_stream.set()
                        check(response.read()==b'last!','planned drain allows healthy stream to complete')
                        connection.close()
                        deadline=time.monotonic()+5
                        while True:
                            rows=admin('GET','/admin/api/network/interfaces')['virtualAddresses']
                            group=[row for row in rows if row['ip']=='127.0.0.4']
                            if len(group)==2 and all(row['plannedDrain'] and row['activeGuardedRequests']==0 for row in group):break
                            if time.monotonic()>=deadline:raise AssertionError('drain counts did not converge')
                            time.sleep(.1)
                        check(True,'both drained sockets report zero tracked requests')
                        # A durable drain survives an actual service restart.
                        proc.terminate()
                        proc.communicate(timeout=8)
                        proc=subprocess.Popen(['dotnet',str(args.dll.resolve())],env=env,
                            cwd=str(Path(__file__).resolve().parents[3] / 'control-center'),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                        deadline=time.monotonic()+25
                        while True:
                            try:
                                if req(ready_url)[0]==200:break
                            except (URLError,TimeoutError,ConnectionError,OSError):pass
                            if proc.poll() is not None or time.monotonic()>=deadline:raise AssertionError('drained service restart failed')
                            time.sleep(.2)
                        check(req(guarded_url)[0]==503 and req(second_url)[0]==503,'persistent drain survives real service restart')
                        deadline=time.monotonic()+10
                        while True:
                            rows=admin('GET','/admin/api/network/interfaces')['virtualAddresses']
                            group=[row for row in rows if row['ip']=='127.0.0.4']
                            if len(group)==2 and all(row['admission']=='present-interface-up' for row in group):break
                            if time.monotonic()>=deadline:raise AssertionError('fresh ownership observation unavailable')
                            time.sleep(.2)
                        admin('POST',drain_path,{'draining':False,'reason':'Disposable planned resume acceptance'})
                        check(req(guarded_url)[0]==200 and req(second_url)[0]==200,'explicit resume opens both sockets')
                        Backend.release_stream.clear()
                        connection=http.client.HTTPConnection('127.0.0.4',guarded_port,timeout=7)
                        connection.request('GET','/stream')
                        response=connection.getresponse()
                        check(response.status==200 and response.read(5)==b'first','real guarded stream is in flight')
                    finally:
                        run('sudo','-n','ip','address','del','127.0.0.4/32','dev','lo')
                    aborted=False
                    try:
                        response.read()
                    except (http.client.IncompleteRead,ConnectionResetError,ConnectionAbortedError):
                        aborted=True
                    check(aborted,'withdrawal aborts in-flight response before backend completion')
                    check(await_status(503)[0]==503,'withdrawn VIP closes new requests on still-bound socket')
                finally:
                    Backend.release_stream.set()
                    connection.close()
            status,body=req(f'http://127.0.0.2:{ports[0]}/api/identity')
            check(status==200 and body==b'{"node":"CI"}','legacy listener still selects unbound route')
            status,_=req(f'http://127.0.0.3:{vip_http}/legacy-only')
            check(status==404,'unbound route cannot leak onto virtual socket',status)
            status,_=req(f'http://127.0.0.2:{ports[0]}/virtual-only')
            check(status==404,'bound route cannot leak onto default socket',status)
            status,_=req(f'https://127.0.0.2:{vip_https}/virtual-only',ca_context)
            check(status==404,'bound route cannot leak onto another virtual socket',status)
            status,_=req(f'http://127.0.0.3:{vip_http}/dashboard')
            check(status==403,'virtual service cannot expose management dashboard',status)
            status,_=req(f'http://127.0.0.2:{ports[0]}/restricted',headers={'X-Forwarded-Proto':'https'})
            check(status==403,'spoofed forwarded scheme cannot bypass TLS requirement',status)
            status,body=req(f'https://127.0.0.2:{ports[1]}/restricted',ca_context)
            check(status==200 and body==b'{"node":"CI"}','TLS and allowed real socket peer admitted',status)
            status,_=req(f'https://127.0.0.2:{ports[1]}/denied',ca_context,
                headers={'X-Forwarded-For':'192.0.2.7','Forwarded':'for=192.0.2.7'})
            check(status==403,'spoofed source cannot bypass route network policy',status)
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
                  'yarp_control_gc_collections_total{generation="2"}' in text and
                  'yarp_control_destination_admission_inflight_requests{destination="api/A"}' in text and
                  'yarp_control_destination_admission_queue_wait_seconds_count{destination="api/A"}' in text,
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
