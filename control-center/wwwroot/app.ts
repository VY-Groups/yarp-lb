type Obj = Record<string, any>;
type State = {name:string;gateway:string;time:string;routes:Obj;clusters:Obj;disabled:Obj;mode:string;telemetry:string;revision:string};
let data:State = {name:'YARP Control Center',gateway:'unknown',time:'',routes:{},clusters:{},disabled:{},mode:'Local testing',telemetry:'',revision:''};
let viewHistory:string[]=[];let lastRenderedView='setup';let restoringNavigation=false;
function navigateBack(){if(viewHistory.length){restoringNavigation=true;view=viewHistory.pop()!;render()}else if(view!=='setup'){restoringNavigation=true;view='setup';render()}}
let view='setup';let dirty=false;let probes:Obj[]=[];let csrf='';let currentRole='';let currentUser='';let otpChallenge='';
const $=(id:string)=>document.getElementById(id)!;
const esc=(s:any)=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'} as Obj)[c]);
const keys=(o:Obj)=>Object.keys(o||{});
type OrgProfile={organizationName:string;sector:string;region:string;notes:string;revision:number;updatedBy:string;updatedUtc:string|null};
let orgProfile:OrgProfile|null=null;
const sectors=['general','technology','finance','healthcare','government','telecom','ecommerce','education','ca-pki','other'];
function updateBrand(){const name=orgProfile?.organizationName?.trim()||'YARP Control Center';
 document.querySelectorAll<HTMLElement>('[data-organization-name]').forEach(el=>el.textContent=name);
 document.title=name+' | YARP Control Center 0.1';
}
async function loadOrganization(){orgProfile=await api('/admin/api/organization');updateBrand()}
async function organizationPage(){try{await loadOrganization();const o=orgProfile!;
 $('content').innerHTML=`<div class="card"><div class="toolbar"><div><h2>Organization profile</h2><p class="subtle">One organization per controller installation. This is NOT multi-tenant isolation or automatic regulatory compliance.</p></div>${currentRole==='Administrator'?actionBtn(o.revision?'Edit organization':'Configure organization','org-edit',''):''}</div>
 <div class="rowline"><b>Name</b><span>${esc(o.organizationName||'Not configured')}</span></div>
 <div class="rowline"><b>Industry</b><span>${esc(o.sector)}</span></div>
 <div class="rowline"><b>Deployment region</b><span>${esc(o.region)}</span></div>
 <div class="rowline"><b>Revision</b><span>${esc(o.revision)}</span></div>
 <div class="rowline"><b>Notes</b><span>${esc(o.notes||'—')}</span></div>
 <div class="healthbanner">Industry selection changes guidance and labels only. CA/PKI, healthcare and financial services require their own policy approval, protocol tests and audit controls.</div></div>`;
 }catch(e){show('Organization profile failed: '+String(e),true)}}
function editOrganization(){if(currentRole!=='Administrator')return show('Administrator role required',true);
 const o=orgProfile||{organizationName:'',sector:'general',region:'unspecified',notes:'',revision:0,updatedBy:'',updatedUtc:null};
 modal('Organization setup','Enter the operator organization. This does not open ports or enable a new tenant.',[
 {name:'name',label:'Organization name',value:o.organizationName||''},
 {name:'sector',label:'Industry profile',value:o.sector||'general',options:sectors},
 {name:'region',label:'Region / deployment locality',value:o.region||'unspecified'},
 {name:'notes',label:'Notes (do not enter secrets)',value:o.notes||'none'}],v=>{
  void api('/admin/api/organization','PUT',{organizationName:v.name,sector:v.sector,region:v.region,notes:v.notes,expectedRevision:o.revision})
   .then(async()=>{show('Organization profile saved');if(!o.organizationName){view='setup';render()}else{await organizationPage()}}).catch(e=>show(String(e),true))
 });
}

const show=(message:string,error=false)=>{const el=$('notice');el.hidden=false;el.className='notice'+(error?' error':'');el.textContent=message;setTimeout(()=>{el.hidden=true},8000)};
async function api(url:string,method='GET',body?:any){const opts:RequestInit={method,credentials:'same-origin',headers:{}};if(method!=='GET'){(opts.headers as Obj)['Content-Type']='application/json';(opts.headers as Obj)['X-CSRF-Token']=csrf;opts.body=JSON.stringify(body??{})}const r=await fetch(url,opts);if(r.status===401){if(!['/admin/api/session','/admin/api/login','/admin/api/bootstrap','/admin/api/login/verify'].includes(url)){if(!$('app-shell').hidden){showLogin(false);$('auth-message').textContent='Your administrator session has expired or was invalidated. Sign in again. No security settings were changed.'}throw Error('Administrator session expired; please sign in again')}throw Error('Authentication failed. Check your credentials or verification code.')}if(r.status===403)throw Error('Access denied. This action requires an authorized role or valid CSRF token.');if(!r.ok){let e='HTTP '+r.status;try{e=(await r.json()).error??e}catch{}throw Error(e)}return await r.json()}
async function reload(){if(dirty&&!confirm('Discard unsaved changes and reload?'))return;try{data=await api('/admin/api/state');dirty=false;render();show('Latest configuration loaded')}catch(e){show(String(e),true)}}
function edit(){dirty=true;render()}
async function save(){
  const reason=prompt('Describe why this change is necessary (minimum 12 characters). A DIFFERENT administrator must approve it.');
  if(reason===null)return;
  try{
    const x=await api('/admin/api/change-requests','POST',{reason,payload:{routes:data.routes,clusters:data.clusters,disabled:data.disabled,revision:data.revision}});
    dirty=false;show('Request '+x.id+' submitted for independent approval. No live routing changed.');
    await reload();view='approvals';render();
  }catch(e){show(String(e),true)}
}
function actionBtn(text:string,action:string,id:string,klass='small-btn mini'){return `<button class="${klass}" data-action="${esc(action)}" data-id="${esc(id)}">${esc(text)}</button>`}
function destinationRows(){const arr:Obj[]=[];for(const cid of keys(data.clusters)){for(const did of keys(data.clusters[cid]?.Destinations)){arr.push({cid,did,address:data.clusters[cid].Destinations[did].Address,enabled:true})}}for(const id of keys(data.disabled)){const [cid,did]=id.split('::');arr.push({cid,did,address:data.disabled[id].Address,enabled:false})}return arr}
function summary(){return `<div class="stats"><div class="card"><h3>Gateway status</h3><div class="stat-number green">ONLINE</div><div class="stat-desc">Local application responding</div></div><div class="card"><h3>Configured routes</h3><div class="stat-number">${keys(data.routes).length}</div><div class="stat-desc">Saved / draft HTTP routing rules</div></div><div class="card"><h3>Backend clusters</h3><div class="stat-number">${keys(data.clusters).length}</div><div class="stat-desc">Independent balancing policies</div></div><div class="card"><h3>Enabled destinations</h3><div class="stat-number">${destinationRows().filter(x=>x.enabled).length}</div><div class="stat-desc">Configured, not necessarily healthy</div></div></div>`}
function overview(){let routes=keys(data.routes).slice(0,5).map(id=>`<div class="rowline"><div><b>${esc(id)}</b><div class="subtle mono">${esc(data.routes[id]?.Match?.Path||'—')}</div></div><span class="chip">${esc(data.routes[id]?.ClusterId||'—')}</span></div>`).join('')||'<div class="empty">No routes configured</div>';let nodes=destinationRows().slice(0,6).map(d=>`<div class="rowline"><div><b>${esc(d.did)}</b><div class="subtle mono">${esc(d.address)}</div></div><span class="chip ${d.enabled?'':'bad'}">${d.enabled?'Configured':'Disabled'}</span></div>`).join('')||'<div class="empty">No destinations configured</div>';return summary()+`<div class="grid2"><div class="card"><div class="flex"><h2 class="section-title">Traffic architecture</h2><span class="chip">Design view</span></div><div class="arch"><div class="archnode">Clients / Public & internal ingress</div><div class="arrow">↓</div><div class="archnode">Firewall / upstream HA VIP</div><div class="arrow">↓</div><div class="archnode accent">${esc(topologyModeName(topologyResponse?.plan?.mode||'standalone'))} (design topology)</div><div class="arrow">↓</div><div class="twonodes"><div class="archnode">Backend node 01</div><div class="archnode">Backend node 02</div></div><div class="arrow">↓</div><div class="archnode">Application-specific data services (optional)</div></div><div class="healthbanner">This gateway is one running instance. The onboarding design is metadata, not proof that a gateway fleet, VIP or backend is healthy.</div></div><div><div class="card"><h2 class="section-title">Route snapshot</h2>${routes}${actionBtn('Manage routes','switch','routes')}</div><div class="card card-spaced"><h2 class="section-title">Destinations</h2>${nodes}${actionBtn('Manage backends','switch','backends')}</div></div></div>`}
function routes(){const rows=keys(data.routes).map(id=>{const r=data.routes[id];return `<tr><td><b>${esc(id)}</b></td><td class="mono">${esc((r.Match?.Hosts||[]).join(', ')||'Any host')}</td><td class="mono">${esc(r.Match?.Path)}</td><td>${esc(r.ClusterId)}</td><td>${actionBtn('Edit','route-edit',id)} ${actionBtn('Advanced','route-advanced',id)} ${actionBtn('Delete','route-delete',id,'danger-btn mini')}</td></tr>`}).join('');return `<div class="toolbar"><div><h2>Routes</h2><p class="subtle">Map incoming host/path matches to clusters.</p></div>${actionBtn('+ Add route','route-add','')}</div><div class="tablewrap"><table><thead><tr><th>Route ID</th><th>Hosts</th><th>Path</th><th>Cluster</th><th>Actions</th></tr></thead><tbody>${rows||'<tr><td colspan="5" class="empty">No routes configured</td></tr>'}</tbody></table></div>`}
function clusters(){const rows=keys(data.clusters).map(id=>{const c=data.clusters[id];return `<tr><td><b>${esc(id)}</b></td><td>${esc(c.LoadBalancingPolicy||'Default')}</td><td>${keys(c.Destinations||{}).length}</td><td>${c.HealthCheck?.Active?.Enabled?'<span class="chip good">Enabled</span>':'<span class="chip">Disabled</span>'}</td><td>${actionBtn('Edit','cluster-edit',id)} ${actionBtn('Advanced','cluster-advanced',id)} ${actionBtn('Delete','cluster-delete',id,'danger-btn mini')}</td></tr>`}).join('');return `<div class="toolbar"><div><h2>Clusters</h2><p class="subtle">Balance and health-check each application separately.</p></div>${actionBtn('+ Add cluster','cluster-add','')}</div><div class="tablewrap"><table><thead><tr><th>Cluster</th><th>Policy</th><th>Active backends</th><th>Health checks</th><th>Actions</th></tr></thead><tbody>${rows||'<tr><td colspan="5" class="empty">No clusters configured</td></tr>'}</tbody></table></div>`}
function backends(){const rows=destinationRows().map(d=>`<tr><td><b>${esc(d.did)}</b><div class="subtle">${esc(d.cid)}</div></td><td class="mono">${esc(d.address)}</td><td><span class="chip ${d.enabled?'good':'bad'}">${d.enabled?'Enabled':'Disabled'}</span></td><td>${actionBtn(d.enabled?'Disable':'Enable','dest-toggle',d.cid+'::'+d.did)} ${actionBtn('Edit','dest-edit',d.cid+'::'+d.did)} ${actionBtn('Advanced','dest-advanced',d.cid+'::'+d.did)} ${actionBtn('Delete','dest-delete',d.cid+'::'+d.did,'danger-btn mini')}</td></tr>`).join('');return `<div class="toolbar"><div><h2>Backend destinations</h2><p class="subtle">Enable, disable, add, or edit nodes. Changes apply only after saving.</p></div>${actionBtn('+ Add backend','dest-add','')}</div><div class="tablewrap"><table><thead><tr><th>Destination</th><th>Address</th><th>Configured state</th><th>Actions</th></tr></thead><tbody>${rows||'<tr><td colspan="4" class="empty">No destinations</td></tr>'}</tbody></table></div><div class="healthbanner">Disabling a destination removes it from the YARP cluster configuration when saved. Existing in-flight requests may still complete. Do not use this alone for graceful drain of sensitive operations.</div>`}
function health(){const p=probes.map(d=>`<tr><td>${esc(d.cluster)} / ${esc(d.destination)}</td><td class="mono">${esc(d.address)}</td><td><span class="chip ${d.status==='reachable'?'good':'bad'}">${esc(d.status)}</span></td><td>${esc(d.httpStatus??'—')}</td></tr>`).join('');return `<div class="toolbar"><div><h2>On-demand backend probes</h2><p class="subtle">Sends GET to the configured health-check path with a 3-second timeout.</p></div>${actionBtn('Run probes now','probe','')}</div><div class="healthbanner">This is an on-demand HTTP connectivity check, NOT YARP's internal destination health state, and not transaction readiness validation. Use HTTPS with trusted certificates for CA services.</div><div class="tablewrap table-spaced"><table><thead><tr><th>Backend</th><th>Destination URL</th><th>Probe</th><th>HTTP</th></tr></thead><tbody>${p||'<tr><td colspan="4" class="empty">No probes run yet</td></tr>'}</tbody></table></div>`}
async function backups(){try{const [b,a]=await Promise.all([api('/admin/api/backups'),api('/admin/api/audit')]);const bs=b.map((name:string)=>`<div class="rowline"><span class="mono">${esc(name)}</span>${actionBtn('Restore','restore',name)}</div>`).join('')||'<div class="empty">No saved backups yet</div>';const audit=a.map((o:Obj)=>`<div class="rowline"><div><b>${esc(o.action)}</b><div class="subtle">${esc(o.timeUtc)}</div></div><span class="chip">${esc(o.backup||o.restored||'—')}</span></div>`).join('')||'<div class="empty">No audit entries</div>';$('content').innerHTML=`<div class="grid2"><div class="card"><h2 class="section-title">Configuration backups</h2>${bs}</div><div class="card"><h2 class="section-title">Recent local audit events</h2>${audit}</div></div>`}catch(e){show(String(e),true)}}

async function approvals(){
 try{
  const items=await api('/admin/api/change-requests');
  const rows=items.map((x:Obj)=>`<tr><td class="mono">${esc(x.id)}</td><td>${esc(x.requestedBy)}</td><td>${esc(x.changeReason)}</td><td>${esc(x.routeCount)} / ${esc(x.clusterCount)}</td><td><span class="chip ${x.status==='Approved'?'good':x.status==='Rejected'?'bad':''}">${esc(x.status)}</span></td><td>${esc(x.reviewedBy||'—')}</td><td>${actionBtn('Review full draft','approval-review',x.id)} ${x.status==='Pending'&&currentRole==='Administrator'?`${actionBtn('Approve','approval-approve',x.id)} ${actionBtn('Reject','approval-reject',x.id,'danger-btn mini')}`:''}</td></tr>`).join('');
  $('content').innerHTML=`<div class="toolbar"><div><h2>Two-person configuration approval</h2><p class="subtle">Submitting a change does not update live routing. A different Administrator must approve the exact saved draft; revision conflicts block outdated submissions.</p></div></div><div class="tablewrap"><table><thead><tr><th>Request</th><th>Requester</th><th>Reason</th><th>Routes / Clusters</th><th>Status</th><th>Reviewer</th><th>Actions</th></tr></thead><tbody>${rows||'<tr><td colspan="7" class="empty">No change requests submitted</td></tr>'}</tbody></table></div>`;
 }catch(e){show(String(e),true)}
}
async function metrics(){
 try{
  const m=await api('/admin/api/metrics');
  $('content').innerHTML=`<div class="stats"><div class="card"><h3>Requests in process lifetime</h3><div class="stat-number">${esc(m.totalRequests)}</div></div><div class="card"><h3>HTTP 2xx</h3><div class="stat-number green">${esc(m.success2xx)}</div></div><div class="card"><h3>HTTP 5xx</h3><div class="stat-number red">${esc(m.serverErrors5xx)}</div></div><div class="card"><h3>Mean duration</h3><div class="stat-number">${esc(m.meanDurationMs)} ms</div></div></div><div class="card card-spaced"><h2>Local YARP gateway process</h2><p class="subtle">${esc(m.scope)}</p><p class="subtle">Gateway ${esc(m.gateway)} · HTTP 4xx: ${esc(m.clientErrors4xx)} · Snapshot: ${esc(m.collectedUtc)}</p>${actionBtn('Refresh metrics','switch','metrics')}</div><div class="healthbanner">Not YARP destination-by-destination health, not real-time RPS, and not a second-gateway overview. Add OpenTelemetry with a central metrics store for those capabilities.</div>`;
 }catch(e){show(String(e),true)}
}
async function featureMatrix(){
 try{
  const result=await api('/admin/api/capabilities');
  const statuses:{[key:string]:string}={'native-config':'Native YARP','local-implemented':'Existing local code','source-implemented-unverified':'Added source / Windows verification required','integration-required':'Needs integration','external-module':'Separate product/module','network-design':'Network engineering','planned':'Not implemented'};
  const body=(result.capabilities||[]).map((x:Obj)=>`<tr><td><strong>${esc(x.name)}</strong><div class="subtle">${esc(x.id)}</div></td><td>${esc(x.category)}</td><td><span class="chip">${esc(statuses[String(x.status)]||x.status)}</span></td><td>${esc(x.engine)}</td><td>${esc(x.notes)}</td></tr>`).join('');
  $('content').innerHTML=`<div class="card"><h2>Traffic Engine & Platform Modules</h2><p class="subtle">Version 0.1. This is an authenticated, API-backed capability register, NOT a claim that every feature is deployed. Native policies are usable after approved configuration. Custom policies require Windows build and two-node traffic verification.</p><div class="healthbanner">IP-based hashing uses the incoming TCP peer IP. With firewall SNAT, different users may all appear identical. Do not use it before verifying the proxy chain. This software is HTTP L7; TCP/UDP, anycast, and authoritative DNS require separate infrastructure.</div><p><b>Policies:</b> ${esc((result.policies||[]).join(', '))}</p></div><div class="tablewrap"><table><thead><tr><th>Capability</th><th>Category</th><th>Implementation status</th><th>Engine</th><th>Constraint</th></tr></thead><tbody>${body}</tbody></table></div>`;
 }catch(e){show(String(e),true)}
}
function capabilities(){const categories=[
 ['Traffic routing','Hostnames, paths, methods, request headers, query matching, route ordering and per-route authorization/rate-limit policy'],
 ['Load balancing','Round Robin, Least Requests, Power of Two Choices, Random, First Alphabetical'],
 ['Resilience','Active and passive health, per-destination readiness, session affinity, transport failure recovery'],
 ['HTTP forwarding','HTTP/1.1, HTTP/2, version policy, activity timeouts, connection limits, response buffering'],
 ['Transforms','Path prefix/set/remove, X-Forwarded headers, request/response header transforms, original host handling'],
 ['Streaming protocols','WebSockets, gRPC, HTTP/2 and streaming validation (endpoint-specific acceptance testing required)'],
 ['Security','Admin RBAC/approvals, route authentication policies, rate limits, backend certificate verification, TLS termination'],
 ['Distributed operations','Gateway fleet rollout, agent mTLS, revision drift checks and best-effort rollback'],
 ];return `<div class="card"><h2>YARP feature coverage</h2><p class="subtle">Basic editors cover frequent settings. Advanced buttons expose additional route, cluster and destination JSON properties with approval and backend validation. This is not a promise that every extension or external security integration is installed.</p>${categories.map(c=>`<div class="rowline"><b>${esc(c[0])}</b><span class="subtle capability-desc">${esc(c[1])}</span></div>`).join('')}</div><div class="healthbanner">Regulated-industry services (e.g. public OCSP/CRL, eKYC, RA and partner mTLS) must be tested independently. Never turn off backend TLS validation to fix a certificate issue.</div>`}
// Topology onboarding 0.1: guided design, not deployment or service enrolment.
let topologyResponse:Obj|null=null;
let topologyDraft:Obj|null=null;
let topologyStep=0;
let topologyChecks:string[]=[];
let topologyWarnings:string[]=[];
const topologySteps=['Deployment mode','YARP gateways','Web & app servers','Ingress & isolation','Management & data','Review'];
const hostingEngines=[['http','Generic HTTP(S)'],['iis','Microsoft IIS'],['apache','Apache httpd'],['nginx','Nginx'],['caddy','Caddy'],['tomcat','Apache Tomcat'],['kestrel','ASP.NET Kestrel'],['node','Node.js'],['kubernetes-ingress','Kubernetes Ingress (external)'],['other','Other HTTP(S) server']];
function topologyModeName(mode:string){return ({standalone:'Single gateway','ha-pair':'Two active gateways',fleet:'Managed fleet'} as Obj)[mode]||'Unselected'}
function topologyDefaults():Obj{return {mode:'standalone',controlPlane:'local',dataStore:'local-file',accessPattern:'segmented',publicVip:'',upstreamHealthAware:false,requireIndependentApproval:true,offlineEnvironment:true,pgpoolEndpoint:'',postgresEndpoint:'',notes:'',gateways:[{id:'yarp-01',hostname:'',agentUrl:''}],workloads:[{id:'web-01',application:'web-site',url:'',zone:'public',hostingEngine:'http'}]}}
async function loadTopology(){const result=await api('/admin/api/onboarding');topologyResponse=result;topologyDraft=JSON.parse(JSON.stringify(result.plan||topologyDefaults()));if(result.status==='not-started')topologyDraft=topologyDefaults();topologyChecks=result.issues||[];topologyWarnings=result.warnings||[]}
const chosen=(a:string,b:string)=>a===b?'checked':'';
function topoInput(field:string,label:string,value:any,placeholder='',help=''){return `<label class="setup-field"><span>${esc(label)}</span><input data-setup-field="${esc(field)}" value="${esc(value||'')}" placeholder="${esc(placeholder)}" autocomplete="off"><small>${esc(help)}</small></label>`}
function topoToggle(field:string,title:string,description:string,value:boolean,locked=false){return `<label class="setup-toggle"><input type="checkbox" data-setup-field="${esc(field)}" ${value?'checked':''} ${locked?'disabled':''}><span><b>${esc(title)}</b><small>${esc(description)}</small></span></label>`}
function topologyStepHtml(){const p=topologyDraft||topologyDefaults();const mode=p.mode||'standalone';
 if(topologyStep===0)return `<h2>Select deployment architecture</h2><p class="subtle">Choose how many YARP instances serve application traffic. This choice changes subsequent setup fields and eligible fleet operations.</p><div class="setup-cards">${[
 {id:'standalone',title:'Single YARP',number:'01',details:'One gateway serving one or more backend API servers. Backend failover works, but the gateway remains a single point of failure.'},
 {id:'ha-pair',title:'Active–Active pair',number:'02',details:'Two independent gateways both serving traffic, behind a health-aware firewall VIP/load balancer. Either gateway may fail.'},
 {id:'fleet',title:'Managed gateway fleet',number:'03+',details:'Three or more gateway instances across zones or environments, with a separately managed desired configuration.'}
 ].map(x=>`<label class="setup-choice ${mode===x.id?'selected':''}"><input type="radio" name="topologyMode" data-setup-field="mode" value="${x.id}" ${chosen(mode,x.id)}><span class="setup-choice-number">${x.number}</span><b>${x.title}</b><small>${x.details}</small></label>`).join('')}</div><div class="healthbanner"><b>YARP is not a master/slave proxy cluster.</b> All YARP gateways can serve requests at the same time. Controller leader/standby is a separate management-plane design, not YARP's built-in traffic behavior.</div>`;
 if(topologyStep===1)return `<h2>Register gateway topology</h2><p class="subtle">Record the gateway hosts. Agent origins are plans only until independently enrolled with mTLS certificates.</p><div class="setup-array">${(p.gateways||[]).map((g:Obj,i:number)=>`<div class="setup-entry"><div class="setup-entry-title"><b>YARP gateway ${i+1}</b>${(p.gateways||[]).length>1?`<button type="button" class="danger-btn mini" data-action="setup-gateway-remove" data-id="${i}">Remove</button>`:''}</div><div class="setup-grid">${topoArrayInput('gateways',i,'id','Gateway ID',g.id,'yarp-01')}${topoArrayInput('gateways',i,'hostname','Windows hostname / IP',g.hostname,'YARP-ND-01')}${mode!=='standalone'?topoArrayInput('gateways',i,'agentUrl','HTTPS agent origin (planned)',g.agentUrl,'https://yarp-01.internal:8443/'):'<p class="subtle">Local gateway does not require a remote agent.</p>'}</div></div>`).join('')}</div><button class="ghost" type="button" data-action="setup-gateway-add">+ Add gateway</button><div class="healthbanner">Physical gateway identity is not verified by typing a hostname. Remote onboarding later requires certificate enrollment, ACLs and an agent handshake.</div>`;
 if(topologyStep===2)return `<h2>Application server inventory</h2><p class="subtle">Add one HTTP(S) website, or multiple origins for load balancing. IIS, Apache, Nginx, Tomcat, Kestrel, Node.js and external ingress can be destinations. This inventory does not create live proxy routes.</p><div class="setup-array">${(p.workloads||[]).map((w:Obj,i:number)=>`<div class="setup-entry"><div class="setup-entry-title"><b>Destination ${i+1}</b><button class="danger-btn mini" type="button" data-action="setup-workload-remove" data-id="${i}">Remove</button></div><div class="setup-grid">${topoArrayInput('workloads',i,'id','Destination ID',w.id,'api-01')}${topoArrayInput('workloads',i,'application','Application / cluster name',w.application,'example-api')}${topoArrayInput('workloads',i,'url','Website / API origin URL',w.url,'http://127.0.0.1/')}<label class="setup-field"><span>Hosting engine</span><select data-setup-array="workloads" data-setup-index="${i}" data-setup-property="hostingEngine">${hostingEngines.map(([k,label])=>`<option value="${k}" ${(w.hostingEngine||'http')===k?'selected':''}>${esc(label)}</option>`).join('')}</select><small>Classification only; GatewayCore does not deploy or manage the hosting engine.</small></label>
<label class="setup-field"><span>Service exposure</span><select data-setup-array="workloads" data-setup-index="${i}" data-setup-property="zone">${[['public','Public website / API'],['restricted','RA / internal tools'],['trust','OCSP / CRL']].map(([k,v])=>`<option value="${k}" ${w.zone===k?'selected':''}>${v}</option>`).join('')}</select></label></div></div>`).join('')}</div><button class="ghost" type="button" data-action="setup-workload-add">+ Add backend destination</button><div class="healthbanner">Application binaries and sessions must be safe for Active–Active operation. PostgreSQL replication/Pgpool does not synchronize ASP.NET in-memory sessions or local files.</div>`;
 if(topologyStep===3)return `<h2>Ingress and network isolation</h2><p class="subtle">Separate public and restricted application access. A public hostname alone is not an access-control boundary.</p><div class="setup-grid">${topoInput('publicVip','Firewall virtual service / VIP (design)',p.publicVip,'api.example.com or firewall VIP','Required for a gateway pair or fleet; this is not a DNS or firewall configuration action.')}
<label class="setup-field"><span>Public and internal access pattern</span><select data-setup-field="accessPattern"><option value="segmented" ${p.accessPattern==='segmented'?'selected':''}>Segregated public and internal ingress</option><option value="shared-restricted" ${p.accessPattern==='shared-restricted'?'selected':''}>Shared gateway hardware, separate protected listeners/ACLs</option></select><small>RA, CA management and internal tools must never become public simply because YARP has a matching route.</small></label></div>
${topoToggle('upstreamHealthAware','Health-aware upstream distribution','Firewall/load balancer will distribute traffic between healthy YARP gateways. This must be tested later.',!!p.upstreamHealthAware)}<div class="healthbanner">For two active YARP gateways, simple DNAT to only YARP-01 is insufficient. A health-aware VIP or equivalent upstream distribution is necessary.</div>`;
 if(topologyStep===4)return `<h2>Management plane and persistence</h2><p class="subtle">Choose how management will be designed. This release saves topology metadata locally; PostgreSQL selection does not start a DB connection.</p><div class="setup-grid"><label class="setup-field"><span>Control-plane design</span><select data-setup-field="controlPlane">${[['local','Local (one gateway only)'],['single-controller','Separate central controller'],['ha-controller','Controller leader / standby (future HA)']].map(([v,t])=>`<option value="${v}" ${p.controlPlane===v?'selected':''}>${t}</option>`).join('')}</select><small>Controller roles apply to management only; all data-plane YARP nodes remain active.</small></label>
<label class="setup-field"><span>Management data store</span><select data-setup-field="dataStore"><option value="local-file" ${p.dataStore==='local-file'?'selected':''}>Local protected files (single/test)</option><option value="postgresql" ${p.dataStore==='postgresql'?'selected':''}>PostgreSQL (planned for central HA)</option></select><small>Do not reuse existing CA production databases without dedicated schema/roles and change approval.</small></label>
${topoInput('pgpoolEndpoint','Existing data tier (optional) endpoint (inventory only)',p.pgpoolEndpoint,'pgpool.internal:9999')}${p.dataStore==='postgresql'?topoInput('postgresEndpoint','Proposed control-plane PostgreSQL endpoint',p.postgresEndpoint,'control-db.internal:5432'):''}</div>
${topoToggle('offlineEnvironment','Air-gapped / offline servers','Installers and package dependencies will be transferred through an approved offline process.',!!p.offlineEnvironment)}
${topoToggle('requireIndependentApproval','Mandatory independent change approval','CA-sensitive changes require a second authorized administrator.',true,true)}
${topoInput('notes','Change or architecture notes',p.notes,'Document existing HA, firewall and CA boundaries')}`;
 return `<h2>Review and confirm architecture design</h2><p class="subtle">Confirmation stores reviewed topology metadata. It does not make your gateway fleet active or modify production traffic.</p><div class="setup-review-grid"><div class="card"><h3>Traffic topology</h3><strong>${esc(topologyModeName(p.mode))}</strong><p class="subtle">${esc((p.gateways||[]).length)} YARP gateway(s), ${(p.workloads||[]).length} backend destination(s)</p></div><div class="card"><h3>Controller / persistence</h3><strong>${esc(p.controlPlane)} · ${esc(p.dataStore)}</strong><p class="subtle">Local file-backed design record in this release</p></div></div><div class="setup-entry"><h3>Gateway inventory</h3>${(p.gateways||[]).map((g:Obj)=>`<div class="rowline"><span>${esc(g.id)}</span><span class="mono">${esc(g.hostname||'Hostname missing')}</span></div>`).join('')}</div><div class="setup-entry"><h3>Application destinations</h3>${(p.workloads||[]).map((w:Obj)=>`<div class="rowline"><span>${esc(w.application||'Unspecified')} / ${esc(w.id)} · ${esc(hostingEngines.find(([k])=>k===(w.hostingEngine||'http'))?.[1]||'Generic HTTP(S)')}</span><span class="mono">${esc(w.url||'URL missing')}</span></div>`).join('')}</div><div class="setup-entry"><h3>Validation</h3>${topologyChecks.length?topologyChecks.map(x=>`<div class="setup-check-error">${esc(x)}</div>`).join(''):'<p class="green">No schema/design-blocking errors reported. Operational readiness has NOT been verified.</p>'}</div><div class="setup-entry"><h3>Operational limitations</h3>${topologyWarnings.map(x=>`<p class="subtle">• ${esc(x)}</p>`).join('')}</div>`;
}
function topoArrayInput(kind:string,index:number,property:string,label:string,value:any,placeholder=''){return `<label class="setup-field"><span>${esc(label)}</span><input data-setup-array="${esc(kind)}" data-setup-index="${index}" data-setup-property="${esc(property)}" value="${esc(value||'')}" placeholder="${esc(placeholder)}" autocomplete="off"></label>`}
function topologyPage(){const status=topologyResponse?.status||'not-started';return `<div class="setup-heading"><div><h2>Gateway onboarding</h2><p class="subtle">For laptop testing, use the quick standalone template; advanced HA planning is optional. Status: <span class="chip">${esc(status)}</span></p></div><span class="chip">DESIGN ONLY</span></div><div class="healthbanner"><b>Quick start:</b> IIS, Apache, Nginx, or another HTTP(S) website can serve as a backend. <button class="ghost mini" type="button" data-action="setup-quick-lab">Fill single-server test draft</button> This fills design fields only and never changes live routes.</div><div class="setup-steps">${topologySteps.map((t,i)=>`<button class="setup-step ${i===topologyStep?'current':''}" data-action="setup-step" data-id="${i}" type="button"><span>${i+1}</span><b>${esc(t)}</b></button>`).join('')}</div><div class="setup-panel">${topologyStepHtml()}</div><div class="setup-actions"><button class="ghost" type="button" data-action="setup-prev">${topologyStep===0?'← Exit to Setup Center':'← Previous step'}</button><span class="subtle">Step ${topologyStep+1} of ${topologySteps.length}</span><div><button class="ghost" type="button" data-action="setup-save" ${currentRole!=='Administrator'?'disabled':''}>Save draft</button> ${topologyStep<5?'<button class="primary" type="button" data-action="setup-next">Continue</button>':`<button class="primary" type="button" data-action="setup-confirm" ${currentRole!=='Administrator'?'disabled':''}>Confirm design</button>`}</div></div><div class="healthbanner">No firewall, service, CA key, Pgpool, PostgreSQL, IIS or live YARP configuration change is performed by this wizard. Gateway connectivity and deployment are separate approved workflows.</div>`}
async function topologyValidate(){if(!topologyDraft||currentRole!=='Administrator')return;try{const r=await api('/admin/api/onboarding/validate','POST',{plan:topologyDraft});topologyChecks=r.issues||[];topologyWarnings=r.warnings||[];}catch(e){show('Validation unavailable: '+String(e),true)}}
async function topologySave(confirmDesign:boolean){if(!topologyDraft)return;try{if(confirmDesign){await topologyValidate();if(topologyChecks.length){render();show('Fix the listed topology validation errors before confirming.',true);return}}const saved=await api('/admin/api/onboarding','POST',{expectedRevision:topologyResponse?.revision||'EMPTY',plan:topologyDraft,confirmDesign});topologyResponse=saved;topologyChecks=saved.issues||[];topologyWarnings=saved.warnings||[];show(confirmDesign?'Architecture design confirmed. Operational deployment is still pending.':'Topology draft saved. No traffic changes.');if(confirmDesign){view='overview';updateTopologyNavigation()}render()}catch(e){show('Could not save topology: '+String(e),true)}}
function topologyModeChange(mode:string){if(!topologyDraft)return;topologyDraft.mode=mode;topologyDraft.controlPlane=mode==='standalone'?'local':'ha-controller';const need=mode==='standalone'?1:mode==='ha-pair'?2:3;const arr=topologyDraft.gateways||[];while(arr.length<need)arr.push({id:`yarp-0${arr.length+1}`,hostname:'',agentUrl:''});if(arr.length>need&&mode!=='fleet')arr.length=need;topologyDraft.gateways=arr}

// 0.1 Setup Center. Every status comes from an authenticated backend API; no mock health data.
type SetupStage = {id:string;title:string;status:string;evidence:string;action:string};
type SetupOverview = {version:string;channel:string;verifiedForProduction:boolean;mode:string;topologyConfirmed:boolean;routeCount:number;clusterCount:number;destinationCount:number;activeHealthClusterCount:number;fleetEntries:number;gateway:string;transport:string;freeze:{frozen:boolean;reason:string;updatedBy:string};stages:SetupStage[];note:string};
let setupState:SetupOverview|null=null;
const readyClass=(s:string)=>['configured','design-confirmed','https-session-unverified'].includes(s)?'good':s==='not-implemented'?'bad':'warn';
const setupActionText=(s:SetupStage)=>s.action==='onboarding'?'Set topology':s.action==='mail'?'Configure mail':s.action==='directory'?'Configure AD':s.action==='health'?'Inspect health':s.action==='fleet'?'Gateway fleet':s.action==='users'?'Accounts':s.action==='approvals'?'Approvals':s.action==='backups'?'Audit log':s.action==='routes'?'Configure routes':'View';
async function setupPage(){
 try {
   setupState=await api('/admin/api/setup/overview') as SetupOverview;
   const x=setupState;
   const configured=x.stages.filter(s=>['configured','design-confirmed'].includes(s.status)).length;
   $('content').innerHTML=`<div class="setup-hero card"><div><div class="setup-eyebrow">FIRST-RUN BOOTSTRAP & OPERATIONS</div><h2>Set up your YARP gateway</h2><p>Choose deployment architecture, verify services and identity, then approve changes before routing traffic. All checks show actual server-side configuration state.</p><span class="chip">Version ${esc(x.version)} · ${esc(x.channel)}</span><span class="chip">${esc(x.gateway)}</span></div><div class="setup-score"><strong>${configured}/${x.stages.length}</strong><span>Configured setup controls, not a production-readiness score</span></div></div>
   <div class="setup-alert">${x.freeze.frozen?`<b>Routing change freeze is ON.</b> ${esc(x.freeze.reason)}`:`<b>Routing changes are allowed with approval.</b> A local emergency freeze can stop route/change operations.`} ${currentRole==='Administrator'?`<button class="ghost mini" data-action="setup-toggle-freeze" data-id="${x.freeze.frozen?'off':'on'}">${x.freeze.frozen?'Unfreeze':'Freeze routing changes'}</button>`:''}</div>
   <div class="setup-summary"><div class="card"><b>${x.routeCount}</b><span>Routes</span></div><div class="card"><b>${x.clusterCount}</b><span>Clusters</span></div><div class="card"><b>${x.destinationCount}</b><span>Enabled backend entries</span></div><div class="card"><b>${x.fleetEntries}</b><span>Gateway agent records</span></div></div>
   <div class="toolbar"><div><h2>Bootstrap checklist</h2><p class="subtle">“Configured” is not the same as operationally tested or production certified.</p></div><div><button class="primary" data-action="setup-add-application">+ Advanced public HTTPS application</button> <button class="ghost" data-action="setup-local-web">+ Local IIS / Apache / Nginx test</button> <button class="ghost" data-action="setup-refresh">Refresh evidence</button></div></div>
   <div class="setup-stage-grid">${x.stages.map((s:SetupStage,i:number)=>`<div class="card setup-stage"><div class="setup-stage-head"><span class="setup-number">${String(i+1).padStart(2,'0')}</span><span class="chip ${readyClass(s.status)}">${esc(s.status.replace(/-/g,' '))}</span></div><h3>${esc(s.title)}</h3><p>${esc(s.evidence)}</p><button class="ghost mini" data-action="setup-open" data-id="${esc(s.action)}">${esc(setupActionText(s))} →</button></div>`).join('')}</div>
   <div class="grid2"><div class="card"><h3>Live YARP health states</h3><p class="subtle">Queries YARP's internal active/passive destination states. Unknown means the policy has not classified the backend.</p><button class="primary" data-action="setup-live-health">Inspect live destinations</button><div id="setup-live-output" class="setup-live-output">No runtime query made yet.</div></div><div class="card"><h3>Production safety gates</h3><p class="subtle">The following are not magically provisioned by this setup page:</p><ul class="setup-bullets"><li>Remote gateway agents, mTLS and network admission</li><li>AD/SMTP delivery and phishing-resistant SSO</li><li>Independent immutable audit retention</li><li>OCSP/CRL and CA issuance failover acceptance</li></ul><p class="subtle">The console deliberately refuses to call this instance production certified.</p></div></div>`;
 } catch(e) { $('content').innerHTML=`<div class="card"><h2>Setup unavailable</h2><p>${esc(String(e))}</p></div>`; }
}
async function setupLiveHealth(){
 try {const r=await api('/admin/api/runtime/destinations');const target=$('setup-live-output');if(!target)return;
  const clusters=(r.clusters||[]) as Obj[];
  target.innerHTML=clusters.length?clusters.map(c=>`<div class="setup-health-block"><b>${esc(c.clusterId)}</b>${(c.destinations||[]).map((d:Obj)=>`<div class="rowline"><span class="mono">${esc(d.destinationId)}</span><span>Active: <b>${esc(d.activeHealth)}</b> · Passive: <b>${esc(d.passiveHealth)}</b> · In-flight: ${esc(d.concurrentRequests)}</span></div>`).join('')}</div>`).join(''):'No live destinations are currently loaded into YARP.';
 } catch(e){show('Could not read YARP runtime health: '+String(e),true)}
}
async function setupFreeze(frozen:boolean){
 if(currentRole!=='Administrator')return show('Administrator role required',true);
 const reason=prompt(frozen?'Reason for freezing routing changes (12+ characters):':'Reason for unfreezing routing changes (12+ characters):');
 if(reason===null)return;
 try {await api('/admin/api/setup/freeze','POST',{frozen,reason});show(frozen?'Routing changes frozen locally.':'Local routing change freeze lifted.');await setupPage()}
 catch(e){show('Freeze operation denied: '+String(e),true)}
}
function updateTopologyNavigation(){const finished=topologyResponse?.status==='design-confirmed';const prereqViews=['organization','setup','onboarding','users','mail','directory'];document.querySelectorAll<HTMLButtonElement>('.nav').forEach(b=>{const dest=b.dataset.view||'';const adminOnly=['users','mail','directory'].includes(dest);b.hidden=(!finished&&!prereqViews.includes(dest))||(dest==='fleet'&&finished&&topologyResponse?.plan?.mode==='standalone')||(adminOnly&&currentRole!=='Administrator')});$('save').hidden=!finished||currentRole==='Viewer'||view==='onboarding'||view==='setup'}

function render(){
 if(view!==lastRenderedView){if(!restoringNavigation)viewHistory.push(lastRenderedView);lastRenderedView=view}
 restoringNavigation=false;
 $('page-back').hidden=view==='setup'&&viewHistory.length===0;
 const names:Obj={organization:'Organization profile',setup:'Setup Center · 0.1',onboarding:'Architecture & setup',overview:'Overview',routes:'Routing rules',clusters:'Backend clusters',backends:'Backend management',health:'Health and diagnostics',backups:'Backups and audit',inventory:'Infrastructure inventory',users:'Administrators and roles',mail:'Mail & OTP',directory:'Active Directory (LDAPS)',approvals:'Change approvals',metrics:'Gateway metrics',fleet:'Gateway fleet',capabilities:'YARP capabilities',featurematrix:'Traffic Engine & platform modules'};$('page-title').textContent=names[view];$('page-subtitle').textContent=dirty?'Unsaved configuration changes — submit for approval':'Control and inspect your gateway';$('gateway-pill').textContent='● Gateway online';$('save').textContent=dirty?'● Submit change request':'Submit change request';document.querySelectorAll<HTMLButtonElement>('.nav').forEach(n=>n.classList.toggle('active',n.dataset.view===view));const pages:Obj={overview,routes,clusters,backends,health,capabilities};updateTopologyNavigation();if(view==='organization')void organizationPage();else if(view==='featurematrix')void featureMatrix();else if(view==='setup')void setupPage();else if(view==='onboarding')$('content').innerHTML=topologyPage();else if(view==='approvals')void approvals();else if(view==='metrics')void metrics();else if(view==='backups')void backups();else if(view==='inventory')void inventory();else if(view==='fleet')void fleet();else if(view==='users')void users();else if(view==='mail')void mailPage();else if(view==='directory')void directoryPage();else $('content').innerHTML=pages[view]();}
type Field={name:string;label:string;value:string;kind?:string;options?:string[];optional?:boolean;minLength?:number};
function modal(title:string,help:string,fields:Field[],cb:(vals:Obj)=>void,confirmLabel='Apply to draft'){$('confirm').textContent=confirmLabel;$('modal-title').textContent=title;$('modal-help').textContent=help;$('modal-fields').innerHTML=fields.map(f=>`<div class="field"><label for="f-${esc(f.name)}">${esc(f.label)}</label>${f.options?`<select id="f-${esc(f.name)}">${f.options.map(o=>`<option value="${esc(o)}" ${o===f.value?'selected':''}>${esc(o)}</option>`).join('')}</select>`:`<input id="f-${esc(f.name)}" value="${esc(f.value)}" type="${f.kind||'text'}" autocomplete="off" ${f.optional?'':'required'} ${f.minLength?`minlength="${f.minLength}"`:''}>`}</div>`).join('');const dlg=$('modal') as HTMLDialogElement;const form=$('editor') as HTMLFormElement;form.onsubmit=e=>{if((e as SubmitEvent).submitter?.getAttribute('value')==='cancel')return; e.preventDefault();const vals:Obj={};for(const f of fields)vals[f.name]=($('f-'+f.name) as HTMLInputElement).value;try{cb(vals);dlg.close()}catch(err){show(String(err),true)}};dlg.showModal()}
function validId(s:string){return /^[A-Za-z0-9_-]{1,80}$/.test(s)}
function advancedJson(kind:'route'|'cluster'|'destination',id:string){
 const obj=kind==='route'?data.routes[id]:kind==='cluster'?data.clusters[id]:(data.clusters[id.split('::')[0]]?.Destinations?.[id.split('::')[1]]??data.disabled[id]);
 if(!obj)return show('Configuration item not found',true);
 const dlg=$('modal') as HTMLDialogElement;
 $('modal-title').textContent='Advanced YARP '+kind+' configuration';
 $('modal-help').textContent='Edit supported YARP properties as JSON. Existing values are preserved. Changes remain a draft and require independent approval. Avoid disabling TLS validation or adding secrets.';
 $('modal-fields').innerHTML='<label for="advanced-json">YARP configuration JSON</label><textarea id="advanced-json" spellcheck="false" class="json-editor" aria-label="YARP configuration JSON"></textarea>';
 ($('advanced-json') as HTMLTextAreaElement).value=JSON.stringify(obj,null,2);
 const form=$('editor') as HTMLFormElement;
 form.onsubmit=e=>{
  if((e as SubmitEvent).submitter?.getAttribute('value')==='cancel')return;
  e.preventDefault();
  try{
   const parsed=JSON.parse(($('advanced-json') as HTMLTextAreaElement).value);
   if(!parsed||typeof parsed!=='object'||Array.isArray(parsed))throw Error('Expected JSON object');
   if(JSON.stringify(parsed).length>15000)throw Error('Configuration exceeds 15 KB limit');
   if(kind==='route'){
     if(!data.clusters[parsed.ClusterId]||!String(parsed.Match?.Path||'').startsWith('/'))throw Error('Route must reference an existing cluster and have a /path');
     data.routes[id]=parsed;
   }else if(kind==='cluster'){
     if(parsed.HttpClient?.DangerousAcceptAnyServerCertificate===true)throw Error('Disabling backend TLS verification is prohibited');
     if(!parsed.Destinations||typeof parsed.Destinations!=='object')throw Error('Cluster requires Destinations');
     data.clusters[id]=parsed;
   }else{
     if(!/^https?:\/\/[^\s]+\/$/.test(String(parsed.Address||'')))throw Error('Backend Address must be an HTTP(S) URL ending in /');
     const [cid,did]=id.split('::');
     if(data.disabled[id])data.disabled[id]=parsed;else data.clusters[cid].Destinations[did]=parsed;
   }
   edit();dlg.close();
  }catch(err){show(String(err),true)}
 };
 dlg.showModal();
}

// Guided public application onboarding; produces an approval-required local configuration DRAFT.
// Restricted RA/SSCA and OCSP/CRL routes deliberately require specialist change review.
function addApplicationWizard(){
 if(currentRole==='Viewer')return show('Viewer accounts cannot submit configuration changes',true);
 if(topologyResponse?.status!=='design-confirmed')return show('Confirm the architecture design first',true);
 modal('Advanced public HTTPS application','Creates a route, cluster and TWO independently reachable HTTPS backend destinations in a draft. Requires an independent administrator approval. Internal/RA/OCSP services need a separately validated network zone.',[
  {name:'id',label:'Application ID (letters, digits, - or _)',value:'example-api'},
  {name:'service',label:'Application category',value:'Public website',options:['Public website','REST API','Partner API','eKYC']},
  {name:'hosting',label:'Backend hosting platform',value:'Generic HTTP(S)',options:['Generic HTTP(S)','Microsoft IIS','Apache httpd','Nginx','Caddy','Apache Tomcat','ASP.NET Kestrel','Node.js','Kubernetes Ingress (external)','Other HTTP(S) server']},
  {name:'hostname',label:'Public hostname (FQDN)',value:'api.example.com'},
  {name:'path',label:'Route path',value:'/{**catch-all}'},
  {name:'backend1',label:'API Server 1 HTTPS URL',value:'https://api01.internal.example.com:5001/'},
  {name:'backend2',label:'API Server 2 HTTPS URL',value:'https://api02.internal.example.com:5001/'},
  {name:'ready',label:'Backend readiness path',value:'/health/ready'}
 ],v=>{
  const id=String(v.id).trim();const host=String(v.hostname).trim().toLowerCase();
  if(!validId(id)||id.length>64)throw Error('Invalid application ID');
  if(!/^[a-z0-9][a-z0-9.-]+\.[a-z]{2,}$/.test(host)||host.includes('..'))throw Error('A valid FQDN is required');
  if(!v.path.startsWith('/')||v.path.startsWith('/admin')||v.path.startsWith('/dashboard')||v.path.startsWith('/gateway'))throw Error('Invalid or reserved route path');
  if(!v.ready.startsWith('/')||v.ready.includes('\\'))throw Error('Readiness path must start with /');
  function approvedBackend(raw:string){const u=new URL(raw);if(u.protocol!=='https:'||u.username||u.password||u.search||u.hash||u.pathname!=='/')throw Error('Backend URLs must use trusted HTTPS and end in /');return u.href}
  const b1=approvedBackend(v.backend1),b2=approvedBackend(v.backend2);
  if(b1===b2)throw Error('Two distinct backend HTTPS destinations are needed for Active–Active');
  const clusterId=id+'-cluster',routeId=id+'-route';if(data.clusters[clusterId]||data.routes[routeId])throw Error('Application already exists');
  data.clusters[clusterId]={LoadBalancingPolicy:'RoundRobin',Destinations:{'api-01':{Address:b1},'api-02':{Address:b2}},
   HealthCheck:{AvailableDestinationsPolicy:'HealthyAndUnknown',Active:{Enabled:false,Interval:'00:00:15',Timeout:'00:00:05',Policy:'ConsecutiveFailures',Path:v.ready}},
   Metadata:{'YARP.ApplicationCategory':v.service,'GatewayCore.HostingEngine':v.hosting}};
  data.routes[routeId]={ClusterId:clusterId,Match:{Hosts:[host],Path:v.path}};
  edit();show('Application added to unsaved draft. Validate both readiness endpoints before enabling active health, then submit for independent approval.');
 })
}

function addLocalWebWizard(){
 if(currentRole==='Viewer')return show('Viewer accounts cannot submit routing changes',true);
 if(topologyResponse?.status!=='design-confirmed')return show('Confirm the standalone architecture draft first. This will not deploy or modify IIS.',true);
 if(topologyResponse?.plan?.mode!=='standalone')return show('The local HTTP test wizard is available only for a standalone gateway.',true);
 modal('Local web-server test (IIS, Apache, Nginx, or other HTTP origin)',
 'Creates an approval-required /lab/ draft. Only loopback HTTP targets are allowed. This does not modify IIS or your web server.',[
 {name:'id',label:'Test route ID',value:'local-web-test'},
 {name:'hosting',label:'Hosting software',value:'Microsoft IIS',options:['Microsoft IIS','Apache httpd','Nginx','Caddy','Apache Tomcat','ASP.NET Kestrel','Node.js','Other HTTP(S)']},
 {name:'origin',label:'Local test website URL',value:'http://127.0.0.1/'}
 ],v=>{
  const id=String(v.id).trim();if(!validId(id))throw Error('Invalid route ID');
  let u:URL;try{u=new URL(String(v.origin))}catch{throw Error('Provide a valid local HTTP URL')}
  if(u.protocol!=='http:'||!['127.0.0.1','localhost','[::1]'].includes(u.hostname)||u.username||u.password||u.search||u.hash||u.pathname!=='/')
   throw Error('Local test requires loopback HTTP root URL only. Remote web servers require HTTPS and independent approval.');
  const clusterId=id+'-cluster',routeId=id+'-route';
  if(data.clusters[clusterId]||data.routes[routeId])throw Error('Test route already exists');
  data.clusters[clusterId]={LoadBalancingPolicy:'RoundRobin',Destinations:{'web-01':{Address:u.href}},Metadata:{'GatewayCore.HostingEngine':String(v.hosting)}};
  data.routes[routeId]={ClusterId:clusterId,Match:{Path:'/lab/{**catch-all}'},Transforms:[{PathRemovePrefix:'/lab'}]};
  edit();show('Local website added to draft. Submit for independent approval; no live traffic changed.');
 });
}

function updateRoute(id=''){const old=data.routes[id]||{Match:{Path:'/api/{**catch-all}',Hosts:[]},ClusterId:keys(data.clusters)[0]||''};modal(id?'Edit route':'Add route','Use comma-separated hostnames or leave blank for any hostname. Avoid exposing internal routes publicly.',[{name:'id',label:'Route ID',value:id||''},{name:'cluster',label:'Target cluster',value:old.ClusterId||'',options:keys(data.clusters)},{name:'path',label:'Route path',value:old.Match?.Path||'/{**catch-all}'},{name:'hosts',label:'Hostnames (comma-separated, optional)',value:(old.Match?.Hosts||[]).join(', '),optional:true}],v=>{if(!validId(v.id)||!data.clusters[v.cluster]||!v.path.startsWith('/'))throw Error('Check route ID, cluster, and /path');if(v.id!==id&&data.routes[v.id])throw Error('Route ID already exists');const x={...old,ClusterId:v.cluster,Match:{...old.Match,Path:v.path,Hosts:v.hosts.split(',').map((s:string)=>s.trim()).filter(Boolean)}};if(x.Match.Hosts.length===0)delete (x.Match as Obj).Hosts;if(id&&id!==v.id)delete data.routes[id];data.routes[v.id]=x;edit()})}
function updateCluster(id=''){const old=data.clusters[id]||{Destinations:{},LoadBalancingPolicy:'RoundRobin',HealthCheck:{Active:{Enabled:false,Interval:'00:00:15',Timeout:'00:00:05',Path:'/health/ready',Policy:'ConsecutiveFailures'}}};modal(id?'Edit cluster':'Add cluster','Health checks need a real backend readiness endpoint. Keep disabled until verified.',[{name:'id',label:'Cluster ID',value:id},{name:'policy',label:'Load balancing',value:old.LoadBalancingPolicy||'RoundRobin',options:['RoundRobin','PowerOfTwoChoices','LeastRequests','Random','FirstAlphabetical','WeightedRandom','SourceIpHash']},{name:'health',label:'Active health checks',value:String(!!old.HealthCheck?.Active?.Enabled),options:['false','true']},{name:'path',label:'Health path',value:old.HealthCheck?.Active?.Path||'/health/ready'}],v=>{if(!validId(v.id)||!v.path.startsWith('/'))throw Error('Invalid cluster ID or path');if(v.id!==id&&data.clusters[v.id])throw Error('Cluster exists');const c={...old,LoadBalancingPolicy:v.policy,HealthCheck:{...old.HealthCheck,Active:{...(old.HealthCheck?.Active||{}),Enabled:v.health==='true',Path:v.path}}};if(id&&id!==v.id){delete data.clusters[id];for(const rid of keys(data.routes)){if(data.routes[rid].ClusterId===id)data.routes[rid].ClusterId=v.id}}data.clusters[v.id]=c;edit()})}
function updateDest(id=''){const [cid,did]=id?id.split('::'):['',''];const old=cid?(data.clusters[cid]?.Destinations?.[did]??data.disabled[id]):null;modal(did?'Edit backend':'Add backend','Provide a reachable absolute HTTP(S) URL ending in /. HTTPS certificate validation remains enabled.',[{name:'cluster',label:'Cluster',value:cid||keys(data.clusters)[0]||'',options:keys(data.clusters)},{name:'id',label:'Destination ID',value:did},{name:'address',label:'Backend URL',value:old?.Address||'https://api01.internal.example.com:5001/'},{name:'weight',label:'Traffic weight (1–100)',value:String(old?.Metadata?.Weight??'1')}],v=>{if(!validId(v.id)||!data.clusters[v.cluster]||!/^https?:\/\/[^\s]+\/$/.test(v.address))throw Error('Invalid ID, cluster or URL; URL must end in /');if(!/^(?:[1-9]|[1-9][0-9]|100)$/.test(v.weight))throw Error('Weight must be an integer from 1 to 100');const newKey=v.cluster+'::'+v.id;const isDisabled=!!data.disabled[id];if(id){delete data.clusters[cid].Destinations[did];delete data.disabled[id]}const configured={...old,Address:v.address,Metadata:{...(old?.Metadata||{}),Weight:String(v.weight)}};if(isDisabled)data.disabled[newKey]=configured;else data.clusters[v.cluster].Destinations[v.id]=configured;edit()})}
function act(type:string,id:string){
 if(type==='org-edit'){editOrganization();return}
 if(type==='setup-add-application'){addApplicationWizard();return}
  if(type==='setup-local-web'){addLocalWebWizard();return}
 if(type==='setup-refresh'){void setupPage();return}
 if(type==='setup-live-health'){void setupLiveHealth();return}
 if(type==='setup-toggle-freeze'){void setupFreeze(id==='on');return}
 if(type==='setup-open'){view=id;render();return}
 if(type==='setup-quick-lab'){topologyDraft={...topologyDefaults(),gateways:[{id:'gateway-01',hostname:'127.0.0.1',agentUrl:''}],workloads:[{id:'web-01',application:'local-test',url:'http://127.0.0.1/',zone:'public',hostingEngine:'iis'}],notes:'Local lab-only IIS/Apache/Nginx test; no public exposure or deployment'};topologyStep=5;void topologyValidate().then(()=>render());return}
  if(type==='setup-next'){topologyStep=Math.min(5,topologyStep+1);if(topologyStep===5)void topologyValidate().then(()=>render());else render();return}
 if(type==='setup-prev'){if(topologyStep===0){view='setup';render()}else{topologyStep--;render()}return}
 if(type==='setup-step'){topologyStep=Math.max(0,Math.min(5,Number(id)||0));if(topologyStep===5)void topologyValidate().then(()=>render());else render();return}
 if(type==='setup-gateway-add'){if((topologyDraft?.gateways||[]).length>=20)return show('Maximum 20 gateways',true);topologyDraft?.gateways.push({id:`yarp-0${topologyDraft.gateways.length+1}`,hostname:'',agentUrl:''});render();return}
 if(type==='setup-gateway-remove'){topologyDraft?.gateways.splice(Number(id),1);render();return}
 if(type==='setup-workload-add'){if((topologyDraft?.workloads||[]).length>=80)return show('Maximum 80 application destinations',true);topologyDraft?.workloads.push({id:'',application:'web-site',url:'',zone:'public',hostingEngine:'http'});render();return}
 if(type==='setup-workload-remove'){topologyDraft?.workloads.splice(Number(id),1);render();return}
 if(type==='setup-save'){void topologySave(false);return}
 if(type==='setup-confirm'){void topologySave(true);return}
 if(type==='approval-review'){
   api('/admin/api/change-requests/'+encodeURIComponent(id)).then(r=>{
     const summary=JSON.stringify(r,null,2);
     const html=`<div class="card"><div class="flex"><h2 class="section-title">Change request details</h2>${actionBtn('Back to approvals','switch','approvals')}</div><pre class="json-review">${esc(summary)}</pre></div>`;
     $('content').innerHTML=html;
   }).catch(e=>show(String(e),true));return;
 }
 if(type==='approval-approve'||type==='approval-reject'){
   const reason=prompt('Enter the independent review note (at least 10 characters):');
   if(reason===null)return;
   api('/admin/api/change-requests/'+encodeURIComponent(id)+'/decision','POST',{
      decision:type==='approval-approve'?'approve':'reject',reason
   }).then(async r=>{show('Request '+r.status);await approvals();await reload();view='approvals';render()}).catch(e=>show(String(e),true));return;
 }
if(type==='route-advanced'||type==='cluster-advanced'||type==='dest-advanced'){advancedJson(type==='route-advanced'?'route':type==='cluster-advanced'?'cluster':'destination',id);return}if(type==='switch'){view=id;render();return}if(type==='route-add'||type==='route-edit'){if(!keys(data.clusters).length)return show('Create a cluster before adding routes',true);updateRoute(type==='route-edit'?id:'');return}if(type==='route-delete'){if(confirm('Delete route '+id+' from draft?')){delete data.routes[id];edit()}return}if(type==='cluster-add'||type==='cluster-edit'){updateCluster(type==='cluster-edit'?id:'');return}if(type==='cluster-delete'){if(keys(data.routes).some(r=>data.routes[r].ClusterId===id))return show('Remove routes referencing this cluster first',true);if(confirm('Delete cluster '+id+'?')){delete data.clusters[id];for(const k of keys(data.disabled))if(k.startsWith(id+'::'))delete data.disabled[k];edit()}return}if(type==='dest-add'||type==='dest-edit'){if(!keys(data.clusters).length)return show('Create a cluster first',true);updateDest(type==='dest-edit'?id:'');return}if(type==='dest-toggle'){const [c,d]=id.split('::');if(data.disabled[id]){data.clusters[c].Destinations[d]=data.disabled[id];delete data.disabled[id]}else{data.disabled[id]=data.clusters[c].Destinations[d];delete data.clusters[c].Destinations[d]}edit();return}if(type==='dest-delete'){const [c,d]=id.split('::');if(confirm('Delete destination '+id+'?')){if(data.clusters[c])delete data.clusters[c].Destinations[d];delete data.disabled[id];edit()}return}if(type==='probe'){show('Running on-demand probes...');api('/admin/api/probe','POST',{}).then(r=>{probes=r.results;render();show('Probe completed. This is not the internal YARP health state.')}).catch(e=>show(String(e),true));return}if(type==='fleet-add'){addFleet();return}if(type==='fleet-remove'){if(!confirm('Remove gateway '+id+' from inventory?'))return;api('/admin/api/fleet/'+encodeURIComponent(id),'DELETE',{}).then(()=>void fleet()).catch(e=>show(String(e),true));return}if(type==='fleet-probe'){void fleetStatus();return}if(type==='fleet-rollout'){void performFleetRollout();return}if(type==='dest-metrics'){void destinationMetrics();return}if(type==='inventory-add'){addInventory();return}if(type==='inventory-delete'){if(!confirm('Remove inventory item '+id+'?'))return;api('/admin/api/inventory/'+encodeURIComponent(id),'DELETE',{}).then(()=>void inventory()).catch(e=>show(String(e),true));return}if(type==='user-add'){addUser();return}if(type==='mail-settings'){view='mail';render();return}if(type==='mail-test'){void api('/admin/api/mail/test','POST',{}).then(r=>{show('SMTP accepted test message for '+r.recipient);void mailPage()}).catch(e=>show('Mail test failed: '+String(e)+'. Save a relay configuration first; verify administrator email and STARTTLS.',true));return}if(type==='directory-test'){void api('/admin/api/directory/test','POST',{}).then(()=>show('LDAPS trust, bind and group lookup verified')).catch(e=>show(String(e),true));return}if(type==='user-disable'||type==='user-enable'){if(!confirm((type==='user-disable'?'Offboard ':'Re-enable ')+id+'?'))return;api('/admin/api/users/'+encodeURIComponent(id)+'/'+(type==='user-disable'?'disable':'enable'),'POST',{}).then(()=>void users()).catch(e=>show(String(e),true));return}if(type==='password-reset'){resetPassword(id);return}if(type==='restore'){if(!confirm('Restore '+id+'? This changes live config and saves a safety backup.'))return;api('/admin/api/restore/'+encodeURIComponent(id),'POST',{}).then(()=>{show('Backup restored');void reload()}).catch(e=>show(String(e),true))}}
$('content').addEventListener('click',e=>{const el=(e.target as HTMLElement).closest<HTMLButtonElement>('[data-action]');if(el)act(el.dataset.action||'',el.dataset.id||'')});
function topologyInputUpdate(el:HTMLInputElement|HTMLSelectElement){if(!topologyDraft)return;
 const field=el.dataset.setupField;const value=(el as HTMLInputElement).type==='checkbox'?(el as HTMLInputElement).checked:el.value;
 if(field){if(field==='mode'){topologyModeChange(String(value));render();return}topologyDraft[field]=value;if(field==='dataStore')render();return}
 const arr=el.dataset.setupArray;const index=Number(el.dataset.setupIndex);const prop=el.dataset.setupProperty;
 if(arr&&prop&&Number.isInteger(index)&&topologyDraft[arr]?.[index])topologyDraft[arr][index][prop]=value;
}
$('content').addEventListener('input',e=>{const el=e.target as HTMLInputElement;if(el.matches('[data-setup-field],[data-setup-array]'))topologyInputUpdate(el)});
$('content').addEventListener('change',e=>{const el=e.target as HTMLInputElement;if(el.matches('#smtp-preset')){
      const host=el.value==='zoho-in-org'?'smtppro.zoho.in':el.value==='zoho-in-standard'?'smtp.zoho.in':'';
      const form=$('mail-config') as HTMLFormElement;
      if(host&&form){(form.elements.namedItem('host') as HTMLInputElement).value=host;(form.elements.namedItem('port') as HTMLInputElement).value='587';(form.elements.namedItem('startTls') as HTMLInputElement).checked=true;(form.elements.namedItem('enabled') as HTMLInputElement).checked=false;show('Zoho India SMTP preset selected. Save with OTP off, test real delivery, then enable OTP. Never paste account passwords into GitHub.')}
      return;
    }if(el.matches('[data-setup-field],[data-setup-array]'))topologyInputUpdate(el)});
document.querySelectorAll<HTMLButtonElement>('.nav').forEach(el=>el.onclick=()=>{view=el.dataset.view||'overview';render()});$('page-back').onclick=()=>navigateBack();$('modal-close').onclick=()=>($('modal') as HTMLDialogElement).close();$('refresh').onclick=()=>void reload();$('save').onclick=()=>void save();$('logout').onclick=()=>void api('/admin/api/logout','POST',{}).then(()=>showLogin(false)).catch(e=>show(String(e),true));void initSession();

async function initSession(){
  try {
    const r=await api('/admin/api/session');
    if(!r.authenticated){showLogin(!r.initialized);return}
    csrf=r.csrf;currentRole=r.role;currentUser=r.username;
    $('user-badge').textContent=currentUser+' · '+currentRole;
    $('auth-screen').hidden=true;$('app-shell').hidden=false;
    document.querySelectorAll<HTMLButtonElement>('[data-view="users"],[data-view="mail"],[data-view="directory"]').forEach(b=>b.hidden=currentRole!=='Administrator');
    $('save').hidden=currentRole==='Viewer';
    await loadTopology();
    await loadOrganization();
    if(!orgProfile?.organizationName) view='organization';
    else if(topologyResponse?.status!=='design-confirmed')view='setup';
    updateTopologyNavigation();
    await reload();
  } catch(err){$('auth-message').textContent=String(err);$('auth-screen').hidden=false;$('app-shell').hidden=true}
}
function showLogin(first:boolean){csrf='';currentRole='';$('app-shell').hidden=true;$('auth-screen').hidden=false;
 $('auth-title').textContent=first?'Create initial administrator':'Sign in to YARP Control Center';
 $('auth-description').textContent=first?'Create a local recovery administrator first. You can enable AD login and email OTP after signing in.':'Restricted local management access';
 $('auth-submit').textContent=first?'Create administrator':'Sign in';
 $('auth-email-row').hidden=!first;$('auth-provider-row').hidden=first;$('auth-otp-row').hidden=true;($('auth-password') as HTMLInputElement).required=true;($('auth-otp') as HTMLInputElement).required=false;otpChallenge='';
 ($('auth-form') as HTMLFormElement).dataset.mode=first?'bootstrap':'login';
 $('auth-message').textContent='';if(!first)void fetch('/admin/api/auth-methods').then(r=>r.json()).then(m=>{const x=$('auth-provider') as HTMLSelectElement;x.querySelectorAll<HTMLOptionElement>('option[value="directory"]').forEach(o=>{o.disabled=!m.activeDirectory;o.textContent=m.activeDirectory?'Active Directory / LDAPS':'Active Directory (not configured)'});}).catch(()=>{});}
($('auth-provider') as HTMLSelectElement).onchange=()=>{($('auth-password') as HTMLInputElement).minLength=($('auth-provider') as HTMLSelectElement).value==='directory'?1:16};
($('auth-form') as HTMLFormElement).onsubmit=async e=>{
 e.preventDefault();const mode=($('auth-form') as HTMLFormElement).dataset.mode;
 const username=($('auth-username') as HTMLInputElement).value.trim();
 const password=($('auth-password') as HTMLInputElement).value;
 const email=($('auth-email') as HTMLInputElement).value.trim();
 try{const r=mode==='verify'?await api('/admin/api/login/verify','POST',{challengeId:otpChallenge,code:($('auth-otp') as HTMLInputElement).value.trim()}):await api('/admin/api/'+mode,'POST',{username,password,email,provider:($('auth-provider') as HTMLSelectElement).value});
   if(r.otpRequired){otpChallenge=r.challengeId;($('auth-form') as HTMLFormElement).dataset.mode='verify';$('auth-otp-row').hidden=false;($('auth-password') as HTMLInputElement).required=false;($('auth-otp') as HTMLInputElement).required=true;$('auth-submit').textContent='Verify email code';$('auth-description').textContent='Enter the six-digit code sent to '+r.emailHint;($('auth-password') as HTMLInputElement).value='';return;}
   if(!r.authenticated)throw Error('Authentication was not completed');
   ($('auth-password') as HTMLInputElement).value='';await initSession();
 }catch(err){$('auth-message').textContent=String(err)}
};
async function inventory(){try{const items=await api('/admin/api/inventory');
 const rows=items.map((x:Obj)=>`<tr><td><b>${esc(x.name)}</b><div class="subtle mono">${esc(x.id)}</div></td><td>${esc(x.type)}</td><td class="mono">${esc(x.address)}</td><td>${esc(x.notes)}</td><td>${currentRole==='Viewer'?'—':actionBtn('Remove','inventory-delete',x.id,'danger-btn mini')}</td></tr>`).join('');
 $('content').innerHTML=`<div class="toolbar"><div><h2>Infrastructure inventory</h2><p class="subtle">Register machines and services for documentation. Registration does not install software or configure firewalls.</p></div>${currentRole==='Viewer'?'':actionBtn('+ Register asset','inventory-add','')}</div><div class="tablewrap"><table><thead><tr><th>Name / ID</th><th>Type</th><th>Address</th><th>Notes</th><th>Actions</th></tr></thead><tbody>${rows||'<tr><td colspan="5" class="empty">No assets registered</td></tr>'}</tbody></table></div>`
 }catch(e){show(String(e),true)}}
function addInventory(){modal('Register infrastructure asset','Inventory only: this does not install an agent or manage a remote Windows machine.',[
{name:'id',label:'Unique ID',value:''},{name:'name',label:'Display name',value:''},
{name:'type',label:'Asset type',value:'Application Server',options:['YARP Gateway','Application Server','Pgpool','Database','Service']},
{name:'address',label:'Address or hostname',value:''},{name:'notes',label:'Notes',value:''}
],async v=>{try{await api('/admin/api/inventory','POST',v);show('Asset registered');await inventory()}catch(e){show(String(e),true)}})}
async function users(){try{const list=await api('/admin/api/users');
 const rows=list.map((x:Obj)=>`<tr><td><b>${esc(x.username)}</b></td><td>${esc(x.email||'—')}</td><td>${esc(x.role)}</td><td>${esc(x.provider||'Local')}</td><td><span class="chip ${x.enabled?'good':'bad'}">${x.enabled?'Enabled':'Disabled'}</span></td><td>${x.provider==='AD'?'AD password managed by directory':actionBtn('Reset password','password-reset',x.username)} ${actionBtn(x.enabled?'Offboard':'Re-enable',x.enabled?'user-disable':'user-enable',x.username)}</td></tr>`).join('');
 $('content').innerHTML=`<div class="toolbar"><div><h2>Administrator accounts</h2><p class="subtle">Administrators onboard/offboard users; Operators manage routes; Viewers read only. Disabling an account blocks new sign-ins and invalidates existing sessions. Inactive sessions expire after 30 minutes.</p></div>${actionBtn('+ Add account','user-add','')} ${actionBtn('Mail & OTP','switch','mail')} ${actionBtn('Active Directory','switch','directory')}</div><div class="tablewrap"><table><thead><tr><th>Username</th><th>Email</th><th>Role</th><th>Authentication</th><th>Status</th><th>Action</th></tr></thead><tbody>${rows}</tbody></table></div>`;
 }catch(e){show(String(e),true)}}
function addUser(){modal('Create management user','Passwords must contain 16 to 256 characters.',[
{name:'username',label:'Username',value:''},{name:'role',label:'Role',value:'Viewer',options:['Viewer','Operator','Administrator']},
{name:'email',label:'Email address for login OTP (required)',value:''},{name:'password',label:'Temporary password (16+ chars)',value:'',kind:'password',minLength:16}
],async v=>{try{await api('/admin/api/users','POST',v);show('Account created');await users()}catch(e){show(String(e),true)}},'Create account')}
function resetPassword(username:string){modal('Reset '+username+' password','Existing sessions should be treated as active until expired; coordinate with users.',[
{name:'password',label:'New password (16+ characters)',value:'',kind:'password',minLength:16}
],async v=>{try{await api('/admin/api/users/'+encodeURIComponent(username)+'/password','POST',v);show('Password changed');await users()}catch(e){show(String(e),true)}},'Reset password')}

async function mailPage(){
 if(currentRole!=='Administrator')return;
 try{
  const m=await api('/admin/api/mail');
  $('content').innerHTML=`<div class="toolbar"><div><h2>Mail relay & email OTP</h2><p class="subtle">Step 1: save relay settings with OTP off. Step 2: test delivery to the administrator email. Step 3: enable OTP only after the test passes. An optional SMTP relay is not needed for local gateway traffic.</p></div><span class="chip ${m.deliveryVerified?'good':'bad'}">${m.deliveryVerified?'SMTP test accepted':'Test required'}</span></div>
  <div class="settings-columns"><div class="card"><h3>SMTP connection</h3><form id="mail-config" class="settings-form">
   <label>SMTP provider / region<select id="smtp-preset">
    <option value="">Custom SMTP server (keep existing settings)</option>
    <option value="zoho-in-org">Zoho Mail India — organization (smtppro.zoho.in)</option>
    <option value="zoho-in-standard">Zoho Mail India — personal/free (smtp.zoho.in)</option>
   </select></label>
   <p class="subtle">mail.zoho.in is the webmail website, not the SMTP endpoint. Confirm the exact server in Zoho Mail → Server Configuration Details. Selecting a preset changes only host, port, STARTTLS and disables OTP until re-tested; it never populates or transmits a password.</p>
   <label>SMTP DNS host<input name="host" value="${esc(m.host||'')}" placeholder="smtp.internal.example.com" required></label>
   <label>Port<input name="port" type="number" value="${esc(m.port||587)}" min="1" max="65535" required></label>
   <label>Sender address<input name="from" type="email" value="${esc(m.from||'')}" placeholder="yarp-alerts@example.com" required></label>
   <label>SMTP login (optional)<input name="username" autocomplete="off" value="${esc(m.username||'')}"></label>
   <label>SMTP password (leave blank to preserve)<input name="password" autocomplete="new-password" type="password" placeholder="${m.passwordConfigured?'A credential is stored':''}"></label>
   <label class="setting-check"><input name="startTls" type="checkbox" ${m.startTls?'checked':''}> Require STARTTLS (recommended: 587)</label>
   <label class="setting-check"><input name="enabled" type="checkbox" ${m.enabled?'checked':''} ${!m.deliveryVerified?'disabled':''}> Require email OTP at sign-in</label>${!m.deliveryVerified?'<p class="subtle">OTP remains unavailable until the saved SMTP settings pass the delivery test. Save with OTP off, test, then return here.</p>':''}
   <div class="action-strip"><button type="submit" class="primary">Save SMTP settings</button><button type="button" class="ghost" data-action="mail-test" data-id="">Send test to my account</button></div>
  </form></div><div class="card"><h3>Secure setup sequence</h3><p class="subtle">1. Save the mail server with OTP disabled.</p><p class="subtle">2. Send a test to your registered administrator email.</p><p class="subtle">3. Confirm the email arrived.</p><p class="subtle">4. Enable OTP and save again. Next login will require a code.</p><div class="healthbanner">Authenticated mail requires STARTTLS and a trusted SMTP certificate. This version supports authenticated STARTTLS (usually port 587); implicit TLS on 465 is intentionally disabled in this version. Email OTP is not phishing-resistant MFA.</div></div></div>`;
 }catch(e){show(String(e),true)}
}
async function directoryPage(){
 if(currentRole!=='Administrator')return;
 try{
  const d=await api('/admin/api/directory');
  $('content').innerHTML=`<div class="toolbar"><div><h2>Active Directory authentication</h2><p class="subtle">Use LDAPS to authenticate users and map AD security groups to YARP management roles.</p></div><span class="chip ${d.enabled?'good':'bad'}">${d.enabled?'AD login enabled':'AD login disabled'}</span></div>
  <div class="settings-columns"><div class="card"><h3>Directory connection and role mapping</h3><form id="directory-config" class="settings-form">
  <label>Domain controller DNS name<input name="host" value="${esc(d.host||'')}" placeholder="dc01.example.internal" required></label>
  <label>LDAPS port<input name="port" type="number" min="1" max="65535" value="${esc(d.port||636)}"></label>
  <label>Search base DN<input name="searchBaseDn" value="${esc(d.searchBaseDn||'')}" placeholder="DC=example,DC=internal" required></label>
  <label>Read-only bind account (UPN)<input name="bindUsername" value="${esc(d.bindUsername||'')}" autocomplete="off" placeholder="svc_yarp_ldap@example.internal" required></label>
  <label>Service account password<input type="password" name="password" autocomplete="new-password" placeholder="${d.passwordConfigured?'Saved credential present; blank keeps current':'Service credential required'}"></label>
  <label>Administrator group distinguished name<input name="adminGroupDn" value="${esc(d.adminGroupDn||'')}" placeholder="CN=YARP-Admins,OU=Security,DC=example,DC=internal" required></label>
  <label>Operator group distinguished name (optional)<input name="operatorGroupDn" value="${esc(d.operatorGroupDn||'')}"></label>
  <label>Viewer group distinguished name (optional)<input name="viewerGroupDn" value="${esc(d.viewerGroupDn||'')}"></label>
  <label class="setting-check"><input type="checkbox" name="enabled" ${d.enabled?'checked':''}> Enable Active Directory login (requires verified email OTP)</label>
  <div class="action-strip"><button type="submit" class="primary">Save & validate directory</button><button type="button" class="ghost" data-action="directory-test" data-id="">Test saved LDAPS</button></div>
  </form></div><div class="card"><h3>How AD login works</h3><p class="subtle">Enter a SAM account name and password on the sign-in page, select Active Directory, then complete email OTP.</p><p class="subtle">Only AD users in the specified groups can sign in. Nested groups are evaluated. A disabled AD user or revoked group membership invalidates its management session.</p>
  <div class="healthbanner">Use LDAPS TCP 636 and import the issuing CA for your domain controller certificate into the Windows trusted root store. The controller does not have to join the domain for LDAP simple bind. Keep local bootstrap admin as a restricted recovery account.</div>
  <h3 class="card-spaced">Test an AD account</h3><form id="directory-user-test" class="settings-form"><label>AD username (sAMAccountName)<input name="username" required autocomplete="off"></label><label>Password (not stored)<input name="password" type="password" autocomplete="off" required></label><button type="submit" class="ghost">Check credentials and group role</button></form></div></div>`;
 }catch(e){show(String(e),true)}
}
function formData(el:HTMLFormElement){const f=new FormData(el);const v:Obj={};f.forEach((x,k)=>{v[k]=String(x)});return v}
$('content').addEventListener('submit',e=>{
 const f=e.target as HTMLFormElement;
 if(!['mail-config','directory-config','directory-user-test'].includes(f.id))return;
 e.preventDefault();const v=formData(f);
 if(f.id==='mail-config'){
  v.port=Number(v.port);v.enabled=f.querySelector<HTMLInputElement>('[name="enabled"]')?.checked??false;
  v.startTls=f.querySelector<HTMLInputElement>('[name="startTls"]')?.checked??false;
  void api('/admin/api/mail','POST',v).then(()=>{show('SMTP settings saved. Send a test before enabling OTP.');void mailPage()}).catch(err=>show(String(err),true));
 } else if(f.id==='directory-config'){
  v.port=Number(v.port);v.enabled=f.querySelector<HTMLInputElement>('[name="enabled"]')?.checked??false;
  void api('/admin/api/directory','POST',v).then(()=>{show('Directory settings saved and validated.');void directoryPage()}).catch(err=>show(String(err),true));
 } else {
  void api('/admin/api/directory/test-user','POST',v).then(r=>{f.reset();show(`AD credentials valid; mapped role: ${r.role}`)}).catch(err=>show(String(err),true));
 }
});

async function fleet(){try{const rows:Obj[]=await api('/admin/api/fleet');$('content').innerHTML=`<div class="toolbar"><div><h2>Managed YARP gateway fleet</h2><p class="subtle">Read-only mTLS gateway status. A registered gateway is not automatically enrolled or remotely controlled.</p></div>${currentRole==='Administrator'?actionBtn('+ Register gateway','fleet-add',''):''} ${actionBtn('Check agent status','fleet-probe','')} ${currentRole==='Administrator'?actionBtn('Roll out approved change','fleet-rollout',''):''} ${actionBtn('Destination metrics','dest-metrics','')}</div><div class="tablewrap"><table><thead><tr><th>Gateway</th><th>HTTPS agent origin</th><th>Identity</th><th>Actions</th></tr></thead><tbody>${rows.map(x=>`<tr><td>${esc(x.id)}</td><td class="mono">${esc(x.url)}</td><td>${esc(x.clientCertificateThumbprint)}</td><td>${currentRole==='Administrator'?actionBtn('Unregister','fleet-remove',x.id):'—'}</td></tr>`).join('')||'<tr><td colspan="4">No gateways registered</td></tr>'}</tbody></table></div><div class="healthbanner">mTLS gateway agents require independent certificate provisioning. This console cannot remotely install Windows services or deploy configs yet.</div>`}catch(e){show(String(e),true)}}
function addFleet(){modal('Register trusted gateway','Only HTTPS gateway origins, with an installed client certificate on the controller. Registration does not establish trust or enable remote actions.',[{name:'id',label:'Gateway ID',value:''},{name:'url',label:'Agent origin e.g. https://gw01.internal:8443/',value:''},{name:'clientCertificateThumbprint',label:'Client certificate thumbprint in LocalMachine\My',value:''}],async v=>{try{await api('/admin/api/fleet','POST',v);show('Gateway registered');await fleet()}catch(e){show(String(e),true)}})}
async function fleetStatus(){try{show('Connecting to registered mTLS agents...');const r=await api('/admin/api/fleet/status');$('content').innerHTML=`<div class="card"><h2>Authenticated gateway reports</h2><p class="subtle">${esc(r.type)}</p>${(r.gateways||[]).map((g:Obj)=>`<div class="rowline"><b>${esc(g.id)}</b><span class="chip">${esc(g.state)}</span></div>`).join('')||'<p>No gateways registered.</p>'}</div>`}catch(e){show(String(e),true)}}

async function performFleetRollout(){
 const changeId=prompt('Enter a two-person APPROVED change request ID for BOTH gateways. Changes can affect live traffic.');
 if(!changeId)return;
 if(!confirm('Confirm staging and activating the approved configuration on EVERY registered gateway? Unavailable gateways can cause a partial deployment requiring manual recovery.'))return;
 try{const x=await api('/admin/api/fleet/rollout/'+encodeURIComponent(changeId),'POST',{});
 show('Rollout '+x.id+': '+x.status+'. Validate live traffic and failover.');await fleetStatus();}
 catch(e){show(String(e)+'; examine Fleet rollout journal before taking further action',true)}
}
async function destinationMetrics(){try{const x=await api('/admin/api/destination-metrics');
 $('content').innerHTML=`<div class="card"><h2>Destination-level request observations</h2><p class="subtle">${esc(x.scope)} · ${esc(x.timestampUtc)}</p><div class="tablewrap"><table><thead><tr><th>Cluster / destination</th><th>Requests</th><th>HTTP 4xx</th><th>HTTP 5xx</th><th>Mean latency (ms)</th></tr></thead><tbody>${(x.destinations||[]).map((d:Obj)=>`<tr><td>${esc(d.id)}</td><td>${esc(d.requests)}</td><td>${esc(d.clientErrors4xx)}</td><td>${esc(d.failures5xx)}</td><td>${esc(d.meanLatencyMs)}</td></tr>`).join('')||'<tr><td colspan="5">No routed requests observed yet.</td></tr>'}</tbody></table></div></div>`;
 }catch(e){show(String(e),true)}}
