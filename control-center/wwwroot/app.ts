type Obj = Record<string, any>;
type State = {name:string;gateway:string;time:string;routes:Obj;clusters:Obj;disabled:Obj;mode:string;telemetry:string;revision:string};
let data:State = {name:'GatewayCore',gateway:'unknown',time:'',routes:{},clusters:{},disabled:{},mode:'Local testing',telemetry:'',revision:''};
let viewHistory:string[]=[];let lastRenderedView='setup';let restoringNavigation=false;
function navigateBack(){if(viewHistory.length){restoringNavigation=true;view=viewHistory.pop()!;render()}else if(view!=='setup'){restoringNavigation=true;view='setup';render()}}
let view='setup';let dirty=false;let probes:Obj[]=[];let liveDestinationHealth:Obj[]|null=null;let liveDestinationHealthAt='';let csrf='';let currentRole='';let currentUser='';let federatedOidcSession=false;let otpChallenge='';
let privacyVersion='';
let authGeneration=0;let gatewayReadyLabel='● Backend readiness not checked';let gatewayReadyWarn=true;let readinessGeneration=0;let readinessAbort:AbortController|null=null;
const $=(id:string)=>document.getElementById(id)!;
const esc=(s:any)=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'} as Obj)[c]);
const keys=(o:Obj)=>Object.keys(o||{});
type OrgProfile={organizationName:string;sector:string;region:string;notes:string;revision:number;updatedBy:string;updatedUtc:string|null};
let orgProfile:OrgProfile|null=null;
const sectors=['general','technology','finance','healthcare','government','telecom','ecommerce','education','ca-pki','other'];
function updateBrand(){const name=orgProfile?.organizationName?.trim()||'GatewayCore';
 document.querySelectorAll<HTMLElement>('[data-organization-name]').forEach(el=>el.textContent=name);
 document.title=name+' | GatewayCore Control Center';
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
async function api(url:string,method='GET',body?:any,signal?:AbortSignal){const opts:RequestInit={method,credentials:'same-origin',headers:{},signal,cache:'no-store'};if(method!=='GET'){(opts.headers as Obj)['Content-Type']='application/json';(opts.headers as Obj)['X-CSRF-Token']=csrf;opts.body=JSON.stringify(body??{})}const generation=authGeneration;const r=await fetch(url,opts);if(generation!==authGeneration)throw Error('Management session changed. Outdated response ignored.');if(r.status===428){showLogin(false);void initSession();throw Error('Please accept the Privacy Policy to continue.')}if(r.status===401){if(!['/admin/api/session','/admin/api/login','/admin/api/bootstrap','/admin/api/login/verify'].includes(url)){if(!$('app-shell').hidden||!$('privacy-screen').hidden){showLogin(false);$('auth-message').textContent='Your administrator session has expired or was invalidated. Sign in again. No security settings were changed.'}throw Error('Administrator session expired; please sign in again')}throw Error('Authentication failed. Check your credentials or verification code.')}if(r.status===403){let stepUp=false;try{stepUp=(await r.json()).signIn==='/admin/oidc/start'}catch{}if(stepUp)throw Error('Fresh enterprise authentication required. Sign out, then sign in with Enterprise SSO / passkey. Retry only after reviewing the change.');throw Error('Access denied. This action requires an authorized role or valid CSRF token.')}if(!r.ok){let e='HTTP '+r.status;try{e=(await r.json()).error??e}catch{}throw Error(e)}const json=await r.json();if(generation!==authGeneration)throw Error('Management session changed. Outdated response ignored.');return json}
async function reload(){if(dirty&&!confirm('Discard unsaved changes and reload?'))return;try{data=await api('/admin/api/state');dirty=false;render();void refreshGatewayReadiness();show('Latest configuration loaded')}catch(e){show(String(e),true)}}
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
function destinationRows(){const arr:Obj[]=[];for(const cid of keys(data.clusters)){for(const did of keys(data.clusters[cid]?.Destinations)){const destination=data.clusters[cid].Destinations[did];arr.push({cid,did,address:destination.Address,enabled:true,metadata:destination.Metadata||{},trafficState:String(destination.Metadata?.TrafficState||'active'),weight:String(destination.Metadata?.Weight||'1'),trafficRole:String(destination.Metadata?.TrafficRole||'primary')})}}for(const id of keys(data.disabled)){const [cid,did]=id.split('::');const destination=data.disabled[id];arr.push({cid,did,address:destination.Address,enabled:false,metadata:destination.Metadata||{},trafficState:String(destination.Metadata?.TrafficState||'active'),weight:String(destination.Metadata?.Weight||'1'),trafficRole:String(destination.Metadata?.TrafficRole||'primary')})}return arr}
function summary(){const ready=!gatewayReadyWarn&&gatewayReadyLabel.includes('Backend readiness observed');const status=ready?'BACKEND READY':gatewayReadyLabel.includes('No healthy backend reported')?'NO BACKEND':'NOT VERIFIED';
 return `<div class="stats"><div class="card"><h3>Backend readiness</h3><div class="stat-number ${ready?'green':'yellow'}">${status}</div><div class="stat-desc">${ready?'At least one configured destination ready; not full fleet health':esc(gatewayReadyLabel.replace('● ',''))}</div></div><div class="card"><h3>Configured routes</h3><div class="stat-number">${keys(data.routes).length}</div><div class="stat-desc">Saved / draft HTTP routing rules</div></div><div class="card"><h3>Backend clusters</h3><div class="stat-number">${keys(data.clusters).length}</div><div class="stat-desc">Independent balancing policies</div></div><div class="card"><h3>Enabled destinations</h3><div class="stat-number">${destinationRows().filter(x=>x.enabled).length}</div><div class="stat-desc">Configured, not necessarily healthy</div></div></div>`}
function guide(){return `<div class="card operator-intro"><h2>GatewayCore in five steps</h2><p>GatewayCore forwards client HTTP(S) requests to application servers. A route matches a hostname/path; a backend group (cluster) contains servers (destinations).</p><div class="operator-flow"><span>Client</span><span aria-hidden="true">→</span><span>GatewayCore</span><span aria-hidden="true">→</span><span>Application servers</span></div></div><div class="operator-steps"><section class="card"><h3>1. Set up the gateway</h3><p>Create an administrator, accept the Privacy Policy and configure your organization. In Start here, open Gateway architecture. Choose Standalone for one server or review the HA design. For a local test, fill the single-server test draft, then Confirm design. This does not create VIPs, agents or firewall rules.</p></section><section class="card"><h3>2. Add a website or API</h3><p>Enter the client hostname and HTTPS backend root URL. Add a second backend only if you want round-robin balancing. Local website test uses an existing loopback HTTP site and the /lab/ prefix. DNS, listeners and IIS are not automatically configured.</p></section><section class="card"><h3>3. Review and approve</h3><p>Review Websites &amp; routes and Backend servers. Submit for approval with a reason of at least 12 characters. A different administrator must review and approve the exact draft in Change requests. Until then, the routing change is not live.</p></section><section class="card"><h3>4. Test actual traffic</h3><p>Inspect live backend health and run HTTP probes. Unknown is not healthy. For the approved local test open http://127.0.0.1:8080/lab/. For other applications test the approved client listener and hostname. Never expose the management listener publicly. Check Traffic metrics for errors.</p></section><section class="card"><h3>5. Operate and recover</h3><p>Configuration contains backend groups, backups and audit. Security &amp; accounts contains administrators, mail and directory settings. Multi-gateway &amp; modules contains fleet, peer and capability evidence. HA needs enrolled agents, signed rollout and independently tested VIP failover.</p></section><section class="card"><h3>Troubleshooting</h3><p>No backend? Add and approve a website first. Unknown health? Check the actual readiness endpoint before enabling active checks. Changes blocked? Check the freeze and request revision. Sign-in failed? Use your recovery administrator; never delete protected state or keys. Lab evidence is not production certification.</p></section></div>`}
function overview(){let routes=keys(data.routes).slice(0,5).map(id=>`<div class="rowline"><div><b>${esc(id)}</b><div class="subtle mono">${esc(data.routes[id]?.Match?.Path||'—')}</div></div><span class="chip">${esc(data.routes[id]?.ClusterId||'—')}</span></div>`).join('')||'<div class="empty">No routes configured</div>';let nodes=destinationRows().slice(0,6).map(d=>`<div class="rowline"><div><b>${esc(d.did)}</b><div class="subtle mono">${esc(d.address)}</div></div><span class="chip ${d.enabled?'':'bad'}">${d.enabled?'Configured':'Disabled'}</span></div>`).join('')||'<div class="empty">No destinations configured</div>';return summary()+`<div class="grid2"><div class="card"><div class="flex"><h2 class="section-title">Traffic architecture</h2><span class="chip">Design view</span></div><div class="arch"><div class="archnode">Clients / Public & internal ingress</div><div class="arrow">↓</div><div class="archnode">Firewall / upstream HA VIP</div><div class="arrow">↓</div><div class="archnode accent">${esc(topologyModeName(topologyResponse?.plan?.mode||'standalone'))} (design topology)</div><div class="arrow">↓</div><div class="twonodes"><div class="archnode">Backend node 01</div><div class="archnode">Backend node 02</div></div><div class="arrow">↓</div><div class="archnode">Application-specific data services (optional)</div></div><div class="healthbanner">This gateway is one running instance. The onboarding design is metadata, not proof that a gateway fleet, VIP or backend is healthy.</div></div><div><div class="card"><h2 class="section-title">Route snapshot</h2>${routes}${actionBtn('Manage routes','switch','routes')}</div><div class="card card-spaced"><h2 class="section-title">Destinations</h2>${nodes}${actionBtn('Manage backends','switch','backends')}</div></div></div>`}
function routes(){const rows=keys(data.routes).map(id=>{const r=data.routes[id];return `<tr><td><b>${esc(id)}</b></td><td class="mono">${esc((r.Match?.Hosts||[]).join(', ')||'Any host')}</td><td class="mono">${esc(r.Match?.Path)}</td><td>${esc(r.ClusterId)}</td><td>${actionBtn('Edit','route-edit',id)} ${actionBtn('Advanced','route-advanced',id)} ${actionBtn('Delete','route-delete',id,'danger-btn mini')}</td></tr>`}).join('');return `<div class="toolbar"><div><h2>Websites &amp; routes</h2><p class="subtle">A route matches the client hostname and path, then forwards to a backend group (cluster). Draft changes need approval.</p></div>${actionBtn('+ Add website / API','setup-simple-website','','primary')} ${actionBtn('Advanced: add route','route-add','')}</div><div class="tablewrap"><table><thead><tr><th>Route ID</th><th>Hosts</th><th>Path</th><th>Cluster</th><th>Actions</th></tr></thead><tbody>${rows||'<tr><td colspan="5" class="empty">No routes configured</td></tr>'}</tbody></table></div>`}
function clusters(){const rows=keys(data.clusters).map(id=>{const c=data.clusters[id];const active=!!c.HealthCheck?.Active?.Enabled,passive=!!c.HealthCheck?.Passive?.Enabled;const health=active&&passive?'<span class="chip good">Active + passive</span>':active?'<span class="chip good">Active</span>':passive?'<span class="chip warn">Passive only</span>':'<span class="chip">Disabled</span>';return `<tr><td><b>${esc(id)}</b></td><td>${esc(c.LoadBalancingPolicy||'Default')}</td><td>${keys(c.Destinations||{}).length}</td><td>${health}</td><td>${actionBtn('Edit','cluster-edit',id)} ${actionBtn('Advanced','cluster-advanced',id)} ${actionBtn('Delete','cluster-delete',id,'danger-btn mini')}</td></tr>`}).join('');return `<div class="toolbar"><div><h2>Backend groups (clusters)</h2><p class="subtle">A group contains the servers for one application and defines traffic distribution.</p></div>${actionBtn('+ Add cluster','cluster-add','')}</div><div class="tablewrap"><table><thead><tr><th>Cluster</th><th>Policy</th><th>Active backends</th><th>Health checks</th><th>Actions</th></tr></thead><tbody>${rows||'<tr><td colspan="5" class="empty">No clusters configured</td></tr>'}</tbody></table></div>`}
function backends(){const rows=destinationRows().map(d=>{const live=liveDestinationHealth?.find(x=>x.clusterId===d.cid&&x.destinationId===d.did);const configuredState=!d.enabled?'Disabled':d.trafficState==='draining'?'Draining':'Active';const stateClass=configuredState==='Active'?'good':configuredState==='Draining'?'warn':'bad';const runtime=live?`<span class="chip">A: ${esc(live.activeHealth||'Unknown')}</span> <span class="chip">P: ${esc(live.passiveHealth||'Unknown')}</span><div class="subtle">In-flight: ${esc(String(live.concurrentRequests??'—'))}</div>`:'<span class="subtle">Not inspected</span>';const drainButton=d.enabled?actionBtn(d.trafficState==='draining'?'Restore traffic':'Drain new traffic','dest-drain',d.cid+'::'+d.did):'';return `<tr><td><b>${esc(d.did)}</b><div class="subtle">${esc(d.cid)} · weight ${esc(d.weight)} · ${esc(d.trafficRole)}</div></td><td class="mono">${esc(d.address)}</td><td><span class="chip ${stateClass}">${configuredState}</span><div class="subtle">Configured draft state; runtime health shown separately</div></td><td>${runtime}<div>${drainButton} ${actionBtn(d.enabled?'Disable':'Enable','dest-toggle',d.cid+'::'+d.did)} ${actionBtn('Edit','dest-edit',d.cid+'::'+d.did)} ${actionBtn('Advanced','dest-advanced',d.cid+'::'+d.did)} ${actionBtn('Delete','dest-delete',d.cid+'::'+d.did,'danger-btn mini')}</div></td></tr>`}).join('');const liveNote=liveDestinationHealth?`<p class="subtle">Live YARP snapshot checked ${esc(liveDestinationHealthAt)} · single local process. Unsaved changes do not affect this runtime snapshot.</p>`:'<p class="subtle">Runtime health has not been inspected in this session.</p>';return `<div class="toolbar"><div><h2>Backend servers (destinations)</h2><p class="subtle">Each application route points to its own cluster. Runtime health is per gateway; draining is a reviewed configuration change.</p></div>${actionBtn('Inspect live health','runtime-health','')} ${actionBtn('+ Add backend','dest-add','')}</div>${liveNote}<div class="tablewrap"><table><thead><tr><th>Destination / pool</th><th>Address</th><th>Traffic state</th><th>Runtime health and actions</th></tr></thead><tbody>${rows||'<tr><td colspan="4" class="empty">No destinations</td></tr>'}</tbody></table></div><div class="healthbanner">Drain removes a destination from new-request selection after an approved config rollout; in-flight requests continue. A host match separates routes, but private API access still requires a restricted listener and firewall policy. Runtime health is an authenticated, point-in-time view of this process only.</div>`}
async function refreshDestinationRuntime(){try{const r=await api('/admin/api/runtime/destinations');const clusters=Array.isArray(r.clusters)?r.clusters as Obj[]:[];liveDestinationHealth=clusters.flatMap((cluster:Obj)=>Array.isArray(cluster.destinations)?(cluster.destinations as Obj[]).map(destination=>({...destination,clusterId:String(cluster.clusterId||'')})):[]);liveDestinationHealthAt=String(r.timestampUtc||'unknown');if(view==='backends')render();show('Live local YARP health snapshot loaded. Unknown remains distinct from healthy.')}catch(e){show('Could not inspect live local YARP health: '+String(e),true)}}
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
  const buckets=Array.isArray(m.durationBuckets)?m.durationBuckets as Obj[]:[];
  const maxBucket=Math.max(1,...buckets.map((x:Obj)=>Number(x.requests)||0));
  const bars=buckets.map((x:Obj,i:number)=>{const n=Math.max(0,Number(x.requests)||0);const h=Math.max(2,Math.round(n/maxBucket*92));const label=x.upperBoundSeconds==='+Inf'?'>10s':`≤ ${Math.round(Number(x.upperBoundSeconds)*1000)}ms`;const cx=34+i*52;return `<g><title>${esc(label)}: ${n} requests</title><rect x="${cx}" y="${100-h}" width="28" height="${h}" rx="3" fill="#3b82f6"/><text x="${cx+14}" y="118" text-anchor="middle" font-size="9">${esc(label)}</text></g>`}).join('');
  const reports=currentRole==='Administrator'||currentRole==='Operator'?'<a class="btn" href="/admin/api/reports/traffic.json" download>Traffic JSON + histogram</a> <a class="btn" href="/admin/api/reports/traffic.csv" download>Traffic CSV + histogram</a> <a class="btn" href="/admin/api/reports/health.json" download>Backend health JSON</a> <a class="btn" href="/admin/api/reports/health.csv" download>Backend health CSV</a>':'';
  $('content').innerHTML=`<div class="stats"><div class="card"><h3>Requests in process lifetime</h3><div class="stat-number">${esc(m.totalRequests)}</div></div><div class="card"><h3>HTTP 2xx</h3><div class="stat-number green">${esc(m.success2xx)}</div></div><div class="card"><h3>HTTP 5xx</h3><div class="stat-number red">${esc(m.serverErrors5xx)}</div></div><div class="card"><h3>Mean duration</h3><div class="stat-number">${esc(m.meanDurationMs)} ms</div></div></div><div class="card card-spaced"><div class="rowline"><div><h2>Request duration distribution</h2><p class="subtle">Per-process histogram since restart · exclusive buckets</p></div><div>${reports}</div></div><svg width="100%" height="160" viewBox="0 0 ${Math.max(440,buckets.length*52+24)} 132" role="img" aria-label="Request duration distribution histogram">${bars}</svg><h2>Local YARP gateway process</h2><p class="subtle">${esc(m.scope)}</p><p class="subtle">Gateway ${esc(m.gateway)} · HTTP 4xx: ${esc(m.clientErrors4xx)} · Snapshot: ${esc(m.collectedUtc)}</p>${actionBtn('Refresh metrics','switch','metrics')}</div><div class="healthbanner">This snapshot covers one process since restart; it is not a time-series or a fleet-wide report. Aggregate historical data across gateways with the secured Prometheus/Grafana pipeline. Access logs omit query strings and headers; client IPs are only accepted from the socket peer or an explicitly trusted proxy.</div>`;
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

async function peerSyncPage() {
    if (view !== 'peers') return;
    $('content').innerHTML = '<div class="card"><h2>Peer synchronization</h2><p class="subtle">Loading authenticated status…</p></div>';
    try {
        const s = await api('/admin/api/peer-sync/status');
        if (view !== 'peers') return;
        const active = !!s.enabled;
        const current = active && !!s.recentExchange && !!s.remoteReportedInCurrentMinute;
        const state = !active ? 'Not configured' : current ? 'Recent exchange observed' : 'No recent exchange';
        const seen = s.lastAcceptedUtc ? new Date(s.lastAcceptedUtc).toLocaleString() : 'No accepted message';
        const rows = [['Local node', s.localNode], ['Expected peer', s.remoteNode],
            ['Last accepted message', seen], ['Expected interval', active ? String(s.expectedIntervalSeconds) + ' seconds' : '—'],
            ['Last accepted age', s.lastAcceptedAgeSeconds == null ? 'No accepted message' : String(s.lastAcceptedAgeSeconds) + ' seconds (monotonic)'],
            ['Publisher attempts', active ? String(s.publisherAttemptsTotal ?? 0) : '—'],
            ['Publisher acknowledgements', active ? String(s.publisherAcknowledgementsTotal ?? 0) : '—'],
            ['Publisher HTTP failures', active ? String(s.publisherHttpFailuresTotal ?? 0) : '—'],
            ['Publisher transport failures', active ? String(s.publisherTransportFailuresTotal ?? 0) : '—'],
            ['Receiver resynchronizations', active ? String(s.publisherResynchronizationsTotal ?? 0) : '—'],
            ['Last outbound acknowledgement age', !active || s.publisherLastAcknowledgedAgeSeconds == null ? 'No acknowledged message' : `${String(s.publisherLastAcknowledgedAgeSeconds)} seconds (monotonic)`],
            ['Publisher backlog', active ? `0 queued; ${String(s.publisherInFlightRequests ?? 0)} in flight` : '—'],
            ['Current-minute remote snapshot', s.remoteReportedInCurrentMinute ? 'Available' : 'Missing / expired']];
        $('content').innerHTML = `<div class="toolbar"><div><h2>Peer synchronization</h2><p class="subtle">Authenticated counter exchange for this gateway. This is not a shared rate-limit authority.</p></div>${actionBtn('Refresh', 'switch', 'peers')}</div>
        <div class="card peer-status-card"><div><p class="subtle">PEER STATE</p><h2><span class="chip ${current ? 'good' : 'warn'}">${esc(state)}</span></h2><p class="subtle">${active ? 'Last accepted exchange and observed peer counters.' : 'No peer transport is configured; this is the safe default.'}</p></div><div><p class="subtle">Strict request admission</p><h3>${esc(s.strictAdmission || 'Not reported')}</h3><p class="subtle">Peer telemetry never authorizes requests during a network partition.</p></div></div>
        ${active ? `<div class="stats peer-stat-grid">
            <div class="card"><h3>Local identities</h3><div class="stat-number">${esc(s.localIdentities)}</div><div class="stat-desc">${esc(s.localRequests)} local request attempts</div></div>
            <div class="card"><h3>Remote identities</h3><div class="stat-number">${esc(s.remoteIdentities)}</div><div class="stat-desc">${esc(s.remoteRequests)} remote request attempts</div></div>
            <div class="card"><h3>Remote sequence</h3><div class="stat-number">${esc(s.remoteSequence)}</div><div class="stat-desc">Current minute</div></div>
            <div class="card"><h3>Identity limit</h3><div class="stat-number">${esc(s.trackedIdentityLimit)}</div><div class="stat-desc">Bounded per-node tracking</div></div>
        </div><div class="card card-spaced"><h2>Exchange diagnostics</h2>
        ${rows.map(([key, val]) => `<div class="rowline"><b>${esc(key)}</b><span>${esc(val ?? '—')}</span></div>`).join('')}</div>`
        : '<div class="card card-spaced"><h2>Optional feature disabled</h2><p class="subtle">Configure reciprocally trusted HTTPS endpoints and secret storage before enabling peer telemetry.</p></div>'}
        <div class="healthbanner">Best-effort status only. No proof of distributed consensus, session or stick-table parity, physical VIP failover, or global admission consistency.</div>`;
    } catch (e) {
        if (view === 'peers') {
            $('content').innerHTML = '<div class="card"><h2>Status unavailable</h2><p class="subtle">No peer status is being claimed.</p></div>';
            show('Peer status unavailable: ' + String(e), true);
        }
    }
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
   if(view!=='setup')return;
   const x=setupState;
   const nextTask=!orgProfile?.organizationName?'Set your organization':topologyResponse?.status!=='design-confirmed'?'Confirm gateway architecture':dirty?'Review and submit your draft':x.routeCount===0?'Add your first website':'Check health or manage websites';
   const nextButton=!orgProfile?.organizationName?actionBtn('Configure organization','setup-open','organization','primary'):topologyResponse?.status!=='design-confirmed'?actionBtn('Choose gateway architecture','setup-open','onboarding','primary'):dirty?actionBtn('Review draft','setup-open','routes','primary'):x.routeCount===0&&currentRole!=='Viewer'?actionBtn('Add website / API','setup-next-website','','primary'):actionBtn('Check backend servers','setup-open','backends','primary');
   const configured=x.stages.filter(s=>['configured','design-confirmed'].includes(s.status)).length;
   $('content').innerHTML=`<div class="setup-hero card"><div><div class="setup-eyebrow">FIRST-RUN BOOTSTRAP & OPERATIONS</div><h2>Set up your YARP gateway</h2><p>Follow the four everyday tasks. Advanced checks are available when needed.</p><span class="chip">Version ${esc(x.version)} · ${esc(x.channel)}</span><span class="chip">${esc(x.gateway)}</span></div><div class="setup-score"><strong>${configured}/${x.stages.length}</strong><span>Configured setup controls, not a production-readiness score</span></div></div>
   <div class="setup-alert">${x.freeze.frozen?`<b>Routing change freeze is ON.</b> ${esc(x.freeze.reason)}`:`<b>Routing changes are allowed with approval.</b> A local emergency freeze can stop route/change operations.`} ${currentRole==='Administrator'?`<button class="ghost mini" data-action="setup-toggle-freeze" data-id="${x.freeze.frozen?'off':'on'}">${x.freeze.frozen?'Unfreeze':'Freeze routing changes'}</button>`:''}</div>
   <div class="card operator-intro"><h2>Start with a website</h2><p><b>Next: ${esc(nextTask)}</b></p><div class="operator-next">${nextButton}</div><p>Follow the steps in order. Creating a draft never changes live traffic.</p><div class="operator-flow"><span>Client</span><span aria-hidden="true">→</span><span>GatewayCore</span><span aria-hidden="true">→</span><span>Backend servers</span></div></div><div class="operator-steps"><section class="card"><span class="operator-number">1</span><h3>Gateway setup</h3><p>Set your organization and choose one gateway or a multi-gateway design.</p><button class="ghost" data-action="setup-open" data-id="organization">Organization</button> <button class="ghost" data-action="setup-open" data-id="onboarding">Gateway architecture</button></section><section class="card"><span class="operator-number">2</span><h3>Add a website or API</h3><p>Enter a hostname and backend URL. For a local test use an existing IIS, Apache or Nginx site.</p><button class="primary" data-action="setup-simple-website">+ Add website / API</button> <button class="ghost" data-action="setup-local-web">Local website test</button></section><section class="card"><span class="operator-number">3</span><h3>Review and approve</h3><p>Check your draft, submit it, then ask a different administrator to approve.</p><button class="ghost" data-action="setup-open" data-id="routes">Review websites &amp; routes</button> <button class="ghost" data-action="setup-open" data-id="approvals">Change requests</button></section><section class="card"><span class="operator-number">4</span><h3>Verify live traffic</h3><p>After approval, inspect health and test real requests. Unknown is not healthy.</p><button class="ghost" data-action="setup-live-health">Check backend health</button> <button class="ghost" data-action="setup-open" data-id="metrics">Traffic metrics</button></section></div><div class="operator-help"><button class="ghost" data-action="setup-open" data-id="guide">Read the step-by-step user guide →</button></div><details class="card operator-advanced"><summary>Advanced setup &amp; deployment evidence</summary><div class="setup-summary"><div class="card"><b>${x.routeCount}</b><span>Routes</span></div><div class="card"><b>${x.clusterCount}</b><span>Clusters</span></div><div class="card"><b>${x.destinationCount}</b><span>Enabled backend entries</span></div><div class="card"><b>${x.fleetEntries}</b><span>Gateway agent records</span></div></div>
   <div class="toolbar"><div><h2>Bootstrap checklist</h2><p class="subtle">“Configured” is not the same as operationally tested or production certified.</p></div><div><button class="ghost" data-action="setup-add-esign-pools">Advanced public / private pools (eSign preset)</button> <button class="ghost" data-action="setup-add-application">Advanced public HTTPS application</button> <button class="ghost" data-action="setup-refresh">Refresh evidence</button></div></div>
   <div class="setup-stage-grid">${x.stages.map((s:SetupStage,i:number)=>`<div class="card setup-stage"><div class="setup-stage-head"><span class="setup-number">${String(i+1).padStart(2,'0')}</span><span class="chip ${readyClass(s.status)}">${esc(s.status.replace(/-/g,' '))}</span></div><h3>${esc(s.title)}</h3><p>${esc(s.evidence)}</p><button class="ghost mini" data-action="setup-open" data-id="${esc(s.action)}">${esc(setupActionText(s))} →</button></div>`).join('')}</div>
   </details><div class="grid2"><div class="card"><h3>Live YARP health states</h3><p class="subtle">Queries YARP's internal active/passive destination states. Unknown means the policy has not classified the backend.</p><p>Use Check backend health in step 4 to refresh this result.</p><div id="setup-live-output" class="setup-live-output">No runtime query made yet.</div></div><div class="card"><h3>Production safety gates</h3><p class="subtle">The following are not magically provisioned by this setup page:</p><ul class="setup-bullets"><li>Remote gateway agents, mTLS and network admission</li><li>AD/SMTP delivery and phishing-resistant SSO</li><li>Independent immutable audit retention</li><li>OCSP/CRL and CA issuance failover acceptance</li></ul><p class="subtle">The console deliberately refuses to call this instance production certified.</p></div></div>`;
 } catch(e) { if(view==='setup')$('content').innerHTML=`<div class="card"><h2>Setup unavailable</h2><p>${esc(String(e))}</p></div>`; }
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
function renderGatewayReadiness(){
 const pill=$('gateway-pill');pill.textContent=gatewayReadyLabel;pill.className=gatewayReadyWarn?'pill warn':'pill';
 if(view==='overview')$('content').innerHTML=overview();
}
async function refreshGatewayReadiness(){
 if($('app-shell').hidden)return;
 readinessAbort?.abort();
 const controller=new AbortController();readinessAbort=controller;
 const generation=++readinessGeneration;
 gatewayReadyLabel='● Checking backend readiness';gatewayReadyWarn=true;renderGatewayReadiness();
 let timer:ReturnType<typeof setTimeout>|undefined;
 try{
  const result=await Promise.race([
   api('/admin/api/gateway-readiness','GET',undefined,controller.signal),
   new Promise<never>((_,reject)=>{
    timer=setTimeout(()=>{controller.abort();reject(new Error('Readiness request timed out'))},5000);
   })
  ]);
  if(generation!==readinessGeneration||$('app-shell').hidden)return;
  if(typeof result?.ready!=='boolean')throw new Error('Invalid readiness response');
  gatewayReadyLabel=result.ready?'● Backend readiness observed':'● No healthy backend reported';
  gatewayReadyWarn=!result.ready;
 }catch{
  if(generation!==readinessGeneration||$('app-shell').hidden)return;
  gatewayReadyLabel='● Readiness unavailable';gatewayReadyWarn=true;
 }finally{
  if(timer!==undefined)clearTimeout(timer);
  if(generation===readinessGeneration)readinessAbort=null;
 }
 renderGatewayReadiness();
}
function updateTopologyNavigation(){const finished=topologyResponse?.status==='design-confirmed';const prereqViews=['organization','setup','onboarding','users','mail','directory','guide'];document.querySelectorAll<HTMLButtonElement>('.nav').forEach(b=>{const dest=b.dataset.view||'';const adminOnly=['users','mail','directory'].includes(dest);b.hidden=(!finished&&!prereqViews.includes(dest))||(dest==='fleet'&&finished&&topologyResponse?.plan?.mode==='standalone')||(adminOnly&&currentRole!=='Administrator')});$('save').hidden=!finished||currentRole==='Viewer'||!dirty||view==='onboarding'}

function render(){
 if(view!==lastRenderedView){if(!restoringNavigation){viewHistory.push(lastRenderedView);if(viewHistory.length>24)viewHistory.shift()}lastRenderedView=view}
 restoringNavigation=false;
 $('page-back').hidden=view==='setup'&&viewHistory.length===0;
 const names:Obj={guide:'User guide',organization:'Organization profile',setup:'Setup Center · 0.1',onboarding:'Architecture & setup',overview:'Overview',routes:'Routing rules',clusters:'Backend clusters',backends:'Backend management',health:'Health and diagnostics',backups:'Backups and audit',inventory:'Infrastructure inventory',users:'Administrators and roles',mail:'Mail & OTP',directory:'Active Directory (LDAPS)',approvals:'Change approvals',metrics:'Gateway metrics',fleet:'Gateway fleet',capabilities:'YARP capabilities',featurematrix:'Traffic Engine & platform modules',peers:'Peer synchronization'};$('page-title').textContent=names[view];$('page-subtitle').textContent=dirty?'Unsaved configuration changes — submit for approval':'Control and inspect your gateway';$('gateway-pill').textContent=gatewayReadyLabel;$('gateway-pill').className=gatewayReadyWarn?'pill warn':'pill';$('save').textContent=dirty?'Submit for approval':'Submit for approval';document.querySelectorAll<HTMLButtonElement>('.nav').forEach(n=>{const selected=n.dataset.view===view;n.classList.toggle('active',selected);if(selected)n.setAttribute('aria-current','page');else n.removeAttribute('aria-current')});const pages:Obj={overview,routes,clusters,backends,health,capabilities,guide};updateTopologyNavigation();if(view==='organization')void organizationPage();else if(view==='featurematrix')void featureMatrix();else if(view==='setup')void setupPage();else if(view==='onboarding')$('content').innerHTML=topologyPage();else if(view==='approvals')void approvals();else if(view==='metrics')void metrics();
    else if (view === 'peers') void peerSyncPage();else if(view==='backups')void backups();else if(view==='inventory')void inventory();else if(view==='fleet')void fleet();else if(view==='users')void users();else if(view==='mail')void mailPage();else if(view==='directory')void directoryPage();else $('content').innerHTML=pages[view]();}
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
function addSimpleWebsite() {
    if (currentRole === 'Viewer')
        return show('Viewer accounts cannot submit configuration changes', true);
    if (topologyResponse?.status !== 'design-confirmed')
        return show('Complete Gateway architecture and confirm the design first (step 1).', true);
    modal('Add website / API', 'One HTTPS backend, or two for round-robin balancing. Use a real client hostname and trusted HTTPS root URLs. A different administrator must approve the draft.', [
        { name: 'id', label: 'Website name (letters, digits, - or _)', value: '' },
        { name: 'hostname', label: 'Client hostname (example: app.example.com)', value: '' },
        { name: 'backend1', label: 'Backend HTTPS URL (example: https://app01.example.com/)', value: '' },
        { name: 'backend2', label: 'Second backend HTTPS URL (optional)', value: '', optional: true }
    ], v => {
        const id = String(v.id).trim(), host = String(v.hostname).trim().toLowerCase();
        if (!validId(id) || id.length > 64)
            throw Error('Enter a valid website name (up to 64 characters)');
        if (!/^[a-z0-9][a-z0-9.-]+\.[a-z]{2,}$/.test(host) || host.includes('..'))
            throw Error('Enter a valid client hostname');
        function backend(raw: string) {
            const u = new URL(raw.trim());
            if (u.protocol !== 'https:' || u.username || u.password || u.search || u.hash || u.pathname !== '/')
                throw Error('Backend must be a trusted HTTPS root URL ending in /');
            return u.href;
        }
        const first = backend(v.backend1), second = v.backend2.trim() ? backend(v.backend2) : '';
        if (first === second)
            throw Error('The second backend must be different');
        const clusterId = id + '-cluster', routeId = id + '-route';
        if (data.clusters[clusterId] || data.routes[routeId])
            throw Error('Website already exists');
        if (keys(data.routes).some(key => (data.routes[key].Match?.Hosts || []).some((h: any) => String(h).toLowerCase() === host)))
            throw Error('This hostname already has a route; edit it in Websites & routes');
        const destinations: Obj = { 'app-01': { Address: first } };
        if (second)
            destinations['app-02'] = { Address: second };
        data.clusters[clusterId] = { LoadBalancingPolicy: 'RoundRobin', Destinations: destinations, HealthCheck: { Active: { Enabled: false, Interval: '00:00:15', Timeout: '00:00:05', Policy: 'ConsecutiveFailures', Path: '/health/ready' } } };
        data.routes[routeId] = { ClusterId: clusterId, Match: { Hosts: [host], Path: '/{**catch-all}' } };
        view = 'routes';
        edit();
        show('Website added to draft. Review the route and servers, then Submit for approval. No live traffic changed.');
    }, 'Add to draft');
}
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

// Creates independent application route/cluster pools as an approval-required draft.
// Host matching is not a network isolation boundary; private access still depends
// on restricted listeners and firewall policy outside this route editor.
function addApplicationPoolsWizard(){
 if(currentRole==='Viewer')return show('Viewer accounts cannot submit configuration changes',true);
 if(topologyResponse?.status!=='design-confirmed')return show('Confirm the architecture design first',true);
 modal('Application public and private API pools','Creates independent route/cluster pools, each with two HTTPS application servers. eSign is the preset; choose a category and only the exposure pools it may safely use. Passive-only uses bounded transport-failure ejection after two consecutive failures, keeps at least one backend eligible, ignores HTTP 5xx/client cancellations, and never retries a request; some requests may fail before ejection. Private host matching does not isolate network access; bind a restricted listener and firewall policy before sending sensitive traffic.',[
  {name:'id',label:'Application ID (letters, digits, - or _)',value:'esign',kind:'text'},
  {name:'service',label:'Application category',value:'eSign',options:['eSign','SSCA Admin','RA','OCSP','TCA','eSign CA','Public API','Private API']},
  {name:'scope',label:'Pools to create',value:'public-and-private',options:['public-and-private','public-only','private-only']},
  {name:'mode',label:'Traffic mode',value:'active-active',options:['active-active','weighted-active-active','primary-backup']},
  {name:'health',label:'Health validation',value:'active',options:['active','passive-only']},
  {name:'publicHost',label:'Public API hostname (if selected)',value:'esign.example.com',optional:true},
  {name:'publicPath',label:'Public API route path (if selected)',value:'/esign/{**catch-all}',optional:true},
  {name:'publicApp1',label:'Public application server 1 HTTPS URL (if selected)',value:'https://esign-public-01.internal.example.com:5001/',optional:true},
  {name:'publicApp2',label:'Public application server 2 HTTPS URL (if selected)',value:'https://esign-public-02.internal.example.com:5001/',optional:true},
  {name:'publicWeight1',label:'Public server 1 weight (weighted mode, 1–100)',value:'50',kind:'number'},
  {name:'publicWeight2',label:'Public server 2 weight (weighted mode, 1–100)',value:'50',kind:'number'},
  {name:'privateHost',label:'Private API hostname (if selected)',value:'esign-api.internal.example.com',optional:true},
  {name:'privatePath',label:'Private API route path (if selected)',value:'/esign-api/{**catch-all}',optional:true},
  {name:'privateApp1',label:'Private application server 1 HTTPS URL (if selected)',value:'https://esign-private-01.internal.example.com:5001/',optional:true},
  {name:'privateApp2',label:'Private application server 2 HTTPS URL (if selected)',value:'https://esign-private-02.internal.example.com:5001/',optional:true},
  {name:'privateWeight1',label:'Private server 1 weight (weighted mode, 1–100)',value:'50',kind:'number'},
  {name:'privateWeight2',label:'Private server 2 weight (weighted mode, 1–100)',value:'50',kind:'number'},
  {name:'ready',label:'Readiness path on all four servers',value:'/health/ready'}
 ],v=>{
  const id=String(v.id).trim();
  if(!/^[A-Za-z0-9_-]{1,48}$/.test(id))throw Error('Application ID must be 1–48 letters, digits, hyphens or underscores');
  const restricted=['SSCA Admin','RA','TCA','eSign CA'].includes(v.service);
  const scopeForService:Record<string,string>={'eSign':'public-and-private','SSCA Admin':'private-only','RA':'private-only','OCSP':'public-only','TCA':'private-only','eSign CA':'private-only','Public API':'public-only','Private API':'private-only'};
  if(!scopeForService[v.service])throw Error('Select a supported application category');
  if(v.scope!==scopeForService[v.service]&&(restricted||v.service==='OCSP'||v.service==='Public API'||v.service==='Private API'))throw Error(`${v.service} must use the ${scopeForService[v.service]} pool scope to preserve its configured exposure boundary`);
  if(!['public-and-private','public-only','private-only'].includes(v.scope))throw Error('Select a supported pool scope');
  const includePublic=v.scope!=='private-only',includePrivate=v.scope!=='public-only';
  if(!['active-active','weighted-active-active','primary-backup'].includes(v.mode))throw Error('Select a supported traffic mode');
  if(!['active','passive-only'].includes(v.health))throw Error('Select active health checks or passive-only fallback');
  if(v.mode==='primary-backup'&&v.health!=='active')throw Error('Primary/DR standby requires active readiness checks; passive-only cannot safely promote the standby');
  function validHost(raw:string){const host=String(raw).trim().toLowerCase();return /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/.test(host)&&!host.includes('..')}
  const publicHost=String(v.publicHost).trim().toLowerCase(),privateHost=String(v.privateHost).trim().toLowerCase();
  if(includePublic&&!validHost(publicHost))throw Error('Provide a valid public API hostname');
  if(includePrivate&&!validHost(privateHost))throw Error('Provide a valid private API hostname');
  if(includePublic&&includePrivate&&publicHost===privateHost)throw Error('Public and private API hostnames must be different');
  function validPath(raw:string){const path=String(raw).trim();return path.startsWith('/')&&!path.startsWith('/admin')&&!path.startsWith('/dashboard')&&!path.startsWith('/gateway')&&!path.includes('\\')&&path.length<=300}
  if(includePublic&&!validPath(v.publicPath)||includePrivate&&!validPath(v.privatePath))throw Error('API paths must be valid non-management paths starting with /');
  if(!String(v.ready).trim().startsWith('/')||String(v.ready).includes('\\'))throw Error('Readiness path must start with /');
  function backend(raw:string){const u=new URL(String(raw).trim());if(u.protocol!=='https:'||u.username||u.password||u.search||u.hash||u.pathname!=='/')throw Error('All eSign application servers must use trusted HTTPS origins ending in /');return u.href}
  const public1=includePublic?backend(v.publicApp1):'',public2=includePublic?backend(v.publicApp2):'',private1=includePrivate?backend(v.privateApp1):'',private2=includePrivate?backend(v.privateApp2):'';
  if(includePublic&&public1===public2||includePrivate&&private1===private2)throw Error('Each API pool needs two distinct application servers');
  function weight(raw:string){const value=String(raw).trim();if(!/^(?:[1-9]|[1-9][0-9]|100)$/.test(value))throw Error('Server weights must be integers from 1 to 100');return value}
  const publicWeights=includePublic?[weight(v.publicWeight1),weight(v.publicWeight2)]:[],privateWeights=includePrivate?[weight(v.privateWeight1),weight(v.privateWeight2)]:[];
  const routeIds=[...(includePublic?[id+'-public-route']:[]),...(includePrivate?[id+'-private-route']:[])];const clusterIds=[...(includePublic?[id+'-public-pool']:[]),...(includePrivate?[id+'-private-pool']:[])];
  if(routeIds.some(key=>data.routes[key])||clusterIds.some(key=>data.clusters[key]))throw Error('An application route or pool with this ID already exists');
  const policy=v.mode==='primary-backup'?'PrimaryBackup':v.mode==='weighted-active-active'?'WeightedRandom':'RoundRobin';
  const healthy=v.health==='active';
  function makePool(first:string,second:string,weights:string[],exposure:string){
   const metadata=(weightValue:string,role:string)=>({Weight:weightValue,TrafficRole:role,TrafficState:'active'});
   return {LoadBalancingPolicy:policy,Destinations:{'app-01':{Address:first,Metadata:metadata(v.mode==='primary-backup'?'100':weights[0],'primary')},'app-02':{Address:second,Metadata:metadata(v.mode==='primary-backup'?'100':weights[1],v.mode==='primary-backup'?'backup':'primary')}},HealthCheck:{AvailableDestinationsPolicy:'HealthyAndUnknown',Active:{Enabled:healthy,Interval:'00:00:15',Timeout:'00:00:05',Policy:'ConsecutiveFailures',Path:String(v.ready).trim()},Passive:{Enabled:!healthy,Policy:'BoundedTransportFailure',ReactivationPeriod:'00:00:15'}},Metadata:{'YARP.ApplicationCategory':String(v.service),'GatewayCore.ExposurePool':exposure,'BoundedTransportFailure.MaxEjectedPercent':'50','BoundedTransportFailure.MinHealthyRemaining':'1','BoundedTransportFailure.ConsecutiveFailures':'2'}};
  }
  if(includePublic){data.clusters[id+'-public-pool']=makePool(public1,public2,publicWeights,'public');data.routes[id+'-public-route']={ClusterId:id+'-public-pool',Match:{Hosts:[publicHost],Path:String(v.publicPath).trim()}}}
  if(includePrivate){data.clusters[id+'-private-pool']=makePool(private1,private2,privateWeights,'private');data.routes[id+'-private-route']={ClusterId:id+'-private-pool',Match:{Hosts:[privateHost],Path:String(v.privatePath).trim()}}}
  edit();
  const policyName=policy==='PrimaryBackup'?'primary plus DR standby':policy==='WeightedRandom'?'weighted active-active':'equal-share active-active';
  const poolNames=includePublic&&includePrivate?'public and private':includePublic?'public':'private';
  show(`Added ${poolNames} ${v.service} route and backend pool(s) (${policyName}). ${healthy?'Active readiness checks are configured.':'Passive-only uses bounded transport-failure ejection after two consecutive failures; it reserves one backend, ignores HTTP 5xx and client cancellations, and never retries requests. Some requests can fail before ejection.'} Private host matching does not enforce network isolation. Submit for independent approval; no route is live yet.`);
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
function updateCluster(id=''){const old=data.clusters[id]||{Destinations:{},LoadBalancingPolicy:'RoundRobin',HealthCheck:{Active:{Enabled:false,Interval:'00:00:15',Timeout:'00:00:05',Path:'/health/ready',Policy:'ConsecutiveFailures'}}};modal(id?'Edit cluster':'Add cluster','Health checks need a real backend readiness endpoint. PrimaryBackup requires active checks and never retries non-idempotent requests.',[{name:'id',label:'Cluster ID',value:id},{name:'policy',label:'Load balancing',value:old.LoadBalancingPolicy||'RoundRobin',options:['RoundRobin','PowerOfTwoChoices','LeastRequests','Random','FirstAlphabetical','WeightedRandom','SourceIpHash','PrimaryBackup']},{name:'health',label:'Active health checks',value:String(!!old.HealthCheck?.Active?.Enabled),options:['false','true']},{name:'path',label:'Health path',value:old.HealthCheck?.Active?.Path||'/health/ready'}],v=>{if(!validId(v.id)||!v.path.startsWith('/'))throw Error('Invalid cluster ID or path');if(v.id!==id&&data.clusters[v.id])throw Error('Cluster exists');if(v.policy==='PrimaryBackup'&&v.health!=='true')throw Error('PrimaryBackup requires active health checks');const c={...old,LoadBalancingPolicy:v.policy,HealthCheck:{...old.HealthCheck,Active:{...(old.HealthCheck?.Active||{}),Enabled:v.health==='true',Path:v.path}}};if(id&&id!==v.id){delete data.clusters[id];for(const rid of keys(data.routes)){if(data.routes[rid].ClusterId===id)data.routes[rid].ClusterId=v.id}}data.clusters[v.id]=c;edit()})}
function updateDest(id=''){
 const [cid,did]=id?id.split('::'):['',''];
 const old=cid?(data.clusters[cid]?.Destinations?.[did]??data.disabled[id]):null;
 const meta=old?.Metadata||{};
 modal(did?'Edit backend':'Add backend','Admission limits are optional and apply to requests selected for this destination. The slot is held until the full response or stream ends.',[
  {name:'cluster',label:'Cluster',value:cid||keys(data.clusters)[0]||'',options:keys(data.clusters)},
  {name:'id',label:'Destination ID',value:did},
  {name:'address',label:'Backend URL',value:old?.Address||'https://api01.internal.example.com:5001/'},
  {name:'weight',label:'Traffic weight (1–100)',value:String(meta.Weight??'1')},
  {name:'role',label:'Traffic role (PrimaryBackup policy only)',value:meta.TrafficRole||'primary',options:['primary','backup']},
  {name:'admissionMax',label:'Maximum requests in flight (optional)',value:String(meta['GatewayCore.Admission.MaxInFlight']??''),kind:'number',optional:true},
  {name:'admissionPending',label:'Maximum queued requests (0–4096; default 0)',value:String(meta['GatewayCore.Admission.MaxPending']??''),kind:'number',optional:true},
  {name:'admissionTimeout',label:'Queue wait timeout in milliseconds (1–60000; default 5000)',value:String(meta['GatewayCore.Admission.QueueTimeoutMs']??''),kind:'number',optional:true}
 ],v=>{
  if(!validId(v.id)||!data.clusters[v.cluster]||!/^https?:\/\/[^\s]+\/$/.test(v.address))throw Error('Invalid ID, cluster or URL; URL must end in /');
  if(!/^(?:[1-9]|[1-9][0-9]|100)$/.test(v.weight))throw Error('Weight must be an integer from 1 to 100');
  if(!['primary','backup'].includes(v.role))throw Error('Traffic role must be primary or backup');
  const max=v.admissionMax.trim(),pending=v.admissionPending.trim(),timeout=v.admissionTimeout.trim();
  if(max&&(!/^[1-9][0-9]*$/.test(max)||Number(max)>50000))throw Error('Maximum in-flight must be an integer from 1 to 50000');
  if((pending!==''||timeout!=='')&&!max)throw Error('Set a maximum in-flight value to enable destination admission');
  if(max&&pending&&(!/^(0|[1-9][0-9]*)$/.test(pending)||Number(pending)>4096))throw Error('Maximum queued requests must be an integer from 0 to 4096');
  if(max&&timeout&&(!/^[1-9][0-9]*$/.test(timeout)||Number(timeout)>60000))throw Error('Queue timeout must be an integer from 1 to 60000 milliseconds');
  const newKey=v.cluster+'::'+v.id,isDisabled=!!data.disabled[id];
  if(id){delete data.clusters[cid].Destinations[did];delete data.disabled[id]}
  const metadata={...(old?.Metadata||{}),Weight:String(v.weight),TrafficRole:v.role};
  delete metadata['GatewayCore.Admission.MaxInFlight'];delete metadata['GatewayCore.Admission.MaxPending'];delete metadata['GatewayCore.Admission.QueueTimeoutMs'];
  if(max){metadata['GatewayCore.Admission.MaxInFlight']=max;metadata['GatewayCore.Admission.MaxPending']=pending||'0';metadata['GatewayCore.Admission.QueueTimeoutMs']=timeout||'5000'}
  const configured={...old,Address:v.address,Metadata:metadata};
  if(isDisabled)data.disabled[newKey]=configured;else data.clusters[v.cluster].Destinations[v.id]=configured;
  edit()
 })
}
function act(type:string,id:string){
 if(type==='runtime-health'){void refreshDestinationRuntime();return}
 if(type==='dest-drain'){const [c,d]=id.split('::');const destination=data.clusters[c]?.Destinations?.[d];if(!destination)return show('Only enabled destinations can be drained',true);destination.Metadata={...(destination.Metadata||{}),TrafficState:String(destination.Metadata?.TrafficState||'active').toLowerCase()==='draining'?'active':'draining'};edit();show('Traffic state changed in the unsaved draft. New requests stop after independent approval and rollout; this does not terminate in-flight work.');return}
 if(type==='org-edit'){editOrganization();return}
 if(type==='setup-simple-website'||type==='setup-next-website'){addSimpleWebsite();return}
 if(type==='setup-add-application'){addApplicationWizard();return}
 if(type==='setup-add-esign-pools'){addApplicationPoolsWizard();return}
  if(type==='setup-local-web'){addLocalWebWizard();return}
 if(type==='setup-refresh'){void setupPage();return}
 if(type==='setup-live-health'){void setupLiveHealth();return}
 if(type==='setup-toggle-freeze'){void setupFreeze(id==='on');return}
 if(type==='setup-open'){
  if(topologyResponse?.status!=='design-confirmed'&&!['organization','setup','onboarding','users','mail','directory','guide'].includes(id))
   return show('Complete Gateway architecture first (step 1).',true);
  if(['users','mail','directory'].includes(id)&&currentRole!=='Administrator')
   return show('Administrator role required',true);
  view=id;
  render();
  return;
 }
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
if(type==='route-advanced'||type==='cluster-advanced'||type==='dest-advanced'){advancedJson(type==='route-advanced'?'route':type==='cluster-advanced'?'cluster':'destination',id);return}if(type==='switch'){view=id;render();return}if(type==='route-add'||type==='route-edit'){if(!keys(data.clusters).length)return show('Create a cluster before adding routes',true);updateRoute(type==='route-edit'?id:'');return}if(type==='route-delete'){if(confirm('Delete route '+id+' from draft?')){delete data.routes[id];edit()}return}if(type==='cluster-add'||type==='cluster-edit'){updateCluster(type==='cluster-edit'?id:'');return}if(type==='cluster-delete'){if(keys(data.routes).some(r=>data.routes[r].ClusterId===id))return show('Remove routes referencing this cluster first',true);if(confirm('Delete cluster '+id+'?')){delete data.clusters[id];for(const k of keys(data.disabled))if(k.startsWith(id+'::'))delete data.disabled[k];edit()}return}if(type==='dest-add'||type==='dest-edit'){if(!keys(data.clusters).length)return show('Create a cluster first',true);updateDest(type==='dest-edit'?id:'');return}if(type==='dest-toggle'){const [c,d]=id.split('::');if(data.disabled[id]){data.clusters[c].Destinations[d]=data.disabled[id];delete data.disabled[id]}else{data.disabled[id]=data.clusters[c].Destinations[d];delete data.clusters[c].Destinations[d]}edit();return}if(type==='dest-delete'){const [c,d]=id.split('::');if(confirm('Delete destination '+id+'?')){if(data.clusters[c])delete data.clusters[c].Destinations[d];delete data.disabled[id];edit()}return}if(type==='probe'){show('Running on-demand probes...');api('/admin/api/probe','POST',{}).then(r=>{probes=r.results;render();show('Probe completed. This is not the internal YARP health state.')}).catch(e=>show(String(e),true));return}if(type==='fleet-add'){addFleet();return}if(type==='fleet-remove'){if(!confirm('Remove gateway '+id+' from inventory?'))return;api('/admin/api/fleet/'+encodeURIComponent(id),'DELETE',{}).then(()=>void fleet()).catch(e=>show(String(e),true));return}if(type==='fleet-probe'){void fleetStatus();return}if(type==='fleet-journal'){void fleetJournal();return}if(type==='fleet-recover'){void recoverFleetRollout(id);return}if(type==='fleet-rollout'){void performFleetRollout();return}if(type==='dest-metrics'){void destinationMetrics();return}if(type==='inventory-add'){addInventory();return}if(type==='inventory-delete'){if(!confirm('Remove inventory item '+id+'?'))return;api('/admin/api/inventory/'+encodeURIComponent(id),'DELETE',{}).then(()=>void inventory()).catch(e=>show(String(e),true));return}if(type==='user-add'){addUser();return}if(type==='mail-settings'){view='mail';render();return}if(type==='mail-test'){void api('/admin/api/mail/test','POST',{}).then(r=>{show('SMTP accepted test message for '+r.recipient);void mailPage()}).catch(e=>show('Mail test failed: '+String(e)+'. Save a relay configuration first; verify administrator email and STARTTLS.',true));return}if(type==='directory-test'){void api('/admin/api/directory/test','POST',{}).then(()=>show('LDAPS trust, bind and group lookup verified')).catch(e=>show(String(e),true));return}if(type==='user-disable'||type==='user-enable'){if(!confirm((type==='user-disable'?'Offboard ':'Re-enable ')+id+'?'))return;api('/admin/api/users/'+encodeURIComponent(id)+'/'+(type==='user-disable'?'disable':'enable'),'POST',{}).then(()=>void users()).catch(e=>show(String(e),true));return}if(type==='password-reset'){resetPassword(id);return}if(type==='restore'){if(!confirm('Restore '+id+'? This changes live config and saves a safety backup.'))return;api('/admin/api/restore/'+encodeURIComponent(id),'POST',{}).then(()=>{show('Backup restored');void reload()}).catch(e=>show(String(e),true))}}
$('content').addEventListener('click',e=>{const el=(e.target as HTMLElement).closest<HTMLButtonElement>('[data-action]');if(el)act(el.dataset.action||'',el.dataset.id||'')});
function topologyInputUpdate(el:HTMLInputElement|HTMLSelectElement){if(!topologyDraft)return;
 const field=el.dataset.setupField;const value=(el as HTMLInputElement).type==='checkbox'?(el as HTMLInputElement).checked:el.value;
 if(field){if(field==='mode'){topologyModeChange(String(value));render();return}topologyDraft[field]=value;if(field==='dataStore')render();return}
 const arr=el.dataset.setupArray;const index=Number(el.dataset.setupIndex);const prop=el.dataset.setupProperty;
 if(arr&&prop&&Number.isInteger(index)&&topologyDraft[arr]?.[index])topologyDraft[arr][index][prop]=value;
}
$('content').addEventListener('input',e=>{const el=e.target as HTMLInputElement;if(el.matches('[data-setup-field],[data-setup-array]'))topologyInputUpdate(el)});
$('content').addEventListener('change',e=>{const el=e.target as HTMLInputElement;if(el.matches('[data-setup-field],[data-setup-array]'))topologyInputUpdate(el)});
document.querySelectorAll<HTMLButtonElement>('.nav').forEach(el=>el.onclick=()=>{const next=el.dataset.view||'overview';if(view===next)return;view=next;render()});$('page-back').onclick=()=>navigateBack();$('modal-close').onclick=()=>($('modal') as HTMLDialogElement).close();$('refresh').onclick=()=>void reload();$('save').onclick=()=>void save();$('logout').onclick=()=>{if(dirty&&!confirm('Sign out? Your unsubmitted configuration draft will be discarded.'))return;if(federatedOidcSession){const form=document.createElement('form');form.method='post';form.action='/admin/api/logout';const token=document.createElement('input');token.type='hidden';token.name='csrf';token.value=csrf;form.append(token);document.body.append(form);form.submit();return}void api('/admin/api/logout','POST',{}).then(()=>showLogin(false)).catch(e=>show(String(e),true))};
setInterval(()=>{if(!$('app-shell').hidden)void refreshGatewayReadiness()},30000);
function showPrivacy(r:Obj){
  privacyVersion=r.privacyVersion;
  $('auth-screen').hidden=true;$('app-shell').hidden=true;$('privacy-screen').hidden=false;
  $('privacy-text').textContent=r.privacyText;
  $('privacy-version').textContent='Revision: '+privacyVersion.slice(0,12);
  $('privacy-message').textContent='';
}
$('privacy-accept').onclick=async()=>{
  const button=$('privacy-accept') as HTMLButtonElement;
  if(button.disabled)return;
  button.disabled=true;
  const decline=$('privacy-decline') as HTMLButtonElement;
  const signout=$('privacy-signout') as HTMLButtonElement;
  decline.disabled=true;signout.disabled=true;
  $('privacy-message').textContent='';
  try{await api('/admin/api/privacy/accept','POST',{version:privacyVersion});await initSession()}
  catch(e){$('privacy-message').textContent=String(e)}
  finally{button.disabled=false;decline.disabled=false;signout.disabled=false}
};
$('privacy-decline').onclick=()=>{$('privacy-message').textContent='Please accept the Privacy Policy to continue using GatewayCore. You can review it again or sign out.'};
$('privacy-signout').onclick=()=>{$('logout').click()};
void initSession();

async function initSession(){
  const generation=authGeneration;
  try {
    const r=await api('/admin/api/session');
    if(!r.authenticated){
      showLogin(!r.initialized);
      if(r.setupRequired===true){
        $('auth-screen').hidden=true;
        $('first-run-screen').hidden=false;
      }
      return
    }
    csrf=r.csrf;currentRole=r.role;currentUser=r.username;federatedOidcSession=r.federatedOidc===true;
    if(r.privacyAccepted!==true){showPrivacy(r);return}
    $('privacy-screen').hidden=true;
    $('license-link').hidden=r.commercial!==true;
    if(r.commercial===true&&r.licenseActive!==true){location.assign('/dashboard/license');return}
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
  } catch(err){if(generation!==authGeneration)return;$('privacy-screen').hidden=true;$('auth-message').textContent=String(err);$('auth-screen').hidden=false;$('app-shell').hidden=true}
}
function showLogin(first:boolean){$('first-run-screen').hidden=true;$('privacy-screen').hidden=true;privacyVersion='';const dialog=$('modal') as HTMLDialogElement;if(dialog.open)dialog.close();$('modal-fields').innerHTML='';authGeneration++;readinessGeneration++;readinessAbort?.abort();readinessAbort=null;gatewayReadyLabel='● Backend readiness not checked';gatewayReadyWarn=true;csrf='';currentRole='';currentUser='';federatedOidcSession=false;otpChallenge='';view='setup';viewHistory=[];lastRenderedView='setup';
 dirty=false;data={name:'GatewayCore',gateway:'unknown',time:'',routes:{},clusters:{},disabled:{},mode:'Local testing',telemetry:'',revision:''};
 probes=[];orgProfile=null;topologyResponse=null;topologyDraft=null;topologyStep=0;topologyChecks=[];topologyWarnings=[];
 $('content').innerHTML='';$('user-badge').textContent='';$('notice').hidden=true;
 ($('auth-password') as HTMLInputElement).value='';($('auth-otp') as HTMLInputElement).value='';
 ($('auth-email') as HTMLInputElement).value='';($('auth-username') as HTMLInputElement).value='';
 ($('auth-provider') as HTMLSelectElement).value='local';($('auth-password') as HTMLInputElement).minLength=16;
 updateBrand();$('app-shell').hidden=true;$('auth-screen').hidden=false;
 $('auth-title').textContent=first?'Create initial administrator':'Sign in to GatewayCore';
 $('auth-description').textContent=first?'Create a local recovery administrator first. You can enable AD login and email OTP after signing in.':'Restricted local management access';
 $('auth-submit').textContent=first?'Create administrator':'Sign in';
 $('auth-email-row').hidden=!first;$('auth-provider-row').hidden=first;$('auth-otp-row').hidden=true;($('auth-password') as HTMLInputElement).required=true;($('auth-otp') as HTMLInputElement).required=false;otpChallenge='';
 ($('auth-form') as HTMLFormElement).dataset.mode=first?'bootstrap':'login';
 $('auth-message').textContent='';const sso=document.getElementById('auth-sso-link');if(sso)sso.hidden=true;if(!first)void fetch('/admin/api/auth-methods').then(r=>r.json()).then(m=>{if(sso)sso.hidden=!m.enterpriseOidc;const x=$('auth-provider') as HTMLSelectElement;x.querySelectorAll<HTMLOptionElement>('option[value="directory"]').forEach(o=>{o.disabled=!m.activeDirectory;o.textContent=m.activeDirectory?'Active Directory / LDAPS':'Active Directory (not configured)'});}).catch(()=>{});}
($('auth-provider') as HTMLSelectElement).onchange=()=>{($('auth-password') as HTMLInputElement).minLength=($('auth-provider') as HTMLSelectElement).value==='directory'?1:16};
($('auth-form') as HTMLFormElement).onsubmit=async e=>{
 e.preventDefault();
 const submit=$('auth-submit') as HTMLButtonElement;
 if(submit.disabled)return;
 submit.disabled=true;($('auth-form') as HTMLFormElement).setAttribute('aria-busy','true');const mode=($('auth-form') as HTMLFormElement).dataset.mode;
 const username=($('auth-username') as HTMLInputElement).value.trim();
 const password=($('auth-password') as HTMLInputElement).value;
 const email=($('auth-email') as HTMLInputElement).value.trim();
 try{const r=mode==='verify'?await api('/admin/api/login/verify','POST',{challengeId:otpChallenge,code:($('auth-otp') as HTMLInputElement).value.trim()}):await api('/admin/api/'+mode,'POST',{username,password,email,provider:($('auth-provider') as HTMLSelectElement).value});
   if(r.otpRequired){otpChallenge=r.challengeId;($('auth-form') as HTMLFormElement).dataset.mode='verify';$('auth-otp-row').hidden=false;($('auth-password') as HTMLInputElement).required=false;($('auth-otp') as HTMLInputElement).required=true;$('auth-submit').textContent='Verify email code';$('auth-description').textContent='Enter the six-digit code sent to '+r.emailHint;($('auth-password') as HTMLInputElement).value='';return;}
   if(!r.authenticated)throw Error('Authentication was not completed');
   ($('auth-password') as HTMLInputElement).value='';await initSession();
 }catch(err){$('auth-message').textContent=String(err)}
 finally{submit.disabled=false;($('auth-form') as HTMLFormElement).removeAttribute('aria-busy')}
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

function updateMailAuthFields(form:HTMLFormElement){
 const mode=form.querySelector<HTMLSelectElement>('select[name="authMode"]')?.value||'password';
 form.querySelectorAll<HTMLElement>('[data-mail-oauth]').forEach(el=>el.hidden=mode==='password');
 const refresh=form.querySelector<HTMLElement>('[data-mail-refresh]');
 if(refresh)refresh.hidden=mode==='password'||mode==='microsoft-app';
}
function applyMailProviderPreset(select:HTMLSelectElement){
 const presets:Obj={
  'zoho-in-org':['smtppro.zoho.in','password'],'zoho-in-standard':['smtp.zoho.in','password'],
  'gmail':['smtp.gmail.com','google-oauth'],'microsoft365':['smtp.office365.com','microsoft-oauth'],
  'outlook':['smtp-mail.outlook.com','microsoft-oauth'],
  'exchange':['','password'],'yahoo':['smtp.mail.yahoo.com','password'],
  'icloud':['smtp.mail.me.com','password'],'fastmail':['smtp.fastmail.com','password']
 };
 const preset=presets[select.value];
 if(!preset)return;
 const form=select.closest('form') as HTMLFormElement|null;
 const hostInput=form?.querySelector<HTMLInputElement>('input[name="host"]');
 const portInput=form?.querySelector<HTMLInputElement>('input[name="port"]');
 const tlsInput=form?.querySelector<HTMLInputElement>('input[name="startTls"]');
 const enabledInput=form?.querySelector<HTMLInputElement>('input[name="enabled"]');
 const modeInput=form?.querySelector<HTMLSelectElement>('select[name="authMode"]');
 if(!form||!hostInput||!portInput||!tlsInput||!enabledInput||!modeInput){show('Mail form could not be updated; reopen Mail & OTP.',true);return}
 if(select.value==='exchange')hostInput.value='';else if(preset[0])hostInput.value=preset[0];
 portInput.value='587';tlsInput.checked=true;enabledInput.checked=false;enabledInput.disabled=true;
 modeInput.value=preset[1];updateMailAuthFields(form);
 show('SMTP provider selected. Confirm its exact host, authentication and approved sender; save with OTP off, test real delivery, then enable OTP. No credentials were autofilled.');
}
let mailPageRender=0;
async function mailPage(){
 if(currentRole!=='Administrator')return;
 const token=++mailPageRender;
 try{
  const m=await api('/admin/api/mail');
  if(view!=='mail'||token!==mailPageRender)return;
  $('content').innerHTML=`<div class="toolbar"><div><h2>Mail relay & email OTP</h2><p class="subtle">Step 1: save relay settings with OTP off. Step 2: test delivery to the administrator email. Step 3: enable OTP only after the test passes. An optional SMTP relay is not needed for local gateway traffic.</p></div><span class="chip ${m.deliveryVerified?'good':'bad'}">${m.deliveryVerified?'SMTP test accepted':'Test required'}</span></div>
  <div class="settings-columns"><div class="card"><h3>SMTP connection</h3><form id="mail-config" class="settings-form">
   <label>SMTP provider / region<select id="smtp-preset">
    <option value="">Custom SMTP server (keep existing settings)</option>
    <option value="zoho-in-org">Zoho Mail India — organization (smtppro.zoho.in)</option>
    <option value="zoho-in-standard">Zoho Mail India — personal/free (smtp.zoho.in)</option>
    <option value="gmail">Gmail / Google Workspace — OAuth2</option>
    <option value="microsoft365">Microsoft 365 / Exchange Online — delegated OAuth2</option>
    <option value="outlook">Outlook.com / Hotmail — delegated OAuth2</option>
    <option value="exchange">Exchange Server on-premises — approved internal SMTP relay</option>
    <option value="yahoo">Yahoo Mail — application password</option>
    <option value="icloud">Apple iCloud Mail — application password</option>
    <option value="fastmail">Fastmail — application password</option>
   </select></label>
   <p class="subtle">Presets suggest server settings; they do not install mail services or grant OAuth permissions. Confirm host and mailbox authentication in your provider's console. mail.zoho.in is webmail, not SMTP. Gmail and Microsoft 365 recommend OAuth2; Exchange on-premises can use a policy-approved STARTTLS relay. Password and OAuth secrets are never autofilled.</p>
   <label>SMTP DNS host<input name="host" value="${esc(m.host||'')}" placeholder="smtp.internal.example.com" required></label>
   <label>Port<input name="port" type="number" value="${esc(m.port||587)}" min="1" max="65535" required></label>
   <label>Sender address<input name="from" type="email" value="${esc(m.from||'')}" placeholder="yarp-alerts@example.com" required></label>
   <label>SMTP login (optional)<input name="username" autocomplete="off" value="${esc(m.username||'')}"></label>
   <label>Authentication mode<select name="authMode" id="mail-auth-mode">
    <option value="password" ${(m.authMode||'password')==='password'?'selected':''}>SMTP app password / trusted relay</option>
    <option value="google-oauth" ${m.authMode==='google-oauth'?'selected':''}>Google OAuth2 (delegated refresh token)</option>
    <option value="microsoft-oauth" ${m.authMode==='microsoft-oauth'?'selected':''}>Microsoft OAuth2 (delegated refresh token)</option>
    <option value="microsoft-app" ${m.authMode==='microsoft-app'?'selected':''}>Microsoft 365 OAuth2 (app-only permissions)</option>
   </select></label>
   <label>SMTP application password (leave blank to preserve)<input name="password" autocomplete="new-password" type="password" placeholder="${m.passwordConfigured?'A credential is stored':''}"></label>
   <label data-mail-oauth>OAuth application/client ID<input name="oauthClientId" value="${esc(m.oAuthClientId||'')}" autocomplete="off" placeholder="Registered OAuth application ID"></label>
   <label data-mail-oauth>OAuth tenant ID (Microsoft only)<input name="oauthTenant" value="${esc(m.oAuthTenant||'')}" autocomplete="off" placeholder="Tenant GUID, organizations, or consumers"></label>
   <label data-mail-oauth>OAuth client secret (blank keeps stored secret for same identity)<input name="oauthClientSecret" autocomplete="new-password" type="password" placeholder="${m.oauthClientSecretConfigured?'Stored secret available':''}"></label>
   <label data-mail-oauth data-mail-refresh>OAuth refresh token (blank keeps stored token for same identity)<input name="oauthRefreshToken" autocomplete="new-password" type="password" placeholder="${m.oauthRefreshTokenConfigured?'Stored token available':''}"></label>
   <p class="subtle">OAuth application registration and consent must be completed externally. Google uses Gmail delegated SMTP permission. Microsoft delegated mode requires SMTP.Send consent; app-only mode requires Exchange Online service principal/mailbox authorization. Tokens and secrets are encrypted at rest, never displayed here.</p>
   <label class="setting-check"><input name="startTls" type="checkbox" ${m.startTls?'checked':''}> Require STARTTLS (recommended: 587)</label>
   <label class="setting-check"><input name="enabled" type="checkbox" ${m.enabled?'checked':''} ${!m.deliveryVerified?'disabled':''}> Require email OTP at sign-in</label>${!m.deliveryVerified?'<p class="subtle">OTP remains unavailable until the saved SMTP settings pass the delivery test. Save with OTP off, test, then return here.</p>':''}
   <div class="action-strip"><button type="submit" class="primary">Save SMTP settings</button><button type="button" class="ghost" data-action="mail-test" data-id="">Send test to my account</button></div>
  </form></div><div class="card"><h3>Secure setup sequence</h3><p class="subtle">1. Save the mail server with OTP disabled.</p><p class="subtle">2. Send a test to your registered administrator email.</p><p class="subtle">3. Confirm the email arrived.</p><p class="subtle">4. Enable OTP and save again. Next login will require a code.</p><div class="healthbanner">Authenticated mail requires STARTTLS and a trusted SMTP certificate. This version supports authenticated STARTTLS (usually port 587); implicit TLS on 465 is intentionally disabled in this version. Email OTP is not phishing-resistant MFA.</div></div></div>`;
  const preset=$('smtp-preset') as HTMLSelectElement;
  // Bind to the rendered select, not a stale delegated event target.
  const form=$('mail-config') as HTMLFormElement;
  const mode=$('mail-auth-mode') as HTMLSelectElement;
  preset.onchange=()=>applyMailProviderPreset(preset);
  mode.onchange=()=>{const enabled=form.querySelector<HTMLInputElement>('input[name="enabled"]');if(enabled){enabled.checked=false;enabled.disabled=true}updateMailAuthFields(form)};
  updateMailAuthFields(form);
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

async function fleet(){try{const rows:Obj[]=await api('/admin/api/fleet');$('content').innerHTML=`<div class="toolbar"><div><h2>Managed YARP gateway fleet</h2><p class="subtle">Read-only mTLS gateway status. A registered gateway is not automatically enrolled or remotely controlled.</p></div>${currentRole==='Administrator'?actionBtn('+ Register gateway','fleet-add',''):''} ${actionBtn('Check agent status','fleet-probe','')} ${currentRole==='Administrator'?actionBtn('Roll out approved change','fleet-rollout',''):''} ${actionBtn('Destination metrics','dest-metrics','')} ${actionBtn('Rollout journal','fleet-journal','')}</div><div class="tablewrap"><table><thead><tr><th>Gateway</th><th>HTTPS agent origin</th><th>Identity</th><th>Actions</th></tr></thead><tbody>${rows.map(x=>`<tr><td>${esc(x.id)}</td><td class="mono">${esc(x.url)}</td><td>${esc(x.clientCertificateThumbprint)}</td><td>${currentRole==='Administrator'?actionBtn('Unregister','fleet-remove',x.id):'—'}</td></tr>`).join('')||'<tr><td colspan="4">No gateways registered</td></tr>'}</tbody></table></div><div class="healthbanner">mTLS gateway agents require independent certificate provisioning. Reviewed configuration rollout requires compatible agent rollback fencing; service installation remains manual.</div>`}catch(e){show(String(e),true)}}
function addFleet(){modal('Register trusted gateway','Only HTTPS gateway origins, with an installed client certificate on the controller. Registration does not establish trust or enable remote actions.',[{name:'id',label:'Gateway ID',value:''},{name:'url',label:'Agent origin e.g. https://gw01.internal:8443/',value:''},{name:'clientCertificateThumbprint',label:'Client certificate thumbprint in LocalMachine\My',value:''}],async v=>{try{await api('/admin/api/fleet','POST',v);show('Gateway registered');await fleet()}catch(e){show(String(e),true)}})}
async function fleetStatus(){
  try {
    show('Connecting to registered mTLS agents...');
    const r = await api('/admin/api/fleet/status');
    const count = (value: unknown) => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? String(value) : '—';
    const runtimePanel = (gateway: Obj) => {
      const runtime = gateway.gslbRuntime as Obj | undefined;
      if (gateway.gslbRuntimeState !== 'available' || !runtime) {
        const message = gateway.gslbRuntimeState === 'disabled'
          ? 'Local GSLB metrics scrape is disabled on this agent.'
          : gateway.gslbRuntimeState === 'unavailable'
            ? 'Local GSLB metrics could not be read from this agent.'
            : gateway.gslbRuntimeState === 'invalid-response'
              ? 'The agent returned an invalid GSLB metrics summary.'
              : 'GSLB runtime metrics are not configured for this gateway.';
        return `<p class="subtle">${esc(message)}</p>`;
      }
      const quorum = runtime.quorumTargets as Obj | undefined;
      const evidence = runtime.observerReports as Obj | undefined;
      const observers = Array.isArray(runtime.observerAgents) ? runtime.observerAgents as Obj[] : [];
      const observerRows = observers.map(observer => `<tr><td>${esc(String(observer.agentId || 'unknown'))}</td><td>${esc(String(observer.lastAcceptedUtc || 'Never'))}</td><td>${observer.lastAcceptedAgeSeconds == null ? '—' : `${count(observer.lastAcceptedAgeSeconds)}s`}</td><td>${count(observer.freshReports)}</td><td>${count(observer.staleOrMissingReports)}</td><td>${count(observer.rejectedTotal)}</td></tr>`).join('');
      return `<div class="subtle">Local metrics snapshot · checked ${esc(String(runtime.checkedUtc || 'unknown'))}</div><div class="grid2"><div><b>Observer quorum</b><div>${count(quorum?.quorum)} of ${count(quorum?.configured)} sites meeting quorum</div><div class="subtle">Below quorum: ${count(quorum?.belowQuorum)}</div></div><div><b>Signed observer reports</b><div>Fresh healthy: ${count(evidence?.healthy)} · unhealthy: ${count(evidence?.unhealthy)}</div><div class="subtle">Unknown: ${count(evidence?.unknown)} · stale or missing: ${count(evidence?.staleOrMissing)}</div></div></div><h4>Configured observer agents</h4><div class="tablewrap"><table><thead><tr><th>Agent ID</th><th>Last accepted (UTC)</th><th>Age</th><th>Fresh reports</th><th>Stale/missing</th><th>Rejected</th></tr></thead><tbody>${observerRows||'<tr><td colspan="6">No agent report status available.</td></tr>'}</tbody></table></div><p class="subtle">Accepted/rejected totals are since the DNS process started. Age uses the DNS process monotonic clock; timestamps are UTC. Status includes configured agent IDs only and omits addresses and certificate/key details.</p>`;
    };
    const gateways = (r.gateways || []).map((g:Obj) => {
      const engines = Array.isArray(g.engines) ? g.engines as Obj[] : [];
      const gslb = engines.find((engine:Obj) => engine.engineId === 'gslb');
      let engineView = '';
      if (g.engineConfigState === 'available') {
        engineView = gslb
          ? `<div class="rowline"><div><b>GSLB DNS configuration</b><div class="subtle">Revision ${esc(String(gslb.revision || '').slice(0,12))} · ${esc(gslb.mode || 'file staging')}</div></div><span class="chip">${gslb.serviceRestarted ? 'Restarted' : 'Restart required'}</span></div>`
          : '<div class="rowline"><b>GSLB DNS configuration</b><span class="chip">Not staged</span></div>';
      } else {
        engineView = `<div class="rowline"><b>GSLB DNS configuration</b><span class="chip">${esc(g.engineConfigState || 'unavailable')}</span></div>`;
      }
      return `<div class="card"><div class="rowline"><b>${esc(g.id)}</b><span class="chip">${esc(g.state)}</span></div><div class="subtle">Agent: ${esc(g.report?.machine || 'unknown')} · ${esc(g.report?.engineConfigStagingEnabled ? 'signed file staging enabled' : 'engine staging disabled')}</div>${engineView}<h3>GSLB runtime evidence</h3>${runtimePanel(g)}<p class="healthbanner">These are local exporter metrics relayed over authenticated mTLS. They do not directly query DNS answers or prove agreement between authorities.</p></div>`;
    }).join('');
    $('content').innerHTML = `<div class="toolbar"><div><h2>GSLB and gateway status</h2><p class="subtle">Authenticated agent metadata, staged configuration, and optional local DNS metrics.</p></div>${actionBtn('Refresh agent status','fleet-probe','')}</div><div class="grid2">${gateways || '<div class="card"><p>No gateways registered.</p></div>'}</div>`;
  } catch(e) { show(String(e),true); }
}

async function fleetJournal(){
 try{const rows:Obj[]=await api('/admin/api/fleet/rollouts');
 $('content').innerHTML=`<div class="toolbar"><h2>Fleet rollout journal</h2>${actionBtn('Back to fleet','switch','fleet')} ${actionBtn('Refresh','fleet-journal','')}</div><p class="subtle">Recovery rolls back attempted targets only. A successful rollback is verified by original revision; application health still requires inspection. Legacy or ambiguous journals require manual reconciliation.</p><div class="tablewrap"><table><thead><tr><th>Transaction</th><th>Status</th><th>Action</th></tr></thead><tbody>${rows.map(x=>`<tr><td>${esc(x.id)}<div class="subtle">${esc(x.changeId||'')}</div></td><td>${esc(x.status)}</td><td>${currentRole==='Administrator'&&x.schema===2&&['starting','preparing','activating','manual-intervention-required','recovering'].includes(x.status)?actionBtn('Recover / rollback','fleet-recover',x.id):'—'}</td></tr>`).join('')||'<tr><td colspan="3">No rollout records</td></tr>'}</tbody></table></div>`;}catch(e){show(String(e),true)}
}
async function recoverFleetRollout(id:string){
 if(!confirm('Recover transaction '+id+' by rolling back attempted gateways? Verify the original fleet membership and maintenance approval before continuing.'))return;
 try{const x=await api('/admin/api/fleet/rollouts/'+encodeURIComponent(id)+'/recover','POST',{});show('Recovery '+id+': '+x.status+'. Inspect live health.');}
 catch(e){show('Recovery not confirmed: '+String(e),true)}
 await fleetJournal();
}
async function performFleetRollout(){
 const changeId=prompt('Enter a two-person APPROVED change request ID for BOTH gateways. Changes can affect live traffic.');
 if(!changeId)return;
 if(!confirm('Confirm staging and activating the approved configuration on EVERY registered gateway? Unavailable gateways can cause a partial deployment requiring manual recovery.'))return;
 try{const x=await api('/admin/api/fleet/rollout/'+encodeURIComponent(changeId),'POST',{});
 show('Rollout '+x.id+': '+x.status+'. Validate live traffic and failover.');await fleetStatus();}
 catch(e){show(String(e)+'; examine Fleet rollout journal before taking further action',true)}
}
async function destinationMetrics(){try{const x=await api('/admin/api/destination-metrics');
 $('content').innerHTML=`<div class="card"><h2>Destination-level request observations</h2><p class="subtle">${esc(x.scope)} · ${esc(x.timestampUtc)}</p><p>Tracked destination limit: ${esc(x.trackedDestinationLimit)} · Requests without per-destination counters after the limit: <strong>${esc(x.untrackedDestinationRequests)}</strong></p><div class="tablewrap"><table><thead><tr><th>Cluster / destination</th><th>Requests</th><th>HTTP 4xx</th><th>HTTP 5xx</th><th>Mean latency (ms)</th></tr></thead><tbody>${(x.destinations||[]).map((d:Obj)=>`<tr><td>${esc(d.id)}</td><td>${esc(d.requests)}</td><td>${esc(d.clientErrors4xx)}</td><td>${esc(d.failures5xx)}</td><td>${esc(d.meanLatencyMs)}</td></tr>`).join('')||'<tr><td colspan="5">No routed requests observed yet.</td></tr>'}</tbody></table></div></div>`;
 }catch(e){show(String(e),true)}}
