type Obj = Record<string, any>;
type State = {name:string;gateway:string;time:string;routes:Obj;clusters:Obj;disabled:Obj;monitorProfiles?:Obj;realServers?:Obj;serviceGroups?:Obj;mode:string;telemetry:string;revision:string};
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
   .then(async()=>{await loadOrganization();show('Organization profile saved');if(!o.organizationName){view='setup';render()}else{await organizationPage()}}).catch(e=>show(String(e),true))
 });
}

const show=(message:string,error=false)=>{const el=$('notice');el.hidden=false;el.className='notice'+(error?' error':'');el.textContent=message;setTimeout(()=>{el.hidden=true},8000)};
async function api(url:string,method='GET',body?:any,signal?:AbortSignal){const opts:RequestInit={method,credentials:'same-origin',headers:{},signal,cache:'no-store'};if(method!=='GET'){(opts.headers as Obj)['Content-Type']='application/json';(opts.headers as Obj)['X-CSRF-Token']=csrf;opts.body=JSON.stringify(body??{})}const generation=authGeneration;const r=await fetch(url,opts);if(generation!==authGeneration)throw Error('Management session changed. Outdated response ignored.');if(r.status===428){showLogin(false);void initSession();throw Error('Please accept the Privacy Policy to continue.')}if(r.status===401){if(!['/admin/api/session','/admin/api/login','/admin/api/bootstrap','/admin/api/login/verify'].includes(url)){if(!$('app-shell').hidden||!$('privacy-screen').hidden){showLogin(false);$('auth-message').textContent='Your administrator session has expired or was invalidated. Sign in again. No security settings were changed.'}throw Error('Administrator session expired; please sign in again')}throw Error('Authentication failed. Check your credentials or verification code.')}if(r.status===403){let stepUp=false;try{stepUp=(await r.json()).signIn==='/admin/oidc/start'}catch{}if(stepUp)throw Error('Fresh enterprise authentication required. Sign out, then sign in with Enterprise SSO / passkey. Retry only after reviewing the change.');throw Error('Access denied. This action requires an authorized role or valid CSRF token.')}if(!r.ok){let e='HTTP '+r.status;try{e=(await r.json()).error??e}catch{}throw Error(e)}const json=await r.json();if(generation!==authGeneration)throw Error('Management session changed. Outdated response ignored.');return json}
async function reload(){if(dirty&&!confirm('Discard unsaved changes and reload?'))return;try{data=await api('/admin/api/state');dirty=false;render();void refreshGatewayReadiness();show('Latest configuration loaded')}catch(e){show(String(e),true)}}
function edit(){dirty=true;render()}
function reasonDialog(title: string, help: string, minimum: number, label: string, perform: (reason: string) => Promise<void>) {
    modal(title, help, [{ name: 'reason', label: 'Reason (' + minimum + '–500 characters)', value: '', minLength: minimum }], () => {}, label);
    const dlg = $('modal') as HTMLDialogElement;
    const form = $('editor') as HTMLFormElement;
    const input = $('f-reason') as HTMLInputElement;
    const confirmButton = $('confirm') as HTMLButtonElement;
    const closeButton = $('modal-close') as HTMLButtonElement;
    const cancelButton = form.querySelector<HTMLButtonElement>('button[value="cancel"]')!;
    const error = document.createElement('p');
    error.className = 'journey-error';
    error.setAttribute('role', 'alert');
    $('modal-fields').append(error);
    input.maxLength = 500;
    let pending = false;
    const generation = authGeneration;
    dlg.oncancel = e => { if (pending) e.preventDefault(); };
    form.onsubmit = async e => {
        if ((e as SubmitEvent).submitter?.getAttribute('value') === 'cancel' && !pending)
            return;
        e.preventDefault();
        if (pending)
            return;
        const reason = input.value.trim();
        if (reason.length < minimum || reason.length > 500) {
            error.textContent = 'Enter a reason of ' + minimum + '–500 characters.';
            return;
        }
        pending = true;
        confirmButton.disabled = closeButton.disabled = cancelButton.disabled = true;
        error.textContent = '';
        try {
            await perform(reason);
            if (generation === authGeneration && dlg.open)
                dlg.close();
        }
        catch (err) {
            if (generation === authGeneration)
                error.textContent = String(err);
        }
        finally {
            pending = false;
            confirmButton.disabled = closeButton.disabled = cancelButton.disabled = false;
            dlg.oncancel = null;
        }
    };
}
async function save() {
    if (!dirty || currentRole === 'Viewer')
        return;
    reasonDialog('Submit configuration for approval', 'Your draft contains ' + keys(data.routes).length + ' route(s) and ' + keys(data.clusters).length + ' backend group(s). Nothing goes live until a different authorized administrator approves this exact revision.', 12, 'Submit request', async reason => {
        const x = await api('/admin/api/change-requests', 'POST', { reason, payload: { routes: data.routes, clusters: data.clusters, disabled: data.disabled, monitorProfiles: data.monitorProfiles || {}, realServers: data.realServers || {}, serviceGroups: data.serviceGroups || {}, revision: data.revision } });
        dirty = false;
        await reload();
        view = 'approvals';
        render();
        show('Request ' + x.id + ' submitted for independent approval. No live routing changed.');
    });
}
function actionBtn(text:string,action:string,id:string,klass='small-btn mini'){return `<button class="${klass}" data-action="${esc(action)}" data-id="${esc(id)}">${esc(text)}</button>`}
function destinationRows(){const arr:Obj[]=[];for(const cid of keys(data.clusters)){for(const did of keys(data.clusters[cid]?.Destinations)){const destination=data.clusters[cid].Destinations[did];arr.push({cid,did,address:destination.Address,enabled:true,metadata:destination.Metadata||{},trafficState:String(destination.Metadata?.TrafficState||'active'),weight:String(destination.Metadata?.Weight||'1'),trafficRole:String(destination.Metadata?.TrafficRole||'primary')})}}for(const id of keys(data.disabled)){const [cid,did]=id.split('::');const destination=data.disabled[id];arr.push({cid,did,address:destination.Address,enabled:false,metadata:destination.Metadata||{},trafficState:String(destination.Metadata?.TrafficState||'active'),weight:String(destination.Metadata?.Weight||'1'),trafficRole:String(destination.Metadata?.TrafficRole||'primary')})}return arr}
function summary(){const ready=!gatewayReadyWarn&&gatewayReadyLabel.includes('Backend readiness observed');const status=ready?'BACKEND READY':gatewayReadyLabel.includes('No healthy backend reported')?'NO BACKEND':'NOT VERIFIED';
 return `<div class="stats"><div class="card"><h3>Backend readiness</h3><div class="stat-number ${ready?'green':'yellow'}">${status}</div><div class="stat-desc">${ready?'At least one configured destination ready; not full fleet health':esc(gatewayReadyLabel.replace('● ',''))}</div></div><div class="card"><h3>Configured routes</h3><div class="stat-number">${keys(data.routes).length}</div><div class="stat-desc">Saved / draft HTTP routing rules</div></div><div class="card"><h3>Backend clusters</h3><div class="stat-number">${keys(data.clusters).length}</div><div class="stat-desc">Independent balancing policies</div></div><div class="card"><h3>Enabled destinations</h3><div class="stat-number">${destinationRows().filter(x=>x.enabled).length}</div><div class="stat-desc">Configured, not necessarily healthy</div></div></div>`}
function guide(){return `<div class="card operator-intro"><h2>GatewayCore in five steps</h2><p>GatewayCore forwards client HTTP(S) requests to application servers. A route matches a hostname/path; a backend group (cluster) contains servers (destinations).</p><div class="operator-flow"><span>Client</span><span aria-hidden="true">→</span><span>GatewayCore</span><span aria-hidden="true">→</span><span>Application servers</span></div></div><div class="operator-steps"><section class="card"><h3>1. Set up the gateway</h3><p>Create an administrator, accept the Privacy Policy and configure your organization. In Start here, open Gateway architecture. Choose Standalone for one server or review the HA design. For a local test, fill the single-server test draft, then Confirm design. This does not create VIPs, agents or firewall rules.</p></section><section class="card"><h3>2. Add a website or API</h3><p>Enter the client hostname and HTTPS backend root URL. Add a second backend only if you want round-robin balancing. Local website test uses an existing loopback HTTP site and the /lab/ prefix. DNS, listeners and IIS are not automatically configured.</p></section><section class="card"><h3>3. Review and approve</h3><p>Review Websites &amp; routes and Backend servers. Submit for approval with a reason of at least 12 characters. A different administrator must review and approve the exact draft in Change requests. Until then, the routing change is not live.</p></section><section class="card"><h3>4. Test actual traffic</h3><p>Inspect live backend health and run HTTP probes. Unknown is not healthy. For the approved local test open http://127.0.0.1:8080/lab/. For other applications test the approved client listener and hostname. Never expose the management listener publicly. Check Traffic metrics for errors.</p></section><section class="card"><h3>5. Operate and recover</h3><p>Configuration contains backend groups, backups and audit. Create a separate administrator before your first change request; use Operator for staff who prepare changes and Viewer for read-only monitoring. Security &amp; accounts contains administrators, mail and directory settings. Multi-gateway &amp; modules contains fleet, peer and capability evidence. HA needs enrolled agents, signed rollout and independently tested VIP failover.</p></section><section class="card"><h3>Troubleshooting</h3><p>No backend? Add and approve a website first. Cannot approve your own request? Sign in using a different authorized administrator, not a shared account. Unknown health? Check the actual readiness endpoint before enabling active checks. Changes blocked? Check the freeze and request revision. Sign-in failed? Use your recovery administrator; never delete protected state or keys. Lab evidence is not production certification.</p></section></div><div id="sop-manual" class="card card-spaced sop-manual"><h2>GatewayCore end-user manual and standard operating procedures</h2><p>Offline reference for L0 new starters, L1 daily operators, L2 administrators and L3 specialists. Applies to the implemented GatewayCore development build; features are conditional on role, license, host provisioning and topology. Production acceptance remains separate. All examples are placeholders.</p><p><strong>Learning path:</strong> L0 foundations → L1 daily operation → L2 administration → L3 specialist deployment and recovery. Start with the five-step overview above. Use chapter search or your browser Find. Read prerequisites before executing a procedure.</p><label for="sop-search">Search SOPs and troubleshooting</label><input id="sop-search" type="search" placeholder="Try 503, OTP, DNSSEC, backup or L3" autocomplete="off"><p id="sop-count" role="status" aria-live="polite">25 chapters</p><section class="sop-chapter" data-level="L0"><details><summary>L0 · SOP-01 · Start here: how GatewayCore works</summary><p><strong>Who:</strong> All users</p><p><strong>Before you start:</strong> Understand the terms before operating a gateway.</p><ol><li>Client → approved DNS/firewall/VIP → GatewayCore → backend group → application server. A route selects a group by hostname/path; a destination is one server. The management listener is separate from client traffic.</li><li>Dashboard shows this gateway, not proof that every site is healthy. Use Health checks and Traffic metrics; design records are not deployed infrastructure.</li><li>Use a named account, never a shared login. Viewer reads; Operator prepares drafts; Administrator manages security and approvals. The requester cannot approve their own routing change.</li></ol><p class="sop-trouble"><strong>Troubleshooting and stop conditions:</strong> If a menu is missing, check your role, topology, configured module and license. Do not try to bypass the restriction.</p><p><strong>Completion evidence:</strong> Explain the traffic path and demonstrate the difference between design, draft, applied configuration and real traffic.</p></details></section><section class="sop-chapter" data-level="L0"><details><summary>L0 · SOP-02 · Windows offline installation and upgrade</summary><p><strong>Who:</strong> Host administrator</p><p><strong>Before you start:</strong> Obtain the exact approved package and prepare an isolated x64 Windows Server 2022 or later lab.</p><ol><li>Obtain GatewayCore-Setup-win-x64.exe, SHA256SUMS.txt and SOURCE_COMMIT.txt from the successful exact-source installer workflow. Verify Get-FileHash -Algorithm SHA256 against the approved hash and independently verify package authorization. Ordinary lab EXE is unsigned; it is not the commercial release.</li><li>Use an elevated local account; confirm disk space, existing service ownership, backup custody and planned maintenance. Setup is self-contained and does not download a runtime or open firewall ports.</li><li>Run Setup. The lab dashboard opens only after local service health succeeds. Open http://127.0.0.1:8080/dashboard on the host, not on a public address. Existing accounts and supported configuration are retained on upgrade.</li><li>Record source SHA, package hash, installer exit status, service identity, local health and the retained backup. The installer rolls back the failed candidate when its immediate health gate fails; later rollback is a separate approved operation.</li></ol><p class="sop-trouble"><strong>Troubleshooting and stop conditions:</strong> If Setup fails, retain its Inno log in the invoking account TEMP directory, or use /LOG with an approved path. Check OS/architecture, disk, rights, conflicting port/service and rollback evidence. Never delete ProgramData to force installation.</p><p><strong>Completion evidence:</strong> Successful health gate, dashboard opens, correct version and service identity; preserve state and rollback evidence.</p></details></section><section class="sop-chapter" data-level="L0"><details><summary>L0 · SOP-03 · First administrator: sender-first registration</summary><p><strong>Who:</strong> Host administrator / first Administrator</p><p><strong>Before you start:</strong> Approved existing company sender or relay, readable test mailbox and protected installation claim.</p><ol><li>On a fresh ordinary Windows lab installation open C:\\ProgramData\\GatewayCoreYarp\\ControlPlane\\first-run-code.txt locally as administrator. Authorize installation with the one-time claim; do not send it to anyone.</li><li>Connect company email: enter sender (for example noreply@example.invalid), verification inbox, SMTP hostname and port, approved authentication method and dedicated credentials. STARTTLS is required; implicit TLS port 465 is unsupported.</li><li>Receive the sender verification OTP and enter it. Register the first administrator email, receive its separate OTP and verify it.</li><li>Create a named username and unique password (16–256 characters); confirm it. Sign in using the configured login OTP workflow, accept Privacy Policy and configure the organization. Existing initialized installations do not repeat first-run enrollment.</li></ol><p class="sop-trouble"><strong>Troubleshooting and stop conditions:</strong> If OTP never arrives, check relay reachability, TLS, allowed sender, recipient quarantine and actual inbox. SMTP acceptance is not mailbox delivery. Restart an expired setup flow using the protected claim only if still unconsumed; contact the host administrator for recovery.</p><p><strong>Completion evidence:</strong> Sender OTP and administrator OTP both verified; named recovery administrator can sign in; no credential included in ticket or screenshots.</p></details></section><section class="sop-chapter" data-level="L0"><details><summary>L0 · SOP-04 · Employee sign-in, invitation and access</summary><p><strong>Who:</strong> Viewer / Operator / Administrator</p><p><strong>Before you start:</strong> Verified mail, separate named accounts; invitation enrollment only where supported.</p><ol><li>Administrator: Security &amp; accounts → Admin accounts → Invite employee. In an ordinary standalone local-account lab choose named username, company email and Viewer or Operator. Invitations cannot assign Administrator.</li><li>Employee: open the authorized dashboard, choose Accept employee invitation, enter the one-time code, then set and confirm a unique password. Invitation lasts at most 30 minutes; completion capability lasts at most 10 minutes. Sign in using password and separate login OTP; accept privacy terms.</li><li>For other deployment modes use the authorized local/enterprise identity enrollment procedure. Test a separate reviewer in a different session. Revoke expired or unwanted invitations and disable accounts through authorized account administration.</li></ol><p class="sop-trouble"><strong>Troubleshooting and stop conditions:</strong> Expired code or service restart: ask issuer to revoke/reissue; do not reuse/forward codes. 401 means sign in again or verify identity; 403 can be role, policy or entitlement denial. Use the authorized recovery account if locked out.</p><p><strong>Completion evidence:</strong> Separate accounts can sign in; role permitted actions verified; departing staff access revoked and audited.</p></details></section><section class="sop-chapter" data-level="L0"><details><summary>L0 · SOP-05 · Commercial offline activation and renewal</summary><p><strong>Who:</strong> License administrator</p><p><strong>Before you start:</strong> Commercial package and independently authorized issuer, not the unsigned lab package.</p><ol><li>Open License Center where available. Download the activation request from the actual installation. Transfer using the approved offline channel to the issuer.</li><li>Import only the signed license (.lic) issued for that installation via Activate / renew. Review licensed features, node limits and expiration. For an approved revocation, use Import revocation with the signed .gcv document.</li><li>Keep issuer signing keys outside the customer gateway. Do not copy licenses between installations, change system time, edit entitlement state or use an unsigned test build as a commercial package.</li></ol><p class="sop-trouble"><strong>Troubleshooting and stop conditions:</strong> If activation fails, preserve the nonsecret request/status and verify package profile, installation binding, validity dates, authorized issuer and feature entitlement; contact the license custodian. Never bypass licensing or roll back trusted state.</p><p><strong>Completion evidence:</strong> Installation reports the correct licensed scope; required operations allowed and excluded operations denied; record sanitized evidence.</p></details></section><section class="sop-chapter" data-level="L1"><details><summary>L1 · SOP-06 · Organization and architecture setup</summary><p><strong>Who:</strong> Administrator</p><p><strong>Before you start:</strong> Actual organization, host inventory, approved network design and change ticket.</p><ol><li>Start here → Organization: configure company labels and region. These are metadata, not tenancy or isolation.</li><li>Start here → Gateway architecture: choose Standalone for a single lab, or the applicable HA/fleet design; enter gateway and application hosts and DC/DR site assignments. Review the topology diagram and confirm.</li><li>Follow the Approval team step. Create/test a separate authorized administrator and use an Operator for preparing routine changes. Record backup and approved maintenance procedures.</li><li>Network team independently provisions listeners, firewall, ingress VIP/ECMP, node identities and agent trust. GatewayCore does not provision those merely by saving the design.</li></ol><p class="sop-trouble"><strong>Troubleshooting and stop conditions:</strong> If checklist says Required, open its recommended next action. A confirmed design with no enrolled agents or VIP is not a live HA deployment.</p><p><strong>Completion evidence:</strong> Organization and design saved, second approver verified, network implementation/evidence tracked separately.</p></details></section><section class="sop-chapter" data-level="L1"><details><summary>L1 · SOP-07 · Add a website or API</summary><p><strong>Who:</strong> Operator / independent Administrator</p><p><strong>Before you start:</strong> Approved client hostname, path, trusted HTTPS backend root URL, application owner and readiness contract.</p><ol><li>Start here → Add website / API. Enter a name, client hostname and backend root URL; add a second distinct server if equal round-robin is intended. For an existing loopback HTTP lab site use Local website test (/lab/).</li><li>Review Websites &amp; routes and Backend servers. Match only intended host/path; use trusted HTTPS origins. Confirm application auth, session state and path handling with its owner. Do not expose restricted admin/CA endpoints by copying a public route.</li><li>Submit for approval with a reason of at least 12 characters. A different Administrator opens Change requests → Review full draft, checks the exact JSON and approves or rejects.</li><li>After approval verify runtime routes and destinations, actual client requests on the approved listener, expected status/body and metrics. Enable readiness checks only after verifying the real endpoint.</li></ol><p class="sop-trouble"><strong>Troubleshooting and stop conditions:</strong> 404: confirm hostname/path and approved revision; 502: inspect backend DNS/TCP/TLS and app logs; 503: inspect eligible destinations and readiness; 504: check downstream latency/timeouts. Do not retry non-idempotent signing or payment operations blindly.</p><p><strong>Completion evidence:</strong> Correct client response and backend selection, independent approval ID, no unauthorized route exposure.</p></details></section><section class="sop-chapter" data-level="L1"><details><summary>L1 · SOP-08 · Backend groups, balancing and maintenance</summary><p><strong>Who:</strong> Operator / independent Administrator</p><p><strong>Before you start:</strong> Healthy application origins and tested policy.</p><ol><li>Configuration → Backend groups → Edit; review policy guidance. RoundRobin spreads equal requests; LeastRequests uses active requests; PowerOfTwoChoices compares two eligible destinations; WeightedRandom uses configured weights; SourceIpHash uses immediate trusted peer identity; FirstAlphabetical prefers the first eligible destination. Primary/backup requires explicit roles and health policy where supported.</li><li>Backend servers: add or edit destination URL, weight (1–100 where weighted policy applies) and enable state. Configure verified readiness path and active thresholds; do not treat Unknown as Healthy.</li><li>For planned maintenance, use the approved drain/disable workflow, verify surviving capacity and existing traffic completion, then service the backend. Restore only after app readiness, actual client test and approval where configuration changes are required.</li></ol><p class="sop-trouble"><strong>Troubleshooting and stop conditions:</strong> Uneven traffic can be expected with weighting, connection reuse or SNAT. Check actual request distribution, policy, health and role/weight settings; do not disable TLS or fail open to sick nodes.</p><p><strong>Completion evidence:</strong> Approved policy; actual distribution and graceful drain verified under representative traffic.</p></details></section><section class="sop-chapter" data-level="L1"><details><summary>L1 · SOP-09 · Change requests, approval and freeze</summary><p><strong>Who:</strong> Operator / independent Administrator</p><p><strong>Before you start:</strong> Named requester, different approver, change record and current revision.</p><ol><li>Prepare a draft and review route/backend changes and advanced JSON. Record business reason, affected services, expected outcome, verification and rollback.</li><li>Submit for approval. Reviewer opens Change requests → Review full draft; compare exact JSON and revision, reject unexpected edits or approve using a different account.</li><li>If freeze is active, do not bypass it. Administrator uses the authorized freeze/unfreeze workflow with reason. Local freeze is not a fleet quorum lock.</li><li>On revision conflict, reread current live configuration, reconcile the draft and submit a new request. After approval verify loaded configuration and real traffic; approval alone is not success.</li></ol><p class="sop-trouble"><strong>Troubleshooting and stop conditions:</strong> HTTP 423 indicates frozen changes; 409 indicates conflicting revision/state or operation. Do not create duplicates or reuse stale approval. For uncertain apply, inspect audit and current revision before retrying.</p><p><strong>Completion evidence:</strong> Request, reviewer and applied revision recorded; traffic verification and rollback decision attached.</p></details></section><section class="sop-chapter" data-level="L1"><details><summary>L1 · SOP-10 · Daily monitoring and shift handover</summary><p><strong>Who:</strong> Viewer / Operator</p><p><strong>Before you start:</strong> Approved read-only access and site-specific baselines.</p><ol><li>Dashboard: inspect local status and gateway readiness. Health checks: compare runtime active/passive states with on-demand probes; a process health response is not end-to-end availability.</li><li>Traffic metrics: inspect request counts, failures, latency and backend distribution; local counters reset at process restart and may not represent fleet totals.</li><li>Review change requests, certificate expiry, backups and audit, fleet state and configured license status. Check configured external telemetry and audit delivery for stale/drop/block indicators.</li><li>At shift handover record UTC time, site/node, affected services, current revision, incidents, upcoming maintenance/renewals, unresolved alarms and the next owner.</li></ol><p class="sop-trouble"><strong>Troubleshooting and stop conditions:</strong> If an alarm appears, collect evidence before changing anything. Compare another gateway and actual client path. Do not reset counters or restart a service just to make an alarm disappear.</p><p><strong>Completion evidence:</strong> Known health, documented deviations, named owner and next action for each unresolved alert.</p></details></section><section class="sop-chapter" data-level="L1"><details><summary>L1 · SOP-11 · SMTP, OTP, directory and account recovery</summary><p><strong>Who:</strong> Administrator / identity specialist</p><p><strong>Before you start:</strong> Dedicated credentials, valid CA chains and tested recovery account.</p><ol><li>Security &amp; accounts → Mail &amp; OTP: configure approved relay/FQDN, STARTTLS and allowed sender; test delivery to the real registered inbox before enabling/changing OTP. Use approved relay/app credentials or configured Google/Microsoft OAuth modes.</li><li>Active Directory: verify LDAPS FQDN, trusted server SAN/chain, port 636 (or approved GC 3269), read-only bind account, search base and exact group-to-role mapping. Test each role with real directory accounts and populated mail attributes.</li><li>Enterprise SSO is separately host-configured with the trusted HTTPS OIDC issuer, exact immutable subject/group mapping, PKCE, phishing-resistant assurance and tested local recovery account. It is not automatic enrollment.</li><li>Keep recovery administrator access under custody; never disable OTP/TLS or remove protected identity state for recovery.</li></ol><p class="sop-trouble"><strong>Troubleshooting and stop conditions:</strong> Mail: distinguish DNS/TCP, TLS, relay authentication and final mailbox delivery. Directory: distinguish bind failure, trust error, missing group or mail. SSO: check issuer/redirect/claims and real IdP assurance; escalate to identity team.</p><p><strong>Completion evidence:</strong> Tested allowed and denied roles, actual delivery, recovery account and audited policy change.</p></details></section><section class="sop-chapter" data-level="L2"><details><summary>L2 · SOP-12 · TLS bootstrap and certificate inventory</summary><p><strong>Who:</strong> Host administrator / PKI specialist</p><p><strong>Before you start:</strong> Approved encrypted PFX files, protected password files, trusted management client CA/pins, distinct addresses and measured limit.</p><ol><li>Before initial isolated HTTPS management, provision approved traffic and management PFX and trust on host. Run the installed executable with --listener-bootstrap-wizard followed by an existing absolute private directory. Enter IPs, ports, protected file paths (not passwords), management CIDRs, pins, DNS names and measured concurrency limit.</li><li>Type CREATE only after validation; wizard creates new listeners.json without overwrite. Configure YARP_LISTENERS_CONFIG_FILE under the service identity, then start through approved host procedure. Verify actual management mTLS and traffic TLS separately.</li><li>Security &amp; accounts → Certificates &amp; TLS: inspect local inventory, expiry, EKU and configured capabilities. Inventory dates do not prove trust, selected leaf or live handshake.</li><li>Configure backend mTLS only with approved installed client certificate and HTTPS origins. Review the draft thumbprint and independently approve; verify actual backend handshake on every target gateway.</li></ol><p class="sop-trouble"><strong>Troubleshooting and stop conditions:</strong> If certificate unavailable, inspect store/service identity, private ACL, password file, SAN/EKU, chain and trust under actual service identity. Never import a private key into chat or disable validation.</p><p><strong>Completion evidence:</strong> Correct live leaf on both listeners, trusted handshake and denied unauthorized management client.</p></details></section><section class="sop-chapter" data-level="L2"><details><summary>L2 · SOP-13 · Certificate renewal, import and revocation</summary><p><strong>Who:</strong> Administrator / PKI specialist</p><p><strong>Before you start:</strong> Configured ACME or approved host-staged certificate and current authority.</p><ol><li>Certificates &amp; TLS → Check renewal now when configured. It checks due-date policy using the existing issuer; no forced early issuance. Independently test the actual TLS leaf after the result.</li><li>For staged import, host operator explicitly enables YARP_STAGED_TRAFFIC_CERTIFICATE_IMPORT and places approved encrypted PFX at the fixed active path plus .pending.pfx using existing protected password. Preview the candidate/active digests; type ACTIVATE and exact candidate SHA-256, then activate. Standalone enterprise mode additionally checks current authority and external audit where configured.</li><li>In commercial fleet mode use the separate SOP below. For historical ACME revocation, provide exact public DER base64, 40-character uppercase thumbprint, supported reason and typed REVOKE confirmation. The active certificate is protected. Revocation is irreversible.</li><li>Verify live handshake, expiry, audit and continuity. A pending or unconfirmed operation is not safe to replay.</li></ol><p class="sop-trouble"><strong>Troubleshooting and stop conditions:</strong> Not due is not a failure. For import conflict, compare active/candidate digests and authority, check protected PFX and live listener. For uncertain renewal/revocation, verify live TLS and CA status before retrying; do not revoke as a troubleshooting shortcut.</p><p><strong>Completion evidence:</strong> New leaf verified independently, or not-due result recorded; old leaf status and audit confirmed.</p></details></section><section class="sop-chapter" data-level="L3"><details><summary>L3 · SOP-14 · Commercial fleet certificate rotation</summary><p><strong>Who:</strong> Fleet operator / independent signer / Administrator</p><p><strong>Before you start:</strong> Licensed TLS/HA/fleet; existing quorum, external audit/outbox, no conflicting ACME; per-node approved PFX and peer-health evidence.</p><ol><li>Verify peer capacity and live traffic first. Obtain staged preview on target. Authorized host operator runs GatewayCoreYarp --fleet-tls-lock acquire with exact active, candidate and peer-evidence SHA-256 values. Preserve the durable plan. If acquisition uncertain, use recover only for the same transaction.</li><li>Independent signer uses ops/fleet/sign_fleet_tls_grant.py --plan with copied plan, --key with protected P-256 key and --purpose activate. Provision fleet-tls-approval.json and pinned signer public key as documented. Never copy private signer key to gateway.</li><li>Administrator refreshes preview until grant/quorum are observed, then confirms exact candidate. Server rechecks authority and consumes one-time epoch. Verify actual TLS leaf and surviving peer traffic.</li><li>Signer issues separate activated or rolled-back completion grant with evidence SHA-256. Provision fleet-tls-completion.json and run --fleet-tls-lock release. Only after exact active file and live TLS verification plus original quorum release may the next node be rotated.</li></ol><p class="sop-trouble"><strong>Troubleshooting and stop conditions:</strong> No grant/current quorum or unconfirmed activation: stop. Preserve plan, epoch, journal and audit; recover same transaction with custodian. Never delete the plan, manually clear quorum or rotate both nodes together.</p><p><strong>Completion evidence:</strong> One-node-at-a-time verified live TLS, independent completion evidence and confirmed original fence release.</p></details></section><section class="sop-chapter" data-level="L2"><details><summary>L2 · SOP-15 · HA, Active-Active, DC-DR and fleet rollout</summary><p><strong>Who:</strong> Platform / network specialist / independent reviewer</p><p><strong>Before you start:</strong> Distinct host identities, management mTLS, signed plan, approved VIP/ECMP, quorum and physical test plan.</p><ol><li>Record gateway/site topology and workload ownership. Network team configures health-aware ingress separately. Enroll agents with pinned identity and verify Gateway fleet/runtime status.</li><li>Use existing signed fleet configuration workflow: inspect current exact revision and enrolled membership, obtain independent signature and valid authority, stage and verify candidate, activate in the approved order and verify live configuration/traffic. Preserve receipts.</li><li>For planned node maintenance verify remaining capacity, drain the target where supported, validate live traffic before and after, recover and rejoin using current approved config. For unplanned failure follow site incident procedure; never replay in-flight POSTs.</li><li>DC-DR data replication and consistency are application-owned. GatewayCore does not replicate application databases. Failback only after data owner, network and gateway teams confirm safe authority and current state.</li></ol><p class="sop-trouble"><strong>Troubleshooting and stop conditions:</strong> Partition, expired lease, mismatch or failed rollout: stop mutations, preserve receipts, inspect both sites and quorum. Do not force promotion or clear fencing. Local UI freeze does not fence other controllers.</p><p><strong>Completion evidence:</strong> Physical node loss, partition, VIP migration, failback and measured capacity demonstrated; issue #36 and authorized production release signoff separate.</p></details></section><section class="sop-chapter" data-level="L2"><details><summary>L2 · SOP-16 · WAF policy and signed dashboard deployment</summary><p><strong>Who:</strong> Security specialist / Administrator / independent reviewers</p><p><strong>Before you start:</strong> Pinned CRS ruleset, representative redacted corpus, independent review, configured operator broker and live external fence.</p><ol><li>Multi-gateway &amp; modules → WAF policy workflow: prepare unsigned candidate with fresh revision, observed ruleset SHA-256, lifetime, detect/block mode and narrowly scoped exceptions where supported. Block requires reviewed shadow evidence. Export exact bytes and digest.</li><li>Obtain two independent signatures and verify against actual ruleset, trusted revision floor and evidence. The current signed coordinator supports mode transitions without scoped exceptions; do not assume draft exceptions can be activated.</li><li>Where configured, use dashboard Deploy independently signed specialist configuration. Enter exact independently staged revision/digest, select Read-only preflight and type PREFLIGHT plus digest. Review evidence; choose execute only with authorized change and typed EXECUTE. Windows dashboard reaches independently administered Linux operator over pinned mTLS; native Windows WAF engine not provided.</li><li>Applied-uncommitted means both nodes verified, independent authority commit still required. For intentional rollback prepare a fresh signed revision to prior mode, not stale policy replay; use existing compensating transaction and preserve receipts.</li></ol><p class="sop-trouble"><strong>Troubleshooting and stop conditions:</strong> Missing broker: check feature, configuration and role. Signature/ruleset mismatch: re-review exact bytes. Unexpected WAF 403: correlate rule and representative traffic, never disable protection globally. Unconfirmed deployment: stop/reconcile receipts and authority before retry.</p><p><strong>Completion evidence:</strong> Detection and block accuracy, per-route evidence, two-node deployment, compensation, independent commit and representative latency/capacity verified.</p></details></section><section class="sop-chapter" data-level="L2"><details><summary>L2 · SOP-17 · DNS/GSLB zone configuration and DNSSEC</summary><p><strong>Who:</strong> DNS specialist / Administrator</p><p><strong>Before you start:</strong> Zone ownership, parent delegation plan, nameservers, forward serial, sites and verified health endpoints.</p><ol><li>Multi-gateway &amp; modules → DNS &amp; GSLB workflow: enter authoritative zone, SOA contact, positive serial, TTL, distinct nameserver/site addresses, HTTPS health URLs, routing policy, weights/priorities and probe thresholds. Export validated unsigned loopback candidate; no actual delegation or live config change.</li><li>Open DNSSEC and delegated authority: choose Disabled, NSEC or NSEC3. Enter only approved absolute signing-key references, optional rollover public/additional key paths, explicit NSEC3 salt/iterations and child delegations/DS records. Never paste key contents.</li><li>Have DNS/PKI operator independently prepare signed engine config and authority/quorum; provision actual interfaces and trust. Validate serial advance, parent DS and DNSSEC response chain, and site failure behavior using real UDP/TCP queries.</li><li>All-down is fail-closed; do not promise site failover merely because a zone is saved.</li></ol><p class="sop-trouble"><strong>Troubleshooting and stop conditions:</strong> SERVFAIL: check DNSSEC signer/clock/DS/trust, authority status and health. NXDOMAIN: verify queried name/zone/delegation. Wrong address: check TTL/cache, actual authoritative response and site health. Do not remove DNSSEC or publish an older SOA serial to fix a symptom.</p><p><strong>Completion evidence:</strong> Expected direct authoritative UDP/TCP answers, SOA, DNSSEC and resolver convergence verified before parent delegation.</p></details></section><section class="sop-chapter" data-level="L3"><details><summary>L3 · SOP-18 · Signed rolling DNS deployment and Windows restart</summary><p><strong>Who:</strong> DNS / fleet operator / Administrator</p><p><strong>Before you start:</strong> Two independently enrolled authorities, exact signed prepare envelopes, common forward serial transition, approved mTLS broker/agent and current quorum where required.</p><ol><li>Operator stages a private approved two-node plan with signed envelopes and baseline SOA; broker --describe produces sequence and canonical digest. In dashboard enter exact sequence/digest and run read-only preflight with typed confirmation. Preflight proves baseline runtime/SOA, not all signature checks.</li><li>After independent authorization execute the same plan. Coordinator prepares both agents, activates/restarts one authority, verifies loaded digest and real UDP/TCP SOA, then repeats on the second and checks both.</li><li>Windows uses the fixed GatewayCoreGslb service with native SCM lifetime; Linux uses gatewaycore-gslb.service. Restart must be explicitly enabled on agent with allowlisted config, loopback metrics and delegated service rights. Commercial operations require current authenticated fence.</li><li>Preserve journal and complete independent authority commit. If a restart may have published a new serial, old-file rollback is refused; use fresh signed forward recovery after reconciliation.</li></ol><p class="sop-trouble"><strong>Troubleshooting and stop conditions:</strong> If file revision differs from loaded revision, restart not confirmed or SOA differs, stop before touching second authority. Preserve restart intent and private journal; never restart both at once or replay uncertain transaction.</p><p><strong>Completion evidence:</strong> Both authorities serve expected forward serial over UDP and TCP; loaded digest and authority commit confirmed.</p></details></section><section class="sop-chapter" data-level="L2"><details><summary>L2 · SOP-19 · L4 TCP/UDP, capability inventory and GitOps</summary><p><strong>Who:</strong> Platform specialist</p><p><strong>Before you start:</strong> Opt-in engine/service, authorized listeners, separate config and acceptance.</p><ol><li>Open Traffic engine &amp; modules / Capabilities to inspect supported/configured features. L4 is a separate engine, not an HTTP route; use the documented signed agent workflow and approved bind/target addresses.</li><li>Validate TCP connectivity and UDP behavior, drain/stop and backend failure with representative protocol traffic. Do not replay bytes after uncertain forwarding. Actual listeners, firewalls and service configuration are host-managed.</li><li>GitOps or infrastructure integrations are capability-dependent; use the documented reviewed workflow and compare desired vs actual state. Do not assume a capability listing means a controller has been installed or accepted.</li></ol><p class="sop-trouble"><strong>Troubleshooting and stop conditions:</strong> Port binding failures: check approved listener, ownership and firewall; protocol timeouts: inspect backend path and runtime evidence. Do not expose management or disable restrictions.</p><p><strong>Completion evidence:</strong> Separate runtime and protocol-specific acceptance for any enabled engine.</p></details></section><section class="sop-chapter" data-level="L2"><details><summary>L2 · SOP-20 · Backups, restore, upgrade rollback and disaster recovery</summary><p><strong>Who:</strong> Administrator / backup custodian</p><p><strong>Before you start:</strong> Approved maintenance, protected backups and recovery procedure.</p><ol><li>Configuration → Backups &amp; audit: identify snapshot and verify revision/contents and independent retention. Maintain separately protected offline copies of config, identity/key state and release artifacts under authorized custody.</li><li>Restore only with approved change and correct snapshot; respect freeze and current revision. Preserve prior evidence, verify restored routing and client traffic. A config restore is not a complete host or identity restore.</li><li>For lab installer upgrade rollback, use retained versioned binaries and protected backup/runbook; installer auto-rollback only covers failed immediate health gate. Uninstall retains ProgramData state. Do not copy Windows DPAPI state to another host.</li><li>For fleet/DR key recovery, use existing authenticated signed recovery and fencing procedures. Application database backup and recovery remain separate.</li></ol><p class="sop-trouble"><strong>Troubleshooting and stop conditions:</strong> Restore blocked: verify Administrator authority, freeze, revision, backup integrity and target identity. Never delete keys or replace entire state from another node as a shortcut.</p><p><strong>Completion evidence:</strong> Restore drill demonstrates correct revision, authorized login, live traffic and auditable recovery; independent backup retention confirmed.</p></details></section><section class="sop-chapter" data-level="L2"><details><summary>L2 · SOP-21 · Observability and incident response</summary><p><strong>Who:</strong> Viewer / Operator / platform specialist</p><p><strong>Before you start:</strong> Site-specific thresholds and external telemetry/audit setup where enabled.</p><ol><li>Traffic metrics and health: record UTC, gateway, route, backend, status/error rates and latency. Compare with actual traffic and approved baseline; distinguish app errors from gateway transport failures.</li><li>For configured OTLP, verify collector HTTPS trust, connectivity, sampling and queue/drop counters. Collector outage can lose telemetry without stopping proxy; audit delivery has separate durable outbox and blocked/fault indicators.</li><li>Do not log authorization headers, passwords, OTPs, private keys, request bodies or customer-sensitive payloads. Use redacted correlation identifiers and timestamps. Preserve audit, transaction IDs and configuration revision.</li><li>Classify incident severity, notify owner/security as needed, freeze risky changes under authorization, investigate one hypothesis at a time and verify recovery before closure.</li></ol><p class="sop-trouble"><strong>Troubleshooting and stop conditions:</strong> Telemetry missing: check configured endpoint, service identity, TLS, collector ingestion and drop/staleness. Audit blocked: escalate before further protected changes; never disable audit to proceed.</p><p><strong>Completion evidence:</strong> Evidence-based RCA, restored traffic, audit continuity and corrective action owner.</p></details></section><section class="sop-chapter" data-level="L1"><details><summary>L1 · SOP-22 · Troubleshooting decision tree: 401, 403, 404, 409, 423, 429, 502, 503, 504</summary><p><strong>Who:</strong> All users / authorized support</p><p><strong>Before you start:</strong> Collect evidence without mutation first.</p><ol><li>401: sign-in/session/OTP; 403: check role, entitlement, WAF or management access policy and audit. Do not bypass auth. 404: check correct listener, hostname/path and route revision.</li><li>409: revision, state or authority conflict; reread current state, reconcile before new action. 423: freeze; ask authorized administrator. 429: respect rate limits; stop repeated attempts.</li><li>502: gateway-to-backend failure or upstream response; verify approved DNS/TCP/TLS and backend logs. 503: readiness/eligible destinations or service/entitlement state; check health and configuration. 504: upstream timeout; correlate app latency and network evidence.</li><li>If impact is broad, compare another gateway and independent client probe. For signing/payment/non-idempotent POST uncertainty, reconcile the business transaction with application owner; never assume failure means it did not commit.</li></ol><p class="sop-trouble"><strong>Troubleshooting and stop conditions:</strong> Escalate when there is customer impact, suspected compromise, uncertain mutation, lost quorum, both nodes unhealthy, or no verified recovery path. Do not restart indiscriminately.</p><p><strong>Completion evidence:</strong> Identify failing layer, collect reproducible sanitized evidence, verify recovery with an independent request.</p></details></section><section class="sop-chapter" data-level="L1"><details><summary>L1 · SOP-23 · Safe diagnostic commands for Windows and Linux</summary><p><strong>Who:</strong> Authorized support / host administrator</p><p><strong>Before you start:</strong> Use only approved endpoints and read-only commands; replace placeholders with authorized values.</p><ol><li>Windows PowerShell: Get-Service to inspect service status; Get-WinEvent -LogName Application -MaxEvents 30 for recent application events; Resolve-DnsName for approved hostname; Test-NetConnection with approved host and port. Get-FileHash -Algorithm SHA256 verifies package or approved artifact.</li><li>Linux: systemctl status with the approved unit; journalctl -u with approved unit and time window; ss -lntup for listening sockets; getent hosts for configured hostname. Use normal service-manager authorization; do not restart without approval.</li><li>Local ordinary lab: curl http://127.0.0.1:8080/gateway/health or Invoke-WebRequest to inspect liveness. Readiness is /gateway/health/ready on the appropriate approved listener. For trusted HTTPS use normal certificate validation; never use -k to claim success.</li><li>For authoritative DNS use approved DNS host and port: dig @server -p port zone SOA +norecurse and repeat with +tcp, validate AA and expected serial. On Windows use approved DNS tooling capable of direct UDP and TCP proof. Do not query public resolvers with sensitive names.</li></ol><p class="sop-trouble"><strong>Troubleshooting and stop conditions:</strong> If a command is unavailable, use approved equivalent or escalate to host team. Redact machine-specific sensitive details before sharing logs; never include passwords, tokens or private keys.</p><p><strong>Completion evidence:</strong> Actual observed output supports the failing layer; all diagnostics are read-only unless separately authorized.</p></details></section><section class="sop-chapter" data-level="L1"><details><summary>L1 · SOP-24 · Incident escalation and RCA template</summary><p><strong>Who:</strong> All users</p><p><strong>Before you start:</strong> Use your organization's severity policy and contact roster.</p><ol><li>Record incident ID, UTC start/end, affected sites/services, business impact, observed symptoms, exact approved version/revision and recent change.</li><li>Collect sanitized request/correlation ID, status, time window, health/metrics, relevant logs, current signed transaction/receipt and configuration diff; exclude OTPs, keys, license secrets and personal data.</li><li>Escalate to L1 service desk for access/basic monitoring, L2 gateway/network/application support for route/backend/service failures, L3 platform/PKI/DNS/security for authority, keys, quorum, DNSSEC, WAF and enterprise identity. Suspected compromise or broad outage follows emergency/security process.</li><li>Document hypothesis vs confirmed root cause, containment, approved corrective action, verification, rollback status, preventive action, owner and due date. Do not mark resolved from a green process health check alone.</li></ol><p class="sop-trouble"><strong>Troubleshooting and stop conditions:</strong> If evidence is inconclusive, say so. If mutation status is uncertain, stop further changes and reconcile. Contact names and response targets must be supplied by the customer's approved SOP.</p><p><strong>Completion evidence:</strong> Incident owner accepts actual service recovery; RCA and follow-up tasks recorded.</p></details></section><section class="sop-chapter" data-level="L3"><details><summary>L3 · SOP-25 · Release, physical acceptance and operator qualification</summary><p><strong>Who:</strong> Platform lead / security / change authority</p><p><strong>Before you start:</strong> Exact reviewed source, approved artifacts, site evidence and authorized production decision.</p><ol><li>Verify exact-head CI including separate CodeQL gate, independent approval, post-merge main CI and final installer/source SHA-256. A green build is software evidence only.</li><li>Use issue #36 physical acceptance: actual independent hosts, VIP/ECMP, real failover/failback and partition, sustained site-specific capacity/latency, TLS/identity/audit, backup recovery and real representative traffic. Do not lower approved thresholds or substitute synthetic runs.</li><li>Train new employees in isolated environment: first login, named role, website draft with separate reviewer, actual request, health incident and escalation. L2/L3 demonstrate certificate, DNS, WAF and recovery procedures with authorized specialists.</li><li>Production remains NO-GO until owner/site change authority signs acceptance. Keep documented release and rollback evidence; do not treat the manual as authorization to execute.</li></ol><p class="sop-trouble"><strong>Troubleshooting and stop conditions:</strong> Failed/unknown gate: stop release, preserve results and assign corrective action. Do not expose lab management to public traffic.</p><p><strong>Completion evidence:</strong> Separate software, user training, physical environment and authorized release signoffs.</p></details></section><p class="subtle">Use your organization's approved contacts, change authority and incident response policy. This guide does not change live configuration.</p></div>`}
function wireGuide() {
    const input = $('sop-search') as HTMLInputElement;
    const sections = Array.from(document.querySelectorAll<HTMLElement>('#sop-manual .sop-chapter'));
    input.oninput = () => {
        const query = input.value.trim().toLowerCase();
        let count = 0;
        for (const section of sections) {
            const match = !query || (section.textContent || '').toLowerCase().includes(query);
            section.hidden = !match;
            if (match)
                count++;
            const details = section.querySelector('details');
            if (details && query)
                details.open = match;
        }
        $('sop-count').textContent = count + (count === 1 ? ' chapter' : ' chapters');
    };
}
function adcServiceMap() {
    const members = destinationRows();
    const services = [];
    for (const id of keys(data.routes)) {
        const route = data.routes[id];
        const groupId = String(route.ClusterId || '');
        const group = Object.prototype.hasOwnProperty.call(data.clusters, groupId) ? data.clusters[groupId] : null;
        const groupMembers = members.filter(d => d.cid === groupId);
        const servers = groupMembers.map(d => `<li><strong>${esc(d.did)}</strong><span class="mono">${esc(d.address)}</span><span class="chip">${d.enabled ? esc(d.trafficState) : 'Disabled'} · weight ${esc(d.weight)}</span></li>`).join('');
        services.push(`<article class="adc-service"><div><strong>${esc(id)}</strong><div class="subtle">${esc((route.Match?.Hosts || []).join(', ') || 'Any host')}</div><div class="mono">${esc(route.Match?.Path || 'Any path')}</div></div><div><strong>${esc(groupId || 'Missing group')}</strong><div class="subtle">${group ? esc(group.LoadBalancingPolicy || 'Default') : 'Unresolved group reference'}</div><div class="subtle">${group ? groupMembers.length + ' configured members' : 'Resolve before approval'}</div></div><div><ul class="adc-members">${servers || '<li>No configured destinations</li>'}</ul></div></article>`);
    }
    const unused = keys(data.clusters).filter(id => !keys(data.routes).some(r => data.routes[r].ClusterId === id));
    return `<section class="card card-spaced" id="adc-service-map"><h2 class="section-title">ADC service map</h2><p class="subtle">${dirty ? 'Unsaved draft' : 'Current configuration snapshot'} · HTTP routes → service groups → real server destinations. These are configuration objects, not confirmed listener VIPs, live health or physical network bindings.</p><div class="adc-service adc-map-head"><strong>HTTP virtual service (route)</strong><strong>Service group (cluster)</strong><strong>Real server destinations</strong></div>${services.join('') || '<p class="empty">No HTTP services configured.</p>'}<p class="subtle">Unreferenced groups: ${unused.length ? esc(unused.join(', ')) : 'None'}</p><div class="adc-map-actions">${actionBtn('Manage services', 'switch', 'routes')} ${actionBtn('Manage service groups', 'switch', 'clusters')} ${actionBtn('Manage real servers', 'switch', 'backends')} ${actionBtn('Inspect health', 'switch', 'health')}</div></section>`;
}
function overview(){let routes=keys(data.routes).slice(0,5).map(id=>`<div class="rowline"><div><b>${esc(id)}</b><div class="subtle mono">${esc(data.routes[id]?.Match?.Path||'—')}</div></div><span class="chip">${esc(data.routes[id]?.ClusterId||'—')}</span></div>`).join('')||'<div class="empty">No routes configured</div>';let nodes=destinationRows().slice(0,6).map(d=>`<div class="rowline"><div><b>${esc(d.did)}</b><div class="subtle mono">${esc(d.address)}</div></div><span class="chip ${d.enabled?'':'bad'}">${d.enabled?'Configured':'Disabled'}</span></div>`).join('')||'<div class="empty">No destinations configured</div>';return summary()+adcServiceMap()+`<div class="grid2"><div class="card"><div class="flex"><h2 class="section-title">Traffic architecture</h2><span class="chip">Design view</span></div><div class="arch"><div class="archnode">Clients / Public & internal ingress</div><div class="arrow">↓</div><div class="archnode">Firewall / upstream HA VIP</div><div class="arrow">↓</div><div class="archnode accent">${esc(topologyModeName(topologyResponse?.plan?.mode||'standalone'))} (design topology)</div><div class="arrow">↓</div><div class="twonodes"><div class="archnode">Backend node 01</div><div class="archnode">Backend node 02</div></div><div class="arrow">↓</div><div class="archnode">Application-specific data services (optional)</div></div><div class="healthbanner">This gateway is one running instance. The onboarding design is metadata, not proof that a gateway fleet, VIP or backend is healthy.</div></div><div><div class="card"><h2 class="section-title">Route snapshot</h2>${routes}${actionBtn('Manage routes','switch','routes')}</div><div class="card card-spaced"><h2 class="section-title">Destinations</h2>${nodes}${actionBtn('Manage backends','switch','backends')}</div></div></div>`}
function editApplicationAccess(id: string) {
    if (currentRole === 'Viewer' || !Object.prototype.hasOwnProperty.call(data.routes, id))
        return;
    const route = data.routes[id];
    const meta = route.Metadata || {};
    modal('Application access policy', 'Restrict this route using actual connection source networks and TLS. Forwarded headers are not trusted. This is not user authentication. Empty allowlist permits all peers. Public asset compression is HTTP-only and excludes private or authenticated traffic. Method restrictions reject traffic on this selected route before forwarding.', [
        { name: 'tls', label: 'Require HTTPS', value: meta['ADC.Access.RequireHttps'] || 'false', options: ['false', 'true'] },
        { name: 'networks', label: 'Allowed CIDRs (comma separated, optional)', value: meta['ADC.Access.AllowedNetworks'] || '', optional: true },
        { name: 'compression', label: 'Public HTTP asset compression', value: meta['ADC.Acceleration.PublicHttpCompression'] || 'false', options: ['false', 'true'] },
        { name: 'methods', label: 'Allowed HTTP methods (comma separated, optional)', value: meta['ADC.Traffic.AllowedMethods'] || '', optional: true }
    ], v => {
        const networks: string = v.networks.trim();
        if (!['true', 'false'].includes(v.tls) || networks.length > 2048 || (networks && (networks.split(',').length > 32 || networks.split(',').some(part => !/^[0-9a-fA-F:.]+\/[0-9]{1,3}$/.test(part.trim())))))
            throw Error('Use at most 32 IPv4/IPv6 CIDRs. The server validates address and prefix semantics.');
        if (!['true', 'false'].includes(v.compression) || (v.compression === 'true' && v.tls === 'true'))
            throw Error('Public HTTP compression cannot be combined with Require HTTPS.');
        const methods: string = v.methods.trim();
        const allowed = methods ? methods.split(',').map(method => method.trim()) : [];
        if (methods.length > 64 || allowed.length > 7 || new Set(allowed).size !== allowed.length || allowed.some(method => !['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'].includes(method)))
            throw Error('Use distinct uppercase HTTP methods: GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS.');
        const metadata = { ...meta };
        delete metadata['ADC.Traffic.AllowedMethods'];
        if (allowed.length)
            metadata['ADC.Traffic.AllowedMethods'] = allowed.join(',');
        delete metadata['ADC.Acceleration.PublicHttpCompression'];
        if (v.compression === 'true')
            metadata['ADC.Acceleration.PublicHttpCompression'] = 'true';
        delete metadata['ADC.Access.RequireHttps'];
        delete metadata['ADC.Access.AllowedNetworks'];
        if (v.tls === 'true')
            metadata['ADC.Access.RequireHttps'] = 'true';
        if (networks)
            metadata['ADC.Access.AllowedNetworks'] = networks;
        route.Metadata = metadata;
        edit();
    });
}
async function bindVirtualService(id: string) {
    if (currentRole === 'Viewer' || !Object.prototype.hasOwnProperty.call(data.routes, id))
        return;
    try {
        const result = await api('/admin/api/virtual-servers');
        const services: Obj[] = Array.isArray(result.services) ? result.services : [];
        const choices = ['(default)', ...services.map(s => String(s.id))];
        const old = data.routes[id].Metadata?.['ADC.VirtualServer.Id'] || '(default)';
        if (!choices.includes(old))
            return show('Existing virtual service is not locally provisioned. Ask the host administrator to restore the binding.', true);
        modal('Bind route to virtual service', 'Actual receiving socket; Host headers do not select the virtual service. ' + services.map(s => s.id + ': ' + s.protocol + ' ' + s.ip + ':' + s.port).join('; ') + '. Host IP and socket provisioning are external.', [{ name: 'service', label: 'Virtual service', value: old, options: choices }], v => {
            if (!choices.includes(v.service) || !Object.prototype.hasOwnProperty.call(data.routes, id))
                throw Error('Invalid route or virtual service.');
            const route = data.routes[id];
            const metadata = { ...(route.Metadata || {}) };
            if (v.service === '(default)')
                delete metadata['ADC.VirtualServer.Id'];
            else
                metadata['ADC.VirtualServer.Id'] = v.service;
            route.Metadata = metadata;
            edit();
        });
    }
    catch (error) {
        show(String(error), true);
    }
}
function routes(){const rows=keys(data.routes).map(id=>{const r=data.routes[id];return `<tr><td><b>${esc(id)}</b><div class="subtle">${esc(r.Metadata?.['ADC.VirtualServer.Id'] || 'Default listener')}</div></td><td class="mono">${esc((r.Match?.Hosts||[]).join(', ')||'Any host')}</td><td class="mono">${esc(r.Match?.Path)}</td><td>${esc(r.ClusterId)}</td><td>${actionBtn('Edit','route-edit',id)} ${currentRole==='Viewer'?'':actionBtn('Bind virtual service','route-bind-socket',id)+' '+actionBtn('Access policy','route-access',id)} ${actionBtn('Advanced','route-advanced',id)} ${actionBtn('Delete','route-delete',id,'danger-btn mini')}</td></tr>`}).join('');return `<div class="toolbar"><div><h2>Websites &amp; routes</h2><p class="subtle">A route matches the client hostname and path, then forwards to a backend group (cluster). Draft changes need approval.</p></div>${actionBtn('+ Add website / API','setup-simple-website','','primary')} ${actionBtn('Advanced: add route','route-add','')}</div><div class="tablewrap"><table><thead><tr><th>Route ID</th><th>Hosts</th><th>Path</th><th>Cluster</th><th>Actions</th></tr></thead><tbody>${rows||'<tr><td colspan="5" class="empty">No routes configured. Use Add website / API to create your first draft.</td></tr>'}</tbody></table></div>`}
const monitorSourceKey = 'ADC.HealthMonitorSource';
const compoundModeKey = 'ADC.Health.CompoundMode';
const compoundPathKey = 'ADC.Health.SecondaryPath';
function checkCompoundTarget(group: Obj) {
    if (group.HttpClient?.WebProxy || keys(group.Destinations || {}).some(key => !!group.Destinations[key].Health))
        throw Error('Compound health does not support web proxies or alternate destination health addresses.');
}
function monitorMembers(id: string) {
    return keys(data.clusters).filter(key => data.clusters[key].Metadata?.[monitorSourceKey] === id);
}
function applyMonitorSnapshot(source: Obj, target: Obj) {
    target.HealthCheck = { ...target.HealthCheck, Active: JSON.parse(JSON.stringify(source.HealthCheck.Active)) };
    const metadata = { ...(target.Metadata || {}) };
    for (const key of ['RiseFall.Rise', 'RiseFall.Fall', 'ConsecutiveFailuresHealthPolicy.Threshold', compoundModeKey, compoundPathKey]) {
        if (Object.prototype.hasOwnProperty.call(source.Metadata || {}, key))
            metadata[key] = source.Metadata[key];
        else
            delete metadata[key];
    }
    target.Metadata = metadata;
    if (metadata[compoundModeKey])
        target.HealthCheck.AvailableDestinationsPolicy = 'HealthyAndUnknown';
}
function unlinkActiveMonitor(id: string) {
    if (currentRole === 'Viewer' || !Object.prototype.hasOwnProperty.call(data.clusters, id))
        return;
    const target = data.clusters[id];
    if (!target.Metadata?.[monitorSourceKey])
        return;
    delete target.Metadata[monitorSourceKey];
    edit();
}
function editActiveMonitor(id: string) {
    if (currentRole === 'Viewer' || !Object.prototype.hasOwnProperty.call(data.clusters, id))
        return show('An authorized existing service group is required', true);
    const cluster = data.clusters[id];
    if (cluster.Metadata?.[monitorSourceKey])
        return show('Edit the source monitor or unlink this group first.', true);
    const old = cluster.HealthCheck?.Active || {};
    const meta = cluster.Metadata || {};
    const seconds = (value: string | undefined, fallback: string) => {
        const parsed = /^(\d{2}):(\d{2}):(\d{2})$/.exec(String(value || ''));
        return parsed ? String(Number(parsed[1]) * 3600 + Number(parsed[2]) * 60 + Number(parsed[3])) : fallback;
    };
    modal('HTTP health monitor', 'Choose actual application readiness. This edits the group draft; it does not probe or deploy. TCP is mandatory in compound mode; AND requires both HTTP checks and OR requires at least one. Passive checks remain unchanged.', [
        { name: 'enabled', label: 'Enable active monitor', value: String(!!old.Enabled), options: ['true', 'false'] },
        { name: 'path', label: 'Readiness path', value: old.Path || '/health/ready' },
        { name: 'interval', label: 'Probe interval (seconds, 1–60)', value: seconds(old.Interval, '15') },
        { name: 'timeout', label: 'Probe timeout (seconds, 1–60)', value: seconds(old.Timeout, '5') },
        { name: 'policy', label: 'Failure / recovery policy', value: old.Policy || 'ConsecutiveFailures', options: ['ConsecutiveFailures', 'RiseFall'] },
        { name: 'fall', label: 'Consecutive failures (1–10)', value: String(old.Policy === 'RiseFall' ? meta['RiseFall.Fall'] || '3' : meta['ConsecutiveFailuresHealthPolicy.Threshold'] || '3') },
        { name: 'rise', label: 'Consecutive successes for RiseFall (1–10)', value: String(meta['RiseFall.Rise'] || '2') },
        { name: 'compound', label: 'Active compound mode', value: meta[compoundModeKey] || 'off', options: ['off', 'AND', 'OR'] },
        { name: 'secondary', label: 'Secondary HTTP readiness path (compound mode)', value: meta[compoundPathKey] || '/health/dependencies', optional: true }
    ], v => {
        const bounded = (raw: string, max: number) => /^\d{1,2}$/.test(raw) && Number(raw) >= 1 && Number(raw) <= max;
        if (!bounded(v.interval, 60) || !bounded(v.timeout, 60) || Number(v.timeout) > Number(v.interval) || !bounded(v.rise, 10) || !bounded(v.fall, 10))
            throw Error('Use bounded whole seconds, timeout no greater than interval, and 1–10 thresholds.');
        if (!v.path.startsWith('/') || v.path.length > 300 || v.path.includes('\\') || /[\r\n]/.test(v.path))
            throw Error('Invalid readiness path.');
        if (monitorMembers(id).length && v.enabled !== 'true')
            throw Error('Unlink dependent groups before disabling this source monitor.');
        if (cluster.LoadBalancingPolicy === 'PrimaryBackup' && v.enabled !== 'true')
            throw Error('PrimaryBackup requires active health checks.');
        if (!['ConsecutiveFailures', 'RiseFall'].includes(v.policy))
            throw Error('Unsupported health policy.');
        if (!['off', 'AND', 'OR'].includes(v.compound))
            throw Error('Unsupported compound mode.');
        if (v.compound !== 'off') {
            const valid = (path: string) => path.startsWith('/') && !path.startsWith('//') && path.length <= 300 && !path.includes('\\') && !path.includes('#') && !/[\x00-\x1f\x7f]/.test(path);
            if (v.enabled !== 'true' || !valid(v.path) || !valid(v.secondary) || v.path === v.secondary)
                throw Error('Compound monitoring requires active checks and two distinct same-origin readiness paths.');
            checkCompoundTarget(cluster);
            for (const member of monitorMembers(id))
                checkCompoundTarget(data.clusters[member]);
        }
        const duration = (raw: string) => '00:' + String(Math.floor(Number(raw) / 60)).padStart(2, '0') + ':' + String(Number(raw) % 60).padStart(2, '0');
        cluster.HealthCheck = { ...cluster.HealthCheck, Active: { ...old, Enabled: v.enabled === 'true', Path: v.path, Interval: duration(v.interval), Timeout: duration(v.timeout), Policy: v.policy } };
        cluster.Metadata = { ...meta, 'RiseFall.Rise': v.rise, 'RiseFall.Fall': v.fall, 'ConsecutiveFailuresHealthPolicy.Threshold': v.fall };
        if (v.compound === 'off') {
            delete cluster.Metadata[compoundModeKey];
            delete cluster.Metadata[compoundPathKey];
        }
        else {
            cluster.Metadata[compoundModeKey] = v.compound;
            cluster.Metadata[compoundPathKey] = v.secondary;
            cluster.HealthCheck.AvailableDestinationsPolicy = 'HealthyAndUnknown';
        }
        for (const member of monitorMembers(id))
            applyMonitorSnapshot(cluster, data.clusters[member]);
        edit();
    });
}
function copyActiveMonitor(id: string) {
    if (currentRole === 'Viewer' || !Object.prototype.hasOwnProperty.call(data.clusters, id))
        return show('An authorized existing service group is required', true);
    if (monitorMembers(id).length)
        return show('Unlink dependent groups before assigning this source to another monitor.', true);
    const candidates = keys(data.clusters).filter(key => key !== id && !data.clusters[key].Metadata?.[monitorSourceKey] && data.clusters[key].HealthCheck?.Active?.Enabled === true && ['ConsecutiveFailures', 'RiseFall'].includes(data.clusters[key].HealthCheck.Active.Policy));
    if (!candidates.length)
        return show('No other group has an enabled supported HTTP monitor.', true);
    modal('Reuse existing HTTP monitor', 'Choose a source group. A linked monitor follows source edits in the reviewed draft; a copy is independent. Verify readiness on every target server.', [{ name: 'source', label: 'Source service group', value: candidates[0], options: candidates }, { name: 'mode', label: 'Reuse mode', value: 'copy', options: ['copy', 'linked'] }], v => {
        if (!candidates.includes(v.source) || !Object.prototype.hasOwnProperty.call(data.clusters, id))
            throw Error('Invalid monitor source.');
        const source = data.clusters[v.source];
        const target = data.clusters[id];
        if (!source?.HealthCheck?.Active?.Enabled || source.Metadata?.[monitorSourceKey] || monitorMembers(id).length)
            throw Error('Invalid or changed monitor source.');
        if (!['copy', 'linked'].includes(v.mode))
            throw Error('Invalid reuse mode.');
        if (source.Metadata?.[compoundModeKey])
            checkCompoundTarget(target);
        applyMonitorSnapshot(source, target);
        if (v.mode === 'linked')
            target.Metadata[monitorSourceKey] = v.source;
        else
            delete target.Metadata[monitorSourceKey];
        edit();
    });
}
function editMonitorProfile(id: string = '') {
    if (currentRole === 'Viewer')
        return;
    const profiles = data.monitorProfiles || {};
    const old = id ? profiles[id] : undefined;
    if (id && !Object.prototype.hasOwnProperty.call(profiles, id))
        return show('Profile not found.', true);
    const active = old?.Active || {};
    const meta = old?.Metadata || {};
    const seconds = (value: string | undefined, fallback: string) => {
        const m = /^(\d{2}):(\d{2}):(\d{2})$/.exec(String(value || ''));
        return m ? String(Number(m[1]) * 3600 + Number(m[2]) * 60 + Number(m[3])) : fallback;
    };
    modal(id ? 'Edit monitor profile' : 'Create monitor profile', 'Reusable independent template. Assign it to a backend group explicitly; editing or deleting a template does not change existing assignments.', [
        { name: 'id', label: 'Profile ID (cannot rename)', value: id },
        { name: 'path', label: 'Primary readiness path', value: active.Path || '/health/ready' },
        { name: 'interval', label: 'Interval in seconds (1–60)', value: seconds(active.Interval, '15') },
        { name: 'timeout', label: 'Timeout in seconds (1–60)', value: seconds(active.Timeout, '5') },
        { name: 'policy', label: 'Health policy', value: active.Policy || 'RiseFall', options: ['RiseFall', 'ConsecutiveFailures'] },
        { name: 'rise', label: 'Rise threshold (1–10)', value: meta['RiseFall.Rise'] || '2' },
        { name: 'fall', label: 'Fall threshold (1–10)', value: meta['RiseFall.Fall'] || meta['ConsecutiveFailuresHealthPolicy.Threshold'] || '3' },
        { name: 'compound', label: 'Active compound mode', value: meta[compoundModeKey] || 'off', options: ['off', 'AND', 'OR'] },
        { name: 'secondary', label: 'Secondary readiness path', value: meta[compoundPathKey] || '/health/dependencies', optional: true }
    ], v => {
        if (!validId(v.id) || (id && v.id !== id) || keys(profiles).some(key => key !== id && key.toLowerCase() === v.id.toLowerCase()))
            throw Error('Use a unique profile ID; renaming is not supported.');
        if (!id && keys(profiles).length >= 100)
            throw Error('At most 100 monitor profiles are supported.');
        const bounded = (raw: string, max: number) => /^\d{1,2}$/.test(raw) && Number(raw) >= 1 && Number(raw) <= max;
        if (!bounded(v.interval, 60) || !bounded(v.timeout, 60) || Number(v.timeout) > Number(v.interval) || !bounded(v.rise, 10) || !bounded(v.fall, 10))
            throw Error('Use bounded whole seconds and thresholds; timeout cannot exceed interval.');
        const valid = (path: string) => path.startsWith('/') && !path.startsWith('//') && path.length <= 300 && !path.includes('\\') && !path.includes('#') && !/[\x00-\x1f\x7f]/.test(path);
        if (!valid(v.path) || !['RiseFall', 'ConsecutiveFailures'].includes(v.policy) || !['off', 'AND', 'OR'].includes(v.compound))
            throw Error('Invalid readiness path or policy.');
        if (v.compound !== 'off' && (!valid(v.secondary) || v.secondary === v.path))
            throw Error('Compound mode requires a distinct secondary readiness path.');
        const duration = (raw: string) => '00:' + String(Math.floor(Number(raw) / 60)).padStart(2, '0') + ':' + String(Number(raw) % 60).padStart(2, '0');
        const metadata: Obj = { 'RiseFall.Rise': String(Number(v.rise)), 'RiseFall.Fall': String(Number(v.fall)), 'ConsecutiveFailuresHealthPolicy.Threshold': String(Number(v.fall)) };
        if (v.compound !== 'off') {
            metadata[compoundModeKey] = v.compound;
            metadata[compoundPathKey] = v.secondary;
        }
        data.monitorProfiles = { ...profiles, [v.id]: { Active: { Enabled: true, Path: v.path, Interval: duration(v.interval), Timeout: duration(v.timeout), Policy: v.policy }, Metadata: metadata } };
        edit();
    });
}
function deleteMonitorProfile(id: string) {
    if (currentRole === 'Viewer' || !Object.prototype.hasOwnProperty.call(data.monitorProfiles || {}, id))
        return;
    if (keys(data.serviceGroups || {}).some(key => data.serviceGroups?.[key].MonitorProfile === id))
        return show('Remove this monitor from service group templates first.', true);
    if (!confirm('Delete reusable profile ' + id + '? Existing assigned snapshots remain unchanged.'))
        return;
    const profiles = { ...data.monitorProfiles };
    delete profiles[id];
    data.monitorProfiles = profiles;
    edit();
}
function assignMonitorProfile(id: string) {
    if (currentRole === 'Viewer' || !Object.prototype.hasOwnProperty.call(data.clusters, id))
        return;
    const target = data.clusters[id];
    if (target.Metadata?.[monitorSourceKey])
        return show('Unlink this group before assigning an independent profile.', true);
    const profiles = data.monitorProfiles || {};
    const choices = keys(profiles);
    if (!choices.length)
        return show('Create a reusable monitor profile first.', true);
    modal('Assign monitor profile', 'Copies an independent snapshot to this group and its linked dependents in the draft. Future template edits will not alter this assignment.', [{ name: 'profile', label: 'Reusable monitor profile', value: choices[0], options: choices }], v => {
        if (!choices.includes(v.profile) || !Object.prototype.hasOwnProperty.call(profiles, v.profile))
            throw Error('Invalid profile.');
        const profile = profiles[v.profile];
        const members = monitorMembers(id);
        if (profile.Metadata?.[compoundModeKey]) {
            checkCompoundTarget(target);
            for (const member of members)
                checkCompoundTarget(data.clusters[member]);
        }
        const source = { HealthCheck: { Active: profile.Active }, Metadata: profile.Metadata };
        applyMonitorSnapshot(source, target);
        for (const member of members)
            applyMonitorSnapshot(source, data.clusters[member]);
        edit();
    });
}
function monitorRegistryPanel() {
    const profiles = data.monitorProfiles || {};
    const rows = keys(profiles).map(id => {
        const p = profiles[id];
        return `<tr><td>${esc(id)}</td><td>${esc(p.Active?.Path || '—')}</td><td>${esc(p.Metadata?.[compoundModeKey] || 'HTTP')}</td><td>${esc(p.Active?.Interval || '—')} / ${esc(p.Active?.Timeout || '—')}</td><td>${currentRole === 'Viewer' ? '' : actionBtn('Edit profile', 'profile-edit', id) + ' ' + actionBtn('Delete profile', 'profile-delete', id, 'danger-btn mini')}</td></tr>`;
    }).join('');
    return `<div class="card"><div class="toolbar"><div><h2>Reusable monitor profiles</h2><p class="subtle">Independent templates; assign a snapshot to a service group. All changes require approval.</p></div>${currentRole === 'Viewer' ? '' : actionBtn('+ Create monitor profile', 'profile-add', '')}</div><div class="tablewrap"><table><thead><tr><th>Profile</th><th>Readiness path</th><th>Mode</th><th>Interval / timeout</th><th>Actions</th></tr></thead><tbody>${rows || '<tr><td colspan="5">No reusable profiles</td></tr>'}</tbody></table></div></div>`;
}
const serviceGroupPolicies = ['RoundRobin', 'WeightedRoundRobin', 'WeightedRandom', 'LeastRequests', 'WeightedLeastRequests', 'FastestResponse', 'SourceIpHash', 'PrimaryBackup'];
function editServiceGroup(id: string = '') {
    if (currentRole === 'Viewer')
        return;
    const templates = data.serviceGroups || {};
    const old = id ? templates[id] : undefined;
    if (id && !Object.prototype.hasOwnProperty.call(templates, id))
        return;
    const servers = keys(data.realServers || {});
    if (!servers.length)
        return show('Create reusable real servers first.', true);
    const profiles = ['(none)', ...keys(data.monitorProfiles || {})];
    modal(id ? 'Edit service group template' : 'Create service group template', 'Choose a policy, monitor and initial member. Add more members after saving. Existing runtime groups are not updated automatically.', [
        { name: 'id', label: 'Template ID (cannot rename)', value: id },
        { name: 'policy', label: 'Load balancing policy', value: old?.Policy || 'RoundRobin', options: serviceGroupPolicies },
        { name: 'monitor', label: 'Monitor profile', value: old?.MonitorProfile || '(none)', options: profiles },
        { name: 'server', label: 'Initial or additional member', value: keys(old?.Members || {})[0] || servers[0], options: servers }
    ], v => {
        if (!validId(v.id) || (id && id !== v.id) || keys(templates).some(key => key !== id && key.toLowerCase() === v.id.toLowerCase()) || (!id && keys(templates).length >= 100))
            throw Error('Use a unique template ID; at most 100 templates.');
        if (!serviceGroupPolicies.includes(v.policy) || !profiles.includes(v.monitor) || !servers.includes(v.server) || (v.policy === 'PrimaryBackup' && v.monitor === '(none)'))
            throw Error('Invalid policy, member or monitor. PrimaryBackup requires a monitor.');
        const members = { ...(old?.Members || {}) };
        if (!Object.prototype.hasOwnProperty.call(members, v.server))
            Object.defineProperty(members, v.server, { value: { Weight: '1', TrafficRole: 'primary' }, enumerable: true, writable: true, configurable: true });
        if (keys(members).length > 40 || (v.policy === 'PrimaryBackup' && !keys(members).some(key => members[key].TrafficRole === 'primary')))
            throw Error('Maximum 40 members; PrimaryBackup requires a primary.');
        data.serviceGroups = { ...templates, [v.id]: { Policy: v.policy, MonitorProfile: v.monitor === '(none)' ? '' : v.monitor, Members: members } };
        edit();
    });
}
function editServiceGroupMember(id: string) {
    if (currentRole === 'Viewer' || !Object.prototype.hasOwnProperty.call(data.serviceGroups || {}, id))
        return;
    const template = data.serviceGroups?.[id];
    const servers = keys(data.realServers || {});
    const members = template.Members || {};
    modal('Manage service group members', 'Add or update an existing member, or explicitly remove it. Changes affect the template only.', [
        { name: 'server', label: 'Real server', value: keys(members)[0], options: servers },
        { name: 'operation', label: 'Action', value: 'upsert', options: ['upsert', 'remove'] },
        { name: 'weight', label: 'Weight (1–100)', value: '1' },
        { name: 'role', label: 'Traffic role', value: 'primary', options: ['primary', 'backup'] }
    ], v => {
        if (!servers.includes(v.server) || !['upsert', 'remove'].includes(v.operation))
            throw Error('Invalid server or action.');
        const next = { ...members };
        if (v.operation === 'remove') {
            if (!Object.prototype.hasOwnProperty.call(next, v.server))
                throw Error('Server is not a member.');
            delete next[v.server];
        }
        else {
            if (!/^(?:[1-9]|[1-9][0-9]|100)$/.test(v.weight) || !['primary', 'backup'].includes(v.role))
                throw Error('Invalid weight or role.');
            Object.defineProperty(next, v.server, { value: { Weight: v.weight, TrafficRole: v.role }, enumerable: true, writable: true, configurable: true });
        }
        if (!keys(next).length || keys(next).length > 40 || (template.Policy === 'PrimaryBackup' && !keys(next).some(key => next[key].TrafficRole === 'primary')))
            throw Error('Keep 1–40 members and at least one primary for PrimaryBackup.');
        template.Members = next;
        edit();
    });
}
function deleteServiceGroup(id: string) {
    if (currentRole === 'Viewer' || !Object.prototype.hasOwnProperty.call(data.serviceGroups || {}, id))
        return;
    if (!confirm('Delete service group template ' + id + '? Existing runtime groups remain unchanged.'))
        return;
    const templates = { ...data.serviceGroups };
    delete templates[id];
    data.serviceGroups = templates;
    edit();
}
function deployServiceGroup(id: string) {
    if (currentRole === 'Viewer' || !Object.prototype.hasOwnProperty.call(data.serviceGroups || {}, id))
        return;
    const template = data.serviceGroups?.[id];
    modal('Create backend group from template', 'Creates a separate backend group in the draft. Attach a route and submit for independent approval. Existing groups cannot be overwritten.', [{ name: 'id', label: 'New backend group ID', value: id + '-pool' }], v => {
        if (!validId(v.id) || keys(data.clusters).some(key => key.toLowerCase() === v.id.toLowerCase()) || keys(data.clusters).length >= 100)
            throw Error('Choose a new backend group ID.');
        const destinations: Obj = {};
        for (const serverId of keys(template.Members)) {
            const server = data.realServers?.[serverId];
            if (!server || !validCatalogOrigin(server.Address))
                throw Error('Missing or invalid real server: ' + serverId);
            const member = template.Members[serverId];
            Object.defineProperty(destinations, serverId, { value: { Address: server.Address, Metadata: { Weight: member.Weight, TrafficRole: member.TrafficRole, TrafficState: 'active' } }, enumerable: true, writable: true, configurable: true });
        }
        const group: Obj = { LoadBalancingPolicy: template.Policy, Destinations: destinations };
        if (template.MonitorProfile) {
            const profile = data.monitorProfiles?.[template.MonitorProfile];
            if (!profile)
                throw Error('Referenced monitor profile is missing.');
            applyMonitorSnapshot({ HealthCheck: { Active: profile.Active }, Metadata: profile.Metadata }, group);
        }
        data.clusters = { ...data.clusters, [v.id]: group };
        edit();
    });
}
function serviceGroupPanel() {
    const templates = data.serviceGroups || {};
    const rows = keys(templates).map(id => {
        const group = templates[id];
        return `<tr><td>${esc(id)}</td><td>${esc(group.Policy)}</td><td>${esc(group.MonitorProfile || 'None')}</td><td>${keys(group.Members).map(key => esc(key + ' · ' + group.Members[key].Weight + ' · ' + group.Members[key].TrafficRole)).join('<br>')}</td><td>${currentRole === 'Viewer' ? '' : actionBtn('Create backend group', 'service-group-deploy', id) + ' ' + actionBtn('Edit template', 'service-group-edit', id) + ' ' + actionBtn('Manage members', 'service-group-members', id) + ' ' + actionBtn('Delete template', 'service-group-delete', id, 'danger-btn mini')}</td></tr>`;
    }).join('');
    return `<div class="card"><div class="toolbar"><div><h2>Reusable service group templates</h2><p class="subtle">Combine real servers, weights, roles and a monitor. Create an independent backend group from a template.</p></div>${currentRole === 'Viewer' ? '' : actionBtn('+ Create service group template', 'service-group-add', '')}</div><div class="tablewrap"><table><thead><tr><th>Template</th><th>Policy</th><th>Monitor</th><th>Members</th><th>Actions</th></tr></thead><tbody>${rows || '<tr><td colspan="5">No reusable service groups</td></tr>'}</tbody></table></div></div>`;
}
function editSecurePersistence(id: string) {
    if (currentRole === 'Viewer' || !Object.prototype.hasOwnProperty.call(data.clusters, id))
        return;
    const cluster = data.clusters[id];
    const affinity = cluster.SessionAffinity || {};
    const enabled = cluster.Metadata?.['ADC.Persistence.Profile'] === 'SecureCookie';
    const parseMinutes = (value: string) => {
        const m = /^(?:(\d+)\.)?(\d{2}):(\d{2}):00$/.exec(value);
        return m ? String(Number(m[1] || 0) * 1440 + Number(m[2]) * 60 + Number(m[3])) : '30';
    };
    modal('HTTPS session persistence', 'Native encrypted affinity cookie. Requires HTTPS; not authentication. Expiry is enforced by the gateway and browser. Select explicit failover behavior. This replaces the existing affinity configuration when applied.', [
        { name: 'mode', label: 'Persistence mode', value: enabled ? 'SecureCookie' : 'off', options: ['off', 'SecureCookie'] },
        { name: 'failure', label: 'When selected destination is unavailable', value: affinity.FailurePolicy === 'Return503Error' ? 'Return503Error' : 'Redistribute', options: ['Redistribute', 'Return503Error'] },
        { name: 'minutes', label: 'Cookie lifetime (1–1440 minutes)', value: parseMinutes(String(affinity.Cookie?.MaxAge || '00:30:00')) },
        { name: 'sameSite', label: 'SameSite policy', value: affinity.Cookie?.SameSite === 'Strict' ? 'Strict' : 'Lax', options: ['Lax', 'Strict'] }
    ], v => {
        if (!['off', 'SecureCookie'].includes(v.mode) || !['Redistribute', 'Return503Error'].includes(v.failure) || !['Lax', 'Strict'].includes(v.sameSite) || !/^\d{1,4}$/.test(v.minutes) || Number(v.minutes) < 1 || Number(v.minutes) > 1440)
            throw Error('Invalid persistence policy or cookie lifetime.');
        const metadata = { ...(cluster.Metadata || {}) };
        if (v.mode === 'off') {
            delete metadata['ADC.Persistence.Profile'];
            cluster.SessionAffinity = { Enabled: false };
        }
        else {
            const total = Number(v.minutes);
            const age = (total === 1440 ? '1.' : '') + String(Math.floor(total % 1440 / 60)).padStart(2, '0') + ':' + String(total % 60).padStart(2, '0') + ':00';
            metadata['ADC.Persistence.Profile'] = 'SecureCookie';
            cluster.SessionAffinity = { Enabled: true, Policy: 'GatewayCoreExpiringCookie', FailurePolicy: v.failure, AffinityKeyName: '__Host-GatewayCore-' + id, Cookie: { Path: '/', HttpOnly: true, SecurePolicy: 'Always', SameSite: v.sameSite, MaxAge: age } };
        }
        cluster.Metadata = metadata;
        edit();
    });
}
function clusters(){const rows=keys(data.clusters).map(id=>{const c=data.clusters[id];const active=!!c.HealthCheck?.Active?.Enabled,passive=!!c.HealthCheck?.Passive?.Enabled;const health=active&&passive?'<span class="chip good">Active + passive</span>':active?'<span class="chip good">Active</span>':passive?'<span class="chip warn">Passive only</span>':'<span class="chip">Disabled</span>';return `<tr><td><b>${esc(id)}</b></td><td>${esc(c.LoadBalancingPolicy||'Default')}</td><td>${keys(c.Destinations||{}).length}</td><td>${health}${c.Metadata?.[monitorSourceKey]?`<div class="subtle">Linked to ${esc(c.Metadata[monitorSourceKey])}</div>`:""}</td><td>${actionBtn('Edit','cluster-edit',id)} ${currentRole==='Viewer'?'':actionBtn('Health monitor','monitor-edit',id)+' '+actionBtn('Reuse monitor','monitor-copy',id)+' '+actionBtn('Assign profile','profile-assign',id)+' '+actionBtn('Persistence','persistence-edit',id)+(c.Metadata?.[monitorSourceKey]?' '+actionBtn('Unlink monitor','monitor-unlink',id):'')} ${actionBtn('Advanced','cluster-advanced',id)} ${actionBtn('Delete','cluster-delete',id,'danger-btn mini')}</td></tr>`}).join('');return `<div class="toolbar"><div><h2>Backend groups (clusters)</h2><p class="subtle">A group contains the servers for one application and defines traffic distribution. Use the policy guide below.</p></div>${actionBtn('+ Add cluster','cluster-add','')}</div><div class="tablewrap"><table><thead><tr><th>Cluster</th><th>Policy</th><th>Active backends</th><th>Health checks</th><th>Actions</th></tr></thead><tbody>${rows||'<tr><td colspan="5" class="empty">No clusters configured</td></tr>'}</tbody></table></div>${policyReference()}${monitorRegistryPanel()}${serviceGroupPanel()}`}
function validCatalogOrigin(value: string) {
    try {
        const uri = new URL(value);
        return value.length <= 2048 && /^https?:\/\//i.test(value) && value.endsWith('/') && !/[\s\\?#]/.test(value) && !!uri.hostname && !uri.username && !uri.password;
    }
    catch {
        return false;
    }
}
function editRealServer(id: string = '') {
    if (currentRole === 'Viewer')
        return;
    const servers = data.realServers || {};
    const old = id ? servers[id] : undefined;
    if (id && !Object.prototype.hasOwnProperty.call(servers, id))
        return show('Server not found.', true);
    modal(id ? 'Edit real server' : 'Create real server', 'A reusable origin template. Existing destination snapshots are not changed when this template changes.', [
        { name: 'id', label: 'Real server ID (cannot rename)', value: id },
        { name: 'address', label: 'HTTP(S) origin URL ending in /', value: old?.Address || 'https://app.internal.example.com/' },
        { name: 'description', label: 'Description (optional)', value: old?.Description || '', optional: true }
    ], v => {
        if (!validId(v.id) || (id && v.id !== id) || keys(servers).some(key => key !== id && key.toLowerCase() === v.id.toLowerCase()))
            throw Error('Use a unique server ID; renaming is not supported.');
        if (!id && keys(servers).length >= 200)
            throw Error('At most 200 real servers are supported.');
        if (!validCatalogOrigin(v.address) || v.description.length > 250 || /[\x00-\x1f\x7f]/.test(v.description))
            throw Error('Invalid origin URL or description. No credentials, query, fragment or control characters.');
        data.realServers = { ...servers, [v.id]: { Address: v.address, Description: v.description } };
        edit();
    });
}
function deleteRealServer(id: string) {
    if (currentRole === 'Viewer' || !Object.prototype.hasOwnProperty.call(data.realServers || {}, id))
        return;
    if (keys(data.serviceGroups || {}).some(key => Object.prototype.hasOwnProperty.call(data.serviceGroups?.[key].Members || {}, id)))
        return show('Remove this server from service group templates first.', true);
    if (!confirm('Delete real server template ' + id + '? Existing destinations remain unchanged.'))
        return;
    const servers = { ...data.realServers };
    delete servers[id];
    data.realServers = servers;
    edit();
}
function assignRealServer(id: string) {
    if (currentRole === 'Viewer' || !Object.prototype.hasOwnProperty.call(data.realServers || {}, id))
        return;
    const groups = keys(data.clusters);
    if (!groups.length)
        return show('Create a backend group first.', true);
    const server = data.realServers?.[id];
    modal('Assign real server', 'Create a destination snapshot with its own weight and role. Existing destinations cannot be overwritten.', [
        { name: 'cluster', label: 'Backend group', value: groups[0], options: groups },
        { name: 'id', label: 'Destination ID', value: id },
        { name: 'weight', label: 'Weight (1–100)', value: '1' },
        { name: 'role', label: 'Traffic role', value: 'primary', options: ['primary', 'backup'] }
    ], v => {
        if (!groups.includes(v.cluster) || !Object.prototype.hasOwnProperty.call(data.clusters, v.cluster) || !validId(v.id) || !/^(?:[1-9]|[1-9][0-9]|100)$/.test(v.weight) || !['primary', 'backup'].includes(v.role) || !validCatalogOrigin(server.Address))
            throw Error('Invalid destination, weight, role or server address.');
        const group = data.clusters[v.cluster];
        const destinations = group.Destinations || {};
        if (keys(destinations).length >= 40 || keys(destinations).some(key => key.toLowerCase() === v.id.toLowerCase()) || keys(data.disabled).some(key => key.toLowerCase() === (v.cluster + '::' + v.id).toLowerCase()))
            throw Error('Destination already exists or group capacity is reached.');
        group.Destinations = { ...destinations, [v.id]: { Address: server.Address, Metadata: { Weight: v.weight, TrafficRole: v.role, TrafficState: 'active' } } };
        edit();
    });
}
function realServerPanel() {
    const servers = data.realServers || {};
    const rows = keys(servers).map(id => {
        const server = servers[id];
        return `<tr><td>${esc(id)}</td><td class="mono">${esc(server.Address)}</td><td>${esc(server.Description || '—')}</td><td>${currentRole === 'Viewer' ? '' : actionBtn('Assign server', 'real-server-assign', id) + ' ' + actionBtn('Edit server', 'real-server-edit', id) + ' ' + actionBtn('Delete server', 'real-server-delete', id, 'danger-btn mini')}</td></tr>`;
    }).join('');
    return `<div class="card"><div class="toolbar"><div><h2>Reusable real servers</h2><p class="subtle">Create origin templates once and assign independent destination snapshots to backend groups. Approval required.</p></div>${currentRole === 'Viewer' ? '' : actionBtn('+ Create real server', 'real-server-add', '')}</div><div class="tablewrap"><table><thead><tr><th>Server ID</th><th>Origin URL</th><th>Description</th><th>Actions</th></tr></thead><tbody>${rows || '<tr><td colspan="4">No reusable real servers</td></tr>'}</tbody></table></div></div>`;
}
function backends(){const rows=destinationRows().map(d=>{const live=liveDestinationHealth?.find(x=>x.clusterId===d.cid&&x.destinationId===d.did);const configuredState=!d.enabled?'Disabled':d.trafficState==='draining'?'Draining':'Active';const stateClass=configuredState==='Active'?'good':configuredState==='Draining'?'warn':'bad';const runtime=live?`<span class="chip">A: ${esc(live.activeHealth||'Unknown')}</span> <span class="chip">P: ${esc(live.passiveHealth||'Unknown')}</span><div class="subtle">In-flight: ${esc(String(live.concurrentRequests??'—'))}</div>`:'<span class="subtle">Not inspected</span>';const drainButton=d.enabled?actionBtn(d.trafficState==='draining'?'Restore traffic':'Drain new traffic','dest-drain',d.cid+'::'+d.did):'';return `<tr><td><b>${esc(d.did)}</b><div class="subtle">${esc(d.cid)} · weight ${esc(d.weight)} · ${esc(d.trafficRole)}</div></td><td class="mono">${esc(d.address)}</td><td><span class="chip ${stateClass}">${configuredState}</span><div class="subtle">Configured draft state; runtime health shown separately</div></td><td>${runtime}<div>${drainButton} ${actionBtn(d.enabled?'Disable':'Enable','dest-toggle',d.cid+'::'+d.did)} ${actionBtn('Edit','dest-edit',d.cid+'::'+d.did)} ${actionBtn('Advanced','dest-advanced',d.cid+'::'+d.did)} ${actionBtn('Delete','dest-delete',d.cid+'::'+d.did,'danger-btn mini')}</div></td></tr>`}).join('');const liveNote=liveDestinationHealth?`<p class="subtle">Live YARP snapshot checked ${esc(liveDestinationHealthAt)} · single local process. Unsaved changes do not affect this runtime snapshot.</p>`:'<p class="subtle">Runtime health has not been inspected in this session.</p>';return `<div class="toolbar"><div><h2>Backend servers (destinations)</h2><p class="subtle">Each application route points to its own cluster. Runtime health is per gateway; draining is a reviewed configuration change.</p></div>${actionBtn('Inspect live health','runtime-health','')} ${actionBtn('+ Add backend','dest-add','')}</div>${liveNote}<div class="tablewrap"><table><thead><tr><th>Destination / pool</th><th>Address</th><th>Traffic state</th><th>Runtime health and actions</th></tr></thead><tbody>${rows||'<tr><td colspan="4" class="empty">No backend servers. Add a website first, or add a server to an existing backend group.</td></tr>'}</tbody></table></div><div class="healthbanner">Drain removes a destination from new-request selection after an approved config rollout; in-flight requests continue. A host match separates routes, but private API access still requires a restricted listener and firewall policy. Runtime health is an authenticated, point-in-time view of this process only.</div>${realServerPanel()}`}
async function refreshDestinationRuntime(){try{const r=await api('/admin/api/runtime/destinations');const clusters=Array.isArray(r.clusters)?r.clusters as Obj[]:[];liveDestinationHealth=clusters.flatMap((cluster:Obj)=>Array.isArray(cluster.destinations)?(cluster.destinations as Obj[]).map(destination=>({...destination,clusterId:String(cluster.clusterId||'')})):[]);liveDestinationHealthAt=String(r.timestampUtc||'unknown');if(view==='backends')render();show('Live local YARP health snapshot loaded. Unknown remains distinct from healthy.')}catch(e){show('Could not inspect live local YARP health: '+String(e),true)}}
function health(){const p=probes.map(d=>`<tr><td>${esc(d.cluster)} / ${esc(d.destination)}</td><td class="mono">${esc(d.address)}</td><td><span class="chip ${d.status==='reachable'?'good':'bad'}">${esc(d.status)}</span></td><td>${esc(d.httpStatus??'—')}</td></tr>`).join('');return `<div class="toolbar"><div><h2>On-demand backend probes</h2><p class="subtle">Sends GET to the configured health-check path with a 3-second timeout.</p></div>${actionBtn('Run probes now','probe','')}</div><div class="healthbanner">This is an on-demand HTTP connectivity check, NOT YARP's internal destination health state, and not transaction readiness validation. Use HTTPS with trusted certificates for CA services.</div><div class="tablewrap table-spaced"><table><thead><tr><th>Backend</th><th>Destination URL</th><th>Probe</th><th>HTTP</th></tr></thead><tbody>${p||'<tr><td colspan="4" class="empty">No probes run yet. Select Run probes now to check saved backend endpoints.</td></tr>'}</tbody></table></div>`}
async function backups(){try{const [b,a]=await Promise.all([api('/admin/api/backups'),api('/admin/api/audit')]);const bs=b.map((name:string)=>`<div class="rowline"><span class="mono">${esc(name)}</span>${actionBtn('Restore','restore',name)}</div>`).join('')||'<div class="empty">No saved backups yet. Review the installation backup and recovery guide before changing configuration.</div>';const audit=a.map((o:Obj)=>`<div class="rowline"><div><b>${esc(o.action)}</b><div class="subtle">${esc(o.timeUtc)}</div></div><span class="chip">${esc(o.backup||o.restored||'—')}</span></div>`).join('')||'<div class="empty">No audit entries</div>';$('content').innerHTML=`<div class="grid2"><div class="card"><h2 class="section-title">Configuration backups</h2>${bs}</div><div class="card"><h2 class="section-title">Recent local audit events</h2>${audit}</div></div>`}catch(e){show(String(e),true)}}

function changeReview(r: Obj) {
    const payload = r.payload || {};
    const routes = payload.routes || {};
    const groups = payload.clusters || {};
    const routeRows = keys(routes).map(id => {
        const route = routes[id];
        return `<tr><td>${esc(id)}</td><td>${esc((route.Match?.Hosts || []).join(', ') || 'Any host')}</td><td>${esc(route.Match?.Path || '—')}</td><td>${esc(route.ClusterId || '—')}</td></tr>`;
    }).join('');
    const groupRows = keys(groups).map(id => {
        const group = groups[id];
        return `<tr><td>${esc(id)}</td><td>${esc(group.LoadBalancingPolicy || 'Default')}</td><td>${keys(group.Destinations || {}).map(d => esc(d + ': ' + group.Destinations[d].Address)).join('<br>') || 'No enabled servers'}</td></tr>`;
    }).join('');
    const own = String(r.requestedBy || '').toLowerCase() === currentUser.toLowerCase();
    const eligible = r.status === 'Pending' && currentRole === 'Administrator' && !own;
    return `<div class="card"><div class="flex"><h2 class="section-title">Change request details</h2>${actionBtn('Back to approvals', 'switch', 'approvals')}</div><p><b>Status:</b> ${esc(r.status)} · <b>Requested by:</b> ${esc(r.requestedBy)}</p><p><b>Reason:</b> ${esc(r.changeReason)}</p><p class="subtle">Full proposed configuration, not a difference report. Review exact JSON below including advanced policies, disabled servers and revision before making a decision.</p><h3>Proposed websites and routes</h3><div class="tablewrap"><table><thead><tr><th>Route</th><th>Hostnames</th><th>Path</th><th>Backend group</th></tr></thead><tbody>${routeRows || '<tr><td colspan="4">No routes in proposed configuration</td></tr>'}</tbody></table></div><h3>Proposed backend groups</h3><div class="tablewrap"><table><thead><tr><th>Group</th><th>Balancing</th><th>Enabled servers</th></tr></thead><tbody>${groupRows || '<tr><td colspan="3">No backend groups in proposed configuration</td></tr>'}</tbody></table></div><details class="operator-advanced" open><summary>Full exact draft and metadata (required review)</summary><pre class="json-review">${esc(JSON.stringify(r, null, 2))}</pre></details><p>${own && r.status === 'Pending' ? 'Your request is waiting for a different authorized administrator.' : ''}</p>${eligible ? actionBtn('Approve after reviewing', 'approval-approve', r.id, 'primary') + ' ' + actionBtn('Reject', 'approval-reject', r.id, 'danger-btn mini') : ''}</div>`;
}
async function approvals(){
 try{
  const items=await api('/admin/api/change-requests');
  if(view!=='approvals')return;
  const rows=items.map((x:Obj)=>`<tr><td class="mono">${esc(x.id)}</td><td>${esc(x.requestedBy)}</td><td>${esc(x.changeReason)}</td><td>${esc(x.routeCount)} / ${esc(x.clusterCount)}</td><td><span class="chip ${x.status==='Approved'?'good':x.status==='Rejected'?'bad':''}">${esc(x.status)}</span></td><td>${esc(x.reviewedBy||'—')}</td><td>${actionBtn('Review full draft','approval-review',x.id)} </td></tr>`).join('');
  $('content').innerHTML=`<div class="toolbar"><div><h2>Two-person configuration approval</h2><p class="subtle">Submitting a change does not update live routing. A different Administrator must approve the exact saved draft; revision conflicts block outdated submissions.</p></div></div><div class="tablewrap"><table><thead><tr><th>Request</th><th>Requester</th><th>Reason</th><th>Routes / Clusters</th><th>Status</th><th>Reviewer</th><th>Actions</th></tr></thead><tbody>${rows||'<tr><td colspan="7" class="empty">No change requests submitted. Create or edit a website, then select Submit for approval.</td></tr>'}</tbody></table></div>`;
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
 if(topologyStep===1)return `<h2>Register gateway topology</h2><p class="subtle">Record the gateway hosts. Agent origins are plans only until independently enrolled with mTLS certificates.</p><div class="setup-array">${(p.gateways||[]).map((g:Obj,i:number)=>`<div class="setup-entry"><div class="setup-entry-title"><b>YARP gateway ${i+1}</b>${(p.gateways||[]).length>1?`<button type="button" class="danger-btn mini" data-action="setup-gateway-remove" data-id="${i}">Remove</button>`:''}</div><div class="setup-grid">${topoArrayInput('gateways',i,'id','Gateway ID',g.id,'yarp-01')}${topoArrayInput('gateways',i,'hostname','Windows hostname / IP',g.hostname,'YARP-ND-01')}${siteSelect('gateways',i,g.site)}${mode!=='standalone'?topoArrayInput('gateways',i,'agentUrl','HTTPS agent origin (planned)',g.agentUrl,'https://yarp-01.internal:8443/'):'<p class="subtle">Local gateway does not require a remote agent.</p>'}</div></div>`).join('')}</div><button class="ghost" type="button" data-action="setup-gateway-add">+ Add gateway</button><div class="healthbanner">Physical gateway identity is not verified by typing a hostname. Remote onboarding later requires certificate enrollment, ACLs and an agent handshake.</div>`;
 if(topologyStep===2)return `<h2>Application server inventory</h2><p class="subtle">Add one HTTP(S) website, or multiple origins for load balancing. IIS, Apache, Nginx, Tomcat, Kestrel, Node.js and external ingress can be destinations. This inventory does not create live proxy routes.</p><div class="setup-array">${(p.workloads||[]).map((w:Obj,i:number)=>`<div class="setup-entry"><div class="setup-entry-title"><b>Destination ${i+1}</b><button class="danger-btn mini" type="button" data-action="setup-workload-remove" data-id="${i}">Remove</button></div><div class="setup-grid">${topoArrayInput('workloads',i,'id','Destination ID',w.id,'api-01')}${topoArrayInput('workloads',i,'application','Application / cluster name',w.application,'example-api')}${topoArrayInput('workloads',i,'url','Website / API origin URL',w.url,'http://127.0.0.1/')}${siteSelect('workloads',i,w.site)}<label class="setup-field"><span>Hosting engine</span><select data-setup-array="workloads" data-setup-index="${i}" data-setup-property="hostingEngine">${hostingEngines.map(([k,label])=>`<option value="${k}" ${(w.hostingEngine||'http')===k?'selected':''}>${esc(label)}</option>`).join('')}</select><small>Classification only; GatewayCore does not deploy or manage the hosting engine.</small></label>
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
function topologyPage(){const status=topologyResponse?.status||'not-started';return `<div class="setup-heading"><div><h2>Gateway onboarding</h2><p class="subtle">For laptop testing, use the quick standalone template; advanced HA planning is optional. Status: <span class="chip">${esc(status)}</span></p></div><span class="chip">DESIGN ONLY</span></div><div class="healthbanner"><b>Quick start:</b> IIS, Apache, Nginx, or another HTTP(S) website can serve as a backend. <button class="ghost mini" type="button" data-action="setup-quick-lab">Fill single-server test draft</button> This fills design fields only and never changes live routes.</div><div class="setup-steps">${topologySteps.map((t,i)=>`<button class="setup-step ${i===topologyStep?'current':''}" data-action="setup-step" data-id="${i}" type="button"><span>${i+1}</span><b>${esc(t)}</b></button>`).join('')}</div>${architecturePreview()}<div class="setup-panel">${topologyStepHtml()}</div><div class="setup-actions"><button class="ghost" type="button" data-action="setup-prev">${topologyStep===0?'← Exit to Setup Center':'← Previous step'}</button><span class="subtle">Step ${topologyStep+1} of ${topologySteps.length}</span><div><button class="ghost" type="button" data-action="setup-save" ${currentRole!=='Administrator'?'disabled':''}>Save draft</button> ${topologyStep<5?'<button class="primary" type="button" data-action="setup-next">Continue</button>':`<button class="primary" type="button" data-action="setup-confirm" ${currentRole!=='Administrator'?'disabled':''}>Confirm design</button>`}</div></div><div class="healthbanner">No firewall, service, CA key, Pgpool, PostgreSQL, IIS or live YARP configuration change is performed by this wizard. Gateway connectivity and deployment are separate approved workflows.</div>${specialistPlan('onboarding')}`}
async function topologyValidate(){if(!topologyDraft||currentRole!=='Administrator')return;try{const r=await api('/admin/api/onboarding/validate','POST',{plan:topologyDraft});topologyChecks=r.issues||[];topologyWarnings=r.warnings||[];}catch(e){show('Validation unavailable: '+String(e),true)}}
async function topologySave(confirmDesign:boolean){if(!topologyDraft)return;try{if(confirmDesign){await topologyValidate();if(topologyChecks.length){render();show('Fix the listed topology validation errors before confirming.',true);return}}const saved=await api('/admin/api/onboarding','POST',{expectedRevision:topologyResponse?.revision||'EMPTY',plan:topologyDraft,confirmDesign});topologyResponse=saved;topologyChecks=saved.issues||[];topologyWarnings=saved.warnings||[];show(confirmDesign?'Architecture design confirmed. Operational deployment is still pending.':'Topology draft saved. No traffic changes.');if(confirmDesign){view='setup';updateTopologyNavigation()}render()}catch(e){show('Could not save topology: '+String(e),true)}}
function topologyModeChange(mode:string){if(!topologyDraft)return;topologyDraft.mode=mode;topologyDraft.controlPlane=mode==='standalone'?'local':'ha-controller';const need=mode==='standalone'?1:mode==='ha-pair'?2:3;const arr=topologyDraft.gateways||[];while(arr.length<need)arr.push({id:`yarp-0${arr.length+1}`,hostname:'',agentUrl:''});if(arr.length>need&&mode!=='fleet')arr.length=need;topologyDraft.gateways=arr}

// 0.1 Setup Center. Every status comes from an authenticated backend API; no mock health data.
type SetupStage = {id:string;title:string;status:string;evidence:string;action:string};
type SetupOverview = {version:string;channel:string;verifiedForProduction:boolean;mode:string;topologyConfirmed:boolean;activeAdministratorCount:number;routeCount:number;clusterCount:number;destinationCount:number;activeHealthClusterCount:number;fleetEntries:number;gateway:string;transport:string;freeze:{frozen:boolean;reason:string;updatedBy:string};stages:SetupStage[];note:string};
let setupState:SetupOverview|null=null;
const readyClass=(s:string)=>['configured','design-confirmed','https-session-unverified'].includes(s)?'good':s==='not-implemented'?'bad':'warn';
const setupActionText=(s:SetupStage)=>s.action==='onboarding'?'Set topology':s.action==='mail'?'Configure mail':s.action==='directory'?'Configure AD':s.action==='health'?'Inspect health':s.action==='fleet'?'Gateway fleet':s.action==='users'?'Accounts':s.action==='approvals'?'Approvals':s.action==='backups'?'Audit log':s.action==='routes'?'Configure routes':'View';
async function setupPage(){
 try {
   setupState=await api('/admin/api/setup/overview') as SetupOverview;
   if(view!=='setup')return;
   const x=setupState;
   const admin = currentRole === 'Administrator';
   const designDone = topologyResponse?.status === 'design-confirmed';
   const orgDone = !!orgProfile?.organizationName;
   const reviewerNeeded = admin && typeof x.activeAdministratorCount === 'number' && x.activeAdministratorCount < 2;
   const nextTask = !orgDone ? 'Set your organization' : !designDone ? 'Confirm gateway architecture' : reviewerNeeded ? 'Prepare a second administrator' : dirty ? 'Review and submit your draft' : x.routeCount === 0 ? 'Add your first website' : 'Check health or manage websites';
   const nextButton = (!orgDone || !designDone) && !admin ? actionBtn('Read the user guide', 'setup-open', 'guide', 'primary') : !orgDone ? actionBtn('Configure organization', 'setup-open', 'organization', 'primary') : !designDone ? actionBtn('Choose gateway architecture', 'setup-open', 'onboarding', 'primary') : reviewerNeeded ? actionBtn('Prepare a second administrator', 'setup-open', 'users', 'primary') : dirty ? actionBtn('Review draft', 'setup-open', 'routes', 'primary') : x.routeCount === 0 && currentRole !== 'Viewer' ? actionBtn('Add website / API', 'setup-next-website', '', 'primary') : actionBtn('Check backend servers', 'setup-open', 'backends', 'primary');
   const configured=x.stages.filter(s=>['configured','design-confirmed'].includes(s.status)).length;
   $('content').innerHTML=`<div class="setup-hero card"><div><div class="setup-eyebrow">FIRST-RUN BOOTSTRAP & OPERATIONS</div><h2>Set up your YARP gateway</h2><p>Follow the setup checklist. Advanced checks are available when needed.</p><span class="chip">Version ${esc(x.version)} · ${esc(x.channel)}</span><span class="chip">${esc(x.gateway)}</span></div><div class="setup-score"><strong>${configured}/${x.stages.length}</strong><span>Configured setup controls, not a production-readiness score</span></div></div>
   <div class="setup-alert">${x.freeze.frozen?`<b>Routing change freeze is ON.</b> ${esc(x.freeze.reason)}`:`<b>Routing changes are allowed with approval.</b> A local emergency freeze can stop route/change operations.`} ${currentRole==='Administrator'?`<button class="ghost mini" data-action="setup-toggle-freeze" data-id="${x.freeze.frozen?'off':'on'}">${x.freeze.frozen?'Unfreeze':'Freeze routing changes'}</button>`:''}</div>
   <div class="card operator-intro"><h2>Start with a website</h2><p><b>Next: ${esc(nextTask)}</b></p><div class="operator-next">${nextButton}</div><p class="journey-role"><b>Your role: ${esc(currentRole)}</b> · ${currentRole==='Administrator'?'Configure the gateway and review other people’s changes.':currentRole==='Operator'?'Prepare configuration drafts and request approval. An administrator owns setup and approvals.':'Read status and documentation. Ask an administrator to configure the gateway.'}</p><p>Follow the steps in order. Creating a draft never changes live traffic.</p><div class="operator-flow"><span>Client</span><span aria-hidden="true">→</span><span>GatewayCore</span><span aria-hidden="true">→</span><span>Backend servers</span></div></div><div class="journey-checklist" aria-label="Setup checklist">
   <section><b>1. Organization</b><span class="chip ${orgProfile?.organizationName?'good':'warn'}">${orgProfile?.organizationName?'Saved':'Required'}</span><p>Identify the company and environment.</p></section>
   <section><b>2. Gateway design</b><span class="chip ${x.topologyConfirmed?'good':'warn'}">${x.topologyConfirmed?'Confirmed':'Required'}</span><p>Single gateway or HA design; this does not deploy a VIP.</p></section>
   <section><b>3. Approval team</b><span class="chip ${x.activeAdministratorCount>=2?'good':'warn'}">${x.activeAdministratorCount>=2?'Accounts configured':'Needs attention'}</span><p>${esc(String(x.activeAdministratorCount??'Unknown'))} enabled administrators. Verify the second administrator can sign in before approving changes.</p></section>
   <section><b>4. Application configuration</b><span class="chip ${dirty?'warn':x.routeCount>0?'good':'warn'}">${dirty?'Draft — not live':x.routeCount>0?'Routes configured':'Not configured'}</span><p>Submit a reviewed draft before testing traffic.</p></section>
   <section><b>5. Verify traffic</b><span class="chip">Manual evidence required</span><p>Check actual backend health and make a client request. Never assume configuration equals availability.</p></section>
   </div><div class="operator-steps"><section class="card"><span class="operator-number">1</span><h3>Gateway setup</h3><p>Set your organization and choose one gateway or a multi-gateway design.</p><button class="ghost" data-action="setup-open" data-id="organization">Organization</button> <button class="ghost" data-action="setup-open" data-id="onboarding">Gateway architecture</button></section><section class="card"><span class="operator-number">2</span><h3>Prepare your approval team</h3><p>Set up a separate authorized administrator to review changes. Never share accounts or passwords. Verify that both people can sign in.</p>${currentRole==='Administrator'?actionBtn('Manage admin accounts','setup-open','users','ghost'):'<p class="subtle">Ask your administrator to complete this step.</p>'}</section><section class="card"><span class="operator-number">3</span><h3>Add a website or API</h3><p>Enter a hostname and backend URL. For a local test use an existing IIS, Apache or Nginx site.</p><button class="primary" data-action="setup-simple-website">+ Add website / API</button> <button class="ghost" data-action="setup-local-web">Local website test</button></section><section class="card"><span class="operator-number">4</span><h3>Review and approve</h3><p>Check your draft, submit it, then ask a different administrator to approve.</p><button class="ghost" data-action="setup-open" data-id="routes">Review websites &amp; routes</button> <button class="ghost" data-action="setup-open" data-id="approvals">Change requests</button></section><section class="card"><span class="operator-number">5</span><h3>Verify live traffic</h3><p>After approval, inspect health and test real requests. Unknown is not healthy.</p><button class="ghost" data-action="setup-live-health">Check backend health</button> <button class="ghost" data-action="setup-open" data-id="metrics">Traffic metrics</button></section></div><div class="operator-help"><button class="ghost" data-action="setup-open" data-id="guide">Read the step-by-step user guide →</button></div><details class="card operator-advanced"><summary>Advanced setup &amp; deployment evidence</summary><div class="setup-summary"><div class="card"><b>${x.routeCount}</b><span>Routes</span></div><div class="card"><b>${x.clusterCount}</b><span>Clusters</span></div><div class="card"><b>${x.destinationCount}</b><span>Enabled backend entries</span></div><div class="card"><b>${x.fleetEntries}</b><span>Gateway agent records</span></div></div>
   <div class="toolbar"><div><h2>Bootstrap checklist</h2><p class="subtle">“Configured” is not the same as operationally tested or production certified.</p></div><div><button class="ghost" data-action="setup-add-esign-pools">Advanced public / private pools (eSign preset)</button> <button class="ghost" data-action="setup-add-application">Advanced public HTTPS application</button> <button class="ghost" data-action="setup-refresh">Refresh evidence</button></div></div>
   <div class="setup-stage-grid">${x.stages.map((s:SetupStage,i:number)=>`<div class="card setup-stage"><div class="setup-stage-head"><span class="setup-number">${String(i+1).padStart(2,'0')}</span><span class="chip ${readyClass(s.status)}">${esc(s.status.replace(/-/g,' '))}</span></div><h3>${esc(s.title)}</h3><p>${esc(s.evidence)}</p><button class="ghost mini" data-action="setup-open" data-id="${esc(s.action)}">${esc(setupActionText(s))} →</button></div>`).join('')}</div>
   </details><div class="grid2"><div class="card"><h3>Live YARP health states</h3><p class="subtle">Queries YARP's internal active/passive destination states. Unknown means the policy has not classified the backend.</p><p>Use Check backend health in step 5 to refresh this result.</p><div id="setup-live-output" class="setup-live-output">No runtime query made yet.</div></div><div class="card"><h3>Production safety gates</h3><p class="subtle">The following are not magically provisioned by this setup page:</p><ul class="setup-bullets"><li>Remote gateway agents, mTLS and network admission</li><li>AD/SMTP delivery and phishing-resistant SSO</li><li>Independent immutable audit retention</li><li>OCSP/CRL and CA issuance failover acceptance</li></ul><p class="subtle">The console deliberately refuses to call this instance production certified.</p></div></div>`;
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
function updateTopologyNavigation(){const finished=topologyResponse?.status==='design-confirmed';const prereqViews=['organization','setup','onboarding','users','mail','directory','guide'];document.querySelectorAll<HTMLButtonElement>('.nav').forEach(b=>{const dest=b.dataset.view||'';const adminOnly=['users','mail','directory'].includes(dest);b.hidden=(!finished&&!prereqViews.includes(dest))||(dest==='fleet'&&finished&&topologyResponse?.plan?.mode==='standalone')||(adminOnly&&currentRole!=='Administrator')||(dest==='tls'&&currentRole==='Viewer')});$('save').hidden=!finished||currentRole==='Viewer'||!dirty||view==='onboarding'}

const specialistHelp: Obj = {"setup":"Follow the next action, then verify each requirement using actual evidence. A saved design is not live deployment.","overview":"Check local readiness and request counts. Unknown health is not healthy; use Health checks and Traffic metrics for evidence.","organization":"Enter the company name, industry and region. This changes labels and guidance, not tenancy or network isolation.","onboarding":"Choose single gateway or Active–Active/fleet, record the actual gateway and application hosts, then confirm design. Use a separate approved VIP and failover plan.","routes":"A hostname/path selects a backend group. Add or edit a website, submit your draft and obtain independent approval before testing.","clusters":"Choose how requests are distributed across a group. Use the policy guide, verify real readiness URLs and submit the draft for independent approval.","backends":"Inspect live health separately from draft state. Drain before maintenance and verify in-flight requests have finished.","health":"Run a GET probe for connectivity. Inspect live active/passive YARP states separately; successful probes do not prove application transaction readiness.","metrics":"Compare errors, request counts and latency to the approved baseline. Counters describe this process, not every node.","approvals":"Review proposed settings and the exact full draft. A different authorized administrator must approve. If a revision conflicts, reconcile rather than retrying blindly.","backups":"Choose the correct configuration backup under change authorization. Preserve state and private keys; verify recovery independently.","inventory":"Record machine identity, site and application details. Inventory is not proof of enrollment or connectivity.","users":"Create named accounts with least privilege. Viewer monitors, Operator prepares changes, Administrator manages identity and approves others’ requests. Never share passwords.","mail":"Use an approved relay, trusted TLS and a readable mailbox to verify delivery. Never paste credentials into a ticket.","directory":"Verify trusted LDAPS, directory group mapping and recovery access before enabling directory sign-in.","fleet":"Register trusted agent origins and provision certificates independently. Check live agent status, roll out an approved revision, then verify every node and journal.","peers":"Check authenticated counter exchange and freshness. This is telemetry, not failover or global authorization.","capabilities":"Review supported features and their restrictions before choosing a specialist workflow.","featurematrix":"Review the capability register, then use the dedicated TLS, WAF and GSLB workflows. Availability is not deployment evidence.","guide":"Use this offline guide for your first shift. Ask the platform owner about permissions, change windows and physical acceptance.","tls":"Inspect local certificate dates, store metadata and configured listeners. Verify certificate chain, SAN, key ACLs and actual TLS connections separately.","waf":"Prepare an approved signed external WAF policy and representative traffic tests. Do not bypass the WAF or activate unsigned rules.","gslb":"Review DNS authority, site readiness, signed configuration and observer quorum. Verify actual DNS responses before delegation."};
const policyGuide = [["RoundRobin","Even rotation","Similar servers, ordinary applications."],["PowerOfTwoChoices","Choose the less busy of two","Balances request concurrency with low selection overhead."],["LeastRequests","Least outstanding requests","Variable request durations; monitor concurrency."],["Random","Random selection","Similar interchangeable servers."],["FirstAlphabetical","First available by ID","Deterministic order, not an independently verified failover design."],["WeightedRandom","Weighted capacity","Set backend weights for unequal capacity."],["WeightedLeastRequests","Capacity-aware least outstanding requests","Uses local HTTP request counts and effective weights; not TCP connection counts."],["WeightedRoundRobin","Cyclic weighted rotation","Exact configured ratio per full cycle with stable eligible destinations and weights; may send consecutive requests to one server."],["FastestResponse","Measured response time","Local successful GET/HEAD completion latency with periodic exploration."],["SourceIpHash","Source IP affinity","Requires verified trusted client-IP handling; NAT may group many users."],["PrimaryBackup","Primary / backup","Requires active readiness checks and explicit backend roles; never replay non-idempotent requests."]];
const specialistPlans: [string, string, string, string[]][] = [["HA and DC-DR","onboarding","Describe the gateway layout and site boundaries. This saves design metadata only.",["Confirm gateway design and identify DC/DR hosts.","Provision distinct gateway identities, mTLS agent trust and upstream health-aware VIP/ECMP.","Register agents and inspect authenticated status; submit and approve the desired configuration.","Use the fleet rollout and journal; test node loss, partition, VIP migration, site recovery and failback independently."]],["WAF policy","waf","External CRS policy deployment uses signed, reversible tooling. No direct activation from this page.",["Inventory protected hostnames and origin paths; prevent direct origin bypass.","Pin the reviewed CRS image and complete the signed policy and exact-route exception review.","Run detection-only evaluation using representative redacted traffic; assess false positives and matched capacity.","Use the approved signed two-node transaction and verify rollback, per-route evidence and audit retention."]],["DNS and GSLB","gslb","DNS is a separate authoritative engine, not the HTTP proxy.",["Record delegated zones, nameservers, A/AAAA addresses, TTL and fail-closed site policy.","Verify site health URLs, DNSSEC signing, trusted ECS and observer quorum where configured.","Stage the approved signed engine configuration using the enrolled agent workflow; inspect agent/runtime evidence.","Test actual UDP/TCP DNS answers, DNSSEC validation, resolver convergence and site failure before delegation."]]];
function contextualHelp() {
    $('context-help-text').textContent = specialistHelp[view] || 'Inspect the current settings and follow the approved change procedure.';
}
function policyReference() {
    return `<details class="card operator-advanced"><summary>Choose a load-balancing policy</summary><div class="specialist-grid">${policyGuide.map(p => `<section class="specialist-tile"><h3>${esc(p[1])}</h3><code>${esc(p[0])}</code><p>${esc(p[2])}</p></section>`).join('')}</div><p>Health policies, weights and roles remain in the draft until independent approval. Test real traffic and preserve non-idempotent request safety.</p></details>`;
}
function specialistPlan(id: string) {
    const plan = specialistPlans.find(p => p[1] === id);
    if (!plan)
        return '';
    return `<div class="card"><h2>${esc(plan[0])}</h2><p class="subtle">${esc(plan[2])}</p><ol class="specialist-steps">${plan[3].map(s => `<li>${esc(s)}</li>`).join('')}</ol><p class="healthbanner">Manual deployment evidence required. This checklist does not change live services, generate private keys or certify production readiness.</p></div>`;
}
function siteSelect(kind: string, i: number, value: string) {
    return `<label class="setup-field"><span>Site (design only)</span><select data-setup-array="${esc(kind)}" data-setup-index="${i}" data-setup-property="site">${[['unassigned', 'Not assigned'], ['dc', 'Primary data center (DC)'], ['dr', 'Disaster recovery (DR)']].map(([k, label]) => `<option value="${k}" ${(value || 'unassigned') === k ? 'selected' : ''}>${label}</option>`).join('')}</select></label>`;
}
function siteName(site: string) {
    return site === 'dc' ? 'Primary data center (DC)' : site === 'dr' ? 'Disaster recovery (DR)' : 'Site not assigned';
}
function architecturePreview() {
    const p = topologyDraft || topologyDefaults();
    const hosts: Obj[] = (p.gateways || []);
    return `<div class="card specialist-topology"><h3>Planned traffic flow</h3><div class="operator-flow"><span>Clients</span><span aria-hidden="true">→</span><span>${esc(p.mode === 'standalone' ? 'Single gateway' : p.publicVip || 'Health-aware ingress / VIP required')}</span></div><div class="specialist-grid">${hosts.map(g => `<section class="specialist-tile"><b>${esc(g.id || 'Unnamed gateway')}</b><p>${esc(g.hostname || 'Hostname not entered')}</p><p>${esc(siteName(g.site))}</p><small>Design record · agent trust not verified</small></section>`).join('')}</div><div class="operator-flow"><span>Application servers</span></div><div class="specialist-grid">${(p.workloads || []).map((w: Obj) => `<section class="specialist-tile"><b>${esc(w.application || w.id || 'Application')}</b><p>${esc(w.url || 'URL not entered')}</p><small>${esc(siteName(w.site))}</small></section>`).join('')}</div><p class="subtle">DC/DR location and database failover are separate operational requirements; this diagram is not live health.</p></div>`;
}
async function certificatePage() {
    $('content').innerHTML = '<div class="card"><h2>Certificates &amp; TLS</h2><p>Loading local inventory…</p></div>';
    try {
        const x = await api('/admin/api/tls/inventory');
        if (view !== 'tls')
            return;
        const certs: Obj[] = Array.isArray(x.certificates) ? x.certificates : [];
        const endpoints: Obj[] = Array.isArray(x.configuredEndpoints) ? x.configuredEndpoints : [];
        const rows = certs.map(c => `<tr><td><b>${esc(c.subject)}</b><div class="subtle">${esc(c.issuer)}</div></td><td class="mono">${esc(c.thumbprint)}</td><td>${esc(c.notAfterUtc)}</td><td><span class="chip ${c.expiryState === 'valid-date-only' ? '' : 'warn'}">${esc(c.expiryState)}</span></td><td>${c.privateKeyAvailable ? 'Reported present' : 'Not reported'} · ${c.serverAuthenticationEku ? 'Server EKU allowed' : 'Server EKU not allowed'}</td></tr>`).join('');
        const listeners = endpoints.map(e => `<tr><td>${esc(e.name)}</td><td>${esc(e.scheme)}</td><td>${e.certificateReferenceConfigured ? 'Reference configured' : 'No reference reported'}</td></tr>`).join('');
        $('content').innerHTML = `<div class="card"><h2>Certificates &amp; TLS</h2><p>Inventory for ${esc(x.gateway)} · ${esc(x.timestampUtc)} · store ${esc(x.storeState)}</p>${actionBtn('Refresh inventory', 'switch', 'tls', 'ghost')}<div class="healthbanner">Read-only local store and configured endpoint metadata. Valid dates and a reported private key do not establish certificate trust, SAN match, active selection or accessibility to the service.</div></div><div class="card card-spaced"><h3>Configured endpoints</h3><div class="tablewrap"><table><thead><tr><th>Listener</th><th>Scheme</th><th>Certificate reference</th></tr></thead><tbody>${listeners || '<tr><td colspan="3">No endpoint metadata reported.</td></tr>'}</tbody></table></div></div><div class="card card-spaced"><h3>Local certificate inventory</h3><div class="tablewrap"><table><thead><tr><th>Subject / issuer</th><th>Thumbprint</th><th>Not after (UTC)</th><th>Date status</th><th>Key / purpose</th></tr></thead><tbody>${rows || '<tr><td colspan="5">No certificates reported; verify the configured file/store separately.</td></tr>'}</tbody></table></div></div><div class="card card-spaced"><h3>ACME lifecycle availability</h3><p>Automatic renewal service: ${x.acmeRenewalConfigured === true ? 'Configured' : 'Not configured'}. Historical certificate revocation service: ${x.acmeRevocationConfigured === true ? 'Configured' : 'Not configured'}.</p><p class="subtle">${esc(x.acmeScope || 'Service capability is not reported; do not infer readiness.')}</p><h3>Certificate change workflow</h3><ol class="specialist-steps"><li>Identify traffic, management or backend client certificate usage and approved CA.</li><li>Provision the trusted chain and protected key via the documented host configuration. Never upload keys to the dashboard.</li><li>Review SAN, expiry, EKU, listener isolation, file/store ACL and renewal or rollback procedure.</li><li>Apply the approved change and test actual TLS and mTLS, then verify live selection and monitor expiration.</li></ol><p class="subtle">Traffic certificate import, ACME configuration and trust-store changes use the approved host runbook. Backend client identity can be added to a reviewed configuration draft below.</p>${actionBtn('Configure backend mTLS', 'backend-cert', '', 'primary')}</div>` + (x.acmeRevocationConfigured === true && currentRole === 'Administrator' ? '<div class="card card-spaced"><h3>Revoke historical ACME certificate</h3><p>Irreversible CA operation. Use only the public DER certificate (base64 without PEM headers), not a PFX or key. The server rejects the currently served certificate.</p><form id="acme-revoke-form" class="auth-form"><label>Public DER base64<textarea name="certificateDerBase64" rows="4" maxlength="30000" required autocomplete="off" spellcheck="false"></textarea></label><label>SHA-1 certificate thumbprint (40 uppercase hex)<input name="thumbprint" required maxlength="40" pattern="[A-F0-9]{40}" autocomplete="off"></label><label>Reason<select name="reason"><option value="Unspecified">Unspecified</option><option value="KeyCompromise">Key compromise</option><option value="Superseded">Superseded</option><option value="CessationOfOperation">Cessation of operation</option></select></label><label>Type REVOKE followed by a space and the exact thumbprint<input name="confirmation" required maxlength="47" autocomplete="off"></label><button type="submit" class="danger-btn">Request revocation</button></form><p id="acme-revoke-status" role="status"></p></div>' : '');
        if (x.acmeRenewalConfigured === true && currentRole === 'Administrator') {
            $('content').insertAdjacentHTML('beforeend', '<div class="card card-spaced"><h3>Check and renew configured ACME certificate</h3><p>Uses the preconfigured CA, DNS name and protected traffic certificate. Renews only when due; never forces early issuance. A check can take several minutes.</p><button id="acme-renew-due" type="button" class="primary">Check renewal now</button><p id="acme-renew-status" role="status"></p></div>');
            wireAcmeRenewal();
        }
        if (x.stagedImportConfigured === true && currentRole === 'Administrator') {
            $('content').insertAdjacentHTML('beforeend', '<div class="card card-spaced"><h3>Provision host-staged traffic certificate</h3><p>Place the approved encrypted PFX at the fixed host staging path. Uses the existing protected password; no private key upload. Preview and confirm exact bytes before activation.</p><button id="tls-stage-preview" type="button" class="primary">1. Preview staged PFX</button><p id="tls-stage-status" role="status"></p><form id="tls-stage-confirm" class="auth-form" hidden><label>2. Type ACTIVATE, a space and the candidate SHA-256<input id="tls-stage-confirmation" maxlength="73" autocomplete="off" required></label><button id="tls-stage-activate" type="submit" class="primary" disabled>3. Activate approved certificate</button></form></div>');
            wireStagedCertificate();
        }
        wireAcmeRevocation();
    }
    catch (e) {
        if (view === 'tls')
            $('content').innerHTML = `<div class="card"><h2>Certificate inventory unavailable</h2><p>${esc(String(e))}</p><p>No certificate readiness is claimed.</p></div>`;
    }
}
function wireStagedCertificate() {
    const button = $('tls-stage-preview') as HTMLButtonElement;
    const form = $('tls-stage-confirm') as HTMLFormElement;
    const confirmation = $('tls-stage-confirmation') as HTMLInputElement;
    const activate = $('tls-stage-activate') as HTMLButtonElement;
    const status = $('tls-stage-status');
    const generation = authGeneration;
    let preview: Obj | null = null;
    const current = () => generation === authGeneration && view === 'tls' && button.isConnected;
    const reset = () => {
        preview = null;
        confirmation.value = '';
        activate.disabled = true;
        form.hidden = true;
    };
    confirmation.oninput = () => {
        activate.disabled = !preview || confirmation.value !== 'ACTIVATE ' + preview.candidateDigest;
    };
    button.onclick = async () => {
        if (button.disabled)
            return;
        reset();
        button.disabled = true;
        status.textContent = 'Reading host-staged certificate and current approval…';
        try {
            const p = await api('/admin/api/tls/staged/preview', 'POST', {});
            if (!current())
                return;
            if (!/^[A-F0-9]{64}$/.test(p.candidateDigest) || !/^[A-F0-9]{64}$/.test(p.activeDigest))
                throw Error('Invalid preview digest.');
            status.textContent = 'Candidate ' + String(p.thumbprint) + ' expires ' + String(p.notAfterUtc) + '; candidate SHA-256 ' + p.candidateDigest + '; active SHA-256 ' + p.activeDigest;
            if (p.fleetMode === true && p.fleetGrantReady !== true) {
                status.textContent += '. Fleet activation blocked: obtain independent signed approval and current quorum, then refresh preview.';
                return;
            }
            if (p.fleetMode === true)
                status.textContent += '. Fleet grant observed; the server will recheck it at commit. Independent completion remains mandatory.';
            preview = p;
            form.hidden = false;
        }
        catch (e) {
            if (current())
                status.textContent = String(e);
        }
        finally {
            button.disabled = false;
        }
    };
    form.onsubmit = async (event) => {
        event.preventDefault();
        if (!current() || !preview || activate.disabled || button.disabled || confirmation.value !== 'ACTIVATE ' + preview.candidateDigest)
            return;
        const approved = preview;
        const typed = confirmation.value;
        reset();
        button.disabled = true;
        status.textContent = 'Validating and applying the approved certificate…';
        try {
            const result = await api('/admin/api/tls/staged/activate', 'POST', { candidateDigest: approved.candidateDigest, activeDigest: approved.activeDigest, confirmation: typed });
            if (!current())
                return;
            if (result.activated !== true || result.thumbprint !== approved.thumbprint)
                throw Error('Activation not confirmed.');
            status.textContent = 'Activated ' + result.thumbprint + (result.independentFleetCompletionRequired === true ? '. Verify live TLS and peer traffic, obtain the signed completion grant and release the original quorum fence before rotating another gateway.' : '. Verify an independent TLS handshake.');
        }
        catch (e) {
            if (current())
                status.textContent = String(e) + ' Reconcile the current certificate before retrying.';
        }
        finally {
            button.disabled = false;
        }
    };
}
function wireAcmeRenewal() {
    const button = $('acme-renew-due') as HTMLButtonElement;
    const status = $('acme-renew-status');
    const generation = authGeneration;
    button.onclick = async () => {
        if (button.disabled || !confirm('Check the configured traffic certificate and renew it only if due?'))
            return;
        button.disabled = true;
        status.textContent = 'Checking configured certificate renewal…';
        try {
            const outcome = await api('/admin/api/tls/acme/renew-due', 'POST', {});
            if (generation !== authGeneration || view !== 'tls' || !button.isConnected)
                return;
            if (outcome.renewed === true && outcome.reason === 'renewed-and-atomically-installed')
                status.textContent = 'Renewal and listener activation reported; expiry: ' + String(outcome.notAfter || 'unknown') + '. Verify independent TLS handshake.';
            else if (outcome.renewed === false && outcome.reason === 'certificate-is-outside-renewal-window')
                status.textContent = 'Not due. Current certificate expiry: ' + String(outcome.notAfter || 'unknown');
            else
                throw Error('Unexpected renewal outcome; verify live certificate before retrying.');
        }
        catch (e) {
            if (generation === authGeneration && view === 'tls' && button.isConnected)
                status.textContent = String(e);
        }
        finally {
            button.disabled = false;
        }
    };
}
function wireAcmeRevocation() {
    const form = document.getElementById('acme-revoke-form') as HTMLFormElement | null;
    if (!form)
        return;
    const status = $('acme-revoke-status');
    const generation = authGeneration;
    form.onsubmit = async (event) => {
        event.preventDefault();
        const submit = form.querySelector('button[type="submit"]') as HTMLButtonElement;
        if (submit.disabled)
            return;
        const fields = new FormData(form);
        const thumbprint = String(fields.get('thumbprint') || '');
        const confirmation = String(fields.get('confirmation') || '');
        const certificateDerBase64 = String(fields.get('certificateDerBase64') || '').replace(/\s/g, '');
        const reason = String(fields.get('reason') || '');
        if (!/^[A-F0-9]{40}$/.test(thumbprint) || confirmation !== 'REVOKE ' + thumbprint || !/^[A-Za-z0-9+/]+={0,2}$/.test(certificateDerBase64)) {
            status.textContent = 'Enter exact public DER base64 and typed thumbprint confirmation.';
            return;
        }
        submit.disabled = true;
        status.textContent = 'Requesting CA revocation…';
        try {
            const reply = await api('/admin/api/tls/acme/revoke', 'POST', { certificateDerBase64, thumbprint, confirmation, reason });
            if (generation !== authGeneration || view !== 'tls' || !form.isConnected)
                return;
            if (reply.revoked !== true || reply.thumbprint !== thumbprint)
                throw Error('Revocation result was not confirmed. Verify CA status before retrying.');
            form.reset();
            status.textContent = 'CA reported revocation of ' + thumbprint + '. Verify independent certificate status.';
        }
        catch (e) {
            if (generation === authGeneration && view === 'tls' && form.isConnected)
                status.textContent = String(e);
        }
        finally {
            submit.disabled = false;
        }
    };
}
function specialistDraftForm(id: string) {
    if (currentRole === 'Viewer')
        return '<div class="card"><p>Only authorized Operators and Administrators can prepare configuration candidates.</p></div>';
    if (id === 'waf')
        return `<div class="card card-spaced"><h2>Prepare WAF policy</h2><p>Build exact unsigned policy bytes for independent signing and the existing external verifier. For an intentional rollback select the previous mode and enter a fresh revision greater than the deployed revision. The observed ruleset and shadow evidence must come from independently collected files.</p><form id="specialist-draft" class="auth-form"><div class="setup-grid"><label>Policy revision<input name="revision" type="number" min="1" max="9007199254740991" required></label><label>Mode<select name="mode"><option value="detect">Detection only</option><option value="block">Blocking (requires reviewed evidence)</option></select></label><label>Observed ruleset SHA-256<input name="rulesetSha256" maxlength="64" pattern="[A-F0-9]{64}" required></label><label>Shadow evidence SHA-256 (blocking only)<input name="shadowEvidenceSha256" maxlength="64" pattern="[A-F0-9]{64}"></label><label>Validity in days<input name="validDays" type="number" min="1" max="45" value="7" required></label><label>Rollback from deployed revision (optional)<input name="rollbackFromRevision" type="number" min="1" max="9007199254740991"></label></div><details><summary>Optional exact-route exceptions</summary><p>One exception per line: ID | owner | route ID | GET or POST | exact path | content type | rule ID | reason | validity days. Maximum 64. No wildcards or broad bypass.</p><label>Scoped exceptions<textarea name="exceptions" rows="4" maxlength="32000" placeholder="exception-01 | security-owner | app-route | POST | /upload | application/pkix-cert | 920420 | Reviewed certificate upload | 7"></textarea></label></details><button class="primary" type="submit">Validate and prepare unsigned policy</button></form><div id="specialist-result" role="status"></div><details><summary>Signed deployment and rollback handoff</summary><ol><li>Export and obtain two independent signatures over the exact policy bytes.</li><li>On the authorized WAF operator host, run the repository signed-policy verifier and rollout controller preflight against actual ruleset bytes and the trusted revision floor.</li><li>Use ops/waf/waf_fleet_rollout.py on the authorized Linux controller: default read-only preflight, then explicit --execute after independent approval. Preserve receipts and verified compensation evidence.</li><li>For a deliberate rollback prepare a fresh signed revision; never reuse a stale signed policy. Confirm actual restored mode and traffic before acceptance.</li></ol><p>The dashboard does not execute Docker, grant leases or sign policies. No activation is claimed here.</p></details></div>`;
    return `<div class="card card-spaced"><h2>Prepare a DNS / GSLB zone</h2><p>Build a new loopback-only initial configuration. Do not overwrite an existing signed multi-zone, DNSSEC or authority-fenced configuration with this candidate.</p><form id="specialist-draft" class="auth-form"><div class="setup-grid"><label>Zone name<input name="name" required maxlength="253" placeholder="app.example.test"></label><label>SOA contact (DNS notation)<input name="soaContact" required maxlength="253" placeholder="hostmaster.example.test"></label><label>SOA serial<input name="serial" type="number" min="1" max="4294967295" value="1" required></label><label>TTL (seconds)<input name="ttl" type="number" min="5" max="300" value="30" required></label><label>Traffic policy<select name="policy"><option value="Weighted">Weighted</option><option value="Failover">Failover</option><option value="WeightedFailover">Weighted failover</option></select></label><label>Probe interval (seconds)<input name="probeInterval" type="number" min="1" max="60" value="5" required></label><label>Consecutive failures<input name="failureThreshold" type="number" min="1" max="10" value="2" required></label><label>Consecutive successes<input name="successThreshold" type="number" min="1" max="10" value="2" required></label></div><label>Sites (IP | HTTPS readiness URL | weight 1–100 | priority 0–1000)<textarea name="sites" rows="4" required maxlength="32000" placeholder="10.0.0.10 | https://dc.example.test/ready | 1 | 0"></textarea></label><label>Authoritative nameservers (DNS name | IP)<textarea name="nameServers" rows="3" required maxlength="32000" placeholder="ns1.example.test | 10.0.0.53"></textarea></label><details><summary>DNSSEC and delegated authority</summary><p>Only pre-provisioned absolute key references are accepted; never paste keys. DNSSEC signing, parent DS publication and quorum must be verified on the target DNS hosts.</p><div class="setup-grid"><label>DNSSEC denial mode<select name="dnssecMode"><option value="Disabled">Disabled</option><option value="Nsec">NSEC</option><option value="Nsec3">NSEC3</option></select></label><label>Active private key path<input name="dnssecKeyPath" maxlength="512"></label><label>NSEC3 salt (hex)<input name="dnssecSalt" maxlength="64"></label><label>NSEC3 iterations<input name="dnssecIterations" type="number" min="0" max="50"></label></div><label>Prepublish public key paths (one per line, max 2)<textarea name="dnssecPrepublishPaths" rows="2" maxlength="1024"></textarea></label><label>Additional signing key paths (one per line, max 2)<textarea name="dnssecAdditionalPaths" rows="2" maxlength="1024"></textarea></label><label>Child delegations (child zone | nameserver | IP)<textarea name="delegations" rows="3" maxlength="12000"></textarea></label><label>Child DS records (child zone | key tag | algorithm | digest type | digest hex)<textarea name="delegationDs" rows="3" maxlength="12000"></textarea></label></details><p>All-down response is fail-closed. Site addresses are not probed by this editor. Actual binding, signing, authority and delegation require separately approved configuration.</p><button class="primary" type="submit">Validate and prepare unsigned zone</button></form><div id="specialist-result" role="status"></div></div>`;
}
async function wireSpecialistDeployment(module: string) {
    const generation = authGeneration;
    try {
        const config = await api('/admin/api/specialist/' + module + '-deployment');
        if (generation !== authGeneration || view !== module)
            return;
        if (config.configured !== true)
            return;
        $('content').insertAdjacentHTML('beforeend', '<div class="card card-spaced"><h3>Deploy independently signed specialist configuration</h3><p>Only the independently staged plan can be executed. The operator broker retains deployment credentials and authority. Preflight is read-only; actual agent signature checks apply at preparation. Applied is not an authority commit.</p><form id="waf-deploy-form" class="auth-form"><label>Approved revision<input name="revision" type="number" min="1" max="9007199254740991" required></label><label>Approved plan or policy SHA-256<input name="digest" pattern="[A-F0-9]{64}" maxlength="64" required></label><label>Operation<select name="operation"><option value="preflight">Read-only preflight</option><option value="execute">Execute signed rollout</option></select></label><label>Type operation (PREFLIGHT or EXECUTE), space, SHA-256<input name="confirmation" maxlength="74" required></label><button class="primary" type="submit">Submit approved operation</button></form><p id="waf-deploy-status" role="status"></p></div>');
        const form = $('waf-deploy-form') as HTMLFormElement;
        const status = $('waf-deploy-status');
        form.onsubmit = async (event) => {
            event.preventDefault();
            const button = form.querySelector('button') as HTMLButtonElement;
            if (button.disabled)
                return;
            const fields = new FormData(form);
            const revision = Number(fields.get('revision'));
            const digest = String(fields.get('digest') || '');
            const operation = String(fields.get('operation') || '');
            const confirmation = String(fields.get('confirmation') || '');
            if (!Number.isSafeInteger(revision) || revision < 1 || !/^[A-F0-9]{64}$/.test(digest) || confirmation !== operation.toUpperCase() + ' ' + digest) {
                status.textContent = 'Exact approved sequence or revision, digest and confirmation required.';
                return;
            }
            button.disabled = true;
            status.textContent = 'Running approved broker operation…';
            try {
                const result = await api('/admin/api/specialist/' + module + '-deployment', 'POST', { revision, digest, operation, confirmation });
                if (generation !== authGeneration || view !== module || !form.isConnected)
                    return;
                if (result.outcome === 'preflight-only')
                    status.textContent = 'Preflight passed; no mutation performed.';
                else if (result.outcome === 'applied-uncommitted')
                    status.textContent = 'Both nodes verified; independent authority commit still required.';
                else
                    throw Error('Outcome unconfirmed. Reconcile before retrying.');
            }
            catch (e) {
                if (generation === authGeneration && view === module && form.isConnected)
                    status.textContent = String(e);
            }
            finally {
                button.disabled = false;
            }
        };
    }
    catch {
        // Optional capability: absence never grants deployment authority.
    }
}
function wireSpecialistDraft(id: string) {
    if ((id === 'waf' || id === 'gslb') && currentRole === 'Administrator')
        void wireSpecialistDeployment(id);
    const form = document.getElementById('specialist-draft') as HTMLFormElement | null;
    if (!form)
        return;
    const result = $('specialist-result');
    const generation = authGeneration;
    form.onsubmit = async (event) => {
        event.preventDefault();
        const submit = form.querySelector('button[type="submit"]') as HTMLButtonElement;
        if (submit.disabled)
            return;
        submit.disabled = true;
        result.textContent = 'Validating candidate…';
        try {
            const fields = new FormData(form);
            const value: Obj = {};
            fields.forEach((v, k) => { value[k] = String(v); });
            const numeric = id === 'waf' ? ['revision', 'validDays'] : ['serial', 'ttl', 'probeInterval', 'failureThreshold', 'successThreshold'];
            numeric.forEach(k => { value[k] = Number(value[k]); });
            const optionalNumber = id === 'waf' ? 'rollbackFromRevision' : 'dnssecIterations';
            value[optionalNumber] = value[optionalNumber] === '' ? null : Number(value[optionalNumber]);
            const reply = await api('/admin/api/specialist/' + id + '-draft', 'POST', value);
            if (generation !== authGeneration || view !== id || !form.isConnected)
                return;
            if (reply.status !== 'unsigned-draft-only' || reply.deploymentReady !== false || typeof reply.json !== 'string' || !/^[A-F0-9]{64}$/.test(reply.sha256) || reply.byteLength !== new TextEncoder().encode(reply.json).length)
                throw Error('Candidate response could not be verified');
            result.innerHTML = '<p>Candidate validated for export only. Not signed or deployed.</p><p>Review fingerprint (SHA-256 of downloaded UTF-8 bytes): <code id="specialist-digest"></code></p><label>Exact candidate JSON<textarea readonly rows="12" id="specialist-json"></textarea></label><button type="button" class="ghost" id="specialist-download">Download unsigned JSON</button>';
            ($('specialist-json') as HTMLTextAreaElement).value = reply.json;
            $('specialist-digest').textContent = reply.sha256;
            $('specialist-download').onclick = () => {
                const url = URL.createObjectURL(new Blob([reply.json], { type: 'application/json' }));
                const link = document.createElement('a');
                link.href = url;
                link.download = id === 'waf' ? 'waf-policy-unsigned.json' : 'gslb-zone-unsigned.json';
                document.body.append(link);
                link.click();
                link.remove();
                setTimeout(() => URL.revokeObjectURL(url), 1000);
            };
        }
        catch (e) {
            if (generation === authGeneration && view === id && form.isConnected)
                result.textContent = String(e);
        }
        finally {
            submit.disabled = false;
        }
    };
}
function backendCertificateWizard() {
    if (currentRole !== 'Administrator' && currentRole !== 'Operator')
        return show('Authorized role required', true);
    const groups = keys(data.clusters);
    if (!groups.length)
        return show('Create an HTTPS backend group before assigning a certificate', true);
    modal('Configure backend client certificate', 'Use an installed and trusted client certificate. Verify it locally, then submit the backend group draft for independent approval. Every destination must use HTTPS.', [
        { name: 'cluster', label: 'Backend group', value: groups[0], options: groups },
        { name: 'thumbprint', label: 'Installed client certificate thumbprint', value: '' }
    ], () => {}, 'Check and apply to draft');
    const form = $('editor') as HTMLFormElement;
    const dialog = $('modal') as HTMLDialogElement;
    const submit = $('confirm') as HTMLButtonElement;
    const error = document.createElement('p');
    error.setAttribute('role', 'alert');
    $('modal-fields').append(error);
    const generation = authGeneration;
    form.onsubmit = async (event) => {
        if ((event as SubmitEvent).submitter?.getAttribute('value') === 'cancel')
            return;
        event.preventDefault();
        if (submit.disabled)
            return;
        const cluster = ($('f-cluster') as HTMLSelectElement).value;
        const thumbprint = ($('f-thumbprint') as HTMLInputElement).value;
        const original = data.clusters[cluster];
        const destinations = [...Object.values(original?.Destinations || {}), ...keys(data.disabled).filter(k => k.startsWith(cluster + '::')).map(k => data.disabled[k])] as Obj[];
        if (!original || !destinations.length || destinations.some(d => !String(d.Address || '').toLowerCase().startsWith('https://'))) {
            error.textContent = 'Every configured destination must use HTTPS.';
            return;
        }
        submit.disabled = true;
        error.textContent = '';
        try {
            const checked = await api('/admin/api/specialist/backend-certificate-check', 'POST', { thumbprint });
            if (generation !== authGeneration || view !== 'tls' || !dialog.open || data.clusters[cluster] !== original)
                return;
            if (!checked.localResolverAccepted || !/^[A-F0-9]{40}$/.test(checked.thumbprint))
                throw Error('Certificate resolution not confirmed');
            original.Metadata = { ...(original.Metadata || {}), BackendClientCertificateThumbprint: checked.thumbprint };
            dialog.close();
            edit();
            show('Client identity added to draft. Submit for independent approval and verify real backend mTLS.');
        }
        catch (e) {
            if (generation === authGeneration && dialog.open)
                error.textContent = String(e);
        }
        finally {
            submit.disabled = false;
        }
    };
}
function modulePage(id: string) {
    const multi = topologyResponse?.plan?.mode !== 'standalone';
    return specialistPlan(id) + specialistDraftForm(id) + (id === 'gslb' && multi ? `<div class="card"><h3>Authenticated DNS and agent evidence</h3><p>Inspect staged revisions and local observer quorum metrics via registered mTLS agents. This is not a direct DNS query.</p>${actionBtn('Inspect agent status', 'fleet-probe', '', 'primary')}</div>` : '') + `<div class="card"><h3>Related tools</h3>${actionBtn('Traffic engine & modules', 'switch', 'featurematrix', 'ghost')} ${actionBtn('User guide', 'switch', 'guide', 'ghost')}</div>`;
}
function render(){
 if(view!==lastRenderedView){if(!restoringNavigation){viewHistory.push(lastRenderedView);if(viewHistory.length>24)viewHistory.shift()}lastRenderedView=view}
 restoringNavigation=false;
 $('page-back').hidden=view==='setup'&&viewHistory.length===0;
 const names:Obj={guide:'User guide',organization:'Organization profile',setup:'Setup Center · 0.1',onboarding:'Architecture & setup',overview:'Overview',routes:'Routing rules',clusters:'Backend clusters',backends:'Backend management',health:'Health and diagnostics',backups:'Backups and audit',inventory:'Infrastructure inventory',users:'Administrators and roles',mail:'Mail & OTP',directory:'Active Directory (LDAPS)',approvals:'Change approvals',metrics:'Gateway metrics',fleet:'Gateway fleet',capabilities:'YARP capabilities',featurematrix:'Traffic Engine & platform modules',peers:'Peer synchronization',tls:'Certificates & TLS',waf:'WAF policy workflow',gslb:'DNS & GSLB workflow'};$('page-title').textContent=names[view];contextualHelp();$('page-subtitle').textContent=dirty?'Unsaved configuration changes — submit for approval':'Choose a task or open the user guide';$('gateway-pill').textContent=gatewayReadyLabel;$('gateway-pill').className=gatewayReadyWarn?'pill warn':'pill';$('save').textContent=dirty?'Submit for approval':'Submit for approval';document.querySelectorAll<HTMLButtonElement>('.nav').forEach(n=>{const selected=n.dataset.view===view;n.classList.toggle('active',selected);if(selected)n.setAttribute('aria-current','page');else n.removeAttribute('aria-current')});const pages:Obj={overview,routes,clusters,backends,health,capabilities,guide};updateTopologyNavigation();if(view==='organization')void organizationPage();else if(view==='featurematrix')void featureMatrix();else if(view==='tls')void certificatePage();else if(view==='waf'||view==='gslb'){$('content').innerHTML=modulePage(view);wireSpecialistDraft(view)}else if(view==='setup')void setupPage();else if(view==='onboarding')$('content').innerHTML=topologyPage();else if(view==='approvals')void approvals();else if(view==='metrics')void metrics();
    else if (view === 'peers') void peerSyncPage();else if(view==='backups')void backups();else if(view==='inventory')void inventory();else if(view==='fleet')void fleet();else if(view==='users')void users();else if(view==='mail')void mailPage();else if(view==='directory')void directoryPage();else {$('content').innerHTML=pages[view]();if(view==='guide')wireGuide();}}
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
function policySelectionHelp() {
    const select = $('f-policy') as HTMLSelectElement;
    const describe = () => {
        const p = policyGuide.find(x => x[0] === select.value);
        $('modal-help').textContent = (p ? p[1] + ': ' + p[2] : 'Review the selected policy.') + ' Use an actual readiness endpoint. Changes remain a draft pending independent approval.';
    };
    select.onchange = describe;
    describe();
}
function updateCluster(id=''){const old=data.clusters[id]||{Destinations:{},LoadBalancingPolicy:'RoundRobin',HealthCheck:{Active:{Enabled:false,Interval:'00:00:15',Timeout:'00:00:05',Path:'/health/ready',Policy:'ConsecutiveFailures'}}};modal(id?'Edit cluster':'Add cluster','Health checks need a real backend readiness endpoint. PrimaryBackup requires active checks and never retries non-idempotent requests.',[{name:'id',label:'Cluster ID',value:id},{name:'policy',label:'Load balancing',value:old.LoadBalancingPolicy||'RoundRobin',options:['RoundRobin','PowerOfTwoChoices','LeastRequests','Random','FirstAlphabetical','WeightedRandom','WeightedLeastRequests','WeightedRoundRobin','FastestResponse','SourceIpHash','PrimaryBackup']},{name:'health',label:'Active health checks',value:String(!!old.HealthCheck?.Active?.Enabled),options:['false','true']},{name:'path',label:'Health path',value:old.HealthCheck?.Active?.Path||'/health/ready'}],v=>{if(!validId(v.id)||!v.path.startsWith('/'))throw Error('Invalid cluster ID or path');if(v.id!==id&&data.clusters[v.id])throw Error('Cluster exists');if(id&&(monitorMembers(id).length||old.Metadata?.[monitorSourceKey])&&(v.id!==id||v.health!==String(!!old.HealthCheck?.Active?.Enabled)||v.path!==(old.HealthCheck?.Active?.Path||'/health/ready')))throw Error('Use the source health monitor editor or unlink dependent groups first');if(v.policy==='PrimaryBackup'&&v.health!=='true')throw Error('PrimaryBackup requires active health checks');const c={...old,LoadBalancingPolicy:v.policy,HealthCheck:{...old.HealthCheck,Active:{...(old.HealthCheck?.Active||{}),Enabled:v.health==='true',Path:v.path}}};if(id&&id!==v.id){delete data.clusters[id];for(const rid of keys(data.routes)){if(data.routes[rid].ClusterId===id)data.routes[rid].ClusterId=v.id}}data.clusters[v.id]=c;edit()});policySelectionHelp()}
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
    if (type === 'monitor-edit') { editActiveMonitor(id); return; }
    if (type === 'monitor-unlink') { unlinkActiveMonitor(id); return; }
    if (type === 'profile-add' || type === 'profile-edit') { editMonitorProfile(type === 'profile-edit' ? id : ''); return; }
    if (type === 'profile-delete') { deleteMonitorProfile(id); return; }
    if (type === 'real-server-add' || type === 'real-server-edit') { editRealServer(type === 'real-server-edit' ? id : ''); return; }
    if (type === 'real-server-delete') { deleteRealServer(id); return; }
    if (type === 'real-server-assign') { assignRealServer(id); return; }
    if (type === 'service-group-add' || type === 'service-group-edit') { editServiceGroup(type === 'service-group-edit' ? id : ''); return; }
    if (type === 'service-group-members') { editServiceGroupMember(id); return; }
    if (type === 'service-group-delete') { deleteServiceGroup(id); return; }
    if (type === 'service-group-deploy') { deployServiceGroup(id); return; }
    if (type === 'persistence-edit') { editSecurePersistence(id); return; }
    if (type === 'route-access') { editApplicationAccess(id); return; }
    if (type === 'route-bind-socket') { void bindVirtualService(id); return; }
    if (type === 'profile-assign') { assignMonitorProfile(id); return; }
    if (type === 'monitor-copy') { copyActiveMonitor(id); return; }
 if(type==='invite-add'){inviteEmployee();return}
 if(type==='invite-revoke'){void revokeEmployeeInvite(id);return}
 if(type==='backend-cert'){backendCertificateWizard();return}
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
     if(view==='approvals')$('content').innerHTML=changeReview(r);
   }).catch(e=>show(String(e),true));return;
 }
 if(type==='approval-approve'||type==='approval-reject'){
   reasonDialog(type === 'approval-approve' ? 'Approve configuration' : 'Reject configuration', 'This decision applies to the exact saved request. Approving may change live routing. Verify the configuration and operational change window before continuing.', 10, type === 'approval-approve' ? 'Approve request' : 'Reject request', async reason => {
            const r = await api('/admin/api/change-requests/' + encodeURIComponent(id) + '/decision', 'POST', { decision: type === 'approval-approve' ? 'approve' : 'reject', reason });
            await reload();
            view = 'approvals';
            render();
            show('Request ' + r.status);
        });
   return;
 }
if(type==='route-advanced'||type==='cluster-advanced'||type==='dest-advanced'){advancedJson(type==='route-advanced'?'route':type==='cluster-advanced'?'cluster':'destination',id);return}if(type==='switch'){view=id;render();return}if(type==='route-add'||type==='route-edit'){if(!keys(data.clusters).length)return show('Create a cluster before adding routes',true);updateRoute(type==='route-edit'?id:'');return}if(type==='route-delete'){if(confirm('Delete route '+id+' from draft?')){delete data.routes[id];edit()}return}if(type==='cluster-add'||type==='cluster-edit'){updateCluster(type==='cluster-edit'?id:'');return}if(type==='cluster-delete'){if(monitorMembers(id).length)return show('Unlink dependent monitors first',true);if(keys(data.routes).some(r=>data.routes[r].ClusterId===id))return show('Remove routes referencing this cluster first',true);if(confirm('Delete cluster '+id+'?')){delete data.clusters[id];for(const k of keys(data.disabled))if(k.startsWith(id+'::'))delete data.disabled[k];edit()}return}if(type==='dest-add'||type==='dest-edit'){if(!keys(data.clusters).length)return show('Create a cluster first',true);updateDest(type==='dest-edit'?id:'');return}if(type==='dest-toggle'){const [c,d]=id.split('::');if(data.disabled[id]){data.clusters[c].Destinations[d]=data.disabled[id];delete data.disabled[id]}else{data.disabled[id]=data.clusters[c].Destinations[d];delete data.clusters[c].Destinations[d]}edit();return}if(type==='dest-delete'){const [c,d]=id.split('::');if(confirm('Delete destination '+id+'?')){if(data.clusters[c])delete data.clusters[c].Destinations[d];delete data.disabled[id];edit()}return}if(type==='probe'){show('Running on-demand probes...');api('/admin/api/probe','POST',{}).then(r=>{probes=r.results;render();show('Probe completed. This is not the internal YARP health state.')}).catch(e=>show(String(e),true));return}if(type==='fleet-add'){addFleet();return}if(type==='fleet-remove'){if(!confirm('Remove gateway '+id+' from inventory?'))return;api('/admin/api/fleet/'+encodeURIComponent(id),'DELETE',{}).then(()=>void fleet()).catch(e=>show(String(e),true));return}if(type==='fleet-probe'){void fleetStatus();return}if(type==='fleet-journal'){void fleetJournal();return}if(type==='fleet-recover'){void recoverFleetRollout(id);return}if(type==='fleet-rollout'){void performFleetRollout();return}if(type==='dest-metrics'){void destinationMetrics();return}if(type==='inventory-add'){addInventory();return}if(type==='inventory-delete'){if(!confirm('Remove inventory item '+id+'?'))return;api('/admin/api/inventory/'+encodeURIComponent(id),'DELETE',{}).then(()=>void inventory()).catch(e=>show(String(e),true));return}if(type==='user-add'){addUser();return}if(type==='mail-settings'){view='mail';render();return}if(type==='mail-test'){void api('/admin/api/mail/test','POST',{}).then(r=>{show('SMTP accepted test message for '+r.recipient);void mailPage()}).catch(e=>show('Mail test failed: '+String(e)+'. Save a relay configuration first; verify administrator email and STARTTLS.',true));return}if(type==='directory-test'){void api('/admin/api/directory/test','POST',{}).then(()=>show('LDAPS trust, bind and group lookup verified')).catch(e=>show(String(e),true));return}if(type==='user-disable'||type==='user-enable'){if(!confirm((type==='user-disable'?'Offboard ':'Re-enable ')+id+'?'))return;api('/admin/api/users/'+encodeURIComponent(id)+'/'+(type==='user-disable'?'disable':'enable'),'POST',{}).then(()=>void users()).catch(e=>show(String(e),true));return}if(type==='password-reset'){resetPassword(id);return}if(type==='restore'){if(!confirm('Restore '+id+'? This changes live config and saves a safety backup.'))return;api('/admin/api/restore/'+encodeURIComponent(id),'POST',{}).then(()=>{show('Backup restored');void reload()}).catch(e=>show(String(e),true))}}
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
async function employeeInvitationPanel() {
    try {
        const methods = await api('/admin/api/auth-methods');
        if (!methods.employeeInvitations)
            return '<div class="card card-spaced"><h3>Employee invitations</h3><p>Available on an ordinary local-account gateway with verified SMTP. Enterprise and multi-gateway enrollment use their approved identity workflows.</p></div>';
        const pending = await api('/admin/api/users/invitations');
        const rows = pending.map((x: Obj) => `<tr><td>${esc(x.username)}</td><td>${esc(x.emailHint)}</td><td>${esc(x.role)}</td><td>${esc(x.status)}</td><td>${esc(x.expiresUtc)}</td><td>${actionBtn('Revoke invitation', 'invite-revoke', x.id, 'danger-btn mini')}</td></tr>`).join('');
        return `<div class="card card-spaced"><div class="toolbar"><div><h3>Employee invitations</h3><p>Assign a role and send a one-time email code. Employees choose their own password. Pending invitations expire or are lost on service restart.</p></div>${actionBtn('+ Invite employee', 'invite-add', '', 'primary')}</div><div class="tablewrap"><table><thead><tr><th>Username</th><th>Email</th><th>Role</th><th>Status</th><th>Expiry (UTC)</th><th>Action</th></tr></thead><tbody>${rows || '<tr><td colspan="6">No pending invitations.</td></tr>'}</tbody></table></div></div>`;
    }
    catch (e) {
        return '<div class="card card-spaced"><h3>Employee invitations</h3><p>Invitation status unavailable. No invitation availability is claimed.</p></div>';
    }
}
function inviteEmployee() {
    if (currentRole !== 'Administrator')
        return show('Administrator role required', true);
    modal('Invite employee', 'Use the employee’s company mailbox. The invitation expires in 30 minutes; the employee chooses their own password after verifying the emailed code.', [
        { name: 'username', label: 'Named employee username', value: '' },
        { name: 'email', label: 'Employee company email', value: '', kind: 'email' },
        { name: 'role', label: 'Employee role', value: 'Viewer', options: ['Viewer', 'Operator'] }
    ], async (v) => {
        try {
            await api('/admin/api/users/invitations', 'POST', v);
            if (view === 'users')
                await users();
            show('Invitation sent. Ask the employee to open the approved dashboard and accept the emailed code.');
        }
        catch (e) {
            show(String(e), true);
        }
    }, 'Send invitation');
}
async function revokeEmployeeInvite(id: string) {
    if (currentRole !== 'Administrator' || !confirm('Revoke this pending invitation? The employee must receive a new invitation.'))
        return;
    try {
        await api('/admin/api/users/invitations/' + encodeURIComponent(id) + '/revoke', 'POST', {});
        if (view === 'users')
            await users();
        show('Invitation revoked');
    }
    catch (e) {
        show(String(e), true);
    }
}
async function users(){try{const list=await api('/admin/api/users');
 const invitationPanel = await employeeInvitationPanel();
 if (view !== 'users')
     return;
 const rows=list.map((x:Obj)=>`<tr><td><b>${esc(x.username)}</b></td><td>${esc(x.email||'—')}</td><td>${esc(x.role)}</td><td>${esc(x.provider||'Local')}</td><td><span class="chip ${x.enabled?'good':'bad'}">${x.enabled?'Enabled':'Disabled'}</span></td><td>${x.provider==='AD'?'AD password managed by directory':actionBtn('Reset password','password-reset',x.username)} ${actionBtn(x.enabled?'Offboard':'Re-enable',x.enabled?'user-disable':'user-enable',x.username)}</td></tr>`).join('');
 $('content').innerHTML=`<div class="toolbar"><div><h2>Administrator accounts</h2><p class="subtle">Administrators onboard/offboard users; Operators manage routes; Viewers read only. Disabling an account blocks new sign-ins and invalidates existing sessions. Inactive sessions expire after 30 minutes.</p></div>${actionBtn('+ Add account','user-add','')} ${actionBtn('Mail & OTP','switch','mail')} ${actionBtn('Active Directory','switch','directory')}</div><div class="tablewrap"><table><thead><tr><th>Username</th><th>Email</th><th>Role</th><th>Authentication</th><th>Status</th><th>Action</th></tr></thead><tbody>${rows}</tbody></table></div>${invitationPanel}`;
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
