// Source-linked operator UX regression contracts. Browser E2E separately
// verifies actual HTTP/DOM, no fake success claims from this test.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const html = fs.readFileSync(new URL('../wwwroot/index.html',import.meta.url),'utf8');
const css = fs.readFileSync(new URL('../wwwroot/style.css',import.meta.url),'utf8');
const js = fs.readFileSync(new URL('../wwwroot/app.js',import.meta.url),'utf8');
const ts = fs.readFileSync(new URL('../wwwroot/app.ts',import.meta.url),'utf8');
for(const part of ['auth-layout','auth-intro','auth-panel','nav-group','workspace-label','page-header','peer-status-card']) {
  assert.match(part === 'peer-status-card' ? css : html, new RegExp(part));
}
for(const id of ['auth-screen','auth-form','auth-submit','auth-otp','auth-provider','app-shell','page-back','page-title','notice','content','modal','editor','logout','save']) {
  assert.match(html,new RegExp('id="'+id+'"'),'missing management DOM contract '+id);
}
const nav=[...html.matchAll(/data-view="([^"]+)"/g)].map(match=>match[1]);
assert.equal(new Set(nav).size,nav.length,'navigation must not duplicate pages');
assert.ok(nav.length>=19, 'all existing pages plus peer status must remain navigable');
assert.ok(nav.includes('peers'));
assert.match(html,/GatewayCore Control Center/);
assert.match(js,/Sign in to GatewayCore/);
assert.match(ts,/Sign in to GatewayCore/);
assert.doesNotMatch(js,/YARP Control Center/,'customer-facing product naming must be consistent');

assert.match(html,/aria-label="Primary navigation"/);
assert.doesNotMatch(html,/style="/,'styles must remain in reviewed stylesheet');
assert.ok(js.includes("aria-current"));
assert.ok(ts.includes("aria-current"));
assert.ok(js.includes("async function peerSyncPage()"));
assert.ok(ts.includes("async function peerSyncPage()"));
assert.ok(css.includes('@media(max-width:950px)'));

const elements=new Map();
function node(id){if(!elements.has(id)) elements.set(id,{innerHTML:'',textContent:'',hidden:false,className:'',dataset:{},classList:{toggle(){}}});return elements.get(id)}
const ctx=vm.createContext({
  console, URL, TextEncoder, setTimeout:()=>0, clearTimeout(){},
  document:{getElementById:node,querySelectorAll:()=>[]},
  fetch:async(url)=>{
    assert.equal(url,'/admin/api/peer-sync/status');
    return {ok:true,status:200,json:async()=>({
      enabled:true,recentExchange:false,remoteReportedInCurrentMinute:false,
      localNode:'<script>alert(1)</script>',remoteNode:'node-b',
      localIdentities:2,localRequests:5,remoteIdentities:0,remoteRequests:0,
      remoteSequence:0,trackedIdentityLimit:2048,strictAdmission:'atomic Redis'
    })};
  }
});
vm.runInContext(js.split("$('content').addEventListener('click'")[0],ctx);
vm.runInContext("view='peers';",ctx);
await vm.runInContext('peerSyncPage()',ctx);
const content=node('content').innerHTML;
assert.match(content,/No recent exchange/);
assert.match(content,/atomic Redis/);
assert.match(content,/&lt;script&gt;/);
assert.doesNotMatch(content,/<script>alert/);
assert.match(content,/Best-effort status only/);

// Fleet status must expose only agent-reported engine configuration metadata
// and must label runtime DNS health and quorum as unverified.
const fleetElements=new Map();
function fleetNode(id){if(!fleetElements.has(id))fleetElements.set(id,{innerHTML:'',textContent:'',hidden:false,className:'',dataset:{},classList:{toggle(){}}});return fleetElements.get(id)}
const fleetCtx=vm.createContext({
  console,URL,TextEncoder,setTimeout:()=>0,clearTimeout(){},
  document:{getElementById:fleetNode,querySelectorAll:()=>[]},
  fetch:async url=>{
    assert.equal(url,'/admin/api/fleet/status');
    return {ok:true,status:200,json:async()=>({
      type:'mTLS agent and signed engine-configuration status; not live DNS or YARP destination health',
      gateways:[{id:'<img src=x>',state:'connected',report:{machine:'node-a',engineConfigStagingEnabled:true},engineConfigState:'available',engines:[{engineId:'gslb',revision:'A'.repeat(64),mode:'signed-file-staging-only',serviceRestarted:false}] }]
    })};
  }
});
const fleetStart=js.indexOf('async function fleetStatus()');
const fleetEnd=js.indexOf('async function performFleetRollout()',fleetStart);
assert.ok(fleetStart>0&&fleetEnd>fleetStart,'compiled fleet status view must exist');
vm.runInContext(js.slice(0,js.indexOf("$('content').addEventListener('click'")),fleetCtx);
vm.runInContext(js.slice(fleetStart,fleetEnd),fleetCtx);
await vm.runInContext('fleetStatus()',fleetCtx);
const fleetContent=fleetNode('content').innerHTML;
assert.match(fleetContent,/GSLB DNS configuration/);
assert.match(fleetContent,/AAAAAAAAAAAA/);
assert.match(fleetContent,/Restart required/);
assert.match(fleetContent,/not proof the DNS process restarted or is healthy/);
assert.match(fleetContent,/does not query DNS answers or authoritative-node quorum/);
assert.match(fleetContent,/&lt;img src=x&gt;/);
assert.doesNotMatch(fleetContent,/<img src=x>/);
console.log('PASS: grouped navigation, auth shell, responsive CSS, authenticated peer status and escaped DOM values');
