// Five-screen regression for the real compiled browser script. This is a
// deterministic DOM-model test, not proof of a physical laptop browser run.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {createHash,webcrypto} from 'node:crypto';
const js=fs.readFileSync(new URL('../wwwroot/app.js',import.meta.url),'utf8');
const html=fs.readFileSync(new URL('../wwwroot/index.html',import.meta.url),'utf8');
const prefix=js.split("$('content').addEventListener('click'")[0];
const nodes=new Map();
const fieldValues=new Map();
let modalOpen=0,modalClosed=0;
function el(id) {
  if(!nodes.has(id)) nodes.set(id,{
    id,innerHTML:'',textContent:'',hidden:false,className:'',dataset:{},value:'',
    classList:{toggle(){}},
    showModal(){modalOpen++;},close(){modalClosed++;},
    querySelectorAll(){return []}
  });
  return nodes.get(id);
}
let calls=[];
const state={
  version:'0.1',channel:'development',verifiedForProduction:false,
  gateway:'LAB',mode:'standalone',topologyConfirmed:false,routeCount:1,
  clusterCount:1,destinationCount:1,activeHealthClusterCount:0,fleetEntries:0,
  transport:'local',freeze:{frozen:false,reason:'',updatedBy:''},
  stages:[{id:'routing',title:'Routes',status:'configured',evidence:'one route',action:'routes'}]
};
const ctx=vm.createContext({
  console,URL,TextEncoder,setTimeout:()=>0,clearTimeout:()=>{},
  prompt:()=>'',confirm:()=>true,
  fetch:async (url,opts={})=>{
    calls.push({url,opts});
    return {ok:true,status:200,json:async()=>url==='/admin/api/setup/overview'?state:{results:[]}};
  },
  document:{getElementById:el,querySelectorAll:()=>[]}
});
vm.runInContext(prefix,ctx);
// The password editor is declared below the browser event wiring. Evaluate
// that exact production function in this isolated DOM context, not a stub.
const passwordStart=js.indexOf('function resetPassword(');
const passwordEnd=js.indexOf('async function mailPage()',passwordStart);
assert.ok(passwordStart>0&&passwordEnd>passwordStart,'password editor must be present');
vm.runInContext(js.slice(passwordStart,passwordEnd),ctx);
const run=(src)=>vm.runInContext(src,ctx);
// 1. Setup Center: accessible entry points and observable stage status.
run("currentRole='Administrator';csrf='test-csrf';");
await run('setupPage()');
assert.match(el('content').innerHTML,/FIRST-RUN BOOTSTRAP/);
assert.match(el('content').innerHTML,/setup-add-application/);
assert.match(el('content').innerHTML,/setup-local-web/);
// 2. Architecture & setup: single origin and exit/back without draft loss.
assert.equal(run('topologyDefaults().workloads.length'),1);
run("topologyDraft=topologyDefaults();topologyStep=0;");
assert.match(run('topologyPage()'),/Exit to Setup Center/);
run("topologyStep=2;");
assert.match(run('topologyStepHtml()'),/Hosting engine/);
assert.match(run('topologyStepHtml()'),/Microsoft IIS/);
assert.match(run('topologyStepHtml()'),/Kubernetes Ingress \(external\)/);
// 3. Add Website: guarded local HTTP wizard and distinct advanced public path.
run("topologyResponse={status:'design-confirmed',plan:{mode:'standalone'}};data={clusters:{},routes:{},disabled:{}};");
run('addLocalWebWizard()');
assert.equal(el('modal-title').textContent,'Local web-server test (IIS, Apache, Nginx, or other HTTP origin)');
assert.match(el('modal-fields').innerHTML,/Hosting software/);
assert.match(el('modal-fields').innerHTML,/Local test website URL/);
assert.ok(modalOpen>0);
assert.match(js,/Remote web servers require HTTPS and independent approval/);
assert.match(js,/function addApplicationWizard\(\)/);
// 4. Edit Route: blank hostnames are truly optional, preserving route shape.
run("data.clusters.iis={Destinations:{iis01:{Address:'http://127.0.0.1/'}}};data.routes.iis={ClusterId:'iis',Match:{Path:'/proxy/{**catch-all}'}};");
run("updateRoute('iis')");
assert.equal(el('modal-title').textContent,'Edit route');
assert.match(el('modal-fields').innerHTML,/Hostnames \(comma-separated, optional\)/);
assert.doesNotMatch(el('modal-fields').innerHTML,/<input[^>]*id="f-hosts"[^>]*required/);
assert.equal(el('confirm').textContent,'Apply to draft');
assert.match(el('modal-fields').innerHTML,/\/proxy\/\{\*\*catch-all\}/);
// 5. Reset Password: explicit action and 16 character minimum (no draft).
run("resetPassword('testadmin')");
assert.equal(el('modal-title').textContent,'Reset testadmin password');
assert.equal(el('confirm').textContent,'Reset password');
assert.match(el('modal-fields').innerHTML,/minlength="16"/);
assert.match(el('modal-fields').innerHTML,/type="password"/);
assert.match(html,/id="modal-close"/);
assert.match(html,/id="page-back"/);
assert.match(html,/value="cancel"/);
console.log('PASS: Setup Center, Architecture, Add Website, Edit Route and Reset Password smoke contracts');

// HA policy export must verify server bytes and the actual reviewed proposal.
const haProposal={version:1,scope:'A'.repeat(64),preferredPin:'B'.repeat(64),
  otherPin:'C'.repeat(64),failbackEnabled:false,rearmEnabled:false,
  pollSeconds:5,failureSamples:3,failureSeconds:10,failbackEligibleSeconds:120,minimumOwnerSeconds:300};
const haReply=(document,applied=false)=>{
  const json=JSON.stringify(document);
  return {json,applied,sha256:createHash('sha256').update(json).digest('hex').toUpperCase()};
};
ctx.crypto=webcrypto;
ctx.haProposal=haProposal;
ctx.haReply=haReply(haProposal);
assert.equal(await run('verifiedHaPolicyExport(haReply,haProposal)'),ctx.haReply.json);
for(const [reply,pattern] of [
  [{...haReply(haProposal),sha256:'0'.repeat(64)},/digest mismatch/],
  [haReply(haProposal,true),/response is invalid/],
  [haReply({...haProposal,preferredPin:'D'.repeat(64)}),/does not match/],
  [haReply({...haProposal,unexpected:true}),/does not match/]
]){
  ctx.haReply=reply;
  await assert.rejects(run('verifiedHaPolicyExport(haReply,haProposal)'),pattern);
}
ctx.haReply=haReply(haProposal);
delete ctx.crypto;
await assert.rejects(run('verifiedHaPolicyExport(haReply,haProposal)'),/Secure browser context/);
console.log('PASS: HA policy byte digest, reviewed values, non-applied response and secure-context checks');
