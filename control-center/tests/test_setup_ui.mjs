import fs from 'node:fs';
import assert from 'node:assert/strict';
import vm from 'node:vm';
const app = fs.readFileSync(new URL('../wwwroot/app.js',import.meta.url),'utf8');
const prefix = app.split("$('content').addEventListener('click'")[0];
assert.ok(prefix.length>10000);
const nodes = new Map();
const getNode = (id)=> { if(!nodes.has(id)) nodes.set(id,{innerHTML:'',textContent:'',hidden:false,className:'',dataset:{},classList:{toggle(){}}}); return nodes.get(id) };
let records=[];
const overview = {
 version:'0.1', channel:'development', verifiedForProduction:false, gateway:'LAB-01', mode:'ha-pair', topologyConfirmed:false,
 routeCount:1, clusterCount:1, destinationCount:2, activeHealthClusterCount:0, fleetEntries:0, transport:'http-loopback',
 freeze:{frozen:true,reason:'Maintenance <script>alert(1)</script>',updatedBy:'admin'},
 stages:[{id:'administrator',title:'Recovery administrator',status:'configured',evidence:'1 admin',action:'users'},
         {id:'audit',title:'Independent immutable audit',status:'not-implemented',evidence:'No WORM destination',action:'backups'}]
};
let returns={ '/admin/api/setup/overview': overview, '/admin/api/setup/freeze': {frozen:false},
 '/admin/api/runtime/destinations': {clusters:[{clusterId:'api',destinations:[{destinationId:'app-01',activeHealth:'Unknown',passiveHealth:'Unknown',concurrentRequests:0}]}]}};
const ctx = vm.createContext({console, setTimeout,clearTimeout,URL,TextEncoder,
  prompt:()=> 'Authorized freeze release after maintenance',confirm:()=>true,
  fetch:async(uri,opts={})=>{records.push({uri,opts});return {ok:true,status:200,json:async()=>returns[uri]}}
  ,document:{getElementById:getNode,querySelectorAll:()=>[]}
});
vm.runInContext(prefix,ctx);
vm.runInContext('currentRole="Administrator";csrf="test-csrf";',ctx);
await vm.runInContext('setupPage()',ctx);
const html=getNode('content').innerHTML;
assert.ok(html.includes('FIRST-RUN BOOTSTRAP'));
assert.ok(html.includes('Version 0.1'));
assert.ok(html.includes('Routing change freeze is ON'));
assert.ok(html.includes('&lt;script&gt;alert(1)&lt;/script&gt;'), 'rendered evidence must be escaped');
assert.ok(!html.includes('Maintenance <script>'), 'no unsanitized response HTML');
assert.ok(html.includes('not implemented'), 'feature gaps must remain visible');
assert.ok(html.includes('setup-add-application'), 'guided public app onboarding action exists');
await vm.runInContext('setupLiveHealth()',ctx);
assert.ok(getNode('setup-live-output').innerHTML.includes('Unknown'));
await vm.runInContext('setupFreeze(false)',ctx);
const post = records.find(x=>x.uri==='/admin/api/setup/freeze' && x.opts.method==='POST');
assert.ok(post);
assert.equal(post.opts.headers['X-CSRF-Token'],'test-csrf');
assert.equal(JSON.parse(post.opts.body).frozen,false);
assert.equal(vm.runInContext('readyClass("not-implemented")',ctx),'bad');
assert.equal(vm.runInContext('topologyDefaults().mode',ctx),'standalone');
assert.ok(!app.includes('style="'),'no unsafe inline styles in generated app');
console.log('PASS: 0.1 setup bootstrapping UI, evidence escaping, runtime health render, freeze CSRF and no inline styles');
