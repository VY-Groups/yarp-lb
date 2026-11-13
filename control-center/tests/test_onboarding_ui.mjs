// Deterministic smoke test of browser-ready JS wizard, without external packages.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import vm from 'node:vm';
const js=fs.readFileSync(new URL('../wwwroot/app.js',import.meta.url),'utf8');
const prefix=js.split("$('content').addEventListener('click'")[0];
assert.ok(prefix.length>10000,'expected compiled application prefix');
const ctx=vm.createContext({console,setTimeout,clearTimeout,confirm:()=>true,prompt:()=>'',URL,TextEncoder,fetch:async()=>{throw Error('Network not expected in static UI test')},document:{getElementById:()=>({}),querySelectorAll:()=>[]}});
vm.runInContext(prefix,ctx);
const get=(expr)=>vm.runInContext(expr,ctx);
assert.equal(get('topologyDefaults().mode'),'standalone');
assert.equal(get('topologyDefaults().gateways.length'),1);
vm.runInContext('topologyDraft=topologyDefaults(); topologyModeChange("ha-pair");',ctx);
assert.equal(get('topologyDraft.gateways.length'),2);
assert.equal(get('topologyDraft.controlPlane'),'ha-controller');
vm.runInContext('topologyModeChange("fleet")',ctx);
assert.equal(get('topologyDraft.gateways.length'),3);
vm.runInContext('topologyDraft.gateways[0].hostname="<script>alert(1)</script>";topologyStep=1;',ctx);
const step1=get('topologyStepHtml()');
assert.ok(step1.includes('&lt;script&gt;alert(1)&lt;/script&gt;'));
assert.ok(!step1.includes('value="<script>'));
for(let i=0;i<6;i++){
 vm.runInContext(`topologyStep=${i}`,ctx);
 assert.ok(get('topologyStepHtml()').length>150,`step ${i} is not rendered`);
}
assert.ok(js.includes('/admin/api/onboarding'));
assert.ok(!js.includes('style="'),'no inline CSS in generated application HTML');
console.log('PASS: mode transitions, server count, six wizard steps, HTML escaping, no inline styles');
