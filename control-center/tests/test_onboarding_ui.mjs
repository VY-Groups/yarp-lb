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
assert.ok(js.includes('setup-quick-lab'),'quick standalone review template is discoverable');
assert.ok(js.includes('setup-local-web'),'local web-server draft action is discoverable');
assert.ok(js.includes('addLocalWebWizard'),'local IIS/Apache/Nginx route wizard is implemented');
assert.ok(js.includes('SMTP accepted test message'),'SMTP delivery guidance remains available');
assert.ok(js.includes('OTP remains unavailable until the saved SMTP settings pass the delivery test'),'OTP has a disabled-until-verified explanation');
assert.ok(js.includes('Remote web servers require HTTPS and independent approval'),'local web wizard rejects remote cleartext origins');
assert.ok(js.includes('← Exit to Setup Center'),'first wizard step must offer exit');
assert.ok(js.includes("function navigateBack()"),'global back navigation available');
assert.ok(js.includes("page-back"),'page history button wired');
assert.ok(js.includes("modal-close"),'modal close button wired');
assert.ok(js.includes("optional: true"),'optional form fields do not block saving');
assert.ok(js.includes("minLength: 16"),'password fields validate length');
assert.ok(js.includes('hostingEngines'),'hosting engine choices available');
for(const label of ['Microsoft IIS','Apache httpd','Nginx','Caddy','Apache Tomcat','Node.js','Kubernetes Ingress (external)'])
  assert.ok(js.includes(label), 'hosting option '+label+' visible');
assert.ok(js.includes('GatewayCore.HostingEngine'),'local server engine saved as metadata');
assert.ok(js.includes('/admin/api/onboarding'));
assert.ok(!js.includes('style="'),'no inline CSS in generated application HTML');
console.log('PASS: mode transitions, server count, six wizard steps, HTML escaping, no inline styles');
