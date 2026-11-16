// Uses the shipped compiled browser functions, never a mock implementation
// of session cleanup or post-logout request invalidation.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const js=fs.readFileSync(new URL('../wwwroot/app.js',import.meta.url),'utf8');
const nodes=new Map();
function element(id) {
  if(!nodes.has(id))nodes.set(id,{
    id,hidden:false,textContent:'',innerHTML:'',dataset:{},className:'',value:'test-secret',
    required:false,minLength:0,disabled:false,
    classList:{toggle(){}},
    querySelectorAll(){return []},
    setAttribute(){},removeAttribute(){}
  });
  return nodes.get(id);
}
let delayed;
const ctx=vm.createContext({
  console, URL, TextEncoder, setTimeout:()=>0, clearTimeout:()=>{},
  confirm:()=>true,prompt:()=>'',document:{
    getElementById:element,querySelectorAll:()=>[]
  },
  fetch:async url=>{
    if(url==='/admin/api/auth-methods')return {ok:true,status:200,json:async()=>({activeDirectory:false})};
    if(url==='/admin/api/state')return await new Promise(resolve=>{delayed=resolve});
    throw Error('Unexpected request '+url);
  }
});
vm.runInContext(js.split("$('content').addEventListener('click'")[0],ctx);
const start=js.indexOf('function showLogin(first) {');
const stop=js.indexOf("$('auth-provider').onchange",start);
assert.ok(start>0&&stop>start,'extract actual browser session cleanup function');
vm.runInContext(js.slice(start,stop),ctx);
const run=expr=>vm.runInContext(expr,ctx);
run("csrf='real-token';currentRole='Administrator';currentUser='former-operator';dirty=true;view='routes';viewHistory=['overview'];lastRenderedView='routes';data.routes={private: {ClusterId:'secret'}};probes=[{address:'secret'}];orgProfile={organizationName:'Private Organization'};topologyDraft={private:'draft'};topologyResponse={private:'site'};otpChallenge='former-challenge';");
element('app-shell').hidden=false;
run("showLogin(false)");
assert.equal(run('csrf'),'');
assert.equal(run('currentRole'),'');
assert.equal(run('currentUser'),'');
assert.equal(run('dirty'),false);
assert.equal(run('Object.keys(data.routes).length'),0);
assert.equal(run('probes.length'),0);
assert.equal(run('topologyDraft'),null);
assert.equal(run('topologyResponse'),null);
assert.equal(run('orgProfile'),null);
assert.equal(run('otpChallenge'),'');
assert.equal(run('view'),'setup');
assert.equal(run('viewHistory.length'),0);
assert.equal(element('auth-password').value,'');
assert.equal(element('auth-otp').value,'');
assert.equal(element('auth-email').value,'');
assert.equal(element('auth-username').value,'');
assert.equal(element('content').innerHTML,'');
assert.equal(element('user-badge').textContent,'');
assert.equal(element('app-shell').hidden,true);
assert.equal(element('auth-screen').hidden,false);

run("csrf='fresh-session';currentRole='Administrator';");
const request=run("api('/admin/api/state')");
await Promise.resolve();
assert.equal(typeof delayed,'function');
run("showLogin(false)");
delayed({ok:true,status:200,json:async()=>({routes:{leaked:{}}})});
await assert.rejects(request,/Outdated response ignored/);
assert.equal(run('Object.keys(data.routes).length'),0);
assert.match(js,/unsubmitted configuration draft will be discarded/);
assert.match(js,/submit.disabled = true;/);
assert.match(js,/submit.disabled = false;/);
assert.match(js,/admin\/api\/gateway-readiness/);
assert.match(js,/Backend readiness observed/);
assert.match(js,/No healthy backend reported/);
console.log('PASS: logout/expiry purges drafts and credentials; stale async responses rejected; live readiness status wired');
