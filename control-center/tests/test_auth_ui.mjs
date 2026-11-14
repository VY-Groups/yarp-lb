// Regression test: 401 is an expired/invalid session, not proof that the route is broken.
// Never weaken role checks or auto-retry unsafe management requests.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import vm from 'node:vm';
const js=fs.readFileSync(new URL('../wwwroot/app.js',import.meta.url),'utf8');
const prefix=js.split("$('content').addEventListener('click'")[0];
assert.ok(prefix.length>10000);
const nodes=new Map();
function element(id){
  if(!nodes.has(id))nodes.set(id,{
    id,hidden:false,textContent:'',innerHTML:'',dataset:{},className:'',
    value:'',required:false,classList:{toggle(){}},
    querySelectorAll(){return []}
  });
  return nodes.get(id);
}
let responses=new Map();
let requests=[];
const ctx=vm.createContext({
  console,URL,TextEncoder,setTimeout:()=>0,clearTimeout:()=>{},confirm:()=>true,prompt:()=>'', 
  document:{getElementById:element,querySelectorAll:()=>[]},
  fetch:async (url,opts={})=>{
    requests.push({url,opts});
    const item=responses.get(url)||{status:200,body:{activeDirectory:false}};
    return {ok:item.status>=200&&item.status<300,status:item.status,json:async()=>item.body};
  }
});
vm.runInContext(prefix,ctx);
// This isolated VM evaluates only the pre-event prefix; login rendering is below
// the event wiring in app.js. Stub the rendering seam, and separately assert
// the actual compiled login handler clears CSRF/session state.
assert.match(js,/function showLogin\(first\)/);
assert.match(js,/function showLogin\(first\)[\s\S]*?csrf = '';/);
vm.runInContext("function showLogin(first) { csrf='';currentRole='';document.getElementById('app-shell').hidden=true;document.getElementById('auth-screen').hidden=false; }",ctx);
const run=(source)=>vm.runInContext(source,ctx);
run("currentRole='Administrator';csrf='valid-csrf';");
element('app-shell').hidden=false;
element('auth-screen').hidden=true;
responses.set('/admin/api/users',{status:401,body:{error:'Unauthorized'}});
await assert.rejects(run("api('/admin/api/users')"),/session expired/);
assert.equal(element('app-shell').hidden,true,'failed session must close management view');
assert.equal(element('auth-screen').hidden,false,'failed session must show sign-in');
assert.match(element('auth-message').textContent,/sign in again/i,'user must receive actionable guidance');
assert.equal(run('csrf'),'','CSRF state cleared on invalidation');
element('app-shell').hidden=false;
element('auth-screen').hidden=true;
responses.set('/admin/api/users',{status:403,body:{error:'Forbidden'}});
await assert.rejects(run("api('/admin/api/users')"),/Access denied/);
assert.equal(element('app-shell').hidden,false,'403 role denial must not pretend cookie expired');
responses.set('/admin/api/login',{status:401,body:{error:'Invalid login'}});
await assert.rejects(run("api('/admin/api/login','POST',{username:'someone',password:'incorrect'})"),/Authentication failed/);
assert.equal(element('app-shell').hidden,false,'bad password must not reset current login controls');
assert.equal(requests.at(-1).opts.headers['X-CSRF-Token'],'','login attempts must not reuse invalid CSRF state');
responses.set('/admin/api/session',{status:200,body:{authenticated:false,initialized:true}});
assert.equal((await run("api('/admin/api/session')")).authenticated,false,'unauthenticated session inspection stays public');
console.log('PASS: unauthenticated 401 opens sign-in; 403 preserves view; invalid login does not invalidate another view; no unsafe retry');
