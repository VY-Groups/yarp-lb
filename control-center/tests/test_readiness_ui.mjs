// Exercises shipped browser functions with deterministic fetches and deadlines.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import test from 'node:test';
const js=fs.readFileSync(new URL('../wwwroot/app.js',import.meta.url),'utf8');
function browser() {
  const nodes=new Map(),requests=[],timers=new Map();let next=0;
  function element(id) {
    if(!nodes.has(id))nodes.set(id,{
      hidden:false,textContent:'',innerHTML:'',dataset:{},className:'',value:'',
      classList:{toggle(){}},querySelectorAll(){return []},
      setAttribute(){},removeAttribute(){}
    });
    return nodes.get(id);
  }
  const ctx=vm.createContext({
    console,URL,TextEncoder,AbortController,
    setTimeout(fn,ms){const id=++next;timers.set(id,{fn,ms});return id},
    clearTimeout(id){timers.delete(id)},
    document:{getElementById:element,querySelectorAll:()=>[]},
    fetch(url,opts) {
      if(url==='/admin/api/auth-methods')
        return Promise.resolve({json:async()=>({activeDirectory:false})});
      return new Promise(resolve=>requests.push({url,opts,resolve}));
    }
  });
  vm.runInContext(js.split("$('content').addEventListener('click'")[0],ctx);
  const start=js.indexOf('function showLogin(first) {');
  const stop=js.indexOf("$('auth-provider').onchange",start);
  vm.runInContext(js.slice(start,stop),ctx);
  const run=expr=>vm.runInContext(expr,ctx);
  run("view='routes';currentRole='Administrator';");
  return {nodes,requests,timers,run,element};
}
const reply=(ready,status=200)=>({
  ok:status>=200&&status<300,status,json:async()=>({ready})
});
test('readiness uses authenticated management endpoint and explicit ready boolean',async()=>{
  const b=browser(),pending=b.run('refreshGatewayReadiness()');
  assert.equal(b.requests[0].url,'/admin/api/gateway-readiness');
  assert.equal(b.requests[0].opts.credentials,'same-origin');
  assert.equal(b.requests[0].opts.cache,'no-store');
  b.requests[0].resolve(reply(true));await pending;
  assert.equal(b.run('gatewayReadyWarn'),false);
  assert.match(b.element('gateway-pill').textContent,/Backend readiness observed/);
  assert.equal(b.timers.size,0);
});
test('previous green is removed immediately while checking',async()=>{
  const b=browser();
  b.run("gatewayReadyWarn=false;gatewayReadyLabel='● Backend readiness observed';");
  const pending=b.run('refreshGatewayReadiness()');
  assert.equal(b.run('gatewayReadyWarn'),true);
  assert.match(b.element('gateway-pill').textContent,/Checking/);
  b.requests[0].resolve(reply(false));await pending;
  assert.match(b.element('gateway-pill').textContent,/No healthy backend reported/);
});
test('deadline clears a hung green state and rejects late success',async()=>{
  const b=browser(),pending=b.run('refreshGatewayReadiness()');
  const timer=[...b.timers.values()].find(t=>t.ms===5000);
  assert.ok(timer,'readiness must have an explicit five-second deadline');
  timer.fn();await pending;
  assert.equal(b.requests[0].opts.signal.aborted,true);
  assert.equal(b.run('gatewayReadyWarn'),true);
  assert.match(b.element('gateway-pill').textContent,/unavailable/i);
  b.requests[0].resolve(reply(true));
  await new Promise(resolve=>setImmediate(resolve));
  assert.equal(b.run('gatewayReadyWarn'),true);
  assert.equal(b.timers.size,0);
});
test('a superseded response cannot overwrite the latest result',async()=>{
  const b=browser(),first=b.run('refreshGatewayReadiness()');
  const second=b.run('refreshGatewayReadiness()');
  assert.equal(b.requests[0].opts.signal.aborted,true);
  b.requests[1].resolve(reply(false));await second;
  b.requests[0].resolve(reply(true));await first;
  assert.match(b.element('gateway-pill').textContent,/No healthy backend reported/);
  assert.equal(b.timers.size,0);
});
test('logout aborts the request and excludes results from the old session',async()=>{
  const b=browser(),pending=b.run('refreshGatewayReadiness()');
  b.run('showLogin(false)');
  assert.equal(b.requests[0].opts.signal.aborted,true);
  b.requests[0].resolve(reply(true));await pending;
  assert.equal(b.run('gatewayReadyWarn'),true);
  assert.match(b.run('gatewayReadyLabel'),/not checked/);
  assert.equal(b.element('app-shell').hidden,true);
  assert.equal(b.timers.size,0);
});
test('missing or non-boolean readiness is never treated as healthy',async()=>{
  for(const value of [undefined,'true',1,null]) {
    const b=browser(),pending=b.run('refreshGatewayReadiness()');
    b.requests[0].resolve(reply(value));await pending;
    assert.equal(b.run('gatewayReadyWarn'),true);
    assert.match(b.element('gateway-pill').textContent,/unavailable/i);
  }
});
test('transport failure cannot be displayed as healthy',async()=>{
  const b=browser(),pending=b.run('refreshGatewayReadiness()');
  b.requests[0].resolve(reply(true,503));await pending;
  assert.equal(b.run('gatewayReadyWarn'),true);
  assert.match(b.element('gateway-pill').textContent,/unavailable/i);
});
test('hidden management shell never starts readiness traffic',async()=>{
  const b=browser();b.element('app-shell').hidden=true;
  await b.run('refreshGatewayReadiness()');
  assert.equal(b.requests.length,0);
});
