'use strict';
const el=id=>document.getElementById(id);
let csrf='',federated=false,busy=false;
async function request(url,method='GET',body){
  const options={method,credentials:'same-origin',cache:'no-store'};
  if(method==='POST'){options.headers={'Content-Type':'application/json','X-CSRF-Token':csrf};options.body=JSON.stringify(body);}
  const r=await fetch(url,options);
  if(r.status===401){location.replace('/dashboard');throw Error('Sign in required');}
  if(!r.ok){let message='HTTP '+r.status;try{message=(await r.json()).error||message}catch{}throw Error(message);}
  return await r.json();
}
async function status(){
  const session=await request('/admin/api/session');
  if(!session.authenticated){location.replace('/dashboard');return;}
  csrf=session.csrf;federated=session.federatedOidc===true;
  const state=await request('/admin/api/license/status');
  el('license-status').textContent=[
    'Status: '+state.state,'Edition: '+(state.edition||'Not activated'),
    'Expires: '+(state.expiresAt||'—'),'Allocation: '+(state.allocationId||'—'),
    'Licensed nodes: '+(state.maxNodes||'—'),'Licensed sites: '+(state.maxSites||'—'),
    'Revision: '+(state.revision||'—'),'Features: '+state.features.join(', '),
    'Traffic admitted in this process: '+(state.trafficAdmitted?'Yes':'No')].join('\n');
  el('license-actions').hidden=session.role!=='Administrator';
  el('license-back').hidden=!state.active;
}
async function operation(action){
  if(busy)return;busy=true;
  const buttons=['license-request','license-import','license-revoke','license-logout'].map(el);
  buttons.forEach(b=>b.disabled=true);el('license-message').textContent='';
  try{await action()}catch(e){el('license-message').textContent=String(e)}
  finally{busy=false;buttons.forEach(b=>b.disabled=false);}
}
el('license-request').onclick=()=>operation(async()=>{
  const result=await request('/admin/api/license/request');
  const url=URL.createObjectURL(new Blob([result.file],{type:'application/octet-stream'}));
  const a=document.createElement('a');a.href=url;a.download='gatewaycore.gcr';a.click();URL.revokeObjectURL(url);
});
async function upload(revoke){
  const file=el('license-file').files[0];
  if(!file||file.size<1||file.size>16384)throw Error('Choose a bounded signed issuer file.');
  await request('/admin/api/license/'+(revoke?'revoke':'import'),'POST',{file:await file.text()});
  el('license-file').value='';await status();el('license-message').textContent='Issuer document verified and imported.';
}
el('license-import').onclick=()=>operation(()=>upload(false));
el('license-revoke').onclick=()=>operation(async()=>{if(confirm('Import permanent allocation revocation?'))await upload(true);});
el('license-logout').onclick=()=>operation(async()=>{
  if(federated){const form=document.createElement('form');form.method='post';form.action='/admin/api/logout';const input=document.createElement('input');input.type='hidden';input.name='csrf';input.value=csrf;form.append(input);document.body.append(form);form.submit();return;}
  await request('/admin/api/logout','POST',{});location.replace('/dashboard');
});
void status().catch(e=>{el('license-message').textContent=String(e)});
