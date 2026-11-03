(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const gate=$('gate'), experience=$('experience'), status=$('status'), keyInput=$('key');
  const pageFrame=$('page'), nav=$('navigation');
  const AAD=new TextEncoder().encode('living-seeds:bundle:v2');
  // Download ciphertext during the invitation screen so unlock has no network wait.
  const bundlePromise=fetch('./site.bundle.enc.json',{cache:'no-store'})
    .then(r=>{if(!r.ok) throw Error('Encrypted bundle is not available.');return r.json();});
  bundlePromise.catch(()=>{}); // no unhandled rejection before an invitation is submitted
  let pages=null;
  function bytes(s){
    if(typeof s!=='string' || !/^[A-Za-z0-9_-]+$/.test(s)) throw Error('Invalid key or bundle encoding.');
    const str=s.replace(/-/g,'+').replace(/_/g,'/');
    return Uint8Array.from(atob(str+'='.repeat((4-str.length%4)%4)),c=>c.charCodeAt(0));
  }
  function show(id){
    const item=pages.find(p=>p.id===id);
    if(!item) return;
    // No decrypted contributor script runs: sandbox has no allow-scripts or allow-same-origin.
    // The restrictive CSP inside srcdoc blocks external fetches, forms and scripts.
    const csp=`<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'; font-src data:; script-src 'none'; connect-src 'none'; form-action 'none'; base-uri 'none'">`;
    const doc=item.html.replace(/<head(\s[^>]*)?>/i,match=>match+csp);
    pageFrame.srcdoc=doc;
    [...nav.children].forEach(b=>b.setAttribute('aria-current',b.dataset.id===id?'page':'false'));
    document.title=item.title+' — Living Seeds';
  }
  $('unlock-form').addEventListener('submit',async e=>{
    e.preventDefault(); $('unlock').disabled=true; status.textContent='Unlocking…';
    try{
      const raw=bytes(keyInput.value.trim());
      if(raw.length!==32) throw Error('Invitation key must contain 32 bytes.');
      const bundle=await bundlePromise;
      if(bundle.v!==2 || bundle.alg!=='A256GCM') throw Error('Unsupported bundle format.');
      const iv=bytes(bundle.iv); if(iv.length!==12) throw Error('Invalid encrypted bundle.');
      const key=await crypto.subtle.importKey('raw',raw,'AES-GCM',false,['decrypt']);
      const plaintext=await crypto.subtle.decrypt({name:'AES-GCM',iv,additionalData:AAD,tagLength:128},key,bytes(bundle.ciphertext));
      const data=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(plaintext));
      if(data.v!==2 || data.type!=='living-seeds-pages' || !Array.isArray(data.pages) || data.pages.length===0) throw Error('Invalid site bundle.');
      if(!data.pages.every(p=>typeof p.id==='string' && /^[a-z0-9-]+$/.test(p.id) && typeof p.title==='string' && typeof p.html==='string')) throw Error('Invalid page records.');
      pages=data.pages;
      nav.replaceChildren();
      pages.forEach(p=>{let b=document.createElement('button');b.type='button';b.dataset.id=p.id;b.textContent=p.title;b.addEventListener('click',()=>show(p.id));nav.appendChild(b);});
      keyInput.value='';gate.hidden=true;experience.hidden=false;status.textContent='';show(data.home);
    }catch(err){status.textContent=err.name==='OperationError'?'Incorrect invitation key or damaged bundle.':(err.message||'Unlock failed.');}
    finally{$('unlock').disabled=false;}
  });
  $('lock').addEventListener('click',()=>{pages=null;pageFrame.removeAttribute('srcdoc');nav.replaceChildren();experience.hidden=true;gate.hidden=false;document.title='Living Seeds — Invitation';keyInput.focus();});
})();
