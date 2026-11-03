(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const enc = new TextEncoder();
  const aad = enc.encode('living-seeds:v1');
  function b64(s) {
    const clean = String(s).trim().replace(/-/g, '+').replace(/_/g, '/');
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(clean)) throw new Error('Invalid key format');
    const padded = clean + '='.repeat((4 - clean.length % 4) % 4);
    return Uint8Array.from(atob(padded), x => x.charCodeAt(0));
  }
  function add(parent, tag, value, cls) {
    const e = document.createElement(tag); e.textContent = value;
    if (cls) e.className = cls;
    parent.appendChild(e);
  }
  $('unlock-form').addEventListener('submit', async ev => {
    ev.preventDefault(); $('unlock').disabled = true; $('status').textContent = 'Unlocking…';
    try {
      const raw = b64($('key').value);
      if (raw.length !== 32) throw new Error('The key must be 32 bytes');
      const r = await fetch('./site.enc.json', {cache:'no-store'});
      if (r.status === 404) throw new Error('Encrypted content has not been deployed yet');
      if (!r.ok) throw new Error('Encrypted content is unavailable');
      const envelope = await r.json();
      if (envelope.v !== 1 || envelope.alg !== 'A256GCM') throw new Error('Unrecognised encrypted format');
      const key = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']);
      const bytes = await crypto.subtle.decrypt({name:'AES-GCM', iv:b64(envelope.iv), additionalData:aad, tagLength:128}, key, b64(envelope.ciphertext));
      const data = JSON.parse(new TextDecoder().decode(bytes));
      if (typeof data.title !== 'string' || !Array.isArray(data.sections) || !data.sections.every(s => typeof s.title === 'string' && typeof s.body === 'string')) throw new Error('Invalid content');
      const container = $('content'); container.replaceChildren();
      add(container,'p','Living Seeds / Founding Circle','overline');
      add(container,'h1',data.title);
      if (typeof data.intro === 'string') add(container,'p',data.intro,'intro');
      for (const section of data.sections) { add(container,'h2',section.title); add(container,'p',section.body); }
      $('key').value = ''; $('gate').hidden = true; container.hidden = false;
      document.title = data.title + ' — Living Seeds';
    } catch (e) {
      $('status').textContent = e.name === 'OperationError' ? 'Incorrect key or corrupted content' : e.message;
    } finally { $('unlock').disabled = false; }
  });
})();
