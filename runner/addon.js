const endpoint = 'http://127.0.0.2:8792/bridge';
const headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer __TOKEN__'};
const snapshot = `(() => {
  const candidates = Array.from(document.querySelectorAll('a, button, input, select, textarea, [role=button]'));
  const controls = candidates.flatMap((element, index) => {
    const box = element.getBoundingClientRect();
    if (box.width < 1 || box.height < 1 || !element.checkVisibility()) return [];
    const label = element.getAttribute('aria-label') || element.labels?.[0]?.innerText ||
      element.innerText || element.getAttribute('placeholder') || element.name || '';
    return [{id:index, label:label.trim().slice(0,100), type:element.type || element.tagName.toLowerCase(),
      login:!!element.form?.querySelector('input[type=password]'),
      x:Math.round((mozInnerScreenX + box.x + box.width/2) * devicePixelRatio), y:Math.round((mozInnerScreenY + box.y + box.height/2) * devicePixelRatio),
      href:element.tagName === 'A' ? element.pathname : undefined}];
  }).slice(0,65);
  return {title:document.title.slice(0,100), path:location.pathname, origin:location.origin,
    controls, text:(document.body?.innerText||'').slice(0,8000), viewport:{width:innerWidth,height:innerHeight}, captcha:!!document.querySelector(
      'iframe[src*="recaptcha"], iframe[src*="challenges.cloudflare"], iframe[src*="hcaptcha"]')};
})()`;

async function readProbe(response, markers) {
  const reader = response.body?.getReader();
  const decoder = new TextDecoder();
  let text = '';
  while (reader && text.length < 32768) {
    const chunk = await reader.read();
    if (chunk.done) break;
    text += decoder.decode(chunk.value.subarray(0, 32768 - text.length), {stream:true});
  }
  if (reader) reader.cancel().catch(() => {});
  const matches = markers.filter(marker => text.includes(marker));
  return {status: response.status, matches, type: (response.headers.get('content-type') || '').slice(0, 80),
    marker: matches[0] || (!markers.length && (text.match(/(?:EGIDE|ESCOPO)-[A-F0-9]{12}/) || [])[0]) || null,
    sample: text.slice(0, 2000), size: text.length, blocked: response.headers.get('x-egide-blocked') === '1'};
}

async function collect(command) {
  const [tab] = await browser.tabs.query({active:true, currentWindow:true});
  if (!tab || !/^https?:/.test(tab.url)) return {};
  if (command?.kind === 'goto') {
    await browser.tabs.update(tab.id, {url:command.url});
    return {result:{ok:true}};
  }
  if (command?.kind === 'dom_probe') {
    const sameDocument = tab.url.split('#')[0] === command.url.split('#')[0];
    await browser.tabs.update(tab.id, {url: command.url});
    if (sameDocument) {
      await new Promise(resolve => setTimeout(resolve, 150));
      await browser.tabs.reload(tab.id, {bypassCache: true});
    }
    await new Promise(resolve => setTimeout(resolve, 1800));
    const code = `(() => { try { const page = window.wrappedJSObject || window; return {executed: page.__EGIDE_XSS === ${JSON.stringify(command.token)}, token: (page.__EGIDE_XSS || null)}; } catch (e) { return {executed:false, token:null}; } })()`;
    try {
      const [value] = await browser.tabs.executeScript(tab.id, {code, runAt:'document_idle'});
      return {result: value || {executed:false, token:null}};
    } catch (e) {
      return {result:{executed:false, token:null, error:String(e).slice(0,80)}};
    }
  }
  if (command?.kind === 'fields' && command.url) {
    if (new URL(tab.url).origin !== command.origin) return {result:{status:0, fields:[]}};
    const response = await fetch(command.url, {credentials:'include', cache:'no-store', redirect:'manual', headers:{'Accept':'application/json','X-Egide-Probe':'1'}, signal:AbortSignal.timeout(5500)});
    let fields = [];
    try {
      const data = JSON.parse(await response.text());
      const record = data && typeof data === 'object' && !Array.isArray(data) ? data : {};
      fields = Object.entries(record)
        .filter(([, value]) => typeof value === 'string')
        .slice(0, 40)
        .map(([key, value]) => ({key, value: value.slice(0, 200), truncated: value.length > 200}));
    } catch { fields = []; }
    return {result:{status: response.status, fields, blocked: response.headers.get('x-egide-blocked') === '1'}};
  }
  if (command?.kind === 'write' && command.url) {
    if (new URL(tab.url).origin !== command.origin) return {result:{status:0}};
    const response = await fetch(command.url, {method: command.method, credentials:'include', cache:'no-store', redirect:'manual',
      headers:{'Content-Type':'application/json','Accept':'application/json','X-Egide-Probe':'1'},
      body: JSON.stringify({[command.field]: command.value}), signal:AbortSignal.timeout(5500)});
    return {result:{status: response.status, blocked: response.headers.get('x-egide-blocked') === '1'}};
  }
  if (command?.kind === 'probe' && command.url) {
    if (new URL(tab.url).origin !== command.origin) return {result:{status:0, matches:[]}};
    const anon = command.anon === true;
    const headers = anon ? {'X-Egide-Probe':'1', 'X-Egide-Anon':'1'} : {'X-Egide-Probe':'1'};
    const init = {credentials: anon ? 'omit' : 'include', cache:'no-store', redirect:'manual', headers, signal:AbortSignal.timeout(8500)};
    if (command.method && command.method !== 'GET') {
      init.method = command.method;
      if (command.method !== 'HEAD' && command.method !== 'OPTIONS') {
        if (typeof command.raw === 'string') {
          headers['Content-Type'] = command.contentType || 'application/xml';
          init.body = command.raw;
        } else if (command.body !== undefined) {
          headers['Content-Type'] = 'application/json';
          init.body = JSON.stringify(command.body);
        }
      }
    }
    const t0 = Date.now();
    const response = await fetch(command.url, init);
    const result = await readProbe(response, command.markers || []);
    result.elapsed = Date.now() - t0;
    return {result};
  }
  if (command?.kind === 'probe') {
    const anon = command.anon === true;
    const headers = anon ? {'X-Egide-Probe':'1', 'X-Egide-Anon':'1'} : {'X-Egide-Probe':'1'};
    const init = {credentials: anon ? 'omit' : 'same-origin', cache:'no-store', redirect:'manual', headers};
    if (command.method && command.method !== 'GET') {
      init.method = command.method;
      if (command.method !== 'HEAD' && command.method !== 'OPTIONS') {
        if (typeof command.raw === 'string') {
          headers['Content-Type'] = command.contentType || 'application/xml';
          init.body = command.raw;
        } else if (command.body !== undefined) {
          headers['Content-Type'] = 'application/json';
          init.body = JSON.stringify(command.body);
        }
      }
    }
    const code = `(async () => {
      if (location.origin !== ${JSON.stringify(command.origin)}) return {status:0, matches:[]};
      const init = ${JSON.stringify(init)};
      init.signal = AbortSignal.timeout(8500);
      const t0 = Date.now();
      const response = await content.fetch(new URL(${JSON.stringify(command.path)}, location.origin).href, init);
      const out = await (${readProbe.toString()})(response, ${JSON.stringify(command.markers || [])});
      out.elapsed = Date.now() - t0;
      return out;
    })()`;
    const [value] = await browser.tabs.executeScript(tab.id, {code, runAt:'document_start'});
    return {result: value};
  }
  if (command?.kind === 'race' && command.path) {
    const n = Math.min(Math.max(parseInt(command.count) || 5, 2), 8);
    const init = {method: command.method || 'POST', credentials:'same-origin', cache:'no-store', redirect:'manual',
      headers:{'Content-Type':'application/json','X-Egide-Probe':'1'}, body: JSON.stringify(command.body || {})};
    const code = `(async () => {
      if (location.origin !== ${JSON.stringify(command.origin)}) return {ok:0, count:0};
      const init = ${JSON.stringify(init)};
      init.signal = AbortSignal.timeout(8500);
      const url = new URL(${JSON.stringify(command.path)}, location.origin).href;
      const rs = await Promise.allSettled(Array.from({length:${n}}, () => content.fetch(url, init).then(r => r.status)));
      const ok = rs.filter(r => r.status === 'fulfilled' && r.value >= 200 && r.value < 300).length;
      return {ok, count:${n}};
    })()`;
    const [value] = await browser.tabs.executeScript(tab.id, {code, runAt:'document_start'});
    return {result: value || {ok:0, count:0}};
  }
  const [value] = await browser.tabs.executeScript(tab.id, {code:snapshot});
  return value || {};
}

let command = null;
let running = false;
async function tick() {
  if (running) return;
  running = true;
  try {
    const data = await collect(command).catch(error => command ? ({result:{status:0, error:String(error).slice(0,120)}}) : ({}));
    const result = await fetch(endpoint, {method:'POST',headers,body:JSON.stringify({id:command?.id, data})});
    command = result.ok ? await result.json() : null;
  } catch {
    command = null;
  } finally {
    running = false;
  }
}
setInterval(tick, 300);
tick();
