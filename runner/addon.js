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
    sample: text.slice(0, 2000), blocked: response.headers.get('x-egide-blocked') === '1'};
}

async function collect(command) {
  const [tab] = await browser.tabs.query({active:true, currentWindow:true});
  if (!tab || !/^https?:/.test(tab.url)) return {};
  if (command?.kind === 'goto') {
    await browser.tabs.update(tab.id, {url:command.url});
    return {result:{ok:true}};
  }
  if (command?.kind === 'dom_probe') {
    await browser.tabs.update(tab.id, {url: command.url});
    await new Promise(resolve => setTimeout(resolve, 1800));
    const code = `(() => { try { return {executed: window.__EGIDE_XSS === ${JSON.stringify(command.token)}, token: (window.__EGIDE_XSS || null)}; } catch (e) { return {executed:false, token:null}; } })()`;
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
    if (command.method && command.method !== 'GET') { init.method = command.method; headers['Content-Type'] = 'application/json'; init.body = JSON.stringify(command.body || {}); }
    const t0 = Date.now();
    const response = await fetch(command.url, init);
    const result = await readProbe(response, command.markers || []);
    result.elapsed = Date.now() - t0;
    return {result};
  }
  if (command?.kind === 'probe') {
    const anon = command.anon === true;
    const code = `(async () => {
      if (location.origin !== ${JSON.stringify(command.origin)}) return {status:0, matches:[]};
      const t0 = Date.now();
      const response = await content.fetch(new URL(${JSON.stringify(command.path)}, location.origin).href, {credentials:${anon ? "'omit'" : "'same-origin'"}, cache:'no-store', redirect:'manual', headers:${anon ? "{'X-Egide-Probe':'1', 'X-Egide-Anon':'1'}" : "{'X-Egide-Probe':'1'}"}, signal:AbortSignal.timeout(8500)});
      const out = await (${readProbe.toString()})(response, ${JSON.stringify(command.markers || [])});
      out.elapsed = Date.now() - t0;
      return out;
    })()`;
    const [value] = await browser.tabs.executeScript(tab.id, {code, runAt:'document_start'});
    return {result: value};
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
