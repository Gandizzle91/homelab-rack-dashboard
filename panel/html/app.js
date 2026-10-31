/* =====================================================================
   Rack dashboard – application code
   Reads Prometheus, Loki and the vulnscan API and draws a 1280x400 panel.
   Settings live in config.js, translations in i18n.js.
   ===================================================================== */
'use strict';

/* ===================== config & language ===================== */
const CFG = Object.assign({ prom: '/prom/api/v1', loki: '/loki/loki/api/v1', systems: [], drives: [], jobs: {}, reasons: {},
  cpuTemp: [70, 85], usage: [85, 95], fwSample: 5000, detailTimeout: 60, modalTimeout: 120 }, window.DASHBOARD_CONFIG || {});
const LANG = ((new URLSearchParams(location.search).get('lang')) || CFG.lang || 'en').toLowerCase().slice(0, 2);
const DICT = (window.I18N || {})[LANG] || {};
const LOCALE = CFG.locale || (LANG === 'de' ? 'de-DE' : 'en-GB');
document.documentElement.lang = LANG;

/* t('Text {n}', {n: 3}) – translate an English text and fill in {placeholders} */
function t(s, v){
  let r = DICT[s] != null ? DICT[s] : s;
  if (v) r = r.replace(/\{(\w+)\}/g, (m, k) => v[k] != null ? v[k] : m);
  return r;
}
const pl = (n, one, many, v) => t(n === 1 ? one : many, Object.assign({n}, v));
/* config texts may be a string or {en: '…', de: '…'} */
const L = x => x && typeof x === 'object' ? (x[LANG] || x.en || Object.values(x)[0]) : (x == null ? '' : String(x));

const SYS = CFG.systems.map(s => Object.assign({}, s, { name: L(s.name), role: L(s.role) }));
const OVERVIEW = SYS.filter(s => s.overview);
const DRIVES = CFG.drives.map(d => Object.assign({}, d, { name: L(d.name), location: L(d.location) }));
const FAN = CFG.fan ? Object.assign({ job: 'rackfan', minRpm: 200 }, CFG.fan) : null;
const JOBS = {};
SYS.forEach(s => JOBS[s.job] = { name: s.name, page: 'systems' });
Object.entries(CFG.jobs).forEach(([j, x]) => JOBS[j] = Object.assign({ page: 'systems' }, JOBS[j], x, { name: L(x.name) || j }));
const WAN = CFG.wan || {};
const WIN = (q, w) => (q || '').replaceAll('$win', w);
const LOG_ROWS = CFG.logRows || (CFG.vuln ? 9 : 13);

const PORTS = {21:'ftp',22:'ssh',23:'telnet',25:'smtp',53:'dns',80:'http',110:'pop3',123:'ntp',135:'rpc',137:'netbios',139:'netbios',143:'imap',161:'snmp',389:'ldap',443:'https',445:'smb',465:'smtps',587:'smtp',993:'imaps',995:'pop3s',1080:'socks',1433:'mssql',1521:'oracle',1723:'pptp',1883:'mqtt',2222:'ssh',2375:'docker',3128:'proxy',3306:'mysql',3389:'rdp',5060:'sip',5432:'postgres',5555:'adb',5900:'vnc',5985:'winrm',6379:'redis',8000:'http',8008:'http',8080:'http',8081:'http',8443:'https',8888:'http',9000:'http',9100:'printer',9200:'elastic',11211:'memcache',27017:'mongodb'};
/* readable names for CrowdSec scenarios; unknown ones are shortened automatically */
const SCENARIOS = { 'ssh-bf':'SSH brute force', 'ssh-slow-bf':'SSH brute force', 'ssh-cve-2024-6387':'SSH exploit', 'http-probing':'Web scan',
  'http-crawl-non_statics':'Web crawler', 'http-bad-user-agent':'Bad user agent', 'http-sensitive-files':'Sensitive files',
  'http-backdoors-attempts':'Backdoor attempt', 'http-admin-interface-probing':'Admin probing', 'http-path-traversal-probing':'Path traversal',
  'http-sqli-probing':'SQL injection', 'http-xss-probing':'XSS', 'http-generic-bf':'Web brute force', 'http-bf-wordpress_bf':'WordPress brute force',
  'http-wordpress-scan':'WordPress scan', 'http-open-proxy':'Open proxy', 'iptables-scan-multi_ports':'Port scan', 'pf-scan-multi_ports':'Port scan',
  'portscan':'Port scan', 'smb-bf':'SMB brute force', 'rdp-bf':'RDP brute force', 'telnet-bf':'Telnet brute force', 'mysql-bf':'MySQL brute force' };

/* ===================== static texts & header ===================== */
const $ = id => document.getElementById(id);
const esc = s => String(s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
document.querySelectorAll('[data-t]').forEach(el => el.textContent = t(el.dataset.t));
$('brand').textContent = L(CFG.brand) || 'HOMELAB';
document.title = $('brand').textContent + ' · Rack';
$('pills').innerHTML =
  (CFG.backup ? `<div class="pill tap" data-detail="backups" style="margin-right:10px"><span class="dot" id="bk-dot"></span><span id="bk-txt">Backups –</span></div>` : '') +
  SYS.filter(s => s.pill).map(s => `<div class="pill tap" data-detail="systems"><span class="dot" id="up-${esc(s.job)}"></span>${esc(s.name)}</div>`).join('') +
  (FAN ? `<div class="pill tap" data-detail="systems" style="margin-left:6px"><span class="dot" id="fan-dot"></span><span id="fan-txt">${t('Fan')} –</span></div>` : '') +
  `<div class="pill" style="margin-left:6px"><span class="dot live" id="live"></span><span id="livetxt">${t('Live')}</span></div>`;
if (!CFG.vuln) $('app').classList.add('no-vuln');

/* ===================== map ===================== */
document.getElementById('land').setAttribute('d', MAP.d);
function project(lat, lon){   // Natural Earth projection, same parameters as the pre-rendered outlines
  const l = lon*Math.PI/180, p = lat*Math.PI/180, p2 = p*p, p4 = p2*p2;
  const x = l*(0.8707 - 0.131979*p2 + p4*(-0.013791 + p4*(0.003971*p2 - 0.001529*p4)));
  const y = p*(1.007226 + p2*(0.015085 + p4*(-0.044475 + 0.028874*p2 - 0.005916*p4)));
  return [MAP.t[0] + MAP.k*x, MAP.t[1] - MAP.k*y];
}
const NS = 'http://www.w3.org/2000/svg';
function pulse(lat, lon){
  if (VIEW || lat == null || lon == null || isNaN(lat) || isNaN(lon)) return;
  const [x, y] = project(lat, lon), g = document.getElementById('pulses');
  for (const [cls, r] of [['pulse', 2], ['core', 2.5]]) {
    const c = document.createElementNS(NS, 'circle');
    c.setAttribute('cx', x); c.setAttribute('cy', y); c.setAttribute('r', r); c.setAttribute('class', cls);
    g.appendChild(c); setTimeout(() => c.remove(), 1900);
  }
}

/* ===================== helpers ===================== */
const NF = {};
const nf = (v, d=0) => (NF[d] = NF[d] || new Intl.NumberFormat(LOCALE, {minimumFractionDigits:d, maximumFractionDigits:d})).format(v);
const health = {};
const PARTS = {log:'Firewall log', rate:'Firewall log', map:'Map', prom:'Prometheus', spark:'WAN history', backup:'Backups', crowdsec:'CrowdSec', vuln:'Security check'};
function mark(key, ok){ health[key] = ok; const bad = Object.keys(health).filter(k => !health[k]);
  $('live').className = 'dot live ' + (bad.length ? 'bad' : 'ok'); $('livetxt').textContent = bad.length ? t('Data error') : t('Live');
  setAlert('data', bad.length ? [{lvl:'warn', msg:t('Data error: {parts}', {parts: [...new Set(bad.map(k => t(PARTS[k] || k)))].join(', ')})}] : []); }
/* alerts: crit = red blinking frame, warn = orange frame; pg = detail page that opens on tap */
const ALERTS = {};
function setAlert(key, list){ ALERTS[key] = list; renderAlerts(); }
function renderAlerts(){
  const all = Object.values(ALERTS).flat(), crit = all.filter(a => a.lvl === 'crit'), warn = all.filter(a => a.lvl === 'warn');
  const show = crit.length ? crit : warn;
  $('app').classList.toggle('crit', !!crit.length); $('app').classList.toggle('warn', !crit.length && !!warn.length);
  $('alert').textContent = show.length ? '⚠ ' + show.map(a => a.msg).join(' · ') : '';
  $('alert').dataset.detail = (show.find(a => a.pg) || {}).pg || '';
}
async function getJSON(url){ const r = await fetch(url, {cache:'no-store'}); if (!r.ok) throw new Error(r.status); const j = await r.json(); if (j.status && j.status !== 'success') throw new Error(j.error); return j.data; }
const prom  = q => getJSON(`${CFG.prom}/query?query=${encodeURIComponent(q)}`).then(d => d.result);
const promR = (q, s, e, st) => getJSON(`${CFG.prom}/query_range?query=${encodeURIComponent(q)}&start=${s}&end=${e}&step=${st}`).then(d => d.result);
const lokiQ = q => getJSON(`${CFG.loki}/query?query=${encodeURIComponent(q)}`).then(d => d.result);
const lokiR = (q, limit, sinceSec) => { const now = Date.now(); return getJSON(`${CFG.loki}/query_range?query=${encodeURIComponent(q)}&limit=${limit}&direction=backward&start=${(now - sinceSec*1000)}000000&end=${now}000000`).then(d => d.result); };
const lokiMR = (q, s, e, st) => getJSON(`${CFG.loki}/query_range?query=${encodeURIComponent(q)}&start=${s}000000000&end=${e}000000000&step=${st}`).then(d => d.result);
const val = r => r && r.length ? parseFloat(r[0].value[1]) : null;
function bps(v){ if (v == null || isNaN(v)) return ['–','']; if (v >= 1e9) return [nf(v/1e9,2),'Gbit/s']; if (v >= 1e6) return [nf(v/1e6, v >= 1e8 ? 0 : 1),'Mbit/s']; if (v >= 1e3) return [nf(v/1e3,0),'kbit/s']; return [nf(v,0),'bit/s']; }
function level(v, warn, crit){ return v == null ? 'var(--dim)' : v >= crit ? 'var(--red)' : v >= warn ? 'var(--orange)' : 'var(--green)'; }
function short(n){ return n >= 10000 ? nf(n/1000,0)+'k' : n >= 1000 ? nf(n/1000,1)+'k' : nf(n,0); }

/* ===================== clock ===================== */
const CLOCK = new Intl.DateTimeFormat(LOCALE, {hour:'2-digit', minute:'2-digit', second:'2-digit', hourCycle:'h23'});
const tod = ms => CLOCK.format(new Date(ms));
function clock(){ $('clock').textContent = tod(Date.now()); idleTick(); }

/* ===================== firewall log ===================== */
const seen = new Set(); let firstLog = true;
function parseEntry(stream, ts, line){
  // prefer the labels extracted by Alloy, fall back to parsing the raw pf filterlog CSV line
  const f = line.split(','), s = stream || {};
  let src = s.src_ip, dport = s.dst_port, proto = s.proto;
  if (!src && f.length > 19) { const v6 = f[8] === '6'; src = v6 ? f[15] : f[18]; proto = v6 ? f[12] : f[16]; dport = v6 ? f[18] : f[21]; }
  return { ts, src: src || '?', dport: dport || '', proto: (proto || '').toLowerCase(), cc: s.geoip_country_code || '',
           city: s.geoip_city_name || s.geoip_country_name || '', lat: parseFloat(s.geoip_location_latitude), lon: parseFloat(s.geoip_location_longitude) };
}
async function updLog(){
  try {
    const res = await lokiR(CFG.logQuery, 40, 3600);
    let rows = [];
    for (const st of res) for (const [ts, line] of st.values) rows.push(parseEntry(st.stream, ts, line));
    rows.sort((a, b) => (a.ts < b.ts ? 1 : -1));
    rows = rows.slice(0, LOG_ROWS);
    const html = [], fresh = [];
    for (const e of rows) {
      const key = e.ts + e.src + e.dport, isNew = !firstLog && !seen.has(key);
      if (isNew) fresh.push(e);
      seen.add(key);
      const svc = PORTS[e.dport] ? ` <span style="color:var(--dim)">${PORTS[e.dport]}</span>` : '';
      html.push(`<div class="row${isNew ? ' new' : ''}"><span class="t">${tod(Number(e.ts.slice(0, 13)))}</span><span class="cc${e.cc ? '' : ' none'}">${esc(e.cc || '--')}</span><span class="ip">${esc(e.src)}</span><span class="port"><b>${esc(e.dport)}</b>/${esc(e.proto)}${svc}</span></div>`);
    }
    $('log').innerHTML = html.join('');
    fresh.reverse().forEach((e, i) => setTimeout(() => {
      const c = MAP.cent[e.cc];
      if (!isNaN(e.lat)) pulse(e.lat, e.lon); else if (c) pulse(c[0], c[1]);
    }, i * 350));
    if (seen.size > 5000) seen.clear();
    firstLog = false; mark('log', true);
  } catch (err) { console.error('log', err); mark('log', false); }
}
async function updRate(){
  try { const v = val(await lokiQ(CFG.rateQuery)); $('rate').textContent = (v == null ? '0' : nf(v/5, v/5 < 10 ? 1 : 0)) + ' / min'; mark('rate', true); }
  catch (err) { console.error('rate', err); mark('rate', false); }
}

/* ===================== map (24 h) ===================== */
async function updMap(){
  try {
    const res = await lokiQ(CFG.mapQuery);
    const items = res.map(r => [r.metric.geoip_country_code, parseFloat(r.value[1])]).filter(x => x[0] && MAP.cent[x[0]]).sort((a, b) => b[1] - a[1]);
    const total = res.reduce((s, r) => s + parseFloat(r.value[1]), 0), max = items.length ? items[0][1] : 1;
    $('total').textContent = nf(total, 0);
    const g = $('hits'); g.innerHTML = '';
    for (const [cc, n] of items.slice().reverse()) {
      const [x, y] = project(...MAP.cent[cc]), c = document.createElementNS(NS, 'circle');
      c.setAttribute('cx', x); c.setAttribute('cy', y); c.setAttribute('r', (2.5 + Math.sqrt(n / max) * 11).toFixed(1)); c.setAttribute('class', 'hit');
      g.appendChild(c);
    }
    $('top').innerHTML = items.slice(0, 8).map(([cc, n]) => `<span class="chip num"><b>${esc(cc)}</b>${short(n)}</span>`).join('');
    trimChips('top');
    mark('map', true);
  } catch (err) { console.error('map', err); mark('map', false); }
}

/* ===================== Prometheus: header, WAN, systems, drives ===================== */
function bar(v, max, warn, crit){ const w = v == null ? 0 : Math.max(2, Math.min(100, v / max * 100));
  return `<div class="track"><div class="fill" style="width:${w}%;background:${level(v, warn, crit)}"></div></div>`; }
const txt = (v, unit, dec=0) => `<span class="v num">${v == null ? '–' : nf(v, dec) + unit}</span>`;
const opt = q => q ? prom(q) : Promise.resolve([]);
async function updProm(){
  try {
    const jobs = OVERVIEW.map(h => h.job).join('|') || 'none';
    const [upR, down, up, cpu, ram, fRpm, fDuty, ...rest] = await Promise.all([
      prom('up'),
      opt(WIN(WAN.down, '2m')), opt(WIN(WAN.up, '2m')),
      prom(`1 - avg by (job) (rate(node_cpu_seconds_total{job=~"${jobs}", mode="idle"}[2m]))`),
      prom(`1 - node_memory_MemAvailable_bytes{job=~"${jobs}"} / node_memory_MemTotal_bytes{job=~"${jobs}"}`),
      opt(FAN && FAN.rpm), opt(FAN && FAN.duty),
      ...OVERVIEW.map(h => opt(h.temp)),
      ...DRIVES.flatMap(d => [opt(d.health), opt(d.temp), opt(d.wear)]),
    ]);
    const upMap = {}, alerts = []; upR.forEach(r => upMap[r.metric.job] = r.value[1] === '1');
    Object.entries(upMap).forEach(([j, ok]) => { if (!ok) { const J = JOBS[j] || {};
      alerts.push({lvl: J.level || 'crit', msg: t('{name} offline', {name: J.name || j}), pg: J.page || 'systems'}); } });
    SYS.forEach(s => { const el = $('up-' + s.job); if (el) el.className = 'dot ' + (upMap[s.job] === undefined ? '' : upMap[s.job] ? 'ok' : 'bad'); });
    if (FAN) {
      const fr = val(fRpm), fd = val(fDuty), fanStop = fr != null && fd > 0 && fr < FAN.minRpm;
      if (fanStop) alerts.push({lvl:'crit', msg:t('Rack fan stopped'), pg:'systems'});
      $('fan-dot').className = 'dot ' + (fr == null ? '' : fanStop ? 'bad' : upMap[FAN.job] === false ? 'warn' : 'ok');
      $('fan-txt').innerHTML = fr == null ? t('Fan') + ' –' : `${t('Fan')} <b class="num" style="color:var(--text)">${nf(fr, 0)}</b> ${t('rpm')}` + (fd == null ? '' : ` · ${nf(fd, 0)} %`);
    }
    const [dv, du] = bps(val(down)), [uv, uu] = bps(val(up));
    $('down').innerHTML = `↓ ${dv}<small>${du}</small>`; $('up').innerHTML = `↑ ${uv}<small>${uu}</small>`;
    const byJob = (res, j) => { const r = res.find(x => x.metric.job === j); return r ? parseFloat(r.value[1]) : null; };
    const pct = v => v == null ? null : v * 100, [uw, uc] = CFG.usage, [tw, tc] = CFG.cpuTemp;
    $('sys').innerHTML = OVERVIEW.map(({name, job}, i) => {
      const c = pct(byJob(cpu, job)), m = pct(byJob(ram, job)), tp = val(rest[i]);
      if (tp != null && tp >= tc) alerts.push({lvl:'warn', msg:`${name} ${nf(tp, 0)} °C`, pg:'systems'});
      return `<div class="bar sys"><span class="k">${esc(name)}</span>${bar(c, 100, uw, uc)}${txt(c, '%')}${bar(m, 100, uw, uc)}${txt(m, '%')}<span class="v num" style="color:${tp == null ? 'var(--dim)' : level(tp, tw, tc)}">${tp == null ? '–' : nf(tp, 0) + '°'}</span></div>`;
    }).join('');
    const dr = rest.slice(OVERVIEW.length);
    $('drives').innerHTML = DRIVES.map((d, i) => {
      const h = val(dr[i*3]), tp = val(dr[i*3+1]), w = val(dr[i*3+2]);
      const dot = h == null ? '' : h === 1 ? 'ok' : 'bad';
      if (h === 0) alerts.push({lvl:'crit', msg:t('SMART failure {name}', {name: d.name}), pg:'drives'});
      if (tp != null && tp >= d.crit) alerts.push({lvl:'warn', msg:`${d.name} ${nf(tp, 0)} °C`, pg:'drives'});
      return `<div class="bar drv"><span class="dot ${dot}"></span><span class="k">${esc(d.name)}</span>${bar(tp, 80, d.warn, d.crit)}${txt(tp, ' °C')}<span class="v num k">${w == null ? '' : nf(w*100, 0) + '%'}</span></div>`;
    }).join('');
    setAlert('prom', alerts);
    mark('prom', true);
  } catch (err) { console.error('prom', err); setAlert('prom', []); mark('prom', false); }
}
async function updSpark(){
  try {
    const end = Math.floor(Date.now()/1000), start = end - 1800;
    const [d, u] = await Promise.all([promR(WIN(WAN.down, '2m'), start, end, 20), promR(WIN(WAN.up, '2m'), start, end, 20)]);
    const pts = r => r.length ? r[0].values.map(([tt, v]) => [tt, parseFloat(v)]) : [];
    const D = pts(d), U = pts(u), max = Math.max(1, ...D.map(p => p[1]), ...U.map(p => p[1])) * 1.1;
    const W = 306, H = 32, X = tt => (tt - start) / 1800 * W, Y = v => H - 1 - v / max * (H - 2);
    const line = P => P.map((p, i) => (i ? 'L' : 'M') + X(p[0]).toFixed(1) + ' ' + Y(p[1]).toFixed(1)).join('');
    $('sp-d').setAttribute('d', line(D)); $('sp-u').setAttribute('d', line(U));
    $('sp-d-area').setAttribute('d', D.length ? line(D) + `L${X(D[D.length-1][0]).toFixed(1)} ${H}L${X(D[0][0]).toFixed(1)} ${H}Z` : '');
    mark('spark', true);
  } catch (err) { console.error('spark', err); mark('spark', false); }
}

/* ===================== backups (Proxmox Backup Server) ===================== */
async function updBackup(){
  try {
    const [ts, use, pup] = await Promise.all([prom('pbs_snapshot_vm_last_timestamp{namespace!=""}'), prom('max(pbs_used) / max(pbs_size)'), prom('pbs_up')]);
    const now = Date.now() / 1000, B = CFG.backup, ign = B.ignoreIds || [];
    const guests = ts.map(r => ({ id: r.metric.vm_id, name: r.metric.vm_name || r.metric.vm_id, age: (now - parseFloat(r.value[1])) / 3600 }))
      .filter(g => !ign.includes(g.id) && g.age < B.ignoreAfterD * 24);
    const ok = guests.filter(g => g.age < B.maxAgeH).length, u = val(use);
    const newest = guests.length ? Math.min(...guests.map(g => g.age)) : null;
    $('bk-dot').className = 'dot ' + (!guests.length ? '' : ok === guests.length ? 'ok' : ok === 0 ? 'bad' : 'warn');
    $('bk-txt').innerHTML = `Backups <b class="num" style="color:var(--text)">${ok}/${guests.length}</b>` +
      (newest == null ? '' : ' · ' + t('{n} h ago', {n: nf(newest, 0)})) + (u == null ? '' : ` · ${nf(u * 100, 0)} %`);
    const al = [], stale = guests.filter(g => g.age >= B.maxAgeH).map(g => g.name);
    if (val(pup) === 0) al.push({lvl:'crit', msg:t('PBS not reachable'), pg:'backups'});
    if (guests.length && ok === 0) al.push({lvl:'crit', msg:t('No recent backups'), pg:'backups'});
    else if (stale.length) al.push({lvl:'warn', msg:t('Backup outdated: {list}', {list: stale.slice(0, 3).join(', ') + (stale.length > 3 ? ' …' : '')}), pg:'backups'});
    setAlert('backup', al);
    mark('backup', true);
  } catch (err) { console.error('backup', err); mark('backup', false); }
}

/* ===================== CrowdSec ===================== */
async function updCrowdsec(){
  try {
    const [all, local, top] = await Promise.all([prom('sum(cs_active_decisions)'), prom('sum(cs_active_decisions{origin=~"crowdsec|cscli"})'),
      prom('topk(6, sum by (reason) (cs_active_decisions))')]);
    const a = val(all), l = val(local);
    $('cs').innerHTML = a == null ? t('CrowdSec · no data') :
      t('CrowdSec bans <b class="num">{a}</b> IPs · <b class="num">{l}</b> detected locally', {a: nf(a, 0), l: nf(l || 0, 0)});
    const agg = {};
    for (const r of top) { const n = reasonName(r.metric.reason || '?'); agg[n] = (agg[n] || 0) + parseFloat(r.value[1]); }
    $('reasons').innerHTML = Object.entries(agg).sort((x, y) => y[1] - x[1]).map(([n, v]) => `<span class="chip r num"><b>${esc(n)}</b>${short(v)}</span>`).join('');
    trimChips('reasons');
    mark('crowdsec', true);
  } catch (err) { console.error('crowdsec', err); mark('crowdsec', false); }
}
function reasonName(r){
  const s = r.replace(/^[a-z0-9_-]+\//i, '');
  if (CFG.reasons[s]) return L(CFG.reasons[s]);
  if (SCENARIOS[s]) return t(SCENARIOS[s]);
  if (/cve|vpatch/i.test(s)) return t('Exploit (CVE)');
  const x = s.replace(/^http-/, 'Web ').replace(/[-_]/g, ' ');
  return x.length > 22 ? x.slice(0, 21) + '…' : x;
}
function originName(o){
  if (o === 'CAPI') return t('Community list');
  if (o === 'crowdsec' || o === 'cscli') return t('Detected locally');
  if (/^lists/.test(o)) return t('Blocklists');
  if (o === 'console') return t('Console');
  return o;
}
function trimChips(id){ const el = $(id); while (el.lastElementChild && el.scrollWidth > el.clientWidth + 1) el.lastElementChild.remove(); }

/* ===================== detail pages: tools ===================== */
const REGION = (() => { try { return new Intl.DisplayNames([LANG], {type:'region'}); } catch (e) { return null; } })();
const country = cc => { try { return (REGION && REGION.of(cc)) || cc; } catch (e) { return cc; } };
const optQ = q => q ? prom(q).catch(e => { console.warn('query', q, e); return []; }) : Promise.resolve([]);
const optR = (q, s, e, st) => q ? promR(q, s, e, st).catch(err => { console.warn('range', q, err); return []; }) : Promise.resolve([]);
const series = r => r && r.length ? r[0].values.map(([tt, v]) => [+tt, parseFloat(v)]) : [];
const seriesBy = (res, l) => { const m = {}; for (const r of res) m[r.metric[l]] = r.values.map(([tt, v]) => [+tt, parseFloat(v)]); return m; };
const valBy = (res, l) => { const m = {}; for (const r of res) m[r.metric[l]] = parseFloat(r.value[1]); return m; };
const fin = v => v != null && isFinite(v);
const nums = P => P.map(p => p[1]).filter(fin);
const avg = a => a.length ? a.reduce((x, y) => x + y, 0) / a.length : null;
const mx = a => a.length ? Math.max(...a) : null;
const mn = a => a.length ? Math.min(...a) : null;
const rangeStr = s => s % 86400 === 0 ? (s / 86400) + 'd' : (s / 3600) + 'h';
const rangeName = s => s >= 2 * 86400 ? t('{n} days', {n: nf(s / 86400, 0)}) : nf(s / 3600, 0) + ' h';
function fmtBytes(v){ if (!fin(v)) return '–'; const u = ['B','kB','MB','GB','TB','PB']; let i = 0; while (v >= 1000 && i < u.length - 1) { v /= 1000; i++; } return nf(v, v >= 100 || i === 0 ? 0 : 1) + ' ' + u[i]; }
const fmtGiB = v => fin(v) ? nf(v / 2**30, v / 2**30 >= 10 ? 0 : 1) + ' GB' : '–';
function fmtDur(s){ if (!fin(s)) return '–'; const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60); return d ? t('{d} d {h} h', {d, h}) : h ? `${h} h ${m} min` : `${m} min`; }
function fmtHours(h){ if (!fin(h)) return '–'; return h >= 8760 ? t('{n} years', {n: nf(h / 8760, 1)}) : h >= 48 ? t('{n} days', {n: nf(h / 24, 0)}) : nf(h, 0) + ' h'; }
const fmtAge = h => h < 48 ? nf(h, h < 10 ? 1 : 0) + ' h' : t('{n} days', {n: nf(h / 24, 0)});
const bpsS = v => { const [a, b] = bps(v); return b ? a + ' ' + b : a; };
const bpsAx = v => v >= 1e9 ? nf(v / 1e9, 1) + 'G' : v >= 1e6 ? nf(v / 1e6, v < 1e7 && v % 1e6 ? 1 : 0) + 'M' : v >= 1e3 ? nf(v / 1e3, 0) + 'k' : nf(v, 0);
const WD = [0, 1, 2, 3, 4, 5, 6].map(i => new Intl.DateTimeFormat(LOCALE, {weekday:'short'}).format(new Date(2024, 0, 7 + i)).replace(/\.$/, ''));   // 7 Jan 2024 = Sunday
const DM = new Intl.DateTimeFormat(LOCALE, {day:'2-digit', month:'2-digit'});
const two = n => String(n).padStart(2, '0');
const hhmm = tt => { const d = new Date(tt * 1000); return two(d.getHours()) + ':' + two(d.getMinutes()); };
const fmtWhen = tt => { const d = new Date(tt * 1000); return `${WD[d.getDay()]} ${DM.format(d)} ${hhmm(tt)}`; };
const meter = (p, color) => `<div class="mini"><i style="width:${fin(p) ? Math.max(1.5, Math.min(100, p)).toFixed(1) : 0}%;background:${color}"></i></div>`;
const tcol = (v, w, c) => !fin(v) ? 'var(--dim)' : v >= c ? 'var(--red)' : v >= w ? 'var(--orange)' : 'var(--text)';
const legend = items => `<span class="leg">${items.map(([c, l]) => `<span><i style="background:${c}"></i>${esc(l)}</span>`).join('')}</span>`;
function niceMax(v){ if (!(v > 0)) return 1; const p = Math.pow(10, Math.floor(Math.log10(v))), n = v / p; return (n <= 1 ? 1 : n <= 1.5 ? 1.5 : n <= 2 ? 2 : n <= 3 ? 3 : n <= 4 ? 4 : n <= 5 ? 5 : n <= 6 ? 6 : n <= 8 ? 8 : 10) * p; }
function timeTicks(s0, s1){
  const out = [], span = s1 - s0;
  if (span > 2 * 86400) {
    const d = new Date(s0 * 1000); d.setHours(24, 0, 0, 0);
    while (d / 1000 < s1) { out.push([d / 1000, WD[d.getDay()] + ' ' + d.getDate() + (LANG === 'de' ? '.' : '')]); d.setHours(24, 0, 0, 0); }
  } else {
    const every = span > 12 * 3600 ? 3 : 1, d = new Date(s0 * 1000); d.setMinutes(0, 0, 0);
    for (let tt = d / 1000 + 3600; tt < s1; tt += 3600) { const h = new Date(tt * 1000).getHours(); if (h % every === 0) out.push([tt, two(h) + ':00']); }
  }
  return out;
}
/* SVG line or bar chart (o.bars); list: [{c: colour, pts: [[t, v]], area: opacity, w: line width}] */
function chart(list, o){
  const W = o.w, H = o.h, ax = o.axes !== false;
  const Lm = ax ? (o.left || 40) : 1, R = ax ? 8 : 1, T = ax ? 7 : 3, B = ax ? 17 : 2, iw = W - Lm - R, ih = H - T - B;
  const s0 = o.start, s1 = o.end, all = list.flatMap(s => nums(s.pts));
  let lo, hi;
  if (o.scale === 'temp') { lo = all.length ? Math.floor((mn(all) - 3) / 5) * 5 : 20; hi = all.length ? Math.ceil((mx(all) + 3) / 5) * 5 : 60; }
  else { lo = 0; hi = niceMax(all.length ? mx(all) * 1.05 : 1); }
  if (o.min != null) lo = o.min;
  if (o.max != null) hi = o.max;
  if (hi <= lo) hi = lo + 1;
  const X = tt => Lm + (tt - s0) / (s1 - s0) * iw, Y = v => T + ih - (Math.max(lo, Math.min(hi, v)) - lo) / (hi - lo) * ih;
  if (!all.length) return `<svg class="ch" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}"><g class="ax"><line x1="${Lm}" x2="${W - R}" y1="${T + ih}" y2="${T + ih}"/><text x="${(Lm + W - R) / 2}" y="${T + ih / 2 + 4}" text-anchor="middle" style="font-size:12px">${t('no data')}</text></g></svg>`;
  let g = '', body = '';
  if (ax) {
    const nice = x => { const f = x / Math.pow(10, Math.floor(Math.log10(x) + 1e-9)); return [1, 2, 2.5, 5, 10].some(k => Math.abs(f - k) < 1e-6); };
    const n = [4, 3, 5, 2].find(k => nice((hi - lo) / k)) || 4;
    for (let i = 0; i <= n; i++) { const v = lo + (hi - lo) * i / n, y = Y(v).toFixed(1);
      g += `<line x1="${Lm}" x2="${W - R}" y1="${y}" y2="${y}"/><text x="${Lm - 6}" y="${(+y + 3.5).toFixed(1)}" text-anchor="end">${o.fmt ? o.fmt(v) : nf(v, 0)}</text>`; }
    for (const [tt, lab] of timeTicks(s0, s1)) { const x = X(tt); if (x < Lm + 12 || x > W - R - 12) continue;
      g += `<line class="vt" x1="${x.toFixed(1)}" x2="${x.toFixed(1)}" y1="${T}" y2="${T + ih}"/><text x="${x.toFixed(1)}" y="${H - 4}" text-anchor="middle">${lab}</text>`; }
  }
  for (const s of list) {
    if (o.bars) {
      const bw = Math.max(2, iw / ((s1 - s0) / o.step) * 0.72);
      for (const [tt, v] of s.pts) if (fin(v) && v > 0) { const y = Y(v), x = X(tt - o.step / 2);
        body += `<rect x="${(x - bw / 2).toFixed(1)}" y="${y.toFixed(1)}" width="${bw.toFixed(1)}" height="${Math.max(1, T + ih - y).toFixed(1)}" rx="2" fill="${s.hot && s.hot(tt) ? (s.hotC || s.c) : s.c}" fill-opacity="${s.hot && s.hot(tt) ? 1 : .72}"/>`; }
      continue;
    }
    const segs = [], gap = (o.step || 60) * 2.5; let cur = [], prev = null;
    for (const [tt, v] of s.pts) {
      if (!fin(v) || (prev != null && tt - prev > gap)) { if (cur.length) segs.push(cur); cur = []; }
      if (fin(v)) { cur.push([X(tt), Y(v)]); prev = tt; }
    }
    if (cur.length) segs.push(cur);
    for (const sg of segs) {
      const d = sg.map((p, i) => (i ? 'L' : 'M') + p[0].toFixed(1) + ' ' + p[1].toFixed(1)).join('');
      if (s.area) body += `<path d="${d}L${sg[sg.length - 1][0].toFixed(1)} ${T + ih}L${sg[0][0].toFixed(1)} ${T + ih}Z" fill="${s.c}" fill-opacity="${s.area}"/>`;
      body += `<path d="${d}" fill="none" stroke="${s.c}" stroke-width="${s.w || 1.6}" stroke-linejoin="round" stroke-linecap="round"/>`;
    }
  }
  return `<svg class="ch" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}"><g class="ax">${g}</g>${body}</svg>`;
}
const card = (title, right, inner, style) => `<section class="card"${style ? ` style="${style}"` : ''}><div class="head"><span class="lbl">${title}</span>${right || ''}</div>${inner}</section>`;

/* ===================== detail: attacks & CrowdSec ===================== */
async function pageAttacks(){
  const end = Math.ceil(Date.now() / 3600000) * 3600, start = end - 23 * 3600;
  const [map, hourly, origins, reasons, overflow] = await Promise.all([
    lokiQ(CFG.mapQuery).catch(() => []),
    lokiMR(CFG.hourQuery, start, end, 3600).catch(() => []),
    optQ('sum by (origin) (cs_active_decisions)'),
    optQ('topk(20, sum by (reason) (cs_active_decisions))'),
    optQ('sum(increase(cs_bucket_overflowed_total[24h]))'),
  ]);
  const items = map.map(r => [r.metric.geoip_country_code, parseFloat(r.value[1])]).filter(x => x[0]).sort((a, b) => b[1] - a[1]);
  const total = items.reduce((s, x) => s + x[1], 0), top = items.length ? items[0][1] : 1;
  const left = card(t('Top countries · 24 h'), `<span class="lbl num">${pl(items.length, '{n} country', '{n} countries')}</span>`, `<div class="list">` +
    items.slice(0, 10).map(([cc, n]) => `<div class="li" style="grid-template-columns:30px 1fr 92px 54px 36px"><span class="cc">${esc(cc)}</span><span class="n">${esc(country(cc))}</span>${meter(n / top * 100, 'var(--red)')}<span class="c">${nf(n, 0)}</span><span class="p">${nf(n / total * 100, 0)}%</span></div>`).join('') +
    (items.length ? '' : `<div class="mut">${t('No data')}</div>`) + '</div>');

  const P = series(hourly), hsum = nums(P), peak = P.reduce((m, p) => fin(p[1]) && p[1] > m[1] ? p : m, [0, -1]);
  const hr = s => new Date(s * 1000).getHours();
  const mid = card(t('Blocks per hour · 24 h'), legend([['#ff4d5e', t('blocked')], ['#ff8a3d', t('peak')]]),
    chart([{c:'#ff4d5e', pts:P, hot: tt => tt === peak[0], hotC:'#ff8a3d'}], {w:464, h:196, start:start - 3600, end, step:3600, bars:true, fmt:v => short(v), left:38}) +
    `<div class="stats"><div class="stat"><b>${nf(total, 0)}</b><span>${t('Total')}</span></div>` +
    `<div class="stat"><b>${hsum.length ? nf(avg(hsum.slice(0, -1).length ? hsum.slice(0, -1) : hsum), 0) : '–'}</b><span>${t('Ø / hour')}</span></div>` +
    `<div class="stat"><b>${peak[1] >= 0 ? nf(peak[1], 0) : '–'}</b><span>${peak[1] >= 0 ? t('Peak {a}–{b} h', {a: hr(peak[0] - 3600), b: hr(peak[0])}) : t('Peak')}</span></div>` +
    `<div class="stat"><b>${P.length && fin(P[P.length - 1][1]) ? nf(P[P.length - 1][1], 0) : '–'}</b><span>${t('Since {h}:00', {h: hr(end - 3600)})}</span></div></div>`);

  const org = {}; for (const r of origins) { const n = originName(r.metric.origin || '?'); org[n] = (org[n] || 0) + parseFloat(r.value[1]); }
  const csTotal = Object.values(org).reduce((a, b) => a + b, 0), orgL = Object.entries(org).sort((a, b) => b[1] - a[1]);
  const rs = {}; for (const r of reasons) { const n = reasonName(r.metric.reason || '?'); rs[n] = (rs[n] || 0) + parseFloat(r.value[1]); }
  const rsL = Object.entries(rs).sort((a, b) => b[1] - a[1]).slice(0, 5), rTop = rsL.length ? rsL[0][1] : 1;
  const ov = val(overflow);
  const right = card(t('CrowdSec · active bans'), `<span class="big num">${origins.length ? nf(csTotal, 0) : '–'}</span>`,
    `<div class="list">` + orgL.slice(0, 3).map(([n, v]) => `<div class="li" style="grid-template-columns:118px 1fr 60px"><span class="n">${esc(n)}</span>${meter(v / csTotal * 100, 'var(--amber)')}<span class="c">${nf(v, 0)}</span></div>`).join('') + '</div>' +
    `<div class="lbl sec">${t('Top reasons')}</div><div class="list">` +
    rsL.map(([n, v]) => `<div class="li" style="grid-template-columns:150px 1fr 54px"><span class="n">${esc(n)}</span>${meter(v / rTop * 100, 'var(--amber)')}<span class="c">${nf(v, 0)}</span></div>`).join('') + '</div>' +
    (fin(ov) ? `<div class="note">${t('Own detections in 24 h: {n}', {n: `<b style="color:var(--text)">${nf(ov, 0)}</b>`})}</div>` : ''));
  return { html: left + mid + right, sub: t('Blocked connection attempts from the internet and the CrowdSec ban list') };
}

/* ===================== detail: firewall log ===================== */
async function pageFirewall(){
  const res = await lokiR(CFG.logQuery, CFG.fwSample, 86400);
  const E = []; for (const st of res) for (const [ts, line] of st.values) E.push(parseEntry(st.stream, ts, line));
  if (!E.length) return { html: `<div class="loading">${t('No WAN blocks in the last 24 h')}</div>`, sub: '' };
  const now = Date.now(); let oldest = now;
  const ports = {}, ips = {}, ccs = {}, protos = {}, perMin = new Array(60).fill(0);
  for (const e of E) {
    const ms = Number(e.ts.slice(0, 13)); if (ms < oldest) oldest = ms;
    const pk = (e.dport || '–') + '/' + (e.proto || '?');
    (ports[pk] = ports[pk] || {n:0, port:e.dport, proto:e.proto, ips:new Set()}).n++; ports[pk].ips.add(e.src);
    const ip = ips[e.src] = ips[e.src] || {n:0, cc:e.cc, last:0, ports:new Set()};
    ip.n++; if (ms > ip.last) ip.last = ms; ip.ports.add(e.dport);
    if (e.cc) ccs[e.cc] = (ccs[e.cc] || 0) + 1;
    const pr = e.proto || '?'; protos[pr] = (protos[pr] || 0) + 1;
    const ago = Math.floor((now - ms) / 60000); if (ago >= 0 && ago < 60) perMin[59 - ago]++;
  }
  const n = E.length, spanMin = Math.max(1, (now - oldest) / 60000);
  const pL = Object.values(ports).sort((a, b) => b.n - a.n).slice(0, 10), pTop = pL.length ? pL[0].n : 1;
  const iL = Object.entries(ips).sort((a, b) => b[1].n - a[1].n).slice(0, 10), iTop = iL.length ? iL[0][1].n : 1;
  const c1 = card(t('Top target ports'), `<span class="lbl">${t('Blocks · senders')}</span>`, '<div class="list">' + pL.map(p =>
    `<div class="li" style="grid-template-columns:96px 1fr 120px 52px 40px"><span><b>${esc(p.port || '–')}</b><span class="m">/${esc(p.proto)}</span></span><span class="n m">${PORTS[p.port] || ''}</span>${meter(p.n / pTop * 100, 'var(--amber)')}<span class="c">${nf(p.n, 0)}</span><span class="p">${nf(p.ips.size, 0)}</span></div>`).join('') + '</div>');
  const c2 = card(t('Top senders'), `<span class="lbl">${t('Ports · blocks · last')}</span>`, '<div class="list">' + iL.map(([ip, x]) =>
    `<div class="li" style="grid-template-columns:30px 1fr 64px 52px 44px"><span class="cc${x.cc ? '' : ' none'}">${esc(x.cc || '--')}</span><span class="n" style="font-family:var(--mono);font-size:12.5px">${esc(ip)}</span><span class="p">${pl(x.ports.size, '{n} port', '{n} ports')}</span><span class="c">${nf(x.n, 0)}</span><span class="p">${hhmm(x.last / 1000)}</span></div>`).join('') + '</div>');
  const prL = Object.entries(protos).sort((a, b) => b[1] - a[1]).slice(0, 3);
  const mStart = Math.floor(now / 1000) - 3600;
  const c3 = card(t('Summary'), `<span class="lbl num">${rangeName(spanMin * 60)}</span>`,
    `<div class="kv"><span>${t('Blocks analysed')}</span><span>${nf(n, 0)}</span><span>${t('Time span')}</span><span>${t('since {t}', {t: hhmm(oldest / 1000)})}</span>` +
    `<span>${t('Ø per minute')}</span><span>${nf(n / spanMin, n / spanMin < 10 ? 1 : 0)}</span><span>${t('Distinct senders')}</span><span>${nf(Object.keys(ips).length, 0)}</span>` +
    `<span>${t('Countries')}</span><span>${nf(Object.keys(ccs).length, 0)}</span></div>` +
    `<div class="lbl sec">${t('Protocols')}</div><div class="list">` + prL.map(([p, v]) =>
      `<div class="li" style="grid-template-columns:44px 1fr 44px"><span class="m">${esc(p.toUpperCase())}</span>${meter(v / n * 100, 'var(--blue)')}<span class="c">${nf(v / n * 100, 0)}%</span></div>`).join('') + '</div>' +
    `<div class="lbl sec">${t('Last 60 min')}</div>` +
    chart([{c:'#ff4d5e', pts: perMin.map((v, i) => [mStart + (i + 1) * 60, v])}], {w:314, h:44, axes:false, start:mStart, end:mStart + 3600, step:60, bars:true}));
  return { html: c1 + c2 + c3, sub: t('Analysis of the last {n} WAN blocks{max} · only senders with a GeoIP country', {n: nf(n, 0), max: n >= CFG.fwSample ? t(' (maximum)') : ''}) };
}

/* ===================== detail: WAN ===================== */
async function pageWan(range){
  const end = Math.floor(Date.now() / 1000), start = end - range, step = Math.max(60, Math.round(range / 300)), win = Math.max(120, step) + 's';
  const rs = rangeStr(range), vol = q => (q || '').replaceAll('$range', rs);
  const [D, U, vd, vu, nd, nu, ifi, ifo] = await Promise.all([
    optR(WIN(WAN.down, win), start, end, step), optR(WIN(WAN.up, win), start, end, step),
    optQ(vol(WAN.volDown)), optQ(vol(WAN.volUp)), optQ(WIN(WAN.down, '2m')), optQ(WIN(WAN.up, '2m')),
    optQ('sum by (interface, device) (rate(opnsense_interfaces_received_bytes_total[2m])) * 8'),
    optQ('sum by (interface, device) (rate(opnsense_interfaces_transmitted_bytes_total[2m])) * 8'),
  ]);
  const Dp = series(D), Up = series(U), dn = nums(Dp), un = nums(Up);
  const c1 = card(t('History · {r}', {r: rangeName(range)}), legend([['#3ddc84', '↓ ' + t('Download')], ['#ffb547', '↑ ' + t('Upload')]]),
    chart([{c:'#3ddc84', pts:Dp, area:.13}, {c:'#ffb547', pts:Up, w:1.3}], {w:894, h:256, start, end, step, fmt:bpsAx, left:42}));
  const ifs = {};
  for (const r of ifi) { const k = r.metric.interface || r.metric.device || '?'; (ifs[k] = ifs[k] || {dev:r.metric.device}).rx = parseFloat(r.value[1]); }
  for (const r of ifo) { const k = r.metric.interface || r.metric.device || '?'; (ifs[k] = ifs[k] || {dev:r.metric.device}).tx = parseFloat(r.value[1]); }
  const ifL = Object.entries(ifs).filter(([k, x]) => !/^lo\d/.test(x.dev || '') && !/loopback/i.test(k)).sort((a, b) => ((b[1].rx || 0) + (b[1].tx || 0)) - ((a[1].rx || 0) + (a[1].tx || 0))).slice(0, 6);
  const row = (k, a, b) => `<tr><td class="s">${k}</td><td class="r" style="color:var(--green)">${a}</td><td class="r" style="color:var(--amber)">${b}</td></tr>`;
  const c2 = card(t('Key figures'), '', `<table class="tbl"><tr><th></th><th class="r">↓ ${t('Download')}</th><th class="r">↑ ${t('Upload')}</th></tr>` +
    row(t('Now'), bpsS(val(nd)), bpsS(val(nu))) + row(t('Average'), bpsS(avg(dn)), bpsS(avg(un))) +
    row(t('Peak'), bpsS(mx(dn)), bpsS(mx(un))) + row(t('Volume {r}', {r: rangeName(range)}), fmtBytes(val(vd)), fmtBytes(val(vu))) + '</table>' +
    (ifL.length ? `<div class="lbl sec">${t('Interfaces now')}</div><table class="tbl"><tr><th></th><th class="r">${t('in')}</th><th class="r">${t('out')}</th></tr>` +
      ifL.map(([k, x]) => `<tr><td class="s">${esc(k)}${x.dev && x.dev !== k ? ` <span style="color:var(--dim)">${esc(x.dev)}</span>` : ''}</td><td class="r">${bpsS(x.rx)}</td><td class="r">${bpsS(x.tx)}</td></tr>`).join('') + '</table>' : ''));
  return { html: c1 + c2, sub: t('WAN interface of the firewall ({dev}) · interfaces as seen by the firewall', {dev: esc(WAN.device || 'WAN')}) };
}

/* ===================== detail: systems ===================== */
async function pageSystems(range){
  const end = Math.floor(Date.now() / 1000), start = end - range, step = Math.max(60, Math.round(range / 200)), win = Math.max(120, step);
  const H = SYS, jobs = H.map(h => h.job).join('|') || 'none', sel = `job=~"${jobs}"`;
  const cpuQ = w => `1 - avg by (job) (rate(node_cpu_seconds_total{${sel}, mode="idle"}[${w}]))`;
  // Linux: MemAvailable; FreeBSD (OPNsense): size - free - inactive
  const ramQ = `(1 - node_memory_MemAvailable_bytes{${sel}} / node_memory_MemTotal_bytes{${sel}}) or ((node_memory_size_bytes{${sel}} - node_memory_free_bytes{${sel}} - node_memory_inactive_bytes{${sel}}) / node_memory_size_bytes{${sel}})`;
  const [upS, cpuR, ramR, cpuN, ramN, upt, load, cores, memT, fans, ...temps] = await Promise.all([
    optQ(`up{${sel}}`),
    optR(cpuQ(win + 's'), start, end, step), optR(ramQ, start, end, step), optQ(cpuQ('2m')), optQ(ramQ),
    optQ(`time() - node_boot_time_seconds{${sel}}`), optQ(`node_load1{${sel}}`), optQ(`count by (job) (node_cpu_seconds_total{${sel}, mode="idle"})`),
    optQ(`node_memory_MemTotal_bytes{${sel}} or node_memory_size_bytes{${sel}}`), optQ(`max by (job) (node_hwmon_fan_rpm{${sel}})`),
    ...H.flatMap(h => [optR(h.temp, start, end, step), optQ(h.temp)]),
  ]);
  const F0 = FAN || {}, [fRpmR, fDutyR, fInR, fRpmN, fDutyN, fInN, fUp] = await Promise.all([
    optR(F0.rpm, start, end, step), optR(F0.duty, start, end, step), optR(F0.input, start, end, step),
    optQ(F0.rpm), optQ(F0.duty), optQ(F0.input), optQ(FAN ? `up{job="${FAN.job}"}` : null)]);
  const hasFan = !!(FAN && (fRpmN.length || nums(series(fRpmR)).length)), CH = hasFan || H.length > 4 ? 38 : 44, five = hasFan || H.length > 4 ? ' five' : '';
  const cR = seriesBy(cpuR, 'job'), mR = seriesBy(ramR, 'job'), cN = valBy(cpuN, 'job'), mN = valBy(ramN, 'job');
  const S = valBy(upS, 'job'), U = valBy(upt, 'job'), Ld = valBy(load, 'job'), Co = valBy(cores, 'job'), Mt = valBy(memT, 'job'), Fn = valBy(fans, 'job');
  const pctP = P => (P || []).map(([tt, v]) => [tt, v * 100]);
  const [uw, uc] = CFG.usage, [tw, tc] = CFG.cpuTemp, SW = 182;
  const kf = v => v >= 1000 ? short(v) : nf(v, 0);
  // sc = scale of the mini chart: 'pct' 0–100 %, 'cpu' from 0 automatically, 'temp' automatic
  const cell = (now, P, color, unit, w, c, sc, empty) => {
    const a = nums(P);
    if (!fin(now) && !a.length) return `<div class="scell"><div><div class="sv" style="color:var(--dim)">–</div><div class="ss">${empty || t('no data')}</div></div><span></span></div>`;
    return `<div class="scell"><div><div class="sv" style="color:${tcol(now, w, c)}">${fin(now) ? nf(now, 0) + unit : '–'}</div><div class="ss">${a.length ? t('Ø {a} · max {b}', {a: kf(avg(a)), b: kf(mx(a))}) : ''}</div></div>` +
      chart([{c:color, pts:P, area:.16, w:1.4}], {w:SW, h:CH, axes:false, start, end, step, ...(sc === 'pct' ? {min:0, max:100} : sc === 'cpu' ? {min:0, max:Math.max(20, niceMax((mx(a) || 0) * 1.15))} : {scale:'temp'})}) + '</div>';
  };
  const rows = H.map(({name, job, role, temp}, i) => {
    const up = U[job], tP = series(temps[i * 2]), tN = val(temps[i * 2 + 1]);
    const st = S[job] === 1 ? 'ok' : S[job] === 0 ? 'bad' : '';
    const info = [S[job] === 0 ? t('not reachable') : fin(up) ? t('up {d}', {d: fmtDur(up)}) : t('no data'), fin(Co[job]) ? pl(Co[job], '{n} core', '{n} cores') : '', fin(Mt[job]) ? fmtGiB(Mt[job]) : ''].filter(Boolean).join(' · ');
    return `<div class="sysg r${five}"><div class="sname"><b><span class="dot ${st}"></span>${esc(name)}</b><span>${esc(role || '')}</span><span>${info}</span></div>` +
      cell(fin(cN[job]) ? cN[job] * 100 : null, pctP(cR[job]), '#4cc2ff', '%', uw, uc, 'cpu') +
      cell(fin(mN[job]) ? mN[job] * 100 : null, pctP(mR[job]), '#a78bfa', '%', uw, uc, 'pct') +
      cell(tN, tP, '#ffb547', '°', tw, tc, 'temp', temp ? t('no data') : t('no sensor (VM)')) +
      `<div class="sx"><div><span>${t('Load')} </span>${fin(Ld[job]) ? nf(Ld[job], 2) : '–'}</div><div><span>${t('Fan')} </span>${fin(Fn[job]) && Fn[job] > 0 ? nf(Fn[job], 0) + ' ' + t('rpm') : '–'}</div></div></div>`;
  }).join('') + (!hasFan ? '' : (() => {
    const rp = val(fRpmN), du = val(fDutyN), fi = val(fInN), fu = val(fUp), stop = fin(rp) && du > 0 && rp < FAN.minRpm;
    const st = stop || fu === 0 ? 'bad' : fu === 1 ? 'ok' : '';
    return `<div class="sysg r five"><div class="sname"><b><span class="dot ${st}"></span>${t('Rack fan')}</b><span>${esc(L(FAN.model))}</span><span>${t('Speed · duty · control temp')}</span></div>` +
      cell(rp, series(fRpmR), '#3ddc84', '', Infinity, Infinity, 'cpu') +
      cell(du, series(fDutyR), '#4cc2ff', '%', Infinity, Infinity, 'pct') +
      cell(fi, series(fInR), '#ffb547', '°', tw, tc, 'temp') +
      `<div class="sx"><div><span>${t('Control')} </span>${fu === 1 ? t('running') : fu === 0 ? `<span class="bad">${t('offline')}</span>` : '–'}</div><div><span>${t('State')} </span>${stop ? `<span class="bad">${t('stopped!')}</span>` : fin(rp) ? t('spinning') : '–'}</div></div></div>`;
  })());
  const r = rangeName(range);
  const head = `<div class="sysg h lbl"><span>${t('System · uptime · cores · RAM')}</span><span>${t('CPU · {r}', {r})}</span><span>${t('RAM · {r}', {r})}</span><span>${t('Temperature · {r}', {r})}</span><span>${t('Load · fan')}</span></div>`;
  return { html: `<section class="card">${head + rows}</section>`, sub: t('Now, average and maximum in the range · uptime, cores, RAM · FreeBSD RAM includes the ZFS cache') };
}

/* ===================== detail: drives ===================== */
async function pageDrives(range){
  const end = Math.floor(Date.now() / 1000), start = end - range, step = Math.max(60, Math.round(range / 250));
  const D = DRIVES, COL = ['#4cc2ff', '#a78bfa', '#3ddc84', '#ffb547', '#f472b6', '#ff8a3d', '#94a3b8'];
  const [tR, inst, info] = await Promise.all([
    Promise.all(D.map(d => optR(d.temp, start, end, step))),
    Promise.all(D.flatMap(d => [optQ(d.health), optQ(d.temp), optQ(d.wear)])),
    Promise.all(D.flatMap(d => [optQ(d.written), optQ(d.hours), optQ(d.errors)])),
  ]);
  const col = i => D[i].color || COL[i % COL.length], TP = tR.map(series);
  const withT = D.map((d, i) => i).filter(i => D[i].temp);
  const c1 = card(t('Temperatures · {r}', {r: rangeName(range)}), '',
    chart(withT.map(i => ({c:col(i), pts:TP[i], w:1.5})), {w:444, h:228, start, end, step, scale:'temp', fmt:v => nf(v, 0) + '°', left:34}) +
    `<div style="margin-top:6px">${legend(withT.map(i => [col(i), D[i].name]))}</div>`);
  const rows = D.map((d, i) => {
    const h = val(inst[i * 3]), tp = val(inst[i * 3 + 1]), w = val(inst[i * 3 + 2]);
    const wb = val(info[i * 3]), ph = val(info[i * 3 + 1]), er = val(info[i * 3 + 2]), a = nums(TP[i]);
    const st = h == null ? ['', '–', 'mut'] : h === 1 ? ['ok', t('OK'), 'ok'] : ['bad', t('FAILED'), 'bad'];
    const wear = w == null ? `<span class="mut">${d.temp && !d.wear && /smartctl/.test(d.health || '') ? 'HDD' : '–'}</span>` :
      `<div style="display:grid;grid-template-columns:52px 34px;gap:7px;align-items:center">${meter(w * 100, w >= .9 ? 'var(--red)' : w >= .75 ? 'var(--orange)' : 'var(--green)')}<span class="r">${nf(w * 100, 0)}%</span></div>`;
    return `<tr><td><span style="display:flex;align-items:center;gap:8px"><span class="dot ${st[0]}"></span><span><b>${esc(d.name)}</b><span class="sub2">${esc(d.location || '')}</span></span></span></td>` +
      `<td class="${st[2]}">${st[1]}</td><td class="r" style="color:${tcol(tp, d.warn, d.crit)};font-weight:700">${fin(tp) ? nf(tp, 0) + ' °C' : '–'}</td>` +
      `<td class="r mut">${a.length ? nf(mn(a), 0) + '–' + nf(mx(a), 0) + ' °C' : '–'}</td><td>${wear}</td>` +
      `<td class="r">${fmtBytes(wb)}</td><td class="r">${fmtHours(ph)}</td>` +
      `<td class="r ${!fin(er) ? 'mut' : er > 0 ? 'bad' : 'ok'}" style="font-weight:700">${fin(er) ? nf(er, 0) : '–'}</td></tr>`;
  }).join('');
  const c2 = card(t('SMART values'), '', `<table class="tbl tall"><tr><th>${t('Drive')}</th><th>${t('Health')}</th><th class="r">${t('Temp')}</th><th class="r">${t('Min–max')}</th><th>${t('Wear')}</th><th class="r">${t('Written')}</th><th class="r">${t('Power-on')}</th><th class="r">${t('Errors')}</th></tr>${rows}</table>` +
    `<div class="note">${t('Errors = reallocated, pending or uncorrectable sectors or media errors · Wear = used lifetime')}</div>`);
  return { html: c1 + c2, sub: t('Temperature, health and wear of all SSDs and hard drives') };
}

/* ===================== detail: backups ===================== */
async function pageBackups(){
  const [ts, cnt, ver, used, size, pup, hc, hmu, hmt, hup, hl] = await Promise.all([
    optQ('pbs_snapshot_vm_last_timestamp'), optQ('pbs_snapshot_vm_count'), optQ('pbs_snapshot_vm_last_verify'),
    optQ('pbs_used'), optQ('pbs_size'), optQ('pbs_up'),
    optQ('pbs_host_cpu_usage'), optQ('pbs_host_memory_used'), optQ('pbs_host_memory_total'), optQ('pbs_host_uptime'), optQ('pbs_host_load1')]);
  const now = Date.now() / 1000, B = CFG.backup || {maxAgeH: 26, ignoreAfterD: 30}, ign = B.ignoreIds || [], key = m => (m.namespace || '') + '|' + m.vm_id;
  const C = {}, V = {}; cnt.forEach(r => C[key(r.metric)] = parseFloat(r.value[1])); ver.forEach(r => V[key(r.metric)] = parseFloat(r.value[1]));
  const G = ts.map(r => { const m = r.metric, tt = parseFloat(r.value[1]), age = (now - tt) / 3600, ns = m.namespace || '';
    const counted = ns !== '' && !ign.includes(m.vm_id) && age < B.ignoreAfterD * 24;
    return { id: m.vm_id, name: m.vm_name || m.vm_id, ns, t: tt, age, n: C[key(m)], v: V[key(m)], counted, fresh: age < B.maxAgeH,
      why: ns === '' ? t('no namespace') : ign.includes(m.vm_id) ? t('excluded') : age >= B.ignoreAfterD * 24 ? t('older than {n} days', {n: B.ignoreAfterD}) : '' };
  }).sort((a, b) => (b.counted - a.counted) || a.ns.localeCompare(b.ns) || (+a.id - +b.id));
  const rows = G.map(g => `<tr class="${g.counted ? '' : 'dim'}"><td><span class="dot ${!g.counted ? '' : g.fresh ? 'ok' : 'warn'}" style="display:inline-block"></span></td>` +
    `<td class="r">${esc(g.id)}</td><td><b style="font-weight:${g.counted ? 600 : 400}">${esc(g.name)}</b></td><td>${esc(g.ns || '–')}</td>` +
    `<td>${fmtWhen(g.t)}</td><td class="r ${g.counted && !g.fresh ? 'wrn' : ''}">${fmtAge(g.age)}</td><td class="r">${fin(g.n) ? nf(g.n, 0) : '–'}</td>` +
    `<td>${g.why ? `<span class="mut">${g.why}</span>` : g.v === 1 ? `<span class="ok">✓ ${t('verified')}</span>` : '<span class="mut">–</span>'}</td></tr>`).join('');
  const c1 = card(t('Guests'), `<span class="lbl">${t('sorted by namespace and ID')}</span>`, `<div class="scroll"><table class="tbl"><tr><th></th><th class="r">ID</th><th>${t('Name')}</th><th>${t('Namespace')}</th><th>${t('Last backup')}</th><th class="r">${t('Age')}</th><th class="r">${t('Count')}</th><th>${t('Verify')}</th></tr>${rows}</table></div>` +
    (G.length ? '' : `<div class="mut" style="margin-top:8px">${t('No backups found')}</div>`));
  const counted = G.filter(g => g.counted), ok = counted.filter(g => g.fresh).length, oldest = counted.length ? mx(counted.map(g => g.age)) : null;
  const Sz = valBy(size, 'datastore'), ds = used.map(r => [r.metric.datastore || 'Datastore', parseFloat(r.value[1]), Sz[r.metric.datastore]]);
  const pv = val(pup), cpu = val(hc), mu = val(hmu), mt = val(hmt), up = val(hup), ld = val(hl);
  const c2 = card('Proxmox Backup Server', `<span class="lbl" style="color:${pv === 1 ? 'var(--green)' : pv === 0 ? 'var(--red)' : 'var(--dim)'}">${pv === 1 ? '● ' + t('reachable') : pv === 0 ? '● ' + t('not reachable') : '–'}</span>`,
    ds.map(([n, u, s]) => `<div class="kv"><span>${esc(n)}</span><span>${t('{a} of {b}', {a: fmtBytes(u), b: fmtBytes(s)})}</span></div><div style="margin:4px 0 2px">${meter(fin(s) ? u / s * 100 : 0, fin(s) && u / s >= .9 ? 'var(--red)' : fin(s) && u / s >= .8 ? 'var(--orange)' : 'var(--blue)')}</div>`).join('') +
    `<div class="lbl sec">${t('Status')}</div><div class="kv"><span>${t('Up to date (younger than {n} h)', {n: B.maxAgeH})}</span><span class="${counted.length && ok === counted.length ? 'ok' : ok === 0 && counted.length ? 'bad' : 'wrn'}" style="font-weight:700">${t('{a} of {b}', {a: ok, b: counted.length})}</span>` +
    `<span>${t('Oldest counted backup')}</span><span>${fin(oldest) ? fmtAge(oldest) : '–'}</span><span>${t('Not counted')}</span><span>${G.length - counted.length}</span></div>` +
    `<div class="lbl sec">${t('PBS host')}</div><div class="kv"><span>${t('CPU · load')}</span><span>${fin(cpu) ? nf(cpu * 100, 0) + ' %' : '–'} · ${fin(ld) ? nf(ld, 2) : '–'}</span>` +
    `<span>RAM</span><span>${fin(mu) ? t('{a} of {b}', {a: fmtGiB(mu), b: fmtGiB(mt)}) : '–'}</span><span>${t('Uptime')}</span><span>${fmtDur(up)}</span></div>`);
  return { html: c1 + c2, sub: t('{a} of {b} guests backed up recently · grey = not counted', {a: ok, b: counted.length}) };
}

/* ===================== security (vulnscan) ===================== */
/* Data and buttons come from the vulnscan API on the scanner (CFG.vuln).
   Reading works from anywhere, scan/patch only from the rack display (checked by the API). */
let VULN = null, VJOB = null, vTimer = null, V_ERR = '', vErrT = null, MODAL = null;
const VLABEL = {ok: t('All good'), warn: t('Attention'), crit: t('Critical')};
const REASON_T = { high_findings: '{n} severe findings', external_vulns: '{n} known vulnerabilities visible from outside',
  security_updates: '{n} security updates pending', reboot: 'Reboot required: {hosts}', unreachable: 'Not reached: {hosts}',
  medium_findings: 'Medium findings: {n}', cert_unchecked: 'Certificate not checkable: {domain}',
  cert_expiring: 'Certificate expires in {n} days: {domain}', all_ok: 'All good' };
const API_ERR = { no_summary: 'No summary available yet', not_found: 'Not found', control_denied: 'Control is only allowed from the rack display',
  origin_denied: 'Request from a foreign web page rejected', json_expected: 'JSON expected', too_large: 'Request too large',
  bad_json: 'Invalid JSON', busy: 'A job is already running', no_confirm: 'Confirmation missing', no_plan: 'No patch status available',
  stale: 'The patch status has changed – please review the list again', no_hosts: 'No systems selected',
  unknown_host: 'Unknown system: {host}', nothing_to_do: 'Nothing to update for the selection' };
const FAILED_T = { status: 'patch status', external: 'external view', nuclei: 'Nuclei', install: 'updates', internal: 'internal error' };
/* the summary carries machine-readable reasons (reason_codes); older scanners only send text */
const vReasons = s => Array.isArray(s && s.reason_codes) ? s.reason_codes.map(r => REASON_T[r.id] ? t(REASON_T[r.id], Object.assign({}, r, {hosts: (r.hosts || []).join(', ')})) : (r.text || r.id))
  : ((s && s.reasons) || []);
function vResult(j){
  const r = j.result_data;
  if (!r) return j.result || '';
  if (r.aborted) return t('Aborted (service restarted)');
  let s = j.kind === 'patch'
    ? t('Security updates {a} → {b} · all updates {c} → {d}', {a: r.security[0], b: r.security[1], c: r.upgradable[0], d: r.upgradable[1]})
    : [VLABEL[r.status] || t('finished')].concat(vReasons(r).slice(0, 2)).join(' · ');
  if (r.failed && r.failed.length) s = t('Failed: {steps}', {steps: r.failed.map(k => t(FAILED_T[k] || k)).join(', ')}) + ' · ' + s;
  return s;
}
const vTs = iso => { if (!iso) return null; const s = /[zZ]$|[+-]\d\d:?\d\d$/.test(iso) ? iso : iso + 'Z'; const x = Date.parse(s); return isNaN(x) ? null : x / 1000; };
const vWhen = iso => { const x = vTs(iso); return x == null ? t('never') : fmtWhen(x); };
const vDur = (a, b) => { const t0 = vTs(a); if (t0 == null) return ''; const s = Math.max(0, Math.round((b ? vTs(b) : Date.now() / 1000) - t0)); return s < 60 ? s + ' s' : Math.floor(s / 60) + ':' + two(s % 60) + ' min'; };
const hostOf = u => { try { return new URL(u, location.href).host; } catch (e) { return u || ''; } };
async function vget(p){ const r = await fetch(CFG.vuln + p, {cache:'no-store'}); if (!r.ok) throw new Error(r.status); return r.json(); }
async function vpost(p, body){
  let r;
  try { r = await fetch(CFG.vuln + p, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body || {})}); }
  catch (e) { throw new Error(t('Scanner not reachable')); }
  let j = {}; try { j = await r.json(); } catch (e) {}
  if (!r.ok) { const err = new Error(API_ERR[j.code] ? t(API_ERR[j.code], j) : (j.error || t('Error {code}', {code: r.status}))); err.stale = !!j.stale; throw err; }
  return j;
}
function vErr(msg){ V_ERR = msg; clearTimeout(vErrT); vErrT = setTimeout(() => { V_ERR = ''; const a = $('v-act'); if (a) a.innerHTML = vActHTML(); }, 15000); }
async function vFetch(){
  const [s, j] = await Promise.all([vget('/summary'), vget('/job')]);
  const wasRun = VJOB && VJOB.running;
  VULN = s; VJOB = j;
  return !!(wasRun && !j.running);   // true = a job has just finished
}
function renderVulnCard(){
  const st = $('v-state'), box = $('v-stats');
  if (!VULN) { st.innerHTML = `<span class="dot bad"></span>${t('No data')}`; st.style.color = 'var(--red)'; box.innerHTML = `<div class="vs" style="grid-column:1/-1"><b style="color:var(--dim)">–</b><span>${t('Scanner {host} not reachable', {host: esc(hostOf(CFG.vuln))})}</span></div>`; return; }
  const s = VULN, p = s.patches, c = s.nuclei.counts, e = s.external, hi = c.critical + c.high, nfd = hi + c.medium + c.low;
  const days = e.certs.map(x => x.days_left).filter(fin), dmin = days.length ? Math.min(...days) : null;
  const j = VJOB && VJOB.job, run = !!(VJOB && VJOB.running);
  if (run) { st.innerHTML = `<span class="dot live" style="background:var(--blue)"></span>${j && j.kind === 'patch' ? t('Patch running') : t('Scan running')}`; st.style.color = 'var(--blue)'; }
  else { st.innerHTML = `<span class="dot ${s.status === 'ok' ? 'ok' : s.status === 'crit' ? 'bad' : 'warn'}"></span>${VLABEL[s.status] || esc(s.status)}`; st.style.color = s.status === 'crit' ? 'var(--red)' : s.status === 'warn' ? 'var(--orange)' : 'var(--green)'; }
  box.innerHTML = [
    [p.total_security, t('Security updates'), p.total_security ? 'var(--orange)' : 'var(--green)'],
    [nfd, t('Scan findings'), hi ? 'var(--red)' : c.medium ? 'var(--orange)' : s.nuclei.lastrun ? 'var(--green)' : 'var(--text)'],
    [e.ports.length, e.ports.length === 1 ? t('External port') : t('External ports'), e.vulns.length ? 'var(--red)' : 'var(--text)'],
    [dmin == null ? '–' : dmin, t('Days cert valid'), dmin == null ? 'var(--dim)' : dmin < 7 ? 'var(--red)' : dmin < 14 ? 'var(--orange)' : 'var(--text)'],
  ].map(([v, l, col]) => `<div class="vs"><b style="color:${col}">${v}</b><span>${l}</span></div>`).join('');
}
async function updVuln(){
  clearTimeout(vTimer);
  try {
    const finished = await vFetch();
    renderVulnCard();
    if (VIEW === 'security') { if (finished) refreshDetail(); else { const a = $('v-act'); if (a) a.innerHTML = vActHTML(); } }
    const s = VULN, j = VJOB.job, al = [], rs = vReasons(s);
    if (s.status === 'crit') al.push({lvl:'crit', msg:t('Security: {r}', {r: rs[0] || t('critical')}), pg:'security'});
    else if (s.status === 'warn') al.push({lvl:'warn', msg:rs[0] || t('Security: attention'), pg:'security'});
    if (j && j.state === 'failed' && Date.now() / 1000 - (vTs(j.ended) || 0) < 12 * 3600) al.push({lvl:'warn', msg:j.kind === 'patch' ? t('Patching failed') : t('Scan failed'), pg:'security'});
    setAlert('vuln', al);
    mark('vuln', true);
  } catch (err) { console.error('vuln', err); renderVulnCard(); mark('vuln', false); }
  vTimer = setTimeout(updVuln, VJOB && VJOB.running ? 3000 : 60000);
}

/* security detail page: actions column */
function vActHTML(){
  const s = VULN, j = VJOB && VJOB.job, run = !!(VJOB && VJOB.running), ctl = !!(VJOB && VJOB.control);
  const nUp = s ? s.patches.hosts.filter(h => h.packages && h.packages.length).length : 0, sec = s ? s.patches.total_security : 0;
  let h = `<div class="acts"><button class="act" data-act="scan"${run || !ctl ? ' disabled' : ''}><span class="ic">⟳</span>${t('Start scan')}</button>` +
    `<button class="act pr" data-act="patch"${run || !ctl || !nUp ? ' disabled' : ''}><span class="ic">⛨</span>${t('Patch vulnerabilities')}${sec ? `<span class="cnt num">${sec}</span>` : ''}</button></div>`;
  if (VJOB && !ctl) h += `<div class="note" style="margin-top:8px;padding:0">${t('Control only works on the rack display')}</div>`;
  if (j) {
    const icon = {ok:'✓', fail:'✗', run:'●', wait:'○', skip:'–'};
    const lbl = j.state === 'running' ? (j.kind === 'patch' ? t('Patch running') : t('Scan running'))
      : t((j.kind === 'patch' ? 'Last patch' : 'Last scan') + (j.state === 'failed' ? ' · failed' : ' · finished'));
    const col = j.state === 'running' ? 'var(--blue)' : j.state === 'done' ? 'var(--green)' : 'var(--red)';
    const res = vResult(j);
    h += `<div class="jhead"><span class="lbl" style="color:${col}">${lbl}</span><span class="lbl num">${vWhen(j.started)}</span></div>` +
      '<div class="steps">' + j.steps.map(x => `<div class="stp s-${x.state}"><i>${icon[x.state] || '○'}</i><span>${esc(t(x.name))}</span>` +
        `<span class="t2">${x.state === 'run' ? vDur(x.started) : x.ended && x.started ? vDur(x.started, x.ended) : ''}</span></div>`).join('') + '</div>' +
      (j.kind === 'patch' && j.hosts && !res ? `<div class="jres mut">${pl(j.packages, '{n} package', '{n} packages')} · ${esc(j.hosts.join(', '))}</div>` : '') +
      (res ? `<div class="jres" style="color:${j.state === 'failed' ? 'var(--red)' : 'var(--text)'}">${esc(res)}</div>` : '') +
      (j.state !== 'done' && j.log && j.log.length ? `<div class="vlog">${esc(j.log.slice(j.state === 'running' ? -3 : -2).join('\n'))}</div>` : '');
  } else h += `<div class="note" style="margin-top:12px;padding:0">${t('No job started from the display yet')}</div>`;
  if (V_ERR) h += `<div class="jres" style="color:var(--red);font-weight:700">${esc(V_ERR)}</div>`;
  return h;
}
async function pageSecurity(){
  await vFetch(); renderVulnCard();
  const s = VULN, p = s.patches, n = s.nuclei, e = s.external, c = n.counts;
  const rows = p.hosts.map(h => `<tr><td><span class="dot ${h.security ? 'warn' : h.upgradable ? '' : 'ok'}" style="display:inline-block"></span></td>` +
    `<td><b>${esc(h.host)}</b>${h.reboot_required ? ` <span class="sv-c" style="background:#ff8a3d26;color:var(--orange)">${t('Reboot')}</span>` : ''}</td><td class="s">${esc(h.address || '')}</td><td class="s">${esc(h.os || '')}</td>` +
    `<td class="r">${h.upgradable ? h.upgradable : '<span class="mut">0</span>'}</td><td class="r ${h.security ? 'wrn' : 'mut'}" style="font-weight:700">${h.security}</td></tr>`).join('') +
    (p.unreachable || []).map(h => `<tr><td><span class="dot bad" style="display:inline-block"></span></td><td><b>${esc(h)}</b></td><td colspan="4" class="bad">${t('not reached')}</td></tr>`).join('');
  const c1 = card(t('Pending updates'), `<span class="lbl num">${t('as of {when}', {when: vWhen(p.generated)})}</span>`,
    `<div class="scroll"><table class="tbl vt"><tr><th></th><th>${t('System')}</th><th>${t('Address')}</th><th>${t('Operating system')}</th><th class="r">${t('Updates')}</th><th class="r">${t('Security')}</th></tr>${rows}</table>` +
    (p.hosts.length ? '' : `<div class="mut" style="margin-top:8px">${t('No patch status yet')}</div>`) + '</div>' +
    `<div class="note">${t('Security = packages from the Debian security repository · {u} updates on {a} of {b} systems', {u: p.total_upgradable, a: p.hosts.filter(h => h.upgradable).length, b: p.hosts.length})}</div>`);
  const hi = c.critical + c.high, F = n.findings || [];
  const sevC = {critical:'#ff4d5e', high:'#ff4d5e', medium:'#ff8a3d', low:'#4cc2ff'};
  const certs = e.certs.filter(x => fin(x.days_left)).sort((a, b) => a.days_left - b.days_left), bad = e.certs.filter(x => !fin(x.days_left));
  const c2 = card(t('Scan & exposure'), `<span class="lbl num">${vWhen(n.lastrun)}</span>`,
    `<div class="sevs"><div class="stat"><b style="color:${hi ? 'var(--red)' : 'var(--text)'}">${hi}</b><span>${t('high')}</span></div>` +
    `<div class="stat"><b style="color:${c.medium ? 'var(--orange)' : 'var(--text)'}">${c.medium}</b><span>${t('medium')}</span></div>` +
    `<div class="stat"><b style="color:${c.low ? 'var(--blue)' : 'var(--text)'}">${c.low}</b><span>${t('low')}</span></div></div>` +
    '<div class="list">' + (F.length ? F.slice(0, 3).map(f => `<div class="li" style="grid-template-columns:auto 1fr"><span class="sv-c" style="background:${sevC[f.severity]}26;color:${sevC[f.severity]}">${t(f.severity)}</span>` +
      `<span class="n">${esc(f.name || f.template || '?')} <span class="m">${esc(hostOf(f.target))}</span></span></div>`).join('') + (F.length > 3 ? `<div class="mut" style="font-size:12px">${t('+ {n} more (details on the scanner dashboard)', {n: F.length - 3})}</div>` : '')
      : `<div class="${n.lastrun ? 'ok' : 'mut'}">${n.lastrun ? t('No findings') : t('No scan has run yet')}</div>`) + '</div>' +
    `<div class="lbl sec">${t('External · {ip}', {ip: esc(e.ip || '–')})}</div><div class="kv">` +
    `<span>${t('Open ports')}</span><span>${e.ports.length ? esc(e.ports.join(', ')) : t('none')}</span>` +
    `<span>${t('Known vulnerabilities')}</span><span class="${e.vulns.length ? 'bad' : 'ok'}">${e.vulns.length ? esc(e.vulns.slice(0, 2).join(', ')) + (e.vulns.length > 2 ? ' …' : '') : t('none')}</span>` +
    `<span>${t('Next certificate')}</span><span class="${certs.length && certs[0].days_left < 7 ? 'bad' : certs.length && certs[0].days_left < 14 ? 'wrn' : ''}">${certs.length ? t('in {n} days', {n: certs[0].days_left}) : '–'}</span></div>` +
    `<div class="note">${certs.length ? esc(certs[0].domain) + ' · ' : ''}${bad.length ? `<span class="wrn">${t('{n} not checkable', {n: bad.length})}</span> · ` : ''}${t('checked {when}', {when: vWhen(e.checked)})}</div>`);
  const c3 = card(t('Actions'), '', `<div id="v-act" style="display:flex;flex-direction:column;flex:1;min-height:0">${vActHTML()}</div>`);
  return { html: c1 + c2 + c3, sub: `${VLABEL[s.status] || s.status} · ${vReasons(s).slice(0, 2).join(' · ')}` };
}

/* buttons and confirmation dialog */
async function vAct(act, el){
  poke();
  if (act === 'scan') {
    el.disabled = true;
    try { V_ERR = ''; await vpost('/scan'); } catch (e) { vErr(e.message); }
    return updVuln();
  }
  if (act === 'patch') return openPatch();
  if (!MODAL) return;
  if (act === 'm-host') {
    const h = el.dataset.host; if (MODAL.sel.has(h)) MODAL.sel.delete(h); else MODAL.sel.add(h);
    el.classList.toggle('on', MODAL.sel.has(h)); MODAL.conf = false; return mFoot();
  }
  if (act === 'm-sec' || act === 'm-all' || act === 'm-none') {
    MODAL.sel = new Set(MODAL.hosts.filter(h => act === 'm-all' || (act === 'm-sec' && h.security > 0)).map(h => h.host));
    document.querySelectorAll('#modal .ph').forEach(r => r.classList.toggle('on', MODAL.sel.has(r.dataset.host)));
    MODAL.conf = false; return mFoot();
  }
  if (act === 'm-conf') { MODAL.conf = !MODAL.conf; return mFoot(); }
  if (act === 'm-cancel') return closeModal();
  if (act === 'm-go') return doPatch();
}
function openPatch(msg){
  const p = VULN && VULN.patches; if (!p) return;
  const hosts = p.hosts.filter(h => h.packages && h.packages.length); if (!hosts.length) return;
  // preselected: systems with security updates; the confirmation tick starts unchecked
  MODAL = { plan: p.generated, hosts, sel: new Set(hosts.filter(h => h.security > 0).map(h => h.host)), conf: false, busy: false, err: msg || '' };
  const kern = h => h.packages.some(x => /kernel|linux-image/.test(x));
  $('modal').innerHTML = `<div class="dlg"><div class="dlh"><h2>${t('PATCH VULNERABILITIES')}</h2>` +
    `<div class="ds">${pl(hosts.length, '{n} system with updates', '{n} systems with updates')}${hosts.length > 5 ? t(' (swipe list)') : ''} · ${t('as of {when}', {when: vWhen(p.generated)})}<br>${t('Exactly the listed packages of the selected systems are installed (plus required dependencies). No automatic reboot.')}</div>` +
    `<button class="sm" data-act="m-sec">${t('Security only')}</button><button class="sm" data-act="m-all">${t('All')}</button><button class="sm" data-act="m-none">${t('None')}</button></div>` +
    '<div class="plist">' + hosts.map(h => `<div class="ph${MODAL.sel.has(h.host) ? ' on' : ''}" data-act="m-host" data-host="${esc(h.host)}"><span class="cb">✓</span>` +
      `<div class="pn"><b>${esc(h.host)}</b><span>${esc(h.address || '')} · ${esc(h.os || '')}</span></div>` +
      `<div class="pc">${pl(h.packages.length, '<b>{n}</b> package', '<b>{n}</b> packages')}<br><span class="${h.security ? 'wrn' : ''}">${h.security ? t('{n} security', {n: h.security}) : t('no security')}</span></div>` +
      `<div class="pk">${h.packages.map(esc).join(' · ')}${kern(h) ? ` <span class="wrn">${t('· new kernel, active after reboot')}</span>` : ''}</div></div>`).join('') + '</div>' +
    `<div class="dfoot"><div class="conf" id="m-conf" data-act="m-conf"><span class="cb">✓</span><span>${t('Yes, I have checked what will be updated')}</span></div>` +
    `<div class="dsum" id="m-sum"></div><button class="act" data-act="m-cancel">${t('Cancel')}</button><button class="act pr" id="m-go" data-act="m-go" disabled>${t('Patch now')}</button></div></div>`;
  $('modal').classList.add('on'); poke(); mFoot();
  const lst = $('modal').querySelector('.plist'), more = () => lst.classList.toggle('more', lst.scrollTop + lst.clientHeight < lst.scrollHeight - 4);
  lst.addEventListener('scroll', () => { more(); poke(); }, {passive: true}); more();
}
function mFoot(){
  if (!MODAL) return;
  const sel = MODAL.hosts.filter(h => MODAL.sel.has(h.host)), pk = sel.reduce((a, h) => a + h.packages.length, 0), sec = sel.reduce((a, h) => a + h.security, 0);
  $('m-conf').classList.toggle('on', MODAL.conf);
  $('m-sum').innerHTML = (sel.length ? pl(sel.length, '{pk} on <b>{n} system</b>', '{pk} on <b>{n} systems</b>', {pk: `<b>${pl(pk, '{n} package', '{n} packages')}</b>`}) +
      (sec ? ' · ' + t('{n} of them security updates', {n: sec}) : '') + `<br>${esc(sel.map(h => h.host).join(', '))}`
    : t('No system selected')) + (MODAL.err ? `<br><span class="err">${esc(MODAL.err)}</span>` : '');
  const go = $('m-go'); go.disabled = !MODAL.conf || !sel.length || MODAL.busy; go.textContent = MODAL.busy ? t('Starting …') : t('Patch now');
}
function closeModal(){ MODAL = null; const m = $('modal'); m.classList.remove('on'); m.innerHTML = ''; }
async function doPatch(){
  const M = MODAL; if (!M || !M.conf || !M.sel.size || M.busy) return;
  M.busy = true; M.err = ''; mFoot();
  try {
    // only the plan id and the host names are sent; the scanner decides which packages that means
    await vpost('/patch', { plan: M.plan, hosts: [...M.sel], confirm: true });
  } catch (e) {
    if (MODAL !== M) return;
    if (e.stale) { await vFetch().catch(() => {}); return openPatch(t('The patch status was re-read in the meantime – please check the list again.')); }
    M.busy = false; M.err = e.message; return mFoot();
  }
  closeModal(); V_ERR = ''; updVuln();
}

/* ===================== detail navigation ===================== */
const PAGES = {
  attacks:  { title: 'ATTACKS & CROWDSEC', render: pageAttacks },
  firewall: { title: 'FIREWALL · WAN BLOCKS', render: pageFirewall },
  wan:      { title: 'WAN TRAFFIC', render: pageWan, range: true },
  systems:  { title: 'SYSTEMS', render: pageSystems, range: true },
  drives:   { title: 'DRIVES', render: pageDrives, range: true },
  backups:  { title: 'BACKUPS', render: pageBackups, off: !CFG.backup },
  security: { title: 'SECURITY · VULNERABILITIES', render: pageSecurity, off: !CFG.vuln },
};
let VIEW = null, RANGE = 86400, lastTouch = 0, dTimer = null, dSeq = 0;
function poke(){ lastTouch = Date.now(); }
function setRange(r){ RANGE = r; document.querySelectorAll('.rng').forEach(b => b.classList.toggle('on', +b.dataset.range === r)); }
function openDetail(name){
  const P = PAGES[name]; if (!P || P.off) return;
  VIEW = name; poke(); setRange(86400);
  $('app').dataset.view = 'detail';
  $('dtitle').textContent = t(P.title); $('dsub').textContent = '';
  $('ranges').style.display = P.range ? '' : 'none';
  const b = $('dbody'); b.className = 'dbody ' + name; b.innerHTML = `<div class="loading">${t('Loading data …')}</div>`;
  idleTick(); refreshDetail();
  clearInterval(dTimer); dTimer = setInterval(refreshDetail, 30000);
}
function closeDetail(){
  closeModal();
  if (!VIEW) return;
  VIEW = null; clearInterval(dTimer); dSeq++;
  delete $('app').dataset.view; $('dbody').innerHTML = '';
  updMap(); updCrowdsec(); // re-fit the chips (they cannot be measured while hidden)
}
async function refreshDetail(){
  const v = VIEW, seq = ++dSeq, b = $('dbody'); if (!v) return;
  b.classList.add('busy');
  try {
    const out = await PAGES[v].render(RANGE);
    if (seq !== dSeq || VIEW !== v) return;
    b.innerHTML = out.html; $('dsub').textContent = out.sub || '';
  } catch (err) {
    console.error('detail', v, err);
    if (seq === dSeq && VIEW === v) { if (b.querySelector('.loading')) b.innerHTML = `<div class="loading">${t('Could not load data ({e})', {e: esc(err.message || err)})}</div>`; else $('dsub').textContent = t('Update failed – showing last state'); }
  } finally { if (seq === dSeq) b.classList.remove('busy'); }
}
function idleTick(){
  if (MODAL) { if ((Date.now() - lastTouch) / 1000 > CFG.modalTimeout) closeModal(); else { $('dauto').textContent = ''; return; } }
  if (!VIEW) return;
  const left = CFG.detailTimeout - (Date.now() - lastTouch) / 1000;
  if (left <= 0) closeDetail(); else $('dauto').textContent = t('Overview in {n} s', {n: Math.ceil(left)});
}
document.addEventListener('click', e => {
  const a = e.target.closest('[data-act]');
  if (a) { vAct(a.dataset.act, a); return; }
  if (MODAL) return;
  const r = e.target.closest('[data-range]');
  if (r) { setRange(+r.dataset.range); refreshDetail(); return; }
  if (e.target.closest('#back') || e.target.closest('.brand')) { closeDetail(); return; }
  const tg = e.target.closest('[data-detail]');
  if (tg && tg.dataset.detail) openDetail(tg.dataset.detail);
});
addEventListener('pointerdown', poke, true);
addEventListener('keydown', e => { poke(); if (e.key === 'Escape' || e.key === 'Backspace') closeDetail(); });
let mouseT = null;
addEventListener('pointermove', e => {
  if (e.pointerType !== 'mouse') return;
  document.documentElement.classList.add('mouse'); poke();
  clearTimeout(mouseT); mouseT = setTimeout(() => document.documentElement.classList.remove('mouse'), 3000);
});

/* ===================== start ===================== */
function fit(){ $('app').style.transform = `scale(${Math.min(innerWidth/1280, innerHeight/400)})`; }
fit(); addEventListener('resize', fit);
clock(); updLog(); updRate(); updMap(); updProm(); updSpark(); updCrowdsec();
if (CFG.backup) updBackup();
if (CFG.vuln) updVuln();
setInterval(clock, 1000);
setInterval(updLog, 5000);
setInterval(updRate, 15000);
setInterval(updProm, 10000);
setInterval(updSpark, 30000);
setInterval(updMap, 60000);
if (CFG.backup) setInterval(updBackup, 60000);
setInterval(updCrowdsec, 30000);
// reload every 6 h to pick up changes (never in the middle of a detail page)
setInterval(() => { if (!VIEW && performance.now() > 6 * 3600 * 1000) location.reload(); }, 60000);
