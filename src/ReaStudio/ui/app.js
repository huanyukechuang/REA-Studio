/* REA Studio - UI logic (WebView2 host bridge) */
'use strict';

const host = window.chrome && window.chrome.webview;
const pending = new Map();
let seq = 0;

function invoke(method, params) {
  return new Promise((resolve, reject) => {
    if (!host) { reject(new Error('当前不在 WebView2 宿主内运行')); return; }
    const id = 'r' + (++seq);
    pending.set(id, { resolve, reject });
    host.postMessage({ id, method, params: params || {} });
    setTimeout(() => {
      if (pending.has(id)) { pending.delete(id); reject(new Error('调用超时: ' + method)); }
    }, 300000);
  });
}

if (host) {
  host.addEventListener('message', (ev) => {
    const d = ev.data;
    if (!d) return;
    if (d.event) { onEvent(d.event, d.data); return; }
    const p = pending.get(d.id);
    if (!p) return;
    pending.delete(d.id);
    if (d.ok) p.resolve(d.result); else p.reject(new Error(d.error || '调用失败'));
  });
}

const $ = (s) => document.querySelector(s);
const $$ = (s) => Array.from(document.querySelectorAll(s));
const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const state = {
  status: null,
  target: null,
  modules: [],
  selected: new Set(),
  results: {},
  running: false,
  evidence: [],
  activeEvidence: null,
  aiSettings: null,
  modelStatus: null,
  modelCatalogLoaded: false,
  chat: [],
  types: [],
  network: null,
  site: null,
  siteStatic: null,
  siteDynamic: null,
  dynamic: null,
  sandbox: null,
  virus: null,
  vuln: null,
};

/* ---------- toast ---------- */
let toastTimer = null;
function toast(msg, ms) {
  const el = $('#toast');
  el.textContent = msg;
  el.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove('show'), ms || 2600);
}

/* ---------- 通用 ---------- */
function humanSize(n) {
  if (n == null) return '—';
  const u = ['B', 'KB', 'MB', 'GB'];
  let i = 0, v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return (i === 0 ? v : v.toFixed(v < 10 ? 2 : 1)) + ' ' + u[i];
}

function navigate(page) {
  $$('.navitem').forEach(b => b.classList.toggle('active', b.dataset.page === page));
  $$('.page').forEach(p => p.classList.toggle('active', p.id === 'page-' + page));
}

/* ---------- 标题栏 ---------- */
$('#btnMin').onclick = () => invoke('window.min');
$('#btnMax').onclick = () => invoke('window.max');
$('#btnClose').onclick = () => invoke('window.close');
// 宿主由 Win32 接管拖动（ReleaseCapture + WM_NCLBUTTONDOWN/HTCAPTION），
// WebView2 铺满客户区时 WPF DragMove() 会失败，故拖动统一走此入口。
document.addEventListener('mousedown', (e) => {
  if (e.button !== 0) return;
  if (e.target.closest('#titlebar') && !e.target.closest('.captionbtn')) {
    invoke('window.drag').catch(() => {});
  }
});
document.addEventListener('dblclick', (e) => {
  if (e.target.closest('#titlebar') && !e.target.closest('.captionbtn')) {
    invoke('window.max').catch(() => {});
  }
});

/* ---------- 导航 ---------- */
$$('.navitem').forEach(b => b.onclick = () => navigate(b.dataset.page));

/* ---------- 目标选择 ---------- */
$('#btnPick').onclick = async () => { await pickTarget(); };

const dz = $('#dropzone');

function dzHot(on) { if (dz) dz.classList.toggle('hot', on); }

// 前端诊断日志：经 Bridge 写入宿主机日志，便于排查拖放链路
function uiLog(msg) {
  try {
    const r = invoke('log.write', { msg: '' + msg });
    if (r && r.catch) r.catch(function () { });
  } catch (e) { /* ignore */ }
}

// 只接管"拖文件"，拖文本进输入框等操作不受影响
function hasDroppedFiles(e) {
  const dt = e.dataTransfer;
  if (!dt) return false;
  const t = dt.types;
  if (t && Array.prototype.indexOf.call(t, 'Files') >= 0) return true;
  return !!(dt.files && dt.files.length); // 少数情况下 types 缺失但 files 已就绪
}

/* Chromium 137 起移除了非标准 File.path，新版 WebView2 拖入文件时 dataTransfer 也不再带
   text/uri-list，于是"拖入读不到本地路径"。唯一可靠的官方途径是宿主侧的
   CoreWebView2File.Path：前端用 postMessageWithAdditionalObjects 把 File 对象交给宿主换取路径。 */
function requestPathsFromFiles(files) {
  return new Promise((resolve, reject) => {
    const list = Array.from(files || []);
    if (!host || typeof host.postMessageWithAdditionalObjects !== 'function') { uiLog('drop: 宿主不支持 postMessageWithAdditionalObjects'); reject(new Error('当前宿主不支持拖放取路径')); return; }
    if (!list.length) { uiLog('drop: dataTransfer.files 为空'); reject(new Error('未检测到拖入的文件')); return; }
    const id = 'r' + (++seq);
    pending.set(id, { resolve, reject });
    try {
      host.postMessageWithAdditionalObjects({ id, method: 'target.paths', params: {} }, list);
      uiLog('drop: 已发送 target.paths, files=' + list.length + ', type=' + (list[0] && list[0].constructor && list[0].constructor.name));
    } catch (err) {
      pending.delete(id);
      uiLog('drop: postMessageWithAdditionalObjects 异常 ' + err.message);
      reject(err);
      return;
    }
    setTimeout(() => {
      if (pending.has(id)) { pending.delete(id); uiLog('drop: target.paths 超时'); reject(new Error('调用超时: target.paths')); }
    }, 60000);
  });
}

// 老宿主兜底：仍能拿到 file:// 的 uri-list 时直接解析
function pathFromUriList(dt) {
  try {
    const uri = dt.getData('text/uri-list') || dt.getData('text/plain') || '';
    const line = uri.split(/\r?\n/).find(x => x.trim().startsWith('file://'));
    if (!line) return '';
    return decodeURIComponent(line.trim().replace(/^file:\/+/, '')).replace(/\//g, '\\').replace(/\\$/, '');
  } catch { return ''; }
}

let dropBusy = false;

// 统一入口：drop（拖入）与 paste（Ctrl+V 粘贴文件）共用同一条取路径链路
async function handleFileList(files, dt) {
  const list = Array.from(files || []);
  const types = (dt && dt.types) ? Array.prototype.join.call(dt.types, '|') : '-';
  const kinds = (dt && dt.items) ? Array.prototype.map.call(dt.items, function (i) { return i.kind + ':' + i.type; }).join('|') : '-';
  uiLog('drop: n=' + list.length + ' types=' + types + ' items=' + kinds);
  if (!list.length || dropBusy) return;
  dropBusy = true;
  dzHot(false);
  try {
    let p = '';
    try {
      const paths = await requestPathsFromFiles(list);
      uiLog('drop: 宿主返回 ' + JSON.stringify(paths || []));
      p = (paths && paths.length) ? paths[0] : '';
    } catch (err) {
      uiLog('drop: 取路径失败 ' + (err && err.message));
      if (window.console && console.warn) console.warn('[drop] target.paths 失败', err);
    }
    if (!p && dt) p = pathFromUriList(dt);
    if (!p) { toast('未能读取拖入路径，已打开文件选择窗口'); await pickTarget(); return; }
    await openPath(p);
  } finally {
    dropBusy = false;
  }
}

async function handleDrop(e) {
  if (!hasDroppedFiles(e) || dropBusy) return;
  e.preventDefault();
  e.stopPropagation();
  await handleFileList(e.dataTransfer && e.dataTransfer.files, e.dataTransfer);
}

// 监听挂在 document 上：任意页面拖入文件都能指定/更换目标
document.addEventListener('dragenter', (e) => { if (hasDroppedFiles(e)) { e.preventDefault(); dzHot(true); } });
document.addEventListener('dragover', (e) => {
  if (!hasDroppedFiles(e)) return;
  e.preventDefault();
  if (e.dataTransfer) e.dataTransfer.dropEffect = 'copy';
  dzHot(true);
});
document.addEventListener('dragleave', (e) => { if (!e.relatedTarget) dzHot(false); });
document.addEventListener('drop', (e) => { if (hasDroppedFiles(e)) handleDrop(e); });

// 通道C：Ctrl+V 粘贴文件（在资源管理器 Ctrl+C 复制文件后，回到应用内直接粘贴即可指定目标）
document.addEventListener('paste', (e) => {
  const cd = e.clipboardData;
  const files = cd && cd.files;
  if (!files || !files.length) return; // 纯文本粘贴交给输入框，不拦截
  e.preventDefault();
  handleFileList(files, cd);
});

document.addEventListener('keydown', (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'o') { e.preventDefault(); $('#btnPick').click(); }
});

async function openPath(p) {
  try {
    const t = await invoke('target.info', { path: p });
    if (t) await setTarget(t); else toast('无法读取该路径（需为本地已存在的文件）');
  } catch (e) { toast(e.message); }
}

async function setTarget(t) {
  state.target = t;
  state.results = {};
  state.evidence = [];
  state.types = [];
  state.network = null;
  state.site = null;
  state.dynamic = null;
  if ($('#netBody')) $('#netBody').innerHTML = '<div class="ev-empty">尚未执行网络分析</div>';
  if ($('#dynBody')) $('#dynBody').innerHTML = '<div class="ev-empty">选择目标后可运行动态分析</div>';
  $('#crumb').textContent = t.name + '  ·  ' + humanSize(t.size);
  $('#targetCard').classList.remove('hidden');
  dz.classList.add('hidden');
  $('#tName').textContent = t.name;
  $('#tPath').textContent = t.path;
  $('#tBadges').innerHTML = [
    `<span class="badge accent">${esc(t.ext || '无扩展名')}</span>`,
    `<span class="badge">${humanSize(t.size)}</span>`,
    `<span class="badge">修改于 ${esc(t.modified)}</span>`
  ].join('');

  try {
    const mods = await invoke('modules.list', { path: t.path });
    state.modules = mods;
    state.selected = new Set(mods.filter(m => m.defaultOn).map(m => m.id));
    renderModules();
    $('#anaSub').textContent = `${t.name} · 可用离线模块 ${mods.length} 个，已选 ${state.selected.size} 个`;
    $('#modCount').textContent = state.selected.size;
  } catch (e) { toast(e.message); }

  $('#results').innerHTML = '<div class="empty" id="anaEmpty"><div class="icon">&#xE9D9;</div><div>尚未执行分析</div></div>';
  $('#evList').innerHTML = '<div class="ev-empty">暂无证据</div>';
  $('#evBody').innerHTML = '<div class="ev-empty">从左侧选择一项证据查看</div>';
  renderAiState();
  detectTypes();
}

/* ---------- 模块 ---------- */
function renderModules() {
  const box = $('#mpList');
  box.innerHTML = state.modules.map(m => `
    <label class="mp-item">
      <input type="checkbox" data-mod="${esc(m.id)}" ${state.selected.has(m.id) ? 'checked' : ''}/>
      <span title="${esc(m.description)}">${esc(m.title)}</span>
      <span class="grp">${esc(m.group)}</span>
    </label>`).join('');
  $$('#mpList input').forEach(cb => cb.onchange = () => {
    if (cb.checked) state.selected.add(cb.dataset.mod); else state.selected.delete(cb.dataset.mod);
    $('#modCount').textContent = state.selected.size;
  });
}

$('#btnModules').onclick = () => $('#modulePanel').classList.toggle('hidden');
$('#btnGotoAnalysis').onclick = () => { navigate('analysis'); if (state.target) runAnalysis(); };

/* ---------- 更换目标 ---------- */
function resetTargetUI() {
  state.target = null;
  state.results = {};
  state.evidence = [];
  state.types = [];
  state.network = null;
  state.site = null;
  state.dynamic = null;
  state.width = 0;
  $('#targetCard').classList.add('hidden');
  dz.classList.remove('hidden');
  $('#crumb').textContent = '未选择目标';
  $('#tName').textContent = '—';
  $('#tPath').textContent = '—';
  $('#tBadges').innerHTML = '';
  $('#anaSub').textContent = '选择目标后可在本机执行离线分析模块。';
  $('#modCount').textContent = '0';
  $('#typeBar').innerHTML = '<span class="junk">尚未识别目标类型</span>';
  $('#results').innerHTML = '<div class="empty" id="anaEmpty"><div class="icon">&#xE9D9;</div><div>尚未执行分析</div></div>';
  $('#evList').innerHTML = '<div class="ev-empty">暂无证据</div>';
  $('#evBody').innerHTML = '<div class="ev-empty">从左侧选择一项证据查看</div>';
  $('#chat').innerHTML = '';
  renderAiState();
}
async function pickTarget() {
  try {
    const t = await invoke('target.pick');
    if (t) await setTarget(t);
  } catch (e) { toast(e.message); }
}
$('#btnRepick').onclick = async () => { resetTargetUI(); await pickTarget(); };

/* ---------- 分析执行 ---------- */
$('#btnRun').onclick = () => runAnalysis();
$('#btnCancel').onclick = () => invoke('analysis.cancel').catch(() => {});
$('#btnReport').onclick = () => exportReport('md', 'static');
$('#btnPdf').onclick = () => exportReport('pdf', 'static');
$('#btnTypes').onclick = () => { if (!state.target) { toast('请先选择目标文件'); return; } detectTypes(); };
$('#btnNetQuick').onclick = () => runNetwork();
$('#btnNet').onclick = () => runNetwork();
$('#btnNetMd').onclick = () => exportReport('md', 'network');
$('#btnNetPdf').onclick = () => exportReport('pdf', 'network');
$('#btnSiteMd').onclick = () => exportReport('md', 'site');
$('#btnSitePdf').onclick = () => exportReport('pdf', 'site');
if ($('#dynSec')) $('#dynSec').onchange = () => syncDynSecUi();
if ($('#dynSecNum')) $('#dynSecNum').oninput = () => { if ($('#dynSec').value !== 'custom') { $('#dynSec').value = 'custom'; syncDynSecUi(); } };
if ($('#dynSecUnit')) $('#dynSecUnit').onchange = () => { if ($('#dynSec').value !== 'custom') { $('#dynSec').value = 'custom'; syncDynSecUi(); } };
$('#btnDynRun').onclick = () => runDynamic();
$('#btnDynStop').onclick = () => { invoke('dynamic.stop').catch(() => {}); toast('正在停止动态分析…', 2500); };
$('#btnDynMd').onclick = () => exportReport('md', 'dynamic');
$('#btnDynPdf').onclick = () => exportReport('pdf', 'dynamic');
$('#btnWebRecon').onclick = () => runWebRecon();
$('#btnSiteStatic').onclick = () => runSiteStatic();
$('#btnSiteDynamic').onclick = () => runSiteDynamic();
$('#btnSbOpen').onclick = () => sandboxOpen();
$('#btnSbPurge').onclick = () => sandboxPurge();
$('#btnSiteDynStop').onclick = () => { invoke('site.dynamic.stop').catch(() => {}); toast('正在停止站点动态分析…', 2500); };
$('#btnExplain').onclick = () => aiExplain();

async function runAnalysis() {
  if (!state.target) { toast('请先选择目标文件'); navigate('target'); return; }
  if (state.running) { toast('分析进行中'); return; }
  if (state.selected.size === 0) { toast('请至少选择一个模块'); $('#modulePanel').classList.remove('hidden'); return; }

  state.running = true;
  state.results = {};
  // 病毒检测面板随本次分析重新开始
  state.virus = null;
  $('#virusCard').classList.add('hidden');
  $('#virusKv').innerHTML = '';
  $('#virusHits').innerHTML = '';
  // 站点独立分析的证据与文件目标无关，切换文件目标时保留
  state.evidence = state.evidence.filter(e => e.source === 'site-static' || e.source === 'site-dynamic');
  state.site = null;
  state.dynamic = null;
  if ($('#siteBody')) $('#siteBody').innerHTML = '<div class="ev-empty">尚未执行站点逆向</div>';
  if ($('#dynBody')) $('#dynBody').innerHTML = '<div class="ev-empty">尚未运行动态分析</div>';
  $('#btnRun').disabled = true;
  $('#btnCancel').classList.remove('hidden');
  $('#progressWrap').classList.remove('hidden');
  $('#progressFill').style.width = '0%';
  $('#results').innerHTML = '';
  navigate('analysis');

  const mods = state.modules.filter(m => state.selected.has(m.id));
  mods.forEach(m => {
    state.results[m.id] = { meta: m, state: 'wait', title: m.title, group: m.group, desc: m.description };
  });
  renderResults();

  try {
    await invoke('analysis.run', { path: state.target.path, modules: mods.map(m => m.id) });
  } catch (e) {
    toast(e.message);
    state.running = false;
    $('#btnRun').disabled = false;
    $('#btnCancel').classList.add('hidden');
  }
}

function renderResults() {
  const box = $('#results');
  const order = state.modules.filter(m => state.selected.has(m.id));
  if (!order.length) {
    box.innerHTML = '<div class="empty"><div class="icon">&#xE9D9;</div><div>尚未执行分析</div></div>';
    return;
  }
  box.innerHTML = order.map(m => {
    const r = state.results[m.id] || { state: 'wait', meta: m };
    let icon = '&#xE9D9;', cls = '', meta = '等待';
    if (r.state === 'run') { icon = ''; cls = 'run'; meta = '分析中'; }
    else if (r.state === 'ok') { icon = '&#xE73E;'; cls = 'ok'; meta = r.elapsed + ' ms'; }
    else if (r.state === 'err') { icon = '&#xE711;'; cls = 'err'; meta = r.code || '不支持'; }
    else if (r.state === 'cancel') { icon = '&#xE71A;'; cls = 'err'; meta = '已取消'; }
    const iconHtml = cls === 'run' ? '<span class="spin"></span>' : `<span class="icon">${icon}</span>`;
    return `<div class="rescard" data-card="${esc(m.id)}">
      <div class="reshead" data-toggle="${esc(m.id)}">
        <div class="resicon ${cls}">${iconHtml}</div>
        <div><div class="rtitle">${esc(m.title)}</div><div class="rdesc">${esc(m.description)}</div></div>
        <div class="rmeta"><span>${esc(m.group)}</span><span data-meta>${esc(meta)}</span></div>
      </div>
      <div class="resbody" data-body></div>
    </div>`;
  }).join('');

  $$('[data-toggle]').forEach(h => h.onclick = () => {
    const card = h.closest('.rescard');
    card.classList.toggle('open');
    if (card.classList.contains('open')) fillBody(card.dataset.card, card.querySelector('[data-body]'));
  });
}

async function fillBody(id, bodyEl) {
  const r = state.results[id];
  if (!r) return;
  if (bodyEl.dataset.filled === '1') return;
  bodyEl.dataset.filled = '1';

  if (r.state === 'err') {
    bodyEl.innerHTML = `<div class="errbox">该模块在本机不可用：${esc(r.message || r.code || '未知原因')}</div>`;
    return;
  }
  if (r.state !== 'ok') { bodyEl.innerHTML = '<div class="errbox">暂无结果</div>'; return; }

  let jsonText = r.json;
  if (!jsonText && r.evidenceFile) {
    bodyEl.innerHTML = '<div class="junk">结果较大（' + humanSize(r.size) + '），正在读取…</div>';
    try {
      const res = await invoke('evidence.peek', { path: r.evidenceFile, maxChars: 400000 });
      jsonText = res.text;
    } catch (e) { bodyEl.innerHTML = `<div class="errbox">${esc(e.message)}</div>`; return; }
  }
  let parsed;
  try { parsed = JSON.parse(jsonText); }
  catch (e) {
    bodyEl.innerHTML = `<div class="jtree">${esc(jsonText || '').slice(0, 20000)}</div>`;
    return;
  }
  bodyEl.innerHTML = '';
  const tree = document.createElement('div');
  tree.className = 'jtree';
  tree.appendChild(buildNode(parsed, 0, ''));
  bodyEl.appendChild(tree);
}

/* ---------- JSON 树 ---------- */
function buildNode(value, depth, key) {
  const wrap = document.createElement('div');
  wrap.className = 'jrow';

  if (value === null) { wrap.innerHTML = `<span class="jkey">${esc(key)}</span><span class="junk"> null</span>`; return wrap; }

  if (Array.isArray(value)) {
    const head = document.createElement('div');
    head.innerHTML = `<span class="jtoggle">▾</span><span class="jkey">${esc(key)}</span><span class="junk"> [${value.length}]</span>`;
    wrap.appendChild(head);
    const kids = document.createElement('div');
    kids.style.paddingLeft = '14px';
    const limit = depth >= 2 ? Math.min(value.length, 60) : value.length;
    for (let i = 0; i < limit; i++) kids.appendChild(buildNode(value[i], depth + 1, String(i)));
    if (value.length > limit) {
      const more = document.createElement('div');
      more.className = 'junk';
      more.textContent = `… 其余 ${value.length - limit} 项已省略`;
      kids.appendChild(more);
    }
    wrap.appendChild(kids);
    let open = depth < 2;
    const apply = () => { kids.style.display = open ? '' : 'none'; head.querySelector('.jtoggle').textContent = open ? '▾' : '▸'; };
    apply();
    head.onclick = (e) => { e.stopPropagation(); open = !open; apply(); };
    return wrap;
  }

  if (typeof value === 'object') {
    const keys = Object.keys(value);
    const head = document.createElement('div');
    head.innerHTML = `<span class="jtoggle">▾</span><span class="jkey">${esc(key)}</span><span class="junk"> {${keys.length}}</span>`;
    wrap.appendChild(head);
    const kids = document.createElement('div');
    kids.style.paddingLeft = '14px';
    const limit = depth >= 2 ? Math.min(keys.length, 80) : keys.length;
    for (let i = 0; i < limit; i++) kids.appendChild(buildNode(value[keys[i]], depth + 1, keys[i]));
    if (keys.length > limit) {
      const more = document.createElement('div');
      more.className = 'junk';
      more.textContent = `… 其余 ${keys.length - limit} 项已省略`;
      kids.appendChild(more);
    }
    wrap.appendChild(kids);
    let open = depth < 2;
    const apply = () => { kids.style.display = open ? '' : 'none'; head.querySelector('.jtoggle').textContent = open ? '▾' : '▸'; };
    apply();
    head.onclick = (e) => { e.stopPropagation(); open = !open; apply(); };
    return wrap;
  }

  let cls = 'jstr', text = JSON.stringify(value);
  if (typeof value === 'number') cls = 'jnum';
  else if (typeof value === 'boolean') cls = 'jbool';
  wrap.innerHTML = `<span class="jkey">${esc(key)}</span>: <span class="${cls}">${esc(text)}</span>`;
  return wrap;
}

/* ---------- 事件 ---------- */
function onEvent(name, data) {
  if (name === 'ai.delta') {
    const s = state.chatStream;
    if (!s) return;
    s.acc += String((data && data.text) || '');
    s.bubble.textContent = cleanAiText(s.acc) || '思考中…';
    autoScrollChat();
    return;
  }
  if (name === 'ai.stats') {
    const s = state.chatStream;
    if (!s) return;
    s.stats = data || {};
    renderChatMeta(s.meta, s.stats);
    return;
  }
  if (name === 'drop.hover') { dzHot(!!(data && data.on)); return; }
  if (name === 'drop.files') {
    dzHot(false);
    const dp = (data && data.paths) || [];
    if (!dp.length) { toast('未能读取拖入路径，已打开文件选择窗口'); pickTarget(); return; }
    openPath(dp[0]);
    return;
  }
  if (name === 'model.progress') { onModelProgress(data); return; }
  if (name === 'dynamic.log') {
    const box = $('#dynBody');
    if (box && box.dataset.running === '1') { box.innerHTML = '<div class="junk">' + esc(String(data || '')) + '</div>'; }
    return;
  }
  if (name === 'open.target') { setTarget(data); return; }
  if (name === 'analysis.begin') {
    toast('开始分析，共 ' + data.total + ' 个模块');
    return;
  }
  if (name === 'analysis.progress') {
    const r = state.results[data.module];
    if (r && data.state === 'running') { r.state = 'run'; patchCard(data.module, '分析中', 'run'); }
    if (r && data.state === 'cancelled') { r.state = 'cancel'; patchCard(data.module, '已取消', 'err'); }
    return;
  }
  if (name === 'analysis.result') {
    const r = state.results[data.module];
    if (!r) return;
    Object.assign(r, data);
    r.state = data.ok ? 'ok' : 'err';
    patchCard(data.module, data.ok ? (data.elapsed + ' ms') : (data.code || '不支持'), data.ok ? 'ok' : 'err');

    if (data.ok) {
      state.evidence.push({
        module: data.module, title: data.title, group: data.group,
        json: data.json, evidenceFile: data.evidenceFile, size: data.size, elapsed: data.elapsed
      });
      renderEvidenceList();
    }
    const done = Object.values(state.results).filter(x => x.state === 'ok' || x.state === 'err' || x.state === 'cancel').length;
    const total = Object.keys(state.results).length || 1;
    $('#progressFill').style.width = Math.round(done * 100 / total) + '%';
    return;
  }
  if (name === 'analysis.done') {
    state.running = false;
    $('#btnRun').disabled = false;
    $('#btnCancel').classList.add('hidden');
    $('#progressFill').style.width = '100%';
    const ok = Object.values(state.results).filter(x => x.state === 'ok').length;
    const bad = Object.values(state.results).filter(x => x.state === 'err').length;
    toast(`分析完成：成功 ${ok} 项${bad ? '，不可用 ' + bad + ' 项' : ''}`);
    setTimeout(() => $('#progressWrap').classList.add('hidden'), 900);
    return;
  }
  if (name === 'virus.begin') {
    state.virus = null;
    $('#virusCard').classList.remove('hidden');
    const badge = $('#virusVerdict');
    badge.className = 'vbadge';
    badge.textContent = '检测中';
    $('#virusKv').innerHTML = '<div class="k">状态</div><div class="v">正在沙箱内比对病毒库…</div>';
    $('#virusHits').innerHTML = '';
    return;
  }
  if (name === 'virus.result') { state.virus = data; renderVirus(data); return; }
  if (name === 'vuln.begin') {
    state.vuln = null;
    $('#vulnCard').classList.remove('hidden');
    const vb = $('#vulnVerdict');
    vb.className = 'vbadge';
    vb.textContent = '检测中';
    $('#vulnKv').innerHTML = '<div class="k">状态</div><div class="v">正在沙箱内比对 CVE 漏洞库…</div>';
    $('#vulnHits').innerHTML = '';
    return;
  }
  if (name === 'vuln.result') { state.vuln = data; renderVuln(data); return; }
  if (name === 'ai.log') {
    toast(data, 2200);
    if (/未找到本地模型|模型文件（GGUF）/.test(String(data || ''))) {
      setTimeout(() => { navigate('settings'); toast('未检测到本地模型，请在「推理服务 · 本地模型」中下载', 4200); }, 600);
    }
    return;
  }
}

function renderVirus(v) {
  const card = $('#virusCard');
  if (!card || !v) return;
  card.classList.remove('hidden');
  const badge = $('#virusVerdict');
  const cls = !v.ok ? 'bad' : (v.score >= 60 ? 'bad' : v.matches && v.matches.length ? 'warn' : 'clean');
  badge.className = 'vbadge ' + cls;
  badge.textContent = v.ok ? (v.verdict + ' · 评分 ' + v.score) : '检测失败';

  const rows = [];
  rows.push(['检测结论', '<b>' + esc(v.verdict || '—') + '</b>']);
  rows.push(['风险统计', '高危 ' + (v.high || 0) + ' / 中危 ' + (v.medium || 0) + ' / 低危 ' + (v.low || 0)]);
  if (v.sha256) rows.push(['SHA-256', esc(v.sha256)]);
  if (v.md5) rows.push(['MD5', esc(v.md5)]);
  if (v.peInfo) rows.push(['结构特征', esc(v.peInfo)]);
  rows.push(['病毒库', esc(v.dbVersion || '—') + '（规则 ' + (v.ruleCount || 0) + ' 条 / 样本哈希 ' + (v.hashCount || 0) + ' 条）']);
  rows.push(['熵值', (v.entropy || 0).toFixed(2) + '　耗时 ' + (v.elapsedMs || 0) + ' ms']);
  rows.push(['检测位置', (v.inSandbox ? '沙箱副本　' : '') + esc(v.scanPath || '—')]);
  if (v.summary) rows.push(['判定说明', esc(v.summary)]);
  if (!v.ok && v.error) rows.push(['错误', esc(v.error)]);
  $('#virusKv').innerHTML = rows.map(r => '<div class="k">' + r[0] + '</div><div class="v">' + r[1] + '</div>').join('');

  const hits = v.matches || [];
  const box = $('#virusHits');
  if (!hits.length) {
    box.innerHTML = '<div class="ev-empty">与当前病毒库无任何匹配（内置规则 ' + (v.ruleCount || 0) + ' 条已全部比对）</div>';
    return;
  }
  box.innerHTML = '<table><thead><tr><th>等级</th><th>检测名称</th><th>家族 / 类型</th><th>来源</th><th>命中位置</th><th>说明</th></tr></thead><tbody>'
    + hits.slice(0, 80).map(m => '<tr class="' + (m.severity === '高' ? 's-high' : m.severity === '中' ? 's-mid' : '') + '">'
      + '<td>' + esc(m.severity || '') + '</td><td>' + esc(m.name || '') + '</td><td>'
      + esc((m.family || '') + (m.type ? ' / ' + m.type : '')) + '</td><td>'
      + esc((m.source || '') + (m.ruleId ? ' ' + m.ruleId : '')) + '</td><td>' + esc(m.match || '') + '</td><td>'
      + esc(m.desc || '') + '</td></tr>').join('') + '</tbody></table>';
}

function patchCard(id, metaText, cls) {
  const card = document.querySelector(`.rescard[data-card="${id}"]`);
  if (!card) return;
  const iconBox = card.querySelector('.resicon');
  iconBox.className = 'resicon ' + (cls || '');
  if (cls === 'run') iconBox.innerHTML = '<span class="spin"></span>';
  else if (cls === 'ok') iconBox.innerHTML = '<span class="icon">&#xE73E;</span>';
  else if (cls === 'err') iconBox.innerHTML = '<span class="icon">&#xE711;</span>';
  const meta = card.querySelector('[data-meta]');
  if (meta) meta.textContent = metaText;
  const body = card.querySelector('[data-body]');
  if (body) { body.dataset.filled = '0'; body.innerHTML = ''; }
}

/* ---------- 证据 ---------- */
function renderEvidenceList() {
  const box = $('#evList');
  if (!state.evidence.length) { box.innerHTML = '<div class="ev-empty">暂无证据</div>'; return; }
  box.innerHTML = state.evidence.map((e, i) => `
    <div class="ev-item ${state.activeEvidence === i ? 'active' : ''}" data-ev="${i}">
      <div>${esc(e.title)}</div>
      <div class="evsub">${esc(e.group)} · ${humanSize(e.size)} · ${e.elapsed} ms</div>
    </div>`).join('');
  $$('[data-ev]').forEach(el => el.onclick = () => showEvidence(Number(el.dataset.ev)));
}

async function showEvidence(i) {
  const e = state.evidence[i];
  if (!e) return;
  state.activeEvidence = i;
  renderEvidenceList();
  $('#evTitle').textContent = e.title + ' — ' + (e.module || '');
  const body = $('#evBody');
  body.innerHTML = '<div class="junk">读取中…</div>';
  let text = e.json;
  if (!text && e.evidenceFile) {
    try { const res = await invoke('evidence.peek', { path: e.evidenceFile, maxChars: 400000 }); text = res.text; }
    catch (err) { body.innerHTML = `<div class="errbox">${esc(err.message)}</div>`; return; }
  }
  let parsed;
  try { parsed = JSON.parse(text); } catch { body.innerHTML = `<div class="jtree">${esc((text || '').slice(0, 40000))}</div>`; return; }
  body.innerHTML = '';
  const tree = document.createElement('div');
  tree.className = 'jtree';
  tree.appendChild(buildNode(parsed, 0, ''));
  body.appendChild(tree);
}

$('#btnEvCopy').onclick = async () => {
  const e = state.evidence[state.activeEvidence];
  if (!e) { toast('请先选择证据'); return; }
  const text = e.json || '';
  try { await navigator.clipboard.writeText(text); toast('已复制到剪贴板'); }
  catch { toast('复制失败'); }
};
$('#btnEvRaw').onclick = () => {
  const e = state.evidence[state.activeEvidence];
  if (!e) { toast('请先选择证据'); return; }
  const body = $('#evBody');
  body.innerHTML = `<pre class="jtree" style="white-space:pre-wrap">${esc((e.json || '').slice(0, 200000))}</pre>`;
};
const btnRevealEl = $('#btnReveal');
if (btnRevealEl) {
  btnRevealEl.onclick = async () => {
    const dir = (state.status && (state.status.evidenceDir || state.status.runtimeRoot)) || '';
    if (!dir) { toast('目录尚未就绪'); return; }
    try { await invoke('shell.reveal', { path: dir }); } catch (e) { toast(e.message); }
  };
}
$('#btnEvFolder').onclick = async () => {
  if (!state.status) return;
  try { await invoke('shell.reveal', { path: state.status.evidenceDir }); } catch (e) { toast(e.message); }
};
$('#evSearch').oninput = () => {
  const q = $('#evSearch').value.trim().toLowerCase();
  const marks = $$('#evBody .jrow');
  if (!q) { marks.forEach(m => m.style.background = ''); return; }
  marks.forEach(m => {
    m.style.background = m.textContent.toLowerCase().includes(q) ? 'rgba(252,225,0,.14)' : '';
  });
};

/* ---------- AI ---------- */
function renderAiState() {
  const ai = (state.status && state.status.ai) || {};
  const pill = $('#aiState');
  const txt = $('#aiStateText');
  if (!ai.engine) { pill.querySelector('.dot').className = 'dot err'; txt.textContent = '未内置推理引擎'; return; }
  if (ai.localRunning) { pill.querySelector('.dot').className = 'dot ok'; txt.textContent = '本地模型运行中'; return; }
  pill.querySelector('.dot').className = 'dot warn';
  txt.textContent = ai.mode === 'cloud' ? '云端模式' : (ai.model ? '本地模型待启动' : '未配置模型');
}

$('#btnAiStart').onclick = async () => {
  toast('正在启动本地推理服务…', 6000);
  try {
    const r = await invoke('ai.start');
    if (r && r.ok) toast('本地模型已就绪'); else toast('启动失败，请在设置中检查模型与引擎');
    state.status.ai = r.status;
    renderAiState();
  } catch (e) { toast(e.message); }
};

$('#btnSend').onclick = sendChat;
$('#chatInput').addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendChat(); }
});
$$('.chip').forEach(c => c.onclick = () => { $('#chatInput').value = c.dataset.q; sendChat(); });

function addBubble(role, text) {
  const div = document.createElement('div');
  div.className = 'chatmsg ' + (role === 'user' ? 'me' : 'ai');
  div.innerHTML = `<div class="avatar">${role === 'user' ? 'ME' : 'AI'}</div><div class="bubblewrap"><div class="bubble">${esc(text)}</div></div>`;
  $('#chat').appendChild(div);
  $('#chat').scrollTop = $('#chat').scrollHeight;
  return div.querySelector('.bubble');
}

/* 流式输出：气泡下方的实时 token 统计（Prefill 预填 / Decode 生成） */
function chatMetaEl(bubble) {
  const wrap = bubble.parentElement;
  let m = wrap.querySelector('.bubmeta');
  if (!m) { m = document.createElement('div'); m.className = 'bubmeta'; wrap.appendChild(m); }
  return m;
}

function fmtSec(ms) {
  const s = Math.max(0, Number(ms) || 0) / 1000;
  if (s >= 60) return (s / 60).toFixed(2) + ' min';
  return s.toFixed(2) + ' s';
}

function fmtTps(v) {
  const n = Number(v) || 0;
  if (n >= 1000) return (n / 1000).toFixed(2) + 'k';
  return n.toFixed(1);
}

function renderChatMeta(meta, st) {
  if (!meta) return;
  const o = st || {};
  const pt = Number(o.promptTokens) || 0;
  const ct2 = Number(o.completionTokens) || 0;
  meta.classList.add('on');
  meta.innerHTML =
    '<div class="mrow"><span class="mk">Prefill</span>' +
      '<span class="mv">' + fmtSec(o.prefillMs) + '</span>' +
      '<span class="mv">' + pt + ' tok</span>' +
      '<span class="mv">' + fmtTps(o.prefillTps) + ' tok/s</span></div>' +
    '<div class="mrow"><span class="mk">Decode</span>' +
      '<span class="mv">' + fmtSec(o.decodeMs) + '</span>' +
      '<span class="mv">' + ct2 + ' tok</span>' +
      '<span class="mv">' + fmtTps(o.decodeTps) + ' tok/s</span></div>';
}

function autoScrollChat() {
  const chat = $('#chat');
  if (!chat) return;
  // 用户上滑查看历史时不打断阅读，仅在贴近底部时跟随
  if (chat.scrollHeight - chat.scrollTop - chat.clientHeight < 120) chat.scrollTop = chat.scrollHeight;
}

function buildContext() {
  const parts = [];
  if (state.target) parts.push('目标文件: ' + state.target.name + ' (' + state.target.path + ', ' + humanSize(state.target.size) + ')');
  const ok = Object.values(state.results).filter(r => r.state === 'ok');
  if (ok.length) {
    let budget = 7000;
    ok.forEach(r => {
      const txt = compactEvidence(r.json || '', 900);
      if (!txt || budget <= 200) return;
      const use = txt.slice(0, budget);
      budget -= use.length;
      const sec = r.elapsed ? ' ' + Math.max(1, Math.round(r.elapsed / 1000)) + 's' : '';
      parts.push('\n[' + r.title + sec + '] ' + use);
    });
  }
  const sitePart = siteContext();
  if (sitePart) parts.push(sitePart);
  return parts.join('\n').trim();
}

// 站点静态/动态分析证据压成提示词文本，供 AI 解读引用
function siteContext() {
  const out = [];
  const evOf = (src) => state.evidence.filter(e => e.source === src);
  const ss = state.siteStatic;
  if (ss && ss.ok) {
    const sm = ss.summary || {};
    out.push('\n[站点静态分析] 地址=' + (sm.finalUrl || ss.url || '') + ' 状态=' + (sm.status || 0)
      + ' 协议=' + (sm.isHttps ? 'HTTPS' : 'HTTP') + ' 页面字节=' + (sm.htmlBytes || 0)
      + ' 同源脚本=' + (sm.jsFiles || 0) + ' 内联脚本=' + (sm.inlineScripts || 0)
      + ' 接口端点=' + (sm.apiEndpoints || 0) + ' 敏感命中=' + (sm.secrets || 0)
      + ' 外部域=' + (sm.externalHosts || 0) + ' 缺失安全头=' + (sm.missingHeaders || 0)
      + ' 不安全Cookie=' + (sm.unsafeCookies || 0) + ' 表单=' + (sm.forms || 0));
    if (asList(sm.tech).length) out.push('  技术栈: ' + asList(sm.tech).join('、'));
    if (asList(sm.signals).length) out.push('  站点信号: ' + asList(sm.signals).join('；'));
    if (sm.verdict) out.push('  静态结论: ' + sm.verdict);
    evOf('site-static').slice(0, 10).forEach(e => {
      const t = compactEvidence(e.json || '', 700);
      if (t) out.push('  - 证据[' + e.title + ']: ' + t);
    });
  }
  const sd = state.siteDynamic;
  if (sd && sd.ok) {
    const sm = sd.summary || {};
    out.push('\n[站点动态分析] 地址=' + (sm.finalUrl || sd.url || '') + ' 观测秒数=' + (sm.durationSec || sd.durationSec || 0)
      + ' 加载毫秒=' + (sm.loadMs || 0) + ' 请求数=' + (sm.requests || 0)
      + ' 第三方域=' + (sm.thirdPartyHosts || 0) + ' 运行时接口=' + (sm.apiCalls || 0)
      + ' 控制台异常=' + (sm.consoleErrors || 0) + ' Cookie=' + (sm.cookies || 0)
      + ' 存储键=' + (sm.storageKeys || 0) + ' 可疑项=' + (sm.dangerousCount || 0));
    if (asList(sm.tech).length) out.push('  技术栈: ' + asList(sm.tech).join('、'));
    if (asList(sm.signals).length) out.push('  动态信号: ' + asList(sm.signals).join('；'));
    if (sm.verdict) out.push('  动态结论: ' + sm.verdict);
    const conns = (Array.isArray(sd.connections) ? sd.connections : []).filter(c => c.thirdParty).slice(0, 10);
    if (conns.length) out.push('  第三方外联: ' + conns.map(c => c.host + '(' + c.count + ')').join('、'));
    (Array.isArray(sd.apiCalls) ? sd.apiCalls : []).slice(0, 12).forEach(a => out.push('  接口: ' + (a.method || 'GET') + ' ' + a.url + (a.hasCredential ? ' [含凭据]' : '')));
    evOf('site-dynamic').slice(0, 8).forEach(e => {
      const t = compactEvidence(e.json || '', 700);
      if (t) out.push('  - 证据[' + e.title + ']: ' + t);
    });
  }
  return out.join('\n');
}

// 把证据 JSON 压成关键指标文本，控制提示词体积
function compactEvidence(json, maxChars) {
  let obj = null;
  try { obj = JSON.parse(json); } catch (e) { return String(json || '').slice(0, maxChars); }
  const root = (obj && obj.normalized_result) ? obj.normalized_result : obj;
  const out = [];
  const SKIP = { sha256: 1, evidence_id: 1, local_path: 1, limitations: 1, raw_result: 1, blocks: 1 };
  (function walk(v, pre, depth) {
    if (out.length >= 18 || depth > 4) return;
    if (v === null || v === undefined) { if (pre) out.push(pre + '=null'); return; }
    if (Array.isArray(v)) {
      if (!v.length) { if (pre) out.push(pre + '=[]'); return; }
      if (typeof v[0] === 'object' && v[0] !== null) out.push(pre + '=<' + v.length + '项>');
      else out.push(pre + '=[' + v.slice(0, 6).join(', ') + (v.length > 6 ? ' …共' + v.length + '项' : '') + ']');
      return;
    }
    if (typeof v === 'object') {
      const keys = Object.keys(v);
      for (let i = 0; i < keys.length; i++) {
        if (SKIP[keys[i]]) continue;
        walk(v[keys[i]], pre ? pre + '.' + keys[i] : keys[i], depth + 1);
        if (out.length >= 18) return;
      }
      return;
    }
    out.push(pre + '=' + String(v).slice(0, 110));
  })(root, '', 0);
  const s = out.join('; ');
  return s.length > maxChars ? s.slice(0, maxChars) + '…' : s;
}

/* ---------- 九大逆向类型识别 ---------- */
function asList(v) {
  if (!v) return [];
  if (Array.isArray(v)) return v;
  return [String(v)];
}

async function detectTypes() {
  const bar = $('#typeBar');
  if (!state.target) {
    if (bar) bar.innerHTML = '<span class="junk">尚未识别目标类型</span>';
    return;
  }
  if (bar) bar.innerHTML = '<span class="junk">正在识别目标类型…</span>';
  try {
    const list = await invoke('types.detect', { path: state.target.path });
    state.types = list || [];
    renderTypeBar();
  } catch (e) {
    if (bar) bar.innerHTML = '<span class="junk">类型识别失败：' + esc(e.message) + '</span>';
  }
}

function renderTypeBar() {
  const bar = $('#typeBar');
  if (!bar) return;
  if (!state.types.length) { bar.innerHTML = '<span class="junk">未能识别目标类型</span>'; return; }
  bar.innerHTML = state.types.map((t, i) => {
    const ev = asList(t.evidence).join('；');
    const c = String(t.confidence || '').toLowerCase();
    const pct = c === 'high' ? '高' : (c === 'medium' ? '中' : (c === 'low' ? '低' : c));
    return '<span class="typechip ' + (i === 0 ? 'main' : '') + '" title="' + esc(ev) + '">'
      + '<span class="icon">&#xE8A5;</span>' + esc(t.name || t.id)
      + '<span class="conf">置信 ' + esc(pct) + '</span></span>';
  }).join('');
}

/* ---------- 网络分析 ---------- */
const levelCls = (l) => (l === '高' ? 'danger' : (l === '中' ? 'warn' : 'ok'));

async function runNetwork() {
  if (!state.target) { toast('请先选择目标文件'); navigate('target'); return; }
  navigate('network');
  const box = $('#netBody');
  box.innerHTML = '<div class="junk">正在从样本中提取网络情报…</div>';
  try {
    const rep = await invoke('net.analyze', { path: state.target.path });
    state.network = rep;
    renderNetwork(rep, box);
    toast('网络分析完成：危险发包 ' + asList(rep && rep.dangerous).length + ' 个', 3200);
  } catch (e) {
    box.innerHTML = '<div class="errbox">网络分析失败：' + esc(e.message) + '</div>';
  }
}

/* ---------- 动态分析 ---------- */
/* 观测时长：预设值或自定义（秒/分钟/小时），0 表示无限制 */
function dynSecLabel(secs) {
  if (!secs || secs <= 0) return '无限制';
  if (secs >= 3600) return (secs / 3600).toFixed(secs % 3600 === 0 ? 0 : 2).replace(/\.?0+$/, '') + ' 小时';
  if (secs >= 60) return (secs / 60).toFixed(secs % 60 === 0 ? 0 : 2).replace(/\.?0+$/, '') + ' 分钟';
  return secs + ' 秒';
}

function dynSeconds() {
  const sel = $('#dynSec');
  const v = sel ? sel.value : '15';
  if (v !== 'custom') return parseInt(v, 10) || 15;
  const numEl = $('#dynSecNum');
  const unitEl = $('#dynSecUnit');
  const n = Math.max(0, parseInt((numEl && numEl.value) || '0', 10) || 0);
  const mul = parseInt((unitEl && unitEl.value) || '1', 10) || 1;
  return n * mul; // 0 => 无限制
}

function syncDynSecUi() {
  const sel = $('#dynSec');
  const wrap = $('#dynSecCustom');
  if (!sel || !wrap) return;
  wrap.style.display = sel.value === 'custom' ? 'flex' : 'none';
}

async function runDynamic() {
  if (!state.target || !state.target.path) { toast('请先选择目标文件'); navigate('target'); return; }
  if (!/\.(exe|scr|com|dll)$/i.test(state.target.path)) { toast('动态分析仅支持可执行文件（exe / scr / com / dll）'); return; }
  navigate('dynamic');
  const box = $('#dynBody');
  const secs = dynSeconds();
  if (secs > 86400) { toast('单次观测最长 24 小时，请调整时长'); return; }
  state.dynamic = null;
  box.dataset.running = '1';
  box.innerHTML = secs > 0
    ? '<div class="junk">正在受控运行样本，观测 ' + dynSecLabel(secs) + '…期间请勿关闭程序</div>'
    : '<div class="junk">正在受控运行样本，观测时长无限制：样本退出或点击“停止”后结束…</div>';
  $('#btnDynRun').disabled = true;
  $('#btnDynStop').disabled = false;
  try {
    const rep = await invoke('dynamic.run', { path: state.target.path, seconds: secs });
    state.dynamic = rep;
    renderDynamic(rep, box);
    toast('动态分析完成：外联 ' + asList(rep && rep.connections).length + ' 条，新增文件 '
      + asList(rep && rep.files).length + ' 个，高危 ' + ((rep && rep.dangerousCount) || 0) + ' 项', 4000);
  } catch (e) {
    box.innerHTML = '<div class="errbox">动态分析失败：' + esc(e.message) + '</div>';
  } finally {
    box.dataset.running = '0';
    $('#btnDynRun').disabled = false;
    $('#btnDynStop').disabled = true;
  }
}

function renderDynamic(rep, box) {
  if (!rep) { box.innerHTML = '<div class="ev-empty">无动态分析结果</div>'; return; }
  if (!rep.ok) {
    box.innerHTML = '<div class="errbox">动态分析未完成：' + esc(rep.error || '样本未能运行') + '</div>';
    return;
  }
  const procs = asList(rep.processes);
  const conns = asList(rep.connections);
  const files = asList(rep.files);
  const evs = asList(rep.events);

  const head = '<div class="card"><div class="cardhead"><span class="icon">&#xE9D2;</span>动态行为概览</div>'
    + '<div class="netgrid">'
    + '<div class="netstat"><div class="k">观测时长</div><div class="v">' + (rep.unlimited ? '无限制' : dynSecLabel(rep.durationSec || 0)) + '</div></div>'
    + '<div class="netstat"><div class="k">进程数</div><div class="v">' + procs.length + '</div></div>'
    + '<div class="netstat"><div class="k">网络外联</div><div class="v">' + conns.length + '</div></div>'
    + '<div class="netstat"><div class="k">新增文件</div><div class="v">' + files.length + '</div></div>'
    + '<div class="netstat"><div class="k">高危行为</div><div class="v ' + ((rep.dangerousCount || 0) ? 'danger_text' : '') + '">' + (rep.dangerousCount || 0) + '</div></div>'
    + '<div class="netstat"><div class="k">SHA-256</div><div class="v mono">' + esc((rep.sha256 || '').slice(0, 16)) + '…</div></div>'
    + '</div>'
    + (rep.verdict ? '<div class="verdict">' + esc(rep.verdict) + '</div>' : '')
    + '</div>';

  const connCard = '<div class="card"><div class="cardhead"><span class="icon">&#xE774;</span>网络外联</div>'
    + (conns.length === 0 ? '<div class="junk">运行窗口内未捕获到网络连接</div>' : '<table class="nettable"><thead><tr><th>时刻</th><th>协议</th><th>远端</th><th>进程</th><th>研判</th></tr></thead><tbody>'
      + conns.slice(0, 150).map(c => '<tr>'
        + '<td class="mono">' + esc(c.time || '') + '</td>'
        + '<td>' + esc(c.proto || '') + '</td>'
        + '<td class="mono">' + esc(c.remote || '') + '</td>'
        + '<td>' + esc(c.process || '') + '</td>'
        + '<td>' + (c.dangerous ? '<span class="nbadge danger_bg">' + esc(c.note || '敏感') + '</span>' : esc(c.note || '—')) + '</td>'
        + '</tr>').join('') + '</tbody></table>') + '</div>';

  const procCard = '<div class="card"><div class="cardhead"><span class="icon">&#xE7F4;</span>进程树</div>'
    + (procs.length === 0 ? '<div class="junk">未捕获到子进程</div>' : '<table class="nettable"><thead><tr><th>PID</th><th>进程</th><th>首见</th><th>文件路径</th></tr></thead><tbody>'
      + procs.slice(0, 80).map(p => '<tr>'
        + '<td class="mono">' + p.pid + '</td>'
        + '<td>' + esc(p.name || '') + '</td>'
        + '<td class="mono">' + esc(p.firstSeen || '') + '</td>'
        + '<td class="mono">' + esc(p.filePath || '') + '</td>'
        + '</tr>').join('') + '</tbody></table>') + '</div>';

  const fileCard = '<div class="card"><div class="cardhead"><span class="icon">&#xE8B7;</span>落盘与自启动</div>'
    + (files.length === 0 ? '<div class="junk">未在监控目录发现新增文件</div>' : '<table class="nettable"><thead><tr><th>时刻</th><th>类型</th><th>路径</th></tr></thead><tbody>'
      + files.slice(0, 120).map(f => '<tr>'
        + '<td class="mono">' + esc(f.time || '') + '</td>'
        + '<td>' + esc(f.kind || '—') + '</td>'
        + '<td class="mono">' + esc(f.path || '') + '</td>'
        + '</tr>').join('') + '</tbody></table>') + '</div>';

  const evCard = '<div class="card"><div class="cardhead"><span class="icon">&#xE81C;</span>行为时间线</div>'
    + (evs.length === 0 ? '<div class="junk">无事件</div>' : '<div class="timeline">'
      + evs.slice(0, 200).map(e => '<div class="tlrow' + (e.dangerous ? ' tldanger' : '') + '">'
        + '<span class="tlwrap"><span class="tltime mono">' + esc(e.time || '') + '</span>'
        + '<span class="tlkind">' + esc(e.kind || '') + '</span>'
        + '<span class="tltitle">' + esc(e.title || '') + '</span></span>'
        + (e.detail ? '<span class="tldetail mono">' + esc(e.detail) + '</span>' : '')
        + '</div>').join('') + '</div>') + '</div>';

  const notes = asList(rep.notes);
  const noteCard = notes.length
    ? '<div class="card"><div class="cardhead"><span class="icon">&#xE946;</span>采集说明</div><div class="junk">'
      + notes.map(n => '· ' + esc(n)).join('<br>') + '</div></div>'
    : '';

  box.innerHTML = head + connCard + procCard + fileCard + evCard + noteCard;
}

function netSummary(rep) {
  const dang = asList(rep.dangerous);
  return '<div class="card"><div class="cardhead"><span class="icon">&#xE9D9;</span>流量概览</div>'
    + '<div class="netgrid">'
    + '<div class="netstat"><div class="k">样本</div><div class="v mono">' + esc(rep.target || '') + '</div></div>'
    + '<div class="netstat"><div class="k">提取字符串</div><div class="v">' + (rep.strings || 0) + '</div></div>'
    + '<div class="netstat"><div class="k">URL 端点</div><div class="v">' + (rep.urlCount || 0) + '</div></div>'
    + '<div class="netstat"><div class="k">裸 IP 直连</div><div class="v">' + (rep.ipCount || 0) + '</div></div>'
    + '<div class="netstat"><div class="k">明文 HTTP 占比</div><div class="v">' + esc(rep.plainHttpShare || '—') + '</div></div>'
    + '<div class="netstat"><div class="k">危险发包</div><div class="v ' + (dang.length ? 'danger_text' : '') + '">' + dang.length + '</div></div>'
    + '</div>'
    + (rep.verdict ? '<div class="verdict">' + esc(rep.verdict) + '</div>' : '')
    + '</div>';
}

function epTable(list, emptyText) {
  const eps = asList(list);
  if (!eps.length) return '<div class="junk">' + emptyText + '</div>';
  const rows = eps.slice(0, 120).map(e => '<tr>'
    + '<td class="mono">' + esc(e.scheme ? (e.scheme + '://' + e.host + (e.port ? ':' + e.port : '')) : e.host) + '</td>'
    + '<td>' + esc(e.direction || '') + '</td>'
    + '<td>' + (e.hits || 0) + '</td>'
    + '<td><span class="nbadge ' + levelCls(e.level) + '">' + esc(e.level || '低') + '</span></td>'
    + '<td class="mono">' + esc(asList(e.paths).slice(0, 3).join(' , ')) + '</td>'
    + '<td>' + esc(asList(e.reasons).join('；')) + '</td>'
    + '<td class="mono">' + esc(asList(e.fields).slice(0, 8).join(', ')) + '</td>'
    + '</tr>').join('');
  return '<table class="nettable"><thead><tr><th>主机</th><th>方向</th><th>命中</th><th>等级</th><th>路径</th><th>判定理由</th><th>关联字段</th></tr></thead><tbody>'
    + rows + '</tbody></table>';
}

function privacyTable(list) {
  const ps = asList(list);
  if (!ps.length) return '<div class="junk">未发现敏感隐私字段</div>';
  const rows = ps.map(x => '<tr>'
    + '<td>' + esc(x.category || '') + '</td>'
    + '<td class="mono">' + esc(x.key || '') + '</td>'
    + '<td>' + esc(x.meaning || '') + '</td>'
    + '<td><span class="nbadge ' + levelCls(x.risk) + '">' + esc(x.risk || '中') + '</span></td>'
    + '<td>' + (x.hits || 0) + '</td>'
    + '<td class="mono">' + esc(asList(x.samples).slice(0, 3).join(' | ')) + '</td>'
    + '</tr>').join('');
  return '<table class="nettable"><thead><tr><th>类别</th><th>字段键</th><th>含义</th><th>风险</th><th>命中</th><th>样例</th></tr></thead><tbody>'
    + rows + '</tbody></table>';
}

function packetList(list) {
  const ps = asList(list);
  if (!ps.length) return '<div class="junk">未还原出数据包结构</div>';
  return ps.map(p => {
    const head = (p.method || 'POST') + ' ' + (p.target || '') + (p.kind ? ' · ' + p.kind : '')
      + (asList(p.reasons).length ? ' · ' + asList(p.reasons).join('；') : '');
    return '<details class="pkt"><summary>' + esc(head) + '</summary>'
      + '<pre>' + esc(p.content || '') + '</pre></details>';
  }).join('');
}

function renderNetwork(rep, box) {
  if (!rep || rep.ok === false) {
    box.innerHTML = '<div class="errbox">网络分析失败：' + esc((rep && rep.error) || '未知原因') + '</div>';
    return;
  }
  box.innerHTML = netSummary(rep)
    + '<div class="netsec"><div class="card"><div class="cardhead"><span class="icon">&#xE711;</span>危险发包 · 命中 ' + (rep.totalDangerous || asList(rep.dangerous).length) + ' 个</div>'
    + epTable(rep.dangerous, '未发现高危外发端点') + '</div></div>'
    + '<div class="netsec"><div class="card"><div class="cardhead"><span class="icon">&#xE774;</span>流量指向 · 共 ' + (rep.totalEndpoints || asList(rep.endpoints).length) + ' 个，展示前 ' + asList(rep.endpoints).length + ' 个</div>'
    + epTable(rep.endpoints, '未提取到 URL 或 IP 端点') + '</div></div>'
    + '<div class="netsec"><div class="card"><div class="cardhead"><span class="icon">&#xE8BD;</span>隐私信息面</div>'
    + privacyTable(rep.privacy) + '</div></div>'
    + '<div class="netsec"><div class="card"><div class="cardhead"><span class="icon">&#xE71D;</span>数据包内容（还原的请求结构）</div>'
    + packetList(rep.packets) + '</div></div>'
    + (asList(rep.services).length
      ? '<div class="netsec"><div class="card"><div class="cardhead"><span class="icon">&#xE946;</span>识别到的服务</div><div class="junk">'
        + esc(asList(rep.services).join(' · ')) + '</div></div></div>' : '');
}

/* ---------- 网站逆向 ---------- */
async function runWebRecon() {
  const input = $('#siteUrl');
  const url = ((input && input.value) || '').trim();
  if (!url) { toast('请输入要逆向的网址'); if (input) input.focus(); return; }
  navigate('network');
  const box = $('#netBody');
  box.innerHTML = '<div class="junk">正在抓取站点静态资源…</div>';
  try {
    const rep = await invoke('web.recon', { url });
    state.site = rep;
    if (!rep || !rep.ok) {
      box.innerHTML = '<div class="errbox">站点抓取失败：' + esc((rep && rep.error) || '未知原因') + '</div>';
      return;
    }
    box.innerHTML = '<div class="card"><div class="cardhead"><span class="icon">&#xE774;</span>站点概览</div>'
      + '<div class="netgrid">'
      + '<div class="netstat"><div class="k">目标</div><div class="v mono">' + esc(rep.finalUrl || rep.url) + '</div></div>'
      + '<div class="netstat"><div class="k">HTTP 状态</div><div class="v">' + (rep.status || 0) + '</div></div>'
      + '<div class="netstat"><div class="k">协议</div><div class="v">' + (rep.isHttps ? 'HTTPS' : 'HTTP（明文）') + '</div></div>'
      + '<div class="netstat"><div class="k">页面标题</div><div class="v">' + esc(rep.title || '—') + '</div></div>'
      + '<div class="netstat"><div class="k">页面大小</div><div class="v">' + humanSize(rep.htmlBytes || 0) + '</div></div>'
      + '<div class="netstat"><div class="k">外部域</div><div class="v">' + asList(rep.externalHosts).length + '</div></div>'
      + '</div>'
      + (rep.description ? '<div class="verdict">' + esc(rep.description) + '</div>' : '')
      + (rep.verdict ? '<div class="verdict">' + esc(rep.verdict) + '</div>' : '')
      + '</div>'
      + '<div class="netsec"><div class="card"><div class="cardhead"><span class="icon">&#xE71D;</span>风险信号</div><div class="junk">'
      + (asList(rep.signals).length ? esc(asList(rep.signals).join('；')) : '无') + '</div></div></div>'
      + '<div class="netsec"><div class="card"><div class="cardhead"><span class="icon">&#xE943;</span>外链脚本（' + asList(rep.scripts).length + '）</div><div class="junk mono" style="word-break:break-all">'
      + esc(asList(rep.scripts).slice(0, 40).join('\n')) + '</div></div></div>'
      + '<div class="netsec"><div class="card"><div class="cardhead"><span class="icon">&#xE774;</span>外部域列表</div><div class="junk mono" style="word-break:break-all">'
      + esc(asList(rep.externalHosts).join(' · ')) + '</div></div></div>'
      + '<div class="netsec"><div class="card"><div class="cardhead"><span class="icon">&#xE8BD;</span>表单与提交面</div><div class="junk">'
      + (asList(rep.forms).length ? esc(asList(rep.forms).join('；')) : '页面未发现显式表单') + '</div></div></div>';
    if (rep.network) {
      const holder = document.createElement('div');
      holder.className = 'netsec';
      box.appendChild(holder);
      renderNetwork(rep.network, holder);
    }
    toast('站点逆向完成：外部域 ' + asList(rep.externalHosts).length + ' 个', 3400);
  } catch (e) {
    box.innerHTML = '<div class="errbox">站点逆向失败：' + esc(e.message) + '</div>';
  }
}

/* ---------- 站点独立静态 / 动态分析 ---------- */
function siteUrlValue() {
  const input = $('#siteUrl');
  const url = ((input && input.value) || '').trim();
  if (!url) { toast('请输入要分析的网址'); if (input) input.focus(); }
  return url;
}

// 把站点分析的证据并入统一证据流，按来源去重，供证据页与 AI 解读使用
function siteEvidenceIngest(rep, mode) {
  const group = mode === 'site-dynamic' ? '站点动态' : '站点静态';
  const items = (rep.evidence || []).map(e => ({
    module: e.module, title: e.title, group: e.group || group,
    size: e.size || 0, elapsed: e.elapsed || 0,
    json: typeof e.json === 'string' ? e.json : JSON.stringify(e.json || null),
    evidenceFile: e.evidenceFile || '',
    source: mode
  }));
  state.evidence = state.evidence.filter(e => e.source !== mode).concat(items);
  state.activeEvidence = null;
  renderEvidenceList();
  return items.length;
}

function siteStaticHtml(rep) {
  const sm = rep.summary || {};
  const tech = asList(sm.tech), signals = asList(sm.signals);
  const ev = Array.isArray(rep.evidence) ? rep.evidence : [];
  return '<div class="card"><div class="cardhead"><span class="icon">&#xE9D9;</span>站点静态分析结论</div>'
    + '<div class="netgrid">'
    + '<div class="netstat"><div class="k">目标地址</div><div class="v mono">' + esc(sm.finalUrl || rep.finalUrl || rep.url || '') + '</div></div>'
    + '<div class="netstat"><div class="k">HTTP 状态</div><div class="v">' + (sm.status || 0) + '</div></div>'
    + '<div class="netstat"><div class="k">协议</div><div class="v">' + (sm.isHttps ? 'HTTPS' : 'HTTP（明文）') + '</div></div>'
    + '<div class="netstat"><div class="k">页面大小</div><div class="v">' + humanSize(sm.htmlBytes || 0) + '</div></div>'
    + '<div class="netstat"><div class="k">同源脚本</div><div class="v">' + (sm.jsFiles || 0) + ' / ' + humanSize(sm.jsBytes || 0) + '</div></div>'
    + '<div class="netstat"><div class="k">内联脚本</div><div class="v">' + (sm.inlineScripts || 0) + '</div></div>'
    + '<div class="netstat"><div class="k">接口端点</div><div class="v">' + (sm.apiEndpoints || 0) + '</div></div>'
    + '<div class="netstat"><div class="k">敏感信息命中</div><div class="v">' + (sm.secrets || 0) + '</div></div>'
    + '<div class="netstat"><div class="k">外部域</div><div class="v">' + (sm.externalHosts || 0) + '</div></div>'
    + '<div class="netstat"><div class="k">缺失安全头</div><div class="v">' + (sm.missingHeaders || 0) + '</div></div>'
    + '<div class="netstat"><div class="k">不安全 Cookie</div><div class="v">' + (sm.unsafeCookies || 0) + '</div></div>'
    + '<div class="netstat"><div class="k">表单数</div><div class="v">' + (sm.forms || 0) + '</div></div>'
    + '</div>'
    + (sm.verdict ? '<div class="verdict">' + esc(sm.verdict) + '</div>' : '')
    + '</div>'
    + '<div class="netsec"><div class="card"><div class="cardhead"><span class="icon">&#xE71D;</span>技术指纹</div><div class="junk">'
    + (tech.length ? esc(tech.join('；')) : '未识别到明确技术栈') + '</div></div></div>'
    + '<div class="netsec"><div class="card"><div class="cardhead"><span class="icon">&#xE71D;</span>风险与合规信号</div><div class="junk">'
    + (signals.length ? esc(signals.join('；')) : '无') + '</div></div></div>'
    + '<div class="netsec"><div class="card"><div class="cardhead"><span class="icon">&#xE8A5;</span>结构化证据（' + ev.length + ' 项，已写入证据页）</div><div class="junk">'
    + (ev.length ? esc(ev.map(e => (e.title || e.module || '') + ' · ' + humanSize(e.size || 0)).join('\n')) : '无')
    + '</div></div></div>'
    + '<div class="netsec"><div class="hint">静态分析不执行页面脚本；动态行为请用「站点动态分析」在内置内核中实测。</div></div>';
}

function siteDynamicHtml(rep) {
  const sm = rep.summary || {};
  const conns = Array.isArray(rep.connections) ? rep.connections : [];
  const apis = Array.isArray(rep.apiCalls) ? rep.apiCalls : [];
  const errs = (Array.isArray(rep.console) ? rep.console : []).filter(c => (c.level || '') === 'error');
  const tech = asList(sm.tech), signals = asList(sm.signals);
  const ev = Array.isArray(rep.evidence) ? rep.evidence : [];
  const third = conns.filter(c => c.thirdParty);
  const plain = conns.filter(c => c.plainHttp);
  const credApis = apis.filter(a => a.hasCredential);
  return '<div class="card"><div class="cardhead"><span class="icon">&#xE768;</span>站点动态分析结论（观测 ' + (sm.durationSec || rep.durationSec || 0) + ' 秒）</div>'
    + '<div class="netgrid">'
    + '<div class="netstat"><div class="k">加载地址</div><div class="v mono">' + esc(sm.finalUrl || rep.finalUrl || rep.url || '') + '</div></div>'
    + '<div class="netstat"><div class="k">页面标题</div><div class="v">' + esc(sm.title || rep.title || '—') + '</div></div>'
    + '<div class="netstat"><div class="k">加载耗时</div><div class="v">' + (sm.loadMs || 0) + ' ms</div></div>'
    + '<div class="netstat"><div class="k">网络请求</div><div class="v">' + (sm.requests || 0) + '</div></div>'
    + '<div class="netstat"><div class="k">第三方域</div><div class="v">' + (sm.thirdPartyHosts || 0) + '</div></div>'
    + '<div class="netstat"><div class="k">运行时接口</div><div class="v">' + (sm.apiCalls || 0) + '</div></div>'
    + '<div class="netstat"><div class="k">控制台异常</div><div class="v">' + (sm.consoleErrors || 0) + '</div></div>'
    + '<div class="netstat"><div class="k">Cookie / 存储键</div><div class="v">' + (sm.cookies || 0) + ' / ' + (sm.storageKeys || 0) + '</div></div>'
    + '<div class="netstat"><div class="k">可疑项</div><div class="v">' + (sm.dangerousCount || 0) + '</div></div>'
    + '<div class="netstat"><div class="k">传输量</div><div class="v">' + humanSize(sm.transferBytes || 0) + '</div></div>'
    + '</div>'
    + (sm.verdict ? '<div class="verdict">' + esc(sm.verdict) + '</div>' : '')
    + '</div>'
    + '<div class="netsec"><div class="card"><div class="cardhead"><span class="icon">&#xE71D;</span>技术指纹</div><div class="junk">'
    + (tech.length ? esc(tech.join('；')) : '未识别') + '</div></div></div>'
    + '<div class="netsec"><div class="card"><div class="cardhead"><span class="icon">&#xE71D;</span>风险信号</div><div class="junk">'
    + (signals.length ? esc(signals.join('；')) : '无') + '</div></div></div>'
    + '<div class="netsec"><div class="card"><div class="cardhead"><span class="icon">&#xE943;</span>运行时接口调用（' + apis.length + (credApis.length ? '，含凭据 ' + credApis.length : '') + '）</div><div class="junk mono" style="word-break:break-all">'
    + esc(apis.slice(0, 40).map(a => (a.method || 'GET') + ' ' + (a.url || '') + (a.via ? ' [' + a.via + ']' : '')).join('\n') || '未捕获到脚本接口调用') + '</div></div></div>'
    + '<div class="netsec"><div class="card"><div class="cardhead"><span class="icon">&#xE774;</span>外联主机（' + conns.length + '，第三方 ' + third.length + '，明文 ' + plain.length + '）</div><div class="junk mono" style="word-break:break-all">'
    + esc(conns.slice(0, 30).map(c => (c.thirdParty ? '[三方] ' : '') + (c.plainHttp ? '[HTTP] ' : '') + (c.host || '') + ' · ' + (c.count || 0) + ' 次').join('\n') || '无外联记录') + '</div></div></div>'
    + '<div class="netsec"><div class="card"><div class="cardhead"><span class="icon">&#xE7BA;</span>控制台异常（' + errs.length + '）</div><div class="junk mono">'
    + esc(errs.slice(0, 15).map(c => c.text || '').join('\n') || '无') + '</div></div></div>'
    + '<div class="netsec"><div class="card"><div class="cardhead"><span class="icon">&#xE8A5;</span>结构化证据（' + ev.length + ' 项，已写入证据页）</div><div class="junk">'
    + (ev.length ? esc(ev.map(e => (e.title || e.module || '') + ' · ' + humanSize(e.size || 0)).join('\n')) : '无')
    + '</div></div></div>';
}

async function runSiteStatic() {
  const url = siteUrlValue();
  if (!url) return;
  const btn = $('#btnSiteStatic');
  navigate('network');
  const box = $('#netBody');
  box.innerHTML = '<div class="junk">正在执行站点静态分析：抓取 HTML 与同源脚本…</div>';
  btn.disabled = true;
  try {
    const rep = await invoke('site.static', { url });
    state.siteStatic = rep;
    if (!rep || !rep.ok) {
      box.innerHTML = '<div class="errbox">站点静态分析失败：' + esc((rep && rep.error) || '未知原因') + '</div>';
      return;
    }
    const n = siteEvidenceIngest(rep, 'site-static');
    box.innerHTML = siteStaticHtml(rep);
    toast('站点静态分析完成：' + n + ' 项证据已写入证据页', 4200);
  } catch (e) {
    box.innerHTML = '<div class="errbox">站点静态分析失败：' + esc(e.message) + '</div>';
  } finally { btn.disabled = false; }
}

async function runSiteDynamic() {
  const url = siteUrlValue();
  if (!url) return;
  const secs = Number($('#siteDynSec') && $('#siteDynSec').value) || 15;
  const btn = $('#btnSiteDynamic'), stop = $('#btnSiteDynStop');
  navigate('network');
  const box = $('#netBody');
  box.innerHTML = '<div class="junk">正在加载 ' + esc(url) + '，观测 ' + secs + ' 秒…</div>';
  btn.disabled = true; stop.disabled = false;
  try {
    const rep = await invoke('site.dynamic', { url, seconds: secs });
    state.siteDynamic = rep;
    if (!rep || !rep.ok) {
      box.innerHTML = '<div class="errbox">站点动态分析失败：' + esc((rep && rep.error) || '未知原因') + '</div>';
      return;
    }
    const n = siteEvidenceIngest(rep, 'site-dynamic');
    box.innerHTML = siteDynamicHtml(rep);
    toast('站点动态分析完成：' + n + ' 项证据已写入证据页', 4200);
  } catch (e) {
    box.innerHTML = '<div class="errbox">站点动态分析失败：' + esc(e.message) + '</div>';
  } finally { btn.disabled = false; stop.disabled = true; }
}

/* ---------- 报告导出 ---------- */
async function exportReport(fmt, scope) {
  fmt = fmt === 'pdf' ? 'pdf' : 'md';
  scope = scope === 'network' ? 'network' : (scope === 'site' ? 'site' : (scope === 'dynamic' ? 'dynamic' : 'static'));

  let items = [], types = [], net = null, site = null, ai = '', dyn = null;
  if (scope === 'dynamic') {
    if (!state.dynamic || !state.dynamic.ok) { toast('还没有动态分析结果，请先运行动态分析'); return; }
    dyn = state.dynamic;
  } else if (scope === 'static') {
    const hasStatic = state.evidence.length || (state.types && state.types.length);
    if (!hasStatic) { toast('还没有静态分析结果，请先完成一次分析'); return; }
    items = state.evidence.map(e => ({
      module: e.module, title: e.title, group: e.group, ok: true,
      elapsed: e.elapsed || 0, evidenceFile: e.evidenceFile || '',
      json: typeof e.json === 'string' ? e.json : JSON.stringify(e.json || null)
    }));
    types = state.types || [];
    ai = state.chat.filter(m => m.role === 'assistant' && m.content).slice(-1).map(m => m.content).join('');
  } else if (scope === 'network') {
    if (!state.network || !state.network.ok) { toast('还没有网络分析结果，请先执行网络分析'); return; }
    net = state.network;
  } else {
    if (!state.site || !state.site.ok) { toast('还没有站点逆向结果，请先逆向或分析一个站点'); return; }
    site = Object.assign({}, state.site, { siteStatic: state.siteStatic || null, siteDynamic: state.siteDynamic || null });
    const siteEv = state.evidence.filter(e => e.source === 'site-static' || e.source === 'site-dynamic');
    if (siteEv.length) {
      items = siteEv.map(e => ({
        module: e.module, title: e.title, group: e.group, ok: true,
        elapsed: e.elapsed || 0, evidenceFile: e.evidenceFile || '',
        json: typeof e.json === 'string' ? e.json : JSON.stringify(e.json || null)
      }));
      ai = state.chat.filter(m => m.role === 'assistant' && m.content).slice(-1).map(m => m.content).join('');
    }
  }

  try {
    toast(fmt === 'pdf' ? '正在生成 PDF 报告…' : '正在生成 Markdown 报告…', 6000);
    const r = await invoke('report.export', {
      path: (state.target && state.target.path) || (site && (site.finalUrl || site.url)) || '',
      items,
      types,
      network: net,
      site,
      dynamic: dyn,
      virus: state.virus || null,
      vuln: state.vuln || null,
      ai,
      format: fmt,
      scope
    });
    toast('报告已保存：' + r.name, 4500);
    invoke('shell.reveal', { path: r.path }).catch(() => {});
  } catch (e) { toast('导出失败：' + e.message, 5000); }
}

async function aiExplain() {
  const hasSite = !!((state.siteStatic && state.siteStatic.ok) || (state.siteDynamic && state.siteDynamic.ok));
  if (!state.evidence.length && !hasSite) { toast('还没有分析证据，请先完成一次分析'); return; }
  const ai = (state.status && state.status.ai) || {};
  if (!ai.localRunning && ai.mode !== 'cloud') {
    toast('正在启动本地模型…', 3000);
    try { await invoke('ai.start', {}); await refreshStatus(); }
    catch (e) { toast('本地模型启动失败：' + e.message); return; }
  }
  navigate('ai');
  const box = $('#chatInput');
  if (hasSite) {
    box.value = '请基于当前站点静态与动态分析证据用中文给出：\n1) 3-6 条站点技术结论（框架/接口结构/鉴权方式/第三方依赖）\n'
      + '2) 数据与接口暴露面风险（敏感信息、明文传输、凭据外发、缺失安全头）\n'
      + '3) 建议的下一步验证动作（按优先级排序，注明需人工确认的点）\n\n【硬性约束】\n'
      + '- 只使用给出的字段与证据值，禁止补充没有的事实，不要臆测站点业务归属\n'
      + '- 静态抓取与动态实测得到的结论需分别注明来源\n'
      + '- 每条结论后用括号标注依据字段名；无字段支撑就写“证据不足”\n'
      + '- 输出控制在 400 字内，不要重复原始指标';
  } else {
    box.value = '请基于当前分析指标用中文给出：\n1) 3-6 条关键技术结论（架构/依赖/加固/可疑点）\n'
    + '2) 风险与暴露面评估\n3) 建议的下一步验证动作\n\n【硬性约束】\n'
    + '- 只使用给出的字段值，禁止补充指标里没有的事实，不要猜测文件用途或恶意性\n'
    + '- 字段直译：architecture=amd64 表示 64 位 x86-64；format=pe32+ 表示 64 位 PE；不要自行推算位数\n'
    + '- 每条结论后用括号标注依据字段名；无字段支撑就写“证据不足”\n'
    + '- 输出控制在 400 字内，不要重复原指标';;
  }
  await sendChat();
}

/* ---------- AI 输出清洗 ----------
   小参数模型在长上下文下容易退化成反复吐 <ref>/<citation> 之类的伪引用标签，
   这些标签既无内容也无意义，还会吃光输出预算。这里按"引用类标签白名单"
   做两层清洗：先删成对标签块，再删残留的孤立标签，最后压缩空行。
   白名单方式可避免误伤 List<int>、<T> 这类泛型/占位符写法。 */
const AI_JUNK_TAG = 'refs?|references?|citations?|cite[sd]?|sources?|evidences?|docs?|documents?|quotes?|contexts?|chunks?|snippets?|think(?:ing)?|analysis|tools?|tool_call|outputs?|results?';

function cleanAiText(t) {
  let s = String(t || '');
  // 1) 成对标签块整段剔除（含内部内容）
  s = s.replace(new RegExp('<\\s*(' + AI_JUNK_TAG + ')\\b[^>]*>[\\s\\S]*?<\\s*\\/\\s*\\1\\s*>', 'gi'), '');
  // 2) 残留的孤立标签 / 自闭合标签
  s = s.replace(new RegExp('<\\s*\\/?\\s*(?:' + AI_JUNK_TAG + ')\\b[^>]*\\/?\\s*>', 'gi'), '');
  // 3) 清理标签删除后留下的空行与行尾空白
  s = s.replace(/[ \t]+\n/g, '\n').replace(/\n{3,}/g, '\n\n').replace(/[ \t]{2,}/g, ' ').trim();
  return s;
}

async function sendChat() {
  const box = $('#chatInput');
  const q = box.value.trim();
  if (!q) return;
  box.value = '';
  addBubble('user', q);

  const ai = (state.status && state.status.ai) || {};
  if (!ai.localRunning && ai.mode !== 'cloud') {
    addBubble('ai', '本地模型尚未运行。请点击右上角“启动本地模型”，或在设置中切换到云端模型后重试。');
    return;
  }

  const bubble = addBubble('ai', '思考中…');
  const meta = chatMetaEl(bubble);
  const t0 = performance.now();
  const sess = { bubble, meta, acc: '', stats: null, timer: null };
  // 首 token 之前本地计时，让 Prefill 段也有实时观感；收到后端统计后改由真实数据接管
  sess.timer = setInterval(() => {
    if (sess.stats) return;
    meta.classList.add('on');
    meta.innerHTML =
      '<div class="mrow"><span class="mk">Prefill</span><span class="mv">' + fmtSec(performance.now() - t0) + '</span><span class="mv">等待首 token…</span></div>'
      + '<div class="mrow"><span class="mk">Decode</span><span class="mv">0.00 s</span><span class="mv">0 tok</span><span class="mv">0.0 tok/s</span></div>';
  }, 120);
  state.chatStream = sess;
  const sys = '你是运行在本地桌面上的逆向分析助手，服务于安全研究人员。基于用户提供的 REA 静态分析证据作答，'
    + '只依据证据推理，不确定时明确说明；输出简洁、分点、面向可执行结论，禁止编造证据中不存在的字段。'
    + '禁止输出任何 XML/HTML 标签，禁止使用 <ref>、<citation>、<source> 之类的引用标记；'
    + '需要指明依据时写成「依据：证据标题」这样的纯文本，不要重复同一句话或同一段落。';

  const ctx = buildContext();
  // Qwen 系列 chat template 要求 system 必须且只能位于首条，证据上下文并入首条 system，禁止再追加第二条
  const sysFull = ctx ? (sys + '\n\n当前分析证据（截断）：\n' + ctx) : sys;
  const messages = [{ role: 'system', content: sysFull }];
  state.chat.slice(-6).forEach(m => messages.push(m));
  messages.push({ role: 'user', content: q });

  try {
    const r = await invoke('ai.chat', { messages });
    const raw = sess.acc || (r && r.content) || '';
    const answer = cleanAiText(raw);
    bubble.textContent = answer || '模型没有产出有效正文（只输出了无效引用标签或占满了输出上限）。请重试，或在“设置 → 最大输出”里调大数值后重新提问。';
    renderChatMeta(meta, (r && r.stats) || sess.stats || {});
    state.chat.push({ role: 'user', content: q });
    state.chat.push({ role: 'assistant', content: answer });
  } catch (e) {
    bubble.textContent = (sess.acc ? sess.acc + '\n\n' : '') + '调用失败：' + e.message;
  } finally {
    clearInterval(sess.timer);
    if (state.chatStream === sess) state.chatStream = null;
  }
  $('#chat').scrollTop = $('#chat').scrollHeight;
}

/* ---------- 设置 ---------- */
async function loadSettings() {
  try {
    const s = await invoke('settings.get');
    state.aiSettings = s;
    $('#setModel').value = s.localModel || '';
    $('#setPort').value = s.localPort || 8791;
    $('#setCtx').value = s.contextSize || 8192;
    if ($('#setMaxTokens')) $('#setMaxTokens').value = s.maxTokens || 2048;
    $('#setBase').value = s.cloudBaseUrl || '';
    $('#setCloudModel').value = s.cloudModel || '';
    $('#setKey').value = s.cloudApiKey || '';
    $$('#aiMode button').forEach(b => b.classList.toggle('on', b.dataset.mode === s.mode));
  } catch (e) { }
}

$$('#aiMode button').forEach(b => b.onclick = () => {
  $$('#aiMode button').forEach(x => x.classList.remove('on'));
  b.classList.add('on');
});

/* ---------- 添加本地 GGUF 模型 ---------- */
$('#btnPickModel').onclick = async () => {
  try {
    const r = await invoke('model.pick');
    if (!r || r.cancelled) return;
    if (!/\.gguf$/i.test(r.path || '')) { toast('请选择 .gguf 格式的模型文件'); return; }
    $('#setModel').value = r.path;
    // 选定即生效：写回设置并立刻刷新状态，不再要求用户额外点「保存设置」
    try {
      const cur = state.aiSettings || await invoke('settings.get');
      const saved = await invoke('settings.set', Object.assign({}, cur, { localModel: r.path }));
      state.aiSettings = saved;
      if (saved && saved.localModel) $('#setModel').value = saved.localModel;
    } catch (e) { toast('保存模型设置失败：' + e.message, 4000); }
    const hint = $('#modelHint');
    if (hint) hint.textContent = '已选择：' + r.name + '（' + r.sizeText + '），已设为当前本地模型。';
    await loadModelStatus();
    toast('已切换本地模型：' + r.name, 3600);
  } catch (e) { toast('选择模型失败：' + e.message, 4000); }
};

/* ---------- 本地模型检测 / 下载 ---------- */
async function loadModelStatus() {
  const dot = $('#modelDot'), text = $('#modelStateText'), hint = $('#modelStateHint');
  if (!dot || !text) return;
  try {
    const st = await invoke('model.status');
    state.modelStatus = st;
    // AI 解读介绍文案随版本切换：含内置模型版说明内置模型；无内置模型版（no model）不出现"内置"表述
    try {
      const intro = document.getElementById('aiIntro');
      if (intro) intro.textContent = (st && st.builtinModel)
        ? '让模型基于本次分析证据给出研判结论，支持本地模型与自定义云端模型。内置 Qwen3.5-0.8B（Q4_K_M），输出仅作辅助研判，关键结论请人工复核。'
        : '绕过模型基于本次分析证据给出研判结论，支持本地模型与自定义云端模型，输出仅作辅助研判，关键结论请人工复核。';
    } catch { }
    if (st.found) {
      dot.className = 'dot ok';
      text.textContent = '已就绪 · ' + st.active.name;
      hint.textContent = st.active.sizeText + ' · ' + st.active.path;
      $('#btnModelDownload').classList.remove('accent');
    } else if (st.missing) {
      // 配置里有模型但文件对不上：这是「路径失效」，不是「没下载」，必须说清楚
      dot.className = 'dot err';
      text.textContent = '所选模型文件未找到';
      hint.textContent = '设置中记录的模型是「' + st.configured + '」，但在下列位置没有找到该文件：'
        + (st.searched || []).join('；') + '。请检查文件是否被移动/删除，或点击「添加本地模型」重新指定。';
      $('#btnModelDownload').classList.add('accent');
    } else {
      dot.className = 'dot warn';
      text.textContent = '未检测到本地模型';
      hint.textContent = '当前没有可用的 GGUF 模型，AI 解读与问答不可用。点击「下载模型」从魔搭在线获取，或「添加本地模型」指定本机已有文件。';
      $('#btnModelDownload').classList.add('accent');
    }
    if (!st.engine) hint.textContent += '（注意：未找到推理引擎 llama-server）';
  } catch (e) {
    dot.className = 'dot err';
    text.textContent = '模型检测失败：' + e.message;
  }
}

function openModelLib() {
  $('#modelLibMask').classList.remove('hidden');
  if (!state.modelCatalogLoaded) loadModelCatalog();
}
function closeModelLib() { $('#modelLibMask').classList.add('hidden'); }

async function loadModelCatalog() {
  const body = $('#modelLibBody');
  body.innerHTML = '<div class="junk">正在读取魔搭社区模型列表…</div>';
  try {
    const r = await invoke('model.catalog');
    if (!r || !r.repos || !r.repos.length) {
      body.innerHTML = '<div class="junk">未能读取模型列表（网络受限或仓库不可访问），可在下方输入仓库名手动载入。</div>';
      return;
    }
    state.modelCatalogLoaded = true;
    renderModelGroups(r.repos);
  } catch (e) {
    body.innerHTML = '<div class="junk">读取失败：' + esc(e.message) + '</div>';
  }
}

function renderModelGroups(repos) {
  const body = $('#modelLibBody');
  const vendors = [];
  repos.forEach(g => {
    const v = g.vendor || (String(g.repo || '').split('/')[0] || '其他');
    if (vendors.indexOf(v) < 0) vendors.push(v);
  });
  const filter = vendors.length > 1
    ? '<div class="mlibfilter"><span class="flabel">厂商</span>' + ['全部'].concat(vendors)
        .map((v, i) => `<button class="vchip${i === 0 ? ' on' : ''}" data-vendor="${esc(v)}">${esc(v)}</button>`).join('') + '</div>'
    : '';

  body.innerHTML = filter + repos.map(g => {
    const v = g.vendor || (String(g.repo || '').split('/')[0] || '其他');
    return `
    <div class="mlibgroup" data-vendor="${esc(v)}">
      <div class="mlibtitle"><span class="vendor">${esc(v)}</span><b>${esc(g.title || g.repo)}</b><span class="repo">${esc(g.repo)}</span></div>
      ${g.note ? `<div class="mlibnote">${esc(g.note)}</div>` : ''}
      ${(g.files || []).map(f => `
        <div class="mfile">
          <span class="q ${f.recommended ? 'rec' : ''}">${esc(f.quant)}</span>
          <span class="nm" title="${esc(f.name)}">${esc(f.name)}</span>
          <span class="sz">${esc(f.sizeText)}</span>
          <button class="btn small" data-repo="${esc(g.repo)}" data-file="${esc(f.name)}">下载</button>
        </div>`).join('')}
    </div>`;
  }).join('');

  body.querySelectorAll('.vchip').forEach(c => {
    c.onclick = () => {
      body.querySelectorAll('.vchip').forEach(x => x.classList.remove('on'));
      c.classList.add('on');
      const v = c.dataset.vendor;
      body.querySelectorAll('.mlibgroup').forEach(g => {
        g.style.display = (v === '全部' || g.dataset.vendor === v) ? '' : 'none';
      });
    };
  });
  body.querySelectorAll('button[data-file]').forEach(b => {
    b.onclick = () => downloadModel(b.dataset.repo, b.dataset.file, b);
  });
}

async function downloadModel(repo, file, btn) {
  try {
    if (btn) { btn.disabled = true; btn.textContent = '下载中…'; }
    $('#modelDlBar').classList.remove('hidden');
    $('#modelDlFill').style.width = '0%';
    $('#modelDlStatus').textContent = '准备下载 ' + file;
    await invoke('model.download', { repo, file });
  } catch (e) {
    toast('下载失败：' + e.message, 4000);
    if (btn) { btn.disabled = false; btn.textContent = '下载'; }
  }
}

function onModelProgress(d) {
  if (!d) return;
  const st = $('#modelDlStatus'), fill = $('#modelDlFill'), bar = $('#modelDlBar');
  const resetBtns = () => $('#modelLibBody').querySelectorAll('button[data-file]')
    .forEach(b => { b.disabled = false; b.textContent = '下载'; });
  if (d.state === 'begin') {
    bar.classList.remove('hidden'); fill.style.width = '0%';
    st.textContent = '开始下载 ' + d.file;
    return;
  }
  if (d.state === 'progress') {
    bar.classList.remove('hidden');
    fill.style.width = (d.percent || 0) + '%';
    st.textContent = (d.percent || 0) + '% · ' + d.receivedText + ' / ' + d.totalText + ' · ' + d.speed;
    return;
  }
  if (d.state === 'done') {
    fill.style.width = '100%';
    bar.classList.add('hidden');
    st.textContent = '下载完成：' + d.file + '（' + d.sizeText + '），已设为当前本地模型';
    toast('模型下载完成，重启推理服务后生效', 5000);
    resetBtns();
    loadModelStatus();
    loadSettings();
    return;
  }
  if (d.state === 'cancelled') {
    bar.classList.add('hidden');
    st.textContent = '已取消下载';
    resetBtns();
    return;
  }
  if (d.state === 'error') {
    bar.classList.add('hidden');
    st.textContent = '下载失败：' + (d.message || '未知错误');
    resetBtns();
    return;
  }
  if (d.state === 'busy') { st.textContent = d.message || '已有下载任务在进行'; return; }
}

$('#btnModelDownload').onclick = openModelLib;
$('#btnModelLibClose').onclick = closeModelLib;
$('#btnModelLibDone').onclick = closeModelLib;
$('#modelLibMask').onclick = (e) => { if (e.target.id === 'modelLibMask') closeModelLib(); };
$('#btnModelDlCancel').onclick = async () => {
  try { await invoke('model.cancel'); } catch (e) { }
};
$('#btnModelDir').onclick = async () => {
  try { await invoke('model.openDir'); } catch (e) { toast('打开目录失败：' + e.message); }
};
$('#btnModelRepoLoad').onclick = async () => {
  const repo = $('#modelRepoInput').value.trim();
  if (!repo || repo.indexOf('/') < 0) { toast('请输入 owner/name 形式的仓库名'); return; }
  const body = $('#modelLibBody');
  body.innerHTML = '<div class="junk">正在读取 ' + esc(repo) + ' …</div>';
  try {
    const files = await invoke('model.repo', { repo });
    if (!files || !files.length) {
      body.innerHTML = '<div class="junk">该仓库下没有可用的单文件 GGUF 模型。</div>';
      return;
    }
    renderModelGroups([{ repo, title: repo, note: '自定义仓库', files }]);
  } catch (e) {
    body.innerHTML = '<div class="junk">读取失败：' + esc(e.message) + '</div>';
  }
};

$('#btnSaveSettings').onclick = async () => {
  const s = {
    mode: (document.querySelector('#aiMode button.on') || {}).dataset ? document.querySelector('#aiMode button.on').dataset.mode : 'local',
    localModel: $('#setModel').value.trim(),
    localPort: Number($('#setPort').value) || 8791,
    contextSize: Number($('#setCtx').value) || 8192,
    maxTokens: Number(($('#setMaxTokens') || {}).value) || 2048,
    threads: 0,
    cloudBaseUrl: $('#setBase').value.trim(),
    cloudApiKey: $('#setKey').value,
    cloudModel: $('#setCloudModel').value.trim(),
    temperature: 0.2
  };
  try {
    const saved = await invoke('settings.set', s);
    state.aiSettings = saved;
    if (saved) {
      $('#setModel').value = saved.localModel || '';
      $('#setCtx').value = saved.contextSize || 8192;
      if ($('#setMaxTokens')) $('#setMaxTokens').value = saved.maxTokens || 2048;
      $('#setPort').value = saved.localPort || 8791;
      $('#setBase').value = saved.cloudBaseUrl || '';
      $('#setCloudModel').value = saved.cloudModel || '';
      $('#setKey').value = saved.cloudApiKey || '';
      $$('#aiMode button').forEach(b => b.classList.toggle('on', b.dataset.mode === saved.mode));
    }
    await loadModelStatus();
    const st = state.modelStatus;
    if (st && st.found) toast('设置已保存 · 本地模型：' + st.active.name);
    else if (st && st.missing) toast('设置已保存，但该模型文件未找到，请重新指定路径', 5000);
    else toast('设置已保存');
    await refreshStatus();
  } catch (e) { toast(e.message); }
};

/* ---------- 状态 ---------- */
const CAPS = [
  { t: '目标总览', d: '格式、架构与线索识别' },
  { t: '发布暴露面', d: '可还原信息量统计' },
  { t: '字节熵', d: '加壳/压缩区段定位' },
  { t: '导入表', d: 'DLL 与 API 能力清单' },
  { t: '导出表', d: '对外暴露符号' },
  { t: '资源目录', d: '资源载荷与图标组' },
  { t: '加载配置', d: 'TLS 回调与 CFG' },
  { t: '加固属性', d: 'ASLR/DEP/CFG 缓解' },
  { t: '签名证书', d: 'Authenticode 身份' },
  { t: '.NET 程序集', d: 'CLI 身份与入口' },
  { t: '类型与成员', d: '类型/方法/字符串' },
  { t: 'P/Invoke 边界', d: '托管到原生调用' }
];

/* ---------- sandbox ---------- */
function fmtBytes(n) {
  if (!n || n < 0) return '0 B';
  const u = ['B', 'KB', 'MB', 'GB'];
  let i = 0, v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return (i ? v.toFixed(1) : String(Math.round(v))) + ' ' + u[i];
}

function renderSandbox(sb) {
  if (!sb) return;
  state.sandbox = sb;
  const pill = $('#sbState');
  if (!sb.enabled) { pill.className = 'sbstate off'; pill.textContent = '已停用'; }
  else if (sb.active) { pill.className = 'sbstate on'; pill.textContent = '运行中 · ' + (sb.scope || 'web'); }
  else { pill.className = 'sbstate'; pill.textContent = '未建立'; }
  const rows = [
    ['会话', sb.active ? sb.id : '尚未建立（首次作业时自动创建）'],
    ['作业域', sb.scope || '—'],
    ['入箱副本', sb.inbox || '—'],
    ['下载隔离', sb.downloads || '—'],
    ['内核数据', sb.web || '—'],
    ['当前占用', sb.active ? fmtBytes(sb.bytes) + ' · ' + (sb.files || 0) + ' 个文件' : '—'],
    ['沙箱总量', fmtBytes(sb.totalBytes) + ' · 保留最近 ' + (sb.keep || 3) + ' 个会话']
  ];
  $('#sbKv').innerHTML = rows.map(([k, v]) => `<div class="k">${esc(k)}</div><div class="v">${esc(v)}</div>`).join('');
}

async function sandboxOpen() {
  try {
    const r = await invoke('sandbox.open');
    toast('已打开沙箱目录：' + ((r && r.path) || ''), 3600);
  } catch (e) { toast('打开沙箱目录失败：' + e.message, 3600); }
}

async function sandboxPurge() {
  if (!confirm('清空沙箱会删除全部会话目录（样本副本、下载、网页内核数据），不可恢复。确定继续？')) return;
  try {
    const r = await invoke('sandbox.purge');
    renderSandbox((r && r.status) || state.sandbox);
    toast('沙箱已清空：移除 ' + ((r && r.removed) || 0) + ' 个会话，释放 ' + fmtBytes((r && r.freed) || 0), 4200);
    refreshStatus();
  } catch (e) { toast('清空沙箱失败：' + e.message, 3600); }
}

async function refreshStatus() {
  try {
    const s = await invoke('app.status');
    state.status = s;
    const dot = $('#runtimeDot'), txt = $('#runtimeText');
    if (s.payloadReady) { dot.className = 'dot ok'; txt.textContent = '运行时就绪'; }
    else { dot.className = 'dot err'; txt.textContent = '运行时缺失'; }

    $('#envKv').innerHTML = [
      ['运行模式', s.payloadKind === 'embedded' ? '单文件内置载荷' : (s.payloadKind === 'dev' ? '开发模式（外部目录）' : '未就绪')],
      ['Node 运行时', s.node || '—'],
      ['REA 分析器', s.rea || '—'],
      ['推理引擎', s.llama || '未内置'],
      ['模型目录', s.modelDir || '未配置'],
      ['证据目录', s.evidenceDir]
    ].map(([k, v]) => `<div class="k">${esc(k)}</div><div class="v">${esc(v)}</div>`).join('');

    renderSandbox(s.sandbox);

    $('#settingsKv').innerHTML = [
      ['版本', s.version],
      ['运行时根目录', s.runtimeRoot || '—'],
      ['Node', s.node || '—'],
      ['REA 入口', s.rea || '—'],
      ['推理引擎', s.llama || '未内置'],
      ['模型文件', (s.ai && s.ai.model) || '未配置'],
      ['证据目录', s.evidenceDir],
      ['载荷类型', s.payloadKind]
    ].map(([k, v]) => `<div class="k">${esc(k)}</div><div class="v">${esc(v)}</div>`).join('');

    $('#aboutVer').textContent = '版本 ' + s.version + '  ·  运行时 ' + (s.payloadKind === 'embedded' ? '单文件内置' : (s.payloadKind || 'none'));
    renderAiState();
  } catch (e) {
    $('#runtimeText').textContent = '状态获取失败';
  }
}

async function refreshVirusLib() {
  try {
    const s = await invoke('virus.status');
    if (!s || !$('#virusLibKv')) return;
    const byType = Object.keys(s.byType || {}).map(k => k + ' ' + s.byType[k]).join('　');
    $('#virusLibKv').innerHTML = [
      ['库版本', s.version],
      ['内置规则', (s.builtinRuleCount || 0) + ' 条（随程序发布，覆盖已知攻击族谱）'],
      ['导入规则', (s.importedRuleCount || 0) + ' 条'],
      ['样本哈希', (s.hashCount || 0) + ' 条'],
      ['类型分布', byType || '—'],
      ['检测方式', s.sandbox ? '沙箱内比对（样本不执行，主系统不受影响）' : '直接读取副本比对（样本不执行）'],
      ['最近同步', (s.lastUpdate || '未同步') + (s.lastSource ? '　来源：' + s.lastSource : '')],
      ['库目录', s.dir || '—']
    ].map(([k, v]) => `<div class="k">${esc(k)}</div><div class="v">${esc(v)}</div>`).join('');
  } catch (e) {
    if ($('#virusLibKv')) $('#virusLibKv').innerHTML = '<div class="v">病毒库状态读取失败：' + esc(e.message) + '</div>';
  }
}

function virusSource() {
  const el = $('#virusSource');
  return ((el && el.value) || 'threatbook').toLowerCase() === 'url' ? 'url' : 'threatbook';
}

function syncVirusSourceUi() {
  const isTb = virusSource() === 'threatbook';
  const urlEl = $('#virusUrl');
  const keyEl = $('#virusApiKey');
  const hashesEl = $('#virusHashes');
  if (urlEl) urlEl.classList.toggle('hidden', isTb);
  if (keyEl) keyEl.classList.toggle('hidden', !isTb);
  if (hashesEl) hashesEl.classList.toggle('hidden', !isTb);
}

async function virusOnline() {
  const src = virusSource();
  const btn = $('#btnVirusOnline');
  if (src === 'threatbook') {
    const apiKey = (($('#virusApiKey') && $('#virusApiKey').value) || '').trim();
    if (!apiKey) { toast('请填写微步 API Key（微步开放平台 v3 接口所需）'); return; }
    const hashes = (($('#virusHashes') && $('#virusHashes').value) || '').trim();
    if (btn) btn.disabled = true;
    toast('正在通过微步威胁情报中心同步样本信誉…', 6000);
    try {
      const r = await invoke('virus.threatbook', { apiKey, hashes });
      const head = '微步同步完成：查询 ' + (r.queried || 0) + ' 个哈希，新增 ' + (r.added || 0) + ' 条恶意情报，当前共 ' + (r.total || 0) + ' 条';
      toast(r.error ? (head + '（' + r.error + '）') : head, 5200);
      refreshVirusLib();
    } catch (e) { toast('微步同步失败：' + e.message, 4800); }
    finally { if (btn) btn.disabled = false; }
    return;
  }
  const url = ($('#virusUrl').value || '').trim();
  if (!url) { toast('请填写威胁情报地址（哈希清单或 YARA 规则）'); return; }
  if (btn) btn.disabled = true;
  toast('正在同步威胁情报…', 5000);
  try {
    const r = await invoke('virus.online', { url, label: 'online' });
    toast(r.error ? ('同步完成但有告警：' + r.error) : ('同步完成，新增 ' + (r.added || 0) + ' 条，当前共 ' + (r.total || 0) + ' 条'), 4800);
    refreshVirusLib();
  } catch (e) { toast('同步失败：' + e.message, 4600); }
  finally { if (btn) btn.disabled = false; }
}

async function virusImport() {
  try {
    const r = await invoke('virus.import');
    if (r.cancelled) return;
    toast('导入完成：新增哈希 ' + (r.hashes || 0) + ' 条、规则 ' + (r.rules || 0) + ' 条' + (r.error ? '（' + r.error + '）' : ''), 5000);
    refreshVirusLib();
  } catch (e) { toast('导入失败：' + e.message, 4600); }
}

async function virusToggleRules() {
  const wrap = $('#virusRulesWrap');
  if (!wrap.classList.contains('hidden')) { wrap.classList.add('hidden'); return; }
  wrap.classList.remove('hidden');
  const box = $('#virusRules');
  box.innerHTML = '<div class="ev-empty">正在载入库内规则…</div>';
  try {
    const rules = await invoke('virus.rules', { take: 300 });
    if (!rules || !rules.length) { box.innerHTML = '<div class="ev-empty">病毒库为空</div>'; return; }
    box.innerHTML = '<table><thead><tr><th>编号</th><th>检测名称</th><th>家族 / 类型</th><th>等级</th><th>来源</th><th>特征</th></tr></thead><tbody>'
      + rules.map(r => '<tr class="' + (r.severity === '高' ? 's-high' : r.severity === '中' ? 's-mid' : '') + '">'
        + '<td>' + esc(r.id || '') + '</td><td>' + esc(r.name || '') + '</td><td>'
        + esc((r.family || '') + (r.type ? ' / ' + r.type : '')) + '</td><td>' + esc(r.severity || '') + '</td><td>'
        + (r.builtin ? '内置' : '导入') + '</td><td>' + esc(r.pattern || '') + '</td></tr>').join('')
      + '</tbody></table><div class="hint">共 ' + rules.length + ' 条（按库内顺序展示，最多 300 条）</div>';
  } catch (e) { box.innerHTML = '<div class="ev-empty">读取失败：' + esc(e.message) + '</div>'; }
}

async function virusClear() {
  if (!confirm('清空导入会移除全部导入的样本哈希与外置规则（内置规则保留），不可恢复。确定继续？')) return;
  try {
    const r = await invoke('virus.clear');
    toast('已清空导入：移除 ' + (r.removed || 0) + ' 条', 4200);
    $('#virusRulesWrap').classList.add('hidden');
    refreshVirusLib();
  } catch (e) { toast('清空失败：' + e.message, 4200); }
}

/* ---------- 初始化 ---------- */
(function init() {
  $('#capGrid').innerHTML = CAPS.map(c => `<div class="capitem"><div class="ct">${esc(c.t)}</div><div class="cd">${esc(c.d)}</div></div>`).join('');
  if ($('#btnVirusOnline')) $('#btnVirusOnline').onclick = virusOnline;
  if ($('#virusSource')) { $('#virusSource').onchange = syncVirusSourceUi; syncVirusSourceUi(); }
  if ($('#btnVirusImport')) $('#btnVirusImport').onclick = virusImport;
  if ($('#btnVirusRules')) $('#btnVirusRules').onclick = virusToggleRules;
  if ($('#btnVirusDir')) $('#btnVirusDir').onclick = () => invoke('virus.open').then(r => toast('已打开病毒库目录：' + ((r && r.path) || ''), 3600)).catch(e => toast('打开失败：' + e.message, 3600));
  if ($('#btnVirusClear')) $('#btnVirusClear').onclick = virusClear;
  refreshVirusLib();
  refreshStatus();
  loadSettings();
  loadModelStatus();
})();

/* ---------- 漏洞检测（CVE） ---------- */
function renderVuln(v) {
  const card = $('#vulnCard');
  if (!card || !v) return;
  card.classList.remove('hidden');
  const badge = $('#vulnVerdict');
  const cls = !v.ok ? 'bad' : (v.score >= 60 ? 'bad' : (v.matches && v.matches.length) ? 'warn' : 'clean');
  badge.className = 'vbadge ' + cls;
  badge.textContent = v.ok ? (v.verdict + ' · 评分 ' + v.score) : '检测失败';

  const rows = [];
  rows.push(['检测结论', '<b>' + esc(v.verdict || '—') + '</b>']);
  rows.push(['漏洞统计', '严重 ' + (v.critical || 0) + ' / 高危 ' + (v.high || 0) + ' / 中危 ' + (v.medium || 0) + ' / 低危 ' + (v.low || 0) + ' / 待确认 ' + (v.pending || 0)]);
  if (v.sha256) rows.push(['SHA-256', esc(v.sha256)]);
  rows.push(['CVE 库', esc(v.dbVersion || '—') + '（可用 CVE ' + (v.cveCount || 0) + ' 条）']);
  rows.push(['组件指纹', (v.components && v.components.length) ? v.components.slice(0, 6).map(c => esc(c.name) + ' ' + esc(c.version || '?')).join('、') : '未识别到受 CVE 覆盖的第三方组件']);
  rows.push(['耗时', (v.elapsedMs || 0) + ' ms']);
  rows.push(['检测位置', (v.inSandbox ? '沙箱副本　' : '') + esc(v.scanPath || '—')]);
  if (v.summary) rows.push(['判定说明', esc(v.summary)]);
  if (!v.ok && v.error) rows.push(['错误', esc(v.error)]);
  $('#vulnKv').innerHTML = rows.map(r => '<div class="k">' + r[0] + '</div><div class="v">' + r[1] + '</div>').join('');

  const hits = v.matches || [];
  const box = $('#vulnHits');
  if (!hits.length) {
    box.innerHTML = '<div class="ev-empty">与当前 CVE 库无匹配（已识别组件 ' + ((v.components || []).length) + ' 个，库内 CVE ' + (v.cveCount || 0) + ' 条）</div>';
    return;
  }
  box.innerHTML = '<table><thead><tr><th>CVE</th><th>等级</th><th>CVSS</th><th>命中形态</th><th>组件 / 版本</th><th>说明</th><th>修复建议</th></tr></thead><tbody>'
    + hits.slice(0, 100).map(m => '<tr class="' + ((m.severity === '严重' || m.severity === '高') ? 's-high' : m.severity === '中' ? 's-mid' : '') + '">'
      + '<td>' + esc(m.cveId || '') + '</td><td>' + esc(m.severity || '') + '</td><td>' + (m.cvss || 0).toFixed(1) + '</td><td>'
      + esc(m.kind || '') + '</td><td>' + esc((m.component || '') + (m.version ? ' ' + m.version : '')) + '</td><td>'
      + esc(m.desc || '') + '</td><td>' + esc(m.fix || '') + '</td></tr>').join('') + '</tbody></table>';
}

async function refreshVulnLib() {
  try {
    const st = await invoke('vuln.status');
    if (!st) { $('#vulnLibKv').innerHTML = '<div class="k">状态</div><div class="v">状态获取失败</div>'; return; }
    const rows = [
      ['CVE 库版本', esc(st.version || '—')],
      ['内置 CVE', (st.builtinCveCount || 0) + ' 条'],
      ['导入 CVE', (st.importedCveCount || 0) + ' 条'],
      ['可用合计', '<b>' + (st.cveCount || 0) + ' 条</b>'],
      ['检测方式', '沙箱内只读比对，样本不执行'],
      ['最近同步', esc(st.lastUpdate || '未同步') + (st.lastSource ? '（' + esc(st.lastSource) + '）' : '')],
      ['库目录', esc(st.dir || '—')]
    ];
    $('#vulnLibKv').innerHTML = rows.map(r => '<div class="k">' + r[0] + '</div><div class="v">' + r[1] + '</div>').join('');
  } catch (e) {
    $('#vulnLibKv').innerHTML = '<div class="k">状态</div><div class="v">CVE 库状态读取失败：' + esc(e.message) + '</div>';
  }
}

async function vulnOnline() {
  const el = $('#vulnKeyword');
  const kw = ((el && el.value) || '').trim();
  const source = ((($('#vulnSource') && $('#vulnSource').value) || 'cnnvd')).toLowerCase() === 'nvd' ? 'nvd' : 'cnnvd';
  const isCnnvd = source === 'cnnvd';
  if (!kw && !isCnnvd) { toast('请填写组件关键词，例如：openssl,zlib,libxml2'); return; }
  const btn = $('#btnVulnOnline');
  const key = (($('#vulnApiKey') && $('#vulnApiKey').value) || '').trim();
  const max = parseInt((($('#vulnMax') && $('#vulnMax').value) || '200'), 10) || 200;
  if (btn) btn.disabled = true;
  try {
    const r = await invoke('vuln.online', { source: source, keyword: kw, apiKey: key, max: String(max) });
    toast((isCnnvd ? 'CNNVD' : 'NVD') + ' 同步完成，新增 ' + (r.added || 0) + ' 条漏洞' + (r.error ? '（' + r.error + '）' : ''));
    refreshVulnLib();
  } catch (e) { toast('同步失败：' + e.message); }
  if (btn) btn.disabled = false;
}

async function vulnImport() {
  try {
    const r = await invoke('vuln.import');
    if (r && r.cancelled) return;
    toast('导入完成：新增 CVE ' + (r.added || 0) + ' 条' + (r.error ? '（' + r.error + '）' : ''));
    refreshVulnLib();
  } catch (e) { toast('导入失败：' + e.message); }
}

async function vulnToggleRules() {
  const wrap = $('#vulnRulesWrap');
  if (!wrap) return;
  if (!wrap.classList.contains('hidden')) { wrap.classList.add('hidden'); return; }
  try {
    const rules = await invoke('vuln.rules', { take: 300 });
    if (!rules || !rules.length) { toast('CVE 库为空'); return; }
    $('#vulnRules').innerHTML = '<table><thead><tr><th>CVE</th><th>组件</th><th>命中形态</th><th>受影响版本</th><th>CVSS</th><th>等级</th><th>来源</th></tr></thead><tbody>'
      + rules.slice(0, 300).map(r => '<tr class="' + ((r.severity === '严重' || r.severity === '高') ? 's-high' : r.severity === '中' ? 's-mid' : '') + '">'
        + '<td>' + esc(r.cveId || '') + '</td><td>' + esc(r.component || '') + '</td><td>' + esc(r.kind || '') + '</td><td>'
        + esc(r.affected || '') + '</td><td>' + (r.cvss || 0).toFixed(1) + '</td><td>' + esc(r.severity || '') + '</td><td>'
        + esc(r.source || '') + '</td></tr>').join('') + '</tbody></table>'
      + '<div class="hint">共 ' + rules.length + ' 条（最多展示 300 条）</div>';
    wrap.classList.remove('hidden');
  } catch (e) { toast('读取失败：' + e.message); }
}

async function vulnClear() {
  if (!confirm('确定清空全部导入的 CVE？内置库保留，导入项不可恢复。')) return;
  try {
    const r = await invoke('vuln.clear');
    toast('已清空导入：移除 ' + (r.removed || 0) + ' 条');
    $('#vulnRulesWrap').classList.add('hidden');
    refreshVulnLib();
  } catch (e) { toast('清空失败：' + e.message); }
}

document.addEventListener('DOMContentLoaded', () => {
  const bind = (sel, fn) => { const el = $(sel); if (el) el.onclick = fn; };
  bind('#btnVulnOnline', vulnOnline);
  bind('#btnVulnImport', vulnImport);
  bind('#btnVulnRules', vulnToggleRules);
  bind('#btnVulnDir', () => invoke('vuln.open').then(r => toast('已打开 CVE 库目录：' + ((r && r.path) || ''), 3600)).catch(e => toast('打开失败：' + e.message, 3600)));
  bind('#btnVulnClear', vulnClear);
  if ($('#vulnLibKv')) refreshVulnLib();
});
