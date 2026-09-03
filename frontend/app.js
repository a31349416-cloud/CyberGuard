/**
 * CyberGuard v2 — POST /api/scan -> WS /ws/{id} (fallback polling) -> dashboard.html?id=
 */
const API_BASE = location.origin.includes('localhost') || location.origin.includes('127.0.0.1')
  ? 'http://localhost:8000'
  : '';
const WS_BASE = API_BASE ? API_BASE.replace('http','ws') : (location.protocol==='https:'?'wss://'+location.host:'ws://'+location.host);

const urlInput = () => document.getElementById('urlInput');
const scanBtn = () => document.getElementById('scanBtn');
const progressWrap = () => document.getElementById('progressWrap');
const progressFill = () => document.getElementById('progressFill');
const progressText = () => document.getElementById('progressText');
const errorBox = () => document.getElementById('errorBox');

async function startScan() {
  const input = urlInput();
  const btn = scanBtn();
  const err = errorBox();
  let url = (input?.value || '').trim();
  if (!url) return showError('Введи URL для сканування');
  if (url.length > 2048) return showError('URL занадто довгий');
  if (!url.startsWith('http://') && !url.startsWith('https://')) url = 'https://' + url;
  if (/localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.169\.254/i.test(url)) return showError('Сканування localhost/metadata заборонено — тестуй лише публічні сайти');
  err.style.display = 'none';
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Скануємо...';
  progressWrap().classList.add('active');
  updateProgress(8, 'Відправляємо запит...');
  try {
    const res = await fetch(`${API_BASE}/api/scan`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url }) });
    const data = await res.json();
    if (!res.ok) {
      const msg = data.detail ? (Array.isArray(data.detail) ? data.detail.map(d=>d.msg||d).join(', ') : data.detail) : (data.message||'Помилка запуску');
      throw new Error(msg);
    }
    const scanId = data.scan_id;
    if (!scanId) throw new Error('Сервер не повернув scan_id');
    updateProgress(15, 'Сканери запущені паралельно (10)...');
    // Спробуємо WebSocket, fallback на polling
    const wsOk = await tryWebSocketProgress(scanId, 8000);
    if (!wsOk) await pollResult(scanId);
  } catch (e) {
    showError(e.message || 'Помилка з’єднання. Перевір що бекенд запущено на :8000');
    resetBtn();
  }
}

function tryWebSocketProgress(scanId, timeoutMs) {
  return new Promise(resolve => {
    let done=false;
    let ws;
    try { ws = new WebSocket(`${WS_BASE}/ws/${scanId}`); } catch { return resolve(false); }
    const timer = setTimeout(()=>{ if(!done){ try{ws.close();}catch{}; resolve(false);} }, timeoutMs);
    ws.onmessage = (ev)=>{
      try{
        const msg = JSON.parse(ev.data);
        if(msg.event==='progress' || msg.event==='init'){ updateProgress(msg.progress||30, msg.message||'Скануємо...'); }
        else if(msg.event==='scanner_done'){ updateProgress(Math.min(85, (msg.progress||50)), `Готово ${msg.scanner} (${msg.findings} findings)`); }
        else if(msg.event==='completed'){ clearTimeout(timer); done=true; updateProgress(100,'Готово! Переходимо до дашборду...'); ws.close(); setTimeout(()=>{ location.href=`dashboard.html?id=${scanId}`; resolve(true); }, 400); }
        else if(msg.event==='failed'){ clearTimeout(timer); done=true; ws.close(); showError(msg.message||'Scan failed'); resetBtn(); resolve(true); }
      }catch{}
    };
    ws.onerror = ()=>{ if(!done){ clearTimeout(timer); resolve(false); } };
    ws.onclose = ()=>{ if(!done){ clearTimeout(timer); resolve(false); } };
  });
}

async function pollResult(scanId) {
  const maxAttempts = 40; let attempts=0;
  while(attempts < maxAttempts){
    await sleep(1100); attempts++;
    try{
      const r = await fetch(`${API_BASE}/api/result/${scanId}`);
      if(!r.ok) throw new Error('Result fetch failed');
      const data = await r.json();
      if(data.status==='running' || data.status==='pending'){ updateProgress(data.progress ?? Math.min(15+attempts*4,92), data.message||'Скануємо...'); continue; }
      if(data.status==='completed'){ updateProgress(100,'Готово! Переходимо до дашборду...'); await sleep(400); location.href=`dashboard.html?id=${scanId}`; return; }
      if(data.status==='failed') throw new Error(data.message||'Сканування не вдалося');
      if(data.risk_score!==undefined){ location.href=`dashboard.html?id=${scanId}`; return; }
    }catch(e){ if(attempts>5) console.warn('poll error',e); }
  }
  showError('Сканування зависло — спробуй ще раз або перевір логи сервера'); resetBtn();
}
function updateProgress(pct, msg){ const fill=progressFill(); const text=progressText(); if(fill) fill.style.width=Math.min(100,pct)+'%'; if(text) text.innerHTML=`<span class="spinner"></span> ${escapeHtml(msg)} (${Math.round(pct)}%)`; }
function showError(msg){ const err=errorBox(); if(err){ err.textContent='⚠️ '+msg; err.style.display='block'; } else alert(msg); }
function resetBtn(){ const btn=scanBtn(); if(btn){ btn.disabled=false; btn.textContent='🔍 Сканувати'; } }
function sleep(ms){ return new Promise(r=>setTimeout(r,ms)); }
function escapeHtml(s){ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
window.startScan=startScan;

// Theme toggle
(function(){
  const key='cg-theme';
  const saved=localStorage.getItem(key);
  if(saved==='light') document.documentElement.setAttribute('data-theme','light');
  window.toggleTheme=()=>{
    const cur=document.documentElement.getAttribute('data-theme');
    const next=cur==='light'?'dark':'light';
    if(next==='light') document.documentElement.setAttribute('data-theme','light'); else document.documentElement.removeAttribute('data-theme');
    localStorage.setItem(key,next);
  };
})();
