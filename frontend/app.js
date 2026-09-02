/**
 * CyberGuard — Frontend Logic
 * POST /api/scan -> polling GET /api/result/{id} -> redirect dashboard.html?id=
 */
const API_BASE = location.origin.includes('localhost') || location.origin.includes('127.0.0.1')
  ? 'http://localhost:8000'
  : ''; // на Render/Vercel — same origin через proxy або абсолютний URL

const urlInput = () => document.getElementById('urlInput');
const scanBtn = () => document.getElementById('scanBtn');
const progressWrap = () => document.getElementById('progressWrap');
const progressFill = () => document.getElementById('progressFill');
const progressText = () => document.getElementById('progressText');
const errorBox = () => document.getElementById('errorBox');

function isValidUrl(str) {
  str = str.trim();
  if (!str) return false;
  // Блокуємо localhost
  const blocked = /localhost|127\.0\.0\.1|0\.0\.0\.0|10\.\d|192\.168|172\.(1[6-9]|2\d|3[0-1])/i;
  if (blocked.test(str)) return false;
  // Додаємо протокол якщо треба для URL parsing
  try {
    const u = new URL(str.startsWith('http') ? str : 'https://' + str);
    return u.hostname.includes('.') || u.hostname === 'localhost';
  } catch { return false; }
}

async function startScan() {
  const input = urlInput();
  const btn = scanBtn();
  const err = errorBox();

  let url = (input?.value || '').trim();
  if (!url) {
    showError('Введи URL для сканування');
    return;
  }
  if (url.length > 2048) {
    showError('URL занадто довгий');
    return;
  }

  // Нормалізація: додаємо https якщо немає
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    url = 'https://' + url;
  }

  // Клієнтська валідація localhost
  if (/localhost|127\.0\.0\.1|0\.0\.0\.0/i.test(url)) {
    showError('Сканування localhost заборонено — тестуй лише публічні сайти або testphp.vulnweb.com');
    return;
  }

  err.style.display = 'none';
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Скануємо...';
  progressWrap().classList.add('active');
  updateProgress(8, 'Відправляємо запит...');

  try {
    const res = await fetch(`${API_BASE}/api/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });

    const data = await res.json();

    if (!res.ok) {
      // Pydantic validation error
      const msg = data.detail
        ? (Array.isArray(data.detail) ? data.detail.map(d => d.msg || d).join(', ') : data.detail)
        : (data.message || 'Помилка запуску сканування');
      throw new Error(msg);
    }

    const scanId = data.scan_id;
    if (!scanId) throw new Error('Сервер не повернув scan_id');

    // Polling
    updateProgress(15, 'Сканери запущені паралельно...');
    await pollResult(scanId);

  } catch (e) {
    showError(e.message || 'Помилка з’єднання з сервером. Перевір що бекенд запущено на :8000');
    resetBtn();
  }
}

async function pollResult(scanId) {
  const maxAttempts = 40; // ~40 сек
  let attempts = 0;

  while (attempts < maxAttempts) {
    await sleep(1100);
    attempts++;

    try {
      const r = await fetch(`${API_BASE}/api/result/${scanId}`);
      if (!r.ok) throw new Error('Result fetch failed');
      const data = await r.json();

      if (data.status === 'running' || data.status === 'pending') {
        const pct = data.progress ?? Math.min(15 + attempts * 4, 92);
        updateProgress(pct, data.message || 'Скануємо...');
        continue;
      }

      if (data.status === 'completed') {
        updateProgress(100, 'Готово! Переходимо до дашборду...');
        await sleep(400);
        location.href = `dashboard.html?id=${scanId}`;
        return;
      }

      if (data.status === 'failed') {
        throw new Error(data.message || 'Сканування не вдалося');
      }

      // Якщо прийшов повний результат без status — теж редирект
      if (data.risk_score !== undefined) {
        location.href = `dashboard.html?id=${scanId}`;
        return;
      }

    } catch (e) {
      if (attempts > 5) {
        // Не падаємо одразу — можливо тимчасова помилка
        console.warn('poll error', e);
      }
    }
  }

  showError('Сканування зависло — спробуй ще раз або перевір логи сервера');
  resetBtn();
}

function updateProgress(pct, msg) {
  const fill = progressFill();
  const text = progressText();
  if (fill) fill.style.width = Math.min(100, pct) + '%';
  if (text) text.innerHTML = `<span class="spinner"></span> ${escapeHtml(msg)} (${Math.round(pct)}%)`;
}

function showError(msg) {
  const err = errorBox();
  if (err) {
    err.textContent = '⚠️ ' + msg;
    err.style.display = 'block';
  } else {
    alert(msg);
  }
}

function resetBtn() {
  const btn = scanBtn();
  if (btn) {
    btn.disabled = false;
    btn.textContent = '🔍 Сканувати';
  }
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function escapeHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// Експорт для inline onclick
window.startScan = startScan;
