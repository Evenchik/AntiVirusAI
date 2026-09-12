const state = { jobId: null, report: null, currentBrowsePath: null, browseParent: null, pollTimer: null, token: null, locations: {} };
const el = (id) => document.getElementById(id);
const text = (id, value) => { el(id).textContent = value; };
const formatBytes = (value) => value < 1024 ? `${value} Б` : value < 1024 * 1024 ? `${(value / 1024).toFixed(1)} КБ` : `${(value / 1024 / 1024).toFixed(1)} МБ`;
const escapeHtml = (value) => String(value ?? "").replace(/[&<>'"]/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" }[char]));

async function api(path, options = {}) {
  if (!state.token) throw new Error('Локальная сессия ещё не готова.');
  const headers = new Headers(options.headers || {});
  headers.set('X-ArmorAV-Token', state.token);
  return fetch(path, { ...options, headers });
}

function showView(name) {
  document.querySelectorAll('.view').forEach((view) => view.classList.toggle('active', view.id === `${name}-view`));
  document.querySelectorAll('.nav-item').forEach((button) => button.classList.toggle('active', button.dataset.view === name));
  const titles = { overview: ['Панель безопасности', 'ЗАЩИТА УСТРОЙСТВА'], scan: ['Новая проверка', 'ЛОКАЛЬНЫЙ АНАЛИЗ'], quarantine: ['Карантин', 'ЗАЩИЩЁННОЕ ХРАНИЛИЩЕ'], reports: ['Отчёты', 'ЭКСПОРТ РЕЗУЛЬТАТОВ'] };
  text('page-title', titles[name][0]); text('page-eyebrow', titles[name][1]);
  if (name === 'quarantine') loadQuarantine();
}

function verdictClass(verdict) { return verdict === 'CONFIRMED' ? 'confirmed' : verdict === 'SUSPICIOUS' ? 'suspicious' : 'clean'; }

function renderReport(report) {
  state.report = report;
  const confirmed = report.confirmed || 0;
  text('metric-status', confirmed ? 'Внимание' : 'Защищено');
  text('metric-files', report.filesScanned);
  text('metric-threats', confirmed);
  text('metric-duration', `${report.durationSeconds.toFixed(2)} с`);
  text('hero-title', confirmed ? 'Обнаружены подтверждённые угрозы' : 'Последняя проверка завершена');
  text('recent-caption', `Проверено ${report.filesScanned} файл(ов) · ${formatBytes(report.bytesScanned)} · ${report.durationSeconds.toFixed(2)} с`);
  text('result-caption', `Подтверждено: ${confirmed} · Подозрительно: ${report.suspicious} · Чисто: ${report.clean} · Пропущено: ${report.skipped.length}`);
  renderResults(report.results, report.skipped);
  renderRecent(report.results);
  document.querySelectorAll('[data-report]').forEach((button) => { button.disabled = false; });
}

function renderResults(results, skipped) {
  const list = el('result-list');
  if (!results.length && !skipped.length) { list.innerHTML = '<div class="empty-state compact"><div>⌕</div><p>Срабатываний и результатов нет.</p></div>'; return; }
  list.innerHTML = results.map((result, index) => `<button class="result-row" data-result="${index}"><span class="verdict ${verdictClass(result.verdict)}">${escapeHtml(result.verdict)}</span><span class="score">${result.score}</span><span class="type">${escapeHtml(result.fileType)}</span><span class="row-path" title="${escapeHtml(result.path)}">${escapeHtml(result.path)}</span></button>`).join('') + skipped.map((item) => `<button class="result-row skipped"><span class="verdict suspicious">ПРОПУЩЕН</span><span class="score">—</span><span class="type">—</span><span class="row-path" title="${escapeHtml(item.reason)}">${escapeHtml(item.path)} · ${escapeHtml(item.reason)}</span></button>`).join('');
  list.querySelectorAll('[data-result]').forEach((button) => button.addEventListener('click', () => showResult(results[Number(button.dataset.result)])));
}

function renderRecent(results) {
  const target = el('recent-list');
  if (!results.length) { target.classList.add('hidden'); el('recent-empty').classList.remove('hidden'); return; }
  el('recent-empty').classList.add('hidden'); target.classList.remove('hidden');
  target.innerHTML = results.slice(0, 6).map((result) => `<div class="recent-row"><span class="verdict ${verdictClass(result.verdict)}">${escapeHtml(result.verdict)}</span><span class="recent-path" title="${escapeHtml(result.path)}">${escapeHtml(result.path)}</span><span class="score">${result.score}</span></div>`).join('');
}

function showResult(result) {
  text('details-title', `${result.verdict} · ${result.score} баллов`);
  text('details-body', `Тип: ${result.fileType}\nSHA-256: ${result.sha256 || '—'}\nСемейства: ${result.families.join(', ') || '—'}\nATT&CK: ${result.techniques.join(', ') || '—'}${result.quarantineNote ? `\nКарантин: ${result.quarantineNote}` : ''}`);
  el('details-findings').innerHTML = result.findings.length ? result.findings.map((finding) => `<span class="finding-chip"><b>${escapeHtml(finding.severity)} · ${escapeHtml(finding.name)}</b><br>${escapeHtml(finding.detail)}</span>`).join('') : '';
}

async function startScan() {
  const path = el('target-path').value.trim();
  if (!path) { toast('Сначала выберите файл или папку.'); return; }
  const command = { path, quarantineConfirmed: el('quarantine-enabled').checked, useCache: el('cache-enabled').checked, maxDepth: Number(el('max-depth').value), threads: Number(el('thread-count').value) };
  const response = await api('/api/scans', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(command) });
  const data = await response.json();
  if (!response.ok) { toast(data.message || 'Не удалось начать проверку.'); return; }
  state.jobId = data.id;
  text('scan-status', 'Проверка поставлена в очередь…'); text('live-status', 'Проверка выполняется');
  el('spinner').classList.remove('hidden'); el('start-scan').disabled = true;
  el('result-list').innerHTML = '<div class="empty-state compact"><div class="spinner"></div><p>ArmorAV выполняет локальный анализ…</p></div>';
  pollScan();
}

async function pollScan() {
  if (!state.jobId) return;
  try {
    const response = await api(`/api/scans/${state.jobId}`);
    const data = await response.json();
    text('scan-status', data.message);
    if (data.state === 'completed') {
      clearTimeout(state.pollTimer); el('spinner').classList.add('hidden'); el('start-scan').disabled = false; text('live-status', 'Проверка завершена'); renderReport(data.report); toast('Проверка завершена.'); return;
    }
    if (data.state === 'failed') {
      clearTimeout(state.pollTimer); el('spinner').classList.add('hidden'); el('start-scan').disabled = false; text('live-status', 'Ошибка проверки'); toast(data.message || 'Проверка завершилась с ошибкой.'); return;
    }
    state.pollTimer = setTimeout(pollScan, 650);
  } catch {
    state.pollTimer = setTimeout(pollScan, 1000);
  }
}

async function openBrowser(path) {
  const response = await api(`/api/browse${path ? `?path=${encodeURIComponent(path)}` : ''}`);
  const data = await response.json();
  if (!response.ok) { toast(data.message || 'Не удалось открыть папку.'); return; }
  state.currentBrowsePath = data.path; state.browseParent = data.parentPath;
  el('browser-path').value = data.path; text('browser-note', 'Выберите папку, чтобы открыть её, или файл, чтобы назначить его для проверки.');
  const items = [...data.directories, ...data.files];
  el('browser-list').innerHTML = items.length ? items.map((item) => `<button class="browser-item" data-kind="${item.kind}" data-path="${escapeHtml(item.path)}"><b>${item.kind === 'directory' ? '▸' : '•'}</b><span title="${escapeHtml(item.path)}">${escapeHtml(item.name)}</span><small>${item.kind === 'directory' ? 'папка' : formatBytes(item.size)}</small></button>`).join('') : '<div class="empty-state compact"><p>В этой папке нет доступных объектов.</p></div>';
  el('browser-list').querySelectorAll('.browser-item').forEach((item) => item.addEventListener('click', () => item.dataset.kind === 'directory' ? openBrowser(item.dataset.path) : selectPath(item.dataset.path)));
  if (!el('browser-dialog').open) el('browser-dialog').showModal();
}

function selectPath(path) { el('target-path').value = path; el('browser-dialog').close(); text('scan-status', 'Объект выбран и готов к проверке.'); }

async function loadQuarantine() {
  const list = el('quarantine-list'); text('quarantine-caption', 'Загрузка списка…'); list.innerHTML = '';
  try {
    const response = await api('/api/quarantine'); const records = await response.json();
    text('quarantine-caption', records.length ? `Объектов в карантине: ${records.length}` : 'Карантин пуст.');
    list.innerHTML = records.length ? records.map((record) => `<div class="quarantine-row"><div><h4>${escapeHtml(record.originalPath)}</h4><p>${escapeHtml(record.timestampUtc)} · SHA-256: ${escapeHtml(record.sha256)}</p></div><button class="restore-button" data-restore="${record.id}">Восстановить</button></div>`).join('') : '<div class="empty-state compact"><div>▣</div><p>В карантине пока нет объектов.</p></div>';
    list.querySelectorAll('[data-restore]').forEach((button) => button.addEventListener('click', () => restoreItem(button.dataset.restore)));
  } catch { text('quarantine-caption', 'Не удалось загрузить карантин.'); }
}

async function restoreItem(id) {
  const response = await api(`/api/quarantine/${encodeURIComponent(id)}/restore`, { method: 'POST' }); const data = await response.json(); toast(data.message); if (response.ok) loadQuarantine();
}

async function downloadReport(format) {
  if (!state.jobId) { toast('Сначала завершите проверку.'); return; }
  try {
    const response = await api(`/api/scans/${state.jobId}/report?format=${encodeURIComponent(format)}`);
    if (!response.ok) { const data = await response.json(); toast(data.message || 'Не удалось скачать отчёт.'); return; }
    const blob = await response.blob();
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = `ArmorAV-report.${format}`;
    link.click();
    URL.revokeObjectURL(link.href);
  } catch { toast('Не удалось скачать отчёт.'); }
}
function toast(message) { const box = el('toast'); box.textContent = message; box.classList.remove('hidden'); clearTimeout(box.timer); box.timer = setTimeout(() => box.classList.add('hidden'), 4200); }

async function quickPath(kind) {
  openBrowser(state.locations[kind] || state.locations.home);
}

document.querySelectorAll('[data-view]').forEach((button) => button.addEventListener('click', () => showView(button.dataset.view)));
document.querySelectorAll('[data-open-view]').forEach((button) => button.addEventListener('click', () => showView(button.dataset.openView)));
el('header-scan').addEventListener('click', () => showView('scan')); el('hero-scan').addEventListener('click', () => showView('scan')); el('start-scan').addEventListener('click', startScan); el('browse-button').addEventListener('click', () => openBrowser(el('target-path').value.trim()));
el('close-browser').addEventListener('click', () => el('browser-dialog').close()); el('parent-folder').addEventListener('click', () => { if (state.browseParent) openBrowser(state.browseParent); }); el('open-path').addEventListener('click', () => openBrowser(el('browser-path').value.trim())); el('browser-path').addEventListener('keydown', (event) => { if (event.key === 'Enter') openBrowser(event.target.value.trim()); });
el('refresh-quarantine').addEventListener('click', loadQuarantine); document.querySelectorAll('[data-report]').forEach((button) => button.addEventListener('click', () => downloadReport(button.dataset.report))); document.querySelectorAll('[data-quick]').forEach((button) => button.addEventListener('click', () => quickPath(button.dataset.quick))); el('stop-app').addEventListener('click', async () => {
  try {
    const response = await api('/api/shutdown', { method: 'POST' });
    if (!response.ok) throw new Error();
    text('live-status', 'ArmorAV завершён');
    toast('ArmorAV завершён. Эту вкладку можно закрыть.');
  } catch { toast('Не удалось завершить ArmorAV.'); }
});
fetch('/api/config').then((response) => response.json()).then((data) => {
  state.token = data.token;
  state.locations = data.locations || {};
  text('live-status', `Готов · ${data.version}`);
}).catch(() => text('live-status', 'Не удалось подключиться к локальному сервису'));
